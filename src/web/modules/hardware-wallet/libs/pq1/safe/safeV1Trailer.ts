// Build the `safe_v1` trailer for the PQ1 firmware's clear-signing
// downgrade gate (`secure/src/tx/eip712/safe/verify.rs::verify_and_bind_trailer`).
//
// Flow:
//   1. Detect `approveHash(bytes32)` calldata on the inner UserOp call.
//   2. Fetch canonical SafeTx fields from the Safe Transaction Service.
//   3. Gate DelegateCall (operation == 1): accepted ONLY for an
//      allowlisted `MultiSendCallOnly` target carrying a batch that
//      passes every multiSend hard rule (companion-safe-cowswap-
//      multisend.md); anything else fails fast here with the same
//      refusal the firmware's verifier enforces.
//   4. Re-derive `safeTxHash` locally and require it equals the on-chain
//      hash from `inner_data[4..36]`. A mismatch is treated as orderbook
//      / API tampering and we refuse to sign.
//   5. Pack the 281-byte canonical || u16 BE raw_data_len || raw_data.
//
// Wire format (`companion-safe-tx-integration.md`):
//
//   offset  size            field
//     0     281             canonical SafeTx fields
//     281   2 (u16 BE)      raw_data_len  (0..=4096)
//     283   raw_data_len    raw_data — exact inner-call calldata (for a
//                           multiSend batch: the FULL multiSend calldata;
//                           it must keccak to the canonical's data_hash)
//
// The firmware refuses to trust any byte here until it re-derives both
// `data_hash = keccak256(raw_data)` and the EIP-712 `safeTxHash`. Every
// other check (chain pinning, safe-address pinning, op==0) fails closed.

import { MAX_TX_LEN } from '../config'
import { bytesToHex0x, concatBytes, hexToBytes, isSameBytes, u16be } from '../transport/bytes'
import { fetchSafeTx, type SafeTxFields } from './api'
import { decodeApproveHash, isApproveHashSelector } from './calldata'
import { encodeSafeCanonical, safeDataHash, SAFE_V1_CANONICAL_LEN } from './canonical'
import { assertSafeOperationSignable } from './multiSend'
import { computeSafeTxHash } from './eip712'

export const SAFE_V1_RAW_DATA_MAX = MAX_TX_LEN // 4096

export interface BuildSafeV1TrailerInput {
  chainId: number | bigint
  /** Inner-call target — must equal the SafeTx's safe address. The firmware
   *  binds `canonical.safe_address` to this value. */
  to: `0x${string}`
  /** Inner-call calldata — must be a 36-byte `approveHash(bytes32)`. */
  innerData: Uint8Array
}

export interface BuildSafeV1TrailerResult {
  safeV1Bundle: Uint8Array
  fields: SafeTxFields
}

/** True when the inner call is a strict 36-byte `approveHash` — i.e. the
 *  shape the firmware's downgrade-mitigation gate requires a `safe_v1`
 *  trailer for. */
export function isSafeApproveHash(_to: `0x${string}`, data: Uint8Array): boolean {
  return data.length === 36 && isApproveHashSelector(data)
}

/** Build the `safe_v1` trailer for an inner approveHash call. Returns null
 *  when the call isn't `approveHash` — callers can keep their normal trailer
 *  routing (ERC-7730 / blind-sign) for non-Safe calls. Throws on any failure
 *  once we've decided this IS an approveHash: there is no graceful fallback
 *  because the firmware refuses to sign approveHash without a `safe_v1`
 *  trailer attached. */
export async function tryBuildSafeV1Trailer(
  args: BuildSafeV1TrailerInput
): Promise<BuildSafeV1TrailerResult | null> {
  const decoded = decodeApproveHash(args.innerData)
  if (!decoded) return null

  const safeTxHashHex = bytesToHex0x(decoded.safeTxHash)

  const fields = await fetchSafeTx(args.chainId, safeTxHashHex)

  const rawData = hexToBytes(fields.data)
  assertSafeOperationSignable(fields.operation, fields.to, rawData)
  if (rawData.length > SAFE_V1_RAW_DATA_MAX) {
    throw new Error(
      `Safe inner raw_data is ${rawData.length} bytes, exceeds firmware cap ${SAFE_V1_RAW_DATA_MAX}`
    )
  }

  // One canonical-fields object for both the trailer bytes and the local
  // safeTxHash re-derivation — if these two ever diverge (an edited field
  // mapping applied to only one) the tamper check below silently checks
  // the wrong thing.
  const canonicalFields = {
    chainId: args.chainId,
    safeAddress: args.to,
    to: fields.to,
    value: fields.value,
    dataHash: safeDataHash(rawData),
    operation: fields.operation,
    safeTxGas: fields.safeTxGas,
    baseGas: fields.baseGas,
    gasPrice: fields.gasPrice,
    gasToken: fields.gasToken,
    refundReceiver: fields.refundReceiver,
    nonce: fields.nonce
  }

  const canonical = encodeSafeCanonical(canonicalFields)
  if (canonical.length !== SAFE_V1_CANONICAL_LEN) {
    throw new Error(`canonical length ${canonical.length} != ${SAFE_V1_CANONICAL_LEN}`)
  }

  // Re-derive safeTxHash from the canonical and require it equals the
  // on-chain hash the dapp asked us to approve. The firmware re-derives
  // it too; checking here gives a clearer error than waiting for the
  // device to silently drop the trailer.
  const recomputed = computeSafeTxHash(canonicalFields)
  if (!isSameBytes(recomputed, decoded.safeTxHash)) {
    throw new Error(
      `Safe Transaction Service returned a SafeTx whose recomputed hash ${bytesToHex0x(
        recomputed
      )} does not match the approveHash argument ${safeTxHashHex}. Refusing to sign — possible API tampering or Safe v1.1.x domain.`
    )
  }

  const safeV1Bundle = concatBytes([canonical, u16be(rawData.length), rawData])
  return { safeV1Bundle, fields }
}
