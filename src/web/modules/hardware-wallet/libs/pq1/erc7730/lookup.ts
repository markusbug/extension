// High-level helpers wrapping the catalog parser for the three sign
// codepaths in `aa/broadcast.ts` and `PQ1Signer/PQ1Signer.ts`.
//
// All helpers are fail-open: when the catalog blob is missing, fails to
// parse, or has no descriptor for the given lookup key, they return
// `null`. The caller ships the sign request without a trailer and the
// firmware silently falls back to blind-sign — matching the contract
// from §1 of the firmware doc ("Clear signing is never required — it is
// an enhancement layer the companion is free to skip per-tx").

import { hexToBytes } from '../transport/bytes'
import { CTX_CONTRACT, CTX_EIP712, loadErc7730Catalog } from './catalog'

/** True for a 20-byte address slice. The companion uses this to skip the
 *  catalog lookup for non-contract targets (precompiles, EOAs) without
 *  paying the catalog-parse cost. */
function isContractAddress(b: Uint8Array): boolean {
  return b.length === 20
}

/** Look up the ERC-7730 descriptor for a contract-context UserOp call
 *  (selector or self-attest path; `to` is the contract being invoked,
 *  `chainId` is the EIP-155 chain). Returns the firmware-ready bundle
 *  or `null` on miss / catalog error. */
export async function buildErc7730BundleForCall(args: {
  chainId: number | bigint
  to: `0x${string}`
}): Promise<Uint8Array | null> {
  const contract = hexToBytes(args.to)
  if (!isContractAddress(contract)) return null
  let catalog
  try {
    catalog = await loadErc7730Catalog()
  } catch (e) {
    console.warn('[pq1] erc7730 catalog unavailable — falling back to blind-sign', e)
    return null
  }
  const entry = catalog.find(args.chainId, contract, CTX_CONTRACT)
  if (!entry) return null
  try {
    return catalog.assembleTrailer(entry)
  } catch (e) {
    console.warn('[pq1] erc7730 trailer assembly failed — falling back to blind-sign', e)
    return null
  }
}

/** Look up the descriptor for an EIP-712 typed-data sign. Returns
 *  `null` when no descriptor exists for `(chainId, verifyingContract)`;
 *  the caller in `PQ1Signer.signTypedData` then routes through kind=0
 *  (raw32) with the pre-computed EIP-712 final hash instead — see
 *  §6.3 of the firmware doc. */
export async function buildErc7730BundleForEip712(args: {
  chainId: number | bigint
  verifyingContract: `0x${string}`
  /** `keccak256(typeString)` of the primary type. Used to pick the right
   *  descriptor when one `(chainId, contract)` pair has multiple EIP-712
   *  formats — e.g. USDC mainnet ships both `TransferWithAuthorization`
   *  and `ReceiveWithAuthorization` as distinct catalog entries. The
   *  firmware compares only the first 4 bytes, but the companion uses
   *  the full hash to keep the lookup deterministic. */
  primaryTypeHash?: Uint8Array
}): Promise<Uint8Array | null> {
  const contract = hexToBytes(args.verifyingContract)
  if (!isContractAddress(contract)) return null
  let catalog
  try {
    catalog = await loadErc7730Catalog()
  } catch (e) {
    console.warn('[pq1] erc7730 catalog unavailable — falling back to raw32', e)
    return null
  }
  const primaryTypeHash4 = args.primaryTypeHash?.subarray(0, 4)
  const entry = catalog.find(args.chainId, contract, CTX_EIP712, primaryTypeHash4)
  if (!entry) return null
  try {
    return catalog.assembleTrailer(entry)
  } catch (e) {
    console.warn('[pq1] erc7730 trailer assembly failed — falling back to raw32', e)
    return null
  }
}
