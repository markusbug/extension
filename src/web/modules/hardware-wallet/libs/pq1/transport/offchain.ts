// CMD_SIGN_OFFCHAIN / CMD_OFFCHAIN_STATUS payload builders + parsers.
// Wire layouts mirror `sphincs_tz_shared::SIGN_OFFCHAIN_*` and
// `OFFCHAIN_STATUS_*` constants in
// sphincs_rust/shared/src/lib.rs.

import {
  C10_SIG_LEN,
  ERC6492_WRAPPED_BLOB_LEN,
  ERC7730_MAX_TRAILER_LEN,
  MAX_ACCOUNT_INDEX,
  MAX_OFFCHAIN_EIP712_ENCODED_DATA_LEN,
  MAX_OFFCHAIN_EIP712_TYPED_LEN,
  MAX_OFFCHAIN_PERSONAL_SIGN_LEN,
  OFFCHAIN_FLAG_ACCOUNT_DEPLOYED,
  OFFCHAIN_KIND_EIP712_TYPED,
  OFFCHAIN_KIND_PERSONAL_SIGN,
  OFFCHAIN_KIND_RAW32,
  OFFCHAIN_STATUS_INPUT_LEN,
  OFFCHAIN_STATUS_OUTPUT_LAST_USEROP_OFF,
  OFFCHAIN_STATUS_OUTPUT_LEN,
  OFFCHAIN_STATUS_OUTPUT_LOCAL_OFF,
  OFFCHAIN_STATUS_OUTPUT_REGISTERED_OFF,
  SIGN_OFFCHAIN_HEADER_LEN,
  SIGN_OFFCHAIN_INPUT_MAX_LEN,
  SIGN_OFFCHAIN_OUTPUT_COUNT_OFF,
  SIGN_OFFCHAIN_OUTPUT_LEN,
  SIGN_OFFCHAIN_OUTPUT_LEN_COUNTERFACTUAL,
  SIGN_OFFCHAIN_OUTPUT_SIG_OFF
} from '../config'
import { concatBytes, u16be, u32be, u64be } from './bytes'

type SignOffchainCommon = {
  accountIndex: number
  chainId: bigint | number
  slotIndex: number
  /** Whether the PQSmartWallet is deployed on the target chain. The
   *  companion checks `eth_getCode(sender) !== "0x"` immediately before
   *  the SIGN_OFFCHAIN APDU and sets this flag accordingly.
   *
   *  - `true`  → device emits 4016 B = `[count(8)][C10 sig(4008)]`. Host
   *              wraps as `abi.encode(uint256 ownerIndex, bytes sig)`.
   *  - `false` → device emits 8616 B = `[count(8)][ERC-6492 blob(8608)]`
   *              that already encodes the factory deploy + sig wrapper +
   *              0x6492…6492 magic. Pass-through to the dapp.
   *
   *  Firmware constraint when `accountDeployed=false`: `slotIndex` MUST
   *  be 0 (the factory only seeds bootstrap + slot 0). */
  accountDeployed: boolean
}

export type SignOffchainParams =
  | (SignOffchainCommon & {
      kind: 'personal_sign'
      message: Uint8Array
    })
  | (SignOffchainCommon & {
      kind: 'raw32'
      digest: Uint8Array
    })
  | (SignOffchainCommon & {
      /** EIP-712 typed-data sign with an ERC-7730 clear-signing trailer.
       *
       *  The firmware (`cmd_sign_offchain.rs` kind=2 branch) verifies the
       *  trailer against `ERC7730_DESCRIPTORS_ROOT`, binds it to the
       *  supplied `(domain_separator, primary_type_hash)`, renders the
       *  descriptor's field-level pages instead of a raw fingerprint,
       *  then signs the EIP-712 final hash
       *  `keccak256(0x1901 || domain_separator || keccak256(primary_type_hash || encoded_data))`.
       *
       *  There is NO blind-sign fallback inside the firmware for kind=2 —
       *  a trailer that fails verify or binding returns
       *  `NscStatus::InvalidPointer` to the host. Callers that can't find
       *  a descriptor MUST route through kind=0 (raw32) instead, hashing
       *  the typed data themselves. */
      kind: 'eip712_typed'
      /** 32-byte `keccak256(EIP712Domain_typehash || encode(domain))`. */
      domainSeparator: Uint8Array
      /** 32-byte `keccak256(typeString)` of the primary type. */
      primaryTypeHash: Uint8Array
      /** `viem::encodeAbiParameters(types[primaryType], message)` — the
       *  ABI-encoded struct body WITHOUT a typehash prefix. The firmware
       *  prepends the typehash internally before hashing. */
      encodedData: Uint8Array
      /** Inner bundle produced by `catalog.assembleTrailer(entry)` —
       *  `ir_len(u16 BE) || ir || leaf_index(u32 BE) || proof_depth(u32 BE) || proof`. */
      erc7730Bundle: Uint8Array
    })

export function buildSignOffchainPayload(p: SignOffchainParams): Uint8Array {
  if (p.accountIndex < 0 || p.accountIndex > MAX_ACCOUNT_INDEX) {
    throw new Error(`signOffchain: account_index out of range: ${p.accountIndex}`)
  }
  if (p.slotIndex < 0 || p.slotIndex > 0x003fffff) {
    throw new Error(`signOffchain: slot_index out of range: ${p.slotIndex}`)
  }
  if (!p.accountDeployed && p.slotIndex !== 0) {
    throw new Error(`signOffchain: counterfactual path requires slot_index=0, got ${p.slotIndex}`)
  }

  let kindByte: number
  let payload: Uint8Array
  if (p.kind === 'personal_sign') {
    if (p.message.length > MAX_OFFCHAIN_PERSONAL_SIGN_LEN) {
      throw new Error(
        `signOffchain: personal_sign message ${p.message.length} > ${MAX_OFFCHAIN_PERSONAL_SIGN_LEN} bytes`
      )
    }
    kindByte = OFFCHAIN_KIND_PERSONAL_SIGN
    payload = p.message
  } else if (p.kind === 'raw32') {
    if (p.digest.length !== 32) {
      throw new Error(`signOffchain: raw32 digest must be 32 bytes, got ${p.digest.length}`)
    }
    kindByte = OFFCHAIN_KIND_RAW32
    payload = p.digest
  } else {
    // kind === 'eip712_typed' — assemble the kind=2 payload per §6.3 of
    // sphincs_rust/docs/companion-erc7730-implementation-guide.md.
    if (p.domainSeparator.length !== 32) {
      throw new Error(
        `signOffchain: eip712 domainSeparator must be 32 bytes, got ${p.domainSeparator.length}`
      )
    }
    if (p.primaryTypeHash.length !== 32) {
      throw new Error(
        `signOffchain: eip712 primaryTypeHash must be 32 bytes, got ${p.primaryTypeHash.length}`
      )
    }
    if (p.encodedData.length > MAX_OFFCHAIN_EIP712_ENCODED_DATA_LEN) {
      throw new Error(
        `signOffchain: eip712 encodedData ${p.encodedData.length} > ${MAX_OFFCHAIN_EIP712_ENCODED_DATA_LEN}`
      )
    }
    if (p.erc7730Bundle.length === 0) {
      // Kind=2 has no blind-sign fallback inside the firmware. Either we
      // ship a trailer or we don't use this codepath — see the doc's
      // failure-mode table for the rationale.
      throw new Error(
        'signOffchain: eip712_typed requires a non-empty erc7730Bundle (firmware refuses bare typed-data signs)'
      )
    }
    if (p.erc7730Bundle.length > ERC7730_MAX_TRAILER_LEN) {
      throw new Error(
        `signOffchain: erc7730Bundle ${p.erc7730Bundle.length} > ${ERC7730_MAX_TRAILER_LEN}`
      )
    }
    kindByte = OFFCHAIN_KIND_EIP712_TYPED
    // `domain_sep_present` u16 BE = 1 (the pre-EIP-712 bare-hash codepath
    // is explicitly refused by the firmware on kind=2).
    payload = concatBytes([
      new Uint8Array([0x00, 0x01]),
      p.domainSeparator,
      p.primaryTypeHash,
      u16be(p.encodedData.length),
      p.encodedData,
      u16be(p.erc7730Bundle.length),
      p.erc7730Bundle
    ])
    if (payload.length > MAX_OFFCHAIN_EIP712_TYPED_LEN) {
      throw new Error(
        `signOffchain: eip712_typed payload ${payload.length} > ${MAX_OFFCHAIN_EIP712_TYPED_LEN}`
      )
    }
  }

  const payloadLen = payload.length
  const flagsByte = p.accountDeployed ? OFFCHAIN_FLAG_ACCOUNT_DEPLOYED : 0x00
  const out = concatBytes([
    new Uint8Array([p.accountIndex & 0xff]),
    u64be(p.chainId),
    u32be(p.slotIndex),
    new Uint8Array([kindByte]),
    u16be(payloadLen),
    new Uint8Array([flagsByte]),
    payload
  ])
  if (out.length !== SIGN_OFFCHAIN_HEADER_LEN + payloadLen) {
    throw new Error(`signOffchain: header invariant broken (${out.length} bytes)`)
  }
  if (out.length > SIGN_OFFCHAIN_INPUT_MAX_LEN) {
    throw new Error(
      `signOffchain: payload too large (${out.length} > ${SIGN_OFFCHAIN_INPUT_MAX_LEN})`
    )
  }
  return out
}

export type SignOffchainBundle =
  | {
      kind: 'deployed'
      newOffchainCount: bigint
      /** 4008-byte raw SPHINCS+C10 signature. Pass through
       *  `abi.encode(uint256 ownerIndex, bytes signature)` to produce the
       *  ERC-1271 sig the verifier consumes. */
      innerSig: Uint8Array
    }
  | {
      kind: 'counterfactual'
      newOffchainCount: bigint
      /** 8608-byte ERC-6492-wrapped signature emitted by the firmware —
       *  `abi.encode(address factory, bytes factoryCalldata, bytes sigWrapper)`
       *  followed by the 32-byte 0x6492…6492 magic suffix. Pass-through
       *  to the dapp; any EIP-6492-aware verifier will deploy-and-verify
       *  the wallet in a single `eth_call`. */
      erc6492Sig: Uint8Array
    }

export function parseSignOffchainResponse(resp: Uint8Array): SignOffchainBundle {
  if (
    resp.length !== SIGN_OFFCHAIN_OUTPUT_LEN &&
    resp.length !== SIGN_OFFCHAIN_OUTPUT_LEN_COUNTERFACTUAL
  ) {
    throw new Error(
      `signOffchain: response length ${resp.length} is neither ${SIGN_OFFCHAIN_OUTPUT_LEN} (deployed) nor ${SIGN_OFFCHAIN_OUTPUT_LEN_COUNTERFACTUAL} (counterfactual)`
    )
  }
  let count = 0n
  for (let i = 0; i < 8; i++) {
    count = (count << 8n) | BigInt(resp[SIGN_OFFCHAIN_OUTPUT_COUNT_OFF + i]!)
  }
  if (resp.length === SIGN_OFFCHAIN_OUTPUT_LEN) {
    const sig = resp.slice(SIGN_OFFCHAIN_OUTPUT_SIG_OFF, SIGN_OFFCHAIN_OUTPUT_SIG_OFF + C10_SIG_LEN)
    return { kind: 'deployed', newOffchainCount: count, innerSig: sig }
  }
  const erc6492Sig = resp.slice(
    SIGN_OFFCHAIN_OUTPUT_SIG_OFF,
    SIGN_OFFCHAIN_OUTPUT_SIG_OFF + ERC6492_WRAPPED_BLOB_LEN
  )
  return { kind: 'counterfactual', newOffchainCount: count, erc6492Sig }
}

export type OffchainStatusInput = {
  accountIndex: number
  chainId: bigint | number
  slotIndex: number
}

export function buildOffchainStatusPayload(p: OffchainStatusInput): Uint8Array {
  if (p.accountIndex < 0 || p.accountIndex > MAX_ACCOUNT_INDEX) {
    throw new Error(`offchainStatus: account_index out of range: ${p.accountIndex}`)
  }
  if (p.slotIndex < 0 || p.slotIndex > 0x003fffff) {
    throw new Error(`offchainStatus: slot_index out of range: ${p.slotIndex}`)
  }
  const out = concatBytes([
    new Uint8Array([p.accountIndex & 0xff]),
    u64be(p.chainId),
    u32be(p.slotIndex)
  ])
  if (out.length !== OFFCHAIN_STATUS_INPUT_LEN) {
    throw new Error(`offchainStatus: payload length ${out.length} != ${OFFCHAIN_STATUS_INPUT_LEN}`)
  }
  return out
}

export type OffchainStatus = {
  localOffchainCount: bigint
  lastUseropCount: bigint
  registered: boolean
}

export function parseOffchainStatusResponse(resp: Uint8Array): OffchainStatus {
  if (resp.length !== OFFCHAIN_STATUS_OUTPUT_LEN) {
    throw new Error(
      `offchainStatus: response length ${resp.length} != ${OFFCHAIN_STATUS_OUTPUT_LEN}`
    )
  }
  let local = 0n
  for (let i = 0; i < 8; i++) {
    local = (local << 8n) | BigInt(resp[OFFCHAIN_STATUS_OUTPUT_LOCAL_OFF + i]!)
  }
  let lastUserop = 0n
  for (let i = 0; i < 8; i++) {
    lastUserop = (lastUserop << 8n) | BigInt(resp[OFFCHAIN_STATUS_OUTPUT_LAST_USEROP_OFF + i]!)
  }
  const registered = resp[OFFCHAIN_STATUS_OUTPUT_REGISTERED_OFF] === 1
  return { localOffchainCount: local, lastUseropCount: lastUserop, registered }
}
