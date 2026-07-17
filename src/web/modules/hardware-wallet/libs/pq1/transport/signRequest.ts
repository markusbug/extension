// SIGN_USEROP / SIGN_USEROP_BATCH wire-format builders.
// Fields mirror
// pq1-companion/src-tauri/crates/pq1-device/src/sign_request.rs:64-192
// and sphincs_rust/tools/webhid_test.html:587-654.

import {
  ACCOUNT_INDEX_MASK,
  ACCOUNT_INDEX_SHIFT,
  ENTRY_POINT_V06,
  ERC7730_MAX_TRAILER_LEN,
  FLAG_INCLUDE_INIT_CODE,
  FLAG_REGISTER_SLOT,
  MAX_ACCOUNT_INDEX,
  MAX_BATCH_TXS,
  MAX_NAME_BUNDLES,
  MAX_TRAILERS_PER_BATCH,
  MAX_TX_LEN,
  SHA256_EMPTY,
  SIGN_USEROP_BATCH_WIRE_VERSION,
  SLOT_INDEX_MASK,
  TRAILER_KIND_ERC20,
  TRAILER_KIND_ERC7730,
  TRAILER_KIND_NAME,
  TRAILER_KIND_SAFE_V1,
  TRAILER_KIND_SEL_CURATED,
  TRAILER_KIND_SEL_SELFATTEST,
  TRAILER_KIND_ZK_V3,
  TRAILER_TX_IDX_BATCH_WIDE,
  TRAILERS_TOTAL_MAX_LEN
} from '../config'
import { decodeApproveHash } from '../safe/calldata'
import { decodeExecTransaction } from '../safe/execCalldata'
import { isCowPresignClaim, resolveSafeCowBinding, type SafeCowBinding } from '../safe/multiSend'
import { bytesToHex0x, concatBytes, hexToBytes, u16be, u256be, u32be, u64be } from './bytes'

// Downgrade-mitigation gate predicates. The firmware aborts a sign when
// these calls are present without their matching trailer; we fail
// fast on the host so the user sees a clear error before the device
// rejects. The approveHash decode, the CoW-claim predicate, and the
// multiSend resolver come from `safe/calldata` / `safe/multiSend` —
// pure byte-parsing, no viem dependency chain, so this module stays
// light enough for PQ1Controller's background-worker startup (same as
// `safe/execCalldata`).

// safe_v1 bundle layout, duplicated from safe/canonical.ts for the same
// lightness reason: canonical(281) with the SafeTx inner `to` at
// [28..48) and the operation byte at [112], then `u16 BE raw_data_len`,
// then raw_data.
const SAFE_V1_CANONICAL_LEN = 281
const SAFE_V1_CANONICAL_TO_OFFSET = 28
const SAFE_V1_CANONICAL_OPERATION_OFFSET = 112

/** Resolve the CoW-binding obligation of a Safe flow: does this
 *  (inner_data, safe_v1 bundle) pair describe a SafeTx whose inner call
 *  claims a CoW `setPreSignature` — directly, or as the unique presign
 *  record inside an allowlisted MultiSendCallOnly batch? Mirrors the
 *  firmware's `resolve_cow_binding` precedence (approveHash context out
 *  of the safe_v1 bundle bytes first, then the execTransaction context
 *  out of the same strict ABI decode the firmware runs) so the host
 *  gate and the device gate cannot disagree. An `operation == 1`
 *  context that is NOT an allowlisted multiSend claim resolves to
 *  `none`: the firmware's Safe verify refuses it first, so it never
 *  reaches the CoW gate. A claimed multiSend that violates a hard rule
 *  resolves to `refuse` — the device rejects it regardless of trailers
 *  (`Safe sign / msend *` banners). */
function safeWrappedCowBinding(data: Uint8Array, safeV1Bundle: Uint8Array): SafeCowBinding {
  if (safeV1Bundle.length >= SAFE_V1_CANONICAL_LEN + 2) {
    const rawLen =
      (safeV1Bundle[SAFE_V1_CANONICAL_LEN]! << 8) | safeV1Bundle[SAFE_V1_CANONICAL_LEN + 1]!
    const rawStart = SAFE_V1_CANONICAL_LEN + 2
    if (rawStart + rawLen <= safeV1Bundle.length) {
      const innerTo = bytesToHex0x(
        safeV1Bundle.subarray(SAFE_V1_CANONICAL_TO_OFFSET, SAFE_V1_CANONICAL_TO_OFFSET + 20)
      )
      const operation = safeV1Bundle[SAFE_V1_CANONICAL_OPERATION_OFFSET]!
      const binding = resolveSafeCowBinding(
        operation,
        innerTo,
        safeV1Bundle.subarray(rawStart, rawStart + rawLen)
      )
      if (binding.kind !== 'none') return binding
    }
  }
  const exec = decodeExecTransaction(data)
  if (exec !== null) {
    const binding = resolveSafeCowBinding(exec.operation, exec.to, exec.data)
    if (binding.kind !== 'none') return binding
  }
  return { kind: 'none' }
}

export type SignRequestParams = {
  chainId: bigint | number
  accountIndex: number // 0..255
  slotIndex: number // 0..(2^22 - 1)
  includeInitCode?: boolean
  registerSlot?: boolean
  sender: `0x${string}`
  entryPoint?: `0x${string}`
  nonce: bigint | number | string
  callGas: bigint | number | string
  verGas: bigint | number | string
  preVerificationGas: bigint | number | string
  maxFeePerGas: bigint | number | string
  maxPriorityFeePerGas: bigint | number | string
  paymasterAndDataHash?: Uint8Array
  to: `0x${string}`
  value: bigint | number | string
  data?: Uint8Array
  erc20Bundle?: Uint8Array
  zkV3Bundle?: Uint8Array
  /** Per-tx Safe v1 `approveHash` clear-sign bundle:
   *  `canonical(281) || raw_data_len(u16 BE) || raw_data`. Required
   *  whenever the inner call is `approveHash(bytes32)` on a Safe — the
   *  firmware's downgrade-mitigation gate refuses to sign otherwise. */
  safeV1Bundle?: Uint8Array
  selectorBundle?: Uint8Array
  selfAttestBundle?: Uint8Array
  /** ERC-7730 clear-signing descriptor bundle. The payload bytes
   *  `ir_len(u16 BE) || ir || leaf_index(u32 BE) || proof_depth(u32 BE) || proof`
   *  produced by the catalog assembler (`erc7730/catalog.ts`). The
   *  firmware verifies the bundle against `ERC7730_DESCRIPTORS_ROOT`,
   *  binds it to `(chain_id, to_address)`, and renders field-level
   *  clear-sign pages instead of the blind-sign fingerprint. */
  erc7730Bundle?: Uint8Array
  /** Address-name bundles (trailer kind 8) for the addresses the device
   *  will display — `to`, ERC-20 recipient/spender, Safe / multiSend
   *  targets, CoW receiver. Each is built by `names/db.ts` and verified
   *  on-device against `NAMES_DB_ROOT`. The section is framed as
   *  `[count u8] + count × (u16 BE len + bundle)` and is the LAST trailer;
   *  including it forces the prefixes for trailers 1..7 to be emitted. Up
   *  to `MAX_NAME_BUNDLES` (4); omit for the always-safe 40-hex render. */
  nameBundles?: Uint8Array[]
}

/** Everything both encoders share: the flags word (accountIndex/slotIndex
 *  bit-packing + the firmware's mutual-exclusion rules) and the header
 *  prefix `chainId .. paymasterHash` — the byte layouts are identical up
 *  to offset 276. One implementation so a firmware flag-layout change or
 *  a new validation rule can't silently apply to only one of the two
 *  paths (the other would then produce payloads the device rejects with
 *  an opaque wire error). */
function buildCommonHeader(
  p: Omit<BatchSignRequestParams, 'calls' | 'nameBundles' | 'selectorBundle' | 'selfAttestBundle'>
): Uint8Array {
  const sender = hexToBytes(p.sender)
  if (sender.length !== 20) throw new Error('sender must be 20 bytes')
  const entryPoint = hexToBytes(p.entryPoint ?? ENTRY_POINT_V06)
  if (entryPoint.length !== 20) throw new Error('entryPoint must be 20 bytes')

  const acctIdx = (p.accountIndex >>> 0) & MAX_ACCOUNT_INDEX
  let flags = (p.slotIndex || 0) & SLOT_INDEX_MASK
  flags |= (acctIdx << ACCOUNT_INDEX_SHIFT) & ACCOUNT_INDEX_MASK
  if (p.registerSlot) flags |= FLAG_REGISTER_SLOT
  if (p.includeInitCode) flags |= FLAG_INCLUDE_INIT_CODE
  if (p.registerSlot && p.includeInitCode) {
    throw new Error('registerSlot and includeInitCode are mutually exclusive')
  }
  if (p.includeInitCode && (p.slotIndex || 0) !== 0) {
    throw new Error('includeInitCode requires slotIndex = 0')
  }
  if (p.registerSlot && (p.slotIndex || 0) === 0) {
    throw new Error('registerSlot requires slotIndex >= 1')
  }

  const paymasterHash = p.paymasterAndDataHash ?? SHA256_EMPTY
  if (paymasterHash.length !== 32) throw new Error('paymasterAndDataHash must be 32 bytes')

  return concatBytes([
    u64be(p.chainId),
    u32be(flags >>> 0),
    sender,
    entryPoint,
    u256be(p.nonce),
    u256be(p.callGas),
    u256be(p.verGas),
    u256be(p.preVerificationGas),
    u256be(p.maxFeePerGas),
    u256be(p.maxPriorityFeePerGas),
    paymasterHash
  ])
}

export function buildSignPayload(p: SignRequestParams): Uint8Array {
  const commonHeader = buildCommonHeader(p)
  const to = hexToBytes(p.to)
  if (to.length !== 20) throw new Error('to must be 20 bytes')
  const data = p.data ?? new Uint8Array(0)
  // Same cap as the batch path — MAX_TX_LEN mirrors the firmware's
  // per-tx calldata ceiling. Anything larger would pass a host gate set
  // at the wire-format ceiling (0xffff) and only be rejected on-device
  // with a raw SW error after gas estimation and the PIN prompt.
  if (data.length > MAX_TX_LEN) {
    throw new Error(`inner data too long (${data.length} > ${MAX_TX_LEN})`)
  }

  const erc20Bundle = p.erc20Bundle ?? new Uint8Array(0)
  const zkV3Bundle = p.zkV3Bundle ?? new Uint8Array(0)
  const safeV1Bundle = p.safeV1Bundle ?? new Uint8Array(0)
  const selectorBundle = p.selectorBundle ?? new Uint8Array(0)
  const selfAttestBundle = p.selfAttestBundle ?? new Uint8Array(0)
  const erc7730Bundle = p.erc7730Bundle ?? new Uint8Array(0)
  if (selectorBundle.length > 0 && selfAttestBundle.length > 0) {
    throw new Error('selectorBundle and selfAttestBundle are mutually exclusive')
  }
  if (erc7730Bundle.length > ERC7730_MAX_TRAILER_LEN) {
    throw new Error(
      `erc7730Bundle ${erc7730Bundle.length} B exceeds firmware cap ${ERC7730_MAX_TRAILER_LEN} B`
    )
  }
  const safeV1Cap = TRAILER_KIND_MAX_LEN[TRAILER_KIND_SAFE_V1]!
  if (safeV1Bundle.length > safeV1Cap) {
    throw new Error(`safeV1Bundle ${safeV1Bundle.length} B exceeds firmware cap ${safeV1Cap} B`)
  }
  // Downgrade-mitigation gates (mirror the firmware aborts in
  // cmd_sign_userop.rs): an inner `approveHash(bytes32)` requires a
  // safe_v1 trailer; a `setPreSignature` on GPv2Settlement — direct, or
  // wrapped as the SafeTx inner call of an approveHash/execTransaction
  // flow, including the unique presign record inside an allowlisted
  // MultiSendCallOnly batch (`cow_bind.via_safe`, "CoW sign: v3
  // required") — requires a zk_v3 trailer. A claimed multiSend batch
  // violating a hard rule refuses outright (`multisend_sign_gate`, no
  // trailer can fix it). The device refuses to sign otherwise.
  if (decodeApproveHash(data) !== null && safeV1Bundle.length === 0) {
    throw new Error('Safe approveHash requires a safeV1Bundle (firmware downgrade-mitigation gate)')
  }
  if (isCowPresignClaim(p.to.toLowerCase(), data) && zkV3Bundle.length === 0) {
    throw new Error(
      'CoW setPreSignature requires a zkV3Bundle (firmware downgrade-mitigation gate)'
    )
  }
  const wrappedBinding = safeWrappedCowBinding(data, safeV1Bundle)
  if (wrappedBinding.kind === 'refuse') {
    throw new Error(
      `Safe multiSend batch refused by PQ1 firmware ("Safe sign / ${wrappedBinding.banner}") — ` +
        'no trailer can fix it; adjust the batch'
    )
  }
  if (wrappedBinding.kind === 'bind' && zkV3Bundle.length === 0) {
    throw new Error(
      'Safe-wrapped CoW setPreSignature requires a zkV3Bundle bound to the presign calldata ' +
        'with uid.owner == the Safe (firmware downgrade-mitigation gate)'
    )
  }
  const head = concatBytes([commonHeader, to, u256be(p.value), u16be(data.length), data])

  // Trailer order mirrors the firmware's reader sequence in
  // sphincs_rust/secure/src/nsc/cmd_sign_userop.rs:252-509:
  //   erc20 → zk_v1 → zk_v3 → safe_v1 → selector → self_attest → erc7730.
  // The parser walks the chain sequentially: every absent slot ahead of
  // a present slot MUST still go in as `[u16 BE 0]`. Trailing absent
  // slots are dropped to keep the payload minimal. Slot 2 (zk_v1, the
  // retired Groth16 clear-sign bundle) is always emitted empty: the host
  // has no producer for it since the offscreen prover was removed, and
  // the firmware dropped the circuit + VK verify in fw 05f9758a. The
  // kind-3 CoW trailer is `canonical(204) + two ERC-20 leg bundles` and
  // carries NO VK. The companion attaches every bundle it wants rendered
  // — there is no on-device DB or injection fallback anymore (fw
  // aae0694e).
  const trailers: Array<{ len: number; bytes?: Uint8Array }> = [
    { len: erc20Bundle.length, bytes: erc20Bundle },
    { len: 0 }, // zk_v1 positional slot — always empty (see above)
    { len: zkV3Bundle.length, bytes: zkV3Bundle },
    { len: safeV1Bundle.length, bytes: safeV1Bundle },
    { len: selectorBundle.length, bytes: selectorBundle },
    { len: selfAttestBundle.length, bytes: selfAttestBundle },
    { len: erc7730Bundle.length, bytes: erc7730Bundle }
  ]
  const nameBundles = p.nameBundles ?? []
  if (nameBundles.length > MAX_NAME_BUNDLES) {
    throw new Error(
      `nameBundles ${nameBundles.length} exceeds MAX_NAME_BUNDLES ${MAX_NAME_BUNDLES}`
    )
  }
  const nameCap = TRAILER_KIND_MAX_LEN[TRAILER_KIND_NAME]!
  for (const nb of nameBundles) {
    if (nb.length > nameCap) {
      throw new Error(`name bundle ${nb.length} B exceeds firmware cap ${nameCap} B`)
    }
  }

  let lastNonEmpty = -1
  for (let i = trailers.length - 1; i >= 0; i--) {
    if (trailers[i]!.len > 0) {
      lastNonEmpty = i
      break
    }
  }
  // The kind-8 names section is positional slot 8 (after the 7
  // length-prefixed trailers). To include it we must emit the prefixes for
  // all 7 preceding trailers (0x0000 for any omitted), then frame it as
  // `[count u8] + count × (u16 BE len + bundle)`. Omit the whole section
  // (not even a count byte) when empty — the device treats its absence as
  // a zero-trailer request, distinct from a `0x00` empty count.
  if (nameBundles.length > 0) lastNonEmpty = trailers.length - 1
  const tail: Uint8Array[] = [head]
  for (let i = 0; i <= lastNonEmpty; i++) {
    const t = trailers[i]!
    tail.push(u16be(t.len))
    if (t.bytes && t.len > 0) tail.push(t.bytes)
  }
  if (nameBundles.length > 0) {
    tail.push(new Uint8Array([nameBundles.length & 0xff]))
    for (const nb of nameBundles) tail.push(u16be(nb.length), nb)
  }
  return concatBytes(tail)
}

/** One inner call inside a batch, plus the optional clear-signing
 *  trailers that should be routed to *this* call by the firmware. The
 *  trailers mirror the single-tx encoder's surface — every kind the
 *  single-tx path accepts can now be attached per inner tx.
 *
 *  `selectorBundle` and `selfAttestBundle` are mutually exclusive per
 *  call (the firmware refuses payloads with both present for the same
 *  `tx_idx`). */
export type BatchInnerCall = {
  to: `0x${string}`
  value: bigint | number | string
  data?: Uint8Array
  erc20Bundle?: Uint8Array
  zkV3Bundle?: Uint8Array
  safeV1Bundle?: Uint8Array
  selectorBundle?: Uint8Array
  selfAttestBundle?: Uint8Array
  erc7730Bundle?: Uint8Array
}

export type BatchSignRequestParams = Omit<
  SignRequestParams,
  | 'to'
  | 'value'
  | 'data'
  | 'erc20Bundle'
  | 'zkV3Bundle'
  | 'safeV1Bundle'
  | 'selectorBundle'
  | 'selfAttestBundle'
  | 'erc7730Bundle'
> & {
  calls: BatchInnerCall[]
  /** Up to `MAX_NAME_BUNDLES` address-name bundles, applied across every
   *  inner tx (resolver lookups key on `(chain_id, address)`). */
  nameBundles?: Uint8Array[]
}

/** Per-kind length caps. Mirrors the secure-side dispatch table in
 *  `secure/src/nsc/batch_trailers.rs::MAX_LEN_PER_KIND`. The companion
 *  enforces these client-side so a malformed payload never even leaves
 *  the host. */
const TRAILER_KIND_MAX_LEN: Record<number, number> = {
  [TRAILER_KIND_ERC20]: 64 + 1024 + 32, // 1120
  // kind 2 (legacy zk_v1) is retired — the host never sends it; see config.ts.
  // kind-3 CoW (fw 05f9758a): canonical(204) + two length-prefixed kind-1
  // ERC-20 leg bundles. No proof/VK anymore — COW_ORDER_TRAILER_MAX_LEN =
  // 204 + 2 + MAX_ERC20_BUNDLE_LEN + 2 + MAX_ERC20_BUNDLE_LEN.
  [TRAILER_KIND_ZK_V3]: 204 + 2 + 1120 + 2 + 1120, // 2448
  [TRAILER_KIND_SAFE_V1]: 281 + 2 + 4096, // 4379
  [TRAILER_KIND_SEL_CURATED]: 1156,
  [TRAILER_KIND_SEL_SELFATTEST]: 68,
  [TRAILER_KIND_ERC7730]: ERC7730_MAX_TRAILER_LEN,
  // Names cap matches `MAX_NAME_BUNDLE_LEN`; bumping in lockstep with
  // firmware's `tx/src/names/bundle.rs`. Conservative cap chosen here.
  [TRAILER_KIND_NAME]: 1156
}

type TrailerRecord = { kind: number; txIdx: number; bytes: Uint8Array }

function pushPerCallTrailer(
  out: TrailerRecord[],
  txIdx: number,
  kind: number,
  bytes?: Uint8Array
): void {
  if (!bytes || bytes.length === 0) return
  const cap = TRAILER_KIND_MAX_LEN[kind]
  if (cap === undefined) throw new Error(`unknown trailer kind ${kind}`)
  if (bytes.length > cap) {
    throw new Error(
      `trailer kind ${kind} for tx_idx=${txIdx} exceeds firmware cap: ${bytes.length} > ${cap}`
    )
  }
  out.push({ kind, txIdx, bytes })
}

export function buildSignBatchPayload(p: BatchSignRequestParams): Uint8Array {
  if (!Array.isArray(p.calls) || p.calls.length === 0) {
    throw new Error('SIGN_USEROP_BATCH: calls[] must be non-empty')
  }
  if (p.calls.length > MAX_BATCH_TXS) {
    throw new Error(`SIGN_USEROP_BATCH: too many calls (${p.calls.length} > ${MAX_BATCH_TXS})`)
  }

  // Header: identical to v1 layout up to offset 276 (see
  // buildCommonHeader), where the new wire-version byte lives.
  // `batch_count` shifts to offset 277.
  const head = concatBytes([
    buildCommonHeader(p),
    new Uint8Array([SIGN_USEROP_BATCH_WIRE_VERSION & 0xff]),
    new Uint8Array([p.calls.length & 0xff])
  ])

  // Walk inner calls: emit per-call bytes + collect routed trailer
  // records. Validation (mutual exclusion, per-kind cap) lives in
  // pushPerCallTrailer; the parser on the firmware enforces the same
  // gates so a buggy host-side encoder can't bypass.
  const innerChunks: Uint8Array[] = []
  const trailerRecords: TrailerRecord[] = []

  for (let txIdx = 0; txIdx < p.calls.length; txIdx++) {
    const c = p.calls[txIdx]!
    const to = hexToBytes(c.to)
    if (to.length !== 20) throw new Error(`inner call ${txIdx}: to must be 20 bytes`)
    const data = c.data ?? new Uint8Array(0)
    if (data.length > MAX_TX_LEN) {
      throw new Error(`inner call ${txIdx} data too long (${data.length} > ${MAX_TX_LEN})`)
    }
    innerChunks.push(to, u256be(c.value), u16be(data.length), data)

    if (
      c.selectorBundle &&
      c.selectorBundle.length > 0 &&
      c.selfAttestBundle &&
      c.selfAttestBundle.length > 0
    ) {
      throw new Error(
        `inner call ${txIdx}: selectorBundle and selfAttestBundle are mutually exclusive`
      )
    }

    // Downgrade-mitigation gates — mirror firmware aborts in
    // secure/src/nsc/cmd_sign_userop_batch.rs. Refuse host-side so the
    // user sees a clear error before the device rejects the payload.
    if (isCowPresignClaim(c.to.toLowerCase(), data) && !(c.zkV3Bundle && c.zkV3Bundle.length > 0)) {
      throw new Error(
        `inner call ${txIdx}: CoW setPreSignature requires a zkV3Bundle (firmware downgrade-mitigation gate)`
      )
    }
    if (decodeApproveHash(data) !== null && !(c.safeV1Bundle && c.safeV1Bundle.length > 0)) {
      throw new Error(
        `inner call ${txIdx}: Safe approveHash requires a safeV1Bundle (firmware downgrade-mitigation gate)`
      )
    }
    // Safe-wrapped CoW presign ("CoW sign: v3 required (batch)"): a Safe
    // flow whose SafeTx inner call is setPreSignature on GPv2Settlement
    // — directly, or as the unique presign record inside an allowlisted
    // MultiSendCallOnly batch — needs a zk_v3 trailer routed to this
    // same tx_idx, bound to the presign calldata with uid.owner == the
    // Safe. Record order doesn't matter — the firmware verifies ZK v3
    // in a second pass. A claimed multiSend violating a hard rule
    // refuses outright (no trailer can fix it).
    const wrappedBinding = safeWrappedCowBinding(data, c.safeV1Bundle ?? new Uint8Array(0))
    if (wrappedBinding.kind === 'refuse') {
      throw new Error(
        `inner call ${txIdx}: Safe multiSend batch refused by PQ1 firmware ("Safe sign / ${wrappedBinding.banner}") — no trailer can fix it; adjust the batch`
      )
    }
    if (wrappedBinding.kind === 'bind' && !(c.zkV3Bundle && c.zkV3Bundle.length > 0)) {
      throw new Error(
        `inner call ${txIdx}: Safe-wrapped CoW setPreSignature requires a zkV3Bundle routed to the same tx_idx (firmware downgrade-mitigation gate)`
      )
    }

    pushPerCallTrailer(trailerRecords, txIdx, TRAILER_KIND_ERC20, c.erc20Bundle)
    pushPerCallTrailer(trailerRecords, txIdx, TRAILER_KIND_ZK_V3, c.zkV3Bundle)
    pushPerCallTrailer(trailerRecords, txIdx, TRAILER_KIND_SAFE_V1, c.safeV1Bundle)
    pushPerCallTrailer(trailerRecords, txIdx, TRAILER_KIND_SEL_CURATED, c.selectorBundle)
    pushPerCallTrailer(trailerRecords, txIdx, TRAILER_KIND_SEL_SELFATTEST, c.selfAttestBundle)
    pushPerCallTrailer(trailerRecords, txIdx, TRAILER_KIND_ERC7730, c.erc7730Bundle)
  }

  // Batch-wide name bundles (kind 8, tx_idx = 0xff).
  const nameBundles = p.nameBundles ?? []
  if (nameBundles.length > MAX_NAME_BUNDLES) {
    throw new Error(
      `nameBundles ${nameBundles.length} exceeds MAX_NAME_BUNDLES ${MAX_NAME_BUNDLES}`
    )
  }
  for (const nb of nameBundles) {
    pushPerCallTrailer(trailerRecords, TRAILER_TX_IDX_BATCH_WIDE, TRAILER_KIND_NAME, nb)
  }

  if (trailerRecords.length > MAX_TRAILERS_PER_BATCH) {
    throw new Error(
      `trailer count ${trailerRecords.length} exceeds MAX_TRAILERS_PER_BATCH ${MAX_TRAILERS_PER_BATCH}`
    )
  }
  let totalTrailerBytes = 0
  for (const r of trailerRecords) totalTrailerBytes += r.bytes.length
  if (totalTrailerBytes > TRAILERS_TOTAL_MAX_LEN) {
    throw new Error(
      `total trailer bytes ${totalTrailerBytes} exceeds TRAILERS_TOTAL_MAX_LEN ${TRAILERS_TOTAL_MAX_LEN}`
    )
  }

  // TLV-tagged trailer list: `[u8 count][count × {u8 kind, u8 tx_idx,
  // u16 BE len, [len bytes]}]`. The firmware refuses any trailing
  // bytes past the last record, so the terminator is implicit.
  const trailerChunks: Uint8Array[] = [new Uint8Array([trailerRecords.length & 0xff])]
  for (const r of trailerRecords) {
    trailerChunks.push(
      new Uint8Array([r.kind & 0xff, r.txIdx & 0xff]),
      u16be(r.bytes.length),
      r.bytes
    )
  }

  return concatBytes([head, ...innerChunks, ...trailerChunks])
}
