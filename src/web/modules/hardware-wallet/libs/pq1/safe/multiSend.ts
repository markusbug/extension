// Host-side mirror of the PQ1 firmware's strict Safe `MultiSendCallOnly`
// decoder + acceptance verdict (`secure/src/tx/eip712/safe/multi_send.rs`)
// and of the CoW-binding resolver's Safe arm
// (`secure/src/tx/eip712/safe/cow_binding.rs::resolve_safe_arm`) — see
// companion-safe-cowswap-multisend.md.
//
// The Safe web UI wraps any flow needing more than one action in
// `SafeTx{to = MultiSendCallOnly, operation = 1 (DELEGATECALL),
// data = multiSend(transactions)}` — e.g. a CoW order placement is
// `[ERC-20 approve(GPv2VaultRelayer, amount), setPreSignature(uid, true)]`.
// The firmware clear-signs exactly that shape under hard rules (target
// allowlist, canonical ABI framing, per-record operation == 0, 1..=6
// records, at most one presign record) and refuses everything else with
// the `msend *` banners. The host mirrors the rules byte-for-byte so its
// trailer routing and fail-fast errors cannot desync from the device:
// both sides either decode the same records or both refuse.
//
// Pure byte-parsing with no dependency chain beyond `transport/bytes` —
// safe to import from `transport/signRequest.ts` (loaded at
// background-worker startup), like `safe/execCalldata.ts`.

import { readU32Word, selectorMatches } from '../transport/bytes'

/** `keccak256("multiSend(bytes)")[..4]`. Mirrors `MULTI_SEND_SELECTOR`
 *  in the firmware's `proto/src/lib.rs`. */
export const MULTI_SEND_SELECTOR = new Uint8Array([0x8d, 0x80, 0xff, 0x0a])

/** Canonical `MultiSendCallOnly` deployments the firmware accepts as a
 *  SafeTx DELEGATECALL target (source: safe-global/safe-deployments;
 *  CREATE2-deployed, address-identical on every chain of each variant).
 *  Plain `MultiSend` (delegatecall-capable records) and zkSync variants
 *  are deliberately NOT listed — mirrors the firmware's
 *  `MULTISEND_CALL_ONLY_ADDRESSES`. */
export const MULTISEND_CALL_ONLY_ADDRESSES_LC: readonly string[] = [
  '0x40a2accbd92bca938b02010e17a5b8929b49130d', // v1.3.0 canonical
  '0xa1dabef33b3b82c7814b6d82a79e50f4ac44102b', // v1.3.0 eip155
  '0x9641d764fc13c8b624c04430c7356c1c7c8102e2', // v1.4.1 canonical
  '0xa83c336b20401af773b6219ba5027174338d1836' // v1.5.0 canonical
]

/** Firmware decode-loop cap (`MULTISEND_MAX_RECORDS`). The trusted
 *  display's 24-page budget is the real binding constraint; this bounds
 *  the record walk. */
export const MULTISEND_MAX_RECORDS = 6

// CoW presign-claim constants, duplicated from `cowswap/eip712.ts` /
// `cowswap/calldata.ts` to keep this module free of the viem dependency
// chain (same rationale as `transport/signRequest.ts`, which imports the
// predicate from here).
const GPV2_SETTLEMENT_ADDRESS_LC = '0x9008d19f58aabd9ed0d60971565aa8510560ab41'
const SET_PRE_SIGNATURE_SELECTOR = new Uint8Array([0xec, 0x6c, 0xb1, 0x3f])

/** Fixed per-record header: `operation(1) || to(20) || value(32) ||
 *  dataLen(32)`, followed by `data(dataLen)`. Packed — no padding
 *  between records. */
const MS_RECORD_HEADER_LEN = 1 + 20 + 32 + 32

/** Mirror of the firmware's CoW-gate predicate
 *  (`cow_binding.rs::safe_inner_is_cow_presign`): GPv2Settlement target +
 *  setPreSignature selector. Deliberately fires for malformed calldata
 *  too — those must refuse loudly (`CoW sign: v3 required`), not fall
 *  through to a blind-sign page. */
export function isCowPresignClaim(toLcHex: string, data: Uint8Array): boolean {
  if (toLcHex !== GPV2_SETTLEMENT_ADDRESS_LC) return false
  return selectorMatches(data, SET_PRE_SIGNATURE_SELECTOR)
}

export function isAllowlistedMultiSendCallOnly(toLcHex: string): boolean {
  return MULTISEND_CALL_ONLY_ADDRESSES_LC.includes(toLcHex)
}

/** Does this SafeTx inner call claim to be an allowlisted multiSend
 *  batch? `operation == 1` is part of the predicate on purpose: under
 *  CALL the MultiSend contract — not the Safe — is `msg.sender` for
 *  every record, so the firmware leaves op-0 calls to MultiSend
 *  addresses on the ordinary loud blind-sign path. Like
 *  `isCowPresignClaim`, this does NOT shape-check the payload — the
 *  claim must also fire for a malformed blob so it refuses loudly
 *  instead of degrading to blind-sign. Mirrors
 *  `multi_send.rs::is_multisend_claim`. */
export function isMultiSendClaim(operation: number, toLcHex: string, data: Uint8Array): boolean {
  if (operation !== 1) return false
  if (!isAllowlistedMultiSendCallOnly(toLcHex)) return false
  if (data.length < MULTI_SEND_SELECTOR.length) return false
  for (let i = 0; i < MULTI_SEND_SELECTOR.length; i++) {
    if (data[i] !== MULTI_SEND_SELECTOR[i]) return false
  }
  return true
}

/** One packed multiSend record. `data` is a subarray view of the input
 *  calldata — don't mutate. */
export interface MultiSendRecord {
  /** Raw operation byte — `summarizeMultiSend` rejects anything but 0;
   *  reported verbatim so tests can probe the rejection. */
  operation: number
  /** Lower-cased 0x-hex record target. */
  to: `0x${string}`
  /** Native value forwarded with the record's call. */
  value: bigint
  data: Uint8Array
}

/** OLED status-line reasons, byte-identical to the firmware's refusal
 *  banners (`MsError::as_status_str` + the verdict's ambiguity case) so
 *  host errors quote exactly what the device would show. */
export type MultiSendRejectBanner =
  | 'msend malformed'
  | 'msend rec op!=0'
  | 'msend rec to=0'
  | 'msend rec count'
  | 'msend 2+ presign'

export interface MultiSendSummary {
  records: MultiSendRecord[]
  /** Indexes of records claiming a CoW `setPreSignature` (target ==
   *  GPv2Settlement, selector match). Exactly one zk_v3 trailer rides a
   *  sign request, so only 0 (generic batch) and 1 (CoW flow) are
   *  signable; >= 2 is refused by `multiSendVerdict`. */
  presignRecordIndexes: number[]
}

/** Strictly decode `multiSend(bytes)` calldata down to the packed
 *  records slice. Canonical-encoding-only, mirroring the firmware's
 *  `decode_multisend`: head offset exactly 0x20, total calldata length
 *  exactly `4 + 64 + ceil32(payload)`, zero padding. Returns null on any
 *  violation — the inputs the device refuses with `msend malformed`. */
export function decodeMultiSend(data: Uint8Array): Uint8Array | null {
  if (data.length < 4 + 64) return null
  for (let i = 0; i < 4; i++) if (data[i] !== MULTI_SEND_SELECTOR[i]) return null
  const head = data.subarray(4)
  // Offset word: the canonical encoding of a single dynamic `bytes`
  // argument always places the tail immediately after the one-word
  // head, i.e. offset == 32.
  if (readU32Word(head, 0) !== 32) return null
  const len = readU32Word(head, 32)
  if (len === null) return null
  const payloadStart = 64
  const payloadEnd = payloadStart + len
  if (payloadEnd > head.length) return null
  // Exact-length + zero-padding: Solidity pads the bytes tail to a
  // 32-byte boundary with zeros and emits nothing after it.
  const paddedEnd = Math.ceil(payloadEnd / 32) * 32
  if (head.length !== paddedEnd) return null
  for (let i = payloadEnd; i < paddedEnd; i++) if (head[i] !== 0) return null
  return head.subarray(payloadStart, payloadEnd)
}

/** Walk the packed records slice. Mirrors the firmware's
 *  `MsRecordIter`: the cursor must land exactly on the slice end — a
 *  partial trailing record, an out-of-range `dataLen`, or a `dataLen`
 *  with bits above u32 returns null (`msend malformed`). Record count
 *  and per-record operation are NOT validated here — that is
 *  `summarizeMultiSend`'s job, so the two refusals keep their distinct
 *  banners. */
export function walkMultiSendRecords(packed: Uint8Array): MultiSendRecord[] | null {
  const records: MultiSendRecord[] = []
  let cursor = 0
  while (cursor < packed.length) {
    const rest = packed.subarray(cursor)
    if (rest.length < MS_RECORD_HEADER_LEN) return null
    const operation = rest[0]!
    let to = '0x'
    for (let i = 1; i < 21; i++) to += rest[i]!.toString(16).padStart(2, '0')
    let value = 0n
    for (let i = 21; i < 53; i++) value = (value << 8n) | BigInt(rest[i]!)
    const dataLen = readU32Word(rest, 53)
    if (dataLen === null) return null
    const dataEnd = MS_RECORD_HEADER_LEN + dataLen
    if (dataEnd > rest.length) return null
    records.push({
      operation,
      to: to as `0x${string}`,
      value,
      data: rest.subarray(MS_RECORD_HEADER_LEN, dataEnd)
    })
    cursor += dataEnd
  }
  return records
}

const ZERO_ADDRESS_LC = '0x0000000000000000000000000000000000000000'

/** Decode + validate the payload's hard rules: strict framing, 1..=
 *  `MULTISEND_MAX_RECORDS` records, every record `operation == 0` and
 *  `to != 0x0`.
 *  Returns the banner string on violation — mirrors the firmware's
 *  `summarize` error mapping. Presign claims are counted selector-level
 *  only (the full 164-byte shape stays in the CoW pipeline, so a
 *  malformed or `signed == false` presign refuses loudly there instead
 *  of blind-rendering). */
export function summarizeMultiSend(data: Uint8Array): MultiSendSummary | MultiSendRejectBanner {
  const packed = decodeMultiSend(data)
  if (packed === null) return 'msend malformed'
  const records = walkMultiSendRecords(packed)
  if (records === null) return 'msend malformed'
  // Per-record checks in the firmware's walk order — operation before
  // the count overflow — so a combined-violation batch quotes the same
  // banner on both sides.
  const presignRecordIndexes: number[] = []
  for (let i = 0; i < records.length; i++) {
    const r = records[i]!
    if (r.operation !== 0) return 'msend rec op!=0'
    // MultiSendCallOnly v1.5.0 rewrites `to == 0` to the Safe itself;
    // the firmware refuses it for every target (`MsError::RecordToZero`).
    if (r.to === ZERO_ADDRESS_LC) return 'msend rec to=0'
    if (i === MULTISEND_MAX_RECORDS) return 'msend rec count'
    if (isCowPresignClaim(r.to, r.data)) presignRecordIndexes.push(i)
  }
  if (records.length === 0) return 'msend rec count'
  return { records, presignRecordIndexes }
}

/** Handler-level acceptance verdict for a Safe context's inner call —
 *  mirror of `multi_send.rs::multisend_verdict`, shared by the trailer
 *  builders and the wire-layer gates so they cannot drift. */
export type MultiSendVerdict =
  | { kind: 'not-multisend' }
  | { kind: 'accept'; summary: MultiSendSummary }
  | { kind: 'reject'; banner: MultiSendRejectBanner }

export function multiSendVerdict(
  operation: number,
  toLcHex: string,
  data: Uint8Array
): MultiSendVerdict {
  if (!isMultiSendClaim(operation, toLcHex, data)) return { kind: 'not-multisend' }
  const summary = summarizeMultiSend(data)
  if (typeof summary === 'string') return { kind: 'reject', banner: summary }
  if (summary.presignRecordIndexes.length >= 2) {
    return { kind: 'reject', banner: 'msend 2+ presign' }
  }
  return { kind: 'accept', summary }
}

/** Which calldata must a CoW zk_v3 trailer bind to, for one Safe context
 *  reduced to its `(operation, inner_to, raw_data)` facts?
 *
 *    * `none`   — no CoW claim: a non-presign single call, or a
 *                 well-formed multiSend with zero presign records (a
 *                 generic batch needs no v3 trailer). Also returned for
 *                 an `operation == 1` context that is NOT an allowlisted
 *                 multiSend claim: the firmware's Safe verifiers refuse
 *                 that shape first (`Safe sign: safe_v1 required` / `exec
 *                 parse fail`), so it never reaches the CoW resolver.
 *    * `bind`   — build/require the v3 trailer against exactly these
 *                 bytes with `uid.owner == the Safe`: the full raw_data
 *                 for a direct presign, the unique presign record's 164
 *                 bytes inside a multiSend batch.
 *    * `refuse` — a claimed multiSend violating a hard rule. No trailer
 *                 can fix it; the device refuses with the quoted banner.
 *
 *  Mirrors `cow_binding.rs::resolve_safe_arm` filtered through the Safe
 *  verifiers' operation gates (the firmware only resolves verified
 *  contexts). */
export type SafeCowBinding =
  | { kind: 'none' }
  | { kind: 'bind'; calldata: Uint8Array }
  | { kind: 'refuse'; banner: MultiSendRejectBanner }

export function resolveSafeCowBinding(
  operation: number,
  toLcHex: string,
  rawData: Uint8Array
): SafeCowBinding {
  if (operation === 1) {
    const verdict = multiSendVerdict(operation, toLcHex, rawData)
    // Non-claim DELEGATECALL: the Safe verify refuses on-device before
    // the CoW gate — nothing for the host to bind or refuse here.
    if (verdict.kind === 'not-multisend') return { kind: 'none' }
    if (verdict.kind === 'reject') return { kind: 'refuse', banner: verdict.banner }
    const idx = verdict.summary.presignRecordIndexes[0]
    if (idx === undefined) return { kind: 'none' }
    return { kind: 'bind', calldata: verdict.summary.records[idx]!.data }
  }
  if (isCowPresignClaim(toLcHex, rawData)) return { kind: 'bind', calldata: rawData }
  return { kind: 'none' }
}

/** Human-readable companion fix per refusal banner — quotes the doc's
 *  table so the host error tells the user what the device would show
 *  AND how to resolve it. */
const MULTISEND_REJECT_FIX: Record<MultiSendRejectBanner, string> = {
  'msend malformed':
    'the multiSend(bytes) calldata is not the canonical Solidity encoding (offset/length/padding/record framing)',
  'msend rec op!=0':
    'a record nests a DELEGATECALL (per-record operation must be 0; MultiSendCallOnly would revert on-chain anyway)',
  'msend rec to=0':
    'a record targets the zero address (MultiSendCallOnly v1.5.0 would call the Safe itself) — address the record explicitly',
  'msend rec count': `the batch must contain 1..=${MULTISEND_MAX_RECORDS} records — split it into smaller SafeTxs`,
  'msend 2+ presign':
    'the batch contains two or more CoW setPreSignature records — one zk_v3 trailer can bind only one order per SafeTx'
}

/** Fail-fast mirror of the firmware's Safe operation gates
 *  (`verify.rs` step 6 / `exec_decode.rs::verify_and_bind_exec` +
 *  `multisend_sign_gate`): `operation == 1` is signable ONLY as an
 *  allowlisted `MultiSendCallOnly` batch that passes every multiSend
 *  hard rule. Throws with the on-device banner quoted so the user sees
 *  a clear error before the device refuses. */
export function assertSafeOperationSignable(
  operation: number,
  to: `0x${string}`,
  rawData: Uint8Array
): void {
  if (operation === 0) return
  if (operation !== 1) {
    throw new Error(`Safe operation=${operation} is out of range (0 = Call, 1 = DelegateCall)`)
  }
  const toLc = to.toLowerCase()
  if (!isMultiSendClaim(operation, toLc, rawData)) {
    throw new Error(
      'Safe DelegateCall is only supported by PQ1 firmware for a canonical MultiSendCallOnly ' +
        `batch — target ${to} with this calldata would be refused on-device ` +
        '(companion-safe-cowswap-multisend.md § Accepted multiSend shape).'
    )
  }
  const verdict = multiSendVerdict(operation, toLc, rawData)
  if (verdict.kind === 'reject') {
    throw new Error(
      `Safe multiSend batch refused by PQ1 firmware ("Safe sign / ${verdict.banner}"): ` +
        `${MULTISEND_REJECT_FIX[verdict.banner]}.`
    )
  }
}
