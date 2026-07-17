// Detect + decode Safe v1.3.0+ `execTransaction(...)` calldata.
//
// Unlike `approveHash`, no trailer is required: the SafeTx fields are
// encoded directly into the function arguments and the PQ1 firmware
// decodes them in `secure/src/tx/eip712/safe/exec_decode.rs`. The host
// needs to:
//   1. Recognise the selector so it can skip the ERC-7730 lookup (the
//      firmware's safe-exec renderer takes priority over erc7730 in
//      `pick_sign_pages`).
//   2. Gate `operation == 1` (DelegateCall) fail-fast — signable only
//      as an allowlisted MultiSendCallOnly batch (`safe/multiSend.ts`,
//      companion-safe-cowswap-multisend.md); any other target the
//      firmware refuses with `Safe sign: exec parse fail`.
//   3. Decode the SafeTx inner `(to, operation, data)` so the
//      Safe-wrapped CoW presign seam (`aa/broadcast.ts` + the
//      signRequest downgrade gates) can attach the mandatory `zk_v3`
//      trailer when the inner call is `setPreSignature` on
//      GPv2Settlement — directly or as the unique presign record of a
//      multiSend batch — see companion-safe-cowswap-presign.md and
//      -multisend.md.
//
// `decodeExecTransaction` mirrors the firmware decoder's acceptance
// rules byte-for-byte so host routing keyed on it cannot diverge from
// the device: both sides either decode the same inner call or both
// refuse.

import { readU32Word, selectorMatches } from '../transport/bytes'

/** `keccak256("execTransaction(address,uint256,bytes,uint8,uint256,uint256,uint256,address,address,bytes)")[..4]`. */
export const SAFE_EXEC_TRANSACTION_SELECTOR = new Uint8Array([0x6a, 0x76, 0x12, 0x02])

/** Min calldata length: selector(4) + 10 head words(320) + 2 dynamic-length words(64). */
export const SAFE_EXEC_TRANSACTION_MIN_CALLDATA_LEN = 4 + 10 * 32 + 2 * 32

export function isExecTransactionSelector(data: Uint8Array): boolean {
  return selectorMatches(data, SAFE_EXEC_TRANSACTION_SELECTOR)
}

/** True for any calldata whose selector matches execTransaction AND whose
 *  length is at least the ABI minimum. Matches the firmware's downgrade-
 *  gate trigger in `cmd_sign_userop.rs` so the host's fast-fail aligns
 *  with the device's refuse-to-sign behaviour. */
export function isSafeExecTransaction(data: Uint8Array): boolean {
  return data.length >= SAFE_EXEC_TRANSACTION_MIN_CALLDATA_LEN && isExecTransactionSelector(data)
}

/** Read the `operation` enum byte without validating the rest of the ABI
 *  encoding. The firmware enforces full strictness; we only need this for
 *  the early DelegateCall reject. Returns null when the calldata is too
 *  short or the selector doesn't match. */
export function readExecTransactionOperation(data: Uint8Array): number | null {
  if (!isSafeExecTransaction(data)) return null
  // operation is uint8 at head word index 3, ABI-padded → low byte at
  // offset selector(4) + 3*32 + 31 = 4 + 96 + 31 = 131.
  return data[131] ?? null
}

/** The SafeTx fields the Safe-wrapped CoW seam needs out of an
 *  `execTransaction` call. `data` is a subarray view of the input —
 *  don't mutate. */
export interface DecodedExecTransaction {
  /** Lower-cased 0x-hex inner-call target. */
  to: `0x${string}`
  value: bigint
  /** 0 = Call, 1 = DelegateCall (range-checked; the firmware's verifier
   *  accepts 1 only for an allowlisted MultiSendCallOnly batch, the
   *  host mirrors the gate in `aa/broadcast.ts`). */
  operation: number
  /** Exact SafeTx `data` bytes (the calldata the Safe forwards on-chain). */
  data: Uint8Array
}

const EXEC_HEAD_WORDS = 10

/** Strict ABI decode of `execTransaction(...)`, mirroring the firmware's
 *  `exec_decode.rs::decode_exec_transaction` acceptance rules exactly:
 *
 *    * canonical address words for `to` / `gasToken` / `refundReceiver`
 *      (top 12 bytes zero);
 *    * `operation` word top-31-bytes zero and value ∈ {0, 1};
 *    * offset / length words fit in u32 (top 28 bytes zero);
 *    * both dynamic tails (`data`, `signatures`) start at or after the
 *      320-byte head and their `offset + 32 + len` stays in bounds.
 *
 *  Returns null on any violation — the same inputs the firmware refuses
 *  with `Safe sign: exec parse fail`. */
export function decodeExecTransaction(cd: Uint8Array): DecodedExecTransaction | null {
  if (!isSafeExecTransaction(cd)) return null
  const head = cd.subarray(4)

  const to = readAddressWord(head, 0)
  if (to === null) return null
  const value = readU256Word(head, 1)
  const dataOff = readOffsetWord(head, 2)
  if (dataOff === null) return null
  // operation: uint8 left-padded to 32 — top 31 bytes must be zero.
  for (let i = 3 * 32; i < 3 * 32 + 31; i++) if (head[i] !== 0) return null
  const operation = head[3 * 32 + 31]!
  if (operation > 1) return null
  // Head words 4..6 (safeTxGas, baseGas, gasPrice) accept any u256.
  if (readAddressWord(head, 7) === null) return null // gasToken
  if (readAddressWord(head, 8) === null) return null // refundReceiver
  const sigsOff = readOffsetWord(head, 9)
  if (sigsOff === null) return null

  const data = readDynamicBytes(head, dataOff)
  if (data === null) return null
  // `signatures` is unused by the host but its framing is part of the
  // firmware's acceptance set — validate it so the two sides agree.
  if (readDynamicBytes(head, sigsOff) === null) return null

  return { to, value, operation, data }
}

/** Canonical `address` word: top 12 bytes zero, low 20 bytes returned as
 *  lower-cased hex. Null on a non-canonical word (firmware refuses). */
function readAddressWord(head: Uint8Array, wordIdx: number): `0x${string}` | null {
  const off = wordIdx * 32
  for (let i = 0; i < 12; i++) if (head[off + i] !== 0) return null
  let s = '0x'
  for (let i = 12; i < 32; i++) s += head[off + i]!.toString(16).padStart(2, '0')
  return s as `0x${string}`
}

function readU256Word(head: Uint8Array, wordIdx: number): bigint {
  const off = wordIdx * 32
  let v = 0n
  for (let i = 0; i < 32; i++) v = (v << 8n) | BigInt(head[off + i]!)
  return v
}

/** Offset / length word: must fit in u32 (top 28 bytes zero). */
function readOffsetWord(head: Uint8Array, wordIdx: number): number | null {
  return readU32Word(head, wordIdx * 32)
}

/** Dynamic `bytes` tail at `head[offset..]`: `[u256 len][len bytes]`. The
 *  tail must sit at or after the 320-byte head (canonical Solidity
 *  encoding) and stay fully in bounds — mirrors the firmware's
 *  `read_dynamic_bytes`. */
function readDynamicBytes(head: Uint8Array, offset: number): Uint8Array | null {
  if (offset < EXEC_HEAD_WORDS * 32) return null
  if (offset + 32 > head.length) return null
  // Length word must itself fit in u32.
  const len = readU32Word(head, offset)
  if (len === null) return null
  const start = offset + 32
  if (start + len > head.length) return null
  return head.subarray(start, start + len)
}
