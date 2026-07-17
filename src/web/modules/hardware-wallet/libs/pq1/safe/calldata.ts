// Detect and decode Safe `approveHash(bytes32)` calldata.
//
// The selector is `keccak256("approveHash(bytes32)")[..4] = 0xd4d9bdcd`.
// Total calldata length is 36 bytes (4 selector + 32 hash).

import { selectorMatches } from '../transport/bytes'

export const SAFE_APPROVE_HASH_SELECTOR = new Uint8Array([0xd4, 0xd9, 0xbd, 0xcd])

export const SAFE_APPROVE_HASH_CALLDATA_LEN = 36

export interface ApproveHashCall {
  /** Bytes 4..36 of the calldata — the SafeTx EIP-712 hash being approved. */
  safeTxHash: Uint8Array
}

export function isApproveHashSelector(data: Uint8Array): boolean {
  return selectorMatches(data, SAFE_APPROVE_HASH_SELECTOR)
}

/** Returns null when the calldata isn't a strict 36-byte `approveHash` call.
 *  The firmware enforces the same length check and any leniency here would
 *  surface as an opaque verifier failure on-device. */
export function decodeApproveHash(data: Uint8Array): ApproveHashCall | null {
  if (data.length !== SAFE_APPROVE_HASH_CALLDATA_LEN) return null
  if (!isApproveHashSelector(data)) return null
  return { safeTxHash: data.slice(4, 36) }
}
