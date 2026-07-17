// SIGN_USEROP response parser.
// Wire format defined at
// sphincs_rust/secure/src/nsc/cmd_sign_userop.rs:1048-1072.

import { readU32Be } from './bytes'

export type SignBundle = {
  /** Firmware-tracked off-chain sig counter for this slot. Must be embedded
   * in the submitted callData (`executeWithOffchainCount` arg 1). */
  newOffchainCount: bigint
  /** 4280-byte factory initCode, present when FLAG_INCLUDE_INIT_CODE was set. */
  initCode: Uint8Array | null
  /** 4128-byte `abi.encode(uint256 ownerIndex, bytes signature)` wrapper for
   *  the bootstrap key (ownerIndex=0). Present on slot rotation. */
  type1: Uint8Array | null
  /** 4128-byte `abi.encode(uint256 ownerIndex, bytes signature)` wrapper for
   *  the active slot (ownerIndex=slotIndex+1). Always present. */
  type2: Uint8Array
}

/** Guarded u32 length-word read. Reading past the end of the buffer would
 *  produce `NaN` (undefined bytes), and `off + NaN > resp.length` is false —
 *  so an unguarded read lets a truncated response slip through the payload
 *  bounds checks below and silently yield an empty signature. */
function readLenWord(resp: Uint8Array, off: number, what: string): number {
  if (off + 4 > resp.length) throw new Error(`sign response truncated (${what} length)`)
  return readU32Be(resp, off)
}

export function parseSignResponse(resp: Uint8Array): SignBundle {
  if (resp.length < 8 + 4 + 4 + 4) throw new Error('sign response too short')

  let newOffchainCount = 0n
  for (let i = 0; i < 8; i++) {
    newOffchainCount = (newOffchainCount << 8n) | BigInt(resp[i]!)
  }
  let off = 8

  const icLen = readLenWord(resp, off, 'initCode')
  off += 4
  let initCode: Uint8Array | null = null
  if (icLen > 0) {
    if (off + icLen > resp.length) throw new Error('sign response truncated (initCode)')
    initCode = resp.slice(off, off + icLen)
    off += icLen
  }

  const t1Len = readLenWord(resp, off, 'type1')
  off += 4
  let type1: Uint8Array | null = null
  if (t1Len > 0) {
    if (off + t1Len > resp.length) throw new Error('sign response truncated (type1)')
    type1 = resp.slice(off, off + t1Len)
    off += t1Len
  }

  const t2Len = readLenWord(resp, off, 'type2')
  off += 4
  if (t2Len === 0) throw new Error('sign response missing type2 signature')
  if (off + t2Len > resp.length) throw new Error('sign response truncated (type2)')
  const type2 = resp.slice(off, off + t2Len)

  return { newOffchainCount, initCode, type1, type2 }
}

/** Decode the ownerIndex (first 32 bytes) of an abi.encode-wrapped sig. */
export function wrapperOwnerIndex(wrapper: Uint8Array): bigint {
  if (wrapper.length < 32) throw new Error('wrapper too short')
  let n = 0n
  for (let i = 0; i < 32; i++) n = (n << 8n) | BigInt(wrapper[i]!)
  return n
}
