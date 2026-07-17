// PQSmartWallet factory helpers.

import { C10_SIG_LEN, FACTORY, FACTORY_CREATE_ACCOUNT_SELECTOR, PQ_INIT_CODE_LEN } from '../config'
import { bytesToHex0x, concatBytes, hexToBytes, u256be } from '../transport/bytes'

/**
 * Build a zero-filled 4280-byte factory initCode suitable for gas estimation.
 * Real bytes come back from SIGN_USEROP when FLAG_INCLUDE_INIT_CODE is set.
 * Layout: factory(20) ‖ selector(4) ‖ masterPkSeed(32) ‖ masterPkRoot(32)
 *   ‖ slot0PkSeed(32) ‖ slot0PkRoot(32) ‖ chainId(32) ‖ offset(32 = 0xC0)
 *   ‖ length(32 = 4008) ‖ factorySig(4008 padded to 4032)
 */
export function buildZeroInitCode(chainId: bigint | number): Uint8Array {
  const factoryBytes = hexToBytes(FACTORY)
  const chainIdBytes = u256be(chainId)
  const offsetWord = u256be(0xc0n)
  const lengthWord = u256be(BigInt(C10_SIG_LEN))
  const paddedSigLen = Math.ceil(C10_SIG_LEN / 32) * 32 // 4032
  const zeroed = new Uint8Array(paddedSigLen)

  const blob = concatBytes([
    factoryBytes,
    FACTORY_CREATE_ACCOUNT_SELECTOR,
    new Uint8Array(32),
    new Uint8Array(32),
    new Uint8Array(32),
    new Uint8Array(32),
    chainIdBytes,
    offsetWord,
    lengthWord,
    zeroed
  ])
  if (blob.length !== PQ_INIT_CODE_LEN) {
    throw new Error(`buildZeroInitCode: expected ${PQ_INIT_CODE_LEN} bytes, got ${blob.length}`)
  }
  return blob
}

export type InitCodeFields = {
  factory: `0x${string}`
  masterPkSeed: `0x${string}`
  masterPkRoot: `0x${string}`
  slot0PkSeed: `0x${string}`
  slot0PkRoot: `0x${string}`
}

export function parseInitCode(initCode: Uint8Array): InitCodeFields | null {
  if (initCode.length !== PQ_INIT_CODE_LEN) return null
  return {
    factory: bytesToHex0x(initCode.slice(0, 20)),
    masterPkSeed: bytesToHex0x(initCode.slice(24, 56)),
    masterPkRoot: bytesToHex0x(initCode.slice(56, 88)),
    slot0PkSeed: bytesToHex0x(initCode.slice(88, 120)),
    slot0PkRoot: bytesToHex0x(initCode.slice(120, 152))
  }
}
