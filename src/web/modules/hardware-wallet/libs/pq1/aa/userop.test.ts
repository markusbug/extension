// Regression tests for the gas-estimation dummy signature (`forEstimate`).
//
// The OOG bug these lock down: the dummy wrapper used to hardcode
// ownerIndex=1, but the callData carries the wallet's *real* active
// ownerIndex. PQSmartWallet._validateSignature enforces an H-3 parity check
// (`_calldataOwnerIndex(callData) == wrapper ownerIndex`); a mismatch makes
// validation bail before stamping the execution-phase credit, so the
// simulated execution reverts with OwnerIndexMismatch() and Pimlico can't
// return a callGasLimit — the extension then shipped a 50k fallback that
// OOG'd on-chain. `forEstimate` must now mirror the callData's ownerIndex.

import { C10_SIG_LEN, SIG_WRAPPER_LEN, VERIFIER_STUB_RETURN_TRUE_CODE } from '../config'
import { buildUserOp, forEstimate, type UserOpJson } from './userop'

const unhex = (s: string): Uint8Array => Uint8Array.from(Buffer.from(s.replace(/^0x/, ''), 'hex'))

function baseOp(): UserOpJson {
  return buildUserOp({
    sender: '0x0000000000000000000000000000000000000160',
    nonce: 0n,
    initCode: new Uint8Array(0),
    callData: '0x',
    callGasLimit: 0n,
    verificationGasLimit: 0n,
    preVerificationGas: 0n,
    maxFeePerGas: 0n,
    maxPriorityFeePerGas: 0n,
    signature: new Uint8Array(0)
  })
}

function readWordBE(sig: Uint8Array, wordIdx: number): bigint {
  let v = 0n
  for (let i = 0; i < 32; i++) v = (v << 8n) | BigInt(sig[wordIdx * 32 + i]!)
  return v
}

describe('forEstimate dummy signature', () => {
  it('emits a structurally valid abi.encode(uint256 ownerIndex, bytes) envelope', () => {
    const sig = unhex(forEstimate(baseOp(), 1n).signature)
    expect(sig.length).toBe(SIG_WRAPPER_LEN)
    // word 1 = offset to the bytes arg (0x40); word 2 = inner length.
    expect(readWordBE(sig, 1)).toBe(0x40n)
    expect(readWordBE(sig, 2)).toBe(BigInt(C10_SIG_LEN))
    // inner payload is all 0xff; the 24-byte ABI tail-pad must be zero (the
    // wallet's audit L-1 malleability check rejects a non-zero pad).
    for (let i = 96; i < 96 + C10_SIG_LEN; i++) expect(sig[i]).toBe(0xff)
    for (let i = 96 + C10_SIG_LEN; i < SIG_WRAPPER_LEN; i++) expect(sig[i]).toBe(0x00)
  })

  it('writes the supplied ownerIndex into the first word (H-3 parity)', () => {
    for (const idx of [0n, 1n, 2n, 3n, 255n, 4096n]) {
      const sig = unhex(forEstimate(baseOp(), idx).signature)
      expect(readWordBE(sig, 0)).toBe(idx)
    }
  })

  it('does NOT hardcode ownerIndex=1 for a rotated-owner wallet', () => {
    // The exact case that OOG'd: active ownerIndex != 1.
    const sig = unhex(forEstimate(baseOp(), 3n).signature)
    expect(readWordBE(sig, 0)).toBe(3n)
    expect(readWordBE(sig, 0)).not.toBe(1n)
  })

  it('leaves every other UserOp field untouched', () => {
    const op = baseOp()
    const out = forEstimate(op, 1n)
    expect({ ...out, signature: '' }).toEqual({ ...op, signature: '' })
  })
})

// The estimation override stubs the SPHINCS+ verifier with a contract that
// returns ABI `true` for any call. A subtle bug here (an extra PUSH1 0x00
// before RETURN) makes RETURN read (offset=0, size=0) and return ZERO bytes;
// `try c10Verifier.verify() returns (bool)` then can't decode a bool and the
// whole validateUserOp reverts with empty data — re-breaking estimation. This
// was caught only by a live on-chain trace, so lock the exact bytecode:
//   60 01      PUSH1 0x01
//   60 00      PUSH1 0x00
//   52         MSTORE        ; mem[0..32] = 0x..01
//   60 20      PUSH1 0x20    ; size = 32
//   60 00      PUSH1 0x00    ; offset = 0
//   f3         RETURN        ; returns mem[0..32] == abi-encoded true
describe('VERIFIER_STUB_RETURN_TRUE_CODE', () => {
  it('is the 10-byte "return 32-byte true" runtime, not the empty-return variant', () => {
    expect(VERIFIER_STUB_RETURN_TRUE_CODE).toBe('0x600160005260206000f3')
    const bytes = VERIFIER_STUB_RETURN_TRUE_CODE.slice(2)
    expect(bytes.length / 2).toBe(10) // NOT 12 — the extra 6000 was the bug
    expect(bytes.endsWith('f3')).toBe(true) // RETURN
    // RETURN's two stack args come from the last two pushes: size then offset.
    // Must be PUSH1 0x20 (size) then PUSH1 0x00 (offset), i.e. "60206000".
    expect(bytes.endsWith('60206000f3')).toBe(true)
  })
})
