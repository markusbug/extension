// ERC-4337 v0.6 UserOp builder for PQSmartWallet.

import { C10_SIG_LEN, SIG_WRAPPER_LEN } from '../config'
import { bytesToHex0x, u64be, u256be } from '../transport/bytes'

export type UserOpJson = {
  sender: `0x${string}`
  nonce: `0x${string}`
  initCode: `0x${string}`
  callData: `0x${string}`
  callGasLimit: `0x${string}`
  verificationGasLimit: `0x${string}`
  preVerificationGas: `0x${string}`
  maxFeePerGas: `0x${string}`
  maxPriorityFeePerGas: `0x${string}`
  paymasterAndData: `0x${string}`
  signature: `0x${string}`
}

export type UserOpGasEstimate = {
  callGasLimit: `0x${string}`
  verificationGasLimit: `0x${string}`
  preVerificationGas: `0x${string}`
}

function toHex(n: bigint | number | string): `0x${string}` {
  const bi = typeof n === 'bigint' ? n : BigInt(n)
  return `0x${bi.toString(16)}`
}

export type BuildArgs = {
  sender: `0x${string}`
  nonce: bigint | number | string
  initCode: Uint8Array
  callData: `0x${string}`
  callGasLimit: bigint | number | string
  verificationGasLimit: bigint | number | string
  preVerificationGas: bigint | number | string
  maxFeePerGas: bigint | number | string
  maxPriorityFeePerGas: bigint | number | string
  paymasterAndData?: Uint8Array
  signature: Uint8Array
}

export function buildUserOp(args: BuildArgs): UserOpJson {
  return {
    sender: args.sender,
    nonce: toHex(args.nonce),
    initCode: bytesToHex0x(args.initCode),
    callData: args.callData,
    callGasLimit: toHex(args.callGasLimit),
    verificationGasLimit: toHex(args.verificationGasLimit),
    preVerificationGas: toHex(args.preVerificationGas),
    maxFeePerGas: toHex(args.maxFeePerGas),
    maxPriorityFeePerGas: toHex(args.maxPriorityFeePerGas),
    paymasterAndData: bytesToHex0x(args.paymasterAndData ?? new Uint8Array(0)),
    signature: bytesToHex0x(args.signature)
  }
}

/**
 * Clone a UserOp and substitute a "semi-valid" dummy signature so the
 * bundler can run `eth_estimateUserOperationGas` against a payload
 * shaped exactly like the real one.
 *
 * Pimlico's docs:
 *   "Use a semi-valid dummy signature that matches your final
 *    signature's length. Ensure proper dummy signature is used during
 *    estimation to ensure proper L1DataCost calculations."
 *
 * The PQSmartWallet's `_validateSignature` decodes the signature as
 * `abi.encode(uint256 ownerIndex, bytes innerSig)` — so a buffer of all
 * `0xff` is the right *length* (4128 bytes) but doesn't parse as a
 * valid ABI envelope: `ownerIndex` reads as `2^256-1` (no such owner),
 * the offset word doesn't equal 0x40, and the inner length doesn't
 * equal `C10_SIG_LEN`. Solady's `ERC1271._erc1271IsValidSignatureNow`
 * (and the wallet's `_validateSignature`) bail out before reaching the
 * SPHINCS+ verify, and Pimlico's simulator surfaces the early revert
 * instead of returning an estimate. We then silently fall back to
 * `DEFAULT_GAS.callGas` (50k) and the on-chain tx OOGs.
 *
 * Step one of the fix: emit a valid ABI envelope — `ownerIndex` (matching
 * the callData's, see below), offset=0x40, length=C10_SIG_LEN — with `0xff`
 * filling only the inner SPHINCS+ sig payload, so the wallet's wrapper
 * decode succeeds and the estimator measures the full path.
 *
 * But a `0xff` inner sig can never pass a real C10 verify, so
 * `_validateSignature` returns SIG_VALIDATION_FAILED and — crucially —
 * skips stamping the execution-phase validated-op credit. Bundlers ignore
 * the signature-validation result during estimation and run the execution
 * phase anyway, where `executeWithOffchainCount` finds no credit and reverts
 * with `OwnerIndexMismatch()`. So estimation MUST additionally override the
 * verifier with a return-true stub (see `aa/broadcast.ts`); only then does
 * the credit get stamped and a real callGasLimit come back.
 *
 * The `ownerIndex` written here MUST equal the callData's ownerIndex:
 * `_validateSignature` enforces an H-3 parity check
 * (`_calldataOwnerIndex(callData) == wrapper ownerIndex`) and rejects the
 * signature otherwise — which would again skip credit-stamping.
 */
export function forEstimate(op: UserOpJson, ownerIndex: bigint | number): UserOpJson {
  const dummy = new Uint8Array(SIG_WRAPPER_LEN)
  // ownerIndex as a big-endian 32-byte word, mirroring the callData's
  // ownerIndex so the wallet's H-3 parity check passes.
  dummy.set(u256be(BigInt(ownerIndex)), 0)
  // offset = 0x40 (bytes-head offset for the second arg in the ABI
  // envelope `(uint256, bytes)`).
  dummy[63] = 0x40
  // length = C10_SIG_LEN (4008), big-endian in the last 8 bytes of the
  // length word.
  dummy.set(u64be(C10_SIG_LEN), 96 - 8)
  // Inner SPHINCS+ sig payload — filled with 0xff so the verify call
  // path actually does the work (the dummy bytes won't verify, but the
  // gas cost up to that point is what we want measured).
  for (let i = 96; i < 96 + C10_SIG_LEN; i++) dummy[i] = 0xff
  // Trailing right-padding to the 32-byte boundary is already zero.
  return { ...op, signature: bytesToHex0x(dummy) }
}

/**
 * Apply a bundler's gas estimate, pinning verificationGasLimit to an
 * AA-verifier-friendly floor. SPHINCS+C10 on-chain verification is near-
 * constant cost (~760k gas across factory + wallet verify on first deploy,
 * ~214k on subsequent txs), and Pimlico occasionally low-balls the estimate.
 */
export function applyEstimate(op: UserOpJson, est: UserOpGasEstimate): UserOpJson {
  // Use Pimlico's estimate as-is for all three fields. Per Pimlico's
  // docs the returned values are the correct figures to submit; they
  // already account for L1 data costs on L2 (in preVerificationGas)
  // and the full validation + execution paths the live tx will take.
  // Margins / floors were a workaround for a buggy dummy signature
  // making estimation fail silently — see `forEstimate` for the fix.
  return {
    ...op,
    callGasLimit: est.callGasLimit,
    verificationGasLimit: est.verificationGasLimit,
    preVerificationGas: est.preVerificationGas
  }
}

/** Swap in the real initCode + signature returned by SIGN_USEROP. */
export function finalize(
  op: UserOpJson,
  parts: { initCode?: Uint8Array | null; signature: Uint8Array }
): UserOpJson {
  return {
    ...op,
    initCode: parts.initCode && parts.initCode.length > 0 ? bytesToHex0x(parts.initCode) : '0x',
    signature: bytesToHex0x(parts.signature)
  }
}
