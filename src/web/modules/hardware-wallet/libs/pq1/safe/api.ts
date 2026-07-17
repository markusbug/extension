// Safe Transaction Service client — used to recover canonical SafeTx fields
// for an `approveHash(safeTxHash)` UserOp so the PQ1 firmware can clear-sign.
//
// See companion-safe-tx-integration.md: the companion fetches SafeTx fields
// out of band, ships them as a `safe_v1` trailer, and the device re-derives
// `safeTxHash` from the bytes. The firmware does not trust any field here —
// every byte is re-anchored to the on-chain hash before rendering.

import SafeApiKit from '@safe-global/api-kit'
import type { SafeMultisigTransactionResponse } from '@safe-global/types-kit'

/** Subset of SafeMultisigTransactionResponse the PQ1 trailer needs. The Safe
 *  API returns u256-as-decimal-strings and addresses as 0x-prefixed hex. */
export interface SafeTxFields {
  to: `0x${string}`
  value: bigint
  data: `0x${string}`
  operation: number
  safeTxGas: bigint
  baseGas: bigint
  gasPrice: bigint
  gasToken: `0x${string}`
  refundReceiver: `0x${string}`
  nonce: bigint
  safeTxHash: `0x${string}`
}

const ZERO_ADDR = '0x0000000000000000000000000000000000000000' as `0x${string}`

export class SafeTxApiError extends Error {
  constructor(
    public readonly kind: 'http' | 'parse',
    message: string
  ) {
    super(message)
    this.name = 'SafeTxApiError'
  }
}

/** Fetch canonical SafeTx fields by `(chainId, safeTxHash)`. The firmware
 *  re-derives `safeTxHash` from these fields and refuses to sign on any
 *  mismatch — a tampered response self-fails at the verifier. */
export async function fetchSafeTx(
  chainId: number | bigint,
  safeTxHash: `0x${string}`
): Promise<SafeTxFields> {
  const kit = new SafeApiKit({
    chainId: typeof chainId === 'bigint' ? chainId : BigInt(chainId),
    apiKey: process.env.SAFE_API_KEY
  })
  let raw: SafeMultisigTransactionResponse
  try {
    raw = await kit.getTransaction(safeTxHash)
  } catch (e) {
    throw new SafeTxApiError(
      'http',
      `Safe Transaction Service GET ${safeTxHash} failed: ${
        e instanceof Error ? e.message : String(e)
      }`
    )
  }
  return parseSafeTx(raw)
}

function parseSafeTx(t: SafeMultisigTransactionResponse): SafeTxFields {
  return {
    to: ensureAddress(t.to, 'to'),
    value: parseU256(t.value, 'value'),
    data: ensureHex(t.data ?? '0x', 'data'),
    operation: ensureOperation(t.operation),
    safeTxGas: parseU256(t.safeTxGas, 'safeTxGas'),
    baseGas: parseU256(t.baseGas, 'baseGas'),
    gasPrice: parseU256(t.gasPrice, 'gasPrice'),
    gasToken: ensureAddress(t.gasToken, 'gasToken'),
    refundReceiver: t.refundReceiver
      ? ensureAddress(t.refundReceiver, 'refundReceiver')
      : ZERO_ADDR,
    nonce: parseU256(t.nonce, 'nonce'),
    safeTxHash: ensureBytes32(t.safeTxHash, 'safeTxHash')
  }
}

function ensureAddress(v: unknown, name: string): `0x${string}` {
  if (typeof v !== 'string' || !/^0x[0-9a-fA-F]{40}$/.test(v)) {
    throw new SafeTxApiError('parse', `${name}: not an address: ${String(v).slice(0, 60)}`)
  }
  return v.toLowerCase() as `0x${string}`
}

function ensureBytes32(v: unknown, name: string): `0x${string}` {
  if (typeof v !== 'string' || !/^0x[0-9a-fA-F]{64}$/.test(v)) {
    throw new SafeTxApiError('parse', `${name}: not a bytes32: ${String(v).slice(0, 80)}`)
  }
  return v.toLowerCase() as `0x${string}`
}

function ensureHex(v: unknown, name: string): `0x${string}` {
  if (typeof v !== 'string' || !/^0x([0-9a-fA-F]{2})*$/.test(v)) {
    throw new SafeTxApiError('parse', `${name}: not hex bytes`)
  }
  return v.toLowerCase() as `0x${string}`
}

function parseU256(v: unknown, name: string): bigint {
  if (typeof v === 'number') return BigInt(v)
  if (typeof v !== 'string') {
    throw new SafeTxApiError('parse', `${name}: expected u256 string, got ${typeof v}`)
  }
  try {
    return BigInt(v)
  } catch {
    throw new SafeTxApiError('parse', `${name}: not a u256 string: ${v}`)
  }
}

function ensureOperation(v: unknown): number {
  if (typeof v !== 'number' || (v !== 0 && v !== 1)) {
    throw new SafeTxApiError('parse', `operation: expected 0 or 1, got ${String(v)}`)
  }
  return v
}
