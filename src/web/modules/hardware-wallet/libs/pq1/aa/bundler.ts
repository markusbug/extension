// Pimlico bundler RPC client.

import type { UserOpGasEstimate, UserOpJson } from './userop'

export type BundlerGasPrice = {
  slow: { maxFeePerGas: `0x${string}`; maxPriorityFeePerGas: `0x${string}` }
  standard: { maxFeePerGas: `0x${string}`; maxPriorityFeePerGas: `0x${string}` }
  fast: { maxFeePerGas: `0x${string}`; maxPriorityFeePerGas: `0x${string}` }
}

/** eth_call-style state-override set passed as the optional 3rd param of
 *  `eth_estimateUserOperationGas`. Keyed by address; we only ever set `code`,
 *  but the full shape is allowed for completeness. */
export type StateOverride = Record<
  `0x${string}`,
  {
    code?: string
    balance?: string
    nonce?: string
    state?: Record<string, string>
    stateDiff?: Record<string, string>
  }
>

export class BundlerError extends Error {
  code: number

  data: unknown

  constructor(code: number, message: string, data?: unknown) {
    super(message)
    this.name = 'BundlerError'
    this.code = code
    this.data = data
  }
}

let nextId = 1

async function rpcCall<T>(url: string, method: string, params: unknown[]): Promise<T> {
  const id = nextId++
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id, method, params })
  })
  if (!res.ok) {
    const text = await res.text().catch(() => '')
    throw new BundlerError(-32603, `HTTP ${res.status}: ${text.slice(0, 200)}`)
  }
  const body = (await res.json()) as {
    result?: T
    error?: { code: number; message: string; data?: unknown }
  }
  if (body.error) {
    throw new BundlerError(body.error.code, body.error.message, body.error.data)
  }
  if (body.result === undefined) {
    throw new BundlerError(-32603, 'empty bundler response')
  }
  return body.result
}

export class BundlerClient {
  constructor(
    readonly url: string,
    readonly entryPoint: `0x${string}`
  ) {}

  estimateUserOperationGas(
    op: UserOpJson,
    stateOverride?: StateOverride
  ): Promise<UserOpGasEstimate> {
    // The optional third param is an eth_call-style state-override set
    // (supported by Pimlico/alto for EntryPoint v0.6). broadcast.ts uses it
    // to stub the SPHINCS+ verifier so the dummy-signed op simulates through
    // the full validate+execute path and returns an accurate callGasLimit.
    const params: unknown[] = [op, this.entryPoint]
    if (stateOverride) params.push(stateOverride)
    return rpcCall<UserOpGasEstimate>(this.url, 'eth_estimateUserOperationGas', params)
  }

  sendUserOperation(op: UserOpJson): Promise<`0x${string}`> {
    return rpcCall<`0x${string}`>(this.url, 'eth_sendUserOperation', [op, this.entryPoint])
  }

  // NOTE: no receipt-polling helper on purpose. Once `eth_sendUserOperation`
  // accepts an op, it can still be included on-chain arbitrarily late —
  // polling with a timeout here misreported slow-but-included ops as failed
  // broadcasts (inviting a duplicate re-sign/re-submit). Inclusion tracking
  // belongs to Ambire's ActivityController via
  // `identifiedBy: { type: 'UserOperation' }`.

  getUserOperationGasPrice(): Promise<BundlerGasPrice> {
    return rpcCall<BundlerGasPrice>(this.url, 'pimlico_getUserOperationGasPrice', [])
  }
}
