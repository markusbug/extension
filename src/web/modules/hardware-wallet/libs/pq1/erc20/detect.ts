// Resolve which token a kind-1 ERC-20 metadata bundle should describe for
// a given inner call, and build that bundle from the host ERC-20 DB.
//
// The firmware consumes the kind-1 bundle only when an inner call is an
// ERC-20 `transfer` / `transferFrom` / `approve` (`tx/src/erc20/calldata.rs`)
// and the bundle's `(chain_id, contract)` matches the call (chain == the
// UserOp chain; contract == the token being called). It matches in three
// shapes (`secure/src/nsc/cmd_sign_userop.rs` + `tx/display/safe_display.rs`):
//
//   1. a direct ERC-20 method call          → contract == call `to`
//   2. a Safe execTransaction / approveHash (op=0) whose
//      inner SafeTx call is an ERC-20 method → contract == SafeTx inner `to`
//   3. a Safe execTransaction multiSend batch
//      with an ERC-20 record (e.g. the CoW
//      approve in an approve+presign batch)  → contract == that record `to`
//
// Only one kind-1 bundle rides a UserOp / tx_idx, so we attach the bundle
// for the first ERC-20 inner call we find (the approve/sell token in the
// CoW multiSend case). Omitting it is always safe — the device renders the
// loud unknown-token page instead.

import { reportClearSigningFallback } from '../db/common'
import { decodeExecTransaction, isSafeExecTransaction } from '../safe/execCalldata'
import { summarizeMultiSend } from '../safe/multiSend'
import { hexToBytes } from '../transport/bytes'
import { loadErc20Db } from './db'
import { isErc20MethodCall } from './selectors'

/** The SafeTx inner call a Safe flow executes: `(operation, to, data)` —
 *  from execTransaction calldata, or from the Safe Transaction Service entry
 *  behind an approveHash (whose trailer the device re-verifies). */
export type SafeTxInnerCall = {
  operation: number
  to: `0x${string}`
  data: Uint8Array
}

/** The token a kind-1 bundle should describe for a SafeTx inner call: the
 *  inner `to` when it is an ERC-20 method (operation 0), else the first
 *  ERC-20 record of an allowlisted MultiSendCallOnly batch (the approve in a
 *  CoW approve+presign batch). A reject banner (string) yields no token. */
export function resolveSafeTxErc20Token(inner: SafeTxInnerCall): Uint8Array | null {
  if (inner.operation === 0) {
    return isErc20MethodCall(inner.data) ? hexToBytes(inner.to) : null
  }
  // operation == 1: only an allowlisted MultiSendCallOnly batch reaches
  // a render — pick the first ERC-20 record (the approve in a CoW
  // approve+presign batch). A reject banner (string) yields no token.
  const summary = summarizeMultiSend(inner.data)
  if (typeof summary === 'string') return null
  for (const rec of summary.records) {
    if (isErc20MethodCall(rec.data)) return hexToBytes(rec.to)
  }
  return null
}

/** The 20-byte token address the kind-1 bundle should describe for this
 *  inner call, or null when no inner call is an ERC-20 method (native
 *  transfer, contract call, CoW presign, etc.). An approveHash is resolved
 *  by the caller from its fetched SafeTx (`resolveSafeTxErc20Token`). */
export function resolveErc20Token(to: `0x${string}`, data: Uint8Array): Uint8Array | null {
  if (isErc20MethodCall(data)) return hexToBytes(to)
  if (!isSafeExecTransaction(data)) return null
  const exec = decodeExecTransaction(data)
  return exec ? resolveSafeTxErc20Token(exec) : null
}

/** The kind-1 bundle for `token` on `chainId`, or undefined when the token
 *  isn't in the DB or the DB fails to load. Never throws. */
export async function buildErc20BundleFor(
  chainId: number | bigint,
  token: Uint8Array
): Promise<Uint8Array | undefined> {
  try {
    const db = await loadErc20Db()
    return db.buildBundle(chainId, token) ?? undefined
  } catch (e) {
    reportClearSigningFallback('ERC-20 bundle lookup failed; rendering unknown-token', e)
    return undefined
  }
}

/** Resolve + build the kind-1 ERC-20 bundle for an inner call. Returns
 *  undefined when the call isn't an ERC-20 method, the token isn't in the
 *  DB, or the DB fails to load — every one a safe degrade (the device
 *  renders the unknown-token page). Never throws. */
export async function resolveErc20Bundle(
  chainId: number | bigint,
  to: `0x${string}`,
  data: Uint8Array
): Promise<Uint8Array | undefined> {
  const token = resolveErc20Token(to, data)
  return token ? buildErc20BundleFor(chainId, token) : undefined
}

/** The kind-1 bundle for the first of `tokens` the DB knows, or undefined.
 *  Used for the tokens an ERC-7730 descriptor's `tokenAmount` fields name
 *  (wstETH `wrap` → stETH, Aave `supply(asset, …)` → the asset): the device
 *  binds the bundle to the descriptor-resolved token, so without it the
 *  amount shows unscaled and an interpolated intent ("Wrap 1 stETH") can't
 *  render at all. Only one ERC-20 bundle rides an inner call. */
export async function firstKnownErc20Bundle(
  chainId: number | bigint,
  tokens: readonly Uint8Array[]
): Promise<Uint8Array | undefined> {
  for (const token of tokens) {
    const bundle = await buildErc20BundleFor(chainId, token)
    if (bundle) return bundle
  }
  return undefined
}
