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
//   2. a Safe execTransaction (op=0) whose
//      inner SafeTx call is an ERC-20 method → contract == SafeTx inner `to`
//   3. a Safe execTransaction multiSend batch
//      with an ERC-20 record (e.g. the CoW
//      approve in an approve+presign batch)  → contract == that record `to`
//
// Only one kind-1 bundle rides a UserOp / tx_idx, so we attach the bundle
// for the first ERC-20 inner call we find (the approve/sell token in the
// CoW multiSend case). Omitting it is always safe — the device renders the
// loud unknown-token page instead.

import { decodeExecTransaction, isSafeExecTransaction } from '../safe/execCalldata'
import { summarizeMultiSend } from '../safe/multiSend'
import { hexToBytes } from '../transport/bytes'
import { loadErc20Db } from './db'
import { isErc20MethodCall } from './selectors'

/** The 20-byte token address the kind-1 bundle should describe for this
 *  inner call, or null when no inner call is an ERC-20 method (native
 *  transfer, contract call, CoW presign, etc.). */
export function resolveErc20Token(to: `0x${string}`, data: Uint8Array): Uint8Array | null {
  if (isErc20MethodCall(data)) return hexToBytes(to)

  if (isSafeExecTransaction(data)) {
    const exec = decodeExecTransaction(data)
    if (!exec) return null
    if (exec.operation === 0) {
      return isErc20MethodCall(exec.data) ? hexToBytes(exec.to) : null
    }
    // operation == 1: only an allowlisted MultiSendCallOnly batch reaches
    // a render — pick the first ERC-20 record (the approve in a CoW
    // approve+presign batch). A reject banner (string) yields no token.
    const summary = summarizeMultiSend(exec.data)
    if (typeof summary === 'string') return null
    for (const rec of summary.records) {
      if (isErc20MethodCall(rec.data)) return hexToBytes(rec.to)
    }
    return null
  }

  return null
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
  if (!token) return undefined
  try {
    const db = await loadErc20Db()
    return db.buildBundle(chainId, token) ?? undefined
  } catch (e) {
    console.warn('[pq1] ERC-20 bundle lookup failed; rendering unknown-token', e)
    return undefined
  }
}
