// Collect the addresses the device will display for an inner call, and
// build the kind-8 address-name bundles for the ones present in the host
// names DB.
//
// The firmware's display layer resolves a name for every address it would
// otherwise show as hex: `to`, an ERC-20 transfer recipient / approve
// spender / transferFrom from+to, a Safe execTransaction inner `to`, each
// MultiSendCallOnly record target (and that record's ERC-20 args), and the
// CoW order receiver (companion-names-db.md). We mirror that set so a name
// rides along for each. Misses are benign — the address renders as 40-hex.
//
// At most MAX_NAME_BUNDLES (4) bundles per sign; we dedupe by address and
// stop once the cap is hit.

import {
  ERC20_APPROVE_SELECTOR,
  ERC20_TRANSFER_FROM_SELECTOR,
  ERC20_TRANSFER_SELECTOR
} from '../erc20/selectors'
import { decodeExecTransaction, isSafeExecTransaction } from '../safe/execCalldata'
import { summarizeMultiSend } from '../safe/multiSend'
import { bytesToHex, hexToBytes, selectorMatches } from '../transport/bytes'
import { loadNamesDb } from './db'

/** The 20-byte `address` argument at ABI word `wordIdx` (after the
 *  selector), or null if the calldata is too short / not left-padded to an
 *  address. */
function addressArg(data: Uint8Array, wordIdx: number): Uint8Array | null {
  const start = 4 + wordIdx * 32
  if (start + 32 > data.length) return null
  // An address word is 12 zero bytes then 20 address bytes.
  for (let i = 0; i < 12; i++) if (data[start + i] !== 0) return null
  return data.subarray(start + 12, start + 32)
}

/** ERC-20 recipient/spender/from addresses carried in transfer-style
 *  calldata (the arguments the device labels). */
function erc20ArgAddresses(data: Uint8Array): Uint8Array[] {
  const out: Uint8Array[] = []
  if (data.length < 4) return out
  if (
    selectorMatches(data, ERC20_TRANSFER_SELECTOR) ||
    selectorMatches(data, ERC20_APPROVE_SELECTOR)
  ) {
    const a = addressArg(data, 0)
    if (a) out.push(a)
  } else if (selectorMatches(data, ERC20_TRANSFER_FROM_SELECTOR)) {
    const from = addressArg(data, 0)
    const to = addressArg(data, 1)
    if (from) out.push(from)
    if (to) out.push(to)
  }
  return out
}

/** Every address the trusted UI will display for this inner call: the call
 *  `to`, its ERC-20 args, and — for a Safe execTransaction — the SafeTx
 *  inner `to` / each multiSend record target plus their ERC-20 args. CoW
 *  receivers are added separately by the caller (they come from the fetched
 *  order, not the calldata). Returned as raw 20-byte addresses; the caller
 *  dedupes. */
export function collectDisplayAddresses(to: `0x${string}`, data: Uint8Array): Uint8Array[] {
  const out: Uint8Array[] = [hexToBytes(to), ...erc20ArgAddresses(data)]

  if (isSafeExecTransaction(data)) {
    const exec = decodeExecTransaction(data)
    if (exec) {
      if (exec.operation === 0) {
        out.push(hexToBytes(exec.to), ...erc20ArgAddresses(exec.data))
      } else {
        const summary = summarizeMultiSend(exec.data)
        if (typeof summary !== 'string') {
          for (const rec of summary.records) {
            out.push(hexToBytes(rec.to), ...erc20ArgAddresses(rec.data))
          }
        }
      }
    }
  }

  return out
}

const ZERO_ADDRESS_KEY = '0'.repeat(40)

/** Build up to `cap` kind-8 name bundles for `addresses` on `chainId`,
 *  deduped by address, skipping the zero address. Never throws — a DB
 *  load/parse failure or a per-address miss just yields fewer (or no)
 *  bundles, and the device renders those addresses as 40-hex. */
export async function buildNameBundles(
  chainId: number | bigint,
  addresses: Uint8Array[],
  cap: number
): Promise<Uint8Array[]> {
  if (cap <= 0 || addresses.length === 0) return []
  let db
  try {
    db = await loadNamesDb()
  } catch (e) {
    console.warn('[pq1] names DB load failed; addresses render as hex', e)
    return []
  }

  const bundles: Uint8Array[] = []
  const seen = new Set<string>()
  for (const addr of addresses) {
    if (bundles.length >= cap) break
    if (addr.length !== 20) continue
    const key = bytesToHex(addr)
    if (key === ZERO_ADDRESS_KEY || seen.has(key)) continue
    seen.add(key)
    try {
      const bundle = db.buildBundle(chainId, addr)
      if (bundle) bundles.push(bundle)
    } catch (e) {
      console.warn('[pq1] name bundle build failed; address renders as hex', key, e)
    }
  }
  return bundles
}
