// Build the SIGN_OFFCHAIN request for a typed-data sign the device clear-signs
// natively: a Safe `SafeTx` (kind 4) or a CoW `Order` (kind 5), as recognised
// by `classifyStructuredTypedData`. The device recomputes the EIP-712 hash
// from these bytes and signs exactly what a raw32 sign of that hash would, so
// the resulting signature verifies wherever the blind one did.

import { CAP_OFFCHAIN_COW_ORDER, CAP_OFFCHAIN_SAFE_TX } from '../config'
import { buildOffchainSafeTxSections } from '../aa/broadcast'
import { buildCowOrderTrailer } from '../cowswap/v3Trailer'
import { encodeSafeCanonical } from '../safe/canonical'
import { packSafeV1Bundle } from '../safe/safeV1Trailer'
import type { SignOffchainParams } from '../transport/offchain'
import type { StructuredTypedData } from './structuredTypedData'

type Structured = Exclude<StructuredTypedData, { kind: 'other' }>

type DistributiveOmit<T, K extends PropertyKey> = T extends unknown ? Omit<T, K> : never

/** A structured request without the account / chain / slot header fields. */
export type StructuredOffchainRequest = DistributiveOmit<
  Extract<SignOffchainParams, { kind: 'safe_tx' | 'cow_order' }>,
  'accountIndex' | 'chainId' | 'slotIndex' | 'accountDeployed'
>

/** The GET_DEVICE_INFO capability bit the device must report before the
 *  companion sends this kind. */
export function structuredCapability(s: Structured): number {
  return s.kind === 'safe_tx' ? CAP_OFFCHAIN_SAFE_TX : CAP_OFFCHAIN_COW_ORDER
}

/** The kind-4 / kind-5 payload fields for `s`, with ERC-20 and name
 *  metadata from the host DBs (a miss only makes the device show raw
 *  values). Throws a user-facing refusal for a SafeTx the device would
 *  refuse (DELEGATECALL outside MultiSendCallOnly, an unreadable CoW
 *  order it pre-signs). */
export async function buildStructuredOffchainRequest(
  s: Structured
): Promise<StructuredOffchainRequest> {
  if (s.kind === 'cow_order') {
    return { kind: 'cow_order', cowTrailer: await buildCowOrderTrailer(s.order) }
  }
  const sections = await buildOffchainSafeTxSections(Number(s.chainId), s.safe, {
    operation: s.canonical.operation,
    to: s.canonical.to,
    data: s.rawData
  })
  return {
    kind: 'safe_tx',
    safeV1Bundle: packSafeV1Bundle(encodeSafeCanonical(s.canonical), s.rawData),
    ...sections
  }
}
