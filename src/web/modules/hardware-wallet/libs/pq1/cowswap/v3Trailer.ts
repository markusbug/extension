// Build the kind-3 CoW trailer required by the PQ1 firmware's
// downgrade-mitigation gate (`secure/src/nsc/cmd_sign_userop.rs`).
//
// As of firmware `05f9758a` the CoW Groth16 circuit + Poseidon ERC-20
// registry are RETIRED. `setPreSignature` orders no longer carry a proof
// or a VK; the device binds the order to the calldata natively (it
// re-keccaks the canonical GPv2Order → orderDigest and byte-compares it
// against `orderUid[0..32]` in the calldata, with `orderUid[32..52] ==
// uid.owner`) and decodes token symbols/decimals on-device from ordinary
// ERC-20 metadata bundles (the same kind-1 bundle as a transfer).
//
// New kind-3 trailer layout (`secure/src/tx/eip712/cowswap/mod.rs`):
//
//   canonical          [u8; 204]          packed GPv2Order
//   [ sell_len u16 BE ][ sell_bundle ]    ERC-20 bundle for the SELL token (optional)
//   [ buy_len  u16 BE ][ buy_bundle  ]    ERC-20 bundle for the BUY  token (optional)
//
// Each leg bundle is the exact kind-1 ERC-20 bundle (`../erc20/db.ts`).
// For a CoW order the bundle's `contract` must equal the canonical leg
// token and its `chain_id` must equal `canonical.chain_id`, or the device
// ignores it and renders that leg AddrHex (raw 20-byte address + uint256
// hex). A leg with `*_len == 0` (or a bare 204-byte trailer) renders
// AddrOnly — still fully bound and safe, just not pretty. No VK, no proof,
// no Poseidon tree.
//
// Flow:
//   1. Parse the orderUid out of the calldata.
//   2. GET /api/v1/orders/{uid} from the CoW orderbook to recover the full
//      GPv2Order (token addresses, amounts, app data, balance enums, etc.).
//   3. Recompute the uid locally and require byte equality — any orderbook
//      tampering would surface here as a mismatch.
//   4. Encode the 204-byte canonical and look up the two leg tokens in the
//      host ERC-20 DB (keyed by (canonical.chain_id, leg token)). A miss /
//      load failure ships a `0x0000`-length leg — the device degrades to
//      AddrOnly, never an error.
//   5. Pack `canonical || [u16 sell_len][sell] || [u16 buy_len][buy]`.

import { loadErc20Db, MAX_ERC20_BUNDLE_LEN } from '../erc20/db'
import { concatBytes, hexToBytes, isSameBytes, u16be } from '../transport/bytes'
import { CowClient, isCowswapSupportedChain, type OrderDetail } from './api'
import { decodeSetPreSignature, SET_PRE_SIGNATURE_SELECTOR } from './calldata'
import { CANONICAL_LEN, encodeCanonical } from './canonical'
import { buildOrderUid, GPV2_SETTLEMENT_ADDRESS } from './eip712'
import { type GPv2Order, OrderUid } from './types'

/** Firmware cap on the kind-3 trailer (`COW_ORDER_TRAILER_MAX_LEN`,
 *  `secure/src/nsc/batch_trailers.rs`): canonical + two length-prefixed
 *  ERC-20 leg bundles. */
export const COW_ORDER_TRAILER_MAX_LEN =
  CANONICAL_LEN + 2 + MAX_ERC20_BUNDLE_LEN + 2 + MAX_ERC20_BUNDLE_LEN // 2448

export interface BuildV3TrailerInput {
  chainId: number | bigint
  /** Expected `orderUid.owner`: the wallet (UserOp sender) for a direct
   *  order, the SAFE address for a Safe-wrapped one. GPv2Settlement
   *  requires `uid.owner == msg.sender` at execution — and when the
   *  presign runs inside a SafeTx, the Safe is `msg.sender`, not the
   *  wallet. The firmware cross-checks the same binding via
   *  `safe::cow_binding::resolve_cow_binding` (companion-safe-cowswap-presign.md). */
  owner: `0x${string}`
  /** The setPreSignature calldata that will reach GPv2Settlement on-chain
   *  — the UserOp inner calldata for a direct order, the SafeTx `data`
   *  for a single-call Safe-wrapped one, or the unique presign record's
   *  164 bytes inside a Safe multiSend batch
   *  (companion-safe-cowswap-multisend.md). */
  innerData: Uint8Array
}

export interface BuildV3TrailerResult {
  zkV3Bundle: Uint8Array
  order: GPv2Order
  uid: OrderUid
}

/** True when this inner-call target+selector matches the CoW gate the
 *  firmware enforces (GPv2Settlement.setPreSignature). Deliberately
 *  selector-only — mirrors `safe_inner_is_cow_presign` and the
 *  direct-path gate in `cmd_sign_userop.rs`, which both fire for
 *  malformed or `signed == false` calldata too, so those refuse loudly
 *  instead of falling through to a blind-sign page. Callers that match
 *  here MUST attach a verifying kind-3 trailer or abort the sign. */
export function isCowSetPreSignature(to: `0x${string}`, data: Uint8Array): boolean {
  if (to.toLowerCase() !== GPV2_SETTLEMENT_ADDRESS.toLowerCase()) return false
  if (data.length < SET_PRE_SIGNATURE_SELECTOR.length) return false
  for (let i = 0; i < SET_PRE_SIGNATURE_SELECTOR.length; i++) {
    if (data[i] !== SET_PRE_SIGNATURE_SELECTOR[i]) return false
  }
  return true
}

/** Returns null when the calldata doesn't strictly decode as a CoW
 *  `setPreSignature` call (the 164-byte ABI shape). Callers that routed
 *  here via `isCowSetPreSignature` — which, like the firmware gate, also
 *  fires on malformed calldata — must treat null as a hard error: the
 *  device refuses to sign those with `CoW sign: v3 required`. Throws on
 *  any failure once the shape decodes — there is no graceful fallback
 *  because the firmware's downgrade gate would reject a no-trailer sign
 *  anyway. The ERC-20 leg lookups are the only soft-fail: a miss or a DB
 *  load failure simply omits that leg (the device renders it AddrOnly). */
export async function tryBuildV3Trailer(
  args: BuildV3TrailerInput
): Promise<BuildV3TrailerResult | null> {
  const decoded = decodeSetPreSignature(args.innerData)
  if (!decoded) return null
  if (!decoded.signed) {
    throw new Error(
      'CoW setPreSignature(uid, false) cannot be clear-signed — only signed=true presignatures are supported'
    )
  }
  const chainNum = typeof args.chainId === 'bigint' ? Number(args.chainId) : args.chainId
  if (!isCowswapSupportedChain(chainNum)) {
    throw new Error(`CoW Protocol not supported on chain ${chainNum}`)
  }

  const uidHex = decoded.uid.toHex()
  let detail: OrderDetail
  try {
    detail = await new CowClient(chainNum).getOrder(uidHex)
  } catch (e) {
    throw new Error(
      `Could not fetch CoW order ${uidHex} from the orderbook — it may not have been posted yet. Underlying error: ${e instanceof Error ? e.message : String(e)}`
    )
  }

  // The orderUid's embedded owner must equal the address that ends up as
  // `msg.sender` at GPv2Settlement — the wallet for a direct order, the
  // Safe for a Safe-wrapped one. CoW's setPreSignature reverts on-chain
  // otherwise (and the firmware refuses the trailer), but reproducing the
  // check here gives a clearer error than waiting for the bundler.
  if (detail.owner.toLowerCase() !== args.owner.toLowerCase()) {
    throw new Error(
      `CoW order owner ${detail.owner} does not match the expected pre-signing owner ${args.owner} ` +
        '(the wallet for a direct order; the Safe for a Safe-wrapped one)'
    )
  }

  const order: GPv2Order = {
    chainId: chainNum,
    sellToken: detail.sellToken,
    buyToken: detail.buyToken,
    receiver: detail.receiver,
    sellAmount: detail.sellAmount,
    buyAmount: detail.buyAmount,
    validTo: detail.validTo,
    appData: detail.appData,
    feeAmount: detail.feeAmount,
    kind: detail.kind,
    partiallyFillable: detail.partiallyFillable,
    sellTokenBalance: detail.sellTokenBalance,
    buyTokenBalance: detail.buyTokenBalance
  }

  // Reproduce the uid locally and require byte equality. If the orderbook
  // returned an order whose struct hash differs from the uid the dapp
  // submitted, the user would otherwise see one set of fields on the
  // hardware screen and sign a different one — the exact downgrade attack
  // the firmware gate exists to prevent.
  const recomputed = buildOrderUid(order, args.owner)
  if (!isSameBytes(recomputed.bytes, decoded.uid.bytes)) {
    throw new Error(
      `CoW orderbook returned an order whose hash (${recomputed.toHex()}) does not match the setPreSignature uid (${uidHex}). Refusing to sign — possible orderbook tampering.`
    )
  }

  const canonical = encodeCanonical(order)

  // Build the two optional ERC-20 leg bundles. Each is keyed by
  // (canonical.chain_id, leg token) so it matches the firmware's per-leg
  // cross-check exactly; a DB miss / load failure yields a 0x0000-length
  // leg and the device degrades that leg to AddrOnly (raw address +
  // uint256 hex) — never an error.
  const [sellBundle, buyBundle] = await Promise.all([
    tryErc20Leg(chainNum, order.sellToken),
    tryErc20Leg(chainNum, order.buyToken)
  ])

  const zkV3Bundle = concatBytes([
    canonical,
    u16be(sellBundle ? sellBundle.length : 0),
    sellBundle ?? new Uint8Array(0),
    u16be(buyBundle ? buyBundle.length : 0),
    buyBundle ?? new Uint8Array(0)
  ])
  if (zkV3Bundle.length > COW_ORDER_TRAILER_MAX_LEN) {
    throw new Error(
      `CoW kind-3 trailer ${zkV3Bundle.length} B exceeds firmware cap ${COW_ORDER_TRAILER_MAX_LEN} B`
    )
  }

  return { zkV3Bundle, order, uid: recomputed }
}

/** Look up one CoW leg token in the host ERC-20 DB and build its kind-1
 *  bundle. Returns null on a miss or any DB load/parse failure — the leg
 *  then ships empty and the device renders it AddrOnly. The render is a
 *  soft fallback only; the order is still fully bound to the calldata. */
async function tryErc20Leg(chainId: number, token: string): Promise<Uint8Array | null> {
  try {
    const db = await loadErc20Db()
    return db.buildBundle(chainId, addressBytes(token))
  } catch (e) {
    console.warn('[pq1] CoW ERC-20 leg lookup failed; rendering AddrOnly', token, e)
    return null
  }
}

function addressBytes(a: string): Uint8Array {
  const b = hexToBytes(a)
  if (b.length !== 20) throw new Error(`address must be 20 bytes, got ${b.length}`)
  return b
}
