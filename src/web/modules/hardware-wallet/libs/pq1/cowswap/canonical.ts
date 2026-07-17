// 204-byte canonical encoding of a GPv2Order — the byte layout the kind-3
// CoW trailer carries. The firmware re-keccaks these bytes into the
// EIP-712 orderDigest and byte-compares it against the calldata's
// orderUid (no Groth16 circuit since fw 05f9758a).
//
// Layout (must match `secure/src/tx/eip712/cowswap/mod.rs::decode_canonical`
// byte-for-byte):
//
//   [  0..  8)  chain_id           u64 BE
//   [  8.. 28)  sellToken          20-byte address
//   [ 28.. 48)  buyToken           20 B
//   [ 48.. 68)  receiver           20 B
//   [ 68..100)  sellAmount         u256 BE
//   [100..132)  buyAmount          u256 BE
//   [132..164)  feeAmount          u256 BE
//   [164..168)  validTo            u32 BE
//   [168]       kind               0=sell / 1=buy
//   [169]       partiallyFillable  0/1
//   [170]       sellTokenBalance   0/1/2
//   [171]       buyTokenBalance    0/1
//   [172..204)  appData            bytes32

import { hexToBytes, u256be, u32be, u64be } from '../transport/bytes'
import { buyTokenBalanceByte, type GPv2Order, orderKindByte, sellTokenBalanceByte } from './types'

export const CANONICAL_LEN = 204

export function encodeCanonical(order: GPv2Order): Uint8Array {
  const out = new Uint8Array(CANONICAL_LEN)

  out.set(u64be(BigInt(order.chainId)), 0)
  out.set(addressBytes(order.sellToken), 8)
  out.set(addressBytes(order.buyToken), 28)
  out.set(addressBytes(order.receiver), 48)
  out.set(u256be(order.sellAmount), 68)
  out.set(u256be(order.buyAmount), 100)
  out.set(u256be(order.feeAmount), 132)
  out.set(u32be(order.validTo), 164)
  out[168] = orderKindByte(order.kind)
  out[169] = order.partiallyFillable ? 1 : 0
  out[170] = sellTokenBalanceByte(order.sellTokenBalance)
  out[171] = buyTokenBalanceByte(order.buyTokenBalance)

  if (order.appData.length !== 32) {
    throw new Error(`appData must be 32 bytes, got ${order.appData.length}`)
  }
  out.set(order.appData, 172)

  return out
}

function addressBytes(a: string): Uint8Array {
  const b = hexToBytes(a)
  if (b.length !== 20) throw new Error(`address must be 20 bytes, got ${b.length}`)
  return b
}
