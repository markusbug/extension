// EIP-712 reference implementation for CoW Protocol GPv2Order.
// Must match secure/src/tx/eip712/cowswap/mod.rs byte-for-byte — the device
// re-derives the digest and signs it.

import { keccak256 } from 'viem'

import { hexToBytes, u256be, u32be } from '../transport/bytes'
import {
  type BuyTokenBalance,
  type GPv2Order,
  OrderUid,
  type OrderKind,
  type SellTokenBalance
} from './types'

export const GPV2_SETTLEMENT_ADDRESS = '0x9008D19f58AAbD9eD0D60971565AA8510560ab41' as const

const DOMAIN_TYPEHASH_PREIMAGE =
  'EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)'

// CoW's canonical TYPE_HASH preimage declares kind / sellTokenBalance /
// buyTokenBalance as `string`, not `bytes32`. Getting this wrong yields a
// different typehash and every uid we derive mismatches the orderbook.
const ORDER_TYPEHASH_PREIMAGE =
  'Order(address sellToken,address buyToken,address receiver,uint256 sellAmount,uint256 buyAmount,uint32 validTo,bytes32 appData,uint256 feeAmount,string kind,bool partiallyFillable,string sellTokenBalance,string buyTokenBalance)'

const DOMAIN_NAME = 'Gnosis Protocol'
const DOMAIN_VERSION = 'v2'

function keccak256Bytes(data: Uint8Array): Uint8Array {
  return hexToBytes(keccak256(data))
}

function keccakAscii(s: string): Uint8Array {
  return keccak256Bytes(new TextEncoder().encode(s))
}

function kindHash(k: OrderKind): Uint8Array {
  return k === 'sell' ? keccakAscii('sell') : keccakAscii('buy')
}

function sellBalanceHash(b: SellTokenBalance): Uint8Array {
  switch (b) {
    case 'erc20':
      return keccakAscii('erc20')
    case 'external':
      return keccakAscii('external')
    case 'internal':
      return keccakAscii('internal')
  }
}

function buyBalanceHash(b: BuyTokenBalance): Uint8Array {
  return b === 'erc20' ? keccakAscii('erc20') : keccakAscii('internal')
}

function domainSeparator(chainId: number): Uint8Array {
  const buf = new Uint8Array(32 * 5)
  buf.set(keccakAscii(DOMAIN_TYPEHASH_PREIMAGE), 0)
  buf.set(keccakAscii(DOMAIN_NAME), 32)
  buf.set(keccakAscii(DOMAIN_VERSION), 64)
  buf.set(u256be(BigInt(chainId)), 96)
  buf.set(hexToBytes(GPV2_SETTLEMENT_ADDRESS), 128 + 12)
  return keccak256Bytes(buf)
}

function structHash(order: GPv2Order): Uint8Array {
  const buf = new Uint8Array(32 * 13)
  buf.set(keccakAscii(ORDER_TYPEHASH_PREIMAGE), 0)

  buf.set(hexToBytes(order.sellToken), 32 + 12)
  buf.set(hexToBytes(order.buyToken), 64 + 12)
  buf.set(hexToBytes(order.receiver), 96 + 12)
  buf.set(u256be(order.sellAmount), 128)
  buf.set(u256be(order.buyAmount), 160)
  buf.set(u32be(order.validTo), 192 + 28)
  if (order.appData.length !== 32) throw new Error('appData must be 32 bytes')
  buf.set(order.appData, 224)
  buf.set(u256be(order.feeAmount), 256)
  buf.set(kindHash(order.kind), 288)
  buf[320 + 31] = order.partiallyFillable ? 1 : 0
  buf.set(sellBalanceHash(order.sellTokenBalance), 352)
  buf.set(buyBalanceHash(order.buyTokenBalance), 384)

  return keccak256Bytes(buf)
}

function orderDigest(order: GPv2Order): Uint8Array {
  const buf = new Uint8Array(2 + 32 + 32)
  buf[0] = 0x19
  buf[1] = 0x01
  buf.set(domainSeparator(order.chainId), 2)
  buf.set(structHash(order), 34)
  return keccak256Bytes(buf)
}

export function buildOrderUid(order: GPv2Order, owner: `0x${string}`): OrderUid {
  const digest = orderDigest(order)
  const ownerBytes = hexToBytes(owner)
  if (ownerBytes.length !== 20) throw new Error('owner must be 20 bytes')
  const out = new Uint8Array(56)
  out.set(digest, 0)
  out.set(ownerBytes, 32)
  out.set(u32be(order.validTo), 52)
  return new OrderUid(out)
}
