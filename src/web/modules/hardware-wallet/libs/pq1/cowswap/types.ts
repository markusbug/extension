// Core CoW Protocol data types. Byte values (kind / sellTokenBalance /
// buyTokenBalance enums, canonical layout) must match the firmware's
// secure/src/tx/eip712/cowswap/mod.rs byte-for-byte — the device decodes
// the canonical and re-derives the EIP-712 orderDigest from these fields.

import { type Address } from 'viem'

import { bytesToHex0x } from '../transport/bytes'

export type OrderKind = 'sell' | 'buy'

export function orderKindByte(k: OrderKind): number {
  return k === 'sell' ? 0 : 1
}

export type SellTokenBalance = 'erc20' | 'external' | 'internal'

export function sellTokenBalanceByte(b: SellTokenBalance): number {
  switch (b) {
    case 'erc20':
      return 0
    case 'external':
      return 1
    case 'internal':
      return 2
  }
}

export type BuyTokenBalance = 'erc20' | 'internal'

export function buyTokenBalanceByte(b: BuyTokenBalance): number {
  return b === 'erc20' ? 0 : 1
}

export type SigningScheme = 'eip712' | 'ethsign' | 'erc1271' | 'presign'

/** `chainId` is bound into the canonical ZK byte layout so a proof
 *  cannot replay across chains. */
export interface GPv2Order {
  chainId: number
  sellToken: Address
  buyToken: Address
  receiver: Address
  sellAmount: bigint
  buyAmount: bigint
  validTo: number
  appData: Uint8Array
  feeAmount: bigint
  kind: OrderKind
  partiallyFillable: boolean
  sellTokenBalance: SellTokenBalance
  buyTokenBalance: BuyTokenBalance
}

/** 56-byte CoW order UID: `orderDigest(32) || owner(20) || validTo(4)`. */
export class OrderUid {
  constructor(public readonly bytes: Uint8Array) {
    if (bytes.length !== 56) throw new Error(`OrderUid: expected 56 bytes, got ${bytes.length}`)
  }

  toHex(): `0x${string}` {
    return bytesToHex0x(this.bytes)
  }
}
