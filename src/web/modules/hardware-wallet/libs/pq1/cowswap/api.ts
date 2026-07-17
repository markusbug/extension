// CoW Protocol orderbook REST client. Only the read paths we need
// for intercepting setPreSignature are kept (cowBaseUrl + getOrder).

import { keccak256, type Address } from 'viem'

import { hexToBytes } from '../transport/bytes'
import {
  type BuyTokenBalance,
  type OrderKind,
  type SellTokenBalance,
  type SigningScheme
} from './types'

export type OrderStatus =
  | 'open'
  | 'fulfilled'
  | 'cancelled'
  | 'expired'
  | 'presignaturePending'
  | 'unknown'

export interface OrderDetail {
  uid: string
  sellToken: Address
  buyToken: Address
  receiver: Address
  sellAmount: bigint
  buyAmount: bigint
  feeAmount: bigint
  executedSellAmount: bigint
  executedBuyAmount: bigint
  validTo: number
  appData: Uint8Array
  kind: OrderKind
  partiallyFillable: boolean
  sellTokenBalance: SellTokenBalance
  buyTokenBalance: BuyTokenBalance
  status: OrderStatus
  signingScheme: SigningScheme
  owner: Address
  creationDate?: string
}

export function cowBaseUrl(chainId: number | bigint): string | null {
  const id = typeof chainId === 'bigint' ? Number(chainId) : chainId
  switch (id) {
    case 1:
      return 'https://api.cow.fi/mainnet/api/v1'
    case 100:
      return 'https://api.cow.fi/xdai/api/v1'
    case 42161:
      return 'https://api.cow.fi/arbitrum_one/api/v1'
    case 8453:
      return 'https://api.cow.fi/base/api/v1'
    case 11155111:
      return 'https://api.cow.fi/sepolia/api/v1'
    default:
      return null
  }
}

export function isCowswapSupportedChain(chainId: number | bigint): boolean {
  return cowBaseUrl(chainId) !== null
}

export class CowswapApiError extends Error {
  constructor(
    public readonly kind: 'http' | 'apiRejected' | 'parse',
    message: string,
    public readonly httpStatus?: number
  ) {
    super(message)
    this.name = 'CowswapApiError'
  }
}

export class CowClient {
  private readonly base: string

  constructor(public readonly chainId: number) {
    const u = cowBaseUrl(chainId)
    if (!u) throw new CowswapApiError('http', `unsupported chain ${chainId}`)
    this.base = u
  }

  async getOrder(uidHex: string): Promise<OrderDetail> {
    const url = `${this.base}/orders/${uidHex}`
    const resp = await fetch(url)
    if (!resp.ok) {
      const body = await resp.text().catch(() => '')
      throw new CowswapApiError(
        'http',
        `GET ${url}: HTTP ${resp.status} ${body.slice(0, 200)}`,
        resp.status
      )
    }
    const json = await resp.json()
    return parseOrderDetail(json)
  }
}

function parseOrderDetail(json: unknown): OrderDetail {
  if (typeof json !== 'object' || json === null) {
    throw new CowswapApiError('parse', 'order detail not an object')
  }
  const o = json as Record<string, unknown>
  return {
    uid: String(o.uid ?? ''),
    sellToken: parseAddress(o.sellToken, 'sellToken'),
    buyToken: parseAddress(o.buyToken, 'buyToken'),
    receiver: parseAddress(o.receiver, 'receiver'),
    sellAmount: parseU256(o.sellAmount, 'sellAmount'),
    buyAmount: parseU256(o.buyAmount, 'buyAmount'),
    feeAmount: parseU256(o.feeAmount, 'feeAmount'),
    executedSellAmount: parseU256(o.executedSellAmount ?? '0', 'executedSellAmount'),
    executedBuyAmount: parseU256(o.executedBuyAmount ?? '0', 'executedBuyAmount'),
    validTo: parseUint(o.validTo, 'validTo'),
    appData: parseAppData(o.appData),
    kind: parseKind(o.kind),
    partiallyFillable: Boolean(o.partiallyFillable),
    sellTokenBalance: parseSellBalance(o.sellTokenBalance),
    buyTokenBalance: parseBuyBalance(o.buyTokenBalance),
    status: parseStatus(o.status),
    signingScheme: parseSigningScheme(o.signingScheme),
    owner: parseAddress(o.owner, 'owner'),
    creationDate: typeof o.creationDate === 'string' ? o.creationDate : undefined
  }
}

function parseAddress(v: unknown, name: string): Address {
  if (typeof v !== 'string' || !/^0x[0-9a-fA-F]{40}$/.test(v)) {
    throw new CowswapApiError('parse', `${name}: invalid address ${String(v).slice(0, 50)}`)
  }
  return v as Address
}

function parseU256(v: unknown, name: string): bigint {
  if (typeof v !== 'string') {
    throw new CowswapApiError('parse', `${name}: expected string, got ${typeof v}`)
  }
  try {
    return BigInt(v)
  } catch {
    throw new CowswapApiError('parse', `${name}: not a u256 string: ${v}`)
  }
}

function parseUint(v: unknown, name: string): number {
  if (typeof v !== 'number' || !Number.isFinite(v) || v < 0) {
    throw new CowswapApiError('parse', `${name}: not a uint`)
  }
  return v
}

function parseKind(v: unknown): OrderKind {
  if (v === 'sell' || v === 'buy') return v
  throw new CowswapApiError('parse', `kind: ${String(v)}`)
}

function parseSellBalance(v: unknown): SellTokenBalance {
  if (v === 'erc20' || v === 'external' || v === 'internal') return v
  if (v === undefined || v === null) return 'erc20'
  throw new CowswapApiError('parse', `sellTokenBalance: ${String(v)}`)
}

function parseBuyBalance(v: unknown): BuyTokenBalance {
  if (v === 'erc20' || v === 'internal') return v
  if (v === undefined || v === null) return 'erc20'
  throw new CowswapApiError('parse', `buyTokenBalance: ${String(v)}`)
}

function parseSigningScheme(v: unknown): SigningScheme {
  if (v === 'eip712' || v === 'ethsign' || v === 'erc1271' || v === 'presign') return v
  if (v === undefined || v === null) return 'eip712'
  throw new CowswapApiError('parse', `signingScheme: ${String(v)}`)
}

function parseStatus(v: unknown): OrderStatus {
  if (
    v === 'open' ||
    v === 'fulfilled' ||
    v === 'cancelled' ||
    v === 'expired' ||
    v === 'presignaturePending'
  ) {
    return v
  }
  return 'unknown'
}

function parseAppData(v: unknown): Uint8Array {
  if (typeof v !== 'string') {
    throw new CowswapApiError('parse', 'appData: not a string')
  }
  const trimmed = v.startsWith('0x') || v.startsWith('0X') ? v.slice(2) : v
  if (trimmed.length === 64 && /^[0-9a-fA-F]+$/.test(trimmed)) {
    return hexToBytes(`0x${trimmed}`)
  }
  const hash = keccak256(new TextEncoder().encode(v))
  return hexToBytes(hash)
}
