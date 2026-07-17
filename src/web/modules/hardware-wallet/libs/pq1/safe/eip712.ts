// Safe v1.3.0+ EIP-712 `safeTxHash` reference implementation. Reproduces the
// firmware's `compute_safe_tx_hash` so the host can sanity-check what the
// Safe API returned before forwarding. The firmware *also* recomputes the
// hash and byte-compares against `inner_data[4..36]`; the host check exists
// so a tampered/stale API response surfaces with a clear error here instead
// of failing opaquely on the device.
//
// Domain: `EIP712Domain(uint256 chainId,address verifyingContract)` — Safe
// v1.3+ chain-specific. v1.1.x used a chain-agnostic domain and produces a
// different hash; the firmware only supports v1.3+.

import { keccak256 } from 'viem'

import { hexToBytes, u256be } from '../transport/bytes'
import type { SafeCanonical } from './canonical'

const SAFE_DOMAIN_TYPEHASH_PREIMAGE = 'EIP712Domain(uint256 chainId,address verifyingContract)'

const SAFE_TX_TYPEHASH_PREIMAGE =
  'SafeTx(address to,uint256 value,bytes data,uint8 operation,uint256 safeTxGas,uint256 baseGas,uint256 gasPrice,address gasToken,address refundReceiver,uint256 nonce)'

function keccak256Bytes(data: Uint8Array): Uint8Array {
  return hexToBytes(keccak256(data))
}

function keccakAscii(s: string): Uint8Array {
  return keccak256Bytes(new TextEncoder().encode(s))
}

function domainSeparator(chainId: bigint, safeAddress: `0x${string}`): Uint8Array {
  const buf = new Uint8Array(32 * 3)
  buf.set(keccakAscii(SAFE_DOMAIN_TYPEHASH_PREIMAGE), 0)
  buf.set(u256be(chainId), 32)
  buf.set(hexToBytes(safeAddress), 64 + 12)
  return keccak256Bytes(buf)
}

function structHash(c: SafeCanonical): Uint8Array {
  const buf = new Uint8Array(32 * 11)
  buf.set(keccakAscii(SAFE_TX_TYPEHASH_PREIMAGE), 0)
  buf.set(hexToBytes(c.to), 32 + 12)
  buf.set(u256be(c.value), 64)
  if (c.dataHash.length !== 32) throw new Error('dataHash must be 32 bytes')
  buf.set(c.dataHash, 96)
  buf[128 + 31] = c.operation & 0xff
  buf.set(u256be(c.safeTxGas), 160)
  buf.set(u256be(c.baseGas), 192)
  buf.set(u256be(c.gasPrice), 224)
  buf.set(hexToBytes(c.gasToken), 256 + 12)
  buf.set(hexToBytes(c.refundReceiver), 288 + 12)
  buf.set(u256be(c.nonce), 320)
  return keccak256Bytes(buf)
}

export function computeSafeTxHash(c: SafeCanonical): Uint8Array {
  const buf = new Uint8Array(2 + 32 + 32)
  buf[0] = 0x19
  buf[1] = 0x01
  buf.set(domainSeparator(BigInt(c.chainId), c.safeAddress), 2)
  buf.set(structHash(c), 34)
  return keccak256Bytes(buf)
}
