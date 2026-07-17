// 281-byte canonical SafeTx encoding — must match firmware byte-for-byte
// (`secure/src/tx/eip712/safe/mod.rs::decode_canonical`). All multi-byte
// integers are big-endian.
//
// Layout (mirror of companion-safe-tx-integration.md):
//
//   [  0..  8)  chain_id          u64 BE
//   [  8.. 28)  safe_address      20 B
//   [ 28.. 48)  to                20 B
//   [ 48.. 80)  value             u256 BE
//   [ 80..112)  data_hash         bytes32  (keccak256(raw_data))
//   [112]       operation         u8  (0 = Call; 1 = DelegateCall, accepted
//                                  by the firmware only for an allowlisted
//                                  MultiSendCallOnly batch)
//   [113..145)  safe_tx_gas       u256 BE
//   [145..177)  base_gas          u256 BE
//   [177..209)  gas_price         u256 BE
//   [209..229)  gas_token         20 B
//   [229..249)  refund_receiver   20 B
//   [249..281)  nonce             u256 BE

import { keccak256 } from 'viem'

import { hexToBytes, u256be, u64be } from '../transport/bytes'

export const SAFE_V1_CANONICAL_LEN = 281

export interface SafeCanonical {
  chainId: number | bigint
  safeAddress: `0x${string}`
  to: `0x${string}`
  value: bigint
  /** keccak256 of the exact `execTransaction` inner `data` bytes. */
  dataHash: Uint8Array
  /** 0 = Call. DelegateCall (1) is permitted in this encoder; the
   *  firmware's verifier accepts it only for an allowlisted
   *  MultiSendCallOnly batch (companion-safe-cowswap-multisend.md) and
   *  rejects every other target. */
  operation: number
  safeTxGas: bigint
  baseGas: bigint
  gasPrice: bigint
  gasToken: `0x${string}`
  refundReceiver: `0x${string}`
  nonce: bigint
}

export function encodeSafeCanonical(c: SafeCanonical): Uint8Array {
  const out = new Uint8Array(SAFE_V1_CANONICAL_LEN)
  out.set(u64be(BigInt(c.chainId)), 0)
  out.set(addressBytes(c.safeAddress), 8)
  out.set(addressBytes(c.to), 28)
  out.set(u256be(c.value), 48)
  if (c.dataHash.length !== 32) {
    throw new Error(`data_hash must be 32 bytes, got ${c.dataHash.length}`)
  }
  out.set(c.dataHash, 80)
  if (c.operation < 0 || c.operation > 0xff) {
    throw new Error(`operation out of range: ${c.operation}`)
  }
  out[112] = c.operation & 0xff
  out.set(u256be(c.safeTxGas), 113)
  out.set(u256be(c.baseGas), 145)
  out.set(u256be(c.gasPrice), 177)
  out.set(addressBytes(c.gasToken), 209)
  out.set(addressBytes(c.refundReceiver), 229)
  out.set(u256be(c.nonce), 249)
  return out
}

/** keccak256(raw_data). `raw_data` is the exact bytes the Safe will pass to
 *  `execTransaction` as its `data` argument — may be empty. */
export function safeDataHash(rawData: Uint8Array): Uint8Array {
  return hexToBytes(keccak256(rawData))
}

function addressBytes(a: string): Uint8Array {
  const b = hexToBytes(a)
  if (b.length !== 20) throw new Error(`address must be 20 bytes, got ${b.length}`)
  return b
}
