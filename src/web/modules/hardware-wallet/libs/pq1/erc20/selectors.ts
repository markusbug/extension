// The exact ERC-20 method selectors the firmware's renderer recognises
// (`tx/src/erc20/calldata.rs`). Kept in one module so an added method
// (e.g. permit rendering in a future firmware) updates every consumer —
// scattered per-file copies meant the device could label a token in one
// code path and show raw hex in another.

import { selectorMatches } from '../transport/bytes'

/** `transfer(address,uint256)` */
export const ERC20_TRANSFER_SELECTOR = new Uint8Array([0xa9, 0x05, 0x9c, 0xbb])
/** `transferFrom(address,address,uint256)` */
export const ERC20_TRANSFER_FROM_SELECTOR = new Uint8Array([0x23, 0xb8, 0x72, 0xdd])
/** `approve(address,uint256)` */
export const ERC20_APPROVE_SELECTOR = new Uint8Array([0x09, 0x5e, 0xa7, 0xb3])

export const ERC20_METHOD_SELECTORS: readonly Uint8Array[] = [
  ERC20_TRANSFER_SELECTOR,
  ERC20_TRANSFER_FROM_SELECTOR,
  ERC20_APPROVE_SELECTOR
]

export function isErc20MethodCall(data: Uint8Array): boolean {
  if (data.length < 4) return false
  return ERC20_METHOD_SELECTORS.some((sel) => selectorMatches(data, sel))
}
