// PQSmartWallet / EntryPoint ABI fragments + encoders.

import { decodeFunctionResult, encodeFunctionData, parseAbi, type Address, type Hex } from 'viem'

// Slot-authorised execute selectors per
// sphincs_rust/contracts/smart-wallet/src/PQSmartWallet.sol:344-349
// (`_isSlotAllowedSelector`). The plain `execute(address,uint256,bytes)` path
// exists on the contract but is NOT allowed for slot signatures.
const executeAbi = parseAbi([
  'function executeWithOffchainCount(uint256 ownerIndex, uint256 newOffchainCount, address target, uint256 value, bytes data) returns (bytes)'
])
const executeBatchAbi = parseAbi([
  'function executeBatchWithOffchainCount(uint256 ownerIndex, uint256 newOffchainCount, address[] targets, uint256[] values, bytes[] datas)'
])
const entryPointAbi = parseAbi([
  'function getNonce(address sender, uint192 key) view returns (uint256)'
])
const walletAbi = parseAbi([
  'function nextOwnerIndex() view returns (uint256)',
  'function offchainSigCount(uint256 ownerIndex) view returns (uint256)',
  'function isValidSignature(bytes32 hash, bytes signature) view returns (bytes4)'
])
// `c10Verifier()` is exposed (public immutable) on BOTH the factory and the
// wallet impl, set to the same CREATE2 singleton in DeployImplAndFactory*.s.sol.
// We read it from the factory because it is always deployed — even when the
// wallet itself is still counterfactual (first-deploy gas estimation).
const factoryAbi = parseAbi(['function c10Verifier() view returns (address)'])

export function encodeExecute(
  ownerIndex: bigint,
  newOffchainCount: bigint,
  target: Address,
  value: bigint,
  data: Hex
): Hex {
  return encodeFunctionData({
    abi: executeAbi,
    functionName: 'executeWithOffchainCount',
    args: [ownerIndex, newOffchainCount, target, value, data]
  })
}

export function encodeExecuteBatch(
  ownerIndex: bigint,
  newOffchainCount: bigint,
  targets: Address[],
  values: bigint[],
  datas: Hex[]
): Hex {
  if (targets.length !== values.length || targets.length !== datas.length) {
    throw new Error('executeBatch: target/value/data length mismatch')
  }
  return encodeFunctionData({
    abi: executeBatchAbi,
    functionName: 'executeBatchWithOffchainCount',
    args: [ownerIndex, newOffchainCount, targets, values, datas]
  })
}

export function encodeGetNonce(sender: Address, key = 0n): Hex {
  return encodeFunctionData({
    abi: entryPointAbi,
    functionName: 'getNonce',
    args: [sender, key]
  })
}

export function encodeNextOwnerIndex(): Hex {
  return encodeFunctionData({ abi: walletAbi, functionName: 'nextOwnerIndex' })
}

export function encodeOffchainSigCount(ownerIndex: bigint): Hex {
  return encodeFunctionData({
    abi: walletAbi,
    functionName: 'offchainSigCount',
    args: [ownerIndex]
  })
}

export function encodeC10Verifier(): Hex {
  return encodeFunctionData({ abi: factoryAbi, functionName: 'c10Verifier' })
}

export function decodeC10Verifier(result: Hex): Address {
  return decodeFunctionResult({ abi: factoryAbi, functionName: 'c10Verifier', data: result })
}

export { entryPointAbi, executeAbi, executeBatchAbi, factoryAbi, walletAbi }
