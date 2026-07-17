// Dapp-facing (EIP-1193 / EIP-5792) answers for PQ1 accounts.
//
// PQ1 accounts are PQSmartWallets — ERC-4337 smart-contract accounts
// deployed via CREATE2 at the same address on every chain in
// `PQ1_SUPPORTED_CHAIN_IDS`. Ambire imports them with `creation: null`, so
// its own account model treats them as plain EOAs. Two dapp-facing answers
// would be wrong under that model, and `ProviderController` delegates them
// here so the PQ1-specific reasoning stays out of the shared controller:
//
//   - `eth_getCode`: dapps (e.g. Safe) only check `code !== '0x'` to tell a
//     smart-contract wallet from an EOA. See `Pq1AccountCodeResolver`.
//   - `wallet_getCapabilities`: `getBaseAccount` → EOA → atomic
//     'unsupported', while every PQ1 wallet runs N inner calls atomically
//     in one userOp via `executeBatchWithOffchainCount`. See
//     `buildPq1Capabilities`.

import type { JsonRpcProvider } from 'ethers'

import { Key } from '@ambire-common/interfaces/keystore'
import { Network } from '@ambire-common/interfaces/network'
import { networkChainIdToHex } from '@ambire-common/libs/networks/networks'

import { PQ1_SUPPORTED_CHAIN_IDS } from './config'

// Non-empty `eth_getCode` stub returned for a connected PQ1 account that
// isn't deployed on the dapp-session chain yet (counterfactual CREATE2
// address). A single INVALID opcode (0xfe) is enough to make dapps treat
// the PQ1 account as a smart-contract wallet pre-deployment.
export const PQ1_UNDEPLOYED_ACCOUNT_CODE = '0xfe'

export const isPq1Key = (keys: Key[], addr: string): boolean =>
  keys.some((k) => k.type === 'pq1' && k.addr.toLowerCase() === addr.toLowerCase())

export const isEthGetCodeParams = (params: unknown): params is [string, ...unknown[]] =>
  Array.isArray(params) && typeof params[0] === 'string'

const isLatestBlockTag = (blockTag: unknown) =>
  blockTag === undefined || blockTag === null || blockTag === 'latest' || blockTag === 'pending'

/**
 * Answers `eth_getCode` for a PQ1 account honestly from the dapp-session
 * chain wherever honesty is possible, and only shims the truly
 * counterfactual case:
 *   - Historical blockTag queries pass through untouched — chain state at
 *     a past block must never be fabricated.
 *   - A 'latest' query is served with the session chain's real bytecode
 *     when there is any. Answering with another chain's bytecode would make
 *     dapps route signature checks down the plain ERC-1271 path against an
 *     address with no code on the session chain — rejecting perfectly valid
 *     ERC-6492 signatures.
 *   - Only when the wallet has no code on the session chain does the
 *     minimal non-empty stub (`PQ1_UNDEPLOYED_ACCOUNT_CODE`) go back instead
 *     of `0x`, so dapps still treat the connected PQ1 account as a
 *     smart-contract wallet before its first on-chain deployment.
 *
 * Positive answers are cached per `${chainId}:${addr}`: a deployed
 * PQSmartWallet's code at 'latest' never changes (no selfdestruct path),
 * and dapps re-probe on every connect / account switch / chain switch.
 * Undeployed ('0x') results are deliberately NOT cached so the first probe
 * after the wallet's deployment sees real code.
 */
export class Pq1AccountCodeResolver {
  #cache = new Map<string, string>()

  async resolve(
    provider: JsonRpcProvider,
    chainId: bigint,
    params: [string, ...unknown[]]
  ): Promise<string> {
    const [addr, blockTag] = params
    if (!isLatestBlockTag(blockTag)) return provider.send('eth_getCode', params)

    const cacheKey = `${chainId.toString()}:${addr.toLowerCase()}`
    const cached = this.#cache.get(cacheKey)
    if (cached) return cached

    try {
      const code = await provider.send('eth_getCode', params)
      if (code && code !== '0x') {
        this.#cache.set(cacheKey, code)
        return code
      }
    } catch (e) {
      // The probe exists to keep SCW detection resilient; a session-chain
      // RPC hiccup shouldn't fail the dapp's whole request when the stub
      // below is exactly what an undeployed wallet would be answered.
      console.warn('[pq1] eth_getCode probe failed, answering with the undeployed stub', e)
    }
    return PQ1_UNDEPLOYED_ACCOUNT_CODE
  }
}

/**
 * EIP-5792 `wallet_getCapabilities` map for a PQ1 account: atomic batching
 * on every chain the wallet is deployable on, nothing else (no gas tank,
 * no paymaster — PQ1 always pays gas in the native token from itself).
 * Same per-chain entry shape as the generic branch in `ProviderController`.
 */
export const buildPq1Capabilities = (networks: Network[]) => {
  const capabilities: Record<string, unknown> = {}
  networks.forEach((network) => {
    const supported = PQ1_SUPPORTED_CHAIN_IDS.includes(Number(network.chainId))
    capabilities[networkChainIdToHex(network.chainId)] = {
      atomicBatch: { supported },
      auxiliaryFunds: { supported: false },
      paymasterService: { supported: false },
      atomic: { status: supported ? 'supported' : 'unsupported' }
    }
  })
  return capabilities
}
