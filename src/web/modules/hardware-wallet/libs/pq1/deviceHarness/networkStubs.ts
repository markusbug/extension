// Network stand-ins for the PQ1 device harness. The harness drives the real
// production entry points (`PQ1Signer.broadcastAccountOp` / `signMessage` /
// `signTypedData`); everything those touch outside the device is answered
// here, so a scenario runs with no wallet funds, no deployed account and —
// most importantly — no way to reach a bundler:
//
//   - `createFakeProvider` answers the handful of on-chain reads the PQ1
//     pipeline makes (deploy status, owner index, EntryPoint nonce,
//     offchain counter, verifier/factory reads).
//   - `installFetchStub` answers Pimlico, the CoW orderbook and the Safe
//     Transaction Service from local fixtures. `eth_sendUserOperation` is
//     recorded and answered with a fake hash; it is NEVER forwarded.
//     Every other request (the extension's own catalog files) passes
//     through untouched.

import type { JsonRpcProvider } from 'ethers'
import { encodeAbiParameters } from 'viem'

import {
  encodeC10Verifier,
  encodeGetAddress,
  encodeGetNonce,
  encodeNextOwnerIndex,
  encodeOffchainSigCount
} from '../aa/contracts'

const ZERO_32 = `0x${'00'.repeat(32)}` as const

const word = (v: bigint) => encodeAbiParameters([{ type: 'uint256' }], [v])
const addressWord = (a: `0x${string}`) => encodeAbiParameters([{ type: 'address' }], [a])
const selectorOf = (calldata: string) => calldata.slice(0, 10).toLowerCase()

/** EntryPoint nonce the fake chain reports for the harness account. */
export const HARNESS_NONCE = 7n

/** On-chain reads for a never-funded harness account. `deployed: false`
 *  sends the pipeline down the first-deploy path (init code from the
 *  device); `deployed: true` makes it sign as an existing account. */
export function createFakeProvider(opts: {
  sender: `0x${string}`
  deployed: boolean
}): JsonRpcProvider {
  const senderLc = opts.sender.toLowerCase()
  const answers: Record<string, string> = {
    [selectorOf(encodeNextOwnerIndex())]: word(2n), // active ownerIndex 1 → slot 0
    [selectorOf(encodeGetNonce(opts.sender))]: word(HARNESS_NONCE),
    [selectorOf(encodeOffchainSigCount(1n))]: word(0n),
    [selectorOf(encodeC10Verifier())]: addressWord('0x00000000000000000000000000000000000c1010'),
    // The factory's CREATE2 prediction always agrees with the device here;
    // the real check runs against the live factory in production.
    [selectorOf(encodeGetAddress(ZERO_32, ZERO_32))]: addressWord(opts.sender)
  }
  const provider = {
    async getCode(address: string) {
      if (address.toLowerCase() !== senderLc) return '0x60'
      return opts.deployed ? '0x6080604052' : '0x'
    },
    async call(tx: { to?: string | null; data?: string | null }) {
      const answer = answers[selectorOf(tx.data ?? '')]
      if (!answer) throw new Error(`[pq1 harness] unexpected eth_call ${selectorOf(tx.data ?? '')}`)
      return answer
    },
    async send(method: string) {
      throw new Error(`[pq1 harness] unexpected provider.send(${method})`)
    }
  }
  // Only the methods above are reachable from the PQ1 pipeline.
  return provider as unknown as JsonRpcProvider
}

/** A UserOp the pipeline tried to submit. Only its shape is kept; the
 *  signature itself is dropped so nothing replayable leaves the page. */
export type CapturedUserOp = {
  hasInitCode: boolean
  callDataBytes: number
  signatureBytes: number
  maxFeePerGas: string
}

export type ApiFixtures = {
  /** CoW orderbook responses keyed by lowercase order uid. */
  cowOrders: Map<string, unknown>
  /** Safe Transaction Service responses keyed by lowercase safeTxHash. */
  safeTxs: Map<string, unknown>
}

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } })

const PIMLICO_ESTIMATE = {
  callGasLimit: '0x30d40', // 200k
  verificationGasLimit: '0xc3500', // 800k
  preVerificationGas: '0xc350' // 50k
}

const FAKE_USER_OP_HASH = `0x${'ab'.repeat(32)}`

function answerPimlico(body: string, onUserOp: (op: CapturedUserOp) => void): Response {
  const req = JSON.parse(body) as { id: number; method: string; params: unknown[] }
  const reply = (result: unknown) => json({ jsonrpc: '2.0', id: req.id, result })
  switch (req.method) {
    case 'eth_estimateUserOperationGas':
      return reply(PIMLICO_ESTIMATE)
    case 'pimlico_getUserOperationGasPrice': {
      const tier = { maxFeePerGas: '0x77359400', maxPriorityFeePerGas: '0x5f5e100' }
      return reply({ slow: tier, standard: tier, fast: tier })
    }
    case 'eth_sendUserOperation': {
      const op = req.params[0] as Record<string, string>
      onUserOp({
        hasInitCode: (op.initCode ?? '0x') !== '0x',
        callDataBytes: ((op.callData ?? '0x').length - 2) / 2,
        signatureBytes: ((op.signature ?? '0x').length - 2) / 2,
        maxFeePerGas: op.maxFeePerGas ?? ''
      })
      return reply(FAKE_USER_OP_HASH)
    }
    default:
      return json({ jsonrpc: '2.0', id: req.id, error: { code: -32601, message: req.method } })
  }
}

/** Last path segment that is a 0x-prefixed id (order uid / safeTxHash). */
function idInPath(url: string, marker: string): string | null {
  const at = url.indexOf(marker)
  if (at < 0) return null
  const rest = url.slice(at + marker.length)
  const end = rest.indexOf('/')
  return (end < 0 ? rest : rest.slice(0, end)).toLowerCase()
}

/** Replace `globalThis.fetch` for the duration of one scenario. Returns the
 *  function that restores the original — always call it (try/finally). */
export function installFetchStub(
  fixtures: ApiFixtures,
  onUserOp: (op: CapturedUserOp) => void
): () => void {
  const originalFetch = globalThis.fetch
  globalThis.fetch = async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url
    if (url.startsWith('https://api.pimlico.io/')) {
      return answerPimlico(String(init?.body ?? '{}'), onUserOp)
    }
    if (url.startsWith('https://api.cow.fi/')) {
      const uid = idInPath(url, '/orders/')
      const order = uid ? fixtures.cowOrders.get(uid) : undefined
      return order ? json(order) : json({ errorType: 'NotFound' }, 404)
    }
    if (url.includes('/multisig-transactions/')) {
      const hash = idInPath(url, '/multisig-transactions/')
      const tx = hash ? fixtures.safeTxs.get(hash) : undefined
      return tx ? json(tx) : json({ detail: 'Not found.' }, 404)
    }
    return originalFetch(input, init)
  }
  return () => {
    globalThis.fetch = originalFetch
  }
}
