// Scenario catalog for the PQ1 device harness: one entry per request shape
// Ambire can hand the PQ1 signer. Each scenario builds exactly what Ambire
// would pass to `PQ1Signer` (calls + fee, a message, or typed data) and
// states what the device should show — or, for requests the wallet must
// refuse, the plain-language message the user should see instead.
//
// CoW and Safe inputs are self-consistent fixtures (the order uid and the
// safeTxHash are derived from the fixture fields with the module's own
// encoders), served by `networkStubs.installFetchStub`, so the trailers the
// device verifies are byte-identical to what production builds.

import {
  encodeFunctionData,
  encodePacked,
  erc20Abi,
  maxUint256,
  parseAbi,
  parseEther,
  parseGwei,
  parseUnits,
  stringToHex,
  zeroAddress
} from 'viem'

import type { TypedMessageUserRequest } from '@ambire-common/interfaces/userRequest'

import { buildOrderUid, GPV2_SETTLEMENT_ADDRESS } from '../cowswap/eip712'
import type { GPv2Order } from '../cowswap/types'
import { safeDataHash } from '../safe/canonical'
import { computeSafeTxHash } from '../safe/eip712'
import { bytesToHex0x, hexToBytes } from '../transport/bytes'
import { ERC7730_CALL_FIXTURES, type Erc7730CallFixture } from './fixtures'
import type { ApiFixtures } from './networkStubs'

type Hex = `0x${string}`
type Call = { to: Hex; value: bigint; data: Hex }
type TypedDataParams = TypedMessageUserRequest['meta']['params']

export type ScenarioGroup =
  | 'Sends'
  | 'Approvals'
  | 'Contract calls'
  | 'Batches'
  | 'CoW Swap'
  | 'Safe'
  | 'First deploy'
  | 'Messages'

export type ScenarioRequest =
  | {
      kind: 'transaction'
      chainId: number
      calls: Call[]
      /** Fee the user approved (max fee per gas). Defaults to 2 gwei. */
      maxFeePerGas?: bigint
      /** false = the account is not on-chain yet (first-deploy path). */
      deployed?: boolean
      fixtures?: Partial<ApiFixtures>
    }
  | { kind: 'message'; chainId: number; message: Hex }
  | { kind: 'typedData'; chainId: number; typedData: TypedDataParams }

export type Scenario = {
  id: string
  group: ScenarioGroup
  title: string
  /** What the device should show, or the message Ambire should show. */
  expected: string
  /** The wallet must refuse before anything reaches the device. */
  expectHostRefusal?: boolean
  /** The request reaches the device, which must refuse to sign it (and say
   *  why on its screen); Ambire then reports the device's refusal. */
  expectDeviceRefusal?: boolean
  /** Spends one use of the few-time bootstrap key; never part of Run all. */
  spendsBootstrapKey?: boolean
  build: (ctx: { sender: Hex }) => ScenarioRequest
}

// ── Addresses (Ethereum unless noted) ─────────────────────────────────
const USDC = '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48'
const USDT = '0xdAC17F958D2ee523a2206206994597C13D831ec7'
const DAI = '0x6B175474E89094C44Da98b954EedeAC495271d0F'
const WETH = '0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2'
const PERMIT2 = '0x000000000022D473030F116dDEE9F6B43aC78BA3'
const UNISWAP_V2_ROUTER = '0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D'
const UNISWAP_SWAP_ROUTER_02 = '0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45'
const COW_VAULT_RELAYER = '0xC92E8bdf79f0507f65a392b0ab4667716BFE0110'
const SEAPORT = '0x0000000000000068F116a894984e2DB1123eB395'
const BAYC = '0xBC4CA0EdA7647A8aB7C2061c2E118A18a936f13D'
const MULTISEND_CALL_ONLY = '0x9641d764fc13c8B624c04430C7356C1C7C8102e2'
const LBTC = '0x8236a87084f8B84306f72007F36F2618A5634494'
const BASE_USDC = '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913'
/** Not in any catalog — renders as a raw address. */
const RECIPIENT = '0x1234567890AbcdEF1234567890aBcdef12345678'
/** Not in the ERC-20 catalog — renders as an unknown token. */
const UNKNOWN_TOKEN = '0x7e57700000000000000000000000000000c0ffee'
/** A Safe the harness account co-owns (fixture only). */
const SAFE = '0x5afe5afe5afe5afe5afe5afe5afe5afe5afe5afe'

const ETHEREUM = 1
const BASE = 8453
const BASE_SEPOLIA = 84532

const COW_ABI = parseAbi(['function setPreSignature(bytes orderUid, bool signed)'])
const SAFE_ABI = parseAbi([
  'function approveHash(bytes32 hashToApprove)',
  'function execTransaction(address to, uint256 value, bytes data, uint8 operation, uint256 safeTxGas, uint256 baseGas, uint256 gasPrice, address gasToken, address refundReceiver, bytes signatures)'
])
const MULTISEND_ABI = parseAbi(['function multiSend(bytes transactions)'])
const MISC_ABI = parseAbi([
  'function safeTransferFrom(address from, address to, uint256 tokenId)',
  'function fulfillAvailableOrders(bytes orders, bytes criteria, bytes fulfillerConduitKey, uint256 maximumFulfilled)'
])

const transfer = (token: Hex, to: Hex, amount: bigint): Call => ({
  to: token,
  value: 0n,
  data: encodeFunctionData({ abi: erc20Abi, functionName: 'transfer', args: [to, amount] })
})
const approve = (token: Hex, spender: Hex, amount: bigint): Call => ({
  to: token,
  value: 0n,
  data: encodeFunctionData({ abi: erc20Abi, functionName: 'approve', args: [spender, amount] })
})
const sendEth = (to: Hex, amount: bigint): Call => ({ to, value: amount, data: '0x' })
const fixtureCall = (f: Erc7730CallFixture): Call => ({ to: f.to, value: f.value, data: f.data })
const fixtureExpectation = (f: Erc7730CallFixture) =>
  `Clear-signed contract call. Same facts as the ERC-7730 registry reference (${
    f.source
  }): ${f.expectedTexts.join(' · ')}`

// ── CoW fixtures ──────────────────────────────────────────────────────
type CowFixture = { presign: Call; uid: string; api: unknown }

/** A sell-USDC-for-WETH order owned by `owner`, its presign call, and the
 *  orderbook entry the stub serves for it. */
function cowOrder(owner: Hex): CowFixture {
  const order: GPv2Order = {
    chainId: ETHEREUM,
    sellToken: USDC,
    buyToken: WETH,
    receiver: owner,
    sellAmount: parseUnits('1500', 6),
    buyAmount: parseEther('0.5'),
    validTo: 1893456000, // 2030-01-01
    appData: new Uint8Array(32),
    feeAmount: 0n,
    kind: 'sell',
    partiallyFillable: false,
    sellTokenBalance: 'erc20',
    buyTokenBalance: 'erc20'
  }
  const uid = buildOrderUid(order, owner).toHex() as Hex
  return {
    uid: uid.toLowerCase(),
    presign: {
      to: GPV2_SETTLEMENT_ADDRESS,
      value: 0n,
      data: encodeFunctionData({ abi: COW_ABI, functionName: 'setPreSignature', args: [uid, true] })
    },
    api: {
      uid,
      owner,
      sellToken: order.sellToken,
      buyToken: order.buyToken,
      receiver: order.receiver,
      sellAmount: order.sellAmount.toString(),
      buyAmount: order.buyAmount.toString(),
      feeAmount: '0',
      validTo: order.validTo,
      appData: bytesToHex0x(order.appData),
      kind: order.kind,
      partiallyFillable: false,
      sellTokenBalance: 'erc20',
      buyTokenBalance: 'erc20',
      signingScheme: 'presign',
      status: 'presignaturePending'
    }
  }
}

// ── Safe fixtures ─────────────────────────────────────────────────────
/** `execTransaction` signature for an owner calling the Safe directly
 *  ("approved by msg.sender": r = owner, s = 0, v = 1). */
const ownerCallSignature = (owner: Hex) =>
  encodePacked(['uint256', 'uint256', 'uint8'], [BigInt(owner), 0n, 1])

const execTransaction = (owner: Hex, inner: { to: Hex; data: Hex; operation: number }): Call => ({
  to: SAFE,
  value: 0n,
  data: encodeFunctionData({
    abi: SAFE_ABI,
    functionName: 'execTransaction',
    args: [
      inner.to,
      0n,
      inner.data,
      inner.operation,
      0n,
      0n,
      0n,
      zeroAddress,
      zeroAddress,
      ownerCallSignature(owner)
    ]
  })
})

/** `approveHash` for a SafeTx that sends 100 USDC from the Safe, plus the
 *  Transaction Service entry the stub serves for its hash. */
function safeApproveHash(): { call: Call; hash: string; api: unknown } {
  const inner = transfer(USDC, RECIPIENT, parseUnits('100', 6))
  const nonce = 3n
  const hash = bytesToHex0x(
    computeSafeTxHash({
      chainId: ETHEREUM,
      safeAddress: SAFE,
      to: inner.to,
      value: 0n,
      dataHash: safeDataHash(hexToBytes(inner.data)),
      operation: 0,
      safeTxGas: 0n,
      baseGas: 0n,
      gasPrice: 0n,
      gasToken: zeroAddress,
      refundReceiver: zeroAddress,
      nonce
    })
  )
  return {
    hash: hash.toLowerCase(),
    call: {
      to: SAFE,
      value: 0n,
      data: encodeFunctionData({ abi: SAFE_ABI, functionName: 'approveHash', args: [hash] })
    },
    api: {
      safe: SAFE,
      to: inner.to,
      value: '0',
      data: inner.data,
      operation: 0,
      safeTxGas: '0',
      baseGas: '0',
      gasPrice: '0',
      gasToken: zeroAddress,
      refundReceiver: zeroAddress,
      nonce: nonce.toString(),
      safeTxHash: hash
    }
  }
}

/** MultiSendCallOnly payload: every record `operation = 0`. */
const multiSend = (records: Call[]): Hex =>
  encodeFunctionData({
    abi: MULTISEND_ABI,
    functionName: 'multiSend',
    args: [
      `0x${records
        .map((r) =>
          encodePacked(
            ['uint8', 'address', 'uint256', 'uint256', 'bytes'],
            [0, r.to, r.value, BigInt((r.data.length - 2) / 2), r.data]
          ).slice(2)
        )
        .join('')}`
    ]
  })

// ── Typed data ────────────────────────────────────────────────────────
const DOMAIN_FIELDS = [
  { name: 'name', type: 'string' },
  { name: 'version', type: 'string' },
  { name: 'chainId', type: 'uint256' },
  { name: 'verifyingContract', type: 'address' }
]

const typed = (
  domain: Record<string, unknown>,
  types: Record<string, { name: string; type: string }[]>,
  primaryType: string,
  message: Record<string, unknown>
): TypedDataParams =>
  ({
    domain,
    types: { EIP712Domain: DOMAIN_FIELDS.filter((f) => f.name in domain), ...types },
    primaryType,
    message
  }) as TypedDataParams

type TransactionRequest = Extract<ScenarioRequest, { kind: 'transaction' }>

const tx = (
  chainId: number,
  calls: Call[],
  extra: Partial<Pick<TransactionRequest, 'maxFeePerGas' | 'deployed' | 'fixtures'>> = {}
): TransactionRequest => ({ kind: 'transaction', chainId, calls, ...extra })

const LONG_MESSAGE = `${'This message is longer than the 700 characters the PQ1 can show as text. '.repeat(11)}`

/** Every scenario, in the order the harness runs them. */
export const SCENARIOS: Scenario[] = [
  // ── Sends ──
  {
    id: 'send-eth-raw',
    group: 'Sends',
    title: 'Send ETH to an address with no name',
    expected: 'Send 0.01 ETH to 0x1234…5678 (raw address), Ethereum, fee shown',
    build: () => tx(ETHEREUM, [sendEth(RECIPIENT, parseEther('0.01'))])
  },
  {
    id: 'send-usdc',
    group: 'Sends',
    title: 'Send USDC',
    expected: 'Send 25 USDC to 0x1234…5678 (token symbol and decimals from the catalog)',
    build: () => tx(ETHEREUM, [transfer(USDC, RECIPIENT, parseUnits('25', 6))])
  },
  {
    id: 'send-unknown-token',
    group: 'Sends',
    title: 'Send a token that is not in the catalog',
    expected: 'Unknown-token warning page: raw token address and raw amount, not a symbol',
    build: () => tx(ETHEREUM, [transfer(UNKNOWN_TOKEN, RECIPIENT, 123456789n)])
  },
  {
    id: 'send-usdc-base',
    group: 'Sends',
    title: 'Send USDC on Base',
    expected: 'Send 10 USDC to 0x1234…5678, network shown as Base',
    build: () => tx(BASE, [transfer(BASE_USDC, RECIPIENT, parseUnits('10', 6))])
  },
  {
    id: 'send-eth-base-sepolia',
    group: 'Sends',
    title: 'Send ETH on Base Sepolia',
    expected: 'Send 0.001 ETH to 0x1234…5678, network shown as Base Sepolia (testnet)',
    build: () => tx(BASE_SEPOLIA, [sendEth(RECIPIENT, parseEther('0.001'))])
  },
  // ── Approvals ──
  {
    id: 'approve-usdc-permit2',
    group: 'Approvals',
    title: 'Approve 100 USDC for Permit2',
    expected: 'Approve 100 USDC, spender shown by name (Permit2)',
    build: () => tx(ETHEREUM, [approve(USDC, PERMIT2, parseUnits('100', 6))])
  },
  {
    id: 'approve-usdt-unlimited',
    group: 'Approvals',
    title: 'Unlimited USDT approval for Uniswap V2',
    expected:
      'Approve "Unlimited USDT" (clearly marked as unlimited), spender shown by name (Uniswap V2 Router). Firmware without the Ethereum-only USDT threshold refuses with "render refused".',
    build: () => tx(ETHEREUM, [approve(USDT, UNISWAP_V2_ROUTER, maxUint256)])
  },
  {
    id: 'revoke-dai',
    group: 'Approvals',
    title: 'Revoke DAI approval (approve 0)',
    expected: 'Approve 0 DAI (revoke), spender shown by name (CoW Vault Relayer)',
    build: () => tx(ETHEREUM, [approve(DAI, COW_VAULT_RELAYER, 0n)])
  },
  // ── Contract calls ──
  ...(
    [
      ['weth-wrap', 'Wrap ETH into WETH', ERC7730_CALL_FIXTURES.wethWrap],
      ['lido-stake', 'Stake ETH with Lido', ERC7730_CALL_FIXTURES.lidoStake],
      ['wsteth-wrap', 'Wrap stETH into wstETH', ERC7730_CALL_FIXTURES.wstEthWrap],
      ['aave-supply', 'Supply USDC to Aave', ERC7730_CALL_FIXTURES.aaveSupply],
      ['uniswap-swap', 'Swap on Uniswap (SwapRouter02)', ERC7730_CALL_FIXTURES.uniswapSwap]
    ] as const
  ).map(
    ([id, title, fixture]): Scenario => ({
      id,
      group: 'Contract calls',
      title,
      expected: fixtureExpectation(fixture),
      build: () => tx(ETHEREUM, [fixtureCall(fixture)])
    })
  ),
  {
    id: 'oneinch-swap',
    group: 'Contract calls',
    title: 'Swap ETH on 1inch',
    expected:
      'The device refuses: the 1inch descriptor has no format for ethUnoswap, and the device knows this call needs one. Ambire says the PQ1 refused to sign. (The registry reference would show: Swap 0.002 ETH for at least 1845685323878608 of an unknown token.)',
    expectDeviceRefusal: true,
    build: () => tx(ETHEREUM, [fixtureCall(ERC7730_CALL_FIXTURES.oneInchEthUnoswap)])
  },
  {
    id: 'weth-wrap-trailing-byte',
    group: 'Contract calls',
    title: 'Wrap ETH with a stray byte after the call (upstream reference calldata)',
    expected:
      'The device refuses: one byte after deposit() would be signed but never shown. Ambire says the PQ1 refused to sign.',
    expectDeviceRefusal: true,
    build: () => tx(ETHEREUM, [fixtureCall(ERC7730_CALL_FIXTURES.wethWrapTrailingByte)])
  },
  {
    id: 'nft-transfer',
    group: 'Contract calls',
    title: 'Transfer an NFT (no descriptor)',
    expected:
      'Blind-sign warning for contract 0xBC4C…f13D, with the function named safeTransferFrom(address,address,uint256), its arguments decoded, and a data fingerprint',
    build: ({ sender }) =>
      tx(ETHEREUM, [
        {
          to: BAYC,
          value: 0n,
          data: encodeFunctionData({
            abi: MISC_ABI,
            functionName: 'safeTransferFrom',
            args: [sender, RECIPIENT, 1234n]
          })
        }
      ])
  },
  {
    id: 'named-contract-blind',
    group: 'Contract calls',
    title: 'Call a known contract without a descriptor (Seaport)',
    expected:
      'Blind-sign warning, but the contract is shown by name (OpenSea Seaport 1.6); the function is shown only as its raw selector (not in the curated list)',
    build: () =>
      tx(ETHEREUM, [
        {
          to: SEAPORT,
          value: 0n,
          data: encodeFunctionData({
            abi: MISC_ABI,
            functionName: 'fulfillAvailableOrders',
            args: ['0x', '0x', '0x', 1n]
          })
        }
      ])
  },
  {
    id: 'high-fee',
    group: 'Contract calls',
    title: 'Send ETH with a very high fee (500 gwei)',
    expected: 'Send 0.01 ETH; the fee page shows a large, exact ETH amount that fits the screen',
    build: () =>
      tx(ETHEREUM, [sendEth(RECIPIENT, parseEther('0.01'))], { maxFeePerGas: parseGwei('500') })
  },
  // ── Batches ──
  {
    id: 'batch-approve-swap',
    group: 'Batches',
    title: 'Approve + swap (the Swap & Bridge shape)',
    expected: '2 actions: approve USDC for Uniswap, then the Uniswap swap, each on its own page',
    build: () =>
      tx(ETHEREUM, [
        approve(USDC, UNISWAP_SWAP_ROUTER_02, parseUnits('1020', 6)),
        fixtureCall(ERC7730_CALL_FIXTURES.uniswapSwap)
      ])
  },
  {
    id: 'batch-4',
    group: 'Batches',
    title: '4 actions in one approval (the maximum)',
    expected: '4 actions: USDC send, DAI send, ETH send, WETH wrap — all readable',
    build: () =>
      tx(ETHEREUM, [
        transfer(USDC, RECIPIENT, parseUnits('5', 6)),
        transfer(DAI, RECIPIENT, parseEther('5')),
        sendEth(RECIPIENT, parseEther('0.002')),
        fixtureCall(ERC7730_CALL_FIXTURES.wethWrap)
      ])
  },
  {
    id: 'batch-5',
    group: 'Batches',
    title: '5 actions (over the limit)',
    expected: 'Nothing on the device. Ambire says a PQ1 can approve up to 4 actions at once',
    expectHostRefusal: true,
    build: () =>
      tx(
        ETHEREUM,
        [1n, 2n, 3n, 4n, 5n].map((n) => transfer(USDC, RECIPIENT, n))
      )
  },
  // ── CoW Swap ──
  {
    id: 'cow-presign',
    group: 'CoW Swap',
    title: 'Place a CoW Swap order (pre-sign)',
    expected:
      'Swap order: sell 1500 USDC for at least 0.5 WETH, receiver = your account, valid until 2030-01-01',
    build: ({ sender }) => {
      const cow = cowOrder(sender)
      return tx(ETHEREUM, [cow.presign], { fixtures: { cowOrders: new Map([[cow.uid, cow.api]]) } })
    }
  },
  {
    id: 'cow-approve-presign',
    group: 'CoW Swap',
    title: 'Approve + place a CoW Swap order',
    expected:
      '2 actions: approve 1500 USDC for the CoW Vault Relayer, then the swap order as above',
    build: ({ sender }) => {
      const cow = cowOrder(sender)
      return tx(ETHEREUM, [approve(USDC, COW_VAULT_RELAYER, parseUnits('1500', 6)), cow.presign], {
        fixtures: { cowOrders: new Map([[cow.uid, cow.api]]) }
      })
    }
  },
  {
    id: 'cow-unknown-order',
    group: 'CoW Swap',
    title: 'Pre-sign an order the orderbook does not know',
    expected:
      "Nothing on the device. Ambire says the swap can't be signed because the order details couldn't be read",
    expectHostRefusal: true,
    build: ({ sender }) => tx(ETHEREUM, [cowOrder(sender).presign])
  },
  // ── Safe ──
  {
    id: 'safe-approve-hash',
    group: 'Safe',
    title: 'Approve a Safe transaction (approveHash)',
    expected:
      'Safe confirmation: Safe 0x5afe…5afe sends 100 USDC (token named, not "unknown token") to 0x1234…5678 (nonce 3)',
    build: () => {
      const safe = safeApproveHash()
      return tx(ETHEREUM, [safe.call], { fixtures: { safeTxs: new Map([[safe.hash, safe.api]]) } })
    }
  },
  {
    id: 'safe-exec-transfer',
    group: 'Safe',
    title: 'Execute a Safe transaction (USDC transfer)',
    expected: 'Safe execution: Safe 0x5afe…5afe sends 50 USDC to 0x1234…5678',
    build: ({ sender }) =>
      tx(ETHEREUM, [
        execTransaction(sender, {
          ...transfer(USDC, RECIPIENT, parseUnits('50', 6)),
          operation: 0
        })
      ])
  },
  {
    id: 'safe-cow-presign',
    group: 'Safe',
    title: 'Safe places a CoW Swap order',
    expected: 'Combined Safe + order page: the Safe sells 1500 USDC for at least 0.5 WETH',
    build: ({ sender }) => {
      const cow = cowOrder(SAFE)
      return tx(ETHEREUM, [execTransaction(sender, { ...cow.presign, operation: 0 })], {
        fixtures: { cowOrders: new Map([[cow.uid, cow.api]]) }
      })
    }
  },
  {
    id: 'safe-multisend-approve-presign',
    group: 'Safe',
    title: 'Safe batch: approve + CoW order (MultiSendCallOnly)',
    expected:
      'Safe batch with 2 actions: approve 1500 USDC for the CoW Vault Relayer, then the order',
    build: ({ sender }) => {
      const cow = cowOrder(SAFE)
      return tx(
        ETHEREUM,
        [
          execTransaction(sender, {
            to: MULTISEND_CALL_ONLY,
            data: multiSend([approve(USDC, COW_VAULT_RELAYER, parseUnits('1500', 6)), cow.presign]),
            operation: 1
          })
        ],
        { fixtures: { cowOrders: new Map([[cow.uid, cow.api]]) } }
      )
    }
  },
  {
    id: 'safe-delegatecall',
    group: 'Safe',
    title: 'Safe DelegateCall to an arbitrary contract',
    expected: "Nothing on the device. Ambire says the PQ1 won't sign this Safe transaction",
    expectHostRefusal: true,
    build: ({ sender }) =>
      tx(ETHEREUM, [execTransaction(sender, { to: RECIPIENT, data: '0x', operation: 1 })])
  },
  // ── First deploy ──
  {
    id: 'first-deploy',
    group: 'First deploy',
    title: 'First transaction from a new account (deploys it)',
    expected: 'Send 0.01 ETH, marked as the first transaction that also creates the account',
    spendsBootstrapKey: true,
    build: () => tx(ETHEREUM, [sendEth(RECIPIENT, parseEther('0.01'))], { deployed: false })
  },
  // ── Messages ──
  {
    id: 'msg-text',
    group: 'Messages',
    title: 'Sign a short text message',
    expected: 'The text "Hello from the PQ1 device test" in full, before the first Confirm?',
    build: () => ({
      kind: 'message',
      chainId: ETHEREUM,
      message: stringToHex('Hello from the PQ1 device test')
    })
  },
  {
    id: 'msg-siwe',
    group: 'Messages',
    title: 'Sign in with Ethereum (SIWE)',
    expected:
      'The full sign-in message with its line breaks (domain app.example.com, your address, nonce, issued-at time), all before the first Confirm?',
    build: ({ sender }) => ({
      kind: 'message',
      chainId: ETHEREUM,
      message: stringToHex(
        [
          'app.example.com wants you to sign in with your Ethereum account:',
          sender,
          '',
          'Sign in to Example.',
          '',
          'URI: https://app.example.com',
          'Version: 1',
          'Chain ID: 1',
          'Nonce: 32891756',
          'Issued At: 2026-10-19T12:00:00Z'
        ].join('\n')
      )
    })
  },
  {
    id: 'msg-binary',
    group: 'Messages',
    title: 'Sign raw bytes that are not text',
    expected:
      'A "! NOT TEXT" warning, then the bytes as hex (deadbeef 00ff10e2 c3a4b5c6), before the first Confirm? — never garbled text',
    build: () => ({ kind: 'message', chainId: ETHEREUM, message: '0xdeadbeef00ff10e2c3a4b5c6' })
  },
  {
    id: 'msg-long',
    group: 'Messages',
    title: 'Sign a message longer than the device can show',
    expected:
      'BLIND HASH: the message digest only, clearly labelled as such, shown before the first Confirm?',
    build: () => ({ kind: 'message', chainId: ETHEREUM, message: stringToHex(LONG_MESSAGE) })
  },
  {
    id: 'typed-lbtc-fee',
    group: 'Messages',
    title: 'Typed data with a descriptor (Lombard network fee)',
    expected:
      'Clear-signed fields: Network Fee Authorization, Chain ID 1, Network Fee 0.0003 LBTC, Expiry 2026-05-21',
    build: () => ({
      kind: 'typedData',
      chainId: ETHEREUM,
      typedData: typed(
        { name: 'Lombard Staked Bitcoin', version: '1', chainId: 1, verifyingContract: LBTC },
        {
          feeApproval: [
            { name: 'chainId', type: 'uint256' },
            { name: 'fee', type: 'uint256' },
            { name: 'expiry', type: 'uint256' }
          ]
        },
        'feeApproval',
        { chainId: 1, fee: '300000000000000', expiry: 1779321600 }
      )
    })
  },
  {
    id: 'typed-usdc-permit',
    group: 'Messages',
    title: 'USDC permit (EIP-2612)',
    expected:
      'BLIND HASH (no on-device route for this typed data): "! BLIND RAW32" warning and the full hash, before the first Confirm?',
    build: ({ sender }) => ({
      kind: 'typedData',
      chainId: ETHEREUM,
      typedData: typed(
        { name: 'USD Coin', version: '2', chainId: 1, verifyingContract: USDC },
        {
          Permit: [
            { name: 'owner', type: 'address' },
            { name: 'spender', type: 'address' },
            { name: 'value', type: 'uint256' },
            { name: 'nonce', type: 'uint256' },
            { name: 'deadline', type: 'uint256' }
          ]
        },
        'Permit',
        { owner: sender, spender: PERMIT2, value: '1000000', nonce: 0, deadline: 1893456000 }
      )
    })
  },
  {
    id: 'typed-permit2',
    group: 'Messages',
    title: 'Permit2 single-token permit',
    expected:
      'BLIND HASH (no on-device route: Ambire cannot send nested typed data yet): "! BLIND RAW32" warning and the full hash, before the first Confirm?',
    build: () => ({
      kind: 'typedData',
      chainId: ETHEREUM,
      typedData: typed(
        { name: 'Permit2', chainId: 1, verifyingContract: PERMIT2 },
        {
          PermitSingle: [
            { name: 'details', type: 'PermitDetails' },
            { name: 'spender', type: 'address' },
            { name: 'sigDeadline', type: 'uint256' }
          ],
          PermitDetails: [
            { name: 'token', type: 'address' },
            { name: 'amount', type: 'uint160' },
            { name: 'expiration', type: 'uint48' },
            { name: 'nonce', type: 'uint48' }
          ]
        },
        'PermitSingle',
        {
          details: { token: USDC, amount: '1000000', expiration: 1893456000, nonce: 0 },
          spender: UNISWAP_SWAP_ROUTER_02,
          sigDeadline: 1893456000
        }
      )
    })
  },
  {
    id: 'typed-cow-order',
    group: 'Messages',
    title: 'CoW Swap order signed by an app (EIP-712)',
    // TODO(C7): becomes a clear-signed order once Ambire sends the off-chain
    // CoW order kind (firmware SIGN_OFFCHAIN kind 5).
    expected:
      'BLIND HASH for now: "! BLIND RAW32" warning and the full hash, before the first Confirm?',
    build: ({ sender }) => ({
      kind: 'typedData',
      chainId: ETHEREUM,
      typedData: typed(
        {
          name: 'Gnosis Protocol',
          version: 'v2',
          chainId: 1,
          verifyingContract: GPV2_SETTLEMENT_ADDRESS
        },
        {
          Order: [
            { name: 'sellToken', type: 'address' },
            { name: 'buyToken', type: 'address' },
            { name: 'receiver', type: 'address' },
            { name: 'sellAmount', type: 'uint256' },
            { name: 'buyAmount', type: 'uint256' },
            { name: 'validTo', type: 'uint32' },
            { name: 'appData', type: 'bytes32' },
            { name: 'feeAmount', type: 'uint256' },
            { name: 'kind', type: 'string' },
            { name: 'partiallyFillable', type: 'bool' },
            { name: 'sellTokenBalance', type: 'string' },
            { name: 'buyTokenBalance', type: 'string' }
          ]
        },
        'Order',
        {
          sellToken: USDC,
          buyToken: WETH,
          receiver: sender,
          sellAmount: '1500000000',
          buyAmount: '500000000000000000',
          validTo: 1893456000,
          appData: `0x${'00'.repeat(32)}`,
          feeAmount: '0',
          kind: 'sell',
          partiallyFillable: false,
          sellTokenBalance: 'erc20',
          buyTokenBalance: 'erc20'
        }
      )
    })
  },
  {
    id: 'typed-safe-tx',
    group: 'Messages',
    title: 'Safe transaction signed off-chain (SafeTx)',
    // TODO(C7): becomes a clear-signed Safe transaction once Ambire sends the
    // off-chain SafeTx kind (firmware SIGN_OFFCHAIN kind 4).
    expected:
      'BLIND HASH for now: "! BLIND RAW32" warning and the full hash, before the first Confirm?',
    build: () => ({
      kind: 'typedData',
      chainId: ETHEREUM,
      typedData: typed(
        { chainId: 1, verifyingContract: SAFE },
        {
          SafeTx: [
            { name: 'to', type: 'address' },
            { name: 'value', type: 'uint256' },
            { name: 'data', type: 'bytes' },
            { name: 'operation', type: 'uint8' },
            { name: 'safeTxGas', type: 'uint256' },
            { name: 'baseGas', type: 'uint256' },
            { name: 'gasPrice', type: 'uint256' },
            { name: 'gasToken', type: 'address' },
            { name: 'refundReceiver', type: 'address' },
            { name: 'nonce', type: 'uint256' }
          ]
        },
        'SafeTx',
        {
          to: USDC,
          value: '0',
          data: transfer(USDC, RECIPIENT, parseUnits('100', 6)).data,
          operation: 0,
          safeTxGas: '0',
          baseGas: '0',
          gasPrice: '0',
          gasToken: zeroAddress,
          refundReceiver: zeroAddress,
          nonce: '3'
        }
      )
    })
  },
  {
    id: 'typed-unknown',
    group: 'Messages',
    title: 'Typed data from an unknown app',
    expected:
      'BLIND HASH (no on-device route for this typed data): "! BLIND RAW32" warning and the full hash, before the first Confirm?',
    build: () => ({
      kind: 'typedData',
      chainId: ETHEREUM,
      typedData: typed(
        { name: 'Ether Mail', version: '1', chainId: 1, verifyingContract: RECIPIENT },
        {
          Mail: [
            { name: 'from', type: 'address' },
            { name: 'to', type: 'address' },
            { name: 'contents', type: 'string' }
          ]
        },
        'Mail',
        { from: RECIPIENT, to: SAFE, contents: 'Hello, Bob!' }
      )
    })
  }
]
