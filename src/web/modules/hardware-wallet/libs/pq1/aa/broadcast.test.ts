// Host-side refusals in the broadcast pipeline must reach the user as plain
// language (`Pq1UserError`), never as protocol detail, and must happen
// before any device or network work. These cover the batch-size gate and
// the Safe DelegateCall gate that mirrors the firmware's refusal.

import { encodeFunctionData, parseAbi, zeroAddress } from 'viem'

import { MAX_BATCH_TXS } from '../config'
import { Pq1UserError } from '../errors'
import { assertPq1CallCount, buildCallTrailers } from './broadcast'

jest.mock('@common/config/analytics/CrashAnalytics.web', () => ({
  captureException: jest.fn()
}))

const SAFE = '0x1111111111111111111111111111111111111111'
const SENDER = '0x2222222222222222222222222222222222222222'
const NOT_MULTISEND = '0x3333333333333333333333333333333333333333'

const SAFE_ABI = parseAbi([
  'function execTransaction(address to, uint256 value, bytes data, uint8 operation, uint256 safeTxGas, uint256 baseGas, uint256 gasPrice, address gasToken, address refundReceiver, bytes signatures)'
])

const execTransaction = (operation: number) =>
  encodeFunctionData({
    abi: SAFE_ABI,
    functionName: 'execTransaction',
    args: [NOT_MULTISEND, 0n, '0x', operation, 0n, 0n, 0n, zeroAddress, zeroAddress, '0x']
  })

describe('assertPq1CallCount', () => {
  it(`accepts up to ${MAX_BATCH_TXS} calls`, () => {
    expect(() => assertPq1CallCount(new Array(MAX_BATCH_TXS).fill(null))).not.toThrow()
  })

  it('refuses a larger batch with a plain-language Pq1UserError', () => {
    let caught: unknown
    try {
      assertPq1CallCount(new Array(MAX_BATCH_TXS + 1).fill(null))
    } catch (e) {
      caught = e
    }
    expect(caught).toBeInstanceOf(Pq1UserError)
    expect((caught as Pq1UserError).message).toContain(`up to ${MAX_BATCH_TXS} actions`)
    expect((caught as Pq1UserError).message).not.toContain('MAX_BATCH_TXS')
  })
})

describe('buildCallTrailers', () => {
  beforeEach(() => {
    jest.spyOn(console, 'warn').mockImplementation(() => {})
  })

  afterEach(() => {
    jest.restoreAllMocks()
  })

  it('refuses a Safe DelegateCall to a non-MultiSend target, in plain language', async () => {
    const result = buildCallTrailers({
      chainId: 1,
      sender: SENDER,
      calls: [{ to: SAFE, value: 0n, data: execTransaction(1) }]
    })
    await expect(result).rejects.toBeInstanceOf(Pq1UserError)
    const error: Pq1UserError = await result.then(
      () => {
        throw new Error('expected buildCallTrailers to reject')
      },
      (e: Pq1UserError) => e
    )
    expect(error.message).not.toContain('DelegateCall')
    expect(error.message).not.toContain('operation')
    expect(error.technicalDetail).toContain('DelegateCall')
  })

  it('attaches no Safe or CoW trailer to a plain Safe Call (operation 0)', async () => {
    const { perCallTrailers } = await buildCallTrailers({
      chainId: 1,
      sender: SENDER,
      calls: [{ to: SAFE, value: 0n, data: execTransaction(0) }]
    })
    expect(perCallTrailers).toHaveLength(1)
    expect(perCallTrailers[0]!.safeV1Bundle).toBeUndefined()
    expect(perCallTrailers[0]!.zkV3Bundle).toBeUndefined()
  })
})
