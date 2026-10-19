// The harness restores progress from a copied report, so the report format
// must round-trip — including comments and device error details.

import { buildReport, parseReport } from './report'
import { SCENARIOS } from './scenarios'
import { SEED_REPORT } from './seedReport'

jest.mock('@common/config/analytics/CrashAnalytics.web', () => ({ captureException: jest.fn() }))

describe('harness report', () => {
  it('restores every row of the first device run', () => {
    const results = parseReport(SEED_REPORT, SCENARIOS)
    expect(Object.keys(results)).toHaveLength(9)
    expect(results['send-usdc']).toMatchObject({
      outcome: { status: 'signed', reachedDevice: true },
      verdict: 'matches'
    })
    expect(results['approve-usdc-permit2']?.verdict).toBe('wrong')
    expect(results['approve-usdt-unlimited']).toMatchObject({
      outcome: {
        status: 'failed',
        deviceDetail: 'SIGN_USEROP failed: SW=0x6f00 [no code]',
        message:
          'Something went wrong while talking to the PQ1. Unplug it, plug it back in, and try again.'
      },
      verdict: 'wrong'
    })
    expect(results['weth-wrap']?.outcome?.status).toBe('failed')
  })

  it('round-trips comments, including pipes and line breaks', () => {
    const results = parseReport(SEED_REPORT, SCENARIOS)
    results['approve-usdc-permit2'] = {
      ...results['approve-usdc-permit2'],
      comment: 'Spender shown as raw hex | not "Permit2"\nsecond line'
    }
    const report = buildReport({ scenarios: SCENARIOS, results, deviceId: 'abc' })
    const reparsed = parseReport(report, SCENARIOS)
    expect(reparsed['approve-usdc-permit2']).toMatchObject({
      verdict: 'wrong',
      comment: 'Spender shown as raw hex | not "Permit2" second line'
    })
    expect(Object.keys(reparsed)).toHaveLength(9)
  })
})
