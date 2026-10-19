// Offline dry run of every harness scenario against a fake device, so a
// broken fixture (CoW uid, safeTxHash, fake-provider gap) shows up here and
// not in front of a real PQ1. The fake device runs the real wire-payload
// builders, so firmware size caps and trailer rules are checked too.

import { C10_SIG_LEN, FACTORY, PQ_INIT_CODE_LEN, SIG_WRAPPER_LEN } from '../config'
import { buildSignOffchainPayload, type SignOffchainParams } from '../transport/offchain'
import {
  buildSignBatchPayload,
  buildSignPayload,
  type BatchSignRequestParams,
  type SignRequestParams
} from '../transport/signRequest'
import { hexToBytes } from '../transport/bytes'
import { HARNESS_ACCOUNT_INDEX, runScenario } from './runScenario'
import { type Scenario, SCENARIOS } from './scenarios'

jest.mock('@common/config/analytics/CrashAnalytics.web', () => ({ captureException: jest.fn() }))
// SafeApiKit loads node-fetch through a dynamic import Jest's VM can't run.
// In the browser it reads `window.fetch` per request, which the harness
// stub intercepts — this stand-in issues the same kind of request.
jest.mock('@safe-global/api-kit', () => ({
  __esModule: true,
  default: class {
    getTransaction(safeTxHash: string) {
      return fetch(`https://safe-tx.test/api/v2/multisig-transactions/${safeTxHash}/`).then((r) =>
        r.json()
      )
    }
  }
}))

const SENDER = '0x00000000000000000000000000000000000abc25'

function fakeInitCode(): Uint8Array {
  const initCode = new Uint8Array(PQ_INIT_CODE_LEN)
  initCode.set(hexToBytes(FACTORY), 0)
  return initCode
}

function fakeDevice() {
  const sent: string[] = []
  const commands = {
    getInitCode: jest.fn(async () => fakeInitCode()),
    signUserOp: jest.fn(async (p: SignRequestParams) => {
      buildSignPayload(p)
      sent.push('signUserOp')
      return {
        newOffchainCount: 1n,
        initCode: p.includeInitCode ? fakeInitCode() : null,
        type1: null,
        type2: new Uint8Array(SIG_WRAPPER_LEN)
      }
    }),
    signUserOpBatch: jest.fn(async (p: BatchSignRequestParams) => {
      buildSignBatchPayload(p)
      sent.push('signUserOpBatch')
      return {
        newOffchainCount: 1n,
        initCode: null,
        type1: null,
        type2: new Uint8Array(SIG_WRAPPER_LEN)
      }
    }),
    signOffchain: jest.fn(async (p: SignOffchainParams) => {
      buildSignOffchainPayload(p)
      sent.push(`signOffchain:${p.kind}`)
      return {
        kind: 'deployed' as const,
        newOffchainCount: 1n,
        innerSig: new Uint8Array(C10_SIG_LEN)
      }
    }),
    offchainSync: jest.fn(async () => {})
  }
  const controller = {
    deviceId: 'harness-test',
    walletSDK: { commands, transport: { isConnected: () => true } },
    unlock: async () => 'ALREADY_UNLOCKED' as const,
    signingCleanup: async () => {}
  }
  return { controller, commands, sent }
}

const run = (scenario: Scenario) => {
  const { controller, commands, sent } = fakeDevice()
  return runScenario({ scenario, controller: controller as never, sender: SENDER }).then(
    (outcome) => ({ outcome, commands, sent })
  )
}

describe('PQ1 device harness scenarios (fake device)', () => {
  const env = { ...process.env }

  beforeAll(() => {
    process.env.REACT_APP_PIMLICO_API_KEY = 'harness-test'
    process.env.SAFE_API_KEY = 'harness-test'
  })

  afterAll(() => {
    process.env = env
  })

  beforeEach(() => {
    jest.spyOn(console, 'warn').mockImplementation(() => {})
    jest.spyOn(console, 'error').mockImplementation(() => {})
  })

  afterEach(() => {
    jest.restoreAllMocks()
  })

  it('has unique scenario ids', () => {
    const ids = SCENARIOS.map((s) => s.id)
    expect(new Set(ids).size).toBe(ids.length)
  })

  it.each(SCENARIOS.map((s) => [s.id, s] as const))(
    '%s behaves as expected',
    async (_id, scenario) => {
      const { outcome, sent } = await run(scenario)
      if (scenario.expectHostRefusal) {
        expect(outcome.status).toBe('refused-by-wallet')
        expect(sent).toHaveLength(0)
        return
      }
      expect({ status: outcome.status, message: outcome.message }).toEqual({
        status: 'signed',
        message: expect.any(String)
      })
      expect(sent).toHaveLength(1)
    }
  )

  it('never touches the bootstrap key unless the scenario allows it', async () => {
    const firstDeploy = SCENARIOS.find((s) => s.spendsBootstrapKey)!
    const { outcome, commands } = await run({ ...firstDeploy, spendsBootstrapKey: false })
    expect(outcome.status).toBe('refused-by-wallet')
    expect(commands.getInitCode).not.toHaveBeenCalled()
  })

  it('signs only as the harness account', async () => {
    const { commands } = await run(SCENARIOS[0]!)
    expect(commands.signUserOp.mock.calls[0]![0].accountIndex).toBe(HARNESS_ACCOUNT_INDEX)
  })
})
