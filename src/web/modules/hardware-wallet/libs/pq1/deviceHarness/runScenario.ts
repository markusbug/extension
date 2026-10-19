// Runs one harness scenario through the real production entry points
// (`PQ1Signer.broadcastAccountOp` / `signMessage` / `signTypedData`) against
// a connected PQ1, with the network stubbed (see `networkStubs.ts`).
//
// Safety rails, all enforced here rather than trusted to the scenarios:
//   - every request signs as HARNESS_ACCOUNT_INDEX, a slot that is never
//     deployed or funded, so its signatures are worthless on-chain;
//   - any device sign command for another account index is refused;
//   - GET_INIT_CODE (one use of the few-time bootstrap key each) is refused
//     unless the scenario is explicitly marked `spendsBootstrapKey`;
//   - `eth_sendUserOperation` is answered by the stub and never forwarded,
//     and the captured signature is reduced to its length.

import type PQ1Controller from '../../../controllers/PQ1Controller'
import PQ1Signer from '../../PQ1Signer'
import { toUserFacingPq1Error } from '../errors'
import { buildPQ1AccountsToImport } from '../importAccounts'
import type { DeviceCommands } from '../transport/commands'
import { DeviceError } from '../transport/hid'
import { type CapturedUserOp, createFakeProvider, installFetchStub } from './networkStubs'
import type { Scenario } from './scenarios'

/** The device account the harness signs with. Account discovery in the
 *  connect screen covers 0-4, so this slot is never one the user imported. */
export const HARNESS_ACCOUNT_INDEX = 250

const DEFAULT_MAX_FEE_PER_GAS = 2_000_000_000n // 2 gwei
const DEFAULT_PRIORITY_FEE_PER_GAS = 100_000_000n // 0.1 gwei

const REJECTED_ON_DEVICE_MESSAGE = toUserFacingPq1Error(
  new DeviceError('rejected', undefined, 'rejected')
).message

export type ScenarioStatus = 'signed' | 'refused-by-wallet' | 'rejected-on-device' | 'failed'

export type ScenarioOutcome = {
  status: ScenarioStatus
  /** Whether a sign command was sent to the device. */
  reachedDevice: boolean
  /** The message the user would see, or a short summary of the signature. */
  message: string
  /** The device's own technical error, if it raised one (for debugging). */
  deviceDetail?: string
  durationMs: number
}

type SignCommand = 'signUserOp' | 'signUserOpBatch' | 'signOffchain'

/** Wrap the device commands for one run. Returns the restore function. */
function guardDevice(
  commands: DeviceCommands,
  scenario: Scenario,
  hooks: { onSign: () => void; onDeviceError: (detail: string) => void }
): () => void {
  // Own-property descriptors before wrapping (undefined = the method came
  // from the prototype), so restoring puts back exactly what was there.
  const saved = new Map<string, PropertyDescriptor | undefined>()
  const wrap = (name: SignCommand | 'getInitCode', value: unknown) => {
    saved.set(name, Object.getOwnPropertyDescriptor(commands, name))
    Object.defineProperty(commands, name, { configurable: true, writable: true, value })
  }
  const recordErrors = <T>(promise: Promise<T>) =>
    promise.catch((e: unknown) => {
      if (e instanceof DeviceError) hooks.onDeviceError(`${e.message} [${e.code ?? 'no code'}]`)
      throw e
    })

  const guardSign = (name: SignCommand) => {
    const original = commands[name].bind(commands) as (p: {
      accountIndex: number
    }) => Promise<unknown>
    wrap(name, (params: { accountIndex: number }) => {
      if (params.accountIndex !== HARNESS_ACCOUNT_INDEX) {
        return Promise.reject(
          new Error(`[pq1 harness] refused to sign for account ${params.accountIndex}`)
        )
      }
      hooks.onSign()
      return recordErrors(original(params))
    })
  }
  guardSign('signUserOp')
  guardSign('signUserOpBatch')
  guardSign('signOffchain')

  const originalGetInitCode = commands.getInitCode.bind(commands)
  wrap('getInitCode', (accountIndex: number, chainId: bigint | number) => {
    if (!scenario.spendsBootstrapKey || accountIndex !== HARNESS_ACCOUNT_INDEX) {
      return Promise.reject(
        new Error(
          '[pq1 harness] GET_INIT_CODE blocked — this scenario may not use the bootstrap key'
        )
      )
    }
    return recordErrors(originalGetInitCode(accountIndex, chainId))
  })

  return () => {
    saved.forEach((descriptor, name) => {
      if (descriptor) Object.defineProperty(commands, name, descriptor)
      else delete (commands as unknown as Record<string, unknown>)[name]
    })
  }
}

const describeUserOp = (op: CapturedUserOp | undefined) =>
  op
    ? `Signed (${op.signatureBytes} B signature${
        op.hasInitCode ? ', with account deployment' : ''
      }). Nothing was sent.`
    : 'Signed. Nothing was sent.'

/** Run `scenario` with the harness account `sender` (account 250's address,
 *  read from the device). `controller` must already be unlocked. */
export async function runScenario(args: {
  scenario: Scenario
  controller: PQ1Controller
  sender: `0x${string}`
}): Promise<ScenarioOutcome> {
  const { scenario, controller, sender } = args
  const startedAt = Date.now()
  const request = scenario.build({ sender })
  const commands = controller.walletSDK?.commands
  if (!commands) {
    return {
      status: 'failed',
      reachedDevice: false,
      message: 'Connect the PQ1 first.',
      durationMs: 0
    }
  }

  let reachedDevice = false
  let deviceDetail: string | undefined
  const captured: CapturedUserOp[] = []
  const fixtures = request.kind === 'transaction' ? request.fixtures : undefined
  const restoreFetch = installFetchStub(
    { cowOrders: fixtures?.cowOrders ?? new Map(), safeTxs: fixtures?.safeTxs ?? new Map() },
    (op) => captured.push(op)
  )
  const restoreDevice = guardDevice(commands, scenario, {
    onSign: () => {
      reachedDevice = true
    },
    onDeviceError: (detail) => {
      deviceDetail = detail
    }
  })

  try {
    const [key] = buildPQ1AccountsToImport(
      [{ accountIndex: HARNESS_ACCOUNT_INDEX, addr: sender }],
      controller.deviceId
    ).keys
    const signer = new PQ1Signer(key!)
    signer.init(controller)
    const provider = createFakeProvider({
      sender,
      deployed: request.kind !== 'transaction' || request.deployed !== false
    })
    const ctx = { chainId: BigInt(request.chainId), provider }

    let message: string
    if (request.kind === 'transaction') {
      await signer.broadcastAccountOp({
        chainId: ctx.chainId,
        provider,
        calls: request.calls,
        gasFeePayment: {
          gasPrice: request.maxFeePerGas ?? DEFAULT_MAX_FEE_PER_GAS,
          maxPriorityFeePerGas: DEFAULT_PRIORITY_FEE_PER_GAS
        }
      })
      message = describeUserOp(captured[0])
    } else if (request.kind === 'message') {
      const signature = await signer.signMessage(request.message, ctx)
      message = `Signed (${(signature.length - 2) / 2} B).`
    } else {
      const signature = await signer.signTypedData(request.typedData, ctx)
      message = `Signed (${(signature.length - 2) / 2} B).`
    }
    return {
      status: 'signed',
      reachedDevice,
      message,
      deviceDetail,
      durationMs: Date.now() - startedAt
    }
  } catch (e) {
    const message = e instanceof Error ? e.message : String(e)
    let status: ScenarioStatus = 'failed'
    if (!reachedDevice) status = 'refused-by-wallet'
    else if (message === REJECTED_ON_DEVICE_MESSAGE) status = 'rejected-on-device'
    return { status, reachedDevice, message, deviceDetail, durationMs: Date.now() - startedAt }
  } finally {
    restoreDevice()
    restoreFetch()
  }
}
