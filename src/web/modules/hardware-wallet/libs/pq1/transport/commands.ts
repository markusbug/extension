// High-level APDU command wrappers for the PQ1 device.

import {
  INS_GET_DEVICE_INFO,
  INS_GET_INIT_CODE,
  INS_GET_STATUS,
  INS_GET_WALLET_ADDRESS,
  INS_LOCK,
  INS_OFFCHAIN_STATUS,
  INS_OFFCHAIN_SYNC,
  INS_SIGN_OFFCHAIN,
  INS_SIGN_USEROP,
  INS_SIGN_USEROP_BATCH,
  INS_UNLOCK,
  MAX_ACCOUNT_INDEX,
  OFFCHAIN_SYNC_INPUT_LEN,
  PQ_INIT_CODE_LEN,
  SW_CONDITIONS_NOT_SATISFIED,
  SW_INS_NOT_SUPPORTED,
  SW_OK,
  SW_SECURITY_CONDITION,
  SW_SESSION_EXPIRED
} from '../config'
import { bytesToHex0x, concatBytes, u32be, u64be } from './bytes'
import { DeviceError, type HidTransport } from './hid'
import {
  buildOffchainStatusPayload,
  buildSignOffchainPayload,
  parseOffchainStatusResponse,
  parseSignOffchainResponse,
  type OffchainStatus,
  type OffchainStatusInput,
  type SignOffchainBundle,
  type SignOffchainParams
} from './offchain'
import {
  buildSignBatchPayload,
  buildSignPayload,
  type BatchSignRequestParams,
  type SignRequestParams
} from './signRequest'
import { parseSignResponse, type SignBundle } from './signResponse'

/** GET_STATUS reply. The firmware deliberately reports no `provisioned`
 *  flag (the old leading byte was a constant 1, even on a blank device). A blank device runs its on-device
 *  first-boot wizard and answers gated commands with 0x6985. */
export type DeviceStatus = { locked: boolean; pinRemaining: number }

/** Wire layout of GET_STATUS: `[locked u8] [pin_remaining u8]`. Older
 *  firmware prefixed that meaningless `provisioned` byte, so a 3-byte
 *  reply is that legacy layout shifted by one. */
const STATUS_RESPONSE_LEN = 2
const LEGACY_STATUS_RESPONSE_LEN = 3

/** Minimum `protocol_version` (u16 BE in `GET_DEVICE_INFO`) advertising
 *  support for the v2 SIGN_USEROP_BATCH wire format (TLV trailer list
 *  + per-call routing). Devices below this report opaque
 *  `InvalidPointer / bad wire_version` rejections when they receive a
 *  v2 batch payload — we refuse to send and surface a clean message. */
export const MIN_BATCH_V2_PROTOCOL_VERSION = 0x0200

export class DeviceCommands {
  // Cached `protocol_version` (u16 BE from the first GET_DEVICE_INFO
  // response). The device's protocol version is immutable per session,
  // so a single read suffices.
  private cachedProtocolVersion: number | null = null

  /** GET_INIT_CODE results keyed by `${accountIndex}:${chainId}`. Every call
   *  spends one signature of the bootstrap key, which is a few-time
   *  signature scheme (each extra use weakens it), and the firmware
   *  documents the bytes as safe to cache, so ask once per device handle. */
  private cachedInitCode = new Map<string, Uint8Array>()

  constructor(readonly t: HidTransport) {}

  async getDeviceInfo(): Promise<Uint8Array> {
    const r = await this.t.sendApdu(INS_GET_DEVICE_INFO)
    expectOk(r.sw, 'GET_DEVICE_INFO')
    if (r.data.length >= 2 && this.cachedProtocolVersion === null) {
      this.cachedProtocolVersion = (r.data[0]! << 8) | r.data[1]!
    }
    return r.data
  }

  /** Returns the device's wire-protocol version, fetching it on first
   *  call and caching for the remainder of the session. Matches the
   *  `PROTOCOL_VERSION` constant in `proto/src/lib.rs`. */
  async getProtocolVersion(): Promise<number> {
    if (this.cachedProtocolVersion !== null) return this.cachedProtocolVersion
    await this.getDeviceInfo()
    if (this.cachedProtocolVersion === null) {
      throw new DeviceError('GET_DEVICE_INFO: response too short to read protocol_version')
    }
    return this.cachedProtocolVersion
  }

  async getStatus(): Promise<DeviceStatus> {
    const r = await this.t.sendApdu(INS_GET_STATUS)
    expectOk(r.sw, 'GET_STATUS')
    if (r.data.length < STATUS_RESPONSE_LEN) {
      throw new DeviceError(`GET_STATUS: response too short (${r.data.length} bytes)`)
    }
    const offset = r.data.length >= LEGACY_STATUS_RESPONSE_LEN ? 1 : 0
    return {
      locked: r.data[offset] === 1,
      pinRemaining: r.data[offset + 1]!
    }
  }

  async unlock(): Promise<number> {
    const r = await this.t.sendApdu(INS_UNLOCK)
    return r.sw
  }

  /** Run a lock-gated command with SW_CONDITIONS_NOT_SATISFIED (0x6985)
   *  disambiguation. The firmware overloads 0x6985 for "device is locked",
   *  "not set up yet" (first-boot wizard still running), PIN lockout AND
   *  offchain-counter refusals — but GET_STATUS is ungated, so one status
   *  poll tells the lock state apart. Only when the device really reports
   *  `locked` do we rethrow a typed 'locked' error the caller can recover
   *  from by prompting for the on-device PIN; an unlocked refusal is
   *  reworded so the user knows to look at the device screen. */
  private async withLockDetection<T>(run: () => Promise<T>): Promise<T> {
    try {
      return await run()
    } catch (e) {
      if (e instanceof DeviceError && e.sw === SW_CONDITIONS_NOT_SATISFIED) {
        let status: DeviceStatus | null = null
        try {
          status = await this.getStatus()
        } catch {
          /* status probe failed — keep the original error below */
        }
        if (status?.locked) {
          throw new DeviceError(
            'The PQ1 is locked (2-minute idle timeout). Unlock it with your PIN and retry.',
            e.sw,
            'locked'
          )
        }
        if (status) {
          throw new DeviceError(
            'The PQ1 refused this request. If the device is showing its first-time setup, finish that on the device first; otherwise check the device screen for details.',
            e.sw
          )
        }
      }
      throw e
    }
  }

  async lock(): Promise<number> {
    const r = await this.t.sendApdu(INS_LOCK)
    return r.sw
  }

  async getWalletAddress(accountIndex = 0): Promise<`0x${string}`> {
    if (accountIndex < 0 || accountIndex > MAX_ACCOUNT_INDEX) {
      throw new DeviceError(`account_index out of range: ${accountIndex}`)
    }
    return this.withLockDetection(async () => {
      const r = await this.t.sendApdu(INS_GET_WALLET_ADDRESS, 0, 0, u32be(accountIndex))
      expectOk(r.sw, `GET_WALLET_ADDRESS(${accountIndex})`)
      if (r.data.length !== 20) throw new DeviceError(`unexpected address length ${r.data.length}`)
      return bytesToHex0x(r.data)
    })
  }

  /** The real 4280-byte factory initCode for a not-yet-deployed wallet,
   *  used to gas-estimate the first deploy. Byte-for-byte what the deploy
   *  path of SIGN_USEROP emits, so the estimate matches the final op. */
  async getInitCode(accountIndex: number, chainId: bigint | number): Promise<Uint8Array> {
    if (accountIndex < 0 || accountIndex > MAX_ACCOUNT_INDEX) {
      throw new DeviceError(`account_index out of range: ${accountIndex}`)
    }
    const cacheKey = `${accountIndex}:${chainId}`
    const cached = this.cachedInitCode.get(cacheKey)
    if (cached) return cached

    const payload = concatBytes([u32be(accountIndex), u64be(chainId)])
    const initCode = await this.withLockDetection(async () => {
      const r = await this.t.sendApdu(INS_GET_INIT_CODE, 0, 0, payload)
      if (r.sw === SW_INS_NOT_SUPPORTED) {
        throw new DeviceError('GET_INIT_CODE: firmware does not expose this INS', r.sw)
      }
      expectOk(r.sw, 'GET_INIT_CODE')
      if (r.data.length !== PQ_INIT_CODE_LEN) {
        throw new DeviceError(
          `GET_INIT_CODE: expected ${PQ_INIT_CODE_LEN} bytes, got ${r.data.length}`
        )
      }
      return r.data
    })
    this.cachedInitCode.set(cacheKey, initCode)
    return initCode
  }

  async signUserOp(params: SignRequestParams): Promise<SignBundle> {
    const payload = buildSignPayload(params)
    return this.withLockDetection(async () => {
      const r = await this.t.sendChainedApdu(INS_SIGN_USEROP, payload)
      expectOk(r.sw, 'SIGN_USEROP')
      return parseSignResponse(r.data)
    })
  }

  async signUserOpBatch(params: BatchSignRequestParams): Promise<SignBundle> {
    // Refuse v1 firmware before assembling the v2 payload — the device
    // would reject with `InvalidPointer / bad wire_version`, which is
    // opaque. Surface a clean "firmware update required" instead.
    const protocolVersion = await this.getProtocolVersion()
    if (protocolVersion < MIN_BATCH_V2_PROTOCOL_VERSION) {
      throw new DeviceError(
        `PQ1 firmware too old for batch signing (protocol 0x${protocolVersion
          .toString(16)
          .padStart(4, '0')} < 0x${MIN_BATCH_V2_PROTOCOL_VERSION.toString(16).padStart(
          4,
          '0'
        )}). Update the device firmware to enable batched UserOps.`
      )
    }
    const payload = buildSignBatchPayload(params)
    return this.withLockDetection(async () => {
      const r = await this.t.sendChainedApdu(INS_SIGN_USEROP_BATCH, payload)
      expectOk(r.sw, 'SIGN_USEROP_BATCH')
      return parseSignResponse(r.data)
    })
  }

  async signOffchain(params: SignOffchainParams): Promise<SignOffchainBundle> {
    const payload = buildSignOffchainPayload(params)
    return this.withLockDetection(async () => {
      const r = await this.t.sendChainedApdu(INS_SIGN_OFFCHAIN, payload)
      expectOk(r.sw, 'SIGN_OFFCHAIN')
      return parseSignOffchainResponse(r.data)
    })
  }

  async offchainStatus(input: OffchainStatusInput): Promise<OffchainStatus> {
    const payload = buildOffchainStatusPayload(input)
    return this.withLockDetection(async () => {
      const r = await this.t.sendApdu(INS_OFFCHAIN_STATUS, 0, 0, payload)
      expectOk(r.sw, 'OFFCHAIN_STATUS')
      return parseOffchainStatusResponse(r.data)
    })
  }

  /**
   * CMD_OFFCHAIN_SYNC — bump the device's per-slot `last_userop_count`
   * to at least `targetCount`. Idempotent and "set if greater" — never
   * reduces. The companion calls this with the on-chain
   * `offchainSigCount[ownerIndex]` before SIGN_USEROP so the next
   * UserOp emits a `newOffchainCount` monotonic w.r.t. on-chain state
   * even after a firmware reflash wiped the secure-flash counters.
   */
  async offchainSync(input: {
    accountIndex: number
    chainId: bigint | number
    slotIndex: number
    targetCount: bigint
  }): Promise<void> {
    if (input.accountIndex < 0 || input.accountIndex > MAX_ACCOUNT_INDEX) {
      throw new DeviceError(`offchainSync: account_index out of range: ${input.accountIndex}`)
    }
    if (input.slotIndex < 0 || input.slotIndex > 0x003fffff) {
      throw new DeviceError(`offchainSync: slot_index out of range: ${input.slotIndex}`)
    }
    const payload = concatBytes([
      new Uint8Array([input.accountIndex & 0xff]),
      u64be(input.chainId),
      u32be(input.slotIndex),
      u64be(input.targetCount)
    ])
    if (payload.length !== OFFCHAIN_SYNC_INPUT_LEN) {
      throw new DeviceError(
        `offchainSync: payload length ${payload.length} != ${OFFCHAIN_SYNC_INPUT_LEN}`
      )
    }
    await this.withLockDetection(async () => {
      const r = await this.t.sendApdu(INS_OFFCHAIN_SYNC, 0, 0, payload)
      expectOk(r.sw, 'OFFCHAIN_SYNC')
    })
  }
}

function expectOk(sw: number, what: string): void {
  if (sw === SW_OK) return
  // Firmware SW semantics (see sphincs_rust nsc_status_to_sw):
  // 0x6982 = PinIncorrect | UserRejected — a deliberate on-device decision,
  //          so it must NEVER be auto-retried.
  // 0x6984 = IdleWipe — the 2-minute idle timeout wiped the session while
  //          this operation was in flight. Nothing was signed; recoverable
  //          by re-entering the PIN.
  // 0x6985 is overloaded (locked / PIN lockout / offchain refusals) and is
  //          disambiguated in `withLockDetection` via the ungated GET_STATUS.
  if (sw === SW_SECURITY_CONDITION) {
    throw new DeviceError(`${what}: rejected on the PQ1 (or PIN entry failed)`, sw, 'rejected')
  }
  if (sw === SW_SESSION_EXPIRED) {
    throw new DeviceError(
      `${what}: the PQ1 locked itself (2-minute idle timeout). Unlock it with your PIN and retry.`,
      sw,
      'locked'
    )
  }
  throw new DeviceError(`${what} failed: SW=0x${sw.toString(16).padStart(4, '0')}`, sw)
}
