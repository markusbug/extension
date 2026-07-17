import ExternalSignerError from '@ambire-common/classes/ExternalSignerError'
import { ExternalSignerController } from '@ambire-common/interfaces/keystore'

import { SW_OK, SW_SECURITY_CONDITION } from '../../libs/pq1/config'
import { DeviceCommands, type DeviceStatus } from '../../libs/pq1/transport/commands'
import { DeviceError, HidTransport } from '../../libs/pq1/transport/hid'

/**
 * Owns the WebHID connection to a single PQ1 hardware wallet inside the
 * background service worker, and implements the Ambire `ExternalSignerController`
 * shape so the keystore / account picker treat it like any other hardware
 * wallet controller.
 *
 * PQ1 has no BIP-32 derivation: the device exposes 256 numbered account slots
 * (`accountIndex`), each of which is its own PQSmartWallet. The Ambire
 * `unlock(path, expectedAddr)` signature is honoured but `path` is ignored —
 * the iterator and signer address the device by `accountIndex` instead.
 */
class PQ1Controller implements ExternalSignerController {
  type = 'pq1'

  deviceModel = 'pq1'

  deviceId = ''

  walletSDK: { transport: HidTransport; commands: DeviceCommands } | null = null

  /** Cached status from the most recent getStatus() — refreshed by every
   *  unlock() probe and by signingCleanup(), so callers can inspect the
   *  latest known lock state / PIN attempts without another APDU. */
  lastStatus: DeviceStatus | null = null

  /** Optional UI hook: set by screens that hold this controller (e.g. the
   *  connect screen) to react when the device is physically unplugged. */
  onDeviceDisconnect?: () => void

  isUnlocked() {
    return this.walletSDK !== null && this.walletSDK.transport.isConnected() && !!this.deviceId
  }

  /** Wired as `HidTransport.onDisconnect`. The transport has already torn
   *  itself down and failed in-flight reads — drop our stale handle so the
   *  next unlock() reconnects from scratch instead of writing into a void. */
  #handleUnplug = () => {
    this.walletSDK = null
    this.deviceId = ''
    this.lastStatus = null
    this.onDeviceDisconnect?.()
  }

  /**
   * Idempotent and self-healing: probes an existing handle with the ungated
   * GET_STATUS (a stale handle after unplug/replug or a service-worker
   * restart fails the probe and triggers a clean reconnect). Otherwise pop
   * the WebHID picker, open the device, run GET_STATUS, and if the firmware
   * reports `locked` (initial state or 2-minute idle re-lock) issue an
   * UNLOCK APDU — which triggers PIN entry on the OLED. The promise
   * resolves once the user has authenticated on-device.
   */
  async unlock(): Promise<'ALREADY_UNLOCKED' | 'JUST_UNLOCKED'> {
    if (this.walletSDK) {
      try {
        this.lastStatus = await this.walletSDK.commands.getStatus()
      } catch {
        // Dead handle — release it fully; the reconnect below starts fresh.
        await this.cleanUp()
      }
    }

    let freshlyConnected = false
    if (!this.walletSDK) {
      const transport = new HidTransport()
      try {
        await transport.connect()
      } catch (e: any) {
        throw new ExternalSignerError(
          e?.message || 'Could not connect to the PQ1 device — pair it via WebHID and retry.',
          { sendCrashReport: false }
        )
      }
      transport.onDisconnect = this.#handleUnplug
      const commands = new DeviceCommands(transport)
      this.walletSDK = { transport, commands }
      this.lastStatus = null
      freshlyConnected = true
    }

    const { commands } = this.walletSDK
    let didPinUnlock = false
    try {
      const status = this.lastStatus ?? (await commands.getStatus())
      this.lastStatus = status
      // GET_STATUS carries no `provisioned` flag (see DeviceStatus). A blank
      // device shows its first-boot wizard and refuses gated commands with
      // 0x6985 while reporting `locked: false`, which is handled below.
      if (status.locked) {
        // INS_UNLOCK blocks until the user enters the PIN on the OLED (or
        // gives up). The transport timeout for this INS is 60 s.
        const sw = await commands.unlock()
        if (sw !== SW_OK) {
          // 0x6982 covers both "wrong PIN" and "user rejected the PIN
          // prompt" — either way it was an on-device decision, so surface
          // it plainly and never auto-retry.
          const reason =
            sw === SW_SECURITY_CONDITION
              ? 'PIN entry was cancelled or the PIN was wrong on the device.'
              : `SW=0x${sw.toString(16).padStart(4, '0')}.`
          throw new ExternalSignerError(`PQ1 unlock refused — ${reason} Retry when ready.`, {
            sendCrashReport: false
          })
        }
        this.lastStatus = await commands.getStatus()
        didPinUnlock = true
      }

      // GET_DEVICE_INFO returns a stable device-identifying blob — we hash
      // it down to a short hex for the `deviceId` field that the keystore
      // tags external keys with. Skipped when already cached so the
      // pre-signing unlock() probe stays a single GET_STATUS round trip.
      if (!this.deviceId) {
        const info = await commands.getDeviceInfo()
        this.deviceId = bytesToShortId(info)
      }
    } catch (e: any) {
      if (e instanceof ExternalSignerError) throw e
      const msg =
        e instanceof DeviceError
          ? `${e.message}${e.sw ? ` (SW=0x${e.sw.toString(16).padStart(4, '0')})` : ''}`
          : e?.message || 'PQ1 unlock failed.'
      throw new ExternalSignerError(msg, { sendCrashReport: false })
    }

    return freshlyConnected || didPinUnlock ? 'JUST_UNLOCKED' : 'ALREADY_UNLOCKED'
  }

  /** Disconnect the WebHID handle and clear cached state. Called from the
   *  keystore on profile-switch / lock. */
  async cleanUp() {
    if (this.walletSDK) {
      try {
        await this.walletSDK.transport.disconnect()
      } catch {
        /* ignore */
      }
    }
    this.walletSDK = null
    this.deviceId = ''
    this.lastStatus = null
  }

  /** Same hook the Ledger/Trezor controllers expose so the background can
   *  clear transient signing state without dropping the device handle. */
  async signingCleanup() {
    // PQ1 has no stateful signing session — INS_SIGN_USEROP is one-shot.
    // Refresh the cached status so the popup sees the latest offchain
    // counter / lock state.
    if (this.walletSDK) {
      try {
        this.lastStatus = await this.walletSDK.commands.getStatus()
      } catch {
        /* ignore */
      }
    }
  }
}

/** Lower-hex of the first 6 bytes — keeps the keystore meta.deviceId field
 *  short while still being collision-resistant across the device fleet. */
function bytesToShortId(b: Uint8Array): string {
  const take = b.subarray(0, Math.min(6, b.length))
  let s = ''
  for (let i = 0; i < take.length; i++) s += take[i]!.toString(16).padStart(2, '0')
  return s
}

export default PQ1Controller
