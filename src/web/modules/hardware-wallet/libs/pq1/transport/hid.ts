// WebHID transport for the PQ1 device, Ledger-style APDU-over-HID framing.
// Exact wire behaviour mirrors sphincs_rust/tools/webhid_test.html:218-520.

import {
  CHANNEL_ID,
  CLA_V2,
  INS_GET_RESPONSE,
  P1_LAST,
  P1_MORE,
  PQ1_PID,
  PQ1_VID,
  REPORT_SIZE,
  SW_OK,
  TAG_APDU,
  timeoutForIns
} from '../config'
import { concatBytes } from './bytes'

export type ApduResponse = { sw: number; data: Uint8Array }

/** Machine-readable failure class so callers can recover instead of parsing
 *  message strings:
 *  - 'disconnected' — the HID handle is gone/stale (unplug, OS drop, closed).
 *    Recoverable by reconnecting via `HidTransport.connect()`.
 *  - 'locked' — the firmware idle-locked (2-minute timeout) or wiped the
 *    session mid-operation. Recoverable via INS_UNLOCK (on-device PIN).
 *  - 'rejected' — the user rejected on the device (or PIN entry failed).
 *    NOT auto-recoverable; never retry without the user asking.
 *  - 'timeout' — no HID report arrived in time; the device may be gone or
 *    the user ignored an on-device prompt. */
export type DeviceErrorCode = 'disconnected' | 'locked' | 'rejected' | 'timeout'

export class DeviceError extends Error {
  sw?: number

  code?: DeviceErrorCode

  constructor(msg: string, sw?: number, code?: DeviceErrorCode) {
    super(msg)
    this.name = 'DeviceError'
    this.sw = sw
    this.code = code
  }
}

type PendingReportReader = {
  resolve: (buf: Uint8Array) => void
  fail: (err: DeviceError) => void
}

export class HidTransport {
  device: HIDDevice | null = null

  /** Invoked once when the OS reports the device gone (unplug / port drop)
   *  while this transport holds it. The controller uses this to drop its
   *  stale `walletSDK` handle so the next operation reconnects cleanly. */
  onDisconnect?: () => void

  private pendingReportReaders: PendingReportReader[] = []

  /** The HIDDevice the `inputreport` listener is currently attached to —
   *  tracked per device (not a boolean) so a reconnect to a new HIDDevice
   *  object re-attaches correctly. */
  private listeningDevice: HIDDevice | null = null

  async connect(): Promise<void> {
    const filters: HIDDeviceFilter[] = [{ vendorId: PQ1_VID, productId: PQ1_PID }]
    const granted = await navigator.hid.getDevices()
    let device = granted.find((d) => d.vendorId === PQ1_VID && d.productId === PQ1_PID) ?? null
    if (!device) {
      // requestDevice needs a user gesture and a foreground document. In the
      // MV3 service worker (or when the user cancels the picker) it throws or
      // returns [] — normalize both to a typed 'disconnected' error so
      // callers can show a "plug it in and retry" message.
      try {
        const picked = await navigator.hid.requestDevice({ filters })
        device = picked[0] ?? null
      } catch {
        device = null
      }
    }
    if (!device) {
      throw new DeviceError(
        'No PQ1 device found. Plug it in via USB and retry.',
        undefined,
        'disconnected'
      )
    }
    if (!device.opened) await device.open()
    this.device = device
    this.attachListener()
    // The 'disconnect' event lives on navigator.hid (not the device), so it
    // fires even for handles the OS dropped without us calling close().
    navigator.hid.addEventListener('disconnect', this.onHidDisconnect)
  }

  async disconnect(): Promise<void> {
    const device = this.device
    this.teardown(new DeviceError('PQ1 transport closed', undefined, 'disconnected'))
    if (device?.opened) {
      try {
        await device.close()
      } catch {
        /* ignore */
      }
    }
  }

  isConnected(): boolean {
    return this.device !== null && this.device.opened
  }

  private onHidDisconnect = (e: HIDConnectionEvent): void => {
    if (!this.device || e.device !== this.device) return
    this.teardown(new DeviceError('PQ1 device was unplugged', undefined, 'disconnected'))
    this.onDisconnect?.()
  }

  /** Drop the device handle, detach listeners and fail any in-flight reads
   *  immediately — otherwise a read against a gone device would sit there
   *  until its full timeout (up to 120 s for sign commands). */
  private teardown(err: DeviceError): void {
    if (this.listeningDevice) {
      this.listeningDevice.removeEventListener('inputreport', this.onInputReport)
      this.listeningDevice = null
    }
    navigator.hid.removeEventListener('disconnect', this.onHidDisconnect)
    this.device = null
    const pending = this.pendingReportReaders.splice(0, this.pendingReportReaders.length)
    pending.forEach((p) => p.fail(err))
  }

  private attachListener(): void {
    if (!this.device || this.listeningDevice === this.device) return
    if (this.listeningDevice) {
      this.listeningDevice.removeEventListener('inputreport', this.onInputReport)
    }
    this.device.addEventListener('inputreport', this.onInputReport)
    this.listeningDevice = this.device
  }

  private onInputReport = (e: HIDInputReportEvent): void => {
    const buf = new Uint8Array(e.data.buffer, e.data.byteOffset, e.data.byteLength)
    const next = this.pendingReportReaders.shift()
    if (next) next.resolve(buf)
  }

  private readOneReport(timeoutMs: number): Promise<Uint8Array> {
    return new Promise<Uint8Array>((resolve, reject) => {
      let timer: ReturnType<typeof setTimeout>
      const reader: PendingReportReader = {
        resolve: (buf) => {
          clearTimeout(timer)
          resolve(buf)
        },
        fail: (err) => {
          clearTimeout(timer)
          reject(err)
        }
      }
      timer = setTimeout(() => {
        const idx = this.pendingReportReaders.indexOf(reader)
        if (idx >= 0) this.pendingReportReaders.splice(idx, 1)
        reject(new DeviceError(`HID read timeout after ${timeoutMs} ms`, undefined, 'timeout'))
      }, timeoutMs)
      this.pendingReportReaders.push(reader)
    })
  }

  private frameApdu(apdu: Uint8Array): Uint8Array[] {
    const frames: Uint8Array[] = []
    let off = 0
    let seq = 0

    const first = new Uint8Array(REPORT_SIZE)
    first[0] = (CHANNEL_ID >> 8) & 0xff
    first[1] = CHANNEL_ID & 0xff
    first[2] = TAG_APDU
    first[3] = 0
    first[4] = 0
    first[5] = (apdu.length >> 8) & 0xff
    first[6] = apdu.length & 0xff
    const firstChunk = Math.min(57, apdu.length)
    first.set(apdu.subarray(0, firstChunk), 7)
    frames.push(first)
    off = firstChunk
    seq = 1

    while (off < apdu.length) {
      const f = new Uint8Array(REPORT_SIZE)
      f[0] = (CHANNEL_ID >> 8) & 0xff
      f[1] = CHANNEL_ID & 0xff
      f[2] = TAG_APDU
      f[3] = (seq >> 8) & 0xff
      f[4] = seq & 0xff
      const c = Math.min(59, apdu.length - off)
      f.set(apdu.subarray(off, off + c), 5)
      frames.push(f)
      off += c
      seq++
    }
    return frames
  }

  private async receiveApdu(timeoutMs: number): Promise<Uint8Array> {
    // `expected` is known from the first frame, so the response buffer is
    // preallocated once and each frame's chunk copied in with `set()` —
    // sign responses run 4-8.6 KB, and byte-by-byte accumulation into a
    // number[] plus a final slice-copy was measurable overhead on every
    // APDU exchange in the signing path.
    let buf = new Uint8Array(0)
    let received = 0
    let expected = 0
    let seq = 0

    while (true) {
      const r = await this.readOneReport(timeoutMs)
      if (r[2] !== TAG_APDU) continue
      const rSeq = ((r[3]! << 8) | r[4]!) & 0xffff
      if (rSeq !== seq) {
        throw new DeviceError(`HID sequence mismatch: expected ${seq}, got ${rSeq}`)
      }
      if (seq === 0) {
        expected = ((r[5]! << 8) | r[6]!) & 0xffff
        buf = new Uint8Array(expected)
        const c = Math.min(57, expected)
        buf.set(r.subarray(7, 7 + c), 0)
        received = c
      } else {
        const c = Math.min(59, expected - received)
        buf.set(r.subarray(5, 5 + c), received)
        received += c
      }
      seq++
      if (received >= expected) break
    }
    return buf
  }

  private buildApdu(ins: number, p1: number, p2: number, data?: Uint8Array): Uint8Array {
    const lc = data ? data.length : 0
    if (lc > 255) throw new DeviceError(`short APDU Lc overflow: ${lc}`)
    const apdu = new Uint8Array(5 + lc)
    apdu[0] = CLA_V2
    apdu[1] = ins
    apdu[2] = p1
    apdu[3] = p2
    apdu[4] = lc
    if (lc && data) apdu.set(data, 5)
    return apdu
  }

  private async send(apdu: Uint8Array): Promise<void> {
    if (!this.device) {
      throw new DeviceError('PQ1 device not connected', undefined, 'disconnected')
    }

    for (const f of this.frameApdu(apdu)) {
      try {
        await this.device.sendReport(0, f as BufferSource)
      } catch (e: any) {
        // sendReport rejects with a raw DOMException when the handle is
        // stale (unplugged, or closed by the OS) — normalize it to a typed
        // 'disconnected' error so callers can reconnect instead of showing
        // a browser-internal message.
        throw new DeviceError(
          `PQ1 write failed — device disconnected? (${e?.message || e})`,
          undefined,
          'disconnected'
        )
      }
    }
  }

  async sendApdu(
    ins: number,
    p1 = 0,
    p2 = 0,
    data?: Uint8Array,
    timeoutMs?: number
  ): Promise<ApduResponse> {
    const t = timeoutMs ?? timeoutForIns(ins)
    await this.send(this.buildApdu(ins, p1, p2, data))
    const collected: Uint8Array[] = []
    let resp = await this.receiveApdu(t)

    while (true) {
      const sw1 = resp[resp.length - 2]!
      const sw2 = resp[resp.length - 1]!
      const sw = ((sw1 << 8) | sw2) & 0xffff
      collected.push(resp.subarray(0, resp.length - 2))
      if (sw1 === 0x61) {
        await this.send(this.buildApdu(INS_GET_RESPONSE, 0, 0))

        resp = await this.receiveApdu(t)
      } else {
        return { sw, data: concatBytes(collected) }
      }
    }
  }

  async sendChainedApdu(
    ins: number,
    payload: Uint8Array,
    timeoutMs?: number
  ): Promise<ApduResponse> {
    const MAX = 255
    const t = timeoutMs ?? timeoutForIns(ins)
    let off = 0
    let last: ApduResponse | null = null
    while (off < payload.length) {
      const remaining = payload.length - off
      const chunk = Math.min(MAX, remaining)
      const isLast = off + chunk >= payload.length
      const p1 = isLast ? P1_LAST : P1_MORE
      const slice = payload.subarray(off, off + chunk)

      await this.send(this.buildApdu(ins, p1, 0x00, slice))

      const collected: Uint8Array[] = []

      let resp = await this.receiveApdu(t)

      while (true) {
        const sw1 = resp[resp.length - 2]!
        const sw2 = resp[resp.length - 1]!
        const sw = ((sw1 << 8) | sw2) & 0xffff
        collected.push(resp.subarray(0, resp.length - 2))
        if (sw1 === 0x61) {
          await this.send(this.buildApdu(INS_GET_RESPONSE, 0, 0))

          resp = await this.receiveApdu(t)
        } else {
          last = { sw, data: concatBytes(collected) }
          break
        }
      }
      off += chunk
      if (isLast) return last!
      if (last.sw !== SW_OK) return last
    }
    return last!
  }
}
