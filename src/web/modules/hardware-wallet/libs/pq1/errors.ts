// User-facing errors for the PQ1 stack. Internal throws (wire-format
// invariants, protocol status words, bundler replies) stay technical so the
// logs are useful; this module is the single place that turns them into
// messages a non-technical user can act on.

import ExternalSignerError from '@ambire-common/classes/ExternalSignerError'
import { captureException } from '@common/config/analytics/CrashAnalytics.web'

import { DeviceError, type DeviceErrorCode } from './transport/hid'

/** An error whose message is already written for the user. Thrown where the
 *  wallet refuses a request for a reason the user can understand (unsupported
 *  network, a transaction the device won't sign, ...). `technicalDetail`
 *  keeps the specifics for the logs. */
export class Pq1UserError extends Error {
  technicalDetail?: string

  constructor(message: string, technicalDetail?: string) {
    super(message)
    this.name = 'Pq1UserError'
    this.technicalDetail = technicalDetail
  }
}

const DEVICE_ERROR_MESSAGES: Record<DeviceErrorCode, string> = {
  disconnected: "The PQ1 isn't connected. Plug it in with the USB cable and try again.",
  locked: 'The PQ1 is locked. Unlock it with your PIN and try again.',
  rejected: 'The request was rejected on the PQ1.',
  timeout: "The PQ1 didn't respond in time. Check the device screen, then try again.",
  refused:
    "The PQ1 refused this request. If it's showing its first-time setup, finish that first. Otherwise, check the device screen for the reason.",
  outdated: 'This needs a newer version of the PQ1 software. Update your PQ1 and try again.'
}

/** Shown when a PQ1 action is requested on a network without the PQ1
 *  contracts (see `PQ1_SUPPORTED_CHAIN_IDS`). */
export const PQ1_UNSUPPORTED_NETWORK_MESSAGE =
  "PQ1 accounts aren't available on this network. Switch to a network that supports PQ1 and try again."

/** Shown for anything unexpected. The original error goes to the logs and Sentry. */
export const PQ1_GENERIC_ERROR_MESSAGE =
  'Something went wrong while talking to the PQ1. Unplug it, plug it back in, and try again.'

/**
 * Turns any error from the PQ1 stack into an `ExternalSignerError` whose
 * message is safe to show to the user. Expected outcomes (unplugged, locked,
 * rejected on the device, ...) map to a plain explanation. Anything else gets
 * `fallbackMessage`, and the original error is logged and reported to Sentry
 * so its technical detail isn't lost.
 */
export function toUserFacingPq1Error(
  e: unknown,
  fallbackMessage: string = PQ1_GENERIC_ERROR_MESSAGE
): ExternalSignerError {
  if (e instanceof ExternalSignerError) return e
  if (e instanceof Pq1UserError) {
    if (e.technicalDetail) console.warn('[pq1]', e.technicalDetail)
    return new ExternalSignerError(e.message, { sendCrashReport: false })
  }
  if (e instanceof DeviceError && e.code) {
    console.warn('[pq1] device error', e)
    return new ExternalSignerError(DEVICE_ERROR_MESSAGES[e.code], { sendCrashReport: false })
  }
  console.error('[pq1] unexpected error', e)
  captureException(e)
  return new ExternalSignerError(fallbackMessage, { sendCrashReport: false })
}
