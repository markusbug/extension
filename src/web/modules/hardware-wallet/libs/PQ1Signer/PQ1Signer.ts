import type { JsonRpcProvider } from 'ethers'
import { encodeAbiParameters, hashMessage, hashTypedData } from 'viem'

import ExternalSignerError from '@ambire-common/classes/ExternalSignerError'
import {
  ExternalKey,
  ExternalSignerController,
  KeystoreSignerInterface,
  SignMessageContext
} from '@ambire-common/interfaces/keystore'

import PQ1Controller from '../../controllers/PQ1Controller'
import { resolvePq1AccountState, type Pq1AccountState } from '../pq1/aa/accountState'
import { pq1BroadcastAccountOp } from '../pq1/aa/broadcast'
import { MAX_OFFCHAIN_PERSONAL_SIGN_LEN, PQ1_SUPPORTED_CHAIN_IDS } from '../pq1/config'
import { buildErc7730Eip712Pieces } from '../pq1/erc7730/eip712'
import { buildErc7730BundleForEip712 } from '../pq1/erc7730/lookup'
import { bytesToHex0x, hexToBytes } from '../pq1/transport/bytes'
import { DeviceError } from '../pq1/transport/hid'
import type { SignOffchainBundle } from '../pq1/transport/offchain'

type PQ1Meta = ExternalKey['meta'] & {
  /** Same as `index` for PQ1 — kept named for clarity at the call site. */
  accountIndex?: number
  /** Active slot on the device *at import time* (0 = bootstrap, ≥1 =
   *  rotated). Import-flow metadata only — signing paths always re-derive
   *  the active slot from the chain (see `#resolveAccountState`), because
   *  a cached value goes stale the moment the user rotates the owner slot
   *  and a stale ownerIndex breaks ERC-1271 verification everywhere. */
  slotIndex?: number
  /** Owner index at import time — equals `slotIndex + 1`. Import-flow
   *  metadata only, same staleness caveat as slotIndex. */
  ownerIndex?: number
}

/**
 * Signing surface for a PQ1 hardware wallet account.
 *
 * PQ1 is a smart-account-only signer (no EOA), so the EOA-style methods
 * (`signRawTransaction`, `sign7702`, `signTransactionTypeFour`) throw. The
 * caller is expected to route transaction signing through
 * `broadcastAccountOp` instead — see the `signingKeyType === 'pq1'` branch
 * in ambire-common's `SignAccountOpController`.
 *
 * Message signing (`signMessage`, `signTypedData`) produces an ERC-1271
 * wrapped signature: `abi.encode(uint256 ownerIndex, bytes innerSig)`.
 * Verifiers must call `PQSmartWallet.isValidSignature(hash, sig)` to verify
 * — a SPHINCS+ signature is not ECDSA-recoverable.
 */
class PQ1Signer implements KeystoreSignerInterface {
  key: ExternalKey & { isExternallyStored: boolean }

  controller: PQ1Controller | null = null

  constructor(_key: ExternalKey) {
    this.key = { ..._key, isExternallyStored: true }
  }

  init(externalDeviceController?: ExternalSignerController) {
    if (!externalDeviceController) {
      throw new ExternalSignerError('pq1Signer: externalDeviceController not initialized', {
        sendCrashReport: true
      })
    }
    this.controller = externalDeviceController as PQ1Controller
  }

  /**
   * Pair-and-unlock the device for an in-flight signing/broadcast op.
   *
   * Why we re-acquire here: the popup-side import flow opens the WebHID
   * handle, discovers addresses, then `cleanUp()`s the transport so the
   * background can take over. By the time `broadcastAccountOp` /
   * `signMessage` runs in the service worker, the *background's*
   * `PQ1Controller` has a fresh `walletSDK === null`, even though the
   * browser still remembers the device permission and the device itself is
   * plugged in and unlocked.
   *
   * `controller.unlock()` is idempotent: if the SDK is already live it
   * just refreshes status; otherwise it calls `HidTransport.connect()`,
   * which tries `navigator.hid.getDevices()` first (no user gesture
   * required, works in MV3 service workers) and only falls back to
   * `requestDevice()` when there's no previously-granted device. Since
   * the popup already granted permission, `getDevices()` returns the
   * PQ1 and `open()` succeeds without UI.
   *
   * If the device firmware is locked, this will trigger the on-device
   * PIN prompt — which is the correct UX.
   *
   * unlock() is also called when `walletSDK` already exists: it probes the
   * handle with the ungated GET_STATUS (one ~ms APDU round trip), so a
   * stale handle (unplug/replug, OS drop) reconnects and a firmware that
   * idle-locked itself (2-minute timeout) re-prompts for the PIN *before*
   * we build and send an expensive sign payload.
   */
  async #acquireDevice() {
    if (!this.controller) {
      throw new ExternalSignerError(
        'PQ1 signer not initialized — externalSignerController missing.',
        { sendCrashReport: true }
      )
    }
    await this.controller.unlock()
    if (!this.controller.walletSDK) {
      throw new ExternalSignerError(
        'PQ1 device not connected. Plug it in, unlock with PIN, and retry.',
        { sendCrashReport: false }
      )
    }
    return this.controller.walletSDK
  }

  /** Run a device operation with one automatic recovery pass: if the
   *  firmware idle-locks (2-minute timeout) between the pre-flight check
   *  and the command, the op fails with a typed 'locked' DeviceError
   *  *before* anything was signed — so we re-run the unlock flow (which
   *  triggers the on-device PIN prompt) and replay the operation once.
   *  Deliberate on-device rejections carry code 'rejected' and are never
   *  retried. */
  async #withDevice<T>(
    run: (sdk: NonNullable<PQ1Controller['walletSDK']>) => Promise<T>
  ): Promise<T> {
    const sdk = await this.#acquireDevice()
    try {
      return await run(sdk)
    } catch (e) {
      if (!(e instanceof DeviceError) || e.code !== 'locked') throw e
      const fresh = await this.#acquireDevice()
      return run(fresh)
    }
  }

  #meta(): PQ1Meta {
    return this.key.meta as PQ1Meta
  }

  #accountIndex(): number {
    const m = this.#meta()
    const v = m.accountIndex ?? m.index ?? 0
    if (typeof v !== 'number' || v < 0 || v > 0xff) {
      throw new ExternalSignerError(`PQ1 key meta has invalid accountIndex: ${String(v)}`)
    }
    return v
  }

  /** PQ1 contracts (factory, verifier, EntryPoint wiring) exist only on a
   *  fixed set of chains. Anywhere else a signature would reference a
   *  factory that doesn't exist (ERC-6492) or a wallet that can never be
   *  deployed — refuse with a clear message instead of emitting blobs no
   *  verifier can validate. */
  #requireSupportedChain(chainId: bigint | number, op: string) {
    if (!PQ1_SUPPORTED_CHAIN_IDS.includes(Number(chainId))) {
      throw new ExternalSignerError(
        `PQ1 ${op}: chain ${chainId.toString()} is not supported by PQ1. Supported chains: ${PQ1_SUPPORTED_CHAIN_IDS.join(
          ', '
        )}. Switch to a supported network and try again.`
      )
    }
  }

  /** Fresh on-chain deploy status + active slot/ownerIndex. Never trust
   *  the values cached in key meta at import time — they go stale after
   *  an owner-slot rotation, and a stale ownerIndex makes every ERC-1271
   *  verification fail (see `resolvePq1AccountState`). */
  async #resolveAccountState(provider: JsonRpcProvider, op: string): Promise<Pq1AccountState> {
    try {
      return await resolvePq1AccountState(provider, this.key.addr as `0x${string}`)
    } catch (e: any) {
      throw new ExternalSignerError(
        `PQ1 ${op}: could not read the wallet's on-chain state (${
          e?.message || 'RPC error'
        }). Check the network connection and try again.`,
        { sendCrashReport: false }
      )
    }
  }

  /** Pack the device's raw SPHINCS+C10 signature into the wrapper the
   *  PQSmartWallet's `_validateSignature` expects:
   *  `abi.encode(uint256 ownerIndex, bytes innerSig)`. */
  #wrap(innerSig: Uint8Array, ownerIndex: bigint): `0x${string}` {
    return encodeAbiParameters(
      [
        { name: 'ownerIndex', type: 'uint256' },
        { name: 'signature', type: 'bytes' }
      ],
      [ownerIndex, bytesToHex0x(innerSig)]
    )
  }

  /** Map a device sign bundle to the signature the verifier consumes: the
   *  firmware's ready-made ERC-6492 blob for counterfactual wallets, or
   *  the ERC-1271 ownerIndex wrapper for deployed ones. */
  #toSignature(bundle: SignOffchainBundle, ownerIndex: bigint): `0x${string}` {
    if (bundle.kind === 'counterfactual') {
      // Firmware already produced the EIP-6492-wrapped blob (factory +
      // factoryCalldata + sigWrapper + 0x6492…6492 magic). Pass it
      // straight through to the dapp.
      return bytesToHex0x(bundle.erc6492Sig)
    }
    return this.#wrap(bundle.innerSig, ownerIndex)
  }

  /** PQ1's output is verified on-chain, so we must know which chain the
   *  verifier will run on — otherwise we cannot decide between the bare
   *  ERC-1271 wrapper and the ERC-6492 deploy-and-verify blob. Every
   *  call site in `libs/signMessage/signMessage.ts` threads a
   *  {@link SignMessageContext} through; if a new path forgets it we
   *  fail loudly here rather than silently signing for the wrong chain. */
  #requireCtx(ctx: SignMessageContext | undefined, op: string): SignMessageContext {
    if (ctx) return ctx
    throw new ExternalSignerError(
      `PQ1 ${op}: SignMessageContext { chainId, provider } is required so the device knows which chain the signature is bound to. The keystore caller must pass it through. See KeystoreSignerInterface.${op}.`,
      { sendCrashReport: true }
    )
  }

  signMessage: KeystoreSignerInterface['signMessage'] = async (hex, ctx) => {
    const { chainId, provider } = this.#requireCtx(ctx, 'signMessage')
    this.#requireSupportedChain(chainId, 'signMessage')
    const messageBytes = hexToBytes(hex)
    const accountIndex = this.#accountIndex()

    // Live on-chain state → set the firmware's account_deployed flag and
    // the active slot. On the counterfactual path the device emits an
    // ERC-6492-wrapped blob and the firmware requires slot_index=0 (the
    // only owner the factory seeds); on the deployed path we use the
    // freshly-derived slot.
    const { isDeployed, slotIndex, ownerIndex } = await this.#resolveAccountState(
      provider,
      'signMessage'
    )

    try {
      const common = { accountIndex, slotIndex, chainId, accountDeployed: isDeployed } as const
      const bundle = await this.#withDevice((sdk) =>
        messageBytes.length <= MAX_OFFCHAIN_PERSONAL_SIGN_LEN
          ? // Pass the raw message — firmware computes the EIP-191 prefix hash
            // and renders the text on the OLED before signing.
            sdk.commands.signOffchain({
              ...common,
              kind: 'personal_sign',
              message: messageBytes
            })
          : // Message exceeds the firmware's 700-byte personal_sign cap. Fall
            // back to raw32 mode using the EIP-191 digest computed on this
            // side. The OLED will only show the digest, not the message.
            sdk.commands.signOffchain({
              ...common,
              kind: 'raw32',
              digest: hexToBytes(hashMessage({ raw: messageBytes }))
            })
      )

      return this.#toSignature(bundle, ownerIndex)
    } catch (e: any) {
      throw new ExternalSignerError(e?.message || 'PQ1 message signing failed', {
        sendCrashReport: false
      })
    }
  }

  signTypedData: KeystoreSignerInterface['signTypedData'] = async (typedData, ctx) => {
    const { chainId, provider } = this.#requireCtx(ctx, 'signTypedData')
    this.#requireSupportedChain(chainId, 'signTypedData')
    const accountIndex = this.#accountIndex()

    const { isDeployed, slotIndex, ownerIndex } = await this.#resolveAccountState(
      provider,
      'signTypedData'
    )
    const common = { accountIndex, slotIndex, chainId, accountDeployed: isDeployed } as const

    try {
      // ── ERC-7730 clear-signing dispatch (kind=2) ────────────────
      // Look up a descriptor by `(chainId, verifyingContract)`. When
      // one exists AND the message uses only static atomic field types
      // (so `encodeAbiParameters` reproduces the EIP-712 struct body),
      // we route through the firmware's kind=2 codepath. The device
      // renders field-level pages instead of a raw hex hash.
      //
      // Falls back to kind=0 (raw32) on any miss: catalog unavailable,
      // no descriptor for the verifyingContract, dynamic field types,
      // or trailer assembly failure. The firmware doc § 6.3 explicitly
      // calls this out as the prescribed fallback.
      const verifyingContract = (typedData.domain as any)?.verifyingContract as
        | `0x${string}`
        | undefined
      if (verifyingContract) {
        const pieces = buildErc7730Eip712Pieces({
          domain: typedData.domain as any,
          types: typedData.types as any,
          primaryType: typedData.primaryType as any,
          message: typedData.message as any
        })
        if (pieces) {
          const erc7730Bundle = await buildErc7730BundleForEip712({
            chainId,
            verifyingContract,
            primaryTypeHash: pieces.primaryTypeHash
          })
          if (erc7730Bundle) {
            const bundle = await this.#withDevice((sdk) =>
              sdk.commands.signOffchain({
                kind: 'eip712_typed',
                domainSeparator: pieces.domainSeparator,
                primaryTypeHash: pieces.primaryTypeHash,
                encodedData: pieces.encodedData,
                erc7730Bundle,
                ...common
              })
            )
            return this.#toSignature(bundle, ownerIndex)
          }
        }
      }

      // No descriptor / non-static fields: fall through to raw32 with
      // the EIP-712 final hash. Device shows the fingerprint page only.
      const digestHex = hashTypedData({
        domain: typedData.domain as any,
        types: typedData.types as any,
        primaryType: typedData.primaryType as any,
        message: typedData.message as any
      })
      const bundle = await this.#withDevice((sdk) =>
        sdk.commands.signOffchain({
          kind: 'raw32',
          digest: hexToBytes(digestHex),
          ...common
        })
      )
      return this.#toSignature(bundle, ownerIndex)
    } catch (e: any) {
      throw new ExternalSignerError(e?.message || 'PQ1 typed data signing failed', {
        sendCrashReport: false
      })
    }
  }

  // PQ1 is a smart-account-only signer — these EOA paths are never valid.
  signRawTransaction: KeystoreSignerInterface['signRawTransaction'] = async () => {
    throw new ExternalSignerError(
      'PQ1 cannot sign raw EOA transactions — it is a smart-contract account. Use the smart-account flow.'
    )
  }

  /**
   * Smart-account broadcast entrypoint. signAccountOp calls this for PQ1
   * accounts instead of `signRawTransaction` + raw-eth_sendRawTransaction.
   * Packages the calls into a single ERC-4337 UserOperation, signs on-device,
   * and submits via Pimlico. Returns the userOpHash + EntryPoint nonce —
   * inclusion and per-op success are tracked by Ambire's ActivityController
   * via `identifiedBy: { type: 'UserOperation' }`.
   */
  broadcastAccountOp: NonNullable<KeystoreSignerInterface['broadcastAccountOp']> = async ({
    chainId,
    provider,
    calls,
    gasFeePayment
  }) => {
    this.#requireSupportedChain(chainId, 'broadcastAccountOp')
    const apiKey = process.env.REACT_APP_PIMLICO_API_KEY || ''
    if (!apiKey) {
      throw new ExternalSignerError(
        'Pimlico API key is missing — PQ1 broadcast requires REACT_APP_PIMLICO_API_KEY at build time.'
      )
    }
    // The PQSmartWallet executes via `executeWithOffchainCount(to, ...)` —
    // there is no CREATE path, so a contract-deployment call (no `to`)
    // must be refused up front instead of failing deep in the ABI encoder.
    const deployCall = calls.find((c) => !c.to)
    if (deployCall) {
      throw new ExternalSignerError(
        'PQ1 accounts cannot deploy contracts (a transaction without a `to` address is not supported).'
      )
    }
    try {
      // #withDevice may replay the whole pipeline once on a mid-flight
      // idle-lock. That's safe: a 'locked' error can only originate from
      // the device APDUs, which all happen before the UserOp is submitted
      // to the bundler — the retry just re-estimates and re-signs.
      const result = await this.#withDevice((sdk) =>
        pq1BroadcastAccountOp({
          accountIndex: this.#accountIndex(),
          sender: this.key.addr as `0x${string}`,
          chainId: Number(chainId),
          calls: calls.map((c) => ({
            to: c.to as `0x${string}`,
            value: c.value,
            data: c.data as `0x${string}`
          })),
          pimlicoApiKey: apiKey,
          provider,
          device: sdk.commands,
          // Bind the UserOp's fee fields to what the user approved in the
          // fee UI — the charge must match the confirmation screen.
          fee: {
            maxFeePerGas: gasFeePayment.gasPrice,
            maxPriorityFeePerGas: gasFeePayment.maxPriorityFeePerGas ?? gasFeePayment.gasPrice
          }
        })
      )
      return { userOpHash: result.userOpHash, nonce: result.nonce }
    } catch (e: any) {
      throw new ExternalSignerError(e?.message || 'PQ1 UserOp broadcast failed', {
        sendCrashReport: false
      })
    }
  }

  sign7702: KeystoreSignerInterface['sign7702'] = async () => {
    throw new ExternalSignerError('PQ1 does not support EIP-7702 authorisations.')
  }

  signTransactionTypeFour: KeystoreSignerInterface['signTransactionTypeFour'] = async () => {
    throw new ExternalSignerError('PQ1 does not support EIP-7702 type-4 transactions.')
  }

  async signingCleanup() {
    await this.controller?.signingCleanup?.()
  }
}

export default PQ1Signer
