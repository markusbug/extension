// PQ1 AccountOp → UserOp broadcast pipeline.
//
// Wraps the full signing path PQ1 needs in a single async function so the
// caller in Ambire's main / signAccountOp controllers can do
// `if (isPQ1Account) return pq1BroadcastAccountOp(...)` and bypass the
// Ambire 4337 / relayer flow entirely.
//
// Integration point — Phase 2 wiring:
//   Ambire's `signAccountOp.sign()` (controllers/signAccountOp/signAccountOp.ts)
//   currently builds an Ambire-style UserOp and broadcasts it through either
//   the Ambire relayer or directly to a bundler that validates ECDSA signatures.
//   For PQ1 accounts (detected via the imported ExternalKey with
//   `type === 'pq1'`), that whole path must be short-circuited and replaced
//   with `pq1BroadcastAccountOp(...)`. The result maps onto Ambire's
//   `identifiedBy: { type: 'UserOperation' }` shape: we return the userOpHash
//   right after `eth_sendUserOperation` accepts the op and let Ambire's
//   ActivityController resolve inclusion, the tx hash, and per-op success
//   (it parses the UserOperationEvent log, so a reverted inner execution is
//   correctly reported as a failure). Waiting for the receipt here instead
//   would misreport slow-but-included ops as failed — and a user who re-signs
//   after such a "failure" risks a duplicate spend.

import type { JsonRpcProvider } from 'ethers'

import { captureException } from '@common/config/analytics/CrashAnalytics.web'

import {
  DEFAULT_GAS,
  ENTRY_POINT_V06,
  FACTORY,
  FALLBACK_GAS,
  MAX_NAME_BUNDLES,
  PQ1_DEFAULT_CHAIN_ID,
  PQ1_SUPPORTED_CHAIN_IDS,
  pimlicoBundlerUrl,
  SIG_WRAPPER_LEN,
  VERIFIER_STUB_RETURN_TRUE_CODE
} from '../config'
import { hexToBytes } from '../transport/bytes'
import type { DeviceCommands } from '../transport/commands'
import { parseCallBigInt, resolvePq1AccountState } from './accountState'
import {
  decodeC10Verifier,
  encodeC10Verifier,
  encodeExecute,
  encodeExecuteBatch,
  encodeGetNonce,
  encodeOffchainSigCount
} from './contracts'
import { buildZeroInitCode } from './factory'
import { BundlerClient, type StateOverride } from './bundler'
import { applyEstimate, buildUserOp, finalize, forEstimate } from './userop'
import { isCowSetPreSignature, tryBuildV3Trailer } from '../cowswap/v3Trailer'
import { resolveErc20Bundle } from '../erc20/detect'
import { buildErc7730BundleForCall } from '../erc7730/lookup'
import { buildNameBundles, collectDisplayAddresses } from '../names/resolve'
import {
  decodeExecTransaction,
  isSafeExecTransaction,
  readExecTransactionOperation
} from '../safe/execCalldata'
import { assertSafeOperationSignable, resolveSafeCowBinding } from '../safe/multiSend'
import { isSafeApproveHash, tryBuildSafeV1Trailer } from '../safe/safeV1Trailer'

type Call = { to: `0x${string}`; value: bigint; data: `0x${string}` }

export type PQ1BroadcastParams = {
  accountIndex: number
  sender: `0x${string}`
  chainId?: number
  calls: Call[]
  /** Pimlico API key — fed in from the host extension's env. */
  pimlicoApiKey: string
  /** Provider used for read calls (getCode, getNonce, nextOwnerIndex). The
   *  caller in signAccountOp passes through its own JsonRpcProvider so the
   *  same RPC settings/headers apply. */
  provider: JsonRpcProvider
  /** Authenticated, unlocked PQ1 device handle. The popup that owns the
   *  WebHID transport supplies this — see PQ1Controller.walletSDK. */
  device: DeviceCommands
  /** The fee the user approved in Ambire's fee UI. When provided, the
   *  UserOp is submitted with exactly these fee-per-gas values, so the
   *  charge matches what the user confirmed. The Pimlico gas-price oracle
   *  is only consulted when absent. */
  fee?: { maxFeePerGas: bigint; maxPriorityFeePerGas: bigint }
}

export type PQ1BroadcastResult = {
  userOpHash: `0x${string}`
  /** EntryPoint nonce the op was submitted with. */
  nonce: bigint
}

/**
 * Execute one or more calls from a PQ1-controlled PQSmartWallet:
 *   1. Read on-chain state (deploy status, nonce, active slot).
 *   2. Pick slot + ownerIndex; build the appropriate `executeWithOffchainCount`
 *      / `executeBatchWithOffchainCount` calldata.
 *   3. Estimate gas via Pimlico (with a dummy signature placeholder).
 *   4. Sign the UserOp on-device.
 *   5. Finalize (real signature, real initCode if first deploy) and submit.
 *   6. Return the userOpHash — inclusion tracking is the caller's job
 *      (Ambire's ActivityController, via `identifiedBy: 'UserOperation'`).
 */
export async function pq1BroadcastAccountOp(
  params: PQ1BroadcastParams
): Promise<PQ1BroadcastResult> {
  const chainId = params.chainId ?? PQ1_DEFAULT_CHAIN_ID

  // Fail fast with a clear message on chains where the PQ1 contracts
  // (factory, verifier, EntryPoint wiring) are not deployed. Without this
  // guard the pipeline dies much later in gas estimation with a generic
  // error that doesn't tell the user the chain is the problem.
  if (!PQ1_SUPPORTED_CHAIN_IDS.includes(chainId)) {
    throw new Error(
      `PQ1 is not available on chain ${chainId}. Supported chains: ${PQ1_SUPPORTED_CHAIN_IDS.join(
        ', '
      )}. Switch to a supported network and try again.`
    )
  }

  const { provider } = params
  const bundler = new BundlerClient(
    pimlicoBundlerUrl(chainId, params.pimlicoApiKey),
    ENTRY_POINT_V06
  )

  // ── 1. On-chain state (+ independent bundler/factory reads) ──────
  // The account state (getCode + nextOwnerIndex), the EntryPoint nonce,
  // the Pimlico gas price, and the factory's c10Verifier read don't
  // depend on each other — fetch them concurrently so the device prompt
  // appears without four serial RPC round trips of delay.
  //
  // Gas price: hardcoded `DEFAULT_GAS` fees (1 gwei) are below Pimlico's
  // gas-oracle minimums on busier chains, which surfaces as a misleading
  // "AA21 didn't pay prefund" — Pimlico computes `requiredPrefund` from
  // the userOp's `maxFeePerGas`, so if that's too low relative to its
  // oracle it rejects even funded wallets. When the caller passes the
  // user-approved fee we use it verbatim (the fee UI's numbers must be
  // what the user actually pays); the oracle is a fallback for callers
  // without a fee UI. On oracle RPC failure we log and fall back to the
  // conservative defaults.
  //
  // Verifier: see § 3b below for why the read is needed.
  const [accountState, nonceHex, oracleGas, verifierHex] = await Promise.all([
    resolvePq1AccountState(provider, params.sender),
    provider.call({ to: ENTRY_POINT_V06, data: encodeGetNonce(params.sender) }),
    params.fee
      ? Promise.resolve(null)
      : bundler.getUserOperationGasPrice().catch((e) => {
          console.warn('[pq1] pimlico_getUserOperationGasPrice failed, using defaults', e)
          return null
        }),
    provider.call({ to: FACTORY, data: encodeC10Verifier() }).catch((e) => {
      // Non-fatal here: without the verifier read the estimate below will
      // fail and we abort with a clear error (rather than shipping
      // under-estimated gas).
      captureException(e)

      console.warn('[pq1] could not read c10Verifier for estimation override', e)
      return null
    })
  ])
  const { isDeployed, slotIndex, ownerIndex } = accountState
  const nonce = parseCallBigInt(nonceHex, 'EntryPoint getNonce')

  // Read on-chain `offchainSigCount[ownerIndex]` once, then use it for
  // two purposes:
  //   1. The estimation-time `newOffchainCount` placeholder in the
  //      initial calldata. The wallet's `_setOffchainSigCount` reverts
  //      with `OffchainSigCountNotMonotonic` if `newCount < current`,
  //      so using `0n` here makes `eth_estimateUserOperationGas`
  //      revert on any deployed wallet that has ever signed an
  //      off-chain message — even though the final calldata (post-
  //      device-sign) will carry the right value.
  //   2. As a floor for the device's `last_userop_count` via
  //      `CMD_OFFCHAIN_SYNC` (recovers the device's view after a
  //      firmware reflash wiped its secure-flash counters).
  //
  // The reference companion implementation follows the same pattern —
  // estimation guess + post-sign re-encode with the firmware's emitted
  // count.
  let onchainOffchainCount = 0n
  if (isDeployed) {
    try {
      const r = await provider.call({
        to: params.sender,
        data: encodeOffchainSigCount(ownerIndex)
      })
      onchainOffchainCount = BigInt(r || '0x0')
      if (onchainOffchainCount > 0n) {
        await params.device.offchainSync({
          accountIndex: params.accountIndex,
          chainId,
          slotIndex,
          targetCount: onchainOffchainCount
        })
      }
    } catch (e) {
      // Best-effort: if the read or the sync APDU fails, fall through.
      // The estimation guess defaults back to 0 in that case — accurate
      // for fresh wallets, will revert on `_setOffchainSigCount` for
      // wallets with existing on-chain count (the explicit warn below
      // makes that path visible instead of silent).

      console.warn('[pq1] offchain count read/sync failed', e)
    }
  }

  // ── 2. Build calldata ────────────────────────────────────────────
  // newOffchainCount placeholder here matches the on-chain count so
  // `_setOffchainSigCount(newCount=prev)` is a no-op pass — both
  // estimation and the eventual broadcast satisfy monotonicity. After
  // the device signs we re-encode with `signBundle.newOffchainCount`
  // (which is `>= onchainOffchainCount` per the sync command above,
  // and `> onchainOffchainCount` whenever the device has issued
  // additional off-chain sigs since the last userop).
  let callData: `0x${string}`
  if (params.calls.length === 1) {
    const c = params.calls[0]!
    callData = encodeExecute(ownerIndex, onchainOffchainCount, c.to, c.value, c.data)
  } else {
    callData = encodeExecuteBatch(
      ownerIndex,
      onchainOffchainCount,
      params.calls.map((c) => c.to),
      params.calls.map((c) => c.value),
      params.calls.map((c) => c.data)
    )
  }

  // ── 3a. Fee-per-gas figures ──────────────────────────────────────
  // Priority: the user-approved fee from Ambire's fee UI, then the
  // Pimlico oracle (fetched above), then conservative defaults.
  let maxFeePerGas: bigint = DEFAULT_GAS.maxFeePerGas
  let maxPriorityFeePerGas: bigint = DEFAULT_GAS.maxPriorityFeePerGas
  if (params.fee) {
    maxFeePerGas = params.fee.maxFeePerGas
    maxPriorityFeePerGas = params.fee.maxPriorityFeePerGas
  } else if (oracleGas) {
    maxFeePerGas = BigInt(oracleGas.standard.maxFeePerGas)
    maxPriorityFeePerGas = BigInt(oracleGas.standard.maxPriorityFeePerGas)
  }

  // ── 3b. Gas-limit estimate via Pimlico ───────────────────────────
  // The dummy estimation signature (all-0xff inner sig) can't pass a real
  // SPHINCS+ verify, so `_validateSignature` returns SIG_VALIDATION_FAILED
  // and skips stamping the execution-phase validated-op credit. Bundlers
  // ignore the signature result during estimation but still run execution,
  // where `executeWithOffchainCount` then reverts with `OwnerIndexMismatch()`
  // — so estimation can never return a callGasLimit. Override the verifier's
  // code with a return-true stub for the simulation: this is the only crypto
  // gate (factory bootstrap verify + wallet per-op verify) and is never
  // reached by the execution phase, so callGas stays exact while validation
  // passes and stamps the credit. The verifier is a CREATE2 singleton read
  // from the always-deployed factory (works for counterfactual wallets too).
  let estimateStateOverride: StateOverride | undefined
  if (verifierHex) {
    try {
      const verifier = decodeC10Verifier(verifierHex as `0x${string}`)
      estimateStateOverride = {
        [verifier.toLowerCase() as `0x${string}`]: { code: VERIFIER_STUB_RETURN_TRUE_CODE }
      }
    } catch (e) {
      // Non-fatal here (like a failed read above): without the override the
      // estimate below will fail and we abort with a clear error (rather
      // than shipping under-estimated gas).
      captureException(e)

      console.warn('[pq1] could not decode c10Verifier for estimation override', e)
    }
  }

  const opForEstimate = forEstimate(
    buildUserOp({
      sender: params.sender,
      nonce,
      initCode: isDeployed ? new Uint8Array(0) : buildZeroInitCode(chainId),
      callData,
      callGasLimit: DEFAULT_GAS.callGas,
      verificationGasLimit: DEFAULT_GAS.verGas,
      preVerificationGas: isDeployed
        ? FALLBACK_GAS.preVerificationGas
        : FALLBACK_GAS.preVerificationGasFirstDeploy,
      maxFeePerGas,
      maxPriorityFeePerGas,
      signature: new Uint8Array(SIG_WRAPPER_LEN).fill(0xff)
    }),
    ownerIndex
  )
  let op: typeof opForEstimate
  try {
    const est = await bundler.estimateUserOperationGas(opForEstimate, estimateStateOverride)
    op = applyEstimate(opForEstimate, est)
  } catch (e) {
    // Estimation failed even with the verifier-stub override: the op would
    // genuinely revert / OOG on-chain, or the bundler/RPC is unavailable. Do
    // NOT fall through to DEFAULT_GAS — a 50k callGas userop is virtually
    // guaranteed to OOG for any router-style call, which is exactly the bug
    // this path used to ship. Track the underlying reason and abort so the
    // user sees a clear pre-flight error instead of losing gas to an OOG.
    captureException(e)

    console.warn('[pq1] eth_estimateUserOperationGas failed', e)
    throw new Error(
      'PQ1 gas estimation failed — transaction not broadcast to avoid an out-of-gas failure.'
    )
  }

  // verificationGasLimit is wallet-specific policy: SPHINCS+C10 verify
  // through SPHINCsC10Asm is dominated by ~256 SHA-256 precompile calls
  // whose individual cost can drift between Pimlico's simulator and a
  // live block (warm/cold precompile, post-fork SHA-256 metering
  // changes, etc.), which is exactly the AA40-over-verificationGasLimit
  // class of error. 800k covers a real SPHINCS+ verify (~214k deployed,
  // ~760k first-deploy with factory bytecode) with comfortable headroom
  // on every chain we target. Hard-pinned post-estimate so it overrides
  // whatever Pimlico returned. callGas / preVerGas remain Pimlico's
  // figures (per llms-full.txt: "use the returned estimate").
  op = { ...op, verificationGasLimit: `0x${800_000n.toString(16)}` }

  // ── 4. Sign on-device ────────────────────────────────────────────
  // SIGN_USEROP_BATCH carries up to 4 calls; single-call uses SIGN_USEROP.
  // The v2 batch wire format (companion-batch-sign-trailer-parity.md)
  // routes per-call trailers via TLV records, so CoW v3 and ERC-7730
  // descriptors are attached to the specific inner tx they bind to.
  const includeInitCode = !isDeployed

  const singleCall = params.calls.length === 1 ? params.calls[0]! : null

  // Build per-call clear-signing trailers in parallel. For each inner
  // call we attempt — in priority order — a CoW v3 trailer (mandatory
  // when the call is setPreSignature on GPv2Settlement), a Safe v1
  // trailer (mandatory when the call is approveHash(bytes32) on a
  // Safe), or an ERC-7730 descriptor. A Safe flow (approveHash or
  // execTransaction) whose SafeTx *inner* call is itself a CoW
  // setPreSignature — directly, or as the unique presign record inside
  // an allowlisted MultiSendCallOnly batch — gets BOTH trailers: the
  // Safe context plus a CoW v3 trailer bound to the exact presign
  // calldata with `uid.owner == the Safe` (GPv2 sees the Safe as
  // msg.sender at execution) — the firmware renders the combined Safe +
  // order confirmation and refuses to sign without the proof
  // (companion-safe-cowswap-presign.md, -multisend.md). The CoW and
  // Safe trailers are firmware downgrade-mitigation gates:
  // refuse-to-sign if the bundle is missing. ERC-7730 lookup misses are
  // silent; the firmware blind-signs calls without a matching trailer.
  type PerCallTrailers = {
    erc20Bundle?: Uint8Array
    zkV3Bundle?: Uint8Array
    safeV1Bundle?: Uint8Array
    erc7730Bundle?: Uint8Array
  }
  type ClearSignTrailers = Omit<PerCallTrailers, 'erc20Bundle'>
  const perCall = await Promise.all(
    params.calls.map(async (c): Promise<{ trailers: PerCallTrailers; nameAddrs: Uint8Array[] }> => {
      const innerData = hexToBytes(c.data)
      // The kind-1 ERC-20 metadata bundle is orthogonal to the CoW/Safe
      // clear-sign trailers: a transfer/transferFrom/approve — direct,
      // Safe-wrapped (op=0), or the approve inside a MultiSendCallOnly CoW
      // approve+presign batch — renders with a token symbol when we attach
      // it. A CoW approve+presign batch needs BOTH the kind-1 bundle (for
      // the approve) and the kind-3 CoW trailer (for the order). Resolve it
      // once and merge with whatever the CoW/Safe/erc7730 routing produces;
      // a miss / DB-load failure degrades safely to the unknown-token page.
      const erc20Bundle = await resolveErc20Bundle(chainId, c.to, innerData)
      const clearSign = await (async (): Promise<ClearSignTrailers & { cowReceiver?: string }> => {
        if (isCowSetPreSignature(c.to, innerData)) {
          const built = await tryBuildV3Trailer({
            chainId,
            owner: params.sender,
            innerData
          })
          if (!built) {
            // isCowSetPreSignature matches on target+selector exactly like
            // the firmware gate, so a strict-decode miss here is calldata
            // the device refuses no matter what we attach.
            throw new Error(
              'CoW setPreSignature calldata is malformed — the PQ1 firmware refuses to sign it (CoW sign: v3 required).'
            )
          }
          return { zkV3Bundle: built.zkV3Bundle, cowReceiver: built.order.receiver }
        }
        if (isSafeApproveHash(c.to, innerData)) {
          const built = await tryBuildSafeV1Trailer({
            chainId,
            to: c.to,
            innerData
          })
          if (!built) return {}
          // Safe-wrapped CoW pre-sign: the SafeTx's inner call is
          // setPreSignature on GPv2Settlement — either directly, or as the
          // unique presign record inside an allowlisted MultiSendCallOnly
          // batch (the shape the Safe UI emits: approve + presign through
          // a DELEGATECALL multiSend, companion-safe-cowswap-multisend.md).
          // Both demand a CoW v3 trailer bound to the exact presign
          // calldata with `uid.owner == the Safe` (c.to), not the wallet.
          // The resolver mirrors the firmware's `resolve_safe_arm`, and
          // its `refuse` case is unreachable here — tryBuildSafeV1Trailer
          // already threw on a multiSend hard-rule violation.
          const safeTxData = hexToBytes(built.fields.data)
          const binding = resolveSafeCowBinding(
            built.fields.operation,
            built.fields.to.toLowerCase(),
            safeTxData
          )
          if (binding.kind === 'refuse') {
            throw new Error(
              `Safe multiSend batch refused by PQ1 firmware ("Safe sign / ${binding.banner}").`
            )
          }
          if (binding.kind === 'bind') {
            const v3 = await tryBuildV3Trailer({
              chainId,
              owner: c.to,
              innerData: binding.calldata
            })
            if (!v3) {
              throw new Error(
                'Safe-wrapped CoW setPreSignature calldata is malformed — the PQ1 firmware refuses to sign it (CoW sign: v3 required).'
              )
            }
            return {
              zkV3Bundle: v3.zkV3Bundle,
              safeV1Bundle: built.safeV1Bundle,
              cowReceiver: v3.order.receiver
            }
          }
          return { safeV1Bundle: built.safeV1Bundle }
        }
        if (isSafeExecTransaction(innerData)) {
          // No safe_v1 trailer needed — the firmware decodes the SafeTx
          // fields directly out of `inner_data`. DelegateCall is signable
          // ONLY as an allowlisted MultiSendCallOnly batch (companion-
          // safe-cowswap-multisend.md); everything else op=1 fail-fasts
          // here with the same refusal the device enforces (`Safe sign:
          // exec parse fail`). Skip the ERC-7730 lookup because the
          // firmware's safe-exec renderer takes priority over any erc7730
          // trailer.
          //
          // Safe-wrapped CoW pre-sign, execTransaction flavour: the SafeTx
          // inner call still demands the v3 trailer — bound to the SafeTx
          // `data` directly, or to the unique presign record inside a
          // multiSend batch. The decode mirrors the firmware's acceptance
          // rules exactly — when it fails here it fails on-device too
          // (`Safe sign: exec parse fail`), so skipping the proof cannot
          // desync the two sides.
          const exec = decodeExecTransaction(innerData)
          if (!exec) {
            const op = readExecTransactionOperation(innerData)
            if (op === 1) {
              throw new Error(
                'Safe execTransaction with DelegateCall (operation=1) is not decodable — the PQ1 ' +
                  'firmware refuses to sign it (Safe sign: exec parse fail).'
              )
            }
            return {}
          }
          if (exec.operation === 1) {
            // Throws unless the inner call is a hard-rule-passing batch on
            // a canonical MultiSendCallOnly deployment.
            assertSafeOperationSignable(exec.operation, exec.to, exec.data)
          }
          const binding = resolveSafeCowBinding(exec.operation, exec.to, exec.data)
          if (binding.kind === 'refuse') {
            throw new Error(
              `Safe multiSend batch refused by PQ1 firmware ("Safe sign / ${binding.banner}").`
            )
          }
          if (binding.kind === 'bind') {
            const v3 = await tryBuildV3Trailer({
              chainId,
              owner: c.to,
              innerData: binding.calldata
            })
            if (!v3) {
              throw new Error(
                'Safe-wrapped CoW setPreSignature calldata is malformed — the PQ1 firmware refuses to sign it (CoW sign: v3 required).'
              )
            }
            return { zkV3Bundle: v3.zkV3Bundle, cowReceiver: v3.order.receiver }
          }
          return {}
        }
        const erc7730Bundle = (await buildErc7730BundleForCall({ chainId, to: c.to })) ?? undefined
        return { erc7730Bundle }
      })()

      // Names (kind 8): every address the device will display for this call
      // — `to`, ERC-20 args, Safe / multiSend targets, plus the CoW order
      // receiver when this is a presign. Collected here; deduped and capped
      // at MAX_NAME_BUNDLES across the whole sign below.
      const nameAddrs = collectDisplayAddresses(c.to, innerData)
      if (clearSign.cowReceiver) nameAddrs.push(hexToBytes(clearSign.cowReceiver))

      const trailers: PerCallTrailers = {
        erc20Bundle,
        zkV3Bundle: clearSign.zkV3Bundle,
        safeV1Bundle: clearSign.safeV1Bundle,
        erc7730Bundle: clearSign.erc7730Bundle
      }
      return { trailers, nameAddrs }
    })
  )
  const perCallTrailers = perCall.map((x) => x.trailers)
  // kind-8 names are batch-wide (one shared NameResolver). Aggregate every
  // displayed address across all inner calls, then dedupe + cap to 4.
  const nameBundles = await buildNameBundles(
    chainId,
    perCall.flatMap((x) => x.nameAddrs),
    MAX_NAME_BUNDLES
  )

  const signBundle = singleCall
    ? await params.device.signUserOp({
        chainId,
        accountIndex: params.accountIndex,
        slotIndex,
        includeInitCode,
        sender: params.sender,
        nonce,
        callGas: BigInt(op.callGasLimit),
        verGas: BigInt(op.verificationGasLimit),
        preVerificationGas: BigInt(op.preVerificationGas),
        maxFeePerGas: BigInt(op.maxFeePerGas),
        maxPriorityFeePerGas: BigInt(op.maxPriorityFeePerGas),
        to: singleCall.to,
        value: singleCall.value,
        data: hexToBytes(singleCall.data),
        erc20Bundle: perCallTrailers[0]!.erc20Bundle,
        zkV3Bundle: perCallTrailers[0]!.zkV3Bundle,
        safeV1Bundle: perCallTrailers[0]!.safeV1Bundle,
        erc7730Bundle: perCallTrailers[0]!.erc7730Bundle,
        nameBundles
      })
    : await params.device.signUserOpBatch({
        chainId,
        accountIndex: params.accountIndex,
        slotIndex,
        includeInitCode,
        sender: params.sender,
        nonce,
        callGas: BigInt(op.callGasLimit),
        verGas: BigInt(op.verificationGasLimit),
        preVerificationGas: BigInt(op.preVerificationGas),
        maxFeePerGas: BigInt(op.maxFeePerGas),
        maxPriorityFeePerGas: BigInt(op.maxPriorityFeePerGas),
        calls: params.calls.map((c, i) => ({
          to: c.to,
          value: c.value,
          data: hexToBytes(c.data),
          erc20Bundle: perCallTrailers[i]!.erc20Bundle,
          zkV3Bundle: perCallTrailers[i]!.zkV3Bundle,
          safeV1Bundle: perCallTrailers[i]!.safeV1Bundle,
          erc7730Bundle: perCallTrailers[i]!.erc7730Bundle
        })),
        nameBundles
      })

  // ── 5. Re-encode callData with the real newOffchainCount, then submit
  if (params.calls.length === 1) {
    const c = params.calls[0]!
    op = {
      ...op,
      callData: encodeExecute(ownerIndex, signBundle.newOffchainCount, c.to, c.value, c.data)
    }
  } else {
    op = {
      ...op,
      callData: encodeExecuteBatch(
        ownerIndex,
        signBundle.newOffchainCount,
        params.calls.map((c) => c.to),
        params.calls.map((c) => c.value),
        params.calls.map((c) => c.data)
      )
    }
  }
  op = finalize(op, { initCode: signBundle.initCode, signature: signBundle.type2 })

  // Submit and return immediately — see the module header for why we do
  // NOT wait for the receipt here.
  const userOpHash = await bundler.sendUserOperation(op)

  return { userOpHash, nonce }
}
