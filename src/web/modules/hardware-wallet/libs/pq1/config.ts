// Protocol + chain constants for the PQ1 post-quantum hardware wallet.
// Mirrors the firmware wire format defined in
// sphincs_rust/shared/src/lib.rs and the tooling reference
// at sphincs_rust/tools/webhid_test.html.

// ── Device transport ────────────────────────────────────────────────
export const PQ1_VID = 0x1209
export const PQ1_PID = 0x7051
export const REPORT_SIZE = 64
export const TAG_APDU = 0x05
export const CHANNEL_ID = 0x0101

// ── APDU ────────────────────────────────────────────────────────────
export const CLA_V2 = 0xf0

export const INS_GET_DEVICE_INFO = 0x01
export const INS_GET_STATUS = 0x02
export const INS_UNLOCK = 0x10
export const INS_LOCK = 0x11
export const INS_SIGN_USEROP = 0x30
export const INS_SIGN_USEROP_BATCH = 0x32
export const INS_GET_WALLET_ADDRESS = 0x60
export const INS_GET_INIT_CODE = 0x61 // probe — may be unsupported on older firmware
export const INS_SIGN_OFFCHAIN = 0x62
export const INS_OFFCHAIN_STATUS = 0x63
export const INS_OFFCHAIN_SYNC = 0x64
export const INS_GET_RESPONSE = 0xc0

// OFFCHAIN_SYNC wire layout — account_index(1) || chain_id(8 BE) ||
// slot_index(4 BE) || target_count(8 BE).
export const OFFCHAIN_SYNC_INPUT_LEN = 1 + 8 + 4 + 8 // 21

export const P1_LAST = 0x00
export const P1_MORE = 0x80

export const SW_OK = 0x9000
export const SW_SECURITY_CONDITION = 0x6982
export const SW_SESSION_EXPIRED = 0x6984
export const SW_CONDITIONS_NOT_SATISFIED = 0x6985
export const SW_INS_NOT_SUPPORTED = 0x6d00

// ── Flags (u32 BE in SIGN_USEROP payload) ──────────────────────────
//   bit 31      = INCLUDE_INIT_CODE  (first deploy)
//   bit 30      = REGISTER_SLOT      (slot rotation)
//   bits 29..22 = account_index      (8 bits, BIP-44-style)
//   bits 21..0  = slot_index         (22 bits)
export const FLAG_INCLUDE_INIT_CODE = 0x80000000 >>> 0
export const FLAG_REGISTER_SLOT = 0x40000000
export const ACCOUNT_INDEX_MASK = 0x3fc00000
export const ACCOUNT_INDEX_SHIFT = 22
export const SLOT_INDEX_MASK =
  ~(FLAG_INCLUDE_INIT_CODE | FLAG_REGISTER_SLOT | ACCOUNT_INDEX_MASK) >>> 0
export const MAX_ACCOUNT_INDEX = 0xff
export const MAX_SLOT_USES = 65_536
export const MAX_BATCH_TXS = 4
export const MAX_TX_LEN = 4096

// ── Sizes ──────────────────────────────────────────────────────────
export const C10_SIG_LEN = 4008
export const SIG_WRAPPER_LEN = 32 + 32 + 32 + Math.ceil(C10_SIG_LEN / 32) * 32 // 4128
export const PQ_INIT_CODE_LEN = 20 + 4 + 5 * 32 + 32 + 32 + 4032 // 4280

// ── CMD_SIGN_OFFCHAIN / CMD_OFFCHAIN_STATUS wire layouts ──────────
// Header (17 bytes):
//   [ 0..  1)  account_index    (u8)
//   [ 1..  9)  chain_id         (u64 BE)
//   [ 9.. 13)  slot_index       (u32 BE)
//   [13.. 14)  kind             (u8 — 0 = RAW32, 1 = PERSONAL_SIGN,
//                                       2 = EIP712_TYPED w/ ERC-7730 trailer)
//   [14.. 16)  payload_len      (u16 BE)
//   [16.. 17)  flags            (u8 — bit 0 = OFFCHAIN_FLAG_ACCOUNT_DEPLOYED)
// Matches `cmd_sign_offchain` in sphincs_rust commit 874cd47 ("ERC-6492
// wrapping for counterfactual wallets").
export const SIGN_OFFCHAIN_HEADER_LEN = 1 + 8 + 4 + 1 + 2 + 1 // 17
export const SIGN_OFFCHAIN_INPUT_KIND_OFF = 13
export const SIGN_OFFCHAIN_INPUT_PAYLOAD_LEN_OFF = 14
export const SIGN_OFFCHAIN_INPUT_FLAGS_OFF = 16
export const SIGN_OFFCHAIN_INPUT_PAYLOAD_OFF = 17
export const MAX_OFFCHAIN_PERSONAL_SIGN_LEN = 700

// ── ERC-7730 trailer caps (mirror firmware `proto/src/lib.rs`) ───
// These bound the trailer the companion may attach to a sign request.
// The firmware refuses anything larger with "erc7730 too big".
export const ERC7730_IR_MAX = 4096
export const ERC7730_PROOF_MAX_DEPTH = 32
// 2 (ir_len) + 4096 (ir) + 4 (leaf_index) + 4 (proof_depth) + 32*32 (proof)
export const ERC7730_MAX_TRAILER_LEN = 2 + ERC7730_IR_MAX + 4 + 4 + ERC7730_PROOF_MAX_DEPTH * 32

// ── CMD_SIGN_USEROP_BATCH wire v2: TLV-tagged trailer list ──────────
//
// After the header + N inner-tx blocks, the payload terminates in a
// TLV-tagged trailer list:
//   [u8 trailer_count]
//   trailer_count × { u8 kind, u8 tx_idx, u16 BE len, [len bytes] }
//
// The wire-version byte at offset 276 of the header gates v1 → v2;
// firmware refuses any payload with `wire_version != 2`. See
// `sphincs_rust/proto/src/lib.rs` and
// `secure/src/nsc/batch_trailers.rs`.
export const SIGN_USEROP_BATCH_WIRE_VERSION = 2

/** Per-tx ERC-20 token metadata bundle (verified vs `ERC20_DB_ROOT`). */
export const TRAILER_KIND_ERC20 = 1
// Trailer kind 2 (legacy "ZK v1" Groth16 clear-sign bundle) stays reserved
// in the firmware's wire enum but is retired host-side: nothing can produce
// it since the offscreen Groth16 prover was removed, so no constant is
// exported for it.
/** Per-tx CoW order bundle (canonical GPv2Order + two ERC-20 leg bundles,
 *  bound natively via keccak; no Groth16/VK since fw 05f9758a). */
export const TRAILER_KIND_ZK_V3 = 3
/** Per-tx Safe v1 `approveHash` clear-sign bundle (281-byte canonical SafeTx). */
export const TRAILER_KIND_SAFE_V1 = 4
/** Per-tx verified-selector bundle (curated Merkle DB). */
export const TRAILER_KIND_SEL_CURATED = 5
/** Per-tx self-attested selector (keccak self-check only — no Merkle). */
export const TRAILER_KIND_SEL_SELFATTEST = 6
/** Per-tx ERC-7730 clear-signing descriptor. */
export const TRAILER_KIND_ERC7730 = 7
/** Batch-wide address-name bundle (`tx_idx == TRAILER_TX_IDX_BATCH_WIDE`). */
export const TRAILER_KIND_NAME = 8

/** Sentinel `tx_idx` for batch-wide trailers (currently kind 8 names only). */
export const TRAILER_TX_IDX_BATCH_WIDE = 0xff

/** Hard cap on the number of trailer records per batch sign. Worst-case
 *  realistic count: `MAX_BATCH_TXS × 6` (six per-tx kinds, curated and
 *  self-attest mutually exclusive) + 4 batch-wide names = 28. Round up
 *  to 32 for headroom. */
export const MAX_TRAILERS_PER_BATCH = 32

/** Sum-of-lengths bound on trailer payloads across a single batch. The
 *  firmware refuses anything that pushes the total above this. */
export const TRAILERS_TOTAL_MAX_LEN = 24 * 1024

/** Batch-wide cap on `kind == TRAILER_KIND_NAME` trailers (mirrors
 *  `NameResolver::MAX_NAME_BUNDLES` in the firmware). */
export const MAX_NAME_BUNDLES = 4

// MAX_OFFCHAIN_EIP712_ENCODED_DATA_LEN — the kind=2 `encoded_data` cap.
// Covers Permit, OrderHash, CowSwap GPv2Order, Safe SignMessage with
// headroom (`proto/src/lib.rs`).
export const MAX_OFFCHAIN_EIP712_ENCODED_DATA_LEN = 512
// MAX_OFFCHAIN_EIP712_TYPED_LEN — full kind=2 payload upper bound.
// 2 (dsep_present) + 32 (dsep) + 32 (pth) + 2 (edl) + edl + 2 (trailer_len) + trailer.
export const MAX_OFFCHAIN_EIP712_TYPED_LEN =
  2 + 32 + 32 + 2 + MAX_OFFCHAIN_EIP712_ENCODED_DATA_LEN + 2 + ERC7730_MAX_TRAILER_LEN

// Sized for the largest valid request across all kinds — kind=2 with a
// max-size ERC-7730 trailer dominates personal_sign. Mirrors
// `proto/src/lib.rs::SIGN_OFFCHAIN_INPUT_MAX_LEN`.
export const SIGN_OFFCHAIN_INPUT_MAX_LEN =
  SIGN_OFFCHAIN_HEADER_LEN + Math.max(MAX_OFFCHAIN_PERSONAL_SIGN_LEN, MAX_OFFCHAIN_EIP712_TYPED_LEN)

export const OFFCHAIN_KIND_RAW32 = 0
export const OFFCHAIN_KIND_PERSONAL_SIGN = 1
// EIP-712 typed-data sign that ships an ERC-7730 clear-signing descriptor
// trailer. Payload shape: dsep_present(2) || dsep(32) || pth(32) ||
// edl(2) || encoded_data || trailer_len(2) || trailer. Matches the
// firmware constant `OFFCHAIN_KIND_EIP712_TYPED` in
// sphincs_rust/proto/src/lib.rs.
export const OFFCHAIN_KIND_EIP712_TYPED = 2

// Flags byte values for the sign-offchain header.
export const OFFCHAIN_FLAG_ACCOUNT_DEPLOYED = 0x01

// Deployed-path response: 8-byte counter + 4008-byte raw C10 sig.
export const SIGN_OFFCHAIN_OUTPUT_LEN = 8 + C10_SIG_LEN // 4016
// Counterfactual-path response: 8-byte counter + 8608-byte ERC-6492 blob
// (abi.encode(address factory, bytes factoryCalldata, bytes sigWrapper) ||
// 0x6492…6492 magic suffix). Pass-through to the dapp verbatim.
export const ERC6492_WRAPPED_BLOB_LEN = 8608
export const SIGN_OFFCHAIN_OUTPUT_LEN_COUNTERFACTUAL = 8 + ERC6492_WRAPPED_BLOB_LEN // 8616
export const SIGN_OFFCHAIN_OUTPUT_COUNT_OFF = 0
export const SIGN_OFFCHAIN_OUTPUT_SIG_OFF = 8

export const OFFCHAIN_STATUS_INPUT_LEN = 1 + 8 + 4 // 13
export const OFFCHAIN_STATUS_OUTPUT_LEN = 8 + 8 + 1 + 7 // 24
export const OFFCHAIN_STATUS_OUTPUT_LOCAL_OFF = 0
export const OFFCHAIN_STATUS_OUTPUT_LAST_USEROP_OFF = 8
export const OFFCHAIN_STATUS_OUTPUT_REGISTERED_OFF = 16

// cmd_sign_offchain enforces `local_offchain - last_userop < MAX_OFFCHAIN_GAP`
// so the device cannot emit more than this many unbacked off-chain sigs before
// the next on-chain UserOp publishes the count.
export const MAX_OFFCHAIN_GAP = 5n

export function timeoutForIns(ins: number): number {
  switch (ins) {
    case INS_UNLOCK:
      return 60_000
    case INS_SIGN_USEROP:
    case INS_SIGN_USEROP_BATCH:
    case INS_SIGN_OFFCHAIN:
      return 120_000
    case INS_GET_WALLET_ADDRESS:
    case INS_GET_INIT_CODE:
      return 30_000
    default:
      return 5_000
  }
}

// ── EntryPoint + factory ─────────────────────────────────────────
export const ENTRY_POINT_V06 = '0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789' as const
// PQSmartWalletFactory — CREATE2-deterministic (Arachnid 0x4e59… deployer),
// same address on every chain. Live on Base Mainnet (2026-06-12); Base
// Sepolia redeploy pending. Must match firmware PQ_SMART_WALLET_FACTORY.
export const FACTORY = '0xe8ce78cd976497447ff8b76c71b59ae42af0d452' as const
// PQSmartWallet slot-authorised execute = executeWithOffchainCount(ownerIndex,
// newOffchainCount, target, value, bytes). The plain `execute` path is NOT
// allowed for slot signatures.
export const EXECUTE_SELECTOR = new Uint8Array([0x14, 0x44, 0x3c, 0x57])
export const ADD_OWNER_BYTES_SELECTOR = new Uint8Array([0x10, 0x14, 0x90, 0xcb])

// sha256("") — used as paymaster_and_data_hash when no paymaster is attached.
export const SHA256_EMPTY = new Uint8Array([
  0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
  0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55
])

// ── Gas defaults / fallbacks ────────────────────────────────────────
export const DEFAULT_GAS = {
  verGas: 800_000n,
  callGas: 50_000n,
  preVerificationGas: 150_000n,
  maxPriorityFeePerGas: 100_000_000n, // 0.1 gwei
  maxFeePerGas: 1_000_000_000n // 1 gwei
} as const

export const FALLBACK_GAS = {
  callGas: 50_000n,
  verGas: 800_000n,
  preVerificationGas: 250_000n,
  preVerificationGasFirstDeploy: 400_000n
} as const

// Minimal EVM runtime that returns ABI `true` (a 32-byte word == 1) for any
// call: PUSH1 0x01, PUSH1 0x00, MSTORE, PUSH1 0x20, PUSH1 0x00, RETURN.
// Used as an `eth_estimateUserOperationGas` state-override for the SPHINCS+
// verifier (see aa/broadcast.ts). The dummy estimation signature can never
// pass a real C10 verify, and both the factory's bootstrap verify
// (PQSmartWalletFactory.createAccount) and the wallet's per-op verify
// (PQSmartWallet._validateSignature) gate their success on it — the wallet
// only stamps the execution-phase validated-op credit AFTER a passing verify.
// Without this stub the simulated execution reverts with OwnerIndexMismatch()
// (selector 0x05d8cb2d) and Pimlico cannot return a callGasLimit. The
// verifier is the ONLY crypto gate and is never reached by the execution
// phase, so stubbing it keeps the measured callGas exact; the cheap
// verificationGasLimit it yields is discarded by the 800k hard-pin in
// broadcast.ts.
export const VERIFIER_STUB_RETURN_TRUE_CODE = '0x600160005260206000f3' as const

// ── Bundler URLs ────────────────────────────────────────────────────
// Pimlico is the bundler PQ1 is validated against. The API key is sourced
// from the host extension's env (Ambire reads it via @env at build time and
// injects it through the background; this module only knows how to format
// the URL).
export function pimlicoBundlerUrl(chainId: number | bigint, apiKey: string): string {
  return `https://api.pimlico.io/v2/${chainId.toString()}/rpc?apikey=${apiKey}`
}

// Chains where the PQ1 factory is deployed at the constant address above.
export const PQ1_SUPPORTED_CHAIN_IDS: readonly number[] = [1, 8453, 84532]
export const PQ1_DEFAULT_CHAIN_ID = 8453
