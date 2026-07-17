// Host-side ERC-20 metadata DB: loader, lookup, and kind-1 trailer builder.
//
// As of firmware `aae0694e`/`7a90f7ca` the ERC-20 / address-name / VK
// databases no longer live on the device — it ships only the 32-byte
// Merkle roots (`ERC20_DB_ROOT`, …) and Merkle-verifies every
// companion-supplied bundle against them in the secure world. The
// companion is the sole holder of the data and MUST attach the matching
// bundle whenever it wants a rich token render ("Send 1 USDC" instead of
// the loud unknown-token page). A withheld bundle degrades safely; a
// forged one cannot pass the Merkle check (second-preimage resistance).
//
// This is the TypeScript port of `tools/companion-stub/db_trailers.py`
// `build_erc20_bundle`, byte-for-byte. It mirrors the firmware's
// `tx/src/erc20/bundle.rs` parse/verify and the on-disk layout in
// `shared/src/db_format.rs`. Header framing / pool accessors / loader
// come from `../db/common.ts` (shared with the names DB and the
// ERC-7730 catalog).
//
// Bundle wire format (`tx/src/erc20/bundle.rs:17-28`, little-endian
// except the address/proof raw bytes):
//
//   chain_id     u64 LE
//   contract     [u8; 20]
//   decimals     u8
//   name_len     u8                (1..=64)
//   name         [u8; name_len]    ASCII
//   symbol_len   u8                (1..=64)
//   symbol       [u8; symbol_len]  ASCII
//   leaf_index   u32 LE
//   proof_depth  u32 LE            (<= 32)
//   proof        [u8; proof_depth * 32]
//
// The caller wraps the bundle as `[u16 BE len][bundle]` when splicing it
// into a sign-input wire payload (positional slot 1 for SIGN_USEROP; the
// two CoW legs of a kind-3 trailer; a per-call record on the batch path).

import {
  checkDbSections,
  createDbLoader,
  DB_HEADER_LEN,
  findSortedEntry,
  parseDbHeader,
  readPoolString,
  readProof,
  readU32Le,
  readU64Le,
  writeU32Le,
  writeU64Le,
  type DbHeader
} from '../db/common'

const ERC20_DB_URL = 'pq1/erc20_db.bin'

const HEADER_MAGIC = new Uint8Array([0x45, 0x52, 0x43, 0x32]) // "ERC2"
const LABEL = 'erc20 db'

// Entry table: 40 bytes per row, sorted by (chain_id, contract).
const ENTRY_LEN = 40
const ENTRY_OFF_CHAIN_ID = 0 // u64 LE
const ENTRY_OFF_CONTRACT = 8 // [u8; 20]
const ENTRY_OFF_NAME_OFF = 28 // u32 LE (offset into the string pool)
const ENTRY_OFF_SYMBOL_OFF = 32 // u32 LE
const ENTRY_OFF_DECIMALS = 36 // u8

/** Firmware cap on the assembled kind-1 bundle (`MAX_ERC20_BUNDLE_LEN`,
 *  `secure/src/nsc/batch_trailers.rs`). The companion enforces it so a
 *  malformed blob never produces an over-cap trailer. */
export const MAX_ERC20_BUNDLE_LEN = 1120

class Erc20Db {
  constructor(
    private readonly blob: Uint8Array,
    readonly header: DbHeader
  ) {}

  /** Leftmost entry-table row for `(chainId, contract20)`, or -1. The
   *  table is sorted by (chain_id, contract) — per-lookup binary search
   *  over the raw rows replaces the eagerly-built key map an earlier
   *  iteration held: the blob is 9.6 MB / ~18k rows and lives for the
   *  lifetime of the always-alive MV3 service worker, so a permanent
   *  string-keyed Map (plus the first-sign full-table parse stall) was
   *  pure overhead next to ~15 row compares. */
  private findRow(chainId: bigint, contract20: Uint8Array): number {
    return findSortedEntry(this.header.entryCnt, (row) => {
      const base = DB_HEADER_LEN + row * ENTRY_LEN
      const rowChain = readU64Le(this.blob, base + ENTRY_OFF_CHAIN_ID)
      if (rowChain < chainId) return -1
      if (rowChain > chainId) return 1
      for (let j = 0; j < 20; j++) {
        const a = this.blob[base + ENTRY_OFF_CONTRACT + j]!
        const b = contract20[j]!
        if (a !== b) return a < b ? -1 : 1
      }
      return 0
    })
  }

  /** Build the kind-1 ERC-20 bundle for `(chainId, contract20)`. Returns
   *  null on a miss — the caller then ships no bundle (the device renders
   *  the fail-safe unknown-token page / per-leg AddrHex). Always keyed by
   *  `(chain_id, contract)`: the same address can be a different token on
   *  different chains (`7a90f7ca`), so a wrong-chain leaf would fail the
   *  device's Merkle check (safe degrade) or — if cached by address —
   *  show the wrong symbol. */
  buildBundle(chainId: number | bigint, contract20: Uint8Array): Uint8Array | null {
    if (contract20.length !== 20) throw new Error('contract must be 20 bytes')
    const leafIndex = this.findRow(BigInt(chainId), contract20)
    if (leafIndex < 0) return null

    const base = DB_HEADER_LEN + leafIndex * ENTRY_LEN
    const decimals = this.blob[base + ENTRY_OFF_DECIMALS]!
    const name = readPoolString(
      this.blob,
      this.header.poolOff + readU32Le(this.blob, base + ENTRY_OFF_NAME_OFF),
      LABEL
    )
    const symbol = readPoolString(
      this.blob,
      this.header.poolOff + readU32Le(this.blob, base + ENTRY_OFF_SYMBOL_OFF),
      LABEL
    )
    const proof = readProof(this.blob, this.header, leafIndex, LABEL)

    const bundleLen = 8 + 20 + 1 + (1 + name.length) + (1 + symbol.length) + 4 + 4 + proof.length
    if (bundleLen > MAX_ERC20_BUNDLE_LEN) {
      throw new Error(
        `erc20 db: assembled bundle ${bundleLen} B exceeds firmware cap ${MAX_ERC20_BUNDLE_LEN} B`
      )
    }

    const out = new Uint8Array(bundleLen)
    let p = 0
    writeU64Le(out, p, BigInt(chainId))
    p += 8
    out.set(contract20, p)
    p += 20
    out[p++] = decimals
    out[p++] = name.length
    out.set(name, p)
    p += name.length
    out[p++] = symbol.length
    out.set(symbol, p)
    p += symbol.length
    writeU32Le(out, p, leafIndex)
    p += 4
    writeU32Le(out, p, this.header.proofDepth)
    p += 4
    out.set(proof, p)
    return out
  }
}

export function parseErc20Db(blob: Uint8Array): Erc20Db {
  const header = parseDbHeader(blob, HEADER_MAGIC, 'ERC2', LABEL)
  checkDbSections(blob, header, ENTRY_LEN, LABEL)
  return new Erc20Db(blob, header)
}

/** Load + parse the ERC-20 DB blob. Idempotent; resolves to the same
 *  cached object on every subsequent call. Throws on header / size
 *  mismatch — callers swallow the throw (log a warning) and ship the
 *  request without an ERC-20 bundle, matching the fail-open contract. */
export const loadErc20Db = createDbLoader(ERC20_DB_URL, parseErc20Db)

export type { Erc20Db }
