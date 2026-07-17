// Host-side address-name DB: loader, two-phase lookup, and kind-8 trailer
// builder.
//
// Like the ERC-20 / VK DBs, the names DB no longer lives on the device —
// it ships only the 32-byte `NAMES_DB_ROOT` and Merkle-verifies every
// companion-supplied bundle against it before a single `name` byte reaches
// the OLED. The companion attaches a bundle for each displayed address so
// the device renders a human label (e.g. `Uniswap V3 Router`) instead of
// 40-hex. A withheld bundle degrades safely to hex; a forged label cannot
// pass the Merkle check (SHA-256 second-preimage). See companion-names-db.md.
//
// TypeScript port of `tools/companion-stub/db_trailers.py build_names_bundle`,
// byte-for-byte; mirrors the firmware's `tx/src/names/bundle.rs` and the
// on-disk layout in `shared/src/db_format.rs`. Header framing / pool
// accessors / loader come from `../db/common.ts` (shared with the ERC-20
// DB and the ERC-7730 catalog).
//
// Bundle wire layout (`tx/src/names/bundle.rs`, LE except address/proof):
//
//   chain_id     u64 LE        0 = wildcard / chain-agnostic
//   address      [u8; 20]
//   name_len     u8            (1..=32)
//   name         [u8; name_len]   printable ASCII (0x20..=0x7e)
//   leaf_index   u32 LE
//   proof_depth  u32 LE        (<= 32)
//   proof        [u8; proof_depth * 32]
//
// The on-disk entry table is keyed by a 16-byte SHA-256 short-key, NOT the
// raw address, so lookup hashes `(chain_id, address)` the same way dbgen
// does. The Merkle leaf still binds the full `(chain_id, address, name)`.

import { sha256 } from 'viem'

import { concatBytes, u64be } from '../transport/bytes'
import {
  checkDbSections,
  createDbLoader,
  DB_HEADER_LEN,
  findSortedEntry,
  parseDbHeader,
  readPoolString,
  readProof,
  readU32Le,
  writeU32Le,
  writeU64Le,
  type DbHeader
} from '../db/common'

const NAMES_DB_URL = 'pq1/names_db.bin'

const HEADER_MAGIC = new Uint8Array([0x4e, 0x41, 0x4d, 0x53]) // "NAMS"
const LABEL = 'names db'

// Entry table: 20 bytes per row, sorted by short_key.
const ENTRY_LEN = 20
const ENTRY_OFF_SHORT_KEY = 0 // [u8; 16]
const ENTRY_OFF_NAME_OFF = 16 // u32 LE (offset into the string pool)
const SHORT_KEY_LEN = 16

/** Domain tag for the on-disk short-key (`NAMES_SHORT_KEY_TAG`):
 *  `sha256(tag || chain_id[8 BE] || address[20])[..16]`. Note this is the
 *  index key only — the Merkle leaf hashes the canonical fields. */
const SHORT_KEY_TAG = new TextEncoder().encode('pqsigner-name-key-v1')

/** `chain_id = 0` is an unambiguous wildcard sentinel (real EVM chain ids
 *  start at 1) for chain-agnostic labels (`NAMES_WILDCARD_CHAIN_ID`). */
const WILDCARD_CHAIN_ID = 0n

/** Firmware cap on one assembled kind-8 bundle (`MAX_NAME_BUNDLE_LEN`). */
export const MAX_NAME_BUNDLE_LEN = 1156

/** `sha256("pqsigner-name-key-v1" || chain_id[8 BE] || address[20])[..16]`
 *  — the on-disk index key, raw bytes. */
function shortKey(chainId: bigint, address20: Uint8Array): Uint8Array {
  const pre = concatBytes([SHORT_KEY_TAG, u64be(chainId), address20])
  return sha256(pre, 'bytes').subarray(0, SHORT_KEY_LEN)
}

class NamesDb {
  constructor(
    private readonly blob: Uint8Array,
    readonly header: DbHeader
  ) {}

  /** Leftmost entry-table row whose 16-byte short_key equals `key`, or
   *  -1. The table is sorted by short_key — binary search over the raw
   *  rows, same rationale as the ERC-20 DB (see `Erc20Db.findRow`). */
  private findRow(key: Uint8Array): number {
    return findSortedEntry(this.header.entryCnt, (row) => {
      const base = DB_HEADER_LEN + row * ENTRY_LEN + ENTRY_OFF_SHORT_KEY
      for (let j = 0; j < SHORT_KEY_LEN; j++) {
        const a = this.blob[base + j]!
        const b = key[j]!
        if (a !== b) return a < b ? -1 : 1
      }
      return 0
    })
  }

  /** Build the kind-8 bundle for `(chainId, address20)` using the same
   *  exact→wildcard two-phase lookup the device's resolver runs. Returns
   *  null on a miss — the caller then ships no bundle (the device renders
   *  the address as 40-hex). The emitted `chain_id` is the chain actually
   *  hit (0 for a wildcard), matching `build_names_bundle`. */
  buildBundle(chainId: number | bigint, address20: Uint8Array): Uint8Array | null {
    if (address20.length !== 20) throw new Error('address must be 20 bytes')
    const queried = BigInt(chainId)

    let hitChain = queried
    let leafIndex = this.findRow(shortKey(queried, address20))
    if (leafIndex < 0 && queried !== WILDCARD_CHAIN_ID) {
      hitChain = WILDCARD_CHAIN_ID
      leafIndex = this.findRow(shortKey(WILDCARD_CHAIN_ID, address20))
    }
    if (leafIndex < 0) return null

    const base = DB_HEADER_LEN + leafIndex * ENTRY_LEN
    const name = readPoolString(
      this.blob,
      this.header.poolOff + readU32Le(this.blob, base + ENTRY_OFF_NAME_OFF),
      LABEL
    )
    const proof = readProof(this.blob, this.header, leafIndex, LABEL)

    const bundleLen = 8 + 20 + 1 + name.length + 4 + 4 + proof.length
    if (bundleLen > MAX_NAME_BUNDLE_LEN) {
      throw new Error(
        `names db: assembled bundle ${bundleLen} B exceeds firmware cap ${MAX_NAME_BUNDLE_LEN} B`
      )
    }

    const out = new Uint8Array(bundleLen)
    let p = 0
    writeU64Le(out, p, hitChain)
    p += 8
    out.set(address20, p)
    p += 20
    out[p++] = name.length
    out.set(name, p)
    p += name.length
    writeU32Le(out, p, leafIndex)
    p += 4
    writeU32Le(out, p, this.header.proofDepth)
    p += 4
    out.set(proof, p)
    return out
  }
}

export function parseNamesDb(blob: Uint8Array): NamesDb {
  const header = parseDbHeader(blob, HEADER_MAGIC, 'NAMS', LABEL)
  checkDbSections(blob, header, ENTRY_LEN, LABEL)
  return new NamesDb(blob, header)
}

/** Load + parse the names DB blob. Idempotent; resolves to the same cached
 *  object on every call. Throws on header / size mismatch — callers swallow
 *  the throw and ship no name bundle (the device renders 40-hex). */
export const loadNamesDb = createDbLoader(NAMES_DB_URL, parseNamesDb)

export type { NamesDb }
