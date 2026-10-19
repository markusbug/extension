// Host-side curated function-selector DB: loader, lookup, and the trailer
// bundle the device uses to name a function it otherwise blind-signs.
//
// The device ships only the 32-byte `SELECTOR_DB_ROOT` and Merkle-verifies
// every companion-supplied bundle against it, then checks
// `bundle.selector == calldata[0..4]` before showing the text signature (and,
// for the signatures its typed-call parser understands, the decoded
// arguments) on the blind-sign pages. A withheld bundle degrades to the
// selector hex; a forged one fails the Merkle check.
//
// Port of the firmware's `tx/src/selectors/bundle.rs` wire format and the
// on-disk layout in `shared/src/db_format.rs` (`b"SEL4"`). Header framing /
// pool accessors / loader come from `../db/common.ts`.
//
// Bundle wire layout (`tx/src/selectors/bundle.rs`):
//
//   selector      [u8; 4]
//   text_sig_len  u8          (1..=63)
//   text_sig      [u8; text_sig_len]   printable ASCII
//   leaf_index    u32 LE
//   proof_depth   u32 LE      (<= 32)
//   proof         [u8; proof_depth * 32]

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
  type DbHeader
} from '../db/common'

const SELECTORS_DB_URL = 'pq1/selectors_db.bin'

const HEADER_MAGIC = new Uint8Array([0x53, 0x45, 0x4c, 0x34]) // "SEL4"
const LABEL = 'selectors db'

// Entry table: 8 bytes per row, sorted by selector.
const ENTRY_LEN = 8
const ENTRY_OFF_TEXT_OFF = 4 // u32 LE (offset into the string pool)
const SELECTOR_LEN = 4

/** Firmware cap on the text signature (`SELECTOR_TEXT_SIG_MAX_LEN`). */
const TEXT_SIG_MAX_LEN = 63

/** Firmware cap on one bundle (`MAX_SELECTOR_BUNDLE_LEN`). */
export const MAX_SELECTOR_BUNDLE_LEN = 4 + 1 + TEXT_SIG_MAX_LEN + 4 + 4 + 32 * 32

class SelectorsDb {
  constructor(
    private readonly blob: Uint8Array,
    readonly header: DbHeader
  ) {}

  private findRow(selector: Uint8Array): number {
    return findSortedEntry(this.header.entryCnt, (row) => {
      const base = DB_HEADER_LEN + row * ENTRY_LEN
      for (let j = 0; j < SELECTOR_LEN; j++) {
        const a = this.blob[base + j]!
        const b = selector[j]!
        if (a !== b) return a < b ? -1 : 1
      }
      return 0
    })
  }

  /** The text signature for `selector` (e.g. `transfer(address,uint256)`),
   *  or null on a miss. */
  textSignature(selector: Uint8Array): string | null {
    const row = selector.length === SELECTOR_LEN ? this.findRow(selector) : -1
    if (row < 0) return null
    return String.fromCharCode(...this.#text(row))
  }

  #text(row: number): Uint8Array {
    const base = DB_HEADER_LEN + row * ENTRY_LEN
    return readPoolString(
      this.blob,
      this.header.poolOff + readU32Le(this.blob, base + ENTRY_OFF_TEXT_OFF),
      LABEL
    )
  }

  /** Build the curated selector bundle for the first 4 bytes of `calldata`,
   *  or null when the calldata is shorter than a selector or the selector
   *  isn't in the DB. */
  buildBundle(calldata: Uint8Array): Uint8Array | null {
    if (calldata.length < SELECTOR_LEN) return null
    const selector = calldata.subarray(0, SELECTOR_LEN)
    const leafIndex = this.findRow(selector)
    if (leafIndex < 0) return null
    const text = this.#text(leafIndex)
    if (text.length === 0 || text.length > TEXT_SIG_MAX_LEN) {
      throw new Error(`${LABEL}: text signature of leaf ${leafIndex} has length ${text.length}`)
    }
    const proof = readProof(this.blob, this.header, leafIndex, LABEL)

    const out = new Uint8Array(SELECTOR_LEN + 1 + text.length + 4 + 4 + proof.length)
    let p = 0
    out.set(selector, p)
    p += SELECTOR_LEN
    out[p++] = text.length
    out.set(text, p)
    p += text.length
    writeU32Le(out, p, leafIndex)
    p += 4
    writeU32Le(out, p, this.header.proofDepth)
    p += 4
    out.set(proof, p)
    return out
  }
}

export function parseSelectorsDb(blob: Uint8Array): SelectorsDb {
  const header = parseDbHeader(blob, HEADER_MAGIC, 'SEL4', LABEL)
  checkDbSections(blob, header, ENTRY_LEN, LABEL)
  return new SelectorsDb(blob, header)
}

/** Load + parse the selectors DB blob. Idempotent; resolves to the same
 *  cached object on every call. Throws on header / size mismatch — callers
 *  swallow the throw and ship no selector bundle (the device then shows the
 *  raw selector). */
export const loadSelectorsDb = createDbLoader(SELECTORS_DB_URL, parseSelectorsDb)

export type { SelectorsDb }
