// Shared infrastructure for the host-side Merkle DB blobs (ERC-20
// metadata, address names, ERC-7730 catalog). All three ship the same
// 32-byte little-endian header layout from `shared/src/db_format.rs`,
// the same string-pool / proofs-pool framing, and the same single-flight
// load-once semantics — one implementation here so a loader or
// bounds-check fix can't silently apply to only one of the copies.

import { isSameBytes } from '../transport/bytes'

export const DB_HEADER_LEN = 32
const SUPPORTED_VERSION = 1

// ── Little-endian readers/writers (blob integers are LE) ────────────

export function readU32Le(b: Uint8Array, off: number): number {
  return (
    (b[off]! |
      ((b[off + 1]! << 8) >>> 0) |
      ((b[off + 2]! << 16) >>> 0) |
      ((b[off + 3]! << 24) >>> 0)) >>>
    0
  )
}

export function readU64Le(b: Uint8Array, off: number): bigint {
  let v = 0n
  for (let i = 7; i >= 0; i--) v = (v << 8n) | BigInt(b[off + i]!)
  return v
}

export function writeU32Le(b: Uint8Array, off: number, v: number): void {
  b[off] = v & 0xff
  b[off + 1] = (v >>> 8) & 0xff
  b[off + 2] = (v >>> 16) & 0xff
  b[off + 3] = (v >>> 24) & 0xff
}

export function writeU64Le(b: Uint8Array, off: number, v: bigint): void {
  let x = v
  for (let i = 0; i < 8; i++) {
    b[off + i] = Number(x & 0xffn)
    x >>= 8n
  }
}

// ── Header ──────────────────────────────────────────────────────────

/** The common subset of the 32-byte DB header. The ERC-7730 catalog's
 *  extra fields (`flags` at 8, `ir_pool_size` at 20) are read separately
 *  by its parser; `poolOff` is its `ir_pool_off`. */
export interface DbHeader {
  version: number
  entryCnt: number
  poolOff: number
  proofDepth: number
  proofsOff: number
}

/** Parse + validate the common header: magic, supported version, sane
 *  proof depth. `label` prefixes every error (e.g. 'erc20 db'). */
export function parseDbHeader(
  blob: Uint8Array,
  magic: Uint8Array,
  magicName: string,
  label: string
): DbHeader {
  if (blob.length < DB_HEADER_LEN) {
    throw new Error(`${label} too short: ${blob.length} < ${DB_HEADER_LEN}`)
  }
  if (!isSameBytes(blob.subarray(0, 4), magic)) {
    throw new Error(`${label}: bad magic (expected ${magicName})`)
  }
  const header: DbHeader = {
    version: readU32Le(blob, 4),
    entryCnt: readU32Le(blob, 12),
    poolOff: readU32Le(blob, 16),
    proofDepth: readU32Le(blob, 24),
    proofsOff: readU32Le(blob, 28)
  }
  if (header.version !== SUPPORTED_VERSION) {
    throw new Error(`${label}: unsupported version ${header.version}`)
  }
  if (header.proofDepth === 0 || header.proofDepth > 32) {
    throw new Error(`${label}: bad proof_depth ${header.proofDepth}`)
  }
  return header
}

/** The entry table and the proofs section must fit inside the blob —
 *  checked once at parse time so per-lookup reads can't run off the end. */
export function checkDbSections(
  blob: Uint8Array,
  header: DbHeader,
  entryLen: number,
  label: string
): void {
  const entriesEnd = DB_HEADER_LEN + header.entryCnt * entryLen
  if (entriesEnd > blob.length) {
    throw new Error(`${label}: truncated entry table (need ${entriesEnd} B, have ${blob.length})`)
  }
  const proofsEnd = header.proofsOff + header.entryCnt * header.proofDepth * 32
  if (proofsEnd > blob.length) {
    throw new Error(`${label}: truncated proofs section (need ${proofsEnd} B, have ${blob.length})`)
  }
}

// ── Pool accessors ──────────────────────────────────────────────────

/** `[u8 len][len bytes]` string at `at` in the string pool. */
export function readPoolString(blob: Uint8Array, at: number, label: string): Uint8Array {
  if (at >= blob.length) throw new Error(`${label}: pool string offset out of range`)
  const n = blob[at]!
  const start = at + 1
  const end = start + n
  if (end > blob.length) throw new Error(`${label}: pool string slice out of range`)
  return blob.subarray(start, end)
}

/** The `proof_depth * 32`-byte Merkle proof for `leafIndex`. */
export function readProof(
  blob: Uint8Array,
  header: DbHeader,
  leafIndex: number,
  label: string
): Uint8Array {
  const span = header.proofDepth * 32
  const base = header.proofsOff + leafIndex * span
  const end = base + span
  if (end > blob.length) {
    throw new Error(`${label}: proof slice out of range for leaf ${leafIndex}`)
  }
  return blob.subarray(base, end)
}

// ── Binary search over a sorted fixed-width entry table ─────────────

/** Leftmost row whose key equals the probe, or -1. `compare(rowIdx)`
 *  must return the row's ordering relative to the probe (<0 row-before,
 *  0 match, >0 row-after) against the table's sort order. Lower-bound
 *  semantics keep the first of any duplicate rows, matching the
 *  first-wins contract of the old eagerly-built index maps. */
export function findSortedEntry(entryCnt: number, compare: (rowIdx: number) => number): number {
  let lo = 0
  let hi = entryCnt
  while (lo < hi) {
    const mid = (lo + hi) >>> 1
    if (compare(mid) < 0) lo = mid + 1
    else hi = mid
  }
  return lo < entryCnt && compare(lo) === 0 ? lo : -1
}

// ── Single-flight loader ────────────────────────────────────────────

/** Build a load-once function for a DB blob shipped in extension assets.
 *  Idempotent: resolves to the same parsed object on every subsequent
 *  call; a failed load clears the in-flight slot so the next call can
 *  retry. Throws on fetch / header / size mismatch — callers swallow the
 *  throw and ship the request without the bundle (fail-open contract). */
export function createDbLoader<T>(url: string, parse: (blob: Uint8Array) => T): () => Promise<T> {
  let cached: T | null = null
  let loading: Promise<T> | null = null

  return async () => {
    if (cached) return cached
    if (loading) return loading

    loading = (async () => {
      let resolvedUrl: string
      try {
        resolvedUrl = chrome.runtime.getURL(url)
      } catch {
        // Outside a chrome-extension context (tests, isolated builds):
        // fall back to the relative path and let fetch decide.
        resolvedUrl = url
      }
      const resp = await fetch(resolvedUrl)
      if (!resp.ok) throw new Error(`failed to load ${url} (${resp.status})`)
      const blob = new Uint8Array(await resp.arrayBuffer())
      const parsed = parse(blob)
      cached = parsed
      return parsed
    })()

    try {
      return await loading
    } finally {
      loading = null
    }
  }
}
