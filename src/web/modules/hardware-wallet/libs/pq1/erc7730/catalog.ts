// ERC-7730 catalog blob parser, lookup, and trailer assembler.
//
// TypeScript port of `tools/companion-stub/erc7730_trailer.py` against the
// `clear-sign-rebased` firmware branch.
//
// What this does:
//   1. Loads `pq1/erc7730_db.bin` from extension assets via
//      `chrome.runtime.getURL` (same pattern as the ERC-20 metadata DB —
//      see ../erc20/db.ts).
//   2. Parses the 32-byte header and N × 72-byte entry table.
//   3. Looks up the descriptor for a given (chainId, contract) pair —
//      `CTX_CONTRACT` for `eth_sendTransaction`-style flows and
//      `CTX_EIP712` for typed-data flows.
//   4. Assembles the on-the-wire bundle the firmware's
//      `pqsigner_erc7730::bundle::verify_erc7730_bundle` consumes:
//
//        ir_len(u16 BE) || ir || leaf_index(u32 BE) || proof_depth(u32 BE) || proof
//
// The caller wraps the bundle as `[u16 BE bundle_len][bundle]` when
// splicing into a sign-input wire payload (see signRequest.ts and
// offchain.ts kind=2).

import { ERC7730_MAX_TRAILER_LEN } from '../config'
import { isSameBytes } from '../transport/bytes'
import {
  checkDbSections,
  createDbLoader,
  DB_HEADER_LEN,
  parseDbHeader,
  readU32Le,
  readU64Le,
  type DbHeader
} from '../db/common'

const CATALOG_URL = 'pq1/erc7730_db.bin'

const HEADER_MAGIC = new Uint8Array([0x50, 0x37, 0x33, 0x30]) // "P730"
const LABEL = 'erc7730 catalog'
const ENTRY_LEN = 72

export const CTX_CONTRACT = 0x01
export const CTX_EIP712 = 0x02

/** Decoded catalog entry. Fields mirror the on-disk layout described in
 *  the firmware doc §3 (companion-erc7730-implementation-guide.md). */
export interface CatalogEntry {
  /** Position in the Merkle tree (also the row index into the proofs pool). */
  leafIndex: number
  chainId: bigint
  contract: Uint8Array // 20 bytes
  primaryTypeHash: Uint8Array // 32 bytes (zero for CTX_CONTRACT)
  contextKind: number // CTX_CONTRACT (1) or CTX_EIP712 (2)
  irOff: number
  irLen: number
}

/** Common DB header (`poolOff` is the catalog's `ir_pool_off`) plus the
 *  catalog-specific fields at offsets 8 / 20. */
interface CatalogHeader extends DbHeader {
  flags: number
  irPoolSize: number
}

class Catalog {
  constructor(
    private readonly blob: Uint8Array,
    readonly header: CatalogHeader,
    readonly entries: CatalogEntry[]
  ) {}

  /** First entry matching `(chainId, contract, contextKind)`. Returns
   *  null on miss — the caller MUST then ship the request without a
   *  trailer; the firmware silently falls back to blind-sign.
   *
   *  When multiple entries share `(chainId, contract, contextKind)` —
   *  e.g. USDC on mainnet has separate descriptors for
   *  `TransferWithAuthorization` and `ReceiveWithAuthorization` — pass
   *  `primaryTypeHash4` (the first 4 bytes of `keccak256(typeString)`)
   *  to disambiguate. The catalog stores the full 32-byte hash; the
   *  firmware only reads the first 4 (§4 of the firmware doc). When
   *  omitted, returns the first match. */
  find(
    chainId: bigint | number,
    contract: Uint8Array,
    contextKind: number,
    primaryTypeHash4?: Uint8Array
  ): CatalogEntry | null {
    if (contract.length !== 20) return null
    const cid = typeof chainId === 'bigint' ? chainId : BigInt(chainId)
    let firstMatch: CatalogEntry | null = null
    // Linear scan — at most ~hundreds of entries; doc § 4 explicitly
    // calls this out as acceptable. The catalog is sorted by
    // (chain_id, contract, primary_type_hash, context_kind) so we could
    // binary-search, but the gain is dwarfed by USB latency.
    for (const e of this.entries) {
      if (e.contextKind !== contextKind) continue
      if (e.chainId !== cid) continue
      if (!isSameBytes(e.contract, contract)) continue
      if (primaryTypeHash4) {
        if (primaryTypeHash4.length < 4) return null
        if (
          e.primaryTypeHash[0] === primaryTypeHash4[0] &&
          e.primaryTypeHash[1] === primaryTypeHash4[1] &&
          e.primaryTypeHash[2] === primaryTypeHash4[2] &&
          e.primaryTypeHash[3] === primaryTypeHash4[3]
        ) {
          return e
        }
      } else if (firstMatch === null) {
        firstMatch = e
      }
    }
    return firstMatch
  }

  /** Build the `[ir_len BE u16][ir][leaf_index BE u32][proof_depth BE u32][proof]`
   *  bundle for `entry`. The caller wraps it in the `[u16 BE bundle_len]`
   *  envelope on the way out. */
  assembleTrailer(entry: CatalogEntry): Uint8Array {
    const { proofDepth, proofsOff, poolOff } = this.header
    const irStart = poolOff + entry.irOff
    const irEnd = irStart + entry.irLen
    if (irEnd > this.blob.length) {
      throw new Error(`erc7730 catalog: IR slice out of range for leaf ${entry.leafIndex}`)
    }
    const proofBase = proofsOff + entry.leafIndex * proofDepth * 32
    const proofEnd = proofBase + proofDepth * 32
    if (proofEnd > this.blob.length) {
      throw new Error(`erc7730 catalog: proof slice out of range for leaf ${entry.leafIndex}`)
    }
    const ir = this.blob.subarray(irStart, irEnd)
    const proof = this.blob.subarray(proofBase, proofEnd)

    const bundleLen = 2 + ir.length + 4 + 4 + proof.length
    if (bundleLen > ERC7730_MAX_TRAILER_LEN) {
      // Catalog itself is malformed if we land here — the firmware
      // bounds `ERC7730_MAX_TRAILER_LEN = 5130 B`.
      throw new Error(
        `erc7730 catalog: assembled bundle ${bundleLen} B exceeds firmware cap ${ERC7730_MAX_TRAILER_LEN} B`
      )
    }

    const out = new Uint8Array(bundleLen)
    let p = 0
    out[p++] = (ir.length >> 8) & 0xff
    out[p++] = ir.length & 0xff
    out.set(ir, p)
    p += ir.length
    out[p++] = (entry.leafIndex >>> 24) & 0xff
    out[p++] = (entry.leafIndex >>> 16) & 0xff
    out[p++] = (entry.leafIndex >>> 8) & 0xff
    out[p++] = entry.leafIndex & 0xff
    out[p++] = (proofDepth >>> 24) & 0xff
    out[p++] = (proofDepth >>> 16) & 0xff
    out[p++] = (proofDepth >>> 8) & 0xff
    out[p++] = proofDepth & 0xff
    out.set(proof, p)
    return out
  }
}

export function parseCatalog(blob: Uint8Array): Catalog {
  const header: CatalogHeader = {
    ...parseDbHeader(blob, HEADER_MAGIC, 'P730', LABEL),
    flags: readU32Le(blob, 8),
    irPoolSize: readU32Le(blob, 20)
  }
  checkDbSections(blob, header, ENTRY_LEN, LABEL)

  const entries: CatalogEntry[] = []
  for (let i = 0; i < header.entryCnt; i++) {
    const base = DB_HEADER_LEN + i * ENTRY_LEN
    entries.push({
      leafIndex: i,
      chainId: readU64Le(blob, base),
      contract: blob.slice(base + 8, base + 28),
      primaryTypeHash: blob.slice(base + 28, base + 60),
      contextKind: blob[base + 60]!,
      irOff: readU32Le(blob, base + 64),
      irLen: readU32Le(blob, base + 68)
    })
  }

  return new Catalog(blob, header, entries)
}

/** Load and parse the catalog blob. Idempotent; resolves to the same
 *  cached object on every subsequent call. Throws on header / size
 *  mismatch — the caller in broadcast.ts swallows the throw (logs a
 *  warning) and ships the sign request without an ERC-7730 trailer,
 *  matching the "fail-open to blind-sign" contract from doc §3. */
export const loadErc7730Catalog = createDbLoader(CATALOG_URL, parseCatalog)

export type { Catalog }
