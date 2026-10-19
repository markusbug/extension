// Tests the selectors DB loader and bundle builder against the shipped
// `selectors_db.bin`. Every bundle's Merkle proof is walked up to the root
// the firmware pins as `SELECTOR_DB_ROOT` (production build), so a stale or
// e2e blob fails here instead of on the device.

import fs from 'fs'
import path from 'path'
import { sha256 } from 'viem'

import { readU32Le } from '../db/common'
import { bytesToHex, concatBytes, hexToBytes } from '../transport/bytes'
import { MAX_SELECTOR_BUNDLE_LEN, parseSelectorsDb } from './db'

jest.mock('@common/config/analytics/CrashAnalytics.web', () => ({
  captureException: jest.fn()
}))

/** `SELECTOR_DB_ROOT` (not e2e) in `sphincs_rust/secure/src/db_roots.rs`. */
const FIRMWARE_SELECTOR_DB_ROOT = '751caf5205a4ff5901ab6478af91ff36338f874b868378c610b693947456e46a'

const BLOB_PATH = path.resolve(__dirname, '../../../../../public/pq1/selectors_db.bin')
const db = parseSelectorsDb(new Uint8Array(fs.readFileSync(BLOB_PATH)))

/** Walk a bundle's proof to the root, exactly as `tx/src/erc20/merkle.rs`
 *  does: leaf `sha256(0x00 || selector || len || text)`, nodes
 *  `sha256(0x01 || left || right)`, bit i of the leaf index picks the side. */
function rootOf(bundle: Uint8Array): string {
  const textLen = bundle[4]!
  const canonical = bundle.subarray(0, 5 + textLen)
  let p = 5 + textLen
  let index = readU32Le(bundle, p)
  const depth = readU32Le(bundle, p + 4)
  p += 8
  let node = sha256(concatBytes([new Uint8Array([0]), canonical]), 'bytes')
  for (let level = 0; level < depth; level++) {
    const sibling = bundle.subarray(p + level * 32, p + level * 32 + 32)
    const pair = index & 1 ? [sibling, node] : [node, sibling]
    node = sha256(concatBytes([new Uint8Array([1]), ...pair]), 'bytes')
    index >>>= 1
  }
  return bytesToHex(node)
}

describe('selectors db', () => {
  it('builds a safeTransferFrom bundle that proves to the firmware root', () => {
    const bundle = db.buildBundle(hexToBytes('0x42842e0e' + '00'.repeat(96)))!
    expect(bundle.length).toBeLessThanOrEqual(MAX_SELECTOR_BUNDLE_LEN)
    expect(db.textSignature(hexToBytes('0x42842e0e'))).toBe(
      'safeTransferFrom(address,address,uint256)'
    )
    expect(rootOf(bundle)).toBe(FIRMWARE_SELECTOR_DB_ROOT)
  })

  it('proves the first and last entries to the same root', () => {
    for (const row of [0, db.header.entryCnt - 1]) {
      const blob = new Uint8Array(fs.readFileSync(BLOB_PATH))
      const selector = blob.subarray(32 + row * 8, 32 + row * 8 + 4)
      expect(rootOf(db.buildBundle(selector)!)).toBe(FIRMWARE_SELECTOR_DB_ROOT)
    }
  })

  it('returns null on a miss or calldata shorter than a selector', () => {
    expect(db.buildBundle(hexToBytes('0xffffffff'))).toBeNull()
    expect(db.buildBundle(hexToBytes('0x4284'))).toBeNull()
  })
})
