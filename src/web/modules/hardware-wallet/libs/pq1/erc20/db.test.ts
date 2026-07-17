// Round-trip test for the host-side ERC-20 metadata DB against the Python
// reference at sphincs_rust/tools/companion-stub/db_trailers.py.
// Both implementations consume the same `erc20_db.bin` and emit the inner
// kind-1 bundle (the bytes inside the `[u16 BE len]` envelope). The
// firmware's `companion_stub_erc20_verifies_against_on_device` round-trip
// keeps the Python side locked to the device verifier, so matching the
// Python output here proves our bundles Merkle-verify on-device.

import fs from 'fs'
import path from 'path'

import { hexToBytes } from '../transport/bytes'
import { parseErc20Db } from './db'

const DB_PATH = path.resolve(__dirname, '../../../../../public/pq1/erc20_db.bin')

// `python3 db_trailers.py erc20 --chain 8453 \
//   --contract 0x09bE1692ca16e06f536F0038fF11D1dA8524aDB1` (Telcoin on Base).
const TELCOIN_BASE = '0x09bE1692ca16e06f536F0038fF11D1dA8524aDB1'
const TELCOIN_BASE_REFERENCE_HEX =
  '052100000000000009be1692ca16e06f536f0038ff11d1da8524adb1020754656c636f' +
  '696e0354454c283400000f000000c032058354f4e0d2347e24012630639d7ebee890ac' +
  'd3949db6efc58903dec98330e294567fb740ac3a2c6b50f50e142a0e1c90d3139563fe' +
  '1a238327752e5012da1dbb1a6dc6cc0ddecc81092ea059956864b6c48925f4c94f4c28' +
  '8d92a1d48301f28c77a83dda59562ad9c4d439db2c620aed7c7bd88c5b8b518a68e541' +
  '51799f98422c5cd6a3f3a5b4d65b2ea2c45626b458906564fd1207b71bb7db99b49771' +
  '0b27f0db8fc554e7ebe600f6f0135d0940cf005317fd0be90a489f99bb5f42fdfc29fb' +
  'da08ddad46ebdc7f8273ae5f3a0601a988d1dd68b025182df7bf0e1c25ac3020209a8d' +
  '46d1b1d00738d6969e914d020527ca517cb70cf4660156f6dbf73b4871e3fc57b6c215' +
  'b724aa6d449fbae524d6b655b948cc4b6cf45b59291b1270fdfc219e9d3cbaafd04a30' +
  '960eecfae990fbc01719028dc94a7d797161581e3b33c9e4c8d0441b83c85a151973a6' +
  '651c5f62748167edc9d4682152adb5e4f706817c42d24479d5e388591b71cac3b04c1d' +
  'c42f4a766f309806be024a88b389a57c07157ad5ce8891aa1b90bbdb9247007257d105' +
  '0443a19d7a431a4fff6579a9c51a3e564843968a3a93914ec1cc1d41892ac8e82b31f3' +
  'c9d61b45dc8349fb67ce13e133ea7e54f7f4f057874720ff77e5b77221c427dd3d20d7' +
  '28027e4c'

describe('erc20 db', () => {
  let blob: Uint8Array

  beforeAll(() => {
    blob = new Uint8Array(fs.readFileSync(DB_PATH))
  })

  it('parses the header and reports the production proof depth (15)', () => {
    const db = parseErc20Db(blob)
    // ~18k tokens across 10 chains, Merkle depth 15 (17,944 after the
    // c0471daa impersonator purge + 4a9323af inactive-token prune +
    // 6a6c5bac full-metadata verify dropped 8 non-contracts).
    expect(db.header.entryCnt).toBeGreaterThan(15_000)
    expect(db.header.proofDepth).toBe(15)
  })

  it('builds the Telcoin/Base bundle byte-for-byte with the Python reference', () => {
    const db = parseErc20Db(blob)
    const bundle = db.buildBundle(8453, hexToBytes(TELCOIN_BASE))
    expect(bundle).not.toBeNull()
    expect(toHex(bundle!)).toBe(TELCOIN_BASE_REFERENCE_HEX)

    // Spell out the fields a wire-format regression would break.
    expect(bundle!.subarray(0, 8)).toEqual(hexToBytes('0521000000000000')) // chain_id 8453 LE
    expect(bundle![28]).toBe(2) // decimals
    expect(bundle![29]).toBe(7) // name_len
    expect(new TextDecoder().decode(bundle!.subarray(30, 37))).toBe('Telcoin')
    expect(bundle![37]).toBe(3) // symbol_len
    expect(new TextDecoder().decode(bundle!.subarray(38, 41))).toBe('TEL')
    // leaf_index u32 LE = 0x00003428, proof_depth u32 LE = 15, proof = 15*32.
    expect(bundle!.subarray(41, 45)).toEqual(hexToBytes('28340000'))
    expect(bundle!.subarray(45, 49)).toEqual(hexToBytes('0f000000'))
    expect(bundle!.length).toBe(49 + 15 * 32)
  })

  it('returns null for a token absent from the DB (safe degrade)', () => {
    const db = parseErc20Db(blob)
    const absent = hexToBytes('0x000000000000000000000000000000000000dead')
    expect(db.buildBundle(8453, absent)).toBeNull()
  })

  it('keys by (chain_id, contract): a Base token is not found on a different chain', () => {
    const db = parseErc20Db(blob)
    // Telcoin's Base leaf must not resolve under an arbitrary other chain id
    // unless that chain genuinely carries the same address (cross-chain
    // keying gotcha from 7a90f7ca). Use a chain id with no such entry.
    expect(db.buildBundle(999999, hexToBytes(TELCOIN_BASE))).toBeNull()
  })
})

function toHex(b: Uint8Array): string {
  let s = ''
  for (let i = 0; i < b.length; i++) s += b[i]!.toString(16).padStart(2, '0')
  return s
}
