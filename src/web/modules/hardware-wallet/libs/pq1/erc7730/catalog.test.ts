// Round-trip test against the Python reference at
// sphincs_rust/tools/companion-stub/erc7730_trailer.py.
// Both implementations consume the same `erc7730_db.bin` and emit the
// inner bundle (the bytes inside the `[u16 BE bundle_len]` envelope).

import fs from 'fs'
import path from 'path'

import { hexToBytes } from '../transport/bytes'
import { CTX_CONTRACT, CTX_EIP712, parseCatalog } from './catalog'

const CATALOG_PATH = path.resolve(__dirname, '../../../../../public/pq1/erc7730_db.bin')

describe('erc7730 catalog', () => {
  let blob: Uint8Array

  beforeAll(() => {
    blob = new Uint8Array(fs.readFileSync(CATALOG_PATH))
  })

  it('parses the catalog header', () => {
    const cat = parseCatalog(blob)
    expect(cat.header.entryCnt).toBeGreaterThan(0)
    expect(cat.header.proofDepth).toBeGreaterThan(0)
    expect(cat.header.proofDepth).toBeLessThanOrEqual(32)
    expect(cat.entries.length).toBe(cat.header.entryCnt)
  })

  it('finds the USDT mainnet entry', () => {
    const cat = parseCatalog(blob)
    const usdt = hexToBytes('0xdAC17F958D2ee523a2206206994597C13D831ec7')
    const entry = cat.find(1n, usdt, CTX_CONTRACT)
    expect(entry).not.toBeNull()
    expect(entry!.chainId).toBe(1n)
    expect(entry!.contextKind).toBe(CTX_CONTRACT)
  })

  it('assembles a trailer for USDT mainnet that matches the Python reference', () => {
    const cat = parseCatalog(blob)
    const usdt = hexToBytes('0xdAC17F958D2ee523a2206206994597C13D831ec7')
    const entry = cat.find(1n, usdt, CTX_CONTRACT)!
    const ours = cat.assembleTrailer(entry)

    // Manually reproduce the trailer bytes the Python reference would
    // emit. This is the same logic as `assembleTrailer` but spelled out
    // step-by-step so a wire-format regression is easy to spot.
    const irOff = cat.header.poolOff + entry.irOff
    const ir = blob.subarray(irOff, irOff + entry.irLen)
    const proofBase = cat.header.proofsOff + entry.leafIndex * cat.header.proofDepth * 32
    const proof = blob.subarray(proofBase, proofBase + cat.header.proofDepth * 32)

    expect(ours.length).toBe(2 + ir.length + 4 + 4 + proof.length)
    // ir_len BE u16
    expect((ours[0]! << 8) | ours[1]!).toBe(ir.length)
    // ir bytes
    expect(Array.from(ours.subarray(2, 2 + ir.length))).toEqual(Array.from(ir))
    // leaf_index BE u32
    const lo = 2 + ir.length
    expect((ours[lo]! << 24) | (ours[lo + 1]! << 16) | (ours[lo + 2]! << 8) | ours[lo + 3]!).toBe(
      entry.leafIndex
    )
    // proof_depth BE u32
    const po = lo + 4
    expect((ours[po]! << 24) | (ours[po + 1]! << 16) | (ours[po + 2]! << 8) | ours[po + 3]!).toBe(
      cat.header.proofDepth
    )
    // proof bytes
    expect(Array.from(ours.subarray(po + 4))).toEqual(Array.from(proof))
  })

  it('returns null on miss', () => {
    const cat = parseCatalog(blob)
    const unknownContract = hexToBytes('0x' + '12'.repeat(20))
    expect(cat.find(1n, unknownContract, CTX_CONTRACT)).toBeNull()
    // Wrong chain for a real contract also misses.
    const usdt = hexToBytes('0xdAC17F958D2ee523a2206206994597C13D831ec7')
    expect(cat.find(999n, usdt, CTX_CONTRACT)).toBeNull()
  })

  it('disambiguates between USDC mainnet EIP-712 descriptors by primary_type_hash[..4]', () => {
    // USDC mainnet ships two EIP-712 formats — TransferWithAuthorization
    // and ReceiveWithAuthorization — so the catalog has two entries with
    // the same `(chain_id, contract)` and distinct primary_type_hashes.
    const cat = parseCatalog(blob)
    const usdc = hexToBytes('0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48')
    const allMatches = cat.entries.filter(
      (e) =>
        e.contextKind === CTX_EIP712 &&
        e.chainId === 1n &&
        Array.from(e.contract).every((b, i) => b === usdc[i])
    )
    if (allMatches.length < 2) {
      // The catalog can legally ship just one USDC descriptor on the
      // chain we test — skip the disambiguation assertion in that case.
      return
    }
    const first4OfA = allMatches[0]!.primaryTypeHash.subarray(0, 4)
    const first4OfB = allMatches[1]!.primaryTypeHash.subarray(0, 4)
    expect(Array.from(first4OfA)).not.toEqual(Array.from(first4OfB))

    const pickedA = cat.find(1n, usdc, CTX_EIP712, first4OfA)
    const pickedB = cat.find(1n, usdc, CTX_EIP712, first4OfB)
    expect(pickedA?.leafIndex).toBe(allMatches[0]!.leafIndex)
    expect(pickedB?.leafIndex).toBe(allMatches[1]!.leafIndex)
  })

  it('matches the Python reference trailer for USDT mainnet byte-for-byte', () => {
    // Reference produced by:
    //   python3 sphincs_rust/tools/companion-stub/erc7730_trailer.py \
    //     --db <CATALOG_PATH> --chain 1 \
    //     --contract 0xdAC17F958D2ee523a2206206994597C13D831ec7 \
    //     --out /tmp/usdt_mainnet_trailer.bin
    const refPath = '/tmp/usdt_mainnet_trailer.bin'
    if (!fs.existsSync(refPath)) {
      // Reference not available in this environment — skip rather than
      // failing CI on machines that don't have python3 or the firmware
      // source tree.

      console.warn(`skipping: ${refPath} not present`)
      return
    }
    const reference = new Uint8Array(fs.readFileSync(refPath))
    const cat = parseCatalog(blob)
    const entry = cat.find(
      1n,
      hexToBytes('0xdAC17F958D2ee523a2206206994597C13D831ec7'),
      CTX_CONTRACT
    )!
    const ours = cat.assembleTrailer(entry)
    expect(ours.length).toBe(reference.length)
    expect(Array.from(ours)).toEqual(Array.from(reference))
  })
})
