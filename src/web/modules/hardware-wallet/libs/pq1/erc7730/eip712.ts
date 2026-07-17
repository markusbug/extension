// EIP-712 → ERC-7730 kind=2 payload prep.
//
// Computes the three pieces the firmware's kind=2 codepath needs:
//   1. `domain_separator = keccak256(EIP712Domain typehash || encode(domain))`
//   2. `primary_type_hash = keccak256(encodeType(types, primaryType))`
//   3. `encoded_data       = encodeAbiParameters(types[primaryType], message)`
//
// Per §6.3 of the firmware doc, `encoded_data` is the STRUCT BODY ONLY
// (no typehash prefix). The firmware concatenates the typehash itself.
//
// Important: viem's `encodeAbiParameters` does NOT apply EIP-712 dynamic-
// field rules (bytes/string get keccak256-hashed; nested structs get
// hashStruct'd; dynamic arrays get keccak256 of concatenated elements).
// Every descriptor in the firmware seed corpus uses only static field
// types (address, uintN, intN, bytesN, bool) so the ABI encoding and
// EIP-712 struct encoding coincide. We assert that statically below; the
// caller falls back to kind=0 (raw32) when the assertion fails.

import { encodeAbiParameters, hashDomain, keccak256, toBytes } from 'viem'

import { hexToBytes } from '../transport/bytes'

export type TypedDataDomain = {
  name?: string
  version?: string
  chainId?: number | bigint
  verifyingContract?: `0x${string}`
  salt?: `0x${string}`
}

export type TypedDataField = { name: string; type: string }
export type TypedDataTypes = Record<string, readonly TypedDataField[]>

export interface Erc7730Eip712Pieces {
  domainSeparator: Uint8Array
  primaryTypeHash: Uint8Array
  encodedData: Uint8Array
}

/** Parse the decimal suffix of a sized type (`uint256` → 256). Returns
 *  null on a non-numeric or leading-zero suffix so `uint0x8`, `uint08`
 *  and friends are rejected exactly like the ABI grammar rejects them. */
function parseSizeSuffix(suffix: string): number | null {
  if (suffix.length === 0 || suffix.length > 3) return null
  if (suffix[0] === '0') return null
  let n = 0
  for (let i = 0; i < suffix.length; i++) {
    const c = suffix.charCodeAt(i)
    if (c < 0x30 || c > 0x39) return null
    n = n * 10 + (c - 0x30)
  }
  return n
}

/** Field types we know we can encode with `encodeAbiParameters` and have
 *  the result still be a valid EIP-712 struct body: `address`, `bool`,
 *  `uintN`/`intN` (N a multiple of 8, ≤ 256, or omitted) and `bytesN`
 *  (1 ≤ N ≤ 32). Everything else — dynamic `bytes`/`string`, arrays,
 *  nested structs — triggers the kind=0 fallback in the signer. A miss
 *  here silently reroutes a message to blind-sign raw32, so the rules
 *  are spelled out explicitly rather than packed into a regex. */
function isStaticAtomicType(t: string): boolean {
  if (t === 'address' || t === 'bool') return true
  if (t === 'uint' || t === 'int') return true
  if (t.startsWith('uint') || t.startsWith('int')) {
    const bits = parseSizeSuffix(t.slice(t.startsWith('uint') ? 4 : 3))
    return bits !== null && bits % 8 === 0 && bits <= 256
  }
  if (t.startsWith('bytes')) {
    const size = parseSizeSuffix(t.slice(5))
    return size !== null && size <= 32
  }
  return false
}

/** Build the (`domainSeparator`, `primaryTypeHash`, `encodedData`)
 *  triple for the firmware's kind=2 sign payload. Returns `null` when
 *  the message uses field types our encoder can't safely round-trip
 *  (dynamic types, nested structs, arrays) — the caller routes the
 *  sign through kind=0 (raw32) with the EIP-712 final hash instead. */
export function buildErc7730Eip712Pieces(args: {
  domain: TypedDataDomain
  types: TypedDataTypes
  primaryType: string
  message: Record<string, unknown>
}): Erc7730Eip712Pieces | null {
  const fields = args.types[args.primaryType]
  if (!fields) {
    // Malformed input — `hashTypedData` would have thrown too.
    return null
  }
  for (const f of fields) {
    if (!isStaticAtomicType(f.type)) return null
  }

  // ── 1. domainSeparator ────────────────────────────────────────
  // `hashDomain` returns `0x${string}` of
  // `keccak256(EIP712Domain typehash || encode(domain))`.
  const dsepHex = hashDomain({
    domain: args.domain as any,
    types: args.types as any
  })
  const domainSeparator = hexToBytes(dsepHex)

  // ── 2. primaryTypeHash ────────────────────────────────────────
  // EIP-712 type string with no whitespace. For the static-only
  // single-struct case this is exactly `Foo(type1 name1,type2 name2,...)`.
  const typeString = `${args.primaryType}(${fields.map((f) => `${f.type} ${f.name}`).join(',')})`
  const primaryTypeHash = hexToBytes(keccak256(toBytes(typeString)))

  // ── 3. encodedData ────────────────────────────────────────────
  // viem.encodeAbiParameters([{type, name}, ...], [values...]) with
  // values ordered to match the field declaration order. Throw-checked
  // above so every field is a static atomic type — ABI and EIP-712
  // struct encoding coincide for these.
  const abiParams = fields.map((f) => ({ name: f.name, type: f.type }))
  const valuesInOrder = fields.map((f) => {
    const v = (args.message as Record<string, unknown>)[f.name]
    if (v === undefined) {
      throw new Error(`buildErc7730Eip712Pieces: message missing field ${f.name}`)
    }
    return v as any
  })
  const encodedHex = encodeAbiParameters(abiParams as any, valuesInOrder)
  const encodedData = hexToBytes(encodedHex)

  return { domainSeparator, primaryTypeHash, encodedData }
}
