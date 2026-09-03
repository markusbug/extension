# PQ1 hardware wallet

PQ1 is a post-quantum hardware wallet. It signs with SPHINCS+ (a hash-based,
quantum-resistant signature scheme) instead of ECDSA, talks to the browser over
WebHID (Ledger-style APDU framing), and its accounts are **smart-contract
wallets** (`PQSmartWallet`, ERC-4337 v0.6), not EOAs. Every account is a
CREATE2 address that is identical on all supported chains
(`PQ1_SUPPORTED_CHAIN_IDS` in `config.ts`: Ethereum, Base, Base Sepolia).

This directory holds everything PQ1-specific that is not a screen, a
controller or the keystore signer. It is web-only: the only files reachable
from the shared `ProviderController` (and so from the mobile bundle) are the
pure constants in `config.ts` and the small `dappProvider.ts` helpers.

## How it fits Ambire

Ambire's hardware-wallet abstraction assumes an EOA signer (a key iterator
that derives addresses, a signer that returns ECDSA signatures). PQ1 does not
fit that mould in three places, and each one is handled at the narrowest
point possible:

| Concern | Where | What |
| --- | --- | --- |
| Importing accounts | `importAccounts.ts`, `PQ1ConnectScreen` | WebHID needs a user gesture, which only the popup has. The popup pairs the device, reads the account addresses, and dispatches them to the background, which writes `Account` + `ExternalKey` records with `creation: null` so the rest of Ambire treats them as plain addresses. There is no key iterator: PQ1 has no BIP-32, just 256 numbered account slots. |
| Broadcasting a transaction | `aa/`, `KeystoreSignerInterface.broadcastAccountOp` (ambire-common) | The signer cannot produce a raw EOA transaction. It packs the AccountOp's calls into a UserOperation, signs it on-device, and submits it to the bundler itself. `SignAccountOpController` calls this hook for `signingKeyType === 'pq1'` and tracks the result like any other bundler broadcast. The user-approved fee is passed in and used verbatim. |
| Signing messages | `transport/offchain.ts`, `SignMessageContext` (ambire-common) | Signatures are verified on-chain via ERC-1271 / ERC-6492, so the signer needs the chain it will be verified on. ambire-common threads an optional `{ chainId, provider }` context through the signing helpers; EOA signers ignore it. |
| Dapp provider answers | `dappProvider.ts` | `eth_getCode` and `wallet_getCapabilities` would describe the account as an EOA. `ProviderController` delegates both to this module for PQ1 keys. |

## Layout

```
transport/   WebHID transport, APDU commands, sign-request/response wire format
aa/          UserOperation building, gas estimation, bundler client, broadcast
db/          shared loader + parsers for the clear-signing catalogs (below)
erc20/       ERC-20 metadata lookup + bundle builder ("Send 1 USDC" on-device)
names/       address-name lookup + bundle builder
erc7730/     ERC-7730 descriptor catalog + EIP-712 trailer builder
safe/        Safe transaction byte-parsers + presign bundle (clear-signs Safe txs)
cowswap/     CoW Protocol order encoding (clear-signs setPreSignature)
```

Comments referencing `sphincs_rust/...` point into the PQ1 firmware source
tree, and `pq1-companion/...` into the desktop companion. Both define the
wire formats these files mirror byte-for-byte; the paths are kept so a change
on either side can be traced.

## Clear-signing catalogs (`src/web/public/pq1/*.bin`)

The device renders human-readable transaction details ("Send 1 USDC to
vitalik.eth") only if the host attaches metadata it can verify. The firmware
ships just three 32-byte Merkle roots and verifies every bundle the host
sends against them, so:

- the host (this extension) is the sole holder of the data and must ship it;
- a withheld bundle degrades safely to the device's "unknown token / raw
  address" screens, and a forged one cannot pass the Merkle check;
- the blobs cannot be trimmed or regenerated independently — their roots are
  pinned in the firmware.

| File | Size | Contents |
| --- | ---: | --- |
| `erc20_db.bin` | 9.6 MB | ERC-20 name/symbol/decimals per (chainId, contract) |
| `names_db.bin` | 105 KB | well-known contract / address names |
| `erc7730_db.bin` | 11 KB | ERC-7730 clear-signing descriptors |

They are copied to the build unchanged (`webpack/extension.js`), never
imported into any JS bundle, and fetched lazily via `chrome.runtime.getURL`
the first time a PQ1 signing request needs them. Users without a PQ1 account
never load them. Because the device verifies the bundle, the blobs could
later be served from a CDN instead of the package with no loss of security.

## Testing

```
npx jest src/web/modules/hardware-wallet/libs/pq1
```

88 tests, including end-to-end wire-format vectors captured from the firmware
(`cowswap/e2eFirmwareVectors.test.ts`, `transport/signRequest.test.ts`) and
the catalog loaders run against the real `.bin` files. No new npm
dependencies are introduced and the LavaMoat policy is unchanged.
