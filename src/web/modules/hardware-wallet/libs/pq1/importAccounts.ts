import { getAddress } from 'ethers'

import { DEFAULT_ACCOUNT_LABEL } from '@ambire-common/consts/account'
import { BIP44_STANDARD_DERIVATION_TEMPLATE } from '@ambire-common/consts/derivation'
import { Account } from '@ambire-common/interfaces/account'
import { ExternalKey } from '@ambire-common/interfaces/keystore'

/**
 * Build the `Account` + `ExternalKey` records Ambire's keystore expects
 * from a set of (accountIndex, address) pairs the popup has already
 * resolved from the PQ1 device.
 *
 * Address resolution happens in the popup rather than here because WebHID
 * device acquisition requires a user gesture, which is only available in
 * the popup context — not in the Manifest V3 service worker that hosts
 * the background controllers.
 *
 * PQ1 accounts are imported into Ambire's model as `creation = null` so
 * Ambire treats them as plain externally-owned addresses. Real transaction
 * execution must be routed through PQ1's own UserOp + bundler pipeline by
 * the PQ1-aware broadcast branch — Ambire's relayer/4337 stack is never
 * invoked for these accounts.
 */
export function buildPQ1AccountsToImport(
  entries: Array<{ accountIndex: number; addr: string }>,
  deviceId: string
): { accounts: Account[]; keys: ExternalKey[] } {
  const accounts: Account[] = []
  const keys: ExternalKey[] = []

  for (const entry of entries) {
    const addr = getAddress(entry.addr)
    const { accountIndex } = entry
    const label = `${DEFAULT_ACCOUNT_LABEL} (PQ1 #${accountIndex})`

    accounts.push({
      addr,
      associatedKeys: [addr],
      initialPrivileges: [],
      // null = treated as an EOA by Ambire's account model. The broadcast
      // branch detects PQ1 via the matching ExternalKey on the keystore.
      creation: null,
      preferences: { label, pfp: addr },
      newlyAdded: true
    })

    keys.push({
      addr,
      type: 'pq1',
      label,
      dedicatedToOneSA: false,
      meta: {
        deviceId,
        deviceModel: 'pq1',
        // PQ1 has no BIP-32; the `index` field doubles as accountIndex so
        // every existing keystore consumer that reads `meta.index` keeps
        // working. The explicit `accountIndex` is what the PQ1 signer
        // actually consumes — kept under both names for clarity.
        hdPathTemplate: BIP44_STANDARD_DERIVATION_TEMPLATE,
        index: accountIndex,
        accountIndex,
        slotIndex: 0,
        ownerIndex: 1,
        // Note: PQ1 keys are chain-agnostic — the same SPHINCS+ keypair
        // signs on every supported chain. The per-request chain comes from
        // the SignMessageContext threaded through the signing helpers.
        createdAt: Date.now()
      }
    })
  }

  return { accounts, keys }
}
