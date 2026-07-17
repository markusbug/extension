import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { ScrollView, View } from 'react-native'

import Button from '@common/components/Button'
import Panel from '@common/components/Panel'
import Text from '@common/components/Text'
import { useTranslation } from '@common/config/localization'
import type { AllControllersMappingType } from '@common/constants/controllersMapping'
import useController from '@common/hooks/useController'
import useControllersMiddleware from '@common/hooks/useControllersMiddleware'
import useTheme from '@common/hooks/useTheme'
import useToast from '@common/hooks/useToast'
import useOnboardingNavigation from '@common/modules/auth/hooks/useOnboardingNavigation'
import spacings from '@common/styles/spacings'
import flexbox from '@common/styles/utils/flexbox'
import {
  TabLayoutContainer,
  TabLayoutWrapperMainContent
} from '@web/components/TabLayoutWrapper/TabLayoutWrapper'
import PQ1Controller from '@web/modules/hardware-wallet/controllers/PQ1Controller'

const DEFAULT_DISCOVERY_RANGE = 5

const selectAccounts = (state: AllControllersMappingType['AccountsController']) => state.accounts

/** How long to wait for the background import to show up in the
 *  AccountsController state before treating it as failed. Generous —
 *  the write path is local (storage), not network-bound. */
const IMPORT_CONFIRM_TIMEOUT_MS = 15000

type DiscoveredEntry = { accountIndex: number; addr: string; selected: boolean }

type DiscoveredAccountRowProps = {
  entry: DiscoveredEntry
  onToggle: (accountIndex: number) => void
}

const DiscoveredAccountRow = React.memo(function DiscoveredAccountRow({
  entry,
  onToggle
}: DiscoveredAccountRowProps) {
  const onPress = useCallback(() => onToggle(entry.accountIndex), [onToggle, entry.accountIndex])

  return (
    <View
      style={[
        flexbox.directionRow,
        flexbox.alignCenter,
        spacings.pvTy,
        spacings.phSm,
        { borderRadius: 6 }
      ]}
    >
      <Button
        type={entry.selected ? 'primary' : 'tertiary'}
        text={
          `#${entry.accountIndex}  ${entry.addr.slice(0, 6)}…${entry.addr.slice(-4)}` +
          (entry.selected ? '  ✓' : '')
        }
        hasBottomSpacing={false}
        onPress={onPress}
      />
    </View>
  )
})

/**
 * Pair-and-import flow for the PQ1 post-quantum hardware wallet.
 *
 * WebHID device acquisition requires a user gesture in the page that owns
 * the device handle, so this screen instantiates a `PQ1Controller` locally
 * (inside the popup) rather than reaching for the background's. Once
 * pairing succeeds and addresses are discovered, the resolved addresses
 * are dispatched to the background via `MAIN_CONTROLLER_IMPORT_PQ1_ACCOUNTS`
 * — the background does the keystore + accounts writes from there.
 */
const PQ1ConnectScreen = () => {
  const { theme } = useTheme()
  const { t } = useTranslation()
  const { addToast } = useToast()
  const { dispatch } = useControllersMiddleware()
  const { goToPrevRoute, goToNextRoute } = useOnboardingNavigation()

  // Indirection so the controller (memoized once) always calls the latest
  // disconnect handler without being mutated after creation.
  const onDeviceDisconnectRef = useRef<() => void>(() => {})
  const controller = useMemo(() => {
    const c = new PQ1Controller()
    c.onDeviceDisconnect = () => onDeviceDisconnectRef.current()
    return c
  }, [])
  const [isConnecting, setIsConnecting] = useState(false)
  const [isImporting, setIsImporting] = useState(false)
  const [discovered, setDiscovered] = useState<DiscoveredEntry[]>([])
  /** Lowercased addresses whose background import we're waiting to see
   *  reflected in the AccountsController state. Null = no import pending. */
  const [pendingImportAddrs, setPendingImportAddrs] = useState<string[] | null>(null)
  const { state: accounts } = useController('AccountsController', selectAccounts)

  useEffect(() => {
    // Physical unplug while on this screen: drop the discovered list (its
    // addresses came from the now-gone device) and put the user back on the
    // Connect step with a clear message.
    onDeviceDisconnectRef.current = () => {
      setDiscovered([])
      addToast(t('PQ1 was disconnected. Plug it in and connect again.'), { type: 'error' })
    }
  }, [addToast, t])

  useEffect(() => {
    return () => {
      // Release the WebHID handle if the user leaves without importing —
      // signing re-acquires it from the background on demand. cleanUp()
      // swallows transport errors internally, so it never rejects.
      void controller.cleanUp()
    }
  }, [controller])

  const onPressConnect = useCallback(async () => {
    setIsConnecting(true)
    try {
      await controller.unlock()
      const sdk = controller.walletSDK
      if (!sdk) throw new Error('PQ1 device not ready')
      const next: DiscoveredEntry[] = []

      for (let i = 0; i < DEFAULT_DISCOVERY_RANGE; i++) {
        const addr = await sdk.commands.getWalletAddress(i)
        next.push({ accountIndex: i, addr, selected: i === 0 })
      }
      setDiscovered(next)
    } catch (e: any) {
      addToast(e?.message || t('Failed to connect to PQ1'), { type: 'error' })
    } finally {
      setIsConnecting(false)
    }
  }, [controller, addToast, t])

  const onToggle = useCallback((accountIndex: number) => {
    setDiscovered((prev) =>
      prev.map((e) => (e.accountIndex === accountIndex ? { ...e, selected: !e.selected } : e))
    )
  }, [])

  const onPressImport = useCallback(() => {
    const entries = discovered.filter((e) => e.selected)
    if (entries.length === 0) {
      addToast(t('Select at least one PQ1 account to import.'), { type: 'error' })
      return
    }
    setIsImporting(true)
    // Fire-and-forget per the controller lifecycle — dispatch reports
    // nothing back, so a local try/catch can never observe a background
    // failure. Success is confirmed by watching the AccountsController
    // state (effects below); ONLY then does the flow navigate on.
    // Navigating right away used to strand users on the completed screen
    // with zero accounts when the background import failed.
    dispatch({
      type: 'MAIN_CONTROLLER_IMPORT_PQ1_ACCOUNTS',
      params: {
        entries: entries.map(({ accountIndex, addr }) => ({ accountIndex, addr })),
        deviceId: controller.deviceId
      }
    })
    setPendingImportAddrs(entries.map((e) => e.addr.toLowerCase()))
  }, [discovered, dispatch, controller, addToast, t])

  // Guards the one-shot success transition so a late accounts-state update
  // (or the timeout below firing during navigation) can't double-run it.
  const hasImportSucceededRef = useRef(false)

  useEffect(() => {
    if (!pendingImportAddrs || hasImportSucceededRef.current) return
    const imported = new Set(accounts.map((a) => a.addr.toLowerCase()))
    if (!pendingImportAddrs.every((addr) => imported.has(addr))) return
    hasImportSucceededRef.current = true
    // Release the device — signing will re-acquire on demand. cleanUp()
    // never rejects (it swallows transport errors internally).
    void controller.cleanUp().then(() => goToNextRoute())
  }, [accounts, pendingImportAddrs, controller, goToNextRoute])

  useEffect(() => {
    if (!pendingImportAddrs) return undefined
    const timer = setTimeout(() => {
      if (hasImportSucceededRef.current) return
      setPendingImportAddrs(null)
      setIsImporting(false)
      addToast(t('Importing PQ1 accounts failed or timed out. Please try again.'), {
        type: 'error'
      })
    }, IMPORT_CONFIRM_TIMEOUT_MS)
    return () => clearTimeout(timer)
  }, [pendingImportAddrs, addToast, t])

  return (
    <TabLayoutContainer backgroundColor={theme.secondaryBackground}>
      <TabLayoutWrapperMainContent>
        <Panel
          spacingsSize="small"
          type="onboarding"
          withBackButton
          onBackButtonPress={goToPrevRoute}
          title={t('Connect PQ1 (post-quantum)')}
        >
          <Text weight="medium" style={spacings.mbSm} fontSize={14}>
            {t('1. Plug your PQ1 in via USB.')}
          </Text>
          <Text weight="medium" style={spacings.mbSm} fontSize={14}>
            {t('2. Press Connect below — your browser will ask you to pick the device.')}
          </Text>
          <Text weight="medium" style={spacings.mbXl} fontSize={14}>
            {t('3. Enter your PIN on the PQ1 OLED when prompted.')}
          </Text>

          {discovered.length === 0 ? (
            <Button
              text={isConnecting ? t('Connecting...') : t('Connect PQ1')}
              disabled={isConnecting}
              onPress={onPressConnect}
              hasBottomSpacing={false}
            />
          ) : (
            <>
              <Text style={spacings.mbSm} fontSize={14} appearance="secondaryText">
                {t('Select PQ1 accounts to import:')}
              </Text>
              <ScrollView style={{ maxHeight: 240 }}>
                {discovered.map((e) => (
                  <DiscoveredAccountRow key={e.accountIndex} entry={e} onToggle={onToggle} />
                ))}
              </ScrollView>
              <View style={spacings.mtXl}>
                <Button
                  text={isImporting ? t('Importing...') : t('Import selected')}
                  disabled={isImporting}
                  onPress={onPressImport}
                  hasBottomSpacing={false}
                />
              </View>
            </>
          )}
        </Panel>
      </TabLayoutWrapperMainContent>
    </TabLayoutContainer>
  )
}

export default React.memo(PQ1ConnectScreen)
