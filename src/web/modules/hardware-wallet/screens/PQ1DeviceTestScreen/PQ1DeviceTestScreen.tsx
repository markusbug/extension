import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { ScrollView, View } from 'react-native'

import Button from '@common/components/Button'
import Input from '@common/components/Input'
import Panel from '@common/components/Panel'
import Text, { type TextAppearance } from '@common/components/Text'
import { useTranslation } from '@common/config/localization'
import useTheme from '@common/hooks/useTheme'
import useToast from '@common/hooks/useToast'
import spacings from '@common/styles/spacings'
import flexbox from '@common/styles/utils/flexbox'
import { setStringAsync } from '@common/utils/clipboard'
import {
  TabLayoutContainer,
  TabLayoutWrapperMainContent
} from '@web/components/TabLayoutWrapper/TabLayoutWrapper'
import PQ1Controller from '@web/modules/hardware-wallet/controllers/PQ1Controller'
import {
  behavedAsExpected,
  buildReport,
  parseReport,
  type ScenarioResult,
  type ScreenVerdict
} from '@web/modules/hardware-wallet/libs/pq1/deviceHarness/report'
import {
  HARNESS_ACCOUNT_INDEX,
  runScenario,
  type ScenarioStatus
} from '@web/modules/hardware-wallet/libs/pq1/deviceHarness/runScenario'
import {
  type Scenario,
  SCENARIOS
} from '@web/modules/hardware-wallet/libs/pq1/deviceHarness/scenarios'
import { SEED_REPORT } from '@web/modules/hardware-wallet/libs/pq1/deviceHarness/seedReport'
import { toUserFacingPq1Error } from '@web/modules/hardware-wallet/libs/pq1/errors'

type Connection = { sender: `0x${string}`; protocol: string; deviceId: string }

/** Results survive page reloads and extension rebuilds (same extension
 *  origin) so a long on-device run is never lost. */
const RESULTS_STORAGE_KEY = 'pq1DeviceTestResults.v1'

function loadResults(): Record<string, ScenarioResult> {
  try {
    const saved = localStorage.getItem(RESULTS_STORAGE_KEY)
    if (saved) return JSON.parse(saved) as Record<string, ScenarioResult>
  } catch (e) {
    console.warn('[pq1 harness] reading saved results failed', e)
  }
  return parseReport(SEED_REPORT, SCENARIOS)
}

function saveResults(results: Record<string, ScenarioResult>) {
  try {
    localStorage.setItem(RESULTS_STORAGE_KEY, JSON.stringify(results))
  } catch (e) {
    console.warn('[pq1 harness] saving results failed', e)
  }
}

const STATUS_APPEARANCE: Record<ScenarioStatus, TextAppearance> = {
  signed: 'successText',
  'refused-by-wallet': 'warningText',
  'rejected-on-device': 'secondaryText',
  failed: 'errorText'
}

type ScenarioRowProps = {
  scenario: Scenario
  result: ScenarioResult | undefined
  isRunning: boolean
  isBusy: boolean
  isConnected: boolean
  onRun: (scenario: Scenario) => void
  onVerdict: (id: string, verdict: ScreenVerdict) => void
  onComment: (id: string, comment: string) => void
}

const ScenarioRow = React.memo(function ScenarioRow({
  scenario,
  result,
  isRunning,
  isBusy,
  isConnected,
  onRun,
  onVerdict,
  onComment
}: ScenarioRowProps) {
  const { t } = useTranslation()
  const { theme } = useTheme()
  const onPressRun = useCallback(() => onRun(scenario), [onRun, scenario])
  const onPressMatches = useCallback(
    () => onVerdict(scenario.id, 'matches'),
    [onVerdict, scenario.id]
  )
  const onPressWrong = useCallback(() => onVerdict(scenario.id, 'wrong'), [onVerdict, scenario.id])
  const onChangeComment = useCallback(
    (text: string) => onComment(scenario.id, text),
    [onComment, scenario.id]
  )
  const outcome = result?.outcome
  const canJudgeScreen = !!outcome?.reachedDevice

  return (
    <View
      style={[
        spacings.pvSm,
        spacings.phSm,
        spacings.mbTy,
        { borderRadius: 8, backgroundColor: theme.secondaryBackground }
      ]}
    >
      <View style={[flexbox.directionRow, flexbox.alignCenter, flexbox.justifySpaceBetween]}>
        <View style={flexbox.flex1}>
          <Text weight="medium" fontSize={14}>
            {t(scenario.title)}
            {scenario.spendsBootstrapKey ? t('  (uses one-time key budget)') : ''}
          </Text>
          <Text fontSize={12} appearance="secondaryText" style={spacings.mtMi}>
            {t('Expected: {{expected}}', { expected: scenario.expected })}
          </Text>
        </View>
        <Button
          text={isRunning ? t('Running…') : t('Run')}
          size="small"
          type="secondary"
          disabled={!isConnected || isBusy}
          hasBottomSpacing={false}
          onPress={onPressRun}
          style={spacings.mlSm}
        />
      </View>
      {!!outcome && (
        <View style={spacings.mtTy}>
          <Text fontSize={12} appearance={STATUS_APPEARANCE[outcome.status]}>
            {behavedAsExpected(scenario, outcome) ? '' : t('Unexpected: ')}
            {outcome.message}
          </Text>
          {!!outcome.deviceDetail && (
            <Text fontSize={11} appearance="tertiaryText">
              {t('Device: {{detail}}', { detail: outcome.deviceDetail })}
            </Text>
          )}
          {canJudgeScreen && (
            <View style={[flexbox.directionRow, spacings.mtTy]}>
              <Button
                text={t('Screen matches')}
                size="tiny"
                type={result?.verdict === 'matches' ? 'success' : 'outline'}
                hasBottomSpacing={false}
                onPress={onPressMatches}
              />
              <Button
                text={t('Screen wrong')}
                size="tiny"
                type={result?.verdict === 'wrong' ? 'danger' : 'outline'}
                hasBottomSpacing={false}
                onPress={onPressWrong}
                style={spacings.mlTy}
              />
            </View>
          )}
          {canJudgeScreen && result?.verdict === 'wrong' && (
            <Input
              value={result.comment ?? ''}
              onChangeText={onChangeComment}
              placeholder={t('What was wrong on the device screen?')}
              multiline
              containerStyle={spacings.mtTy}
            />
          )}
        </View>
      )}
    </View>
  )
})

/**
 * Developer tool: sends every request shape Ambire can hand a PQ1 to a
 * connected device, through the real signer, so a tester can confirm what
 * the device screen shows. Signs as an unused device account and never
 * broadcasts — see `libs/pq1/deviceHarness/`.
 */
const PQ1DeviceTestScreen = () => {
  const { t } = useTranslation()
  const { theme } = useTheme()
  const { addToast } = useToast()
  // Indirection so the controller (memoized once) always calls the latest
  // disconnect handler without being mutated after creation.
  const onDeviceDisconnectRef = useRef<() => void>(() => {})
  const controller = useMemo(() => {
    const c = new PQ1Controller()
    c.onDeviceDisconnect = () => onDeviceDisconnectRef.current()
    return c
  }, [])
  const [connection, setConnection] = useState<Connection | null>(null)
  const [isConnecting, setIsConnecting] = useState(false)
  const [runningId, setRunningId] = useState<string | null>(null)
  const [isRunningAll, setIsRunningAll] = useState(false)
  const [results, setResults] = useState<Record<string, ScenarioResult>>(loadResults)
  const isMountedRef = useRef(true)
  const stopRequestedRef = useRef(false)

  useEffect(() => {
    onDeviceDisconnectRef.current = () => setConnection(null)
  }, [])

  // Lets Run remaining see results recorded while it is looping.
  const resultsRef = useRef(results)
  useEffect(() => {
    resultsRef.current = results
    saveResults(results)
  }, [results])

  useEffect(() => {
    isMountedRef.current = true
    return () => {
      isMountedRef.current = false
      stopRequestedRef.current = true
      // cleanUp() logs transport errors internally, so it never rejects.
      void controller.cleanUp()
    }
  }, [controller])

  const onPressConnect = useCallback(async () => {
    setIsConnecting(true)
    try {
      await controller.unlock()
      const commands = controller.walletSDK?.commands
      if (!commands) throw new Error('PQ1 walletSDK missing right after unlock()')
      const sender = await commands.getWalletAddress(HARNESS_ACCOUNT_INDEX)
      const protocol = `0x${(await commands.getProtocolVersion()).toString(16).padStart(4, '0')}`
      if (isMountedRef.current) {
        setConnection({ sender, protocol, deviceId: controller.deviceId })
      }
    } catch (e) {
      if (!isMountedRef.current) return
      addToast(t(toUserFacingPq1Error(e).message), { type: 'error' })
    } finally {
      if (isMountedRef.current) setIsConnecting(false)
    }
  }, [controller, addToast, t])

  const run = useCallback(
    async (scenario: Scenario) => {
      if (!connection) return
      setRunningId(scenario.id)
      const outcome = await runScenario({ scenario, controller, sender: connection.sender })
      if (!isMountedRef.current) return
      setResults((prev) => ({ ...prev, [scenario.id]: { outcome } }))
      setRunningId(null)
    },
    [connection, controller]
  )

  const onRun = useCallback((scenario: Scenario) => void run(scenario), [run])

  const onPressRunAll = useCallback(async () => {
    stopRequestedRef.current = false
    setIsRunningAll(true)
    for (const scenario of SCENARIOS) {
      if (stopRequestedRef.current || !isMountedRef.current) break
      if (scenario.spendsBootstrapKey || resultsRef.current[scenario.id]?.outcome) continue

      await run(scenario)
    }
    if (isMountedRef.current) setIsRunningAll(false)
  }, [run])

  const onPressStop = useCallback(() => {
    stopRequestedRef.current = true
  }, [])

  const onVerdict = useCallback((id: string, verdict: ScreenVerdict) => {
    setResults((prev) => ({ ...prev, [id]: { ...prev[id], verdict } }))
  }, [])

  const onComment = useCallback((id: string, comment: string) => {
    setResults((prev) => ({ ...prev, [id]: { ...prev[id], comment } }))
  }, [])

  const onPressCopyReport = useCallback(async () => {
    const report = buildReport({
      scenarios: SCENARIOS,
      results,
      // Captured at connect: an unplug resets the controller's deviceId.
      deviceId: connection?.deviceId || controller.deviceId,
      firmwareProtocol: connection?.protocol
    })
    try {
      await setStringAsync(report)
      addToast(t('Report copied as Markdown.'))
    } catch (e) {
      console.error('[pq1 harness] copying the report failed', e)
      addToast(t("Couldn't copy the report."), { type: 'error' })
    }
  }, [results, controller, connection, addToast, t])

  const isBusy = !!runningId || isRunningAll

  return (
    <TabLayoutContainer backgroundColor={theme.primaryBackground}>
      <TabLayoutWrapperMainContent>
        <Panel title={t('PQ1 device test')} spacingsSize="small">
          <Text fontSize={13} appearance="secondaryText" style={spacings.mbSm}>
            {t(
              'Sends every kind of request Ambire can give a PQ1 to your device. It signs as device account {{index}}, which is never used for real funds, and nothing is ever sent to a network. Check each screen on the device, approve it there, then mark whether it matched.',
              { index: HARNESS_ACCOUNT_INDEX }
            )}
          </Text>
          <View style={[flexbox.directionRow, flexbox.wrap, spacings.mbSm]}>
            <Button
              text={
                connection
                  ? t('Connected: {{address}}', { address: `${connection.sender.slice(0, 8)}…` })
                  : isConnecting
                    ? t('Connecting…')
                    : t('Connect PQ1')
              }
              disabled={!!connection || isConnecting}
              hasBottomSpacing={false}
              onPress={onPressConnect}
            />
            <Button
              text={t('Run remaining')}
              type="secondary"
              disabled={!connection || isBusy}
              hasBottomSpacing={false}
              onPress={onPressRunAll}
              style={spacings.mlSm}
            />
            <Button
              text={t('Stop after current')}
              type="outline"
              disabled={!isRunningAll}
              hasBottomSpacing={false}
              onPress={onPressStop}
              style={spacings.mlSm}
            />
            <Button
              text={t('Copy report')}
              type="outline"
              hasBottomSpacing={false}
              onPress={onPressCopyReport}
              style={spacings.mlSm}
            />
          </View>
          <ScrollView>
            {SCENARIOS.map((scenario, i) => (
              <View key={scenario.id}>
                {SCENARIOS[i - 1]?.group !== scenario.group && (
                  <Text weight="semiBold" fontSize={15} style={[spacings.mtSm, spacings.mbTy]}>
                    {t(scenario.group)}
                  </Text>
                )}
                <ScenarioRow
                  scenario={scenario}
                  result={results[scenario.id]}
                  isRunning={runningId === scenario.id}
                  isBusy={isBusy}
                  isConnected={!!connection}
                  onRun={onRun}
                  onVerdict={onVerdict}
                  onComment={onComment}
                />
              </View>
            ))}
          </ScrollView>
        </Panel>
      </TabLayoutWrapperMainContent>
    </TabLayoutContainer>
  )
}

export default React.memo(PQ1DeviceTestScreen)
