// Markdown report of a harness run, ready to paste into the PR's testing
// section or an issue.

import type { ScenarioOutcome, ScenarioStatus } from './runScenario'
import type { Scenario } from './scenarios'

/** The tester's judgement of what the device actually showed. */
export type ScreenVerdict = 'matches' | 'wrong'

export type ScenarioResult = { outcome?: ScenarioOutcome; verdict?: ScreenVerdict }

const STATUS_LABEL: Record<ScenarioStatus, string> = {
  signed: 'signed',
  'refused-by-wallet': 'refused by wallet',
  'rejected-on-device': 'rejected on device',
  failed: 'FAILED'
}

const cell = (s: string) => s.split('|').join('\\|').split('\n').join(' ')

/** Whether a finished run behaved as the scenario expects, before the
 *  tester's screen check: refusals must not reach the device, everything
 *  else must reach it. */
export function behavedAsExpected(scenario: Scenario, outcome: ScenarioOutcome): boolean {
  if (scenario.expectHostRefusal) return outcome.status === 'refused-by-wallet'
  return outcome.status === 'signed' || outcome.status === 'rejected-on-device'
}

export function buildReport(args: {
  scenarios: Scenario[]
  results: Record<string, ScenarioResult>
  deviceId: string
  firmwareProtocol?: string
}): string {
  const ran = args.scenarios.filter((s) => args.results[s.id]?.outcome)
  const ok = ran.filter((s) => {
    const r = args.results[s.id]!
    return behavedAsExpected(s, r.outcome!) && r.verdict !== 'wrong'
  })
  const lines = [
    `### PQ1 device test — ${new Date().toISOString().slice(0, 10)}`,
    '',
    `Device ${args.deviceId}${args.firmwareProtocol ? `, protocol ${args.firmwareProtocol}` : ''}. ` +
      `${ok.length}/${ran.length} scenarios OK (${args.scenarios.length - ran.length} not run).`,
    '',
    '| Group | Scenario | Expected | Result | Screen check |',
    '| --- | --- | --- | --- | --- |'
  ]
  for (const s of args.scenarios) {
    const r = args.results[s.id]
    if (!r?.outcome) continue
    const result = `${STATUS_LABEL[r.outcome.status]}: ${r.outcome.message}${
      r.outcome.deviceDetail ? ` (device: ${r.outcome.deviceDetail})` : ''
    }`
    const check = r.verdict ?? (s.expectHostRefusal ? 'n/a' : 'not checked')
    lines.push(
      `| ${s.group} | ${cell(s.title)} | ${cell(s.expected)} | ${cell(result)} | ${check} |`
    )
  }
  return lines.join('\n')
}
