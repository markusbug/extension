// Markdown report of a harness run, ready to paste into the PR's testing
// section or an issue — and the parser that turns such a report back into
// results, so progress can be restored after a rebuild.

import type { ScenarioOutcome, ScenarioStatus } from './runScenario'
import type { Scenario } from './scenarios'

/** The tester's judgement of what the device actually showed. */
export type ScreenVerdict = 'matches' | 'wrong'

export type ScenarioResult = {
  outcome?: ScenarioOutcome
  verdict?: ScreenVerdict
  /** What was wrong on the device screen, in the tester's words. */
  comment?: string
}

const STATUS_LABEL: Record<ScenarioStatus, string> = {
  signed: 'signed',
  'refused-by-wallet': 'refused by wallet',
  'rejected-on-device': 'rejected on device',
  'refused-on-device': 'refused on device',
  failed: 'FAILED'
}

const DEVICE_DETAIL_PREFIX = ' (device: '
const COMMENT_SEPARATOR = ' — '

const cell = (s: string) => s.split('|').join('\\|').split('\n').join(' ')

/** Whether a finished run behaved as the scenario expects, before the
 *  tester's screen check: host refusals must not reach the device, device
 *  refusals must be refused there, and everything else must be signable. */
export function behavedAsExpected(scenario: Scenario, outcome: ScenarioOutcome): boolean {
  if (scenario.expectHostRefusal) return outcome.status === 'refused-by-wallet'
  if (scenario.expectDeviceRefusal) return outcome.status === 'refused-on-device'
  return outcome.status === 'signed' || outcome.status === 'rejected-on-device'
}

const screenCheck = (scenario: Scenario, r: ScenarioResult) => {
  if (!r.verdict) return scenario.expectHostRefusal ? 'n/a' : 'not checked'
  const comment = r.comment?.trim()
  return comment ? `${r.verdict}${COMMENT_SEPARATOR}${comment}` : r.verdict
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
      r.outcome.deviceDetail ? `${DEVICE_DETAIL_PREFIX}${r.outcome.deviceDetail})` : ''
    }`
    lines.push(
      `| ${s.group} | ${cell(s.title)} | ${cell(s.expected)} | ${cell(result)} | ${cell(
        screenCheck(s, r)
      )} |`
    )
  }
  return lines.join('\n')
}

/** Split a Markdown table row on its unescaped `|` separators. */
function splitRow(line: string): string[] {
  const cells: string[] = []
  let current = ''
  for (let i = 0; i < line.length; i++) {
    const ch = line[i]!
    if (ch === '\\' && line[i + 1] === '|') {
      current += '|'
      i++
    } else if (ch === '|') {
      cells.push(current.trim())
      current = ''
    } else {
      current += ch
    }
  }
  cells.push(current.trim())
  return cells.slice(1, -1) // drop the empty edges outside the outer pipes
}

function parseResultCell(text: string): ScenarioOutcome | null {
  const statuses = Object.keys(STATUS_LABEL) as ScenarioStatus[]
  const status = statuses.find((s) => text.startsWith(`${STATUS_LABEL[s]}: `))
  if (!status) return null
  let message = text.slice(STATUS_LABEL[status].length + 2)
  let deviceDetail: string | undefined
  const detailAt = message.lastIndexOf(DEVICE_DETAIL_PREFIX)
  if (detailAt >= 0 && message.endsWith(')')) {
    deviceDetail = message.slice(detailAt + DEVICE_DETAIL_PREFIX.length, -1)
    message = message.slice(0, detailAt)
  }
  return {
    status,
    reachedDevice: status !== 'refused-by-wallet',
    message,
    deviceDetail,
    durationMs: 0
  }
}

function parseCheckCell(text: string): Pick<ScenarioResult, 'verdict' | 'comment'> {
  const verdicts: ScreenVerdict[] = ['matches', 'wrong']
  const verdict = verdicts.find((v) => text === v || text.startsWith(`${v}${COMMENT_SEPARATOR}`))
  if (!verdict) return {}
  const comment = text.slice(verdict.length + COMMENT_SEPARATOR.length).trim()
  return comment ? { verdict, comment } : { verdict }
}

/** Results from a report produced by `buildReport`, matched to scenarios
 *  by title. Rows that don't match a scenario are skipped. */
export function parseReport(
  markdown: string,
  scenarios: Scenario[]
): Record<string, ScenarioResult> {
  const byTitle = new Map(scenarios.map((s) => [s.title, s]))
  const results: Record<string, ScenarioResult> = {}
  for (const line of markdown.split('\n')) {
    if (!line.startsWith('|')) continue
    const [, title, , resultText, checkText] = splitRow(line)
    const scenario = title ? byTitle.get(title) : undefined
    const outcome = resultText ? parseResultCell(resultText) : null
    if (!scenario || !outcome) continue
    results[scenario.id] = { outcome, ...parseCheckCell(checkText ?? '') }
  }
  return results
}
