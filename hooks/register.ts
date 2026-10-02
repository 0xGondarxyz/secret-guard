import { atom, read, update } from 'claude-code'
import type { EngineInterface, Register } from 'claude-code'

import type { Guard } from '../types'
import { hasMarker, maskBlocks, writtenText } from './detect'
import { denyText, fileAdded, addedLines, parsePushes, repoSpec, scanAdded } from './push'
import type { Added, Finding, Push } from './push'

const guard = atom({ plugin: 'secret-guard', key: 'guard' } as const, { masked: 0, passUntil: 0 } as Guard)

const PASS_MS = 10 * 60 * 1000
const SCAN_MS = 5000
const MAX_UNTRACKED = 200

const MARKER_DENY =
  'secret-guard: this content holds a masked secret marker. The file holds a masked secret: edit around it or ask the user to change that value.'

type Scan = { findings: Finding[]; visibilityKnown: boolean }

// Scans one push. Throws when the scan itself fails; the caller then lets the push through.
async function scanPush($: EngineInterface, p: Push, home: string | undefined, homes: Array<string | undefined>, t0: number): Promise<Scan> {
  const run = async (argv: string[], cwd?: string) => {
    const left = SCAN_MS - ((await $.clock.now()) - t0)
    if (left <= 0) throw new Error('scan timed out')
    return $.process.run(argv, cwd === undefined ? { timeoutMs: left } : { cwd, timeoutMs: left })
  }
  const base = p.chdir?.replace(/^~(?=\/|$)/, home ?? '~')
  const gitC = p.gitDir === undefined ? [] : ['-C', p.gitDir]

  const topRun = await run(['git', ...gitC, 'rev-parse', '--show-toplevel'], base)
  const top = topRun.stdout.trim()
  if (topRun.exitCode !== 0 || top === '') return { findings: [], visibilityKnown: true }

  const remoteUrl = await run(['git', 'remote', 'get-url', p.remote], top)
  const url = remoteUrl.exitCode === 0 ? remoteUrl.stdout.trim() : /[:/]/.test(p.remote) ? p.remote : ''
  let visibility = ''
  if (url !== '') {
    try {
      const r = await run(['gh', 'repo', 'view', repoSpec(url), '--json', 'visibility', '--jq', '.visibility'], top)
      if (r.exitCode === 0) visibility = r.stdout.trim().toUpperCase()
    } catch {}
  }
  if (visibility === 'PRIVATE' || visibility === 'INTERNAL') return { findings: [], visibilityKnown: true }

  const pending = async (): Promise<Added[]> => {
    const out: Added[] = []
    const diffArgs = ['--no-pager', 'diff', '--no-color', '--no-ext-diff']
    let d = await run(['git', ...diffArgs, 'HEAD'], top)
    if (d.exitCode !== 0) d = await run(['git', ...diffArgs, '--cached'], top)
    if (d.exitCode === 0) out.push(...addedLines(d.stdout))
    const ls = await run(['git', 'ls-files', '-z', '-o', '--exclude-standard'], top)
    if (ls.exitCode !== 0) return out
    const files = ls.stdout.split('\0').filter((f) => f !== '').slice(0, MAX_UNTRACKED)
    const texts = await Promise.all(files.map((f) => run(['head', '-c', String(1024 * 1024 + 1), '--', f], top)))
    texts.forEach((t, i) => {
      if (t.exitCode === 0) out.push(...fileAdded(files[i] as string, t.stdout))
    })
    return out
  }

  const [log, extra] = await Promise.all([
    run(
      ['git', '--no-pager', 'log', '-p', '--no-color', '--no-ext-diff', '--format=%H', '--branches', '--not', `--remotes=${p.remote}`],
      top,
    ),
    p.staged ? pending() : Promise.resolve([] as Added[]),
  ])
  if (log.exitCode !== 0) throw new Error('git log failed')
  const findings = scanAdded([...addedLines(log.stdout), ...extra], homes)
  return { findings, visibilityKnown: visibility === 'PUBLIC' }
}

// A deny text for the call, or undefined to let it run.
async function verdict($: EngineInterface, e: { tool: string }, command: string | undefined): Promise<string | undefined> {
  if (writtenText(e.tool, e as unknown as Record<string, unknown>).some(hasMarker)) return MARKER_DENY
  if (command === undefined) return undefined
  const pushes = parsePushes(command)
  if (pushes.length === 0) return undefined

  const now = await $.clock.now()
  if ((await read($, guard)).passUntil > now) {
    await update($, guard, (g) => ({ ...g, passUntil: 0 }))
    return undefined
  }
  const home = await $.env.get('HOME')
  const homes = [home, await $.env.get('USERPROFILE')]
  const findings: Finding[] = []
  let known = true
  try {
    for (const p of pushes) {
      const r = await scanPush($, p, home, homes, now)
      findings.push(...r.findings)
      known = known && r.visibilityKnown
    }
  } catch {
    $.ui.toast('secret-guard: scan failed, push allowed')
    return undefined
  }
  if (findings.length === 0) return undefined
  $.ui.toast(`secret-guard: push blocked, ${findings.length} findings`)
  return denyText(findings, known)
}

export const register: Register = (on) => {
  on('session.start', async ($, e, next) => {
    try {
      await $.command.register({
        name: 'secret-guard',
        description: 'Show secret-guard status, or let the next push skip the scan',
        argumentHint: '[allow]',
      })
    } catch {}
    return next(e)
  })

  on('session.append', async ($, e, next) => {
    let masked: { content: typeof e.message.content; count: number } | null = null
    try {
      if (e.door === 'tool-result' || e.door === 'tool-message') {
        const r = maskBlocks(e.message.content)
        if (r.count > 0) masked = r
      }
    } catch {}
    if (masked === null) return next(e)
    const stored = await next({ ...e, message: { ...e.message, content: masked.content } })
    try {
      const n = masked.count
      await update($, guard, (g) => ({ ...g, masked: g.masked + n }))
    } catch {}
    return stored
  })

  on('tool.call', async ($, e, next) => {
    let deny: string | undefined
    try {
      deny = await verdict($, e, e.tool === 'Bash' ? e.command : undefined)
    } catch {}
    return deny === undefined ? next(e) : { deny }
  })

  on('command.run', { command: 'secret-guard' }, async ($, e, next) => {
    try {
      const now = await $.clock.now()
      if (e.args.trim() === 'allow') {
        await update($, guard, (g) => ({ ...g, passUntil: now + PASS_MS }))
        return { text: 'secret-guard: the next push skips the scan. The pass lasts 10 minutes.' }
      }
      const g = await read($, guard)
      const left = Math.ceil((g.passUntil - now) / 60000)
      const pass = g.passUntil > now ? `a pass is active (${left} min left)` : 'no pass is active'
      return { text: `secret-guard: ${g.masked} values masked this session, ${pass}.` }
    } catch {
      return { text: 'secret-guard: something went wrong' }
    }
  })
}
