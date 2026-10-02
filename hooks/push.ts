// Pure helpers for the push check. No `$` here, so tests can call them directly.
import { findSecrets } from './detect'

export type Push = {
  /** Folder from a leading `cd <dir>`, run from the session's cwd. */
  chdir?: string
  /** Folder from `git -C <dir>`, relative to chdir when both are given. */
  gitDir?: string
  remote: string
  /** True when the command stages or commits before the push. */
  staged: boolean
}

export type Finding = { file: string; line: number; kind: string }

type Segment = { text: string; tokens: string[] }

// Splits a command on && || ; | and newlines outside quotes, and each part into unquoted words.
function segments(cmd: string): Segment[] {
  const out: Segment[] = []
  let tokens: string[] = []
  let word = ''
  let hasWord = false
  let text = ''
  let quote = ''
  const endWord = () => {
    if (hasWord) tokens.push(word)
    word = ''
    hasWord = false
  }
  const endSegment = () => {
    endWord()
    if (tokens.length > 0) out.push({ text: text.trim(), tokens })
    tokens = []
    text = ''
  }
  for (let i = 0; i < cmd.length; i++) {
    const c = cmd[i] as string
    if (quote) {
      if (c === quote) quote = ''
      else word += c
      text += c
      continue
    }
    if (c === '"' || c === "'") {
      quote = c
      hasWord = true
      text += c
    } else if (c === '&' || c === '|' || c === ';' || c === '\n') {
      endSegment()
      if ((c === '&' || c === '|') && cmd[i + 1] === c) i++
    } else if (c === ' ' || c === '\t') {
      endWord()
      text += c
    } else {
      word += c
      hasWord = true
      text += c
    }
  }
  endSegment()
  return out
}

type GitCall = { sub: string; gitDir?: string; rest: string[] }

// `git [-C dir] [-c k=v] [flags] <sub> ...`, only when git is the segment's command.
function gitCall(tokens: string[]): GitCall | null {
  let i = 0
  while (i < tokens.length && /^[A-Za-z_][A-Za-z0-9_]*=/.test(tokens[i] as string)) i++
  if (tokens[i] !== 'git') return null
  i++
  let gitDir: string | undefined
  while (i < tokens.length && (tokens[i] as string).startsWith('-')) {
    if (tokens[i] === '-C') gitDir = tokens[i + 1]
    i += tokens[i] === '-C' || tokens[i] === '-c' ? 2 : 1
  }
  const sub = tokens[i]
  if (sub === undefined) return null
  return { sub, gitDir, rest: tokens.slice(i + 1) }
}

// Every git push in the command. Errs on the safe side: any `git ... push` the parser
// cannot place (inside `bash -c`, after echo) still counts, with the defaults.
export function parsePushes(cmd: string): Push[] {
  const pushes: Push[] = []
  let chdir: string | undefined
  let staged = false
  for (const seg of segments(cmd)) {
    const first = seg.tokens[0]?.replace(/^[({]+/, '')
    if (first === 'cd' && seg.tokens[1] !== undefined && seg.tokens[1] !== '-') {
      chdir = seg.tokens[1]
      continue
    }
    const call = gitCall(seg.tokens.map((t, i) => (i === 0 ? t.replace(/^[({]+/, '') : t)))
    if (!call) continue
    if (call.sub === 'add' || call.sub === 'commit') staged = true
    if (call.sub === 'push') {
      const remote = call.rest.find((t) => !t.startsWith('-')) ?? 'origin'
      pushes.push({ chdir, gitDir: call.gitDir, remote, staged })
    }
  }
  if (pushes.length === 0 && /\bgit\b[^;&|\n]*\bpush\b/.test(cmd)) {
    pushes.push({ remote: 'origin', staged: /\bgit\b[^;&|\n]*\b(?:add|commit)\b/.test(cmd) })
  }
  return pushes
}

// A form `gh repo view` reads: git@host:o/r and ssh://git@host/o/r become https URLs.
export function repoSpec(url: string): string {
  const u = url.trim()
  const scp = /^[\w.-]+@([\w.-]+):(.+?)(?:\.git)?\/?$/.exec(u)
  if (scp) return `https://${scp[1]}/${scp[2]}`
  const ssh = /^ssh:\/\/(?:[\w.-]+@)?([\w.-]+)(?::\d+)?\/(.+?)(?:\.git)?\/?$/.exec(u)
  if (ssh) return `https://${ssh[1]}/${ssh[2]}`
  return u.replace(/\.git$/, '')
}

export type Added = { file: string; line: number; text: string }

// The added lines of a unified diff or a `git log -p` stream, with their line in the new file.
export function addedLines(diff: string): Added[] {
  const out: Added[] = []
  let file = ''
  let line = 0
  let inHunk = false
  for (const raw of diff.split('\n')) {
    if (raw.startsWith('diff --git ')) {
      inHunk = false
      file = ''
    } else if (!inHunk && raw.startsWith('+++ ')) {
      const p = raw.slice(4)
      file = p === '/dev/null' ? '' : p.replace(/^b\//, '')
    } else if (raw.startsWith('@@')) {
      const m = /\+(\d+)/.exec(raw)
      line = m ? Number(m[1]) : 1
      inHunk = true
    } else if (inHunk && raw.startsWith('+')) {
      out.push({ file, line, text: raw.slice(1) })
      line++
    } else if (inHunk && raw.startsWith(' ')) {
      line++
    }
  }
  return out
}

const HOME_PATH = /(?:\/home|\/Users)\/([A-Za-z0-9._-]+)(?=\/)/g
const IGNORED_HOME_USERS = new Set(['user', 'runner'])
const escape = (s: string): string => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')

// Secrets and home paths in the added lines. Lines of one file are joined so that a
// multi-line private key block is seen whole. Never returns a secret value.
export function scanAdded(added: Added[], home?: string): Finding[] {
  const findings: Finding[] = []
  const byFile = new Map<string, Added[]>()
  for (const a of added) byFile.set(a.file, [...(byFile.get(a.file) ?? []), a])
  const homeRe = home && home.length > 1 ? new RegExp(`${escape(home.replace(/\/+$/, ''))}(?![A-Za-z0-9._-])`) : null
  for (const [file, lines] of byFile) {
    const starts: number[] = []
    let text = ''
    for (const l of lines) {
      starts.push(text.length)
      text += l.text + '\n'
    }
    const lineAt = (offset: number): number => {
      let i = 0
      while (i + 1 < starts.length && (starts[i + 1] as number) <= offset) i++
      return (lines[i] as Added).line
    }
    for (const s of findSecrets(text)) findings.push({ file, line: lineAt(s.start), kind: s.kind })
    for (const l of lines) {
      const homeHit =
        (homeRe?.test(l.text) ?? false) ||
        [...l.text.matchAll(HOME_PATH)].some((m) => !IGNORED_HOME_USERS.has(m[1] as string))
      if (homeHit) findings.push({ file, line: l.line, kind: 'home_path' })
    }
  }
  return findings
}

export function denyText(findings: Finding[], visibilityKnown: boolean): string {
  const shown = findings.slice(0, 10).map((f) => `${f.file}:${f.line} ${f.kind}`)
  const more = findings.length > 10 ? [`and ${findings.length - 10} more`] : []
  const why = visibilityKnown ? '' : ' (repo visibility unknown, scanned to be safe)'
  return [
    `secret-guard: push blocked, ${findings.length} finding${findings.length === 1 ? '' : 's'}${why}.`,
    ...shown,
    ...more,
    'If these are false positives, ask the user to run /secret-guard allow, then push again.',
  ].join('\n')
}

const MAX_FILE_BYTES = 1024 * 1024

// Whole-file "added lines" of an untracked file; none for a binary or a file over 1 MB.
export function fileAdded(file: string, text: string): Added[] {
  if (text.length > MAX_FILE_BYTES || text.includes('\0')) return []
  return text.split('\n').map((t, i) => ({ file, line: i + 1, text: t }))
}
