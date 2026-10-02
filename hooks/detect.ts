// Pure secret detection and masking. No `$` here, so tests can call it directly.

export type Secret = { kind: string; start: number; end: number }

type Rule = { kind: string; re: RegExp; ok?: (s: string) => boolean }

const hasLetterAndDigit = (s: string): boolean => /[A-Za-z]/.test(s) && /[0-9]/.test(s)

// Left boundary: a token never starts in the middle of a word.
const PREFIXED: Rule[] = [
  { kind: 'anthropic_key', re: /(?<![A-Za-z0-9])sk-ant-[A-Za-z0-9_-]{20,}/g },
  { kind: 'openai_key', re: /(?<![A-Za-z0-9])sk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}/g, ok: hasLetterAndDigit },
  { kind: 'github_token', re: /(?<![A-Za-z0-9])gh[pousr]_[A-Za-z0-9]{36,}/g },
  { kind: 'github_token', re: /(?<![A-Za-z0-9])github_pat_[A-Za-z0-9_]{50,}/g },
  { kind: 'aws_key', re: /(?<![A-Za-z0-9])AKIA[0-9A-Z]{16}(?![0-9A-Z])/g },
  { kind: 'google_key', re: /(?<![A-Za-z0-9])AIza[0-9A-Za-z_-]{35}/g },
  { kind: 'slack_token', re: /(?<![A-Za-z0-9])xox[abprs]-[A-Za-z0-9-]{10,}/g },
  { kind: 'stripe_key', re: /(?<![A-Za-z0-9])(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}/g },
  { kind: 'stripe_key', re: /(?<![A-Za-z0-9])whsec_[A-Za-z0-9]{16,}/g },
  { kind: 'gitlab_token', re: /(?<![A-Za-z0-9])glpat-[A-Za-z0-9_-]{20,}/g },
  { kind: 'apify_token', re: /(?<![A-Za-z0-9])apify_api_[A-Za-z0-9]{20,}/g },
  { kind: 'notion_token', re: /(?<![A-Za-z0-9])ntn_[A-Za-z0-9]{30,}/g },
  { kind: 'notion_token', re: /(?<![A-Za-z0-9])secret_[A-Za-z0-9]{40,}/g },
  { kind: 'huggingface_token', re: /(?<![A-Za-z0-9])hf_[A-Za-z0-9]{30,}/g },
  { kind: 'replicate_token', re: /(?<![A-Za-z0-9])r8_[A-Za-z0-9]{30,}/g },
  { kind: 'npm_token', re: /(?<![A-Za-z0-9])npm_[A-Za-z0-9]{30,}/g },
  { kind: 'telegram_token', re: /(?<![0-9])\d{8,10}:AA[A-Za-z0-9_-]{33}/g },
  { kind: 'jwt', re: /(?<![A-Za-z0-9])eyJ[A-Za-z0-9_-]{5,}\.eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}/g },
  {
    kind: 'private_key',
    re: /-----BEGIN (?:[A-Z]+ )*PRIVATE KEY-----[\s\S]*?-----END (?:[A-Z]+ )*PRIVATE KEY-----/g,
  },
  // A block cut short before its END line: the BEGIN line and the body that follows.
  { kind: 'private_key', re: /-----BEGIN (?:[A-Z]+ )*PRIVATE KEY-----\s*(?:[A-Za-z0-9+/=]{20,}\s*)+/g },
]

const BEARER = /\bbearer[ \t]+([A-Za-z0-9._~+/-]{20,}=*)/gi

const URL_PASSWORD = /[A-Za-z][A-Za-z0-9+.-]*:\/\/[^\s:/@"'<>]+:([^\s@/"'<>]+)@/g

const ASSIGNMENT =
  /(?:api[_-]?key|secret|token|passw(?:or)?d|credential|private[_-]?key|access[_-]?key|auth(?!or))[A-Za-z0-9_.-]*["']?[ \t]*[=:][ \t]*["']?([A-Za-z0-9_\-./+=]{16,})/gi

const PLACEHOLDER =
  /^(?:your|x{3,}|\*+$|<|\$|process\.env|os\.environ|os\.getenv)|changeme|change_me|example/i

const GENERIC_PASSWORD = /^(?:pass|password|passwd|pwd|secret|user|x+|\*+)$/i

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i

function isAssignedSecret(v: string): boolean {
  if (!hasLetterAndDigit(v)) return false
  if (PLACEHOLDER.test(v) || /^(.)\1+$/.test(v)) return false
  if (UUID.test(v) || /^[0-9a-f]{40}$/i.test(v)) return false
  if (/^sha\d+-/.test(v)) return false
  if (/^(?:\/|\.\.?\/|~)/.test(v)) return false
  return true
}

// Priority: a prefixed token wins over the assignment rule at the same spot.
function collect(text: string): Array<Secret & { rank: number }> {
  const found: Array<Secret & { rank: number }> = []
  for (const rule of PREFIXED) {
    for (const m of text.matchAll(rule.re)) {
      if (rule.ok && !rule.ok(m[0])) continue
      found.push({ kind: rule.kind, start: m.index, end: m.index + m[0].length, rank: 0 })
    }
  }
  for (const m of text.matchAll(URL_PASSWORD)) {
    const pw = m[1] as string
    if (PLACEHOLDER.test(pw) || GENERIC_PASSWORD.test(pw)) continue
    const end = m.index + m[0].length - 1
    found.push({ kind: 'url_password', start: end - pw.length, end, rank: 1 })
  }
  for (const m of text.matchAll(BEARER)) {
    const v = m[1] as string
    if (!hasLetterAndDigit(v) || PLACEHOLDER.test(v)) continue
    const end = m.index + m[0].length
    found.push({ kind: 'bearer_token', start: end - v.length, end, rank: 2 })
  }
  for (const m of text.matchAll(ASSIGNMENT)) {
    const v = m[1] as string
    if (!isAssignedSecret(v)) continue
    const end = m.index + m[0].length
    found.push({ kind: 'secret', start: end - v.length, end, rank: 2 })
  }
  return found
}

// Every secret in the text, in order, none overlapping.
export function findSecrets(text: string): Secret[] {
  const all = collect(text).sort((a, b) => a.start - b.start || a.rank - b.rank || b.end - a.end)
  const out: Secret[] = []
  let last = 0
  for (const s of all) {
    if (s.start < last) continue
    out.push({ kind: s.kind, start: s.start, end: s.end })
    last = s.end
  }
  return out
}

function tail(kind: string, s: string): string {
  const body = kind === 'private_key' ? s.replace(/-----END[\s\S]*$/, '').replace(/[\s-]/g, '') : s
  return body.slice(-4)
}

export function mask(text: string): { text: string; count: number } {
  const found = findSecrets(text)
  if (found.length === 0) return { text, count: 0 }
  let out = ''
  let at = 0
  for (const s of found) {
    out += text.slice(at, s.start) + `[masked ${s.kind} ...${tail(s.kind, text.slice(s.start, s.end))}]`
    at = s.end
  }
  return { text: out + text.slice(at), count: found.length }
}

type Block = { type: string; [field: string]: unknown }

// Masks text blocks and the text inside tool_result blocks. Every other block is kept as is.
export function maskBlocks(blocks: Block[]): { content: Block[]; count: number } {
  let count = 0
  const text = (s: string): string => {
    const r = mask(s)
    count += r.count
    return r.text
  }
  const content = blocks.map((b): Block => {
    if (b.type === 'text' && typeof b.text === 'string') {
      const t = text(b.text)
      return t === b.text ? b : { ...b, text: t }
    }
    if (b.type !== 'tool_result') return b
    if (typeof b.content === 'string') {
      const t = text(b.content)
      return t === b.content ? b : { ...b, content: t }
    }
    if (!Array.isArray(b.content)) return b
    const inner = (b.content as Block[]).map((c): Block => {
      if (c.type !== 'text' || typeof c.text !== 'string') return c
      const t = text(c.text)
      return t === c.text ? c : { ...c, text: t }
    })
    return { ...b, content: inner }
  })
  return { content: count === 0 ? blocks : content, count }
}

const MARKER = /\[masked [a-z_]+ \.\.\.[^\]\s]{1,4}\]/

export const hasMarker = (s: string): boolean => MARKER.test(s)

// The text a tool call would write or run, for the write guard.
export function writtenText(tool: string, input: Record<string, unknown>): string[] {
  const str = (v: unknown): string[] => (typeof v === 'string' ? [v] : [])
  switch (tool) {
    case 'Write':
      return str(input.content)
    case 'Edit':
      return str(input.new_string)
    case 'MultiEdit':
      return Array.isArray(input.edits)
        ? input.edits.flatMap((x) => str((x as Record<string, unknown> | null)?.new_string))
        : []
    case 'NotebookEdit':
      return str(input.new_source)
    case 'Bash':
      return str(input.command)
    default:
      return []
  }
}
