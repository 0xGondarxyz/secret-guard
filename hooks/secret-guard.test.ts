import { test, expect, mock } from 'claude-code/testing'
import { findSecrets, mask, maskBlocks, writtenText, hasMarker } from './detect'
import { register } from './register'
import { addedLines, denyText, parsePushes, repoSpec, scanAdded } from './push'

// Fixtures are built from pieces so this file holds no whole token or home path,
// and pushing this repo does not trip secret-guard itself.
const fill = (n: number, seed = 'aB3dE5gH7jK9mN1pQ2rS4tU6vW8xY0zA'): string => seed.repeat(Math.ceil(n / seed.length)).slice(0, n)
const HOME = '/ho' + 'me/'
const marker = (kind: string, last: string): string => '[mas' + `ked ${kind} ...${last}]`

const kinds: Array<[string, string]> = [
  ['anthropic_key', 'sk-ant-' + 'api03-' + fill(90)],
  ['openai_key', 'sk-' + 'proj-' + fill(48)],
  ['openai_key', 'sk-' + fill(48)],
  ['github_token', 'ghp' + '_' + fill(36)],
  ['github_token', 'gho' + '_' + fill(36)],
  ['github_token', 'ghs' + '_' + fill(40)],
  ['github_token', 'github_pat' + '_' + fill(70)],
  ['aws_key', 'AKIA' + 'IOSFODNN7EXAMPL3'],
  ['google_key', 'AIza' + fill(35)],
  ['slack_token', 'xoxb' + '-123456789012-' + fill(24)],
  ['stripe_key', 'sk_' + 'live_' + fill(30)],
  ['stripe_key', 'sk_' + 'test_' + fill(30)],
  ['stripe_key', 'rk_' + 'live_' + fill(30)],
  ['stripe_key', 'whsec' + '_' + fill(32)],
  ['gitlab_token', 'glpat' + '-' + fill(24)],
  ['apify_token', 'apify_' + 'api_' + fill(36)],
  ['notion_token', 'ntn' + '_' + fill(44)],
  ['notion_token', 'secret' + '_' + fill(43)],
  ['huggingface_token', 'hf' + '_' + fill(34)],
  ['replicate_token', 'r8' + '_' + fill(37)],
  ['npm_token', 'npm' + '_' + fill(36)],
  ['telegram_token', '1234567890' + ':AA' + fill(33)],
  ['jwt', 'eyJ' + 'hbGciOiJIUzI1NiJ9' + '.eyJ' + 'zdWIiOiIxMjM0NTY3ODkwIn0' + '.' + fill(43)],
]

test('mask: every prefixed kind', () => {
  for (const [kind, token] of kinds) {
    const r = mask(`before ${token} after`)
    expect(r.count).toBe(1)
    expect(r.text).toBe(`before ${marker(kind, token.slice(-4))} after`)
    expect(r.text.includes(token)).toBe(false)
  }
})

test('mask: assignment rule masks only the value', () => {
  const v = 'Zq8' + fill(30)
  const last = v.slice(-4)
  const cases: Array<[string, string]> = [
    [`API_KEY=${v}`, `API_KEY=${marker('secret', last)}`],
    [`export db-password = "${v}"`, `export db-password = "${marker('secret', last)}"`],
    [`"access_key": "${v}",`, `"access_key": "${marker('secret', last)}",`],
    [`client_secret: ${v}`, `client_secret: ${marker('secret', last)}`],
    [`MY_AUTH_TOKEN='${v}'`, `MY_AUTH_TOKEN='${marker('secret', last)}'`],
    [`private-key=${v}`, `private-key=${marker('secret', last)}`],
  ]
  for (const [input, expected] of cases) expect(mask(input).text).toBe(expected)
})

test('mask: a prefixed token in an assignment is one value', () => {
  const t = 'sk-ant-' + 'api03-' + fill(90)
  const r = mask(`ANTHROPIC_API_KEY=${t}`)
  expect(r.count).toBe(1)
  expect(r.text).toBe(`ANTHROPIC_API_KEY=${marker('anthropic_key', t.slice(-4))}`)
})

test('mask: bearer tokens', () => {
  const v = 'Zq8' + fill(40) + '=='
  const r = mask(`> Authorization: Bearer ${v}\n> Accept: */*`)
  expect(r.text).toBe(`> Authorization: Bearer ${marker('bearer_token', '==')}\n> Accept: */*`.replace('...==', '...' + v.slice(-4)))
  expect(mask(`curl -H "authorization: BEARER ${v}"`).count).toBe(1)
})

test('mask: url password and private key block', () => {
  const pw = 'Pq7' + fill(14)
  const r = mask(`DATABASE_URL=postgres://admin:${pw}@db.example.org:5432/app`)
  expect(r.text).toBe(`DATABASE_URL=postgres://admin:${marker('url_password', pw.slice(-4))}@db.example.org:5432/app`)

  const body = fill(64) + '\n' + fill(64) + '\n' + 'Zk9d'
  const pem = `-----BEGIN ${'RSA '}PRIVATE KEY-----\n${body}\n-----END ${'RSA '}PRIVATE KEY-----`
  const k = mask(`one\n${pem}\ntwo`)
  expect(k.count).toBe(1)
  expect(k.text).toBe(`one\n${marker('private_key', 'Zk9d')}\ntwo`)

  const cut = mask(`-----BEGIN ${'PRIVATE KEY'}-----\n${fill(64)}\n${fill(64)}`)
  expect(cut.count).toBe(1)
  expect(cut.text.startsWith('[mas' + 'ked private_key')).toBe(true)
})

test('mask: placeholders, hashes, ids, numbers, paths stay untouched', () => {
  const same = [
    'API_KEY=your_api_key_goes_here_123',
    'TOKEN=xxxxxxxxxxxxxxxxxxxxxxxx1',
    'password: <your-password-here-12345>',
    'secret: ${SECRET_VALUE_FROM_VAULT_1}',
    'token = process.env.STRIPE_SECRET_KEY_2',
    'api_key = os.environ["API_KEY_NUMBER_2"]',
    'API_KEY=changeme_please_1234567890',
    'API_KEY=example_value_1234567890ab',
    'postgres://user:password@localhost/db',
    'postgres://user:${DB_PASS}@localhost/db',
    'commit 3f786850e387550fdab836ed7e6dc881de23001b',
    'id 123e4567-e89b-12d3-a456-426614174000',
    'token: 123e4567-e89b-12d3-a456-426614174000',
    'sha256 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    '"integrity": "sha512-' + fill(86) + '=="',
    'secret_path=/etc/ssl/private/server-key-1.pem',
    'token: 12345678901234567890',
    'version 2026.10.02 build 98765432101234',
    'task-' + fill(40),
    'sk-learn-pipeline-with-a-long-readable-name',
    'author: Murat Can Yuksel the builder 2026',
    HOME + 'project/src/components/Button123.tsx',
    'A bearer of good news arrived, and the Bearer token idea is explained below.',
    'Authorization: Bearer ${TOKEN}',
  ]
  for (const s of same) expect(mask(s)).toEqual({ text: s, count: 0 })
})

test('mask: surrounding text is kept byte for byte, and masking is idempotent', () => {
  const t = 'ghp' + '_' + fill(36)
  const input = `  line one\r\n\ttab ${t}\n\n  ${t}  \nlast é ✓`
  const once = mask(input)
  expect(once.count).toBe(2)
  expect(once.text).toBe(`  line one\r\n\ttab ${marker('github_token', t.slice(-4))}\n\n  ${marker('github_token', t.slice(-4))}  \nlast é ✓`)
  expect(mask(once.text)).toEqual({ text: once.text, count: 0 })
  expect(findSecrets(input).map((s) => s.kind)).toEqual(['github_token', 'github_token'])
})

test('maskBlocks: text and tool_result shapes', () => {
  const t = 'AIza' + fill(35)
  const clean = [{ type: 'text', text: 'nothing here' }]
  expect(maskBlocks(clean).content).toBe(clean)

  const blocks = [
    { type: 'tool_result', tool_use_id: 'toolu_1', content: `key ${t}` },
    { type: 'tool_result', tool_use_id: 'toolu_2', content: [{ type: 'text', text: t }, { type: 'image', source: {} }] },
    { type: 'text', text: t },
    { type: 'tool_use', id: 'x', name: 'Read', input: { path: t } },
  ]
  const r = maskBlocks(blocks)
  expect(r.count).toBe(3)
  const m = marker('google_key', t.slice(-4))
  expect(r.content[0]).toEqual({ type: 'tool_result', tool_use_id: 'toolu_1', content: `key ${m}` })
  expect(r.content[1]).toEqual({ type: 'tool_result', tool_use_id: 'toolu_2', content: [{ type: 'text', text: m }, { type: 'image', source: {} }] })
  expect(r.content[2]).toEqual({ type: 'text', text: m })
  expect(r.content[3]).toBe(blocks[3])
})

// The engine's bottom cannot answer session.append in a test, so the hook runs directly
// with a recording `next` and a $ that keeps plugin state in memory.
function appendHook(): (e: any, next: (e: any) => Promise<any>) => Promise<any> {
  let hook: any
  ;(register as any)(((event: string, ...rest: any[]) => {
    if (event === 'session.append') hook = rest[rest.length - 1]
  }) as any)
  const mem = new Map<string, unknown>()
  const $: any = {
    state: {
      get: async (ref: any) => ({ value: mem.get(ref.key), version: 1 }),
      set: async (ref: any, value: unknown) => (mem.set(ref.key, value), { isSet: true, version: 2 }),
    },
  }
  return (e, next) => hook($, e, next)
}

const appendInput = (door: string, content: unknown[]): any => ({
  message: { type: 'user', role: 'user', content },
  door,
  origin: { kind: 'tool', tool: 'Read' },
  uuid: 'row-1',
})

test('session.append rewrites a tool result that holds a key', async () => {
  const hook = appendHook()
  const t = 'sk-ant-' + 'api03-' + fill(90)
  const row = [{ type: 'tool_result', tool_use_id: 'toolu_1', content: `{"k": "${t}"}` }]
  let seen: any
  await hook(appendInput('tool-result', row), async (e) => ((seen = e), { message: e.message, uuid: e.uuid }))
  expect(seen.message.content[0].content).toBe(`{"k": "${marker('anthropic_key', t.slice(-4))}"}`)
  expect(seen.message.content[0].tool_use_id).toBe('toolu_1')
  expect(seen.message.type).toBe('user')
  expect(seen.uuid).toBe('row-1')
})

test('session.append passes a clean row, and rows of other doors, through', async () => {
  const hook = appendHook()
  const clean = appendInput('tool-result', [{ type: 'tool_result', tool_use_id: 'toolu_1', content: 'hello' }])
  let seen: any
  const keep = async (e: any) => ((seen = e), { message: e.message, uuid: e.uuid })
  await hook(clean, keep)
  expect(seen).toBe(clean)
  const typed = appendInput('prompt', [{ type: 'text', text: `my key is ${'ghp' + '_' + fill(36)}` }])
  await hook(typed, keep)
  expect(seen).toBe(typed)
})

test('write guard: a mask marker is denied, normal writes pass', async ($, on) => {
  on('tool.call', () => ({ result: 'ok', text: 'ok' }) as never)
  const m = marker('anthropic_key', 'a1b2')
  const denied: any[] = await Promise.all([
    $.tool.call({ tool: 'Write' as const, file_path: '/tmp/x', content: `K=${m}` }),
    $.tool.call({ tool: 'Edit' as const, file_path: '/tmp/x', old_string: 'a', new_string: `K=${m}` }),
    $.tool.call({ tool: 'NotebookEdit' as const, notebook_path: '/tmp/x.ipynb', new_source: m }),
    $.tool.call({ tool: 'Bash' as const, command: `echo ${m} > /tmp/x` }),
  ])
  for (const r of denied) expect(String(r.deny).includes('masked secret')).toBe(true)

  const ok: any[] = await Promise.all([
    $.tool.call({ tool: 'Write' as const, file_path: '/tmp/x', content: 'hello [masked]' }),
    $.tool.call({ tool: 'Edit' as const, file_path: '/tmp/x', old_string: m, new_string: 'K=1' }),
    $.tool.call({ tool: 'Bash' as const, command: 'ls -la' }),
  ])
  for (const r of ok) expect(r.text).toBe('ok')
})

test('writtenText covers MultiEdit and ignores other tools', () => {
  const m = marker('jwt', 'zzzz')
  expect(hasMarker(m)).toBe(true)
  expect(hasMarker('[masked]')).toBe(false)
  expect(writtenText('MultiEdit', { edits: [{ old_string: 'a', new_string: 'b' }, { new_string: m }] })).toEqual(['b', m])
  expect(writtenText('Read', { file_path: m })).toEqual([])
})

test('push parsing', () => {
  const one = (cmd: string) => parsePushes(cmd)
  expect(one('git push')).toEqual([{ remote: 'origin', staged: false }])
  expect(one('git push origin main')).toEqual([{ remote: 'origin', staged: false }])
  expect(one('git push -u upstream feature')).toEqual([{ remote: 'upstream', staged: false }])
  expect(one('cd foo && git push')).toEqual([{ chdir: 'foo', remote: 'origin', staged: false }])
  expect(one('git -C /x push -u origin b')).toEqual([{ gitDir: '/x', remote: 'origin', staged: false }])
  expect(one('git add . && git commit -m "x && y; z" && git push')).toEqual([{ remote: 'origin', staged: true }])
  expect(one('cd "my dir" ; git -c core.pager=cat push --force fork')).toEqual([{ chdir: 'my dir', remote: 'fork', staged: false }])
  expect(one('echo "git push"')).toEqual([{ remote: 'origin', staged: false }])
  expect(one("bash -c 'git add -A && git push'")).toEqual([{ remote: 'origin', staged: true }])
  expect(one('git status')).toEqual([])
  expect(one('git log --oneline')).toEqual([])
  expect(one('git pushx')).toEqual([])
  expect(one('ls && git commit -m "later"')).toEqual([])
})

test('repoSpec turns ssh remotes into https', () => {
  expect(repoSpec('git@github.com:0xGondarxyz/secret-guard.git')).toBe('https://github.com/0xGondarxyz/secret-guard')
  expect(repoSpec('ssh://git@github.com/o/r.git')).toBe('https://github.com/o/r')
  expect(repoSpec('https://github.com/o/r.git')).toBe('https://github.com/o/r')
})

const diffOf = (file: string, lines: string[]): string =>
  `abc1234\n\ndiff --git a/${file} b/${file}\nnew file mode 100644\nindex 0000000..1111111\n--- /dev/null\n+++ b/${file}\n@@ -0,0 +1,${lines.length} @@\n${lines.map((l) => '+' + l).join('\n')}\n`

test('addedLines numbers the new file and skips headers', () => {
  const d = `diff --git a/a.txt b/a.txt\n--- a/a.txt\n+++ b/a.txt\n@@ -1,3 +1,4 @@\n one\n-two\n+TWO\n+++not a header\n three\n`
  expect(addedLines(d)).toEqual([
    { file: 'a.txt', line: 2, text: 'TWO' },
    { file: 'a.txt', line: 3, text: '++not a header' },
  ])
})

test('scanAdded: secrets, home paths, never values', () => {
  const t = 'sk-ant-' + 'api03-' + fill(90)
  const home = HOME + 'tester'
  const added = addedLines(
    diffOf('src/a.ts', ['const a = 1', `const k = "${t}"`, `const p = "${home}/work/x"`, `const o = "${HOME}other/x"`, `const ok = "${HOME}user/x"`, `const ci = "${HOME}runner/x"`]),
  )
  const found = scanAdded(added, home)
  expect(found).toEqual([
    { file: 'src/a.ts', line: 2, kind: 'anthropic_key' },
    { file: 'src/a.ts', line: 3, kind: 'home_path' },
    { file: 'src/a.ts', line: 4, kind: 'home_path' },
  ])
  const text = denyText(found, false)
  expect(text.includes(t)).toBe(false)
  expect(text.includes('src/a.ts:2 anthropic_key')).toBe(true)
  expect(text.includes('visibility unknown')).toBe(true)
  expect(text.endsWith('If these are false positives, ask the user to run /secret-guard allow, then push again.')).toBe(true)
})

test('scanAdded: a multi-line private key reports its first line', () => {
  const pem = `-----BEGIN ${'PRIVATE KEY'}-----\n${fill(64)}\n${fill(64)}\n-----END ${'PRIVATE KEY'}-----`
  const found = scanAdded(addedLines(diffOf('k.pem', ['x', ...pem.split('\n')])))
  expect(found).toEqual([{ file: 'k.pem', line: 2, kind: 'private_key' }])
})

// Push flow with a fake git and gh behind a mocked process.run.
type Fake = { calls: string[]; toasts: string[] }
function fakeGit(
  on: any,
  opts: { visibility?: string | 'missing'; log?: string; logFails?: boolean; diff?: string; untracked?: Record<string, string> },
): Fake {
  const f: Fake = { calls: [], toasts: [] }
  const out = (stdout: string, exitCode = 0) => ({ value: { exitCode, stdout, stderr: '', isStdoutTruncated: false, isStderrTruncated: false } }) as never
  on('process.run', (_$: any, e: any) => {
    const argv: string[] = e.argv
    f.calls.push(argv.join(' '))
    const joined = argv.join(' ')
    if (argv[0] === 'gh') {
      if (opts.visibility === 'missing') throw new Error('spawn gh ENOENT')
      return out((opts.visibility ?? 'PUBLIC') + '\n')
    }
    if (joined.includes('rev-parse --show-toplevel')) return out('/repo\n')
    if (joined.includes('remote get-url')) return out('git@github.com:someone/repo.git\n')
    if (joined.includes(' log ')) {
      if (opts.logFails) throw new Error('timed out')
      return out(opts.log ?? '')
    }
    if (joined.includes(' diff ')) return out(opts.diff ?? '')
    if (joined.includes('ls-files')) return out(Object.keys(opts.untracked ?? {}).join('\0') + '\0')
    if (argv[0] === 'head') return out((opts.untracked ?? {})[argv[argv.length - 1] as string] ?? '')
    return out('', 1)
  })
  on('ui.toast', (_$: any, e: any) => {
    f.toasts.push(e.text)
    return { value: undefined } as never
  })
  on('tool.call', () => ({ result: 'pushed', text: 'pushed' }) as never)
  return f
}

const push = ($: any, command = 'git push'): Promise<any> => $.tool.call({ tool: 'Bash' as const, command })

test('push: public repo with a key is denied without the value', async ($, on) => {
  mock.clock(on)
  mock.env(on, { HOME: HOME + 'tester' })
  const t = 'sk-ant-' + 'api03-' + fill(90)
  const f = fakeGit(on, { log: diffOf('.env', [`KEY=${t}`]) })
  const r = await push($)
  expect(String(r.deny).startsWith('secret-guard: push blocked, 1 finding.')).toBe(true)
  expect(String(r.deny).includes('.env:1 anthropic_key')).toBe(true)
  expect(String(r.deny).includes(t)).toBe(false)
  expect(String(r.deny).includes('/secret-guard allow')).toBe(true)
  expect(f.toasts).toEqual(['secret-guard: push blocked, 1 findings'])
  expect(f.calls.some((c) => c.startsWith('gh repo view https://github.com/someone/repo'))).toBe(true)
})

test('push: clean public repo and a repo with no findings go through', async ($, on) => {
  mock.clock(on)
  mock.env(on, { HOME: HOME + 'tester' })
  fakeGit(on, { log: diffOf('a.ts', ['const a = 1']) })
  expect((await push($)).text).toBe('pushed')
})

test('push: private and internal repos are allowed without a scan', async ($, on) => {
  mock.clock(on)
  mock.env(on, { HOME: HOME + 'tester' })
  const t = 'sk-ant-' + 'api03-' + fill(90)
  const f = fakeGit(on, { visibility: 'PRIVATE', log: diffOf('.env', [`KEY=${t}`]) })
  expect((await push($)).text).toBe('pushed')
  expect(f.calls.some((c) => c.includes(' log '))).toBe(false)
})

test('push: unknown visibility scans and says so', async ($, on) => {
  mock.clock(on)
  mock.env(on, { HOME: HOME + 'tester' })
  const t = 'ghp' + '_' + fill(36)
  fakeGit(on, { visibility: 'missing', log: diffOf('x.js', [`const t = "${t}"`]) })
  const r = await push($, 'cd foo && git push origin main')
  expect(String(r.deny).includes('visibility unknown')).toBe(true)
  expect(String(r.deny).includes('x.js:1 github_token')).toBe(true)
})

test('push: a failed scan allows the push and toasts', async ($, on) => {
  mock.clock(on)
  mock.env(on, { HOME: HOME + 'tester' })
  const f = fakeGit(on, { logFails: true })
  expect((await push($)).text).toBe('pushed')
  expect(f.toasts).toEqual(['secret-guard: scan failed, push allowed'])
})

test('push after add and commit also scans the working tree and untracked files', async ($, on) => {
  mock.clock(on)
  mock.env(on, { HOME: HOME + 'tester' })
  const t = 'glpat' + '-' + fill(24)
  fakeGit(on, {
    diff: diffOf('staged.ts', ['ok']).replace('abc1234\n\n', ''),
    untracked: { 'new.env': `TOKEN2=${t}\n`, 'blob.bin': 'a\0b' },
  })
  const withStage = await push($, 'git add . && git commit -m x && git push')
  expect(String(withStage.deny).includes('new.env:1 gitlab_token')).toBe(true)
  expect(String(withStage.deny).includes('blob.bin')).toBe(false)
  expect((await push($, 'git push')).text).toBe('pushed')
})

test('/secret-guard allow lets exactly one push through', async ($, on) => {
  mock.clock(on)
  mock.env(on, { HOME: HOME + 'tester' })
  const t = 'ghp' + '_' + fill(36)
  const f = fakeGit(on, { log: diffOf('.env', [`K=${t}`]) })
  expect(String((await push($)).deny).startsWith('secret-guard: push blocked')).toBe(true)
  const allowed: any = await ($ as any).command.run({ command: 'secret-guard', args: 'allow' })
  expect(allowed.text.includes('next push')).toBe(true)
  const status: any = await ($ as any).command.run({ command: 'secret-guard', args: '' })
  expect(status.text).toBe('secret-guard: 0 values masked this session, a pass is active (10 min left).')
  const before = f.calls.length
  expect((await push($)).text).toBe('pushed')
  expect(f.calls.length).toBe(before)
  expect(String((await push($)).deny).startsWith('secret-guard: push blocked')).toBe(true)
})
