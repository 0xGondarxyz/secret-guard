# secret-guard

A Claude Code mod that keeps secrets out of the conversation and out of public repos.

1. It masks API keys, tokens and passwords in every tool result before Claude reads them.
2. It blocks a `git push` that would leak a secret or a home path to a public repo.

## Install

```
/plugin marketplace add 0xGondarxyz/secret-guard
/plugin install secret-guard@secret-guard
```

Or try it without installing:

```
git clone https://github.com/0xGondarxyz/secret-guard
claude --plugin-dir secret-guard
```

Mods are not sandboxed. They run with the same access as Claude Code. Read the source before you install any mod, including this one.

## Masking

Every tool result is checked before it is stored: built-in tools, MCP tools, the main thread and subagents. Each secret becomes a marker. The rest of the text is kept byte for byte.

```
ANTHROPIC_API_KEY=[masked anthropic_key ...a1b2]
```

The marker shows the kind and the last 4 characters.

What it finds:

- Prefixed tokens: Anthropic, OpenAI, GitHub (`ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_`, `github_pat_`), AWS `AKIA`, Google `AIza`, Slack, Stripe, GitLab, Apify, Notion, Hugging Face, Replicate, npm, Telegram bot tokens, JWTs.
- PEM private key blocks (the whole block).
- Bearer tokens (`Bearer` followed by 20 or more token characters).
- The password in a URL such as `postgres://user:PASSWORD@host`.
- Assignments: a name that contains `api_key`, `secret`, `token`, `password`, `credential`, `private_key`, `access_key` or `auth`, then `=` or `:`, then a value of 16 or more characters with a letter and a digit. Only the value is masked.

What it leaves alone: placeholders (`your_...`, `xxx...`, `<...>`, `${...}`, `process.env...`, `os.environ...`, `changeme`, `example`), git SHAs, UUIDs, numbers, file paths, npm `sha512-` integrity hashes.

Claude now sees markers, so it could write one back over the real secret. The write guard stops that. Write, Edit, MultiEdit and NotebookEdit are denied when the new text holds a marker, and so is a Bash command that holds one. Claude is told to edit around the line or ask you to change that value.

## Push check

When a Bash command runs `git push`, secret-guard checks before it runs:

1. It finds the repo (`git -C <dir>`, a leading `cd <dir> &&`, or the session folder) and the remote (default `origin`).
2. It asks `gh repo view` for the visibility. `PRIVATE` or `INTERNAL`: the push goes through, no scan. `PUBLIC` or unknown (no `gh`, not GitHub, an error): it scans.
3. It scans the added lines of every local commit the remote does not have. If the same command also runs `git add` or `git commit`, it scans the working tree diff and the untracked files too (not ignored, under 1 MB, not binary).
4. It looks for the same secrets as masking, plus absolute home paths: your real home folder and any `/home/<name>/` or `/Users/<name>/` path. `/home/user/` and `/home/runner/` are ignored.

With findings, the push is denied. The text lists up to 10 as `file:line kind`. It never prints the secret. A toast says `secret-guard: push blocked, N findings`. When the visibility was unknown, the text says so.

If the scan itself fails (git error, timeout of about 5 seconds), the push is allowed and a toast says `secret-guard: scan failed, push allowed`.

## Commands

| Command | What it does |
| --- | --- |
| `/secret-guard` | Shows how many values were masked this session and whether a pass is active. |
| `/secret-guard allow` | Lets the next push skip the scan. The pass lasts 10 minutes and works once. |

For a false positive: run `/secret-guard allow`, then push again.

## Limits

- Detection is by pattern. A secret with no known prefix and no telling name (for example a bare random string) is not masked.
- What the model reads is masked. The engine stores a tool result's structured record (what the screen draws) as made, so the transcript file on disk can still hold the raw output.
- Rows that are not tool results (your prompts, attachments) are not masked.
- `git log` output is cut at 4 MB. A very large unpushed history is only scanned in part.
- Pushes started outside Claude Code's Bash tool (hooks, scripts it launches) are not seen.
- A file that must contain the literal marker text cannot be written by Claude. Ask Claude to leave it to you.

No options.

## License

MIT
