# Dev insights: rca, changes, blame, friction

Prismor records every tool call an agent makes. Four views turn that record into
answers to the questions developers ask when an agent run goes sideways:

| Question | Command | Dashboard |
|---|---|---|
| Where did this run go wrong? | `prismor rca [session]` | Session page, "What went wrong" |
| What did this session change? | `prismor session <id> --changes` | Session page, "Changes" |
| Which session wrote this file or line, and why? | `prismor blame <path>[:<line>]` | Files page |
| What do agents keep tripping over here? | `prismor friction` | Overview, "Agent friction" card |

All four read the local store and the agent's own transcript. They don't change
policy or screening, and everything they print goes through the same redaction
as [`prismor query`](query-your-data.md).

## Where outcomes come from

When a Claude Code call fails, Claude fires `PostToolUseFailure`, not
`PostToolUse`. Before 1.61.0 Prismor didn't subscribe to it, so a failed call
was stored as an allowed call with no result. For Claude these views read the
session transcript (`transcript_path`, on every hook payload), which records
each result with `is_error` and marks hook denials. A call that a policy denied
is not counted as a failure.

Agents often pipe test runs (`pytest -q 2>&1 | tail -40`), so the shell exits 0
even when tests failed. A call is also counted as failed when its output
carries an unambiguous runner summary: pytest, jest, go, cargo, tsc, npm,
`command not found`, or a Python traceback.

For agents whose hooks don't report outcomes, the views fall back to the events
table: the calls are known, the failures aren't, and `rca` says so.

## `prismor rca [session]`

What went wrong in one session. Without an id it uses the latest session.

- **First failure**, with the three calls before it.
- **Retry loops**: the same call failing 3 or more times, with the time span and
  tokens spent.
- **Reverted edits**: an edit that restores exactly what an earlier edit
  replaced.

```
$ prismor rca d0c441fc…
4 calls · 4 failed · 0 denied

Loop: failed 4× (09:38:08–09:38:16)
  Bash: python3 -c 'import yaml_extras'
    → ModuleNotFoundError: No module named 'yaml_extras'
```

Flags: `--workspace`, `--json`.

![Retry loop in the session panel](dev-insights/session-retry-loop.jpg)

## `prismor session <id> --changes`

What a session actually touched: each file it wrote as a red/green diff with
+N −M, the commands it ran, and a drafted PR description built from the
prompts, files and test runs. For Claude the diff comes from Claude's own
`structuredPatch`, so line numbers match the editor.

![First failure and changes](dev-insights/session-first-failure-changes.jpg)

## `prismor blame <path>[:<line>]`

Which agent session wrote a file, or one line of it, and what that session was
asked. The dashboard's **Files** page lists every file an agent wrote as a
folder tree.

Agents often write files from the shell (`cat > f <<'EOF'`, `>>`, `tee`). Those
never become file-write events, so blame finds them by parsing the shell
commands and marks them **shell**. The text they replaced was never recorded.

The first `blame` on a large store builds an index (about 11 s on a 2 GB
store); later calls take a fraction of a second.

Flags: `--workspace`, `--json`.

![Files page](dev-insights/files-page.jpg)

## `prismor friction`

Failures that recur across sessions, grouped by command
(`cd x && FOO=1 python3 -m pytest -q | tail` counts as `python3 -m pytest`) and
printed as lines you can paste into `AGENTS.md`, so the next agent doesn't have
to rediscover the fix. A failure has to appear in at least 2 sessions.

```
$ prismor friction --all
Recurring failures, last 14 days (4 sessions). Paste into AGENTS.md:

- `python3 -m pytest` has failed in 3 sessions: ModuleNotFoundError: No module named 'invoice'
```

Flags: `--days` (default 14), `--all` (every workspace), `--workspace`, `--json`.

![Agent friction card](dev-insights/overview-friction.jpg)

## Live retry-loop warning (Claude Code)

`install-hooks` registers `PostToolUseFailure` for Claude Code. Only failed calls
reach it, so successful calls cost nothing. On the third identical failure in a
session, the agent is told:

> Prismor: this exact Bash call has now failed 3 times in this session
> (ModuleNotFoundError: No module named 'yaml_extras'). Retrying it unchanged
> will fail again: read the error, check the assumption behind the call, and
> change approach.

It's advisory: nothing is blocked. Existing installs get it after re-running
`prismor setup` or `prismor install-hooks --agent claude`.

## Limits

- Non-Claude agents: hook payloads carry no result status, so `rca` reports
  their calls without failures.
- Blame has no commit linkage: transcripts carry the branch, not the commit.
- Shell writes are found in the most recent 3,000 redirecting commands.

See also: [Dashboard](dashboard.md) · [Query your data](query-your-data.md) ·
[CLI reference](cli-reference.md#visibility).
