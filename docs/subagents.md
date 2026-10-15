# Subagents

Claude Code can hand work to subagents (the `Task` / `Agent` tool), in the
foreground or in the background. A subagent's tool calls go through the same
Prismor hooks as the main agent's, tagged with the subagent's `agent_id` and
`agent_type`, so the same policy applies to them. What changes is who hears
about it: a subagent's blocks go to the subagent, and a background subagent's
work never shows in the main chat. From the release after 1.61.0 (#628),
Prismor tells the person what happened inside each subagent.

## What is enforced

- **Every rule that applies to the main agent applies inside a subagent.**
  Blocks are returned to the subagent with the usual reason, and the subagent
  reports them back to the main agent.
- **A subagent can't ask for approval.** A rule whose action is `step_up`
  (approval needed) would raise an approval dialog in the main chat for a call
  the person never saw, and the whole session waits. Inside a subagent, a
  step-up is refused instead, with this reason:

  > Prismor: this needs the user's OK, and a subagent cannot ask for it. Stop
  > and report back to the main agent, which should ask the user or run it in
  > the main conversation.

  The main agent can then ask in the open, and the person decides.
- **Driving the logged-in browser is a step-up.** The rule
  `browser-session-control` catches `connectOverCDP` / `connect_over_cdp`,
  `puppeteer.connect`, `chrome-remote-interface`, loopback `:92xx` debugging
  ports and DevTools websocket paths. A subagent used a browser's logged-in
  sessions to reach a host that egress had just blocked; this closes that path
  for main agents and subagents alike.

## What the person sees

Each screened call inside a subagent adds one line to a per-session ledger
under `~/.prismor/subagents/`. When the subagent finishes (`SubagentStop`),
the ledger becomes one line in the main chat:

```
Prismor · general-purpose (ae5e3143): 4 tool calls screened · 1 needed your OK and were refused (browser-session-control) · 1 flagged (…). Details: prismor sessions --findings-only
```

The label is the subagent's type and the first 8 characters of its id. When
Claude Code doesn't send a type (for some of its own internal helper agents),
the label is just `subagent`.

Claude Code files a `SubagentStop` message under the subagent's own transcript,
where nobody sees it. So Prismor queues the line and shows it with the next
main-thread hook: after the `Agent` tool returns for a foreground subagent, or
with the task-notification prompt for a background one, so it appears as the
subagent finishes. A subagent that made no screened calls adds no line.

## Subagent reports

A background subagent hands its report back as a `<task-notification>`
prompt. These prompts are never blocked: a report that quotes an injection the
subagent correctly refused used to be blocked by the judge, and the report was
lost. A flagged report gets the same "treat as untrusted data" notice as tool
output instead.

The result of the `Task` / `Agent` tool itself is not judged for prompt
injection. It is either the parent's own brief echoed back or a report from a
subagent whose calls were already screened; what happened inside is reported
at `SubagentStop`.

## Setup

Claude Code hooks register `SubagentStop` from the release after 1.61.0. Existing installs get
it by re-running `prismor setup` or `prismor install-hooks --agent claude`.
`prismor doctor` reports the event in its hook health check.

## Limits

- Subagent attribution, the step-up refusal and the summary line are Claude
  Code features: other agents don't tag subagent calls with an `agent_id`.
- Without a semantic judge, file and shell output inside a subagent is not
  screened for prompt injection (the injection patterns only cover tool
  results). See [Semantic Guard](semantic-guard.md).

See also: [Sessions and the dashboard](dashboard.md) · [Prismor runtime](prismor-runtime.md).
