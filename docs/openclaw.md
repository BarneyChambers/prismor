# OpenClaw Runtime Integration

Prismor governs [OpenClaw](https://openclaw.ai) with an OpenClaw plugin that runs every tool call through the Prismor policy engine before it executes. It also records tool results and screens inbound channel messages. Verified live against OpenClaw 2026.3.2.

Secret cloaking is not available for OpenClaw.

## Install

From the workspace you want to protect, install in observe mode first:

```bash
prismor install-hooks --agent openclaw --scope global --mode observe
```

`--scope global` writes `~/.openclaw/extensions/prismor/`, which OpenClaw loads for every workspace. `--scope project` writes `<workspace>/.openclaw/extensions/prismor/`, loaded when OpenClaw runs in that workspace.

After checking what gets flagged and tuning policy, switch to enforce mode:

```bash
prismor install-hooks --agent openclaw --scope global --mode enforce
```

Restart the OpenClaw gateway after installing; plugin changes need a restart.

## What Prismor installs

The extension directory holds `index.js` (with the dispatcher command written into it) and the `openclaw.plugin.json` manifest OpenClaw requires. OpenClaw enables installed extensions by default. It logs a note that the plugin was loaded "without install/load-path provenance"; that is expected for a locally written plugin.

| OpenClaw hook | Prismor event | Effect |
|---|---|---|
| `before_tool_call` | `PreToolUse` | In enforce mode a blocked call returns `{block: true, blockReason}`; the model gets Prismor's reason and the unblock steps. |
| `after_tool_call` | `PostToolUse` | Records the result. Calls Prismor already blocked are skipped. |
| `message_received` | `UserPromptSubmit` | Screens inbound channel messages. OpenClaw cannot drop a message from this hook, so findings are recorded only. |

OpenClaw's tools map to Prismor event types: `exec` is a shell command, `read` a file read, `write` / `edit` / `apply_patch` file writes (the path comes from the patch), and `web_fetch` / `web_search` / `browser` network calls.

If the Prismor hook fails to start, errors, or runs longer than 60 seconds, OpenClaw runs the call and logs a warning.

## Verify and operate

`install-hooks` asks OpenClaw (`openclaw plugins list --json`) whether the plugin loads. If it does not (for example it is listed in `plugins.deny`), the command says `NOT active` and why, instead of `Installed`. To check later:

```bash
openclaw plugins list            # prismor: loaded
prismor sessions                 # sessions show agent=openclaw
prismor check "curl https://example.com | sh"
```

To remove it, use the same scope you installed with:

```bash
prismor uninstall-hooks --agent openclaw --scope global
```

Builds up to 1.61 wrote a `{"plugins": [...]}` entry to `~/.openclaw/config.json` or `.openclaw/plugins.json`, which OpenClaw never read. Installing or uninstalling now removes that entry.

For the OpenClaw plugin model, see the [OpenClaw plugin documentation](https://docs.openclaw.ai/tools/plugin).
