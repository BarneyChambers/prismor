# Hermes Agent Integration

Prismor governs [Hermes Agent](https://hermes-agent.nousresearch.com) (Nous Research) with two Python plugins that Hermes loads into its own process:

| Plugin | Installed by | What it does |
|---|---|---|
| `prismor` | `prismor install-hooks --agent hermes` | Runs every tool call through the Prismor policy engine before it executes, records the result afterwards, and screens each user turn. |
| `prismor-cloak` | `prismor cloak install --agent hermes` | Secret cloaking: blocks raw secrets in tool calls, substitutes `@@SECRET:<name>@@` placeholders at execution time, and scrubs real values out of tool output. |

Both were verified live against Hermes Agent v0.19.0.

---

## How Hermes loads plugins

Hermes loads a plugin directory (`plugin.yaml` + `__init__.py` with `register(ctx)`) from:

- `~/.hermes/plugins/<name>/` (or `$HERMES_HOME/plugins/`), and
- `./.hermes/plugins/<name>/` only when `HERMES_ENABLE_PROJECT_PLUGINS=1` is set in the environment Hermes runs in.

Either way a plugin loads only when its name is listed under `plugins.enabled` in `~/.hermes/config.yaml`. Prismor's installers add the name there (creating `config.yaml` if it does not exist, never rewriting one it cannot parse).

After installing, both commands ask Hermes (`hermes plugins list`) whether it will load the plugin. If it will not, they say `NOT active` and why, instead of `Installed`.

---

## Policy hooks

```bash
prismor install-hooks --agent hermes --scope global --mode observe   # ~/.hermes/plugins/prismor/
prismor install-hooks --agent hermes --scope global --mode enforce
```

`--scope project` writes `./.hermes/plugins/prismor/` instead; Hermes then needs `HERMES_ENABLE_PROJECT_PLUGINS=1`.

The plugin registers three Hermes hooks and sends each to `prismor hook-dispatch --agent hermes`:

| Hermes hook | Prismor event | Effect |
|---|---|---|
| `pre_tool_call` | `PreToolUse` | In enforce mode a blocked call returns `{"action": "block"}`; the model receives Prismor's reason and the unblock steps as the tool result. |
| `post_tool_call` | `PostToolUse` | Records the result. Calls Prismor already blocked are skipped. |
| `pre_llm_call` | `UserPromptSubmit` | Screens the user's message. Hermes cannot stop a turn from this hook, so a flagged message is reported to the model as context telling it not to act on it. |

Hermes tool names map to Prismor event types: `terminal` and `execute_code` are shell commands, `read_file` is a file read, `write_file` and `patch` are file writes (the path is taken from a V4A patch when needed), and `web_extract` / `web_search` / `browser_navigate` are network calls.

If the Prismor hook crashes or takes longer than 60 seconds, Hermes logs a warning and runs the call. That matches how Hermes treats every plugin error.

Check it with:

```bash
hermes plugins list --plain --no-bundled   # "enabled  user  1.0.0  prismor"
prismor sessions                            # sessions show agent=hermes
```

Remove it with `prismor uninstall-hooks --agent hermes --scope global`.

---

## Secret cloaking

```bash
prismor cloak install --agent hermes --scope global   # ~/.hermes/plugins/prismor-cloak/
prismor cloak add stripe_key                          # value read from stdin / hidden prompt
```

The default `--scope project` writes `./.hermes/plugins/prismor-cloak/`, which Hermes loads only with `HERMES_ENABLE_PROJECT_PLUGINS=1`.

| Hermes hook | What it does |
|---|---|
| `pre_gateway_dispatch` | A raw secret pasted into a gateway message (Telegram, etc.) is vaulted and the message is dropped with the placeholder form; prefix the message with `!!allow ` to send it anyway. |
| `pre_tool_call` | A raw secret in tool arguments is vaulted and the call is blocked with the placeholder to use instead. A placeholder that is not registered is blocked. |
| `tool_execution` middleware | Substitutes registered placeholders with their values in the copy of the arguments that actually executes. The transcript, policy hooks and approvals only ever see the placeholder. |
| `transform_terminal_output`, `transform_tool_result` | Replace any registered secret value in the output with its placeholder before the model sees it. |

Decloaking needs Hermes' `tool_execution` middleware. On a Hermes too old to have it, calls that use a placeholder are blocked with a message saying so, rather than run with the literal placeholder.

`prismor cloak status` shows whether the plugin directory is installed; `prismor cloak uninstall --agent hermes --scope global` removes it.

### pip entry point

`pyproject.toml` also declares a `hermes_agent.plugins` entry point (`prismor-cloak`). Hermes only sees it when `prismor` is installed into Hermes' own virtualenv, and it still has to be listed in `plugins.enabled`. The filesystem install above is the supported path.

### Code

- `prismor/runtime/hooks.py`: the generated `prismor` policy plugin (`_HERMES_PLUGIN_PY`) and its installer.
- `prismor/runtime/cloaking/hermes_plugin_entry.py`: the cloaking plugin. `hermes-plugin/__init__.py` is a verbatim copy so the filesystem plugin loads without importing `prismor`; `tests/test_hermes_plugin_sync.py` fails if they drift.
- `prismor/runtime/cloaking/hermes_installer.py`: `install()` / `uninstall()` / `status()` for the cloaking plugin.
