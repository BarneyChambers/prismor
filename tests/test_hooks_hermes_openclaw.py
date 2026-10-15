"""OpenClaw and Hermes Agent load a plugin module, not a JSON hook config.

Up to 1.61 Prismor wrote ~/.openclaw/config.json and ~/.hermes/config.json
{"plugins": [...]} files neither agent reads, so both ran unguarded while
`install-hooks` said "Installed". These pin the formats the agents load
(verified live against openclaw 2026.3.2 and Hermes Agent v0.19.0).
"""
import importlib.util
import json
import sys
from pathlib import Path

import pytest
import yaml

from prismor.runtime import hooks

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def home(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setattr(Path, "home", staticmethod(lambda: home))
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.delenv("HERMES_HOME", raising=False)
    monkeypatch.delenv("HERMES_ENABLE_PROJECT_PLUGINS", raising=False)
    monkeypatch.setattr(hooks.shutil, "which", lambda name, *a, **k: None)  # never ask a real agent
    return home


def _install(agent, scope, ws):
    return hooks.install_hooks(repo_root=ROOT, workspace=ws, agent=agent, scope=scope, mode="enforce")


def test_openclaw_writes_a_loadable_extension_and_cleans_legacy(home, tmp_path):
    legacy = home / ".openclaw" / "config.json"
    legacy.parent.mkdir()
    legacy.write_text(json.dumps({"plugins": ["/old/prismor/runtime/openclaw-plugin"], "other": 1}))
    [res] = _install("openclaw", "global", tmp_path)
    plugin = home / ".openclaw" / "extensions" / "prismor"
    assert res["configPath"] == str(plugin / "index.js") and res["loadWarning"] is None
    assert json.loads((plugin / "openclaw.plugin.json").read_text())["id"] == "prismor"
    assert "before_tool_call" in (plugin / "index.js").read_text()
    assert json.loads(legacy.read_text()) == {"plugins": [], "other": 1}
    assert hooks.hook_installed("openclaw", "global", tmp_path)
    [out] = hooks.uninstall_hooks(repo_root=ROOT, workspace=tmp_path, agent="openclaw", scope="global")
    assert out["removed"] and not plugin.exists()


def test_hermes_writes_plugin_and_enables_it(home, tmp_path):
    cfg = home / ".hermes" / "config.yaml"
    cfg.parent.mkdir()
    cfg.write_text("model:\n  default: gpt-5-nano\n")
    _install("hermes", "global", tmp_path)
    plugin = home / ".hermes" / "plugins" / "prismor"
    assert yaml.safe_load((plugin / "plugin.yaml").read_text())["name"] == "prismor"
    data = yaml.safe_load(cfg.read_text())
    assert data["plugins"]["enabled"] == ["prismor"] and data["model"]["default"] == "gpt-5-nano"
    hooks.uninstall_hooks(repo_root=ROOT, workspace=tmp_path, agent="hermes", scope="global")
    assert not plugin.exists() and yaml.safe_load(cfg.read_text())["plugins"]["enabled"] == []


def test_hermes_creates_missing_config_but_never_clobbers_an_unreadable_one(home, tmp_path):
    _install("hermes", "global", tmp_path)
    assert yaml.safe_load((home / ".hermes" / "config.yaml").read_text()) == {"plugins": {"enabled": ["prismor"]}}
    cfg = home / ".hermes" / "config.yaml"
    cfg.write_text("model: [unclosed\n")
    _install("hermes", "global", tmp_path)
    assert cfg.read_text() == "model: [unclosed\n"


def test_hermes_project_scope_warns_without_project_plugins(home, tmp_path, monkeypatch):
    [res] = _install("hermes", "project", tmp_path)
    assert "HERMES_ENABLE_PROJECT_PLUGINS" in res["loadWarning"]
    monkeypatch.setenv("HERMES_ENABLE_PROJECT_PLUGINS", "1")
    [res] = _install("hermes", "project", tmp_path)
    assert res["loadWarning"] is None


@pytest.mark.parametrize("agent,tool,args,want", [
    ("hermes", "terminal", {"command": "ls"}, ("shell", "command", "ls")),
    ("hermes", "execute_code", {"code": "import os"}, ("shell", "command", "import os")),
    ("hermes", "read_file", {"path": ".env"}, ("file_read", "path", ".env")),
    ("hermes", "write_file", {"path": "a.txt", "content": "x"}, ("file_write", "path", "a.txt")),
    ("hermes", "patch", {"mode": "patch", "patch": "*** Begin Patch\n*** Update File: .prismor/policy.yaml\n"},
     ("file_write", "path", ".prismor/policy.yaml")),
    ("openclaw", "exec", {"command": "ls"}, ("shell", "command", "ls")),
    ("openclaw", "edit", {"path": "b.py", "oldText": "a", "newText": "b"}, ("file_write", "content", "b")),
    ("openclaw", "apply_patch", {"input": "*** Begin Patch\n*** Add File: ~/.ssh/authorized_keys\n"},
     ("file_write", "path", "~/.ssh/authorized_keys")),
    ("openclaw", "web_fetch", {"url": "https://x.test"}, ("network", "url", "https://x.test")),
])
def test_native_tool_names_normalize(agent, tool, args, want, tmp_path):
    for ev in ("PreToolUse", "before_tool_call"):
        event = hooks.normalize_payload(agent=agent, workspace=tmp_path, payload={
            "hookEvent": ev, "toolName": tool, "toolInput": args, "sessionId": "s"})["event"]
        assert (event["type"], event[want[1]]) == (want[0], want[2])
        assert event["agent"] == agent and event["agent_event"] == "PreToolUse"
    post = hooks.normalize_payload(agent=agent, workspace=tmp_path, payload={
        "hookEvent": "PostToolUse", "toolName": tool, "toolInput": args, "sessionId": "s", "result": "ok"})["event"]
    assert post["agent_event"] == "PostToolUse" and post["response"] == "ok"


def test_generated_hermes_plugin_blocks_on_exit_2(home, tmp_path):
    _install("hermes", "global", tmp_path)
    src = (home / ".hermes" / "plugins" / "prismor" / "__init__.py").read_text()
    fake = f'{sys.executable} -c "import sys; sys.stderr.write(\\"nope\\"); sys.exit(2)"'
    src = "\n".join(f"PRISMOR_COMMAND = {json.dumps(fake)}" if l.startswith("PRISMOR_COMMAND = ") else l
                    for l in src.splitlines())
    mod_path = tmp_path / "plugin_under_test.py"
    mod_path.write_text(src)
    spec = importlib.util.spec_from_file_location("plugin_under_test", mod_path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    # Hermes 0.19 passes turn_id, api_request_id, middleware_trace...
    assert mod._pre_tool_call(tool_name="terminal", args={"command": "x"}, turn_id="t", middleware_trace=[]) == {
        "action": "block", "message": "nope"}
    assert mod._post_tool_call(tool_name="terminal", status="blocked") is None
