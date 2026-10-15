"""The active-mirror marker that stops mirrored calls being screened twice."""
import json
import os

import pytest

from prismor.runtime import mirror


@pytest.fixture(autouse=True)
def isolated_home(tmp_path, monkeypatch):
    monkeypatch.setenv("PRISMOR_HOME", str(tmp_path / "home"))
    yield


@pytest.fixture()
def ws(tmp_path):
    d = tmp_path / "ws"
    d.mkdir()
    return d


def test_no_marker_means_nothing_is_skipped(ws):
    assert mirror.active_tools(ws) == []
    assert mirror.already_screened("mcp__prismor__Bash", ws) is False


def test_marker_makes_mirrored_tools_recognised(ws):
    mirror.mark_active(ws)
    assert set(mirror.active_tools(ws)) == set(mirror.mirror_tool_names())
    assert mirror.already_screened("mcp__prismor__Bash", ws) is True
    assert mirror.already_screened("mcp__anything__Read", ws) is True


def test_native_and_unrelated_mcp_tools_are_never_skipped(ws):
    mirror.mark_active(ws)
    assert mirror.already_screened("Bash", ws) is False          # native: hooks own it
    assert mirror.already_screened("mcp__posthog__exec", ws) is False
    assert mirror.already_screened("", ws) is False


def test_unrelated_workspace_is_not_covered(ws, tmp_path):
    other = tmp_path / "other"
    other.mkdir()
    mirror.mark_active(ws)
    assert mirror.already_screened("mcp__prismor__Bash", other) is False


def test_a_global_hook_install_still_matches(ws):
    """The hook layer's workspace routinely differs from the gateway's — a
    global install reports the home directory while the gateway reports the
    project. Exact-equality keying silently disabled the dedup entirely."""
    mirror.mark_active(ws)
    assert mirror.already_screened("mcp__prismor__Bash", ws.parent) is True


def test_agent_cwd_is_used_when_the_hook_workspace_is_unrelated(ws, tmp_path):
    other = tmp_path / "elsewhere"
    other.mkdir()
    mirror.mark_active(ws)
    assert mirror.already_screened("mcp__prismor__Bash", other, cwd=str(ws)) is True


def test_a_subdirectory_of_the_mirrored_workspace_matches(ws):
    sub = ws / "pkg" / "mod"
    sub.mkdir(parents=True)
    mirror.mark_active(ws)
    assert mirror.already_screened("mcp__prismor__Read", ws, cwd=str(sub)) is True


def test_clearing_restores_screening(ws):
    mirror.mark_active(ws)
    mirror.clear_active(ws)
    assert mirror.already_screened("mcp__prismor__Bash", ws) is False


def test_stale_marker_from_a_dead_gateway_is_ignored_and_removed(ws):
    """A crashed gateway must not leave behind a rule that silently
    un-screens real tool calls."""
    mirror.mark_active(ws)
    path = mirror._marker_path(ws)
    data = json.loads(path.read_text())
    data["pid"] = 2 ** 22           # not a live pid
    path.write_text(json.dumps(data))
    assert mirror.already_screened("mcp__prismor__Bash", ws) is False
    assert not path.exists(), "stale marker should be cleaned up"


def test_corrupt_marker_fails_towards_screening(ws):
    mirror.mark_active(ws)
    mirror._marker_path(ws).write_text("{not json")
    assert mirror.already_screened("mcp__prismor__Bash", ws) is False


def test_marker_records_the_live_pid(ws):
    mirror.mark_active(ws)
    assert json.loads(mirror._marker_path(ws).read_text())["pid"] == os.getpid()


def test_instruction_files_are_redelivered_while_mirror_serves_read(ws, tmp_path, monkeypatch):
    """`mirror on` denies native Read, and Claude Code will not load a CLAUDE.md
    a Read deny covers: project instructions silently disappeared."""
    monkeypatch.setenv("HOME", str(tmp_path / "userhome"))
    (ws / "CLAUDE.md").write_text("Always use tabs in this repo.\n")
    (ws / "AGENTS.md").write_text("codex-only notes\n")
    assert mirror.instruction_context(ws) == ""           # no live mirror: Claude loads it
    mirror.mark_active(ws)
    ctx = mirror.instruction_context(ws)
    assert "Always use tabs in this repo." in ctx
    assert "codex-only notes" not in ctx                  # Claude Code never loads AGENTS.md
    assert mirror.instruction_context(ws, agent="codex") == ""
