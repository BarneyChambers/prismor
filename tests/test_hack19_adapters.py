"""Adapter entry points must carry the argument the policy judges."""

import sys
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
for _rel in (
    "adapters/claude-agent-sdk",
    "adapters/browser-use",
    "adapters/openai-agents",
    "adapters/crewai",
):
    _path = str(_ROOT / _rel)
    if _path not in sys.path:
        sys.path.insert(0, _path)

from prismor.runtime.runtime import _retype_adapter_file_call


class TestAdapterPayloads(unittest.TestCase):
    def test_claude_multiedit_and_websearch(self):
        from prismor_claude_agent_sdk import _normalize
        event = _normalize("MultiEdit", {
            "file_path": "a.txt",
            "edits": [{"new_string": "connect_over_cdp('http://127.0.0.1:9222')"}],
        })
        self.assertIn("127.0.0.1:9222", event["content"])
        search = _normalize("WebSearch", {"query": "http://169.254.169.254/latest"})
        self.assertIn("169.254.169.254", search["url"])

    def test_browser_use_content_and_new_tab(self):
        from prismor_browser_use import _build_event
        event = _build_event(
            action_name="write_file",
            params={"path": "notes.txt", "content": "SECRET-BODY"},
            session_id="s",
            agent="browser",
            subject=None,
        )
        self.assertEqual(event["content"], "SECRET-BODY")
        nav = _build_event(
            action_name="navigate",
            params={"url": "https://example.com", "new_tab": "http://169.254.169.254/"},
            session_id="s",
            agent="browser",
            subject=None,
        )
        self.assertIn("169.254.169.254", nav["url"])

    def test_openai_payload_includes_keys(self):
        from prismor_openai import _payload_from_tool_input
        self.assertIn("rm -rf /", _payload_from_tool_input({"rm -rf /": "ok"}))

    def test_retype_reads_metadata_args(self):
        event = {
            "type": "shell",
            "command": "ok",
            "metadata": {"framework": "google-adk", "tool_name": "read_file",
                         "args": {"path": "/home/u/.env"}},
        }
        _retype_adapter_file_call(event)
        self.assertEqual(event["type"], "file_read")
        self.assertIn(".env", event["path"])

    def test_crewai_wraps_run_and_does_not_mark_slots(self):
        from prismor_crewai import prismor_guard_tool

        class Tool:
            name = "shell"
            def func(self, cmd):
                return ("FUNC", cmd)
            def _run(self, cmd):
                return ("RUN", cmd)

        tool = prismor_guard_tool(Tool(), workspace=str(Path("/tmp")), mode="enforce")
        self.assertNotEqual(tool._run("rm -rf /"), ("RUN", "rm -rf /"))
        self.assertNotEqual(tool.func("rm -rf /"), ("FUNC", "rm -rf /"))

        class Slot:
            __slots__ = ("name",)
            def __init__(self):
                self.name = "shell"
            def func(self, cmd):
                return ("SLOT", cmd)

        slot = prismor_guard_tool(Slot(), workspace=str(Path("/tmp")), mode="enforce")
        self.assertFalse(getattr(slot, "__prismor_guarded__", False))
