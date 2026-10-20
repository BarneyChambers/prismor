"""A local agents.yaml observe must not clear a hook started in enforce."""

import tempfile
import unittest
from pathlib import Path

from prismor.runtime.hooks import should_block
from prismor.runtime.policy_engine import PolicyEngine
from prismor.runtime.runtime import evaluate_tool_call


class TestLocalAgentMode(unittest.TestCase):
    def test_agents_set_is_a_self_edit(self):
        with tempfile.TemporaryDirectory() as tmp:
            eng = PolicyEngine(workspace=Path(tmp))
            findings = eng.evaluate(
                {"type": "shell", "command": "prismor agents set claude --mode observe"},
                index=0,
            )
        self.assertIsNotNone(
            should_block(findings, {"type": "shell", "agent_event": "PreToolUse"})
        )

    def test_local_observe_does_not_downgrade_enforce(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            cfg = ws / ".prismor"
            cfg.mkdir()
            (cfg / "agents.yaml").write_text(
                "agents:\n  claude:\n    mode: observe\n", encoding="utf-8"
            )
            decision = evaluate_tool_call(
                event={
                    "type": "shell",
                    "command": "rm -rf /",
                    "agent_event": "PreToolUse",
                },
                workspace=ws,
                agent="claude",
                mode="enforce",
                persist=False,
                record=False,
                register_agent=False,
            )
        self.assertIsNotNone(decision.blocking)
        self.assertFalse(decision.allow)
