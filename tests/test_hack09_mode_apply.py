"""An agent must not compile the observe preview that turns the floor off."""

import os
import sys
import tempfile
import unittest
from pathlib import Path

from prismor.runtime.hooks import should_block
from prismor.runtime.policy_engine import PolicyEngine


class TestModeApply(unittest.TestCase):
    def test_shell_command_is_a_self_edit(self):
        with tempfile.TemporaryDirectory() as tmp:
            eng = PolicyEngine(workspace=Path(tmp))
            findings = eng.evaluate(
                {"type": "shell", "command": "prismor mode apply dev-safe --observe"},
                index=0,
            )
        self.assertIsNotNone(
            should_block(findings, {"type": "shell", "agent_event": "PreToolUse"})
        )

    def test_cli_observe_refuses_non_tty(self):
        import subprocess
        env = os.environ.copy()
        root = Path(__file__).resolve().parents[1]
        env["PYTHONPATH"] = str(root) + (
            os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else ""
        )
        env["PRISMOR_HOME"] = tempfile.mkdtemp()
        r = subprocess.run(
            [sys.executable, "-m", "prismor.runtime.immunity_cli",
             "mode", "apply", "dev-safe", "--observe"],
            cwd=tempfile.mkdtemp(),
            env=env,
            capture_output=True,
            text=True,
            timeout=60,
        )
        self.assertEqual(r.returncode, 2)
        self.assertIn("needs a terminal", r.stderr)
