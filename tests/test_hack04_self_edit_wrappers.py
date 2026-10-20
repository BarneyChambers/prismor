"""Self-edit wrappers and a non-tty uninstall-hooks must not get through."""

import os
import sys
import tempfile
import unittest
from pathlib import Path

from prismor.runtime.hooks import should_block
from prismor.runtime.policy_engine import PolicyEngine


def _blocked(command: str) -> bool:
    with tempfile.TemporaryDirectory() as tmp:
        eng = PolicyEngine(workspace=Path(tmp))
        findings = eng.evaluate({"type": "shell", "command": command}, index=0)
    return should_block(findings, {"type": "shell", "agent_event": "PreToolUse"}) is not None


class TestSelfEditWrappers(unittest.TestCase):
    def test_wrappers_block(self):
        for command in (
            "eval 'prismor allow risky-write --off'",
            "eval 'prismor uninstall-hooks --agent claude'",
            "$(echo prismor) allow risky-write --off",
            "{ prismor allow risky-write --off; }",
            'ssh -o ProxyCommand="prismor pause" example.invalid',
            "prismor allow risky-write --off",
        ):
            self.assertTrue(_blocked(command), command)

    def test_uninstall_hooks_refuses_non_tty(self):
        import subprocess
        env = os.environ.copy()
        env["PRISMOR_HOME"] = tempfile.mkdtemp()
        root = Path(__file__).resolve().parents[1]
        env["PYTHONPATH"] = str(root) + (
            os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else ""
        )
        r = subprocess.run(
            [sys.executable, "-m", "prismor.runtime.immunity_cli",
             "uninstall-hooks", "--agent", "claude", "--scope", "project"],
            cwd=tempfile.mkdtemp(),
            env=env,
            capture_output=True,
            text=True,
            timeout=60,
        )
        self.assertEqual(r.returncode, 2)
        self.assertIn("needs a terminal", r.stderr)
