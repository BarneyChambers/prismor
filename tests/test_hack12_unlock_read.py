"""A Read of the unlock credential is a self-edit, not an ordinary file read."""

import tempfile
import unittest
from pathlib import Path

from prismor.runtime.hooks import should_block
from prismor.runtime.policy_engine import PolicyEngine


class TestUnlockRead(unittest.TestCase):
    def test_file_read_of_unlock_and_identity_blocks(self):
        with tempfile.TemporaryDirectory() as tmp:
            eng = PolicyEngine(workspace=Path(tmp))
            for path in ("/home/u/.prismor/unlock.json", "/home/u/.prismor/identity.json"):
                findings = eng.evaluate({"type": "file_read", "path": path}, index=0)
                self.assertIsNotNone(
                    should_block(
                        findings,
                        {"type": "file_read", "path": path, "agent_event": "PreToolUse"},
                    ),
                    path,
                )

    def test_ordinary_read_still_does_not_block(self):
        with tempfile.TemporaryDirectory() as tmp:
            eng = PolicyEngine(workspace=Path(tmp))
            path = str(Path(tmp) / "README.md")
            findings = eng.evaluate({"type": "file_read", "path": path}, index=0)
        self.assertIsNone(
            should_block(
                findings,
                {"type": "file_read", "path": path, "agent_event": "PreToolUse"},
            )
        )
