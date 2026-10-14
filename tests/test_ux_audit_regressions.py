"""Regressions found by a UX audit on a real enrolled device (2026-10-14)."""
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from prismor.runtime.policy_engine import PolicyEngine
from prismor.runtime.hooks import should_block
from prismor.runtime.enterprise import audit_trail, receipt_signing


class MalformedProjectPolicyTest(unittest.TestCase):
    """A typo in .prismor/policy.yaml used to raise out of the engine, crashing
    hook-dispatch with exit 1 - which agents treat as allow."""

    def _engine(self, text):
        ws = Path(tempfile.mkdtemp())
        (ws / ".prismor").mkdir()
        (ws / ".prismor" / "policy.yaml").write_text(text)
        with mock.patch("prismor.runtime.enterprise.workspace_scope.is_managed", return_value=False):
            return PolicyEngine(workspace=ws)

    def test_broken_yaml_is_skipped_and_reported_not_raised(self):
        eng = self._engine('version: "1.0"\nrules: [\n  - id: x\n')
        self.assertIsNotNone(eng.project_policy_error)
        self.assertIn("policy.yaml", eng.project_policy_error)

    def test_floor_still_blocks_with_a_broken_project_file(self):
        eng = self._engine('version: "1.0"\nrules: [\n')
        findings = eng.evaluate({"type": "shell", "command": "rm -rf /"}, index=0)
        self.assertIsNotNone(should_block(findings, {"type": "shell", "agent_event": "PreToolUse"}))

    def test_non_mapping_top_level_is_rejected_cleanly(self):
        eng = self._engine("- just\n- a list\n")
        self.assertIn("mapping", eng.project_policy_error or "")


class TrailVerifyWithoutBackendTest(unittest.TestCase):
    """Without `cryptography` no signature can be checked; that must read as
    'not checked', never as 'tampered'."""

    def test_unverifiable_is_not_tampered(self):
        d = Path(tempfile.mkdtemp())
        trail = d / "trail.jsonl"
        rec = {"seq": 0, "prev_hash": audit_trail.GENESIS, "ts": "2026-10-14T00:00:00Z",
               "signature": "AAAA", "signing_key_id": "k", "signing_pubkey": "AAAA"}
        rec["hash"] = audit_trail.compute_hash(rec)
        trail.write_text(json.dumps(rec) + "\n")
        (d / "state.json").write_text(json.dumps({"seq": 0, "last_hash": rec["hash"]}))
        with mock.patch.object(receipt_signing, "_HAVE_CRYPTO", False), \
             mock.patch.object(audit_trail, "state_path", return_value=d / "state.json"):
            report = audit_trail.verify_trail(path=trail)
        self.assertEqual(report["unverifiable"], 1)
        self.assertEqual(report["sig_failures"], [])
        self.assertNotEqual(report["status"], "tampered")


if __name__ == "__main__":
    unittest.main()
