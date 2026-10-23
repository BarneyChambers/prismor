"""A judge reply with no risk_score is not a score of zero."""

import unittest

from prismor.runtime.semantic_guard_v2 import _parse_verdict


class TestMissingRiskScore(unittest.TestCase):
    def test_missing_score_is_not_a_verdict(self):
        self.assertIsNone(_parse_verdict("{}", 0))
        self.assertIsNone(_parse_verdict('{"recommended_action": "block"}', 0))
        self.assertIsNone(_parse_verdict("not json", 0))

    def test_present_score_is_kept(self):
        verdict = _parse_verdict('{"risk_score": 0.9, "recommended_action": "block"}', 0)
        self.assertIsNotNone(verdict)
        self.assertAlmostEqual(verdict.risk_score, 0.9)
