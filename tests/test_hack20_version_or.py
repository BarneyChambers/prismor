"""An advisory range with || matches either branch, and 1.2.x is not 1.2.0."""

import unittest

from supplychain.version_range import parse_npm_range, parse_version, version_in_range, version_satisfies


class TestVersionOr(unittest.TestCase):
    def test_or_matches_either_side(self):
        spec = "<=1.0.0 || >=9.0.0"
        self.assertTrue(version_satisfies((9, 9, 9), spec))
        self.assertTrue(version_satisfies((0, 0, 1), spec))
        self.assertFalse(version_satisfies((5, 0, 0), spec))

    def test_wildcard_is_not_a_pin(self):
        self.assertIsNone(parse_version("1.2.x"))
        self.assertTrue(version_in_range((1, 2, 5), *parse_npm_range("1.2.x")))
        self.assertFalse(version_in_range((1, 3, 0), *parse_npm_range("1.2.x")))

    def test_unparseable_bound_matches_nothing(self):
        self.assertFalse(version_in_range((1, 2, 3), *parse_npm_range("<=not-a-version")))
