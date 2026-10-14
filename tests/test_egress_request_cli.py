"""`prismor egress request` input handling: what people paste, and what must be refused."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from prismor.runtime.egress_cli import _is_catch_all, _request_host


class RequestHostTest(unittest.TestCase):
    def test_a_pasted_url_becomes_its_host(self):
        self.assertEqual(_request_host("https://Docs.Example.com/path?q=1"), "docs.example.com")
        self.assertEqual(_request_host("http://api.stripe.com:8443/v1"), "api.stripe.com")

    def test_case_and_trailing_dot_are_normalised(self):
        self.assertEqual(_request_host("WWW.LinkedIn.com."), "www.linkedin.com")

    def test_plain_hosts_and_wildcards_pass_through(self):
        self.assertEqual(_request_host("*.linkedin.com"), "*.linkedin.com")

    def test_catch_alls_are_refused(self):
        for h in ("*", "0.0.0.0/0", "::/0", "10.0.0.0/4"):
            with self.subTest(h=h):
                self.assertTrue(_is_catch_all(h))
        for h in ("10.0.0.0/8", "api.x.com", "*.x.com", "fd00::/16"):
            with self.subTest(h=h):
                self.assertFalse(_is_catch_all(h))


if __name__ == "__main__":
    unittest.main()
