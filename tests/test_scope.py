from __future__ import annotations

import unittest

from mosh.scope import ScopePolicy, normalize_url


class ScopePolicyTests(unittest.TestCase):
    def test_www_target_allows_root_and_subdomains(self) -> None:
        scope = ScopePolicy.from_url("https://www.example.com")

        self.assertTrue(scope.in_scope("https://example.com/path"))
        self.assertTrue(scope.in_scope("https://api.example.com/path"))
        self.assertTrue(scope.host_in_scope("api.example.com"))
        self.assertFalse(scope.in_scope("https://example.test/path"))
        self.assertFalse(scope.host_in_scope("evil-example.com"))
        self.assertEqual(scope.passive_query_root(), "example.com")

    def test_localhost_scope_stays_on_same_host(self) -> None:
        scope = ScopePolicy.from_url("http://127.0.0.1:8000")

        self.assertTrue(scope.in_scope("http://127.0.0.1:9000/other"))
        self.assertFalse(scope.in_scope("http://127.0.0.2:8000/other"))
        self.assertIsNone(scope.passive_query_root())

    def test_normalize_adds_scheme_and_path(self) -> None:
        self.assertEqual(normalize_url("example.com"), "https://example.com/")


if __name__ == "__main__":
    unittest.main()
