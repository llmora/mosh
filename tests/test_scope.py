from __future__ import annotations

from pathlib import Path
import unittest

from mosh.scope import ScopePolicy, normalize_url, report_dir_name, source_report_dir_name


class ScopePolicyTests(unittest.TestCase):
    def test_www_target_allows_root_and_subdomains(self) -> None:
        scope = ScopePolicy.from_url("https://www.test.com")

        self.assertTrue(scope.in_scope("https://test.com/path"))
        self.assertTrue(scope.in_scope("https://api.test.com/path"))
        self.assertFalse(scope.in_scope("https://example.com/path"))

    def test_localhost_scope_stays_on_same_host(self) -> None:
        scope = ScopePolicy.from_url("http://127.0.0.1:8000")

        self.assertTrue(scope.in_scope("http://127.0.0.1:9000/other"))
        self.assertFalse(scope.in_scope("http://127.0.0.2:8000/other"))

    def test_normalize_adds_scheme_and_path(self) -> None:
        self.assertEqual(normalize_url("example.com"), "https://example.com/")

    def test_report_dir_uses_host_only_with_port_for_local_targets(self) -> None:
        self.assertEqual(report_dir_name("http://127.0.0.1:8080/path"), "127.0.0.1_8080")
        self.assertEqual(report_dir_name("https://www.example.com/path"), "www.example.com")

    def test_source_report_dir_name_uses_readable_name_and_hash(self) -> None:
        first = source_report_dir_name(Path("/tmp/apps/api"))
        second = source_report_dir_name(Path("/tmp/other/api"))

        self.assertRegex(first, r"^source-api-[0-9a-f]{8}$")
        self.assertRegex(source_report_dir_name("https://github.com/example/app.git"), r"^source-github.com-app-[0-9a-f]{8}$")
        self.assertNotEqual(first, second)


if __name__ == "__main__":
    unittest.main()
