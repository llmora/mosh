from __future__ import annotations

import unittest

from open_security_harness.crews.discovery.crawler import Crawler
from tests.fixtures import fixture_server


class CrawlerTests(unittest.TestCase):
    def test_crawls_in_scope_pages_and_records_out_of_scope_references(self) -> None:
        with fixture_server() as url:
            result = Crawler(timeout=3).crawl(url, max_pages=5, max_depth=1)

        crawled_urls = {page.url for page in result.pages}
        self.assertIn(url, crawled_urls)
        self.assertTrue(any(page.title == "About" for page in result.pages))
        self.assertIn("https://outside.example.org/path", result.out_of_scope)
        self.assertIn("https://cdn.example.net/site.css", result.out_of_scope)
        self.assertTrue(result.robots)
        self.assertTrue(result.robots["found"])
        self.assertEqual(result.failed, [])

    def test_resolves_relative_references_against_final_redirect_url_and_keeps_inline_scripts(self) -> None:
        with fixture_server() as url:
            base = url.rstrip("/")
            result = Crawler(timeout=3).crawl(f"{base}/redirect-app", max_pages=1, max_depth=0)

        self.assertEqual(result.failed, [])
        page = result.pages[0]
        self.assertEqual(page.url, f"{base}/redirect-app/")
        self.assertIn(f"{base}/redirect-app/shell.js", page.references)
        self.assertTrue(any("BACKOFFICE_API_BASE" in script for script in page.inline_scripts))


if __name__ == "__main__":
    unittest.main()
