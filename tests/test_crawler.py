from __future__ import annotations

import unittest

from appsec_harness.components import compile_component_inventory
from appsec_harness.crawler import Crawler
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

    def test_component_inventory_uses_headers_and_referenced_assets(self) -> None:
        with fixture_server() as url:
            result = Crawler(timeout=3).crawl(url, max_pages=5, max_depth=1)

        components = compile_component_inventory(result)
        names = {component["name"] for component in components}

        self.assertIn("FixtureFramework", names)
        self.assertIn("jquery", names)
        self.assertIn("jquery-3.7.1.min.js", names)


if __name__ == "__main__":
    unittest.main()
