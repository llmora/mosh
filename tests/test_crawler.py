from __future__ import annotations

import unittest
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import Mock, patch

from mosh.crews.discovery_live.crawler import Crawler, _SameOriginRedirects, _origin
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

    def test_configured_headers_authenticate_robots_and_pages(self) -> None:
        seen: list[str] = []

        class AccessHandler(BaseHTTPRequestHandler):
            def do_GET(self):
                if self.headers.get("X-Gateway-Id") != "fixture-id" or self.headers.get("X-Gateway-Secret") != "fixture-secret":
                    self.send_response(403)
                    self.end_headers()
                    return
                seen.append(self.path)
                body = "User-agent: *\n" if self.path == "/robots.txt" else '<title>fixture-secret</title><a href="/about">About</a>' if self.path == "/" else "About"
                encoded = body.encode()
                self.send_response(200)
                self.send_header("Content-Type", "text/plain" if self.path == "/robots.txt" else "text/html")
                self.send_header("Content-Length", str(len(encoded)))
                self.send_header("X-Echo", "fixture-secret")
                self.end_headers()
                self.wfile.write(encoded)

            def log_message(self, *args):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), AccessHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            url = f"http://127.0.0.1:{server.server_port}/"
            result = Crawler(
                timeout=3,
                request_headers={"X-Gateway-Id": "fixture-id", "X-Gateway-Secret": "fixture-secret"},
                access_origin=url,
            ).crawl(url, max_pages=3, max_depth=1)
        finally:
            server.shutdown()
            thread.join(timeout=2)
            server.server_close()
        self.assertEqual(result.failed, [])
        self.assertEqual(seen, ["/robots.txt", "/", "/about"])
        self.assertNotIn("fixture-secret", str(result.to_dict()))

    def test_configured_headers_are_not_sent_to_another_origin_or_redirect(self) -> None:
        crawler = Crawler(request_headers={"X-Gateway-Secret": "fixture-secret"}, access_origin="https://app.example.test/")
        opener = Mock()
        with patch("mosh.crews.discovery_live.crawler.build_opener", return_value=opener):
            crawler._open("https://app.example.test/private")
            crawler._open("https://other.example.test/private")
        self.assertEqual(opener.open.call_args_list[0].args[0].get_header("X-gateway-secret"), "fixture-secret")
        self.assertIsNone(opener.open.call_args_list[1].args[0].get_header("X-gateway-secret"))
        handler = _SameOriginRedirects(_origin("https://app.example.test/"))
        self.assertIsNone(handler.redirect_request(None, None, 302, "Found", {}, "https://other.example.test/"))


if __name__ == "__main__":
    unittest.main()
