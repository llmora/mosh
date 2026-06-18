from __future__ import annotations

import json
import unittest

from mosh.crews.discovery.openapi_parser import (
    is_openapi_spec,
    parse_openapi_spec,
    _extract_base_url,
)
from mosh.models import CrawledPage


SWAGGER_2_SPEC = {
    "swagger": "2.0",
    "host": "api.example.com",
    "basePath": "/v1",
    "schemes": ["https"],
    "paths": {
        "/users": {
            "get": {"summary": "List users"},
            "post": {"description": "Create a user"},
        },
        "/users/{id}": {
            "delete": {"summary": "Delete a user"},
        },
    },
}

OPENAPI_3_SPEC = {
    "openapi": "3.0.1",
    "servers": [{"url": "https://api.example.com/api"}],
    "paths": {
        "/orders": {
            "get": {"summary": "List orders"},
            "put": {"description": "Replace orders"},
        },
        "/health": {
            "head": {},
        },
    },
}


class ParseOpenApiSpecTests(unittest.TestCase):
    def test_valid_swagger_2_returns_pages_per_endpoint(self):
        pages = parse_openapi_spec(
            "https://api.example.com/swagger.json", json.dumps(SWAGGER_2_SPEC)
        )
        # 2 methods on /users + 1 on /users/{id} = 3 endpoints
        self.assertEqual(len(pages), 3)
        for page in pages:
            self.assertIsInstance(page, CrawledPage)
            self.assertIn("https://api.example.com/v1/", page.url)
            self.assertEqual(page.references, ["https://api.example.com/swagger.json"])
        titles = {p.title for p in pages}
        self.assertIn("GET /users", titles)
        self.assertIn("POST /users", titles)
        self.assertIn("DELETE /users/{id}", titles)

    def test_valid_openapi_3_returns_pages(self):
        pages = parse_openapi_spec(
            "https://api.example.com/docs/json", json.dumps(OPENAPI_3_SPEC)
        )
        # 2 methods on /orders + 1 on /health = 3 endpoints
        self.assertEqual(len(pages), 3)
        urls = {p.url for p in pages}
        self.assertIn("https://api.example.com/api/orders", urls)
        self.assertIn("https://api.example.com/api/health", urls)
        titles = {p.title for p in pages}
        self.assertIn("GET /orders", titles)
        self.assertIn("PUT /orders", titles)
        self.assertIn("HEAD /health", titles)

    def test_openapi_3_relative_server_returns_pages_under_resolved_base_path(self):
        spec = {
            "openapi": "3.0.1",
            "servers": [{"url": "/api"}],
            "paths": {
                "/users": {
                    "get": {"summary": "List users"},
                },
            },
        }

        pages = parse_openapi_spec("https://app.example.test/docs/openapi.json", json.dumps(spec))

        self.assertEqual(len(pages), 1)
        self.assertEqual(pages[0].url, "https://app.example.test/api/users")
        self.assertEqual(pages[0].title, "GET /users")

    def test_non_json_returns_empty_list(self):
        self.assertEqual(parse_openapi_spec("http://x/y", "<html>not json</html>"), [])
        self.assertEqual(parse_openapi_spec("http://x/y", None), [])

    def test_json_without_openapi_keys_returns_empty_list(self):
        # Valid JSON dict but missing swagger/openapi keys
        self.assertEqual(
            parse_openapi_spec("http://x/y", json.dumps({"data": [1, 2, 3]})), []
        )
        # Has openapi key but no paths
        self.assertEqual(
            parse_openapi_spec("http://x/y", json.dumps({"openapi": "3.0.0"})), []
        )
        # JSON array, not a dict
        self.assertEqual(parse_openapi_spec("http://x/y", json.dumps([1, 2, 3])), [])

    def test_skips_non_http_methods_and_non_dict_methods(self):
        spec = {
            "openapi": "3.0.0",
            "servers": [{"url": "https://api.example.com"}],
            "paths": {
                "/a": {"get": {}, "parameters": []},  # 'parameters' is not a method
                "/b": "not-a-dict",  # skipped entirely
            },
        }
        pages = parse_openapi_spec("https://api.example.com/spec", json.dumps(spec))
        self.assertEqual(len(pages), 1)
        self.assertEqual(pages[0].title, "GET /a")


class IsOpenApiSpecTests(unittest.TestCase):
    def test_detects_swagger_spec(self):
        self.assertTrue(
            is_openapi_spec("application/json", json.dumps(SWAGGER_2_SPEC))
        )

    def test_detects_openapi_spec(self):
        self.assertTrue(
            is_openapi_spec("application/json; charset=utf-8", json.dumps(OPENAPI_3_SPEC))
        )

    def test_non_json_content_type_is_false(self):
        self.assertFalse(is_openapi_spec("text/html", json.dumps(OPENAPI_3_SPEC)))

    def test_invalid_json_is_false(self):
        self.assertFalse(is_openapi_spec("application/json", "not json"))

    def test_json_without_paths_is_false(self):
        self.assertFalse(
            is_openapi_spec("application/json", json.dumps({"openapi": "3.0.0"}))
        )

    def test_json_array_is_false(self):
        self.assertFalse(is_openapi_spec("application/json", json.dumps([1, 2, 3])))


class ExtractBaseUrlTests(unittest.TestCase):
    def test_from_openapi_servers(self):
        base = _extract_base_url(
            {"servers": [{"url": "https://svc.example.com/api"}]},
            "https://other.example.com/docs/json",
        )
        self.assertEqual(base, "https://svc.example.com/api")

    def test_from_swagger_host(self):
        base = _extract_base_url(
            {"host": "api.example.com", "basePath": "/v2", "schemes": ["https"]},
            "https://other.example.com/swagger.json",
        )
        self.assertEqual(base, "https://api.example.com/v2")

    def test_swagger_host_defaults_to_https_without_schemes(self):
        base = _extract_base_url(
            {"host": "api.example.com"},
            "https://other.example.com/swagger.json",
        )
        self.assertEqual(base, "https://api.example.com")

    def test_fallback_to_spec_url(self):
        base = _extract_base_url({}, "https://fallback.example.com/docs/json?x=1")
        self.assertEqual(base, "https://fallback.example.com")

    def test_servers_relative_url_resolves_against_spec_url(self):
        base = _extract_base_url(
            {"servers": [{"url": "/api"}]},
            "https://fallback.example.com/spec",
        )
        self.assertEqual(base, "https://fallback.example.com/api")


if __name__ == "__main__":
    unittest.main()
