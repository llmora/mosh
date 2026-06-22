from __future__ import annotations

import unittest
from urllib.error import HTTPError
from urllib.parse import parse_qs, urlparse
from urllib.request import Request
from unittest.mock import patch

from mosh.crews.discovery_live.osint import (
    CensysOsintProvider,
    CrtShOsintProvider,
    OsintObservation,
    ShodanOsintProvider,
    _open_json,
    build_default_osint_providers,
)
from mosh.crews.discovery_live.tools import ExternalOsintDiscoveryTool


class StaticOsintProvider:
    name = "static_external_osint"

    def __init__(self, observations: list[OsintObservation]) -> None:
        self.observations = observations
        self.calls: list[tuple[str, int]] = []

    def query(self, root_domain: str, timeout: int) -> list[OsintObservation]:
        self.calls.append((root_domain, timeout))
        return self.observations


class FailingOsintProvider:
    name = "failing_external_osint"

    def __init__(self) -> None:
        self.calls: list[tuple[str, int]] = []

    def query(self, root_domain: str, timeout: int) -> list[OsintObservation]:
        self.calls.append((root_domain, timeout))
        raise RuntimeError("provider unavailable")


class JsonResponse:
    def __init__(self, body: str) -> None:
        self.body = body

    def __enter__(self) -> "JsonResponse":
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        return None

    def read(self) -> bytes:
        return self.body.encode("utf-8")


class ExternalOsintDiscoveryToolTests(unittest.TestCase):
    def test_queries_authorized_root_and_filters_results_before_candidates(self) -> None:
        provider = StaticOsintProvider(
            [
                OsintObservation(
                    host="api.example.test",
                    source_tool="static_external_osint",
                    evidence=["provider host result"],
                ),
                OsintObservation(
                    host="*.admin.example.test",
                    source_tool="static_external_osint",
                    evidence=["provider wildcard certificate"],
                ),
                OsintObservation(
                    host="evil-example.test",
                    source_tool="static_external_osint",
                    evidence=["provider false positive"],
                ),
                OsintObservation(
                    host="outside.test",
                    source_tool="static_external_osint",
                    evidence=["provider outside result"],
                ),
            ]
        )
        tool = ExternalOsintDiscoveryTool([provider], provider_timeout=7)

        result = tool.run("https://www.example.test/app", max_pages=25, max_depth=3)

        self.assertEqual(provider.calls, [("example.test", 7)])
        self.assertEqual(
            [candidate.url for candidate in result.candidates],
            ["https://admin.example.test/", "https://api.example.test/"],
        )
        self.assertEqual([candidate.kind for candidate in result.candidates], ["host", "host"])
        self.assertEqual([candidate.should_crawl for candidate in result.candidates], [True, True])
        self.assertEqual(
            result.out_of_scope,
            ["https://evil-example.test/", "https://outside.test/"],
        )

    def test_maps_web_services_to_crawlable_urls_and_keeps_non_web_services_passive(self) -> None:
        provider = StaticOsintProvider(
            [
                OsintObservation(
                    host="api.example.test",
                    source_tool="static_external_osint",
                    evidence=["provider https service"],
                    port=8443,
                ),
                OsintObservation(
                    host="ssh.example.test",
                    source_tool="static_external_osint",
                    evidence=["provider ssh service"],
                    port=22,
                ),
            ]
        )
        tool = ExternalOsintDiscoveryTool([provider])

        result = tool.run("https://example.test", max_pages=25, max_depth=3)

        self.assertEqual(
            [candidate.url for candidate in result.candidates],
            ["https://api.example.test:8443/", "tcp://ssh.example.test:22"],
        )
        self.assertEqual([candidate.kind for candidate in result.candidates], ["service", "service"])
        self.assertEqual([candidate.should_crawl for candidate in result.candidates], [True, False])

    def test_records_provider_failures_without_blocking_other_providers(self) -> None:
        provider = StaticOsintProvider(
            [
                OsintObservation(
                    host="api.example.test",
                    source_tool="static_external_osint",
                    evidence=["provider host result"],
                )
            ]
        )
        tool = ExternalOsintDiscoveryTool([FailingOsintProvider(), provider])

        result = tool.run("https://example.test", max_pages=25, max_depth=3)

        self.assertEqual([candidate.url for candidate in result.candidates], ["https://api.example.test/"])
        self.assertEqual(
            result.failed,
            [
                {
                    "url": "https://example.test/",
                    "error": "failing_external_osint failed: provider unavailable",
                }
            ],
        )

    def test_skips_passive_osint_for_ip_scoped_targets(self) -> None:
        provider = StaticOsintProvider(
            [
                OsintObservation(
                    host="api.example.test",
                    source_tool="static_external_osint",
                    evidence=["provider host result"],
                )
            ]
        )
        tool = ExternalOsintDiscoveryTool([provider])

        result = tool.run("http://127.0.0.1:8000", max_pages=25, max_depth=3)

        self.assertEqual(provider.calls, [])
        self.assertEqual(result.candidates, [])
        self.assertEqual(result.failed, [])

    def test_queries_each_passive_root_once_per_tool_instance(self) -> None:
        provider = StaticOsintProvider(
            [
                OsintObservation(
                    host="api.example.test",
                    source_tool="static_external_osint",
                    evidence=["provider host result"],
                )
            ]
        )
        tool = ExternalOsintDiscoveryTool([provider], provider_timeout=7)

        first = tool.run("https://www.example.test/app", max_pages=25, max_depth=3)
        second = tool.run("https://example.test/login", max_pages=25, max_depth=3)

        self.assertEqual(provider.calls, [("example.test", 7)])
        self.assertEqual([candidate.url for candidate in first.candidates], ["https://api.example.test/"])
        self.assertEqual(second.candidates, [])
        self.assertEqual(second.failed, [])

    def test_does_not_repeat_failed_passive_root_queries(self) -> None:
        provider = FailingOsintProvider()
        tool = ExternalOsintDiscoveryTool([provider], provider_timeout=7)

        first = tool.run("https://example.test", max_pages=25, max_depth=3)
        second = tool.run("https://www.example.test/register", max_pages=25, max_depth=3)

        self.assertEqual(provider.calls, [("example.test", 7)])
        self.assertEqual(
            first.failed,
            [
                {
                    "url": "https://example.test/",
                    "error": "failing_external_osint failed: provider unavailable",
                }
            ],
        )
        self.assertEqual(second.failed, [])
        self.assertEqual(second.candidates, [])

    def test_default_provider_builder_includes_key_backed_providers_when_configured(self) -> None:
        providers = build_default_osint_providers(
            shodan_api_key="shodan-key",
            securitytrails_api_key="securitytrails-key",
            censys_api_id="censys-id",
            censys_api_secret="censys-secret",
        )

        self.assertEqual(
            [provider.name for provider in providers],
            [
                "crtsh_external_osint",
                "securitytrails_external_osint",
                "shodan_external_osint",
                "censys_external_osint",
            ],
        )

    def test_crtsh_provider_parses_and_deduplicates_certificate_names(self) -> None:
        provider = CrtShOsintProvider()
        with patch(
            "mosh.crews.discovery_live.osint._open_json",
            return_value=[
                {"name_value": "*.api.example.test\napi.example.test\nwww.example.test"},
                {"name_value": "WWW.example.test."},
            ],
        ) as open_json:
            observations = provider.query("example.test", timeout=5)

        request = open_json.call_args.args[0]
        self.assertIn("q=%25.example.test", request.full_url)
        self.assertEqual(
            [observation.host for observation in observations],
            ["api.example.test", "www.example.test"],
        )
        self.assertEqual({observation.source_tool for observation in observations}, {"crtsh_external_osint"})

    def test_shodan_provider_extracts_hostnames_and_protocol_from_service_metadata(self) -> None:
        provider = ShodanOsintProvider("shodan-key")
        with patch(
            "mosh.crews.discovery_live.osint._open_json",
            return_value={
                "matches": [
                    {
                        "hostnames": ["api.example.test"],
                        "port": 443,
                        "_shodan": {"module": "https"},
                    }
                ]
            },
        ) as open_json:
            observations = provider.query("example.test", timeout=5)

        request = open_json.call_args.args[0]
        self.assertIn("hostname%3Aexample.test", request.full_url)
        self.assertEqual(len(observations), 1)
        self.assertEqual(observations[0].host, "api.example.test")
        self.assertEqual(observations[0].port, 443)
        self.assertEqual(observations[0].protocol, "https")

    def test_censys_provider_uses_get_search_query_parameters(self) -> None:
        provider = CensysOsintProvider("censys-id", "censys-secret")
        with patch(
            "mosh.crews.discovery_live.osint._open_json",
            return_value={"result": {"hits": []}},
        ) as open_json:
            observations = provider.query("example.test", timeout=5)

        request = open_json.call_args.args[0]
        query = parse_qs(urlparse(request.full_url).query)
        self.assertEqual(request.get_method(), "GET")
        self.assertIsNone(request.data)
        self.assertEqual(query["per_page"], ["50"])
        self.assertEqual(query["virtual_hosts"], ["EXCLUDE"])
        self.assertEqual(
            query["q"],
            ["dns.names: *.example.test or services.tls.certificates.leaf_data.names: *.example.test"],
        )
        self.assertEqual(observations, [])

    def test_open_json_retries_transient_osint_query_failures(self) -> None:
        request = Request("https://crt.sh/?q=%25.example.test&output=json")
        with patch(
            "mosh.crews.discovery_live.osint.urlopen",
            side_effect=[
                TimeoutError("slow response"),
                HTTPError(request.full_url, 503, "Service Unavailable", {}, None),
                JsonResponse('{"ok": true}'),
            ],
        ) as urlopen:
            with patch("mosh.crews.discovery_live.osint.time.sleep") as sleep:
                payload = _open_json(request, timeout=5)

        self.assertEqual(payload, {"ok": True})
        self.assertEqual(urlopen.call_count, 3)
        self.assertEqual([call.args[0] for call in sleep.call_args_list], [0.25, 0.5])

    def test_open_json_does_not_retry_non_transient_http_errors(self) -> None:
        request = Request("https://crt.sh/?q=%25.example.test&output=json")
        with patch(
            "mosh.crews.discovery_live.osint.urlopen",
            side_effect=HTTPError(request.full_url, 404, "Not Found", {}, None),
        ) as urlopen:
            with self.assertRaises(HTTPError):
                _open_json(request, timeout=5)

        self.assertEqual(urlopen.call_count, 1)


if __name__ == "__main__":
    unittest.main()
