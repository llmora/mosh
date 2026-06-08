from __future__ import annotations

import json
import unittest

from appsec_harness.docker_tools import DockerToolResult
from appsec_harness.crews.discovery.tools import JsStaticEndpointDockerTool, parse_js_static_output


class FakeDockerRunner:
    def __init__(self, result: DockerToolResult) -> None:
        self.result = result
        self.calls: list[dict[str, object]] = []

    def run(
        self,
        args: list[str],
        input_text: str | None = None,
        timeout: int = 60,
        tty: bool = False,
    ) -> DockerToolResult:
        self.calls.append({"args": args, "input_text": input_text, "timeout": timeout, "tty": tty})
        return self.result


class JsStaticEndpointDockerToolTests(unittest.TestCase):
    def test_runs_static_endpoint_extractor_for_javascript_urls(self) -> None:
        runner = FakeDockerRunner(
            DockerToolResult(
                exit_code=0,
                stdout='[{"source":"https://example.test/app.js","endpoints":["/api/login","https://api.example.test/users"]}]',
                stderr="",
            )
        )
        tool = JsStaticEndpointDockerTool("discovery-tools:test", runner=runner)

        result = tool.run(
            "https://example.test/app",
            ["https://example.test/app.js", "https://example.test/app.js#ignored"],
        )

        args = runner.calls[0]["args"]
        self.assertEqual(args, ["js-endpoint-extractor", "--base-url", "https://example.test/app", "--json"])
        self.assertEqual(runner.calls[0]["input_text"], "https://example.test/app.js\n")
        self.assertEqual(runner.calls[0]["timeout"], 120)
        self.assertFalse(runner.calls[0]["tty"])
        self.assertEqual(
            [page.url for page in result.pages],
            ["https://api.example.test/users", "https://example.test/api/login"],
        )

    def test_passes_page_contexts_to_static_endpoint_extractor(self) -> None:
        runner = FakeDockerRunner(DockerToolResult(exit_code=0, stdout="[]", stderr=""))
        tool = JsStaticEndpointDockerTool("discovery-tools:test", runner=runner)
        contexts = [
            {
                "source": "https://example.test/backoffice/shell.js",
                "page_url": "https://example.test/backoffice/",
                "inline_scripts": ["window.BACKOFFICE_API_BASE = 'https://api.example.test/api/private';"],
            }
        ]

        tool.run(
            "https://example.test/",
            ["https://example.test/backoffice/shell.js"],
            contexts=contexts,
        )

        payload = json.loads(runner.calls[0]["input_text"])
        self.assertEqual(payload, contexts)

    def test_parses_static_endpoint_json_with_scope_filtering(self) -> None:
        output = (
            '[{"source":"https://example.test/static/app.js",'
            '"endpoints":["/api/login","https://outside.test/api"],'
            '"findings":[{"endpoint":"https://ignored.test/from-nested"}]}]'
        )

        result = parse_js_static_output("https://www.example.test", output)

        self.assertEqual([page.url for page in result.pages], ["https://example.test/api/login"])
        self.assertEqual(result.out_of_scope, ["https://outside.test/api"])
        self.assertEqual(result.pages[0].references, ["https://example.test/static/app.js"])

    def test_records_invalid_json_as_failure(self) -> None:
        result = parse_js_static_output("https://example.test", "not-json")

        self.assertEqual(result.pages, [])
        self.assertEqual(result.failed[0]["url"], "https://example.test/")
        self.assertIn("invalid JSON", result.failed[0]["error"])


if __name__ == "__main__":
    unittest.main()
