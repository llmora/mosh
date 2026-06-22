from __future__ import annotations

import unittest

from mosh.docker_tools import DockerToolResult
from mosh.crews.discovery_live.tools import SourceMapDiscoveryDockerTool, parse_source_map_output


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


class SourceMapDiscoveryDockerToolTests(unittest.TestCase):
    def test_runs_source_map_discovery_for_javascript_urls(self) -> None:
        runner = FakeDockerRunner(
            DockerToolResult(
                exit_code=0,
                stdout=(
                    '[{"source":"https://example.test/app.js",'
                    '"checked":[{"url":"https://example.test/app.js.map","reason":"sibling","found":true}],'
                    '"source_maps":[{"url":"https://example.test/app.js.map","sources":["src/App.jsx"],'
                    '"sources_count":1,"sources_with_content":1,"source_root":"","valid":true}]}]'
                ),
                stderr="",
            )
        )
        tool = SourceMapDiscoveryDockerTool("discovery-tools:test", runner=runner)

        summary = tool.run(
            "https://example.test/app",
            ["https://example.test/app.js", "https://example.test/app.js#ignored"],
        )

        args = runner.calls[0]["args"]
        self.assertEqual(args, ["source-map-discovery", "--base-url", "https://example.test/app", "--json"])
        self.assertEqual(runner.calls[0]["input_text"], "https://example.test/app.js\n")
        self.assertEqual(runner.calls[0]["timeout"], 300)
        self.assertFalse(runner.calls[0]["tty"])
        self.assertTrue(summary["checked"])
        self.assertEqual(summary["javascript_assets"], 1)
        self.assertEqual(summary["source_maps_found"], 1)
        self.assertEqual(summary["sources_with_content"], 1)

    def test_reuses_cached_result_for_same_javascript_assets(self) -> None:
        runner = FakeDockerRunner(DockerToolResult(exit_code=0, stdout="[]", stderr=""))
        tool = SourceMapDiscoveryDockerTool("discovery-tools:test", runner=runner)

        tool.run("https://example.test", ["https://example.test/app.js"])
        tool.run("https://example.test", ["https://example.test/app.js#ignored"])

        self.assertEqual(len(runner.calls), 1)

    def test_parse_source_map_output_records_invalid_json_failure(self) -> None:
        summary = parse_source_map_output("https://example.test", "not-json")

        self.assertFalse(summary["checked"])
        self.assertEqual(summary["failed"][0]["url"], "https://example.test/")
        self.assertIn("invalid JSON", summary["failed"][0]["error"])

    def test_run_records_docker_failure(self) -> None:
        runner = FakeDockerRunner(DockerToolResult(exit_code=124, stdout="", stderr="Docker tool timed out after 300 seconds"))
        tool = SourceMapDiscoveryDockerTool("discovery-tools:test", runner=runner)

        summary = tool.run("https://example.test", ["https://example.test/app.js"])

        self.assertEqual(summary["failed"], [{"url": "https://example.test/", "error": "Docker tool timed out after 300 seconds"}])


if __name__ == "__main__":
    unittest.main()
