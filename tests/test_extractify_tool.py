from __future__ import annotations

import unittest

from appsec_harness.docker_tools import DockerToolResult
from appsec_harness.tools import ExtractifyDockerTool, parse_extractify_output


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


class ExtractifyDockerToolTests(unittest.TestCase):
    def test_runs_extractify_for_javascript_urls(self) -> None:
        runner = FakeDockerRunner(
            DockerToolResult(
                exit_code=0,
                stdout='[{"source":"https://example.test/app.js","endpoints":["/api/login"],"urls":["https://api.example.test/users"]}]',
                stderr="",
            )
        )
        tool = ExtractifyDockerTool("discovery-tools:test", runner=runner)

        result = tool.run(
            "https://example.test",
            ["https://example.test/app.js", "https://example.test/app.js"],
        )

        args = runner.calls[0]["args"]
        self.assertEqual(args, ["extractify", "-ee", "-eu", "-json", "-dedup"])
        self.assertEqual(runner.calls[0]["input_text"], "https://example.test/app.js\n")
        self.assertEqual(runner.calls[0]["timeout"], 120)
        self.assertFalse(runner.calls[0]["tty"])
        self.assertEqual(
            [page.url for page in result.pages],
            ["https://api.example.test/users", "https://example.test/api/login"],
        )

    def test_parses_extractify_json_with_scope_filtering(self) -> None:
        output = (
            '[{"source":"https://example.test/static/app.js",'
            '"endpoints":["/api/login","https://outside.test/api"],'
            '"urls":["//cdn.example.test/lib.js"]}]'
        )

        result = parse_extractify_output("https://www.example.test", output)

        self.assertEqual(
            [page.url for page in result.pages],
            ["https://cdn.example.test/lib.js", "https://example.test/api/login"],
        )
        self.assertEqual(result.out_of_scope, ["https://outside.test/api"])
        self.assertEqual(result.pages[1].references, ["https://example.test/static/app.js"])

    def test_records_invalid_json_as_failure(self) -> None:
        result = parse_extractify_output("https://example.test", "not-json")

        self.assertEqual(result.pages, [])
        self.assertEqual(result.failed[0]["url"], "https://example.test/")
        self.assertIn("invalid JSON", result.failed[0]["error"])


if __name__ == "__main__":
    unittest.main()
