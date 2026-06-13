from __future__ import annotations

import unittest

from mosh.docker_tools import DockerToolResult
from mosh.crews.discovery.tools import DirbDockerDiscoveryTool, parse_dirb_output


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


class DirbDockerDiscoveryToolTests(unittest.TestCase):
    def test_runs_dirb_with_bounded_non_recursive_flags(self) -> None:
        runner = FakeDockerRunner(
            DockerToolResult(
                exit_code=0,
                stdout="+ https://example.test/admin (CODE:200|SIZE:42)\n",
                stderr="",
            )
        )
        tool = DirbDockerDiscoveryTool(
            "discovery-tools:test",
            runner=runner,
            wordlist="/wordlists/small.txt",
            docker_timeout=45,
        )

        result = tool.run("https://example.test/app", max_pages=25, max_depth=3)

        self.assertEqual(
            runner.calls[0]["args"],
            ["dirb", "https://example.test/app", "/wordlists/small.txt", "-S", "-r", "-w"],
        )
        self.assertEqual(runner.calls[0]["timeout"], 45)
        self.assertFalse(runner.calls[0]["tty"])
        self.assertEqual(result.pages, [])
        self.assertEqual([candidate.url for candidate in result.candidates], ["https://example.test/admin"])

    def test_parses_dirb_output_with_scope_filtering(self) -> None:
        output = "\n".join(
            [
                "+ https://example.test/admin (CODE:200|SIZE:42)",
                "==> DIRECTORY: https://example.test/images/",
                "+ https://outside.test/admin (CODE:200|SIZE:12)",
            ]
        )

        result = parse_dirb_output("https://www.example.test", output)

        self.assertEqual(
            [candidate.url for candidate in result.candidates],
            ["https://example.test/admin", "https://example.test/images/"],
        )
        self.assertEqual([candidate.status for candidate in result.candidates], [200, 0])
        self.assertEqual([candidate.kind for candidate in result.candidates], ["path", "directory"])
        self.assertEqual([candidate.should_crawl for candidate in result.candidates], [True, True])
        self.assertEqual(result.out_of_scope, ["https://outside.test/admin"])
        self.assertEqual(result.candidates[0].evidence, ["https://www.example.test/"])

    def test_marks_static_asset_candidates_as_not_crawlable(self) -> None:
        result = parse_dirb_output("https://example.test", "+ https://example.test/logo.svg (CODE:200|SIZE:12)")

        self.assertEqual(result.candidates[0].kind, "asset")
        self.assertFalse(result.candidates[0].should_crawl)

    def test_records_failed_dirb_run(self) -> None:
        runner = FakeDockerRunner(DockerToolResult(exit_code=1, stdout="", stderr="dirb error"))
        tool = DirbDockerDiscoveryTool("discovery-tools:test", runner=runner)

        result = tool.run("https://example.test", max_pages=25, max_depth=3)

        self.assertEqual(result.failed, [{"url": "https://example.test/", "error": "dirb error"}])


if __name__ == "__main__":
    unittest.main()
