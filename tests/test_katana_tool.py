from __future__ import annotations

import unittest

from mmosh.docker_tools import DockerToolResult
from mmosh.crews.discovery.tools import KatanaDockerCrawlerTool, parse_katana_output


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


class KatanaDockerCrawlerToolTests(unittest.TestCase):
    def test_runs_katana_with_discovery_flags(self) -> None:
        runner = FakeDockerRunner(
            DockerToolResult(
                exit_code=0,
                stdout='{"url":"https://example.test/app","status_code":200}\n',
                stderr="",
            )
        )
        tool = KatanaDockerCrawlerTool("discovery-tools:test", runner=runner)

        result = tool.run("https://example.test", max_pages=11, max_depth=4)

        args = runner.calls[0]["args"]
        self.assertEqual(args[:3], ["katana", "-u", "https://example.test/"])
        self.assertIn("-jc", args)
        self.assertIn("-jsl", args)
        self.assertIn("-j", args)
        self.assertIn("-silent", args)
        self.assertIn("-do", args)
        self.assertIn("-or", args)
        self.assertIn("-ob", args)
        self.assertIn("-kf", args)
        self.assertIn("all", args)
        self.assertIn("-mdp", args)
        self.assertIn("11", args)
        self.assertIn("-d", args)
        self.assertIn("4", args)
        self.assertIn("-ct", args)
        self.assertIn("270s", args)
        self.assertIn("-headless", args)
        self.assertIn("-system-chrome", args)
        self.assertEqual(args[args.index("-system-chrome-path") + 1], "/usr/bin/chromium")
        self.assertIn("-no-sandbox", args)
        self.assertIn("-xhr", args)
        self.assertIn("-aff", args)
        self.assertEqual(args[args.index("-headless-options") + 1], "--disable-dev-shm-usage,--disable-gpu")
        self.assertEqual(runner.calls[0]["timeout"], 300)
        self.assertTrue(runner.calls[0]["tty"])
        self.assertEqual(result.pages[0].url, "https://example.test/app")

    def test_requested_depth_reaches_katana_command(self) -> None:
        runner = FakeDockerRunner(DockerToolResult(exit_code=0, stdout="", stderr=""))
        tool = KatanaDockerCrawlerTool("discovery-tools:test", runner=runner)

        tool.run("https://example.test", max_pages=25, max_depth=3)

        args = runner.calls[0]["args"]
        self.assertEqual(args[args.index("-d") + 1], "3")

    def test_allows_custom_duration_and_docker_timeout(self) -> None:
        runner = FakeDockerRunner(DockerToolResult(exit_code=0, stdout="", stderr=""))
        tool = KatanaDockerCrawlerTool(
            "discovery-tools:test",
            runner=runner,
            crawl_duration="45s",
            docker_timeout=60,
        )

        tool.run("https://example.test", max_pages=5, max_depth=2)

        self.assertIn("45s", runner.calls[0]["args"])
        self.assertEqual(runner.calls[0]["timeout"], 60)

    def test_records_failed_katana_run(self) -> None:
        runner = FakeDockerRunner(DockerToolResult(exit_code=1, stdout="", stderr="boom"))
        tool = KatanaDockerCrawlerTool("discovery-tools:test", runner=runner)

        result = tool.run("https://example.test", max_pages=5, max_depth=2)

        self.assertEqual(result.failed, [{"url": "https://example.test/", "error": "boom"}])

    def test_uses_stdout_as_failure_detail_when_stderr_is_empty(self) -> None:
        runner = FakeDockerRunner(DockerToolResult(exit_code=1, stdout="invalid flag", stderr=""))
        tool = KatanaDockerCrawlerTool("discovery-tools:test", runner=runner)

        result = tool.run("https://example.test", max_pages=5, max_depth=2)

        self.assertEqual(result.failed, [{"url": "https://example.test/", "error": "invalid flag"}])

    def test_parses_json_and_url_line_output_with_scope_filtering(self) -> None:
        output = "\n".join(
            [
                '{"url":"https://example.test/app","status_code":200,"source":"https://example.test/main.js","response":{"headers":{"Content-Type":"text/html"}}}',
                '{"request":{"endpoint":"https://api.example.test/v1/users","source":"https://example.test/app.js"},"response":{"status_code":200}}',
                "https://outside.test/path",
            ]
        )

        result = parse_katana_output("https://www.example.test", output)

        self.assertEqual(
            [page.url for page in result.pages],
            ["https://api.example.test/v1/users", "https://example.test/app"],
        )
        self.assertEqual(result.out_of_scope, ["https://outside.test/path"])
        self.assertEqual(result.pages[1].content_type, "text/html")

    def test_parses_concatenated_json_objects_from_tty_output(self) -> None:
        output = (
            '{"url":"https://example.test/one","status_code":200}'
            '{"url":"https://example.test/two","status_code":200}'
        )

        result = parse_katana_output("https://example.test", output)

        self.assertEqual(
            [page.url for page in result.pages],
            ["https://example.test/one", "https://example.test/two"],
        )


if __name__ == "__main__":
    unittest.main()
