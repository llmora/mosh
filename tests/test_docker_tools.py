from __future__ import annotations

import subprocess
import unittest
from unittest.mock import patch

from mmosh.docker_tools import DockerToolRunner


class DockerToolRunnerTests(unittest.TestCase):
    def test_runs_container_without_tty_by_default(self) -> None:
        runner = DockerToolRunner("image:test")

        with patch("mmosh.docker_tools.subprocess.run") as run:
            run.return_value.returncode = 0
            run.return_value.stdout = "ok"
            run.return_value.stderr = ""

            result = runner.run(["tool", "--flag"], timeout=30)

        run.assert_called_once_with(
            ["docker", "run", "--rm", "-i", "image:test", "tool", "--flag"],
            input=None,
            text=True,
            capture_output=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(result.stdout, "ok")

    def test_can_run_container_with_interactive_tty(self) -> None:
        runner = DockerToolRunner("image:test")

        with patch("mmosh.docker_tools.subprocess.run") as run:
            run.return_value.returncode = 0
            run.return_value.stdout = "ok"
            run.return_value.stderr = ""

            result = runner.run(["tool", "--flag"], timeout=30, tty=True)

        run.assert_called_once_with(
            ["docker", "run", "--rm", "-i", "-t", "image:test", "tool", "--flag"],
            input=None,
            text=True,
            capture_output=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(result.stdout, "ok")

    def test_can_mount_workspace_and_set_workdir(self) -> None:
        runner = DockerToolRunner("image:test")

        with patch("mmosh.docker_tools.subprocess.run") as run:
            run.return_value.returncode = 0
            run.return_value.stdout = "ok"
            run.return_value.stderr = ""

            result = runner.run(
                ["bash", "-lc", "pwd"],
                timeout=30,
                volumes=[("/host/workspace", "/work")],
                workdir="/work",
            )

        run.assert_called_once_with(
            [
                "docker",
                "run",
                "--rm",
                "-i",
                "-v",
                "/host/workspace:/work",
                "-w",
                "/work",
                "image:test",
                "bash",
                "-lc",
                "pwd",
            ],
            input=None,
            text=True,
            capture_output=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(result.stdout, "ok")

    def test_returns_timeout_result_instead_of_raising(self) -> None:
        runner = DockerToolRunner("image:test")

        with patch("mmosh.docker_tools.subprocess.run") as run:
            run.side_effect = subprocess.TimeoutExpired(
                cmd=["docker", "run"],
                timeout=300,
                output=b"partial output",
            )

            result = runner.run(["tool"], timeout=300)

        self.assertEqual(result.exit_code, 124)
        self.assertEqual(result.stdout, "partial output")
        self.assertEqual(result.stderr, "Docker tool timed out after 300 seconds")


if __name__ == "__main__":
    unittest.main()
