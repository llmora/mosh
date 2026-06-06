from __future__ import annotations

import subprocess
from dataclasses import dataclass


@dataclass(frozen=True)
class DockerToolResult:
    exit_code: int
    stdout: str
    stderr: str


class DockerToolRunner:
    def __init__(self, image: str) -> None:
        self.image = image

    def run(self, args: list[str], input_text: str | None = None, timeout: int = 60) -> DockerToolResult:
        command = ["docker", "run", "--rm", "-i", "-t", self.image, *args]
        try:
            completed = subprocess.run(
                command,
                input=input_text,
                text=True,
                capture_output=True,
                timeout=timeout,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            return DockerToolResult(
                exit_code=124,
                stdout=_decode_timeout_output(exc.stdout),
                stderr=f"Docker tool timed out after {timeout} seconds",
            )
        return DockerToolResult(
            exit_code=completed.returncode,
            stdout=completed.stdout,
            stderr=completed.stderr,
        )


def _decode_timeout_output(output: str | bytes | None) -> str:
    if output is None:
        return ""
    if isinstance(output, bytes):
        return output.decode("utf-8", errors="replace")
    return output
