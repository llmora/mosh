from __future__ import annotations

import unittest
from pathlib import Path


class SecurityToolsContainerTests(unittest.TestCase):
    def test_security_tools_dockerfile_installs_baseline_tools(self) -> None:
        dockerfile = Path("tools/security/Dockerfile").read_text(encoding="utf-8")

        for tool in (
            "build-essential",
            "corepack",
            "curl",
            "file",
            "httpie",
            "jq",
            "maven",
            "nodejs",
            "npm",
            "openjdk-17-jdk-headless",
            "procps",
            "python3",
            "ripgrep",
            "tar",
            "tree",
            "unzip",
            "wget",
        ):
            self.assertIn(tool, dockerfile)
        self.assertIn("bandit", dockerfile)
        self.assertIn("pip-audit", dockerfile)
        self.assertIn("semgrep", dockerfile)
        self.assertIn("npm install -g", dockerfile)
        self.assertIn("corepack@0.29.4", dockerfile)
        self.assertIn("jwt-cli", dockerfile)
        self.assertIn("corepack enable", dockerfile)


if __name__ == "__main__":
    unittest.main()
