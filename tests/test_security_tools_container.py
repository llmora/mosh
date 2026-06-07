from __future__ import annotations

import unittest
from pathlib import Path


class SecurityToolsContainerTests(unittest.TestCase):
    def test_security_tools_dockerfile_installs_baseline_tools(self) -> None:
        dockerfile = Path("tools/security/Dockerfile").read_text(encoding="utf-8")

        for tool in ("curl", "httpie", "jq", "python3", "nodejs", "npm", "ripgrep", "wget", "build-essential"):
            self.assertIn(tool, dockerfile)
        self.assertIn("npm install -g jwt-cli", dockerfile)


if __name__ == "__main__":
    unittest.main()
