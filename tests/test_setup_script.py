from __future__ import annotations

import os
import subprocess
import unittest
from pathlib import Path


class SetupScriptTests(unittest.TestCase):
    def test_setup_script_is_executable_and_valid_shell(self) -> None:
        script = Path("scripts/setup.sh")

        self.assertTrue(script.exists())
        self.assertTrue(os.access(script, os.X_OK))
        completed = subprocess.run(["bash", "-n", str(script)], capture_output=True, text=True, check=False)
        self.assertEqual(completed.returncode, 0, completed.stderr)

    def test_setup_script_rebuilds_expected_tool_images_from_source_inputs(self) -> None:
        script = Path("scripts/setup.sh").read_text(encoding="utf-8")

        self.assertIn("osh-discovery-tools:latest", script)
        self.assertIn("tools/discovery/Dockerfile", script)
        self.assertIn("tools/discovery/katana-form-config.yaml", script)
        self.assertIn("tools/discovery/js-endpoint-extractor/package.json", script)
        self.assertIn("tools/discovery/js-endpoint-extractor/js-endpoint-extractor.mjs", script)
        self.assertIn("osh-security-tools:latest", script)
        self.assertIn("tools/security/Dockerfile", script)
        self.assertIn("image_needs_rebuild", script)
        self.assertIn("--force-docker", script)
        self.assertIn("--skip-docker", script)


if __name__ == "__main__":
    unittest.main()
