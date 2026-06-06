from __future__ import annotations

import contextlib
import io
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from appsec_harness.cli import main
from appsec_harness.scope import report_dir_name
from tests.fakes import FakeCrewRunner
from tests.fixtures import fixture_server


class CliTests(unittest.TestCase):
    def test_cli_writes_markdown_report_and_runtime_json_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with fixture_server() as url:
                stdout = io.StringIO()
                with patch("appsec_harness.orchestrator.build_discovery_crew_runner", return_value=FakeCrewRunner()):
                    with contextlib.redirect_stdout(stdout):
                        exit_code = main([url, "--output-root", str(Path(directory) / "report"), "--max-pages", "5"])

                report_dir = Path(directory) / "report" / report_dir_name(url) / "discovery"
                self.assertEqual(exit_code, 0)
                self.assertIn("Report written to", stdout.getvalue())
                self.assertTrue((report_dir / "report.md").exists())
                self.assertFalse((report_dir / "report.json").exists())
                self.assertTrue((report_dir / "events.json").exists())
                self.assertTrue((report_dir / "memory.json").exists())

                import json
                memory = json.loads((report_dir / "memory.json").read_text(encoding="utf-8"))
                self.assertTrue(any(item["kind"] == "llm_report" for item in memory))


if __name__ == "__main__":
    unittest.main()
