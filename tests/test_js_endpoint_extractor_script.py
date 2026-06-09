from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path


SCRIPT_DIR = Path("tools/discovery/js-endpoint-extractor")
SCRIPT_PATH = SCRIPT_DIR / "js-endpoint-extractor.mjs"


def node_can_import_acorn() -> bool:
    try:
        completed = subprocess.run(
            ["node", "--input-type=module", "-e", "import 'acorn';"],
            cwd=SCRIPT_DIR,
            text=True,
            capture_output=True,
            check=False,
            timeout=5,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False
    return completed.returncode == 0


@unittest.skipUnless(node_can_import_acorn(), "node/acorn is not available")
class JsEndpointExtractorScriptTests(unittest.TestCase):
    def test_resolves_base_constants_and_template_literals(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            html = root / "index.html"
            js = root / "shell.js"
            html.write_text(
                """
                <script>
                window.BACKOFFICE_API_BASE = 'https://api.example.test/api/private';
                </script>
                """,
                encoding="utf-8",
            )
            js.write_text(
                """
                const API_BASE = (window.BACKOFFICE_API_BASE || '/api/private').replace(/\\/$/, '');
                const AUTH_BASE = API_BASE;
                const DEV_BASE = `${API_BASE}/developer`;

                fetch(`${AUTH_BASE}/auth/login`, { method: 'POST' });
                axios.get(`${DEV_BASE}/app-bundle`);
                """,
                encoding="utf-8",
            )

            completed = subprocess.run(
                ["node", str(SCRIPT_PATH), "--base-url", str(html), "--json"],
                input=f"{js}\n",
                text=True,
                capture_output=True,
                check=False,
                timeout=10,
            )

            self.assertEqual(completed.returncode, 0, completed.stderr)
            output = json.loads(completed.stdout)
            endpoints = set(output[0]["endpoints"])
            self.assertEqual(
                endpoints,
                {
                    "https://api.example.test/api/private/auth/login",
                    "https://api.example.test/api/private/developer/app-bundle",
                },
            )

    def test_resolves_inline_context_constants_from_json_input(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            js = root / "shell.js"
            js.write_text(
                """
                const API_BASE = (window.BACKOFFICE_API_BASE || '/api/private').replace(/\\/$/, '');
                const AUTH_BASE = API_BASE;
                const SALES_BASE = `${API_BASE}/sales`;

                fetch(`${AUTH_BASE}/auth/login`, { method: 'POST' });
                fetch(`${SALES_BASE}/customers`);
                """,
                encoding="utf-8",
            )
            payload = [
                {
                    "source": str(js),
                    "page_url": "https://example.test/backoffice/",
                    "inline_scripts": [
                        "window.BACKOFFICE_API_BASE = 'https://api.example.test/api/private';"
                    ],
                }
            ]

            completed = subprocess.run(
                ["node", str(SCRIPT_PATH), "--json"],
                input=json.dumps(payload),
                text=True,
                capture_output=True,
                check=False,
                timeout=10,
            )

            self.assertEqual(completed.returncode, 0, completed.stderr)
            output = json.loads(completed.stdout)
            endpoints = set(output[0]["endpoints"])
            self.assertEqual(
                endpoints,
                {
                    "https://api.example.test/api/private/auth/login",
                    "https://api.example.test/api/private/sales/customers",
                },
            )


if __name__ == "__main__":
    unittest.main()
