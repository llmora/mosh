from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path


SCRIPT_PATH = Path("tools/discovery/source-map-discovery/source-map-discovery.mjs")


def node_is_available() -> bool:
    try:
        completed = subprocess.run(
            ["node", "--version"],
            text=True,
            capture_output=True,
            check=False,
            timeout=5,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False
    return completed.returncode == 0


@unittest.skipUnless(node_is_available(), "node is not available")
class SourceMapDiscoveryScriptTests(unittest.TestCase):
    def test_discovers_explicit_source_mapping_url(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            js = root / "app.js"
            source_map = root / "app.js.map"
            js.write_text("console.log('app');\n//# sourceMappingURL=app.js.map\n", encoding="utf-8")
            source_map.write_text(
                json.dumps(
                    {
                        "version": 3,
                        "file": "app.js",
                        "sources": ["src/App.jsx"],
                        "sourcesContent": ["export default function App() {}"],
                    }
                ),
                encoding="utf-8",
            )

            completed = subprocess.run(
                ["node", str(SCRIPT_PATH), "--json"],
                input=f"{js}\n",
                text=True,
                capture_output=True,
                check=False,
                timeout=10,
            )

            self.assertEqual(completed.returncode, 0, completed.stderr)
            output = json.loads(completed.stdout)
            self.assertEqual(output[0]["source"], str(js))
            self.assertEqual(output[0]["source_maps"][0]["url"], str(source_map))
            self.assertEqual(output[0]["source_maps"][0]["sources"], ["src/App.jsx"])
            self.assertEqual(output[0]["source_maps"][0]["sources_with_content"], 1)

    def test_discovers_sibling_source_map_without_comment(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            js = root / "bundle.js"
            source_map = root / "bundle.js.map"
            js.write_text("console.log('bundle');\n", encoding="utf-8")
            source_map.write_text(
                json.dumps({"version": 3, "sources": ["src/index.ts"], "mappings": ""}),
                encoding="utf-8",
            )

            completed = subprocess.run(
                ["node", str(SCRIPT_PATH), "--json"],
                input=json.dumps([{"source": str(js)}]),
                text=True,
                capture_output=True,
                check=False,
                timeout=10,
            )

            self.assertEqual(completed.returncode, 0, completed.stderr)
            output = json.loads(completed.stdout)
            self.assertEqual(output[0]["source_maps"][0]["url"], str(source_map))
            self.assertEqual(output[0]["checked"][0]["reason"], "sibling")


if __name__ == "__main__":
    unittest.main()
