from __future__ import annotations

import unittest
from pathlib import Path


class DiscoveryToolsContainerTests(unittest.TestCase):
    def test_dockerfile_installs_extractify(self) -> None:
        dockerfile = Path("tools/discovery/Dockerfile").read_text(encoding="utf-8")

        self.assertIn("go install github.com/SharokhAtaie/extractify@latest", dockerfile)
        self.assertIn("COPY --from=katana-builder /go/bin/extractify /usr/local/bin/extractify", dockerfile)

    def test_dockerfile_installs_static_js_endpoint_extractor(self) -> None:
        dockerfile = Path("tools/discovery/Dockerfile").read_text(encoding="utf-8")

        self.assertIn("nodejs", dockerfile)
        self.assertIn("npm", dockerfile)
        self.assertIn("COPY tools/discovery/js-endpoint-extractor/package.json", dockerfile)
        self.assertIn("npm install --omit=dev", dockerfile)
        self.assertIn("COPY tools/discovery/js-endpoint-extractor/js-endpoint-extractor.mjs", dockerfile)
        self.assertIn("/usr/local/bin/js-endpoint-extractor", dockerfile)

    def test_dockerfile_installs_dirb(self) -> None:
        dockerfile = Path("tools/discovery/Dockerfile").read_text(encoding="utf-8")

        self.assertIn("dirb", dockerfile)


if __name__ == "__main__":
    unittest.main()
