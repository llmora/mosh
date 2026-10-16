from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from pathlib import Path


class SetupScriptTests(unittest.TestCase):
    def _run_with_fake_docker(self, *, initial_run: str, post_build_run: str = "pass") -> tuple[subprocess.CompletedProcess[str], str]:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bin_dir = root / "bin"
            bin_dir.mkdir()
            built = root / "built"
            log = root / "docker.log"
            uv = bin_dir / "uv"
            uv.write_text("#!/bin/sh\ncase \"$1\" in sync) exit 0;; run) exit 1;; esac\nexit 2\n", encoding="utf-8")
            docker = bin_dir / "docker"
            docker.write_text(
                "#!/bin/sh\n"
                'echo "$*" >> "$MOSH_FAKE_DOCKER_LOG"\n'
                'if [ -n "${DOCKER_DEFAULT_PLATFORM:-}" ]; then echo "platform=$DOCKER_DEFAULT_PLATFORM" >> "$MOSH_FAKE_DOCKER_LOG"; fi\n'
                'case "$1" in\n'
                '  info) exit 0;;\n'
                '  image) if [ "$3" = "-f" ]; then echo "2099-01-01T00:00:00Z"; fi; exit 0;;\n'
                '  run)\n'
                '    if [ ! -e "$MOSH_FAKE_BUILT" ] && [ "$MOSH_FAKE_INITIAL_RUN" = fail ]; then exit 125; fi\n'
                '    if [ -e "$MOSH_FAKE_BUILT" ] && [ "$MOSH_FAKE_POST_BUILD_RUN" = fail ]; then exit 125; fi\n'
                '    exit 0;;\n'
                '  build) touch "$MOSH_FAKE_BUILT"; exit 0;;\n'
                'esac\nexit 2\n',
                encoding="utf-8",
            )
            uv.chmod(0o755)
            docker.chmod(0o755)
            env = {
                **os.environ,
                "PATH": f"{bin_dir}:{os.environ['PATH']}",
                "MOSH_FAKE_DOCKER_LOG": str(log),
                "MOSH_FAKE_BUILT": str(built),
                "MOSH_FAKE_INITIAL_RUN": initial_run,
                "MOSH_FAKE_POST_BUILD_RUN": post_build_run,
            }
            result = subprocess.run(["bash", "scripts/setup.sh"], env=env, capture_output=True, text=True, check=False)
            return result, log.read_text(encoding="utf-8")

    def test_inspectable_but_unrunnable_image_is_rebuilt(self) -> None:
        result, docker_calls = self._run_with_fake_docker(initial_run="fail")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("mosh-discovery-tools:latest: image cannot run", result.stdout)
        self.assertIn("Building mosh-discovery-tools:latest", result.stdout)
        self.assertIn("mosh-security-tools:latest: current", result.stdout)
        self.assertIn("run --rm --pull=never mosh-discovery-tools:latest true", docker_calls)
        self.assertEqual(docker_calls.count("build -t mosh-discovery-tools:latest"), 1)

    def test_setup_does_not_succeed_if_rebuilt_image_still_cannot_run(self) -> None:
        result, _ = self._run_with_fake_docker(initial_run="fail", post_build_run="fail")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Docker cannot run the image", result.stderr)
        self.assertNotIn("Setup complete", result.stdout)

    def test_setup_ignores_shell_wide_platform_override(self) -> None:
        with unittest.mock.patch.dict(os.environ, {"DOCKER_DEFAULT_PLATFORM": "linux/amd64"}):
            result, docker_calls = self._run_with_fake_docker(initial_run="pass")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("platform=linux/amd64", docker_calls)

    def test_setup_script_is_executable_and_valid_shell(self) -> None:
        script = Path("scripts/setup.sh")

        self.assertTrue(script.exists())
        self.assertTrue(os.access(script, os.X_OK))
        completed = subprocess.run(["bash", "-n", str(script)], capture_output=True, text=True, check=False)
        self.assertEqual(completed.returncode, 0, completed.stderr)

    def test_setup_script_rebuilds_expected_tool_images_from_source_inputs(self) -> None:
        script = Path("scripts/setup.sh").read_text(encoding="utf-8")

        self.assertIn("mosh-discovery-tools:latest", script)
        self.assertIn("tools/discovery/Dockerfile", script)
        self.assertIn("tools/discovery/katana-form-config.yaml", script)
        self.assertIn("tools/discovery/js-endpoint-extractor/package.json", script)
        self.assertIn("tools/discovery/js-endpoint-extractor/js-endpoint-extractor.mjs", script)
        self.assertIn("tools/discovery/source-map-discovery/package.json", script)
        self.assertIn("tools/discovery/source-map-discovery/source-map-discovery.mjs", script)
        self.assertIn("mosh-security-tools:latest", script)
        self.assertIn("tools/security/Dockerfile", script)
        self.assertIn("image_needs_rebuild", script)
        self.assertIn("--force-docker", script)
        self.assertIn("--skip-docker", script)


if __name__ == "__main__":
    unittest.main()
