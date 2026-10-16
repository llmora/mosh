from __future__ import annotations

import json
import io
import os
import re
import shutil
import stat
import subprocess
import tempfile
import threading
import time
import unittest
import zipfile
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import quote
from unittest.mock import Mock, patch

from dotenv import dotenv_values

from mosh.engagements import load_engagement
from mosh.web import DiscoveryRun, PlanningRun, ReportingRun, TestingRun, WebApp, check_asset_reachability, check_provider_api, main


class WebTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.environment = patch.dict(os.environ, {}, clear=True)
        self.environment.start()
        self.addCleanup(self.environment.stop)
        self.app = WebApp(
            self.root,
            environment_probe=lambda: {"uv": True, "docker": True, "images": True},
            build_runner=lambda: True,
            provider_checker=lambda provider, key, base_url: (True, ""),
            asset_checker=lambda kind, locator: (True, "Reachable when added"),
            folder_root=self.root,
        )

    def add_asset(self, kind: str, locator: str):
        response = self.post("/new/add", {"asset_type": kind, "locator": locator})
        deadline = time.monotonic() + 2
        while self.app.assessment_draft.check_state == "checking" and time.monotonic() < deadline:
            time.sleep(.001)
        self.assertNotEqual(self.app.assessment_draft.check_state, "checking")
        return response

    def get(self, path: str, *, host: str = "127.0.0.1:8765"):
        return self.app.handle("GET", path, headers={"Host": host})

    def post(self, path: str, data: dict[str, str] | None = None, *, host: str = "127.0.0.1:8765", origin: str | None = None):
        headers = {"Host": host}
        if origin:
            headers["Origin"] = origin
        return self.app.handle("POST", path, {"csrf": self.app.csrf_token, **(data or {})}, headers)

    def connect(self, provider: str, key: str = "", base_url: str = ""):
        result = self.post("/setup/provider", {"provider": provider, "api_key": key, "base_url": base_url})
        self.wait_for_check(provider)
        return result

    def wait_for_check(self, provider: str) -> None:
        deadline = time.monotonic() + 2
        while self.app.provider_state.get(provider, ("", ""))[0] == "checking" and time.monotonic() < deadline:
            time.sleep(.001)
        self.assertNotEqual(self.app.provider_state.get(provider, ("", ""))[0], "checking")

    def ready(self) -> None:
        (self.root / ".env").write_text("DEEPSEEK_API_KEY=test-key\n", encoding="utf-8")


class WebSetupTests(WebTestCase):
    def test_environment_probe_requires_runnable_images(self) -> None:
        commands = []

        def command_ok(command):
            commands.append(command)
            return command != ["docker", "run", "--rm", "--pull=never", "mosh-discovery-tools:latest", "true"]

        with patch("mosh.web.shutil.which", return_value="/usr/local/bin/tool"), patch("mosh.web._command_ok", side_effect=command_ok):
            checks = self.app._probe_environment()

        self.assertTrue(checks["docker"])
        self.assertFalse(checks["images"])
        self.assertIn(["docker", "run", "--rm", "--pull=never", "mosh-discovery-tools:latest", "true"], commands)

    def test_environment_probe_ignores_global_platform_override(self) -> None:
        with patch.dict(os.environ, {"DOCKER_DEFAULT_PLATFORM": "linux/amd64"}), patch("mosh.web.shutil.which", return_value="/usr/local/bin/tool"), patch("mosh.web.subprocess.run") as run:
            run.return_value.returncode = 0
            checks = self.app._probe_environment()
        self.assertTrue(checks["images"])
        self.assertEqual(run.call_count, 3)
        self.assertTrue(all("DOCKER_DEFAULT_PLATFORM" not in call.kwargs["env"] for call in run.call_args_list))

    def test_connect_shows_checking_then_saves_only_after_success(self) -> None:
        started = threading.Event()
        release = threading.Event()
        self.addCleanup(release.set)

        def check(provider: str, key: str, base_url: str) -> tuple[bool, str]:
            started.set()
            release.wait(2)
            return True, ""

        self.app.provider_checker = check
        self.assertEqual(self.post("/setup/provider", {"provider": "deepseek", "api_key": "secret"}).location, "/setup?step=model")
        self.assertTrue(started.wait(1))
        page = self.get("/setup?step=model").body
        self.assertIn("Checking API", page)
        self.assertIn('http-equiv="refresh"', page)
        self.assertIn('<button class="primary" type="button" disabled>Finish setup</button>', page)
        self.assertFalse((self.root / ".env").exists())
        self.assertEqual(self.post("/setup/finish").location, "/setup?step=model")
        release.set()
        self.wait_for_check("deepseek")
        page = self.get("/setup?step=model").body
        self.assertIn("Verified", page)
        self.assertNotIn("Checking API", page)
        self.assertNotIn("secret", page)
        self.assertEqual(dotenv_values(self.root / ".env")["DEEPSEEK_API_KEY"], "secret")

    def test_failed_check_does_not_save_and_retry_can_succeed(self) -> None:
        self.app.provider_checker = lambda provider, key, base_url: (False, "API key was rejected.")
        self.connect("deepseek", "rejected-key")
        page = self.get("/setup?step=model").body
        self.assertIn("API key was rejected.", page)
        self.assertIn("Retry", page)
        self.assertIn('<button class="primary" type="button" disabled>Finish setup</button>', page)
        self.assertNotIn("rejected-key", page)
        self.assertFalse((self.root / ".env").exists())
        self.app.provider_checker = lambda provider, key, base_url: (True, "")
        self.connect("deepseek", "good-key")
        self.assertEqual(dotenv_values(self.root / ".env")["DEEPSEEK_API_KEY"], "good-key")

    def test_provider_checks_use_expected_urls_and_auth_without_model_calls(self) -> None:
        opener = Mock()
        with patch("mosh.web.build_opener", return_value=opener):
            opener.open.return_value = io.BytesIO(b'{"data":[]}')
            self.assertEqual(check_provider_api("deepseek", "deep-key", ""), (True, ""))
            request = opener.open.call_args.args[0]
            self.assertEqual(request.full_url, "https://api.deepseek.com/models")
            self.assertEqual(request.get_header("Authorization"), "Bearer deep-key")

            opener.open.return_value = io.BytesIO(b'{"data":{}}')
            self.assertEqual(check_provider_api("openrouter", "router-key", ""), (True, ""))
            request = opener.open.call_args.args[0]
            self.assertEqual(request.full_url, "https://openrouter.ai/api/v1/key")
            self.assertEqual(request.get_header("Authorization"), "Bearer router-key")

            opener.open.return_value = io.BytesIO(b'{"data":[]}')
            self.assertEqual(check_provider_api("custom", "", "http://localhost:11434/v1"), (True, ""))
            request = opener.open.call_args.args[0]
            self.assertEqual(request.full_url, "http://localhost:11434/v1/models")
            self.assertIsNone(request.get_header("Authorization"))

            opener.open.side_effect = HTTPError("https://api.deepseek.com/models", 401, "secret details", None, None)
            self.assertEqual(check_provider_api("deepseek", "bad-key", ""), (False, "API key was rejected."))
            opener.open.side_effect = HTTPError("https://api.deepseek.com/models", 302, "redirect", None, None)
            self.assertEqual(check_provider_api("deepseek", "bad-key", ""), (False, "API redirected the check. Verify the endpoint URL."))
            opener.open.side_effect = HTTPError("http://localhost:11434/v1/models", 401, "auth", None, None)
            self.assertEqual(check_provider_api("custom", "", "http://localhost:11434/v1"), (False, "This endpoint requires an API key."))

    def test_save_failure_finishes_check_without_claiming_success(self) -> None:
        with patch("mosh.web._write_env_settings", side_effect=RuntimeError("secret-key")):
            self.connect("deepseek", "secret-key")
        page = self.get("/setup?step=model").body
        self.assertIn("Could not save provider access.", page)
        self.assertNotIn("secret-key", page)
        self.assertFalse((self.root / ".env").exists())

    def test_first_run_waits_for_configuration_then_opens_assessments(self) -> None:
        self.assertEqual(self.get("/").location, "/setup")
        environment = self.get("/setup").body
        self.assertIn("Python and uv", environment)
        self.assertIn("Tool images", environment)
        self.assertNotIn("Build tool images", environment)
        self.assertNotIn("New assessment", environment)
        providers = self.get("/setup?step=model").body
        self.assertIn("Connect providers", providers)
        self.assertIn("DeepSeek", providers)
        self.assertIn("OpenRouter", providers)
        self.assertIn("Custom endpoint", providers)
        self.assertEqual(providers.count(">Connect</a>"), 3)
        self.assertLess(providers.index("DeepSeek"), providers.index("OpenRouter"))
        self.assertNotIn("Planning model", providers)
        self.assertNotIn("3. Review", providers)
        self.assertIn('<button class="primary" type="button" disabled>Finish setup</button>', providers)

        secret = "test-secret-with-#-and-$"
        self.assertIn('name="api_key"', self.get("/setup?step=provider&provider=deepseek").body)
        self.assertEqual(self.connect("deepseek", secret).location, "/setup?step=model")
        pending = self.get("/setup?step=model").body
        self.assertIn("Verified", pending)
        self.assertIn('action="/setup/finish"', pending)
        self.assertIn('>Finish setup</button>', pending)
        self.assertNotIn(secret, pending)
        self.assertEqual(self.get("/setup?step=review").location, "/setup?step=model")
        self.assertEqual(dotenv_values(self.root / ".env")["DEEPSEEK_API_KEY"], secret)

        self.assertEqual(self.post("/setup/finish").location, "/")
        self.assertTrue(self.app.setup_ready())
        self.assertEqual(dotenv_values(self.root / ".env")["DEEPSEEK_API_KEY"], secret)
        self.assertEqual(stat.S_IMODE((self.root / ".env").stat().st_mode), 0o600)
        self.assertIn("New assessment", self.get("/").body)
        self.assertEqual(self.get("/setup").location, "/")
        (self.root / ".env").unlink()
        self.assertEqual(self.get("/").location, "/setup")

    def test_existing_config_skips_setup_and_preserves_other_env_settings(self) -> None:
        (self.root / ".env").write_text("# local settings\nMOSH_MAX_DEPTH=3\n", encoding="utf-8")
        self.connect("openrouter", "router-key")
        self.assertEqual(self.post("/setup/finish").location, "/")
        saved = (self.root / ".env").read_text(encoding="utf-8")
        self.assertIn("# local settings", saved)
        self.assertIn("MOSH_MAX_DEPTH=3", saved)
        self.assertEqual(dotenv_values(self.root / ".env")["OPENROUTER_API_KEY"], "router-key")
        self.assertEqual(self.get("/setup").location, "/")

    def test_invalid_provider_or_missing_key_does_not_complete_setup(self) -> None:
        response = self.connect("other", "abc")
        self.assertEqual(response.location, "/setup?step=model")
        self.assertFalse(self.app.setup_ready())
        response = self.connect("deepseek", "")
        self.assertIn("valid API key", response.body)
        response = self.connect("deepseek", "bad\nkey")
        self.assertIn("valid API key", response.body)
        self.assertFalse((self.root / ".env").exists())

    def test_mixed_model_configuration_requires_matching_api_access(self) -> None:
        (self.root / "mosh.yaml").write_text("models:\n  planning:\n    planner: openai/gpt-example\n", encoding="utf-8")
        self.assertEqual(self.connect("deepseek", "direct-key").location, "/setup?step=model")
        response = self.get("/setup?step=model")
        self.assertIn("OpenRouter", response.body)
        self.assertIn('<button class="primary" type="button" disabled>Finish setup</button>', response.body)
        self.assertEqual(dotenv_values(self.root / ".env")["DEEPSEEK_API_KEY"], "direct-key")
        self.assertIn("Verified", response.body)
        self.assertIn("Additional provider access is needed", self.post("/setup/finish").body)
        self.assertEqual(self.get("/").location, "/setup")
        self.assertEqual(self.connect("openrouter", "router-key").location, "/setup?step=model")
        providers = self.get("/setup?step=model").body
        self.assertIn('action="/setup/finish"', providers)
        self.assertNotIn("direct-key", providers)
        self.assertNotIn("router-key", providers)
        self.assertEqual(self.post("/setup/finish").location, "/")
        saved = dotenv_values(self.root / ".env")
        self.assertEqual(saved["DEEPSEEK_API_KEY"], "direct-key")
        self.assertEqual(saved["OPENROUTER_API_KEY"], "router-key")

    def test_existing_provider_key_is_kept_when_adding_another(self) -> None:
        (self.root / "mosh.yaml").write_text("models:\n  planning:\n    planner: openai/gpt-example\n", encoding="utf-8")
        (self.root / ".env").write_text("# existing\nDEEPSEEK_API_KEY=existing-key\n", encoding="utf-8")
        page = self.get("/setup?step=model").body
        self.assertIn("Configured", page)
        self.assertNotIn("existing-key", page)
        self.assertEqual(self.connect("openrouter", "router-key").location, "/setup?step=model")
        self.assertEqual(self.post("/setup/finish").location, "/")
        saved = (self.root / ".env").read_text(encoding="utf-8")
        self.assertIn("# existing", saved)
        self.assertEqual(dotenv_values(self.root / ".env")["DEEPSEEK_API_KEY"], "existing-key")
        self.assertEqual(dotenv_values(self.root / ".env")["OPENROUTER_API_KEY"], "router-key")

    def test_custom_endpoint_can_be_added_with_api_key(self) -> None:
        page = self.get("/setup?step=provider&provider=custom").body
        self.assertIn('name="base_url"', page)
        self.assertIn("Optional", page)
        self.assertEqual(self.connect("custom", "local-key", "http://127.0.0.1:11434/v1").location, "/setup?step=model")
        providers = self.get("/setup?step=model").body
        self.assertIn("Verified", providers)
        self.assertIn('action="/setup/finish"', providers)
        self.assertNotIn("local-key", providers)
        self.assertEqual(self.post("/setup/finish").location, "/")
        saved = dotenv_values(self.root / ".env")
        self.assertEqual(saved["MOSH_LLM_BASE_URL"], "http://127.0.0.1:11434/v1")
        self.assertEqual(saved["MOSH_LLM_API_KEY"], "local-key")

    def test_custom_endpoint_without_key_completes_setup(self) -> None:
        self.assertEqual(self.connect("custom", base_url="http://localhost:11434/v1").location, "/setup?step=model")
        providers = self.get("/setup?step=model").body
        self.assertIn('action="/setup/finish"', providers)
        self.assertIn("This custom endpoint currently handles all models", providers)
        self.assertEqual(providers.count(">Connect</a>"), 2)
        self.assertEqual(self.post("/setup/finish").location, "/")
        saved = dotenv_values(self.root / ".env")
        self.assertEqual(saved["MOSH_LLM_BASE_URL"], "http://localhost:11434/v1")
        self.assertNotIn("MOSH_LLM_API_KEY", saved)
        self.assertTrue(self.app.setup_ready())

    def test_custom_deepseek_and_openrouter_can_connect_and_serve_different_models(self) -> None:
        from mosh.config import AppConfig

        (self.root / "mosh.yaml").write_text(
            "models:\n"
            "  planning:\n"
            "    planner: custom/local-planner\n"
            "    reviewer: openrouter/deepseek/deepseek-v4-pro\n",
            encoding="utf-8",
        )
        self.connect("custom", base_url="http://localhost:11434/v1")
        self.assertFalse(self.app.setup_ready())
        self.assertIn("Additional provider access is needed", self.post("/setup/finish").body)
        self.connect("deepseek", "deep-key")
        self.assertFalse(self.app.setup_ready())
        self.assertIn(">Connect</a>", self.get("/setup?step=model").body)
        self.connect("openrouter", "router-key")
        self.assertTrue(self.app.setup_ready())
        self.assertEqual(self.post("/setup/finish").location, "/")

        config = AppConfig.from_env(self.root / "mosh.yaml", self.root / ".env")
        self.assertEqual(config.llm_base_url_for_model(config.models.planning.planner), "http://localhost:11434/v1")
        self.assertIsNone(config.llm_base_url_for_model(config.models.discovery_live.crawler))
        self.assertEqual(config.llm_base_url_for_model(config.models.planning.reviewer), config.openrouter_base_url)
        settings = dotenv_values(self.root / ".env")
        self.assertEqual(settings["DEEPSEEK_API_KEY"], "deep-key")
        self.assertEqual(settings["OPENROUTER_API_KEY"], "router-key")

    def test_keyless_custom_endpoint_removes_stale_custom_key(self) -> None:
        (self.root / ".env").write_text("MOSH_LLM_API_KEY=old-key\nMOSH_MAX_DEPTH=3\n", encoding="utf-8")
        self.connect("custom", base_url="http://localhost:11434/v1")
        saved = dotenv_values(self.root / ".env")
        self.assertNotIn("MOSH_LLM_API_KEY", saved)
        self.assertEqual(saved["MOSH_MAX_DEPTH"], "3")
        self.assertEqual(saved["MOSH_LLM_BASE_URL"], "http://localhost:11434/v1")

    def test_custom_endpoint_rejects_invalid_url_without_writing_settings(self) -> None:
        for url in ("", "localhost:11434/v1", "file:///tmp/model", "http://user:secret@localhost/v1", "http://@localhost/v1", "http://localhost/v1?key=x"):
            response = self.connect("custom", base_url=url)
            self.assertIn("Enter an http or https endpoint URL", response.body)
        self.assertFalse((self.root / ".env").exists())

    def test_missing_images_build_automatically_and_show_progress(self) -> None:
        images = {"present": False}
        started = threading.Event()
        release = threading.Event()
        self.addCleanup(release.set)
        calls = []

        def build() -> bool:
            calls.append(1)
            started.set()
            release.wait(2)
            images["present"] = True
            return True

        self.app.environment_probe = lambda: {"uv": True, "docker": True, "images": images["present"]}
        self.app.build_runner = build
        page = self.get("/setup").body
        self.assertTrue(started.wait(1))
        self.assertIn('class="building">Building tools', page)
        self.assertIn('http-equiv="refresh"', page)
        self.assertNotIn("Retry build", page)
        self.assertIn('<button class="primary" type="button" disabled>Continue</button>', page)
        self.assertEqual(self.get("/setup?step=model").location, "/setup")
        self.assertEqual(self.connect("deepseek", "test").location, "/setup")
        self.get("/setup")
        self.assertEqual(len(calls), 1)

        release.set()
        deadline = time.monotonic() + 2
        while self.app.build_state == "running" and time.monotonic() < deadline:
            time.sleep(.001)
        self.assertEqual(self.app.build_state, "done")
        page = self.get("/setup").body
        self.assertIn('class="ready">Ready', page)
        self.assertNotIn('http-equiv="refresh"', page)
        self.assertIn('<a class="primary" href="/setup?step=model">Continue</a>', page)
        self.assertIn("Connect providers", self.get("/setup?step=model").body)

    def test_failed_image_build_offers_retry_without_looping(self) -> None:
        calls = []
        self.app.environment_probe = lambda: {"uv": True, "docker": True, "images": False}
        self.app.build_runner = lambda: calls.append(1) or False
        self.get("/setup")
        deadline = time.monotonic() + 2
        while self.app.build_state == "running" and time.monotonic() < deadline:
            time.sleep(.001)
        self.assertEqual(self.app.build_state, "failed")
        page = self.get("/setup").body
        self.assertIn('class="failed">Build failed', page)
        self.assertIn("Retry build", page)
        self.assertIn('<button class="primary" type="button" disabled>Continue</button>', page)
        self.assertNotIn('http-equiv="refresh"', page)
        self.assertEqual(len(calls), 1)
        self.assertEqual(self.post("/setup/build").location, "/setup")
        deadline = time.monotonic() + 2
        while self.app.build_state == "running" and time.monotonic() < deadline:
            time.sleep(.001)
        self.assertEqual(len(calls), 2)

    def test_image_deleted_after_previous_build_triggers_new_build(self) -> None:
        release = threading.Event()
        self.addCleanup(release.set)
        started = threading.Event()
        self.app.build_state = "done"
        self.app.environment_probe = lambda: {"uv": True, "docker": True, "images": False}

        def build() -> bool:
            started.set()
            release.wait(2)
            return False

        self.app.build_runner = build
        page = self.get("/setup").body
        self.assertTrue(started.wait(1))
        self.assertIn('class="building">Building tools', page)

    def test_images_wait_for_docker_before_building(self) -> None:
        calls = []
        self.app.environment_probe = lambda: {"uv": True, "docker": False, "images": False}
        self.app.build_runner = lambda: calls.append(1) or True
        page = self.get("/setup").body
        self.assertIn("Install uv and Docker", page)
        self.assertNotIn("Building tools", page)
        self.assertIn('<button class="primary" type="button" disabled>Continue</button>', page)
        self.assertEqual(self.post("/setup/build").location, "/setup")
        self.assertEqual(calls, [])

    def test_setup_finish_waits_if_environment_stops_being_ready(self) -> None:
        self.assertEqual(self.connect("deepseek", "test-key").location, "/setup?step=model")
        self.app.environment_probe = lambda: {"uv": True, "docker": False, "images": False}
        self.assertEqual(self.get("/setup?step=model").location, "/setup")
        self.assertEqual(self.post("/setup/finish").location, "/setup")
        self.assertEqual(dotenv_values(self.root / ".env")["DEEPSEEK_API_KEY"], "test-key")

    def test_build_uses_source_checkout_with_temporary_configuration_root(self) -> None:
        with patch("mosh.web.subprocess.run") as run:
            run.return_value.returncode = 0
            self.assertTrue(self.app._build_tool_images())
        script = Path(__file__).resolve().parents[1] / "scripts" / "setup.sh"
        self.assertEqual(run.call_args.args[0], [str(script)])
        self.assertEqual(run.call_args.kwargs["cwd"], script.parent.parent)

    def test_build_failure_keeps_diagnostics_for_web_page(self) -> None:
        def fail_build(*args, **kwargs):
            kwargs["stdout"].write(b"Docker build failed: invalid repository signature <check>\n")
            return Mock(returncode=1)

        with patch.dict(os.environ, {"DOCKER_DEFAULT_PLATFORM": "linux/amd64"}), patch("mosh.web.subprocess.run", side_effect=fail_build) as run:
            self.assertFalse(self.app._build_tool_images())
        self.assertNotIn("DOCKER_DEFAULT_PLATFORM", run.call_args.kwargs["env"])
        self.assertIn("invalid repository signature", self.app.build_error)
        self.app.build_state = "failed"
        self.app._record_tool_checks({"uv": True, "docker": True, "images": False})
        self.assertIn("Build details", self.app._local_tools_section())
        self.assertIn("&lt;check&gt;", self.app._local_tools_section())

    def test_external_host_origin_and_missing_form_token_are_rejected(self) -> None:
        self.assertEqual(self.get("/setup", host="example.com").status, 403)
        self.assertEqual(self.get("/setup", host="127.0.0.1.evil.test").status, 403)
        self.assertEqual(
            self.post("/setup/provider", {"provider": "deepseek", "api_key": "secret"}, origin="https://evil.test").status,
            403,
        )
        self.assertEqual(self.app.handle("POST", "/setup/provider", {}, {"Host": "localhost:8765"}).status, 403)
        self.assertEqual(self.post("/setup/provider", {"provider": "deepseek", "api_key": "secret"}, origin="http://127.0.0.1:8765").status, 303)
        self.wait_for_check("deepseek")

    def test_web_server_binds_to_loopback_only(self) -> None:
        with patch("mosh.web.HTTPServer") as server:
            server.return_value.__enter__.return_value.server_port = 8765
            server.return_value.__enter__.return_value.serve_forever.side_effect = KeyboardInterrupt
            self.assertEqual(main(["--project-root", str(self.root), "--port", "8765"]), 0)
        self.assertEqual(server.call_args.args[0], ("127.0.0.1", 8765))


class WebSettingsTests(WebTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.ready()
        self.app.onboarding_active = False

    def _review_digest(self, body: str) -> str:
        match = re.search(r'name="source_digest" value="([a-f0-9]+)"', body)
        self.assertIsNotNone(match)
        return match.group(1)

    def test_settings_show_effective_models_and_link_from_header(self) -> None:
        page = self.get("/settings").body
        self.assertIn('<a href="/settings" data-settings-link>Settings', page)
        self.assertIn("Connected providers", page)
        self.assertIn("DeepSeek", page)
        self.assertIn("Model assignments", page)
        self.assertIn('href="/settings/models/planning"', page)
        self.assertIn("2 models across 5 agents", page)
        discovery_editor = self.get("/settings/models/discovery").body
        self.assertIn("Live discovery", discovery_editor)
        self.assertIn("Source discovery", discovery_editor)
        self.assertIn('name="model_id__discovery_live__crawler" type="text" maxlength="200" required value="deepseek-v4-flash"', discovery_editor)

    def test_missing_tool_image_appears_in_settings_and_can_be_rebuilt(self) -> None:
        images = {"ready": False}
        builds = []
        self.app.environment_probe = lambda: {
            "uv": True, "docker": True, "images": images["ready"],
            "discovery_image": images["ready"], "security_image": True,
        }

        def build() -> bool:
            builds.append(1)
            images["ready"] = True
            return True

        self.app.build_runner = build
        self.app._record_tool_checks(self.app.environment_probe())
        page = self.get("/settings").body
        self.assertIn('href="/settings#local-tools" data-settings-link', page)
        self.assertIn('id="local-tools"', page)
        self.assertIn('action="/settings/tools/build"', page)
        self.assertIn('action="/settings/tools/check"', page)
        self.assertIn('Discovery tools</strong><span class="tool-check missing"', page)
        self.assertIn('Security tools</strong><span class="tool-check ready"', page)
        self.assertTrue(json.loads(self.get("/settings/tools/status").body)["warning"])

        self.assertEqual(self.post("/settings/tools/build").location, "/settings#local-tools")
        deadline = time.monotonic() + 2
        while self.app.build_state == "running" and time.monotonic() < deadline:
            time.sleep(.001)
        self.assertEqual(self.app.build_state, "done")
        self.assertEqual(builds, [1])
        status = json.loads(self.get("/settings/tools/status").body)
        self.assertFalse(status["warning"])
        self.assertIn('Discovery tools</strong><span class="tool-check ready"', status["html"])
        self.assertNotIn('action="/settings/tools/build"', status["html"])

    def test_docker_unavailable_explains_fix_and_disables_build(self) -> None:
        docker = {"ready": False}
        self.app.environment_probe = lambda: {"uv": True, "docker": docker["ready"], "images": docker["ready"]}
        self.app._record_tool_checks(self.app.environment_probe())
        page = self.get("/settings").body
        self.assertIn("Start Docker, then check again", page)
        self.assertNotIn('action="/settings/tools/build"', page)
        self.assertTrue(json.loads(self.get("/settings/tools/status").body)["warning"])
        docker["ready"] = True
        self.assertEqual(self.post("/settings/tools/check").location, "/settings#local-tools")
        deadline = time.monotonic() + 2
        while self.app._tool_snapshot()[1] and time.monotonic() < deadline:
            time.sleep(.001)
        self.assertFalse(json.loads(self.get("/settings/tools/status").body)["warning"])

    def test_settings_pages_can_close_to_previous_page_or_assessments(self) -> None:
        for path in ("/settings", "/settings/providers", "/settings/providers/deepseek", "/settings/models/planning"):
            with self.subTest(path=path):
                page = self.get(path).body
                self.assertIn('<body class="settings-page">', page)
                self.assertIn('class="settings-close" href="/" data-close-settings aria-label="Close settings"', page)
                self.assertIn('class="settings-footer"><a class="secondary" href="/" data-close-settings>Close settings</a>', page)
        review = self.post("/settings/models/planning", {
            "action": "review", "provider": "deepseek", "model_id": "deepseek-v4-pro",
        }).body
        self.assertIn('aria-label="Close settings"', review)
        self.assertIn('>Close settings</a>', review)

    def test_stage_change_reviews_and_saves_only_that_stage(self) -> None:
        config_path = self.root / "mosh.yaml"
        config_path.write_text(
            "# user note\nmodels:\n  planning:\n    planner: deepseek/deepseek-v4-flash\n"
            "  testing:\n    reviewer: deepseek/deepseek-v4-pro\n",
            encoding="utf-8",
        )
        editor = self.get("/settings/models/planning").body
        self.assertIn("Agent assignments", editor)
        self.assertIn('name="provider__planning__planner"', editor)
        self.assertIn("This assigns one model to all 5 agents", editor)
        reviewed = self.post("/settings/models/planning", {
            "action": "review", "provider": "deepseek", "model_id": "deepseek-v4-pro",
        }).body
        self.assertIn("Review planning models", reviewed)
        self.assertIn("Routing changes", reviewed)
        self.assertIn("Save assignments", reviewed)
        self.assertNotIn("other stages", reviewed)
        self.assertIn("planner: deepseek/deepseek-v4-flash", config_path.read_text(encoding="utf-8"))

        saved = self.post("/settings/models/planning", {
            "action": "save", "provider": "deepseek", "model_id": "deepseek-v4-pro",
            "reviewed": "yes", "source_digest": self._review_digest(reviewed),
        })
        self.assertEqual(saved.location, "/settings?saved=planning")
        content = config_path.read_text(encoding="utf-8")
        self.assertIn("# user note", content)
        self.assertIn("planner: deepseek/deepseek-v4-pro", content)
        self.assertIn("engagement_refiner: deepseek/deepseek-v4-pro", content)
        self.assertIn("reviewer: deepseek/deepseek-v4-pro", content)
        self.assertIn("Model assignments saved", self.get(saved.location).body)

    def test_individual_agent_assignments_review_and_save_only_changed_roles(self) -> None:
        from mosh.config import AppConfig

        (self.root / ".env").write_text("DEEPSEEK_API_KEY=deep-key\nOPENROUTER_API_KEY=router-key\n", encoding="utf-8")
        editor = self.get("/settings/models/planning").body
        self.assertIn('name="provider__planning__planner"', editor)
        self.assertIn('name="model_id__planning__evidence_linker"', editor)
        self.assertIn("Apply one model to all 5 agents", editor)
        config = self.app._settings_config()
        form = {"mode": "agents", "action": "review"}
        for group, role, model in self.app._stage_models(config, "planning"):
            route_provider, route_model = self.app._model_route(config, model)
            form[f"provider__{group}__{role}"] = route_provider.lower()
            form[f"model_id__{group}__{role}"] = route_model
        form["provider__planning__planner"] = "openrouter"
        form["model_id__planning__planner"] = "anthropic/claude-sonnet-4"
        form["model_id__planning__reviewer"] = "deepseek-v4-flash"

        reviewed = self.post("/settings/models/planning", form).body
        self.assertIn("Planning · Planner", reviewed)
        self.assertIn("Planning · Reviewer", reviewed)
        self.assertNotIn("Planning · Evidence Linker", reviewed)
        self.assertIn('name="mode" value="agents"', reviewed)
        saved = self.post("/settings/models/planning", {
            **form, "action": "save", "reviewed": "yes", "source_digest": self._review_digest(reviewed),
        })
        self.assertEqual(saved.location, "/settings?saved=planning")
        config = AppConfig.from_env(self.root / "mosh.yaml", self.root / ".env")
        self.assertEqual(config.models.planning.planner, "openrouter/anthropic/claude-sonnet-4")
        self.assertEqual(config.models.planning.reviewer, "deepseek/deepseek-v4-flash")
        self.assertEqual(config.models.planning.evidence_linker, "deepseek/deepseek-v4-flash")
        content = (self.root / "mosh.yaml").read_text(encoding="utf-8")
        self.assertNotIn("evidence_linker:", content)
        self.assertNotIn("testing:", content)

    def test_individual_agent_validation_keeps_entered_values(self) -> None:
        config = self.app._settings_config()
        form = {"mode": "agents", "action": "review"}
        for group, role, model in self.app._stage_models(config, "planning"):
            route_provider, route_model = self.app._model_route(config, model)
            form[f"provider__{group}__{role}"] = route_provider.lower()
            form[f"model_id__{group}__{role}"] = route_model
        form["provider__planning__planner"] = "openrouter"
        form["model_id__planning__planner"] = "anthropic/claude-sonnet-4"
        page = self.post("/settings/models/planning", form).body
        self.assertIn("Connect the provider for planner", page)
        self.assertIn('name="model_id__planning__planner" type="text" maxlength="200" required value="anthropic/claude-sonnet-4"', page)
        self.assertFalse((self.root / "mosh.yaml").exists())

    def test_individual_edit_preserves_legacy_custom_routes(self) -> None:
        from mosh.config import AppConfig

        (self.root / ".env").write_text(
            "DEEPSEEK_API_KEY=deep-key\nMOSH_LLM_BASE_URL=http://localhost:11434/v1\n",
            encoding="utf-8",
        )
        config = self.app._settings_config()
        form = {"mode": "agents", "action": "review"}
        for group, role, model in self.app._stage_models(config, "planning"):
            route_provider, route_model = self.app._model_route(config, model)
            form[f"provider__{group}__{role}"] = route_provider.lower()
            form[f"model_id__{group}__{role}"] = route_model
        form["provider__planning__planner"] = "deepseek"
        form["model_id__planning__planner"] = "deepseek-v4-pro"
        reviewed = self.post("/settings/models/planning", form).body
        self.assertIn("other stages keep using your custom endpoint", reviewed)
        saved = self.post("/settings/models/planning", {
            **form, "action": "save", "reviewed": "yes", "source_digest": self._review_digest(reviewed),
        })
        self.assertEqual(saved.location, "/settings?saved=planning")
        updated = AppConfig.from_env(self.root / "mosh.yaml", self.root / ".env")
        self.assertIsNone(updated.llm_base_url_for_model(updated.models.planning.planner))
        self.assertEqual(updated.llm_base_url_for_model(updated.models.planning.reviewer), "http://localhost:11434/v1")
        self.assertEqual(updated.llm_base_url_for_model(updated.models.testing.executor), "http://localhost:11434/v1")

    def test_legacy_custom_editor_preserves_other_stage_routes(self) -> None:
        from mosh.config import AppConfig

        (self.root / ".env").write_text("MOSH_LLM_BASE_URL=http://localhost:11434/v1\n", encoding="utf-8")
        self.assertIn("custom endpoint currently serves every model", self.get("/settings").body)
        blocked = self.post("/settings/models/planning", {
            "action": "review", "provider": "deepseek", "model_id": "deepseek-v4-pro",
        }).body
        self.assertIn("Connect this provider before assigning", blocked)
        self.assertFalse((self.root / "mosh.yaml").exists())

        self.post("/settings/providers/connect", {"provider": "deepseek", "api_key": "deep-key"})
        self.wait_for_check("deepseek")
        reviewed = self.post("/settings/models/planning", {
            "action": "review", "provider": "deepseek", "model_id": "deepseek-v4-pro",
        }).body
        self.assertIn("other stages keep using your custom endpoint", reviewed)
        self.assertIn("Custom", reviewed)
        self.assertIn("DeepSeek", reviewed)
        self.assertNotIn("also changes where models run in", reviewed)
        saved = self.post("/settings/models/planning", {
            "action": "save", "provider": "deepseek", "model_id": "deepseek-v4-pro",
            "reviewed": "yes", "source_digest": self._review_digest(reviewed),
        })
        self.assertEqual(saved.location, "/settings?saved=planning")
        config = AppConfig.from_env(self.root / "mosh.yaml", self.root / ".env")
        self.assertTrue(config.has_explicit_custom_models())
        self.assertIsNone(config.llm_base_url_for_model(config.models.planning.planner))
        self.assertEqual(config.llm_base_url_for_model(config.models.testing.executor), "http://localhost:11434/v1")
        self.assertEqual(config.llm_model_name(config.models.testing.executor), "deepseek/deepseek-v4-flash")

    def test_model_save_rejects_stale_review_and_active_stage(self) -> None:
        from mosh.web import TestingRun

        reviewed = self.post("/settings/models/chat", {
            "action": "review", "provider": "deepseek", "model_id": "deepseek-v4-pro",
        }).body
        (self.root / "mosh.yaml").write_text("# changed in another window\n", encoding="utf-8")
        stale = self.post("/settings/models/chat", {
            "action": "save", "provider": "deepseek", "model_id": "deepseek-v4-pro",
            "reviewed": "yes", "source_digest": self._review_digest(reviewed),
        }).body
        self.assertIn("changed since the review", stale)
        self.assertNotIn("assistant:", (self.root / "mosh.yaml").read_text(encoding="utf-8"))

        self.app.testing_runs["running"] = TestingRun(status="running")
        running = self.post("/settings/models/chat", {
            "action": "review", "provider": "deepseek", "model_id": "deepseek-v4-pro",
        }).body
        self.assertIn("Wait for the current stage", running)
        self.assertNotIn("assistant:", (self.root / "mosh.yaml").read_text(encoding="utf-8"))

    def test_provider_connection_is_available_after_onboarding(self) -> None:
        page = self.get("/settings/providers").body
        self.assertIn("DeepSeek", page)
        self.assertIn("Not connected", page)
        self.assertIn('href="/settings/providers/custom"', page)
        self.assertIn('name="base_url"', self.get("/settings/providers/custom").body)
        self.assertEqual(self.post("/settings/providers/connect", {
            "provider": "custom", "base_url": "http://localhost:11434/v1", "api_key": "",
        }).location, "/settings/providers")
        self.wait_for_check("custom")
        saved = dotenv_values(self.root / ".env")
        self.assertEqual(saved["DEEPSEEK_API_KEY"], "test-key")
        self.assertEqual(saved["MOSH_LLM_BASE_URL"], "http://localhost:11434/v1")
        self.assertNotIn("MOSH_LLM_API_KEY", saved)

    def test_stage_editor_can_explicitly_choose_openrouter_for_deepseek_model(self) -> None:
        from mosh.config import AppConfig

        self.post("/settings/providers/connect", {"provider": "openrouter", "api_key": "router-key"})
        self.wait_for_check("openrouter")
        reviewed = self.post("/settings/models/testing", {
            "action": "review", "provider": "openrouter", "model_id": "deepseek/deepseek-v4-pro",
        }).body
        self.assertIn("OpenRouter · deepseek/deepseek-v4-pro", reviewed)
        saved = self.post("/settings/models/testing", {
            "action": "save", "provider": "openrouter", "model_id": "deepseek/deepseek-v4-pro",
            "reviewed": "yes", "source_digest": self._review_digest(reviewed),
        })
        self.assertEqual(saved.location, "/settings?saved=testing")
        config = AppConfig.from_env(self.root / "mosh.yaml", self.root / ".env")
        self.assertEqual(config.models.testing.executor, "openrouter/deepseek/deepseek-v4-pro")
        self.assertEqual(config.llm_base_url_for_model(config.models.testing.executor), config.openrouter_base_url)

    def test_failed_provider_replacement_keeps_current_key(self) -> None:
        self.app.provider_checker = lambda provider, key, base_url: (False, "API key was rejected.")
        self.post("/settings/providers/connect", {"provider": "deepseek", "api_key": "bad-key"})
        self.wait_for_check("deepseek")
        page = self.get("/settings/providers").body
        self.assertIn("API key was rejected", page)
        self.assertNotIn("bad-key", page)
        self.assertEqual(dotenv_values(self.root / ".env")["DEEPSEEK_API_KEY"], "test-key")

    def test_settings_forms_keep_localhost_origin_and_csrf_checks(self) -> None:
        response = self.app.handle("POST", "/settings/models/chat", {"action": "review", "provider": "deepseek", "model_id": "deepseek-v4-pro"}, {"Host": "127.0.0.1:8765"})
        self.assertEqual(response.status, 403)
        response = self.post("/settings/models/chat", {"action": "review", "provider": "deepseek", "model_id": "deepseek-v4-pro"}, origin="http://evil.example")
        self.assertEqual(response.status, 403)


class WebAssessmentTests(WebTestCase):
    def test_missing_discovery_image_blocks_run_and_links_to_settings(self) -> None:
        from mosh.engagements import attach_asset, create_engagement

        self.ready()
        engagement = create_engagement(self.app.output_root, "Missing discovery tools")
        attach_asset(self.app.output_root, engagement.id, "https://app.example.test")
        self.app.environment_probe = lambda: {
            "uv": True, "docker": True, "images": False,
            "discovery_image": False, "security_image": True,
        }
        url = f"/assessments/{engagement.id}/discovery"
        page = self.post(url, {"action": "start"}).body
        self.assertIn("Discovery tools are unavailable", page)
        self.assertIn('href="/settings#local-tools" data-settings-link', page)
        self.assertNotIn("Start discovery</button>", page)
        self.assertNotIn(engagement.id, self.app.discovery_runs)

    def test_missing_security_image_blocks_testing_run(self) -> None:
        from mosh.engagements import attach_asset, create_engagement, engagement_plan_dir

        self.ready()
        engagement = create_engagement(self.app.output_root, "Missing security tools")
        attach_asset(self.app.output_root, engagement.id, "https://app.example.test")
        plan_dir = engagement_plan_dir(self.app.output_root, engagement.id)
        plan_dir.mkdir(parents=True)
        (plan_dir / "plan.md").write_text("# Plan\n", encoding="utf-8")
        self.app._planning_current = lambda _: True
        self.app.environment_probe = lambda: {
            "uv": True, "docker": True, "images": False,
            "discovery_image": True, "security_image": False,
        }
        url = f"/assessments/{engagement.id}/testing"
        page = self.post(url, {"action": "start"}).body
        self.assertIn("Security testing tools are unavailable", page)
        self.assertIn('href="/settings#local-tools" data-settings-link', page)
        self.assertNotIn(engagement.id, self.app.testing_runs)

    def test_stop_discovery_finishes_current_asset_and_runs_remaining_later(self) -> None:
        from mosh.engagements import asset_discovery_dir, attach_asset, create_engagement

        engagement = create_engagement(self.app.output_root, "Stop discovery")
        first = attach_asset(self.app.output_root, engagement.id, "https://first.example.test").asset
        second = attach_asset(self.app.output_root, engagement.id, "https://second.example.test").asset
        entered = threading.Event()
        release = threading.Event()
        self.addCleanup(release.set)
        calls = []

        def discover(config, output_root, current_engagement, asset, event_sink):
            calls.append(asset.id)
            if asset.id == first.id:
                entered.set()
                release.wait(2)
            report_dir = asset_discovery_dir(output_root, current_engagement.id, asset.id)
            report_dir.mkdir(parents=True, exist_ok=True)
            (report_dir / "report.md").write_text(f"# {asset.id}", encoding="utf-8")
            return report_dir

        self.app.discovery_runner = discover
        url = f"/assessments/{engagement.id}/discovery"
        self.post(url, {"action": "start"})
        self.assertTrue(entered.wait(1))
        running = self.get(url + "?view=logs").body
        self.assertIn('data-open-stop="stop-discovery"', running)
        self.assertIn('data-stop-confirm', running)
        self.assertIn("Finished asset and test reports remain available", running)
        self.assertIn("Confirm before stopping Discovery", self.post(url, {"action": "stop"}).body)
        self.assertFalse(self.app.discovery_runs[engagement.id].stop_requested.is_set())
        self.post(url, {"action": "stop", "confirmed": "yes"})
        self.assertEqual(self.app.discovery_runs[engagement.id].status, "running")
        self.assertIn("Stopping discovery", self.get(url).body)
        self.assertTrue(json.loads(self.get(url + "/status").body)["poll"])
        release.set()
        self.wait_for_discovery(engagement.id)
        self.assertEqual(self.app.discovery_runs[engagement.id].status, "stopped")
        self.assertEqual(calls, [first.id])
        self.assertTrue((asset_discovery_dir(self.app.output_root, engagement.id, first.id) / "report.md").is_file())
        self.assertIn("Stopped by you", self.get(url).body)
        self.assertIn("Run remaining", self.get(url).body)
        self.post(url, {"action": "start"})
        self.wait_for_discovery(engagement.id)
        self.assertEqual(calls, [first.id, second.id])
        self.assertEqual(self.app.discovery_runs[engagement.id].status, "complete")

    def test_stop_model_stages_waits_for_runner_checkpoint(self) -> None:
        from mosh.engagements import attach_asset, create_engagement, asset_discovery_dir

        engagement = create_engagement(self.app.output_root, "Stop stages")
        asset = attach_asset(self.app.output_root, engagement.id, "https://app.example.test").asset
        discovery_dir = asset_discovery_dir(self.app.output_root, engagement.id, asset.id)
        discovery_dir.mkdir(parents=True, exist_ok=True)
        (discovery_dir / "report.md").write_text("# Discovery", encoding="utf-8")
        for stage, run_type, task_name, runner_name, path in (
            ("planning", PlanningRun, "_run_planning_task", "planning_runner", "planning"),
            ("testing", TestingRun, "_run_testing_task", "testing_runner", "testing"),
            ("reporting", ReportingRun, "_run_reporting_task", "reporting_runner", "report"),
        ):
            with self.subTest(stage=stage):
                entered = threading.Event()
                release = threading.Event()
                self.addCleanup(release.set)

                def runner(config, output_root, engagement_id, sink):
                    entered.set()
                    release.wait(2)
                    sink.check_stop()
                    raise AssertionError("Runner continued after stop")

                setattr(self.app, runner_name, runner)
                run = run_type()
                getattr(self.app, f"{stage}_runs")[engagement.id] = run
                thread = threading.Thread(target=getattr(self.app, task_name), args=(engagement.id, run))
                thread.start()
                self.addCleanup(thread.join, 2)
                self.assertTrue(entered.wait(1))
                url = f"/assessments/{engagement.id}/{path}"
                self.assertIn("data-open-stop", self.get(url).body)
                self.post(url, {"action": "stop", "confirmed": "yes"})
                self.assertEqual(run.status, "running")
                self.assertIn("Stopping", self.get(url).body)
                release.set()
                thread.join(2)
                self.assertFalse(thread.is_alive())
                self.assertEqual(run.status, "stopped")
                self.assertIn("stopped by you", self.get(url).body.lower())

        feedback = PlanningRun(from_testing=True)
        self.app.planning_runs[engagement.id] = feedback
        testing_url = f"/assessments/{engagement.id}/testing"
        self.assertIn('value="stop-replan"', self.get(testing_url).body)
        self.post(testing_url, {"action": "stop-replan", "confirmed": "yes"})
        self.assertTrue(feedback.stop_requested.is_set())

    def test_markdown_views_offer_contents_and_three_download_formats(self) -> None:
        from mosh.engagements import asset_discovery_dir, attach_asset, create_engagement, engagement_dir, engagement_plan_dir
        from mosh.web import make_handler

        self.ready()
        engagement = create_engagement(self.app.output_root, "PDF export")
        asset = attach_asset(self.app.output_root, engagement.id, "https://app.example.test").asset
        discovery_dir = asset_discovery_dir(self.app.output_root, engagement.id, asset.id)
        planning_dir = engagement_plan_dir(self.app.output_root, engagement.id)
        testing_dir = engagement_dir(self.app.output_root, engagement.id) / "security-testing"
        final_dir = engagement_dir(self.app.output_root, engagement.id) / "final-report"
        for directory in (discovery_dir, planning_dir, testing_dir / "executed_tests", final_dir):
            directory.mkdir(parents=True, exist_ok=True)
        source = "# Report title\n\n## Findings\n\nA **confirmed** finding.\n\n| Area | Status |\n| --- | --- |\n| Login | Reviewed |\n"
        (discovery_dir / "report.md").write_text(source, encoding="utf-8")
        (planning_dir / "plan.md").write_text(source, encoding="utf-8")
        (testing_dir / "preflight.md").write_text(source, encoding="utf-8")
        (testing_dir / "executed_tests" / "AUTH-001.md").write_text(source, encoding="utf-8")
        (final_dir / "report.md").write_text(source, encoding="utf-8")
        (final_dir / "events.json").write_text(json.dumps([{"agent": "orchestrator", "action": "complete"}]), encoding="utf-8")
        base = f"/assessments/{engagement.id}"
        paths = (
            (f"{base}/discovery/{asset.id}/report", "discovery"),
            (f"{base}/planning/report", "security-test-plan"),
            (f"{base}/testing/preflight", "testing-preflight"),
            (f"{base}/testing/reports/AUTH-001", "test-AUTH-001"),
            (f"{base}/report/view", "final-report"),
        )
        for path, filename_part in paths:
            with self.subTest(path=path):
                page = self.get(path)
                self.assertIn('aria-label="Contents"', page.body)
                self.assertIn('href="#section-2">Findings</a>', page.body)
                self.assertIn('<summary class="secondary">Download</summary>', page.body)
                for format_name in ("pdf", "docx", "md"):
                    with self.subTest(path=path, format=format_name):
                        self.assertIn(f'href="{path}?format={format_name}" download', page.body)
                        response = self.get(path + f"?format={format_name}")
                        self.assertEqual(response.status, 200)
                        self.assertIn(filename_part, response.download_filename)
                        self.assertTrue(response.download_filename.endswith(f".{format_name}"))
                        if format_name == "pdf":
                            self.assertEqual(response.content_type, "application/pdf")
                            self.assertTrue(response.body.startswith(b"%PDF-"))
                        elif format_name == "docx":
                            self.assertEqual(response.content_type, "application/vnd.openxmlformats-officedocument.wordprocessingml.document")
                            self.assertTrue(zipfile.is_zipfile(io.BytesIO(response.body)))
                        else:
                            self.assertEqual(response.content_type, "text/markdown; charset=utf-8")
                            self.assertEqual(response.body, source.encode("utf-8"))
                        sender = Mock()
                        sender.wfile = io.BytesIO()
                        make_handler(self.app)._send(sender, response)
                        headers = dict(call.args for call in sender.send_header.call_args_list)
                        self.assertEqual(headers["Content-Type"], response.content_type)
                        self.assertTrue(headers["Content-Disposition"].startswith('attachment; filename="'))
                        self.assertEqual(sender.wfile.getvalue(), response.body)
        for format_name in ("pdf", "docx", "md"):
            self.assertEqual(self.get(f"{base}/discovery/unknown/report?format={format_name}").status, 404)
            self.assertEqual(self.get(f"{base}/testing/reports/unknown?format={format_name}").status, 404)

    def test_repository_label_names_git_and_transport(self) -> None:
        from mosh.web import ASSET_TYPES
        self.assertEqual(ASSET_TYPES["source_repo"], "Git repository (HTTPS)")

    def setUp(self) -> None:
        super().setUp()
        self.ready()
        self.app = WebApp(
            self.root,
            environment_probe=lambda: {"uv": True, "docker": True, "images": True},
            build_runner=lambda: True,
            provider_checker=lambda provider, key, base_url: (True, ""),
            asset_checker=lambda kind, locator: (True, "Reachable when added"),
            folder_root=self.root,
        )

    def wait_for_assessment_asset_check(self, engagement_id: str) -> None:
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            pending = self.app.assessment_asset_checks.get(engagement_id)
            if pending is None or pending.state != "checking":
                return
            time.sleep(.001)
        self.fail("Assessment asset check did not finish")

    def wait_for_discovery(self, engagement_id: str) -> None:
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            run = self.app.discovery_runs.get(engagement_id)
            if run and run.status != "running":
                return
            time.sleep(.001)
        self.fail("Discovery did not finish")

    def wait_for_planning(self, engagement_id: str) -> None:
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            run = self.app.planning_runs.get(engagement_id)
            if run and run.status != "running":
                return
            time.sleep(.001)
        self.fail("Planning did not finish")

    def wait_for_testing(self, engagement_id: str) -> None:
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            run = self.app.testing_runs.get(engagement_id)
            if run and run.status != "running":
                return
            time.sleep(.001)
        self.fail("Testing did not finish")

    def wait_for_reporting(self, engagement_id: str) -> None:
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            run = self.app.reporting_runs.get(engagement_id)
            if run and run.status != "running":
                return
            time.sleep(.001)
        self.fail("Reporting did not finish")

    def completed_testing_with_feedback(self):
        from mosh.crews.testing.crew import hypothesis_fingerprint, plan_revision_id
        from mosh.engagement import build_minimal_engagement_template
        from mosh.engagements import asset_discovery_dir, attach_asset, create_engagement, engagement_dir, engagement_plan_dir
        from mosh.memory import FileMemory

        engagement = create_engagement(self.app.output_root, "Feedback choice")
        asset = attach_asset(self.app.output_root, engagement.id, "https://app.example.test").asset
        discovery_dir = asset_discovery_dir(self.app.output_root, engagement.id, asset.id)
        discovery_dir.mkdir(parents=True)
        (discovery_dir / "report.md").write_text("# Original discovery\n", encoding="utf-8")
        (discovery_dir / "memory.json").write_text("[]", encoding="utf-8")
        plan_dir = engagement_plan_dir(self.app.output_root, engagement.id)
        plan_dir.mkdir(parents=True)
        (plan_dir / "plan.md").write_text("# Original plan\n", encoding="utf-8")
        plan = {"test_hypotheses": [{"id": "AUTH-001", "title": "Check authorization", "requirements": ["No credentials required."]}]}
        (plan_dir / "memory.json").write_text(json.dumps([{"kind": "security_test_plan_final", "content": {"structured": plan}}]), encoding="utf-8")
        template = build_minimal_engagement_template()
        template["engagement"].update(authorization_confirmed=True, active_testing_allowed=True)
        template["targets"]["production"]["web"] = asset.locator
        (engagement_dir(self.app.output_root, engagement.id) / "engagement_template.yaml").write_text(json.dumps(template), encoding="utf-8")
        self.app._planning_current = lambda _: True
        runs = []

        def testing_runner(config, output_root, engagement_id, event_sink):
            runs.append(engagement_id)
            report_dir = output_root / engagement_id / "security-testing"
            memory = FileMemory(report_dir, event_sink=event_sink)
            memory.add_item("testing_preflight", {
                "ready": [{"id": "AUTH-001", "hypothesis_fingerprint": hypothesis_fingerprint(plan["test_hypotheses"][0])}],
                "blocked": [], "plan_revision_id": plan_revision_id(plan),
            }, "security_test_coordinator")
            (report_dir / "preflight.md").write_text("# Preflight\n", encoding="utf-8")
            executed_dir = report_dir / "executed_tests"
            executed_dir.mkdir()
            (executed_dir / "AUTH-001.md").write_text(
                '<!-- mosh-execution ' + json.dumps({"test_id": "AUTH-001", "review_accepted": True,
                    "hypothesis_fingerprint": hypothesis_fingerprint(plan["test_hypotheses"][0]), "status": "no-finding"})
                + ' -->\n# Completed test\n', encoding="utf-8",
            )
            memory.add_item("security_test_execution_bundle", {
                "test_id": "AUTH-001", "final_evidence": {"discovery_updates": [
                    {"type": "endpoint", "detail": "A newly identified test endpoint."}
                ]},
            }, "security_test_coordinator")
            memory.record_event("orchestrator", "complete", "Security testing completed")
            return report_dir

        self.app.testing_runner = testing_runner
        testing_url = f"/assessments/{engagement.id}/testing"
        self.assertEqual(self.post(testing_url, {"action": "start"}).location, testing_url)
        self.wait_for_testing(engagement.id)
        return engagement, plan_dir, discovery_dir, runs

    def test_discovery_shows_asset_steps_logs_and_reports(self) -> None:
        from mosh.engagements import asset_discovery_dir, attach_asset, create_engagement
        from mosh.models import Event
        engagement = create_engagement(self.app.output_root, "Discovery UI")
        live = attach_asset(self.app.output_root, engagement.id, "https://app.example.test").asset
        source = self.root / "source"
        source.mkdir()
        local = attach_asset(self.app.output_root, engagement.id, str(source)).asset
        detail_url = f"/assessments/{engagement.id}"
        live_started = threading.Event()
        live_release = threading.Event()
        source_started = threading.Event()
        source_release = threading.Event()
        self.addCleanup(live_release.set)
        self.addCleanup(source_release.set)

        def discover(config, output_root, current_engagement, asset, event_sink):
            report_dir = asset_discovery_dir(output_root, current_engagement.id, asset.id)
            report_dir.mkdir(parents=True, exist_ok=True)
            if asset.id == live.id:
                event_sink(Event("crawler", "tool_result", "Found <pages>"))
                event_sink(Event("crewai", "agent_started", "Technology mapper started", {"agent_role": "Application Technology Mapper"}))
                live_started.set()
                live_release.wait(2)
                event_sink(Event("technology_mapper", "agent_output", "Mapped services", {"task": "compile_components_task"}))
            else:
                event_sink(Event("source_mapper", "agent_output", "Indexed files", {"task": "map_source_task"}))
                source_started.set()
                source_release.wait(2)
                event_sink(Event("dependency_config", "agent_output", "Reviewed config", {"task": "inspect_dependency_config_task"}))
                event_sink(Event("source_gap_analyst", "agent_output", "Checked gaps", {"task": "analyze_discovery_source_gaps_task"}))
            (report_dir / "report.md").write_text("# Report\n<script>unsafe</script>", encoding="utf-8")
            return report_dir

        self.app.discovery_runner = discover
        stage_url = detail_url + "/discovery"
        assessment = self.get(detail_url).body
        self.assertEqual(assessment.count(f"<code>{live.locator}</code>"), 1)
        self.assertEqual(assessment.count(f"<code>{local.locator}</code>"), 1)
        self.assertNotIn('class="discovery-asset"', assessment)
        self.assertNotIn('id="discovery-status"', assessment)
        self.assertIn(f'href="{stage_url}" aria-label="Discovery, Not started"', assessment)
        self.assertNotIn("Continue to discovery", assessment)
        self.assertIn('aria-label="Assessment stages"', assessment)
        self.assertIn('aria-label="Scope, Complete" aria-current="step"', assessment)
        self.assertIn('aria-disabled="true"', assessment)
        discovery_page = self.get(stage_url).body
        self.assertIn('class="discovery-asset"', discovery_page)
        self.assertIn('aria-label="Discovery, Not started" aria-current="step"', discovery_page)
        self.assertEqual(self.post(stage_url, {"action": "start"}).location, stage_url)
        self.assertTrue(live_started.wait(1))
        running = self.get(stage_url).body
        self.assertIn('class="stage-item running active"', running)
        self.assertIn('aria-label="Discovery, In progress" aria-current="step"><span class="stage-mark" aria-hidden="true"></span>Discovery', running)
        self.assertIn("Discovering asset 1 of 2", running)
        self.assertIn('class="done">Crawling pages, forms and APIs', running)
        self.assertIn('class="current">Identifying technologies and services', running)
        self.assertIn("Writing discovery report", running)
        self.assertNotIn('http-equiv="refresh"', running)
        self.assertIn(f'data-poll-url="{stage_url}/status"', running)
        status_response = self.get(stage_url + "/status")
        self.assertEqual(status_response.content_type, "application/json; charset=utf-8")
        status = json.loads(status_response.body)
        self.assertTrue(status["poll"])
        self.assertIn("Identifying technologies and services", status["html"])
        self.assertIn('class="discovery-asset"', status["html"])
        self.assertIn('aria-label="Assessment stages"', status["html"])
        self.assertIn('<details class="log-console" data-live-logs data-logs-loaded="false">', status["html"])
        self.assertNotIn("Found &lt;pages&gt;", running)
        self.assertNotIn('http-equiv="refresh"', self.get(detail_url).body)
        logs = self.get(stage_url + "?view=logs").body
        self.assertIn("Found &lt;pages&gt;", logs)
        self.assertIn('<details class="log-console" data-live-logs data-logs-loaded="true" open>', logs)
        self.assertIn('<span class="log-hide">Hide logs</span>', logs)
        self.assertNotIn(f'href="{stage_url}">Hide logs</a>', logs)
        self.assertNotIn('http-equiv="refresh"', logs)
        self.assertIn(f'data-poll-url="{stage_url}/status?view=logs"', logs)
        self.assertIn("Found &lt;pages&gt;", json.loads(self.get(stage_url + "/status?view=logs").body)["html"])
        self.assertIn("Wait for the current stage", self.post(detail_url + "/assets", {"action": "remove", "asset_id": live.id}).body)
        self.assertEqual(len(load_engagement(self.app.output_root, engagement.id).assets), 2)
        self.assertIn("already running", self.post(stage_url, {"action": "start"}).body)

        live_release.set()
        self.assertTrue(source_started.wait(1))
        source_page = self.get(stage_url).body
        self.assertIn("Discovering asset 2 of 2", source_page)
        self.assertIn('class="done">Indexing files, routes and API handlers', source_page)
        self.assertIn('class="current">Inspecting dependencies and configuration', source_page)
        self.assertIn("Summarizing components and coverage gaps", source_page)
        self.assertIn("View report", source_page)
        source_release.set()
        self.wait_for_discovery(engagement.id)
        complete = self.get(stage_url).body
        self.assertIn("Discovery complete", complete)
        self.assertEqual(complete.count("View report"), 2)
        self.assertIn(f'href="{detail_url}/planning" aria-label="Planning, Not started"', complete)
        self.assertNotIn("Continue to planning", complete)
        self.assertNotIn("Start planning", complete)
        self.assertIn('aria-label="Discovery, Complete" aria-current="step"', complete)
        self.assertIn("Refresh discovery", complete)
        self.assertNotIn('http-equiv="refresh"', complete)
        self.assertNotIn('data-poll-url=', complete)
        self.assertFalse(json.loads(self.get(stage_url + "/status").body)["poll"])
        self.assertNotIn("Continue to discovery", self.get(detail_url).body)
        report = self.get(f"{detail_url}/discovery/{live.id}/report")
        self.assertEqual(report.status, 200)
        self.assertIn('<article class="markdown-document">', report.body)
        self.assertIn('<h1 id="section-1">Report</h1>', report.body)
        self.assertIn("&lt;script&gt;unsafe&lt;/script&gt;", report.body)
        self.assertNotIn("<script>unsafe</script>", report.body)
        self.assertEqual(self.get(f"{detail_url}/discovery/asset_live_99/report").status, 404)

    def test_discovery_poller_and_spinner_assets_are_served(self) -> None:
        from mosh.web import make_handler

        script = self.get("/web.js")
        self.assertEqual(script.content_type, "text/javascript; charset=utf-8")
        self.assertIn('if (logsOpen) url.searchParams.set("view", "logs")', script.body)
        self.assertIn('fetch(url, { cache: "no-store" })', script.body)
        self.assertIn('nextLogs.open = stillOpen', script.body)
        self.assertIn('logs.dataset.logsLoaded === "false"', script.body)
        self.assertIn("section.outerHTML = update.html", script.body)
        self.assertIn('<script src="/web.js" defer></script>', self.get("/").body)
        sender = Mock()
        sender.wfile = io.BytesIO()
        make_handler(self.app)._send(sender, self.get("/"))
        headers = dict(call.args for call in sender.send_header.call_args_list)
        self.assertIn("script-src 'self'", headers["Content-Security-Policy"])
        self.assertIn("connect-src 'self'", headers["Content-Security-Policy"])

        stylesheet = self.get("/web.css").body
        self.assertIn(".discovery-steps li.current::before", stylesheet)
        self.assertIn(".stage-item.running .stage-mark { height: 11px; border: 2px", stylesheet)
        self.assertIn(".stage-item.running .stage-mark, .discovery-steps li.current::before { animation: none; }", stylesheet)
        self.assertIn("animation: discovery-spin", stylesheet)
        self.assertIn('.discovery-steps li.done::before { content: "✓"; }', stylesheet)

    def test_favicon_uses_packaged_brand_icon(self) -> None:
        favicon = self.get("/favicon.ico")
        self.assertEqual(favicon.status, 200)
        self.assertEqual(favicon.content_type, "image/x-icon")
        self.assertEqual(
            favicon.body,
            (Path(__file__).parents[1] / "assets/brand/favicon/favicon.ico").read_bytes(),
        )
        self.assertIn('<link rel="icon" href="/favicon.ico" type="image/x-icon">', self.get("/").body)

    def test_discovery_failure_and_retry_only_remaining_asset(self) -> None:
        from mosh.engagements import asset_discovery_dir, attach_asset, create_engagement
        engagement = create_engagement(self.app.output_root, "Retry discovery")
        first = attach_asset(self.app.output_root, engagement.id, "https://first.example.test").asset
        second = attach_asset(self.app.output_root, engagement.id, "https://second.example.test").asset
        detail_url = f"/assessments/{engagement.id}"
        stage_url = detail_url + "/discovery"
        calls = []

        def discover(config, output_root, current_engagement, asset, event_sink):
            calls.append(asset.id)
            if asset.id == second.id and calls.count(second.id) == 1:
                raise RuntimeError("Model request failed")
            report_dir = asset_discovery_dir(output_root, current_engagement.id, asset.id)
            report_dir.mkdir(parents=True, exist_ok=True)
            (report_dir / "report.md").write_text("# Report", encoding="utf-8")
            return report_dir

        self.app.discovery_runner = discover
        self.post(stage_url, {"action": "start"})
        self.wait_for_discovery(engagement.id)
        failed = self.get(stage_url).body
        self.assertIn("Discovery needs attention", failed)
        self.assertIn("Model request failed", failed)
        self.assertIn("Retry remaining", failed)
        self.assertIn("Needs attention", failed)
        self.assertIn('class="failed">Crawling pages, forms and APIs', failed)
        failed_status = json.loads(self.get(stage_url + "/status").body)
        self.assertFalse(failed_status["poll"])
        self.assertIn("Retry remaining", failed_status["html"])
        self.assertEqual(calls, [first.id, second.id])
        self.post(stage_url, {"action": "retry"})
        self.wait_for_discovery(engagement.id)
        self.assertEqual(calls, [first.id, second.id, second.id])
        self.assertIn("Discovery complete", self.get(stage_url).body)
        self.assertIn("No assets need discovery", self.post(stage_url, {"action": "start"}).body)

    def test_discovery_reads_existing_reports_and_logs_after_restart(self) -> None:
        from mosh.engagements import asset_discovery_dir, attach_asset, create_engagement
        engagement = create_engagement(self.app.output_root, "Existing discovery")
        asset = attach_asset(self.app.output_root, engagement.id, "https://app.example.test").asset
        report_dir = asset_discovery_dir(self.app.output_root, engagement.id, asset.id)
        report_dir.mkdir(parents=True)
        (report_dir / "report.md").write_text("# Existing report", encoding="utf-8")
        (report_dir / "events.json").write_text(json.dumps([{"timestamp": "2026-10-05T10:00:00Z", "agent": "crawler", "message": "Found routes"}]), encoding="utf-8")
        detail_url = f"/assessments/{engagement.id}"
        page = self.get(detail_url).body
        self.assertIn('aria-label="Discovery, Complete"', page)
        self.assertNotIn("Continue to discovery", page)
        self.assertIn("View report", self.get(detail_url + "/discovery").body)
        stored_logs = self.get(detail_url + "/discovery?view=logs").body
        self.assertIn("Found routes", stored_logs)
        self.assertIn('<time title="2026-10-05T10:00:00Z">2026-10-05 10:00:00</time>', stored_logs)

    def test_refresh_shows_existing_reports_as_waiting_until_rerun(self) -> None:
        from mosh.engagements import asset_discovery_dir, attach_asset, create_engagement
        engagement = create_engagement(self.app.output_root, "Refresh discovery")
        first = attach_asset(self.app.output_root, engagement.id, "https://first.example.test").asset
        second = attach_asset(self.app.output_root, engagement.id, "https://second.example.test").asset
        for asset in (first, second):
            report_dir = asset_discovery_dir(self.app.output_root, engagement.id, asset.id)
            report_dir.mkdir(parents=True)
            (report_dir / "report.md").write_text("# Previous report", encoding="utf-8")
        started = threading.Event()
        release = threading.Event()
        self.addCleanup(release.set)

        def discover(config, output_root, current_engagement, asset, event_sink):
            started.set()
            release.wait(2)
            report_dir = asset_discovery_dir(output_root, current_engagement.id, asset.id)
            (report_dir / "report.md").write_text("# Refreshed report", encoding="utf-8")
            return report_dir

        self.app.discovery_runner = discover
        stage_url = f"/assessments/{engagement.id}/discovery"
        discovery_page = self.get(stage_url).body
        self.assertIn(f'href="{stage_url}/refresh">Refresh discovery</a>', discovery_page)
        confirmation = self.get(stage_url + "/refresh")
        self.assertIn("Refresh discovery?", confirmation.body)
        self.assertIn("all 2 attached assets", confirmation.body)
        self.assertIn("reports and logs may be replaced", confirmation.body)
        self.assertIn(f'href="{stage_url}">Cancel</a>', confirmation.body)
        self.assertFalse(started.is_set())
        self.assertNotIn(engagement.id, self.app.discovery_runs)
        self.assertIn("Refresh discovery?", self.post(stage_url, {"action": "refresh"}).body)
        self.assertFalse(started.is_set())
        self.assertNotIn(engagement.id, self.app.discovery_runs)
        self.assertEqual(self.post(stage_url, {"action": "refresh", "confirmed": "yes"}).location, stage_url)
        self.assertTrue(started.wait(1))
        running = self.get(stage_url).body
        self.assertIn("Discovering asset 1 of 2", running)
        self.assertIn('class="discovery-status waiting">Waiting', running)
        self.assertNotIn("View report", running)
        release.set()
        self.wait_for_discovery(engagement.id)
        self.assertEqual(self.get(stage_url).body.count("View report"), 2)
        self.assertEqual(self.app.handle("POST", stage_url, {"action": "refresh"}, {"Host": "127.0.0.1:8765"}).status, 403)

    def test_failed_refresh_labels_stale_report(self) -> None:
        from mosh.engagements import asset_discovery_dir, attach_asset, create_engagement
        engagement = create_engagement(self.app.output_root, "Failed refresh")
        asset = attach_asset(self.app.output_root, engagement.id, "https://app.example.test").asset
        report_dir = asset_discovery_dir(self.app.output_root, engagement.id, asset.id)
        report_dir.mkdir(parents=True)
        (report_dir / "report.md").write_text("# Previous report", encoding="utf-8")

        def fail(*args):
            raise RuntimeError("Discovery failed")

        self.app.discovery_runner = fail
        stage_url = f"/assessments/{engagement.id}/discovery"
        self.post(stage_url, {"action": "refresh", "confirmed": "yes"})
        self.wait_for_discovery(engagement.id)
        page = self.get(stage_url).body
        self.assertIn("Needs attention", page)
        self.assertIn("Previous report", page)
        self.assertIn("Retry remaining", page)
        self.assertIn("Discovery failed", page)

    def test_planning_runs_from_discovery_and_renders_plan(self) -> None:
        from mosh.engagements import asset_discovery_dir, attach_asset, create_engagement, engagement_plan_dir
        from mosh.models import Event

        engagement = create_engagement(self.app.output_root, "Planning UI")
        asset = attach_asset(self.app.output_root, engagement.id, "https://app.example.test").asset
        discovery_dir = asset_discovery_dir(self.app.output_root, engagement.id, asset.id)
        discovery_dir.mkdir(parents=True)
        (discovery_dir / "report.md").write_text("# Discovery", encoding="utf-8")
        plan_dir = engagement_plan_dir(self.app.output_root, engagement.id)
        self.app._planning_current = lambda _: (plan_dir / "plan.md").is_file()
        reviewing = threading.Event()
        review_done = threading.Event()
        writing = threading.Event()
        write_done = threading.Event()
        self.addCleanup(review_done.set)
        self.addCleanup(write_done.set)

        def plan(config, output_root, engagement_id, event_sink):
            event_sink(Event("evidence_linker", "complete", "Evidence linked"))
            event_sink(Event("planner", "plan_submitted", "Draft <plan> submitted"))
            reviewing.set()
            review_done.wait(2)
            event_sink(Event("orchestrator", "engagement_template_written", "Plan reviewed"))
            writing.set()
            write_done.wait(2)
            plan_dir.mkdir(parents=True, exist_ok=True)
            (plan_dir / "plan.md").write_text("# Security test plan\n\n| Test | Priority |\n| --- | --- |\n| Login | High |\n\n<script>unsafe</script>", encoding="utf-8")
            return plan_dir

        self.app.planning_runner = plan
        detail_url = f"/assessments/{engagement.id}"
        planning_url = detail_url + "/planning"
        self.assertIn(f'href="{detail_url}/discovery"', self.get(detail_url).body)
        self.assertNotIn("Start planning", self.get(detail_url).body)
        self.assertNotIn("Continue to planning", self.get(detail_url + "/discovery").body)
        planning_page = self.get(planning_url).body
        self.assertIn("Start planning", planning_page)
        self.assertIn("Discovery is complete. Ready to build a security test plan.", planning_page)
        self.assertIn("identifies potential security issues, and turns them into testable hypotheses with checks tailored to this assessment", planning_page)
        self.assertIn("It writes the plan; security tests run later.", planning_page)
        self.assertIn('aria-label="Planning, Not started" aria-current="step"', planning_page)
        self.assertNotIn("Review discovery", planning_page)
        self.assertNotIn("Back to assessment", planning_page)
        self.assertEqual(self.post(planning_url, {"action": "start"}).location, planning_url)
        self.assertTrue(reviewing.wait(1))
        running = self.get(planning_url).body
        self.assertIn('class="stage-item running active"', running)
        self.assertIn('aria-label="Planning, In progress" aria-current="step"><span class="stage-mark" aria-hidden="true"></span>Planning', running)
        self.assertIn("Planning in progress", running)
        self.assertIn('class="done">Linking discovery evidence', running)
        self.assertIn('class="done">Drafting security test hypotheses', running)
        self.assertIn('class="current">Reviewing and refining the plan', running)
        self.assertIn(f'data-poll-url="{planning_url}/status"', running)
        self.assertNotIn('http-equiv="refresh"', running)
        self.assertTrue(json.loads(self.get(planning_url + "/status").body)["poll"])
        self.assertIn("Draft &lt;plan&gt; submitted", self.get(planning_url + "?view=logs").body)
        self.assertIn('<details class="log-console" data-live-logs data-logs-loaded="true" open>', self.get(planning_url + "?view=logs").body)
        self.assertIn('<details class="log-console" data-live-logs data-logs-loaded="false">', self.get(planning_url).body)
        self.assertIn(f'data-poll-url="{planning_url}/status?view=logs"', self.get(planning_url + "?view=logs").body)
        self.assertIn("Wait for the current stage", self.post(detail_url + "/assets", {"action": "remove", "asset_id": asset.id}).body)
        self.assertIn("already running", self.post(detail_url + "/discovery", {"action": "refresh"}).body)
        self.assertNotIn("Continue to discovery", self.get(detail_url).body)

        review_done.set()
        self.assertTrue(writing.wait(1))
        self.assertIn('class="current">Writing security test plan', self.get(planning_url).body)
        write_done.set()
        self.wait_for_planning(engagement.id)
        complete = self.get(planning_url).body
        self.assertIn("Planning complete", complete)
        self.assertIn(f'href="{detail_url}/testing">Continue to testing</a>', complete)
        self.assertIn("View plan", complete)
        self.assertFalse(json.loads(self.get(planning_url + "/status").body)["poll"])
        self.assertNotIn("View plan", self.get(detail_url).body)
        report = self.get(planning_url + "/report")
        self.assertIn('<h1 id="section-1">Security test plan</h1>', report.body)
        self.assertIn('<div class="markdown-table-wrap"><table>', report.body)
        self.assertIn("&lt;script&gt;unsafe&lt;/script&gt;", report.body)
        self.assertNotIn("<script>unsafe</script>", report.body)
        self.assertEqual(self.get("/assessments/eng_missing/planning/report").status, 404)
        (plan_dir / "events.json").write_text(json.dumps([{"timestamp": "2026-10-05T10:00:00Z", "agent": "planner", "message": "Plan persisted"}]), encoding="utf-8")
        self.app.planning_runs.clear()
        self.assertIn("Continue to testing", self.get(planning_url).body)
        (self.app.output_root / engagement.id / "security-testing").mkdir()
        after_testing_started = self.get(planning_url).body
        self.assertNotIn("Continue to testing", after_testing_started)
        self.assertIn("View plan", after_testing_started)
        self.assertIn("Plan persisted", self.get(planning_url + "?view=logs").body)
        self.app._planning_current = lambda _: False
        self.assertNotIn("Update plan", self.get(detail_url).body)
        self.assertIn("Update plan", self.get(planning_url).body)
        self.assertIn("Previous plan", self.get(planning_url).body)

    def test_web_planning_uses_existing_orchestrator(self) -> None:
        from mosh.config import AppConfig

        config = AppConfig.from_env(self.root / "mosh.yaml", self.root / ".env")
        sink = Mock()
        with patch("mosh.crews.planning.crew.SecurityTestPlanningOrchestrator") as orchestrator:
            orchestrator.return_value.run.return_value = self.root / "report" / "plan"
            result = self.app._run_planning(config, self.app.output_root, "eng_12345678", sink)
        self.assertEqual(result, self.root / "report" / "plan")
        self.assertEqual(orchestrator.call_args.kwargs, {"output_root": self.app.output_root, "event_sink": sink})
        orchestrator.return_value.run.assert_called_once_with("eng_12345678")

    def test_testing_runs_from_plan_and_renders_preflight_and_test_report(self) -> None:
        from mosh.crews.testing.crew import hypothesis_fingerprint, plan_revision_id
        from mosh.engagement import build_minimal_engagement_template
        from mosh.engagements import attach_asset, create_engagement, engagement_dir, engagement_plan_dir
        from mosh.memory import FileMemory

        engagement = create_engagement(self.app.output_root, "Testing UI")
        asset = attach_asset(self.app.output_root, engagement.id, "https://app.example.test").asset
        plan_dir = engagement_plan_dir(self.app.output_root, engagement.id)
        plan_dir.mkdir(parents=True)
        (plan_dir / "plan.md").write_text("# Plan", encoding="utf-8")
        plan = {"test_hypotheses": [{"id": "AUTH-001", "title": "Check authorization"}]}
        (plan_dir / "memory.json").write_text(json.dumps([{"kind": "security_test_plan_final", "content": {"structured": plan}}]), encoding="utf-8")
        template = build_minimal_engagement_template()
        template["engagement"].update({"authorization_confirmed": True, "active_testing_allowed": True})
        template["targets"]["production"]["web"] = asset.locator
        (engagement_dir(self.app.output_root, engagement.id) / "engagement_template.yaml").write_text(json.dumps(template), encoding="utf-8")
        self.app._planning_current = lambda _: True
        executing = threading.Event()
        release = threading.Event()
        planning_refresh_started = threading.Event()
        finish_planning_refresh = threading.Event()
        self.addCleanup(release.set)
        self.addCleanup(finish_planning_refresh.set)

        def test_runner(config, output_root, engagement_id, event_sink):
            report_dir = output_root / engagement_id / "security-testing"
            memory = FileMemory(report_dir, event_sink=event_sink)
            memory.record_event("orchestrator", "start", "Starting security testing preflight")
            memory.add_item("testing_preflight", {
                "ready": [{"id": "AUTH-001", "hypothesis_fingerprint": hypothesis_fingerprint(plan["test_hypotheses"][0])}],
                "ready_pending": ["AUTH-001"], "blocked": [], "plan_revision_id": plan_revision_id(plan),
            }, "security_test_coordinator")
            (report_dir / "preflight.md").write_text("# Preflight\n\nOne ready test.", encoding="utf-8")
            memory.record_event("orchestrator", "execution_start", "Starting unified security test execution")
            executing.set()
            release.wait(2)
            reports_dir = report_dir / "executed_tests"
            reports_dir.mkdir()
            (reports_dir / "AUTH-001.md").write_text(
                '<!-- mosh-execution ' + json.dumps({
                    "test_id": "AUTH-001", "review_accepted": True,
                    "hypothesis_fingerprint": hypothesis_fingerprint(plan["test_hypotheses"][0]),
                }) + ' -->\n# Authorization result\n<script>unsafe</script>',
                encoding="utf-8",
            )
            memory.record_event("orchestrator", "planning_refresh_start", "Updating plan from test findings")
            planning_refresh_started.set()
            finish_planning_refresh.wait(2)
            memory.record_event("orchestrator", "planning_refresh_complete", "Updated plan from test findings")
            memory.record_event("orchestrator", "complete", "Security testing completed")
            return report_dir

        self.app.testing_runner = test_runner
        testing_url = f"/assessments/{engagement.id}/testing"
        initial = self.get(testing_url).body
        self.assertIn('aria-label="Testing, Not started" aria-current="step"', initial)
        self.assertIn("Ready to run security tests.", initial)
        self.assertIn("Start testing", initial)
        self.assertIn("Planned tests", initial)
        self.assertIn("Check authorization", initial)
        self.assertIn("1 ready · 0 blocked · 0 deferred", initial)
        self.assertNotIn("Engagement settings:", initial)
        self.assertNotIn("Start testing", self.get(f"/assessments/{engagement.id}").body)
        self.assertIn("Choose a valid testing action", self.post(testing_url, {"action": "wrong"}).body)
        self.assertEqual(self.post(testing_url, {"action": "start"}).location, testing_url)
        self.assertTrue(executing.wait(1))
        running = self.get(testing_url).body
        self.assertIn("Executing and reviewing ready security tests", running)
        self.assertIn('aria-label="Testing, In progress" aria-current="step"><span class="stage-mark" aria-hidden="true"></span>Testing', running)
        self.assertIn("1 ready · 0 blocked · 0 deferred", running)
        self.assertIn(f'data-poll-url="{testing_url}/status"', running)
        status = json.loads(self.get(testing_url + "/status").body)
        self.assertTrue(status["poll"])
        self.assertIn("View preflight", status["html"])
        self.assertIn("already running", self.post(testing_url, {"action": "start"}).body)
        self.assertIn("Wait for the current stage", self.post(f"/assessments/{engagement.id}/assets", {"action": "remove", "asset_id": asset.id}).body)
        self.assertIn("Wait for the current stage to finish", self.post(f"/assessments/{engagement.id}/guidance", {"action": "save-notes", "notes": "changed"}).body)
        self.assertIn("Starting unified security test execution", self.get(testing_url + "?view=logs").body)
        release.set()
        self.assertTrue(planning_refresh_started.wait(1))
        refreshing = self.get(testing_url).body
        self.assertIn("Test reports are saved. Findings from Testing updated Discovery; Planning is now generating a revised plan.", refreshing)
        self.assertIn('aria-label="Planning, Updating plan"', refreshing)
        self.assertIn('class="stage-item running"', refreshing)
        self.assertIn('aria-label="Testing, Updating plan" aria-current="step"', refreshing)
        self.assertIn("The saved reports cover the tests just run", refreshing)
        self.assertIn("1 complete", refreshing)
        self.assertTrue(json.loads(self.get(testing_url + "/status").body)["poll"])
        planning_url = f"/assessments/{engagement.id}/planning"
        planning_refresh = self.get(planning_url).body
        self.assertIn("Updating the plan with new information found during Testing", planning_refresh)
        self.assertIn('aria-label="Planning, Updating plan" aria-current="step"', planning_refresh)
        self.assertNotIn("Update plan</button>", planning_refresh)
        self.assertTrue(json.loads(self.get(planning_url + "/status").body)["poll"])
        finish_planning_refresh.set()
        self.wait_for_testing(engagement.id)
        complete = self.get(testing_url).body
        self.assertIn("Testing complete", complete)
        self.assertIn('aria-label="Testing, Complete" aria-current="step"', complete)
        self.assertIn("AUTH-001", complete)
        self.assertIn("1 complete", complete)
        self.assertIn("View report", complete)
        self.assertIn("Continue to reporting", complete)
        self.assertNotIn("Start testing", complete)
        self.assertFalse(json.loads(self.get(testing_url + "/status").body)["poll"])
        self.assertIn('<h1 id="section-1">Preflight</h1>', self.get(testing_url + "/preflight").body)
        report = self.get(testing_url + "/reports/AUTH-001")
        self.assertIn('<h1 id="section-1">Authorization result</h1>', report.body)
        self.assertIn("&lt;script&gt;unsafe&lt;/script&gt;", report.body)
        self.assertNotIn("mosh-execution", report.body)
        self.assertEqual(self.get(testing_url + "/reports/missing").status, 404)
        self.app.testing_runs.clear()
        self.assertIn('aria-label="Testing, Complete" aria-current="step"', self.get(testing_url).body)
        report_path = self.app.output_root / engagement.id / "security-testing" / "executed_tests" / "AUTH-001.md"
        accepted_report = report_path.read_text(encoding="utf-8")
        report_path.write_text(accepted_report.replace('"review_accepted": true', '"review_accepted": false'), encoding="utf-8")
        needs_rerun = self.get(testing_url).body
        self.assertIn("1 test(s) needing another run", needs_rerun)
        self.assertIn("Needs rerun", needs_rerun)
        self.assertIn('aria-label="Testing, Needs attention" aria-current="step"', needs_rerun)
        report_path.write_text(accepted_report, encoding="utf-8")
        updated_plan = {"test_hypotheses": [*plan["test_hypotheses"], {"id": "AUTH-002", "title": "Check another role"}]}
        (plan_dir / "memory.json").write_text(json.dumps([{"kind": "security_test_plan_final", "content": {"structured": updated_plan}}]), encoding="utf-8")
        updated = self.get(testing_url).body
        self.assertIn('aria-label="Testing, Needs attention" aria-current="step"', updated)
        self.assertIn("Testing finished and saved reports. Test findings led Mosh to update Discovery and Planning", updated)
        self.assertIn("Mosh refined the plan", updated)
        self.assertIn("Testing uncovered new details about the assets", updated)
        self.assertIn("reconsidered the testing approach, and refined the hypotheses", updated)
        self.assertIn("review the changes and decide what to run next", updated)
        self.assertIn("Run remaining tests", updated)
        revised_plan = {"test_hypotheses": [{"id": "AUTH-001", "title": "Check revised authorization"}]}
        (plan_dir / "memory.json").write_text(json.dumps([{"kind": "security_test_plan_final", "content": {"structured": revised_plan}}]), encoding="utf-8")
        revised = self.get(testing_url).body
        self.assertIn("Needs rerun", revised)
        self.assertIn("Report saved for an earlier version of this test", revised)
        earlier_report = self.get(testing_url + "/reports/AUTH-001").body
        self.assertIn("Authorization result", earlier_report)
        self.assertIn('class="report-currency-note" role="note"', earlier_report)
        self.assertIn("Report saved for an earlier version of this test", earlier_report)

    def test_testing_feedback_choice_survives_restart_and_can_continue_to_reporting(self) -> None:
        from mosh.crews.reporting.crew import build_final_report_bundle
        from mosh.memory import FileMemory

        engagement, plan_dir, discovery_dir, runs = self.completed_testing_with_feedback()
        testing_url = f"/assessments/{engagement.id}/testing"
        report_url = f"/assessments/{engagement.id}/report"
        before = self.get(testing_url).body
        self.assertIn("New findings from testing", before)
        self.assertIn("A newly identified test endpoint.", before)
        self.assertIn("AUTH-001 · Check authorization", before)
        self.assertIn(f'/assessments/{engagement.id}/testing/reports/AUTH-001', before)
        self.assertIn("adds these details to the Discovery reports", before)
        self.assertIn("may add, change, or remove tests", before)
        self.assertIn("Discovery and completed tests are not repeated", before)
        self.assertIn("Testing checks the revised plan before reporting", before)
        self.assertIn("no further tests are planned from them", before)
        self.assertIn("Update discovery and plan", before)
        self.assertIn("Continue to reporting", before)
        self.assertIn('aria-label="Report, Not started"', before)
        self.assertEqual(len(runs), 1)
        self.assertEqual((discovery_dir / "report.md").read_text(encoding="utf-8"), "# Original discovery\n")
        self.assertEqual((plan_dir / "plan.md").read_text(encoding="utf-8"), "# Original plan\n")

        restarted = WebApp(self.root, folder_root=self.root)
        restarted._planning_current = lambda _: True
        self.assertIn("Continue to reporting", restarted.handle("GET", testing_url, headers={"Host": "127.0.0.1:8765"}).body)

        bundles = []

        def reporting_runner(config, output_root, engagement_id, event_sink):
            bundle = build_final_report_bundle(output_root, engagement_id)
            bundles.append(bundle)
            report_dir = output_root / engagement_id / "final-report"
            memory = FileMemory(report_dir, event_sink=event_sink)
            (report_dir / "report.md").write_text("# Final report\n\n<script>unsafe</script>\n", encoding="utf-8")
            memory.record_event("orchestrator", "complete", "Final report generation completed")
            return report_dir

        self.app.reporting_runner = reporting_runner
        self.assertIn("has not been added to Discovery or Planning", self.get(report_url).body)
        self.assertEqual(self.post(report_url, {"action": "start"}).location, report_url)
        self.wait_for_reporting(engagement.id)
        self.assertEqual(self.app.reporting_runs[engagement.id].status, "complete")
        self.assertEqual([item["id"] for item in bundles[0]["executed_tests"]], ["AUTH-001"])
        self.assertIn('aria-label="Report, Complete" aria-current="step"', self.get(report_url).body)
        self.assertIn("&lt;script&gt;unsafe&lt;/script&gt;", self.get(report_url + "/view").body)
        self.assertEqual(self.post(report_url, {"action": "start"}).location, report_url)
        self.assertEqual(len(bundles), 1)
        self.assertIn("View report", restarted.handle("GET", report_url, headers={"Host": "127.0.0.1:8765"}).body)
        self.assertEqual(len(runs), 1)
        self.assertEqual((discovery_dir / "report.md").read_text(encoding="utf-8"), "# Original discovery\n")
        self.assertEqual((plan_dir / "plan.md").read_text(encoding="utf-8"), "# Original plan\n")
        self.assertNotIn("New findings from testing", self.get(testing_url).body)

    def test_testing_feedback_choice_shows_all_findings_and_escapes_details(self) -> None:
        engagement, _, _, _ = self.completed_testing_with_feedback()
        memory_path = self.app.output_root / engagement.id / "security-testing" / "memory.json"
        items = json.loads(memory_path.read_text(encoding="utf-8"))
        bundle = next(item["content"] for item in items if item["kind"] == "security_test_execution_bundle")
        bundle["final_evidence"]["discovery_updates"].extend(
            {"type": "endpoint", "detail": detail}
            for detail in ("Second endpoint", "Third endpoint", "Fourth endpoint", "<script>unsafe</script>")
        )
        memory_path.write_text(json.dumps(items), encoding="utf-8")

        body = self.get(f"/assessments/{engagement.id}/testing").body
        self.assertIn("Show 2 more findings", body)
        self.assertIn("Fourth endpoint", body)
        self.assertIn("&lt;script&gt;unsafe&lt;/script&gt;", body)
        self.assertNotIn("<script>unsafe</script>", body)

    def test_reporting_shows_event_driven_steps(self) -> None:
        from mosh.memory import FileMemory

        engagement, _, _, _ = self.completed_testing_with_feedback()
        report_url = f"/assessments/{engagement.id}/report"
        started, evidence_ready, written = (threading.Event() for _ in range(3))
        next_evidence, next_writer, next_review = (threading.Event() for _ in range(3))
        self.addCleanup(next_evidence.set)
        self.addCleanup(next_writer.set)
        self.addCleanup(next_review.set)

        def reporting_runner(config, output_root, engagement_id, event_sink):
            report_dir = output_root / engagement_id / "final-report"
            memory = FileMemory(report_dir, event_sink=event_sink)
            memory.record_event("orchestrator", "start", "Starting final report generation")
            started.set()
            next_evidence.wait(2)
            memory.record_event("orchestrator", "engagement_steer_loaded", "Assessment evidence is ready")
            evidence_ready.set()
            next_writer.wait(2)
            (report_dir / "report.md").write_text("# Final report\n", encoding="utf-8")
            memory.record_event("writer", "report_written", "Final report written")
            written.set()
            next_review.wait(2)
            memory.record_event("reviewer", "review_submitted", "Final report reviewed")
            memory.record_event("orchestrator", "complete", "Final report generation completed")
            return report_dir

        self.app.reporting_runner = reporting_runner
        self.assertEqual(self.post(report_url, {"action": "start"}).location, report_url)
        self.assertTrue(started.wait(1))
        first = self.get(report_url).body
        self.assertIn('<li class="current">Preparing assessment evidence</li>', first)
        self.assertIn('<li class="waiting">Writing the final report</li>', first)
        self.assertTrue(json.loads(self.get(report_url + "/status").body)["poll"])

        next_evidence.set()
        self.assertTrue(evidence_ready.wait(1))
        second = self.get(report_url).body
        self.assertIn('<li class="done">Preparing assessment evidence</li>', second)
        self.assertIn('<li class="current">Writing the final report</li>', second)

        next_writer.set()
        self.assertTrue(written.wait(1))
        third = self.get(report_url).body
        self.assertIn('<li class="done">Writing the final report</li>', third)
        self.assertIn('<li class="current">Reviewing and finalizing the report</li>', third)

        next_review.set()
        self.wait_for_reporting(engagement.id)
        finished = self.get(report_url).body
        self.assertIn('<li class="done">Reviewing and finalizing the report</li>', finished)
        self.assertNotIn('<li class="current">', finished)
        self.assertFalse(json.loads(self.get(report_url + "/status").body)["poll"])

    def test_reporting_marks_failed_active_step(self) -> None:
        from mosh.web import ReportingRun

        engagement, _, _, _ = self.completed_testing_with_feedback()
        self.app.reporting_runs[engagement.id] = ReportingRun(
            active_step=1, status="failed", error="Writer unavailable",
        )
        body = self.get(f"/assessments/{engagement.id}/report").body
        self.assertIn('<li class="done">Preparing assessment evidence</li>', body)
        self.assertIn('<li class="failed">Writing the final report</li>', body)
        self.assertIn('<li class="waiting">Reviewing and finalizing the report</li>', body)
        self.assertIn("Retry reporting", body)

    def test_testing_feedback_choice_replans_without_running_tests_again(self) -> None:
        from mosh.crews.testing.crew import collect_testing_discovery_updates
        from mosh.memory import FileMemory

        engagement, plan_dir, discovery_dir, runs = self.completed_testing_with_feedback()
        testing_url = f"/assessments/{engagement.id}/testing"
        saved_report = (self.app.output_root / engagement.id / "security-testing" / "executed_tests" / "AUTH-001.md").read_text(encoding="utf-8")
        started = threading.Event()
        release = threading.Event()
        self.addCleanup(release.set)
        refreshes = []

        def feedback_runner(config, output_root, engagement_id, event_sink):
            refreshes.append(engagement_id)
            started.set()
            release.wait(2)
            report_dir = output_root / engagement_id / "security-testing"
            memory = FileMemory(report_dir, event_sink=event_sink, reset=False)
            memory.record_event("orchestrator", "planning_refresh_start", "Updating plan")
            updates = collect_testing_discovery_updates(report_dir)
            (discovery_dir / "memory.json").write_text(json.dumps([{
                "kind": "testing_discovery_feedback", "content": {"updates": updates},
            }]), encoding="utf-8")
            (discovery_dir / "report.md").write_text("# Updated discovery\n", encoding="utf-8")
            revised = {"test_hypotheses": [{"id": "AUTH-001", "title": "Check revised authorization", "requirements": ["No credentials required."]}]}
            (plan_dir / "memory.json").write_text(json.dumps([{"kind": "security_test_plan_final", "content": {"structured": revised}}]), encoding="utf-8")
            memory.record_event("orchestrator", "planning_refresh_complete", "Plan updated")
            return report_dir

        self.app.feedback_runner = feedback_runner
        self.assertEqual(self.post(testing_url, {"action": "replan"}).location, testing_url)
        self.assertTrue(started.wait(1))
        updating = self.get(testing_url).body
        self.assertIn("Updating Discovery and Planning", updating)
        self.assertIn('aria-label="Planning, In progress"', updating)
        self.assertTrue(json.loads(self.get(testing_url + "/status").body)["poll"])
        release.set()
        self.wait_for_planning(engagement.id)
        updated = self.get(testing_url).body
        self.assertIn("Needs rerun", updated)
        self.assertNotIn("New findings from testing", updated)
        self.assertEqual(refreshes, [engagement.id])
        self.assertEqual(len(runs), 1)
        self.assertEqual((self.app.output_root / engagement.id / "security-testing" / "executed_tests" / "AUTH-001.md").read_text(encoding="utf-8"), saved_report)
        self.assertIn('aria-disabled="true"', updated)
        self.assertIn("Finish Testing for the current plan", self.post(f"/assessments/{engagement.id}/report", {"action": "start"}).body)

    def test_testing_blocked_preflight_can_retry_and_failed_run_shows_error(self) -> None:
        from mosh.crews.testing.crew import plan_revision_id
        from mosh.engagements import attach_asset, create_engagement, engagement_plan_dir
        from mosh.memory import FileMemory

        engagement = create_engagement(self.app.output_root, "Blocked testing")
        attach_asset(self.app.output_root, engagement.id, "https://app.example.test")
        plan_dir = engagement_plan_dir(self.app.output_root, engagement.id)
        plan_dir.mkdir(parents=True)
        (plan_dir / "plan.md").write_text("# Plan", encoding="utf-8")
        plan = {"test_hypotheses": [{"id": "AUTH-001", "title": "Check authorization"}]}
        (plan_dir / "memory.json").write_text(json.dumps([{"kind": "security_test_plan_final", "content": {"structured": plan}}]), encoding="utf-8")
        self.app._planning_current = lambda _: True
        testing_url = f"/assessments/{engagement.id}/testing"
        attempts = []

        def test_runner(config, output_root, engagement_id, event_sink):
            attempts.append(engagement_id)
            if len(attempts) == 1:
                raise RuntimeError("Testing model unavailable")
            report_dir = output_root / engagement_id / "security-testing"
            memory = FileMemory(report_dir, event_sink=event_sink)
            memory.add_item("testing_preflight", {
                "ready_pending": [], "blocked": [{"id": "AUTH-001", "title": "Check authorization"}],
                "plan_revision_id": plan_revision_id(plan),
            }, "security_test_coordinator")
            (report_dir / "preflight.md").write_text("# Preflight\n\nMissing credentials.", encoding="utf-8")
            memory.record_event("orchestrator", "complete", "Security testing completed")
            return report_dir

        self.app.testing_runner = test_runner
        self.post(testing_url, {"action": "start"})
        self.wait_for_testing(engagement.id)
        failure = self.get(testing_url).body
        self.assertIn("Testing model unavailable", failure)
        self.assertIn("Retry testing", failure)
        self.post(testing_url, {"action": "start"})
        self.wait_for_testing(engagement.id)
        blocked = self.get(testing_url).body
        self.assertIn("Testing finished with 1 blocked test(s)", blocked)
        self.assertIn('aria-label="Testing, Needs attention" aria-current="step"', blocked)
        self.assertIn("Needs a prerequisite before it can run", blocked)
        self.assertIn("Run remaining tests", blocked)
        self.assertIn("Missing credentials", self.get(testing_url + "/preflight").body)
        self.app.testing_runs.clear()
        self.assertIn('aria-label="Testing, Needs attention" aria-current="step"', self.get(testing_url).body)

    def test_testing_lists_current_prerequisites_before_run_and_updates_after_credentials(self) -> None:
        from mosh.engagement import build_minimal_engagement_template
        from mosh.engagements import attach_asset, create_engagement, engagement_dir, engagement_plan_dir

        engagement = create_engagement(self.app.output_root, "Readiness preview")
        asset = attach_asset(self.app.output_root, engagement.id, "https://app.example.test").asset
        plan_dir = engagement_plan_dir(self.app.output_root, engagement.id)
        plan_dir.mkdir(parents=True)
        (plan_dir / "plan.md").write_text("# Plan", encoding="utf-8")
        plan = {"test_hypotheses": [
            {"id": "PUBLIC-001", "title": "Check public headers <script>", "execution_mode": "live", "requirements": ["No credentials required."]},
            {"id": "ADMIN-001", "title": "Check admin access", "execution_mode": "live", "requirements": ["Admin credentials"]},
            {"id": "FOLLOWUP-001", "title": "Check follow-up", "execution_mode": "live", "requirements": ["No credentials required."], "depends_on": ["PUBLIC-001"]},
            {"id": "LATER-001", "title": "Check later integration", "execution_mode": "deferred", "defer_reason": ["Need test tenant"]},
        ]}
        (plan_dir / "memory.json").write_text(json.dumps([{"kind": "security_test_plan_final", "content": {"structured": plan}}]), encoding="utf-8")
        template = build_minimal_engagement_template()
        template["engagement"].update({"authorization_confirmed": True, "active_testing_allowed": True})
        template["targets"]["production"]["web"] = asset.locator
        (engagement_dir(self.app.output_root, engagement.id) / "engagement_template.yaml").write_text(json.dumps(template), encoding="utf-8")
        self.app._planning_current = lambda _: True
        url = f"/assessments/{engagement.id}/testing"

        before = self.get(url).body
        self.assertIn("1 ready · 2 blocked · 1 deferred", before)
        self.assertIn('class="planned-test-status blocked">Blocked</span>', before)
        self.assertIn("PUBLIC-001", before)
        self.assertIn("ADMIN-001", before)
        self.assertIn("Complete test PUBLIC-001 first to unlock this test.", before)
        self.assertIn("LATER-001", before)
        self.assertIn("Add Admin credentials in Scope.", before)
        self.assertIn("Need test tenant", before)
        self.assertIn("Check public headers &lt;script&gt;", before)
        self.assertNotIn("<script>\n", before)
        self.assertNotIn("View preflight", before)
        self.assertIsNone(self.app.testing_runs.get(engagement.id))

        self.post(f"/assessments/{engagement.id}/credentials", {"action": "save", "role": "admin", "token": "secret-test-token"})
        after = self.get(url).body
        self.assertIn("2 ready · 1 blocked · 1 deferred", after)
        self.assertNotIn("Add Admin credentials in Scope.", after)
        self.assertNotIn("secret-test-token", after)
        self.assertIsNone(self.app.testing_runs.get(engagement.id))

    def test_testing_shows_plan_blocker_and_previous_report(self) -> None:
        from mosh.engagement import build_minimal_engagement_template
        from mosh.engagements import attach_asset, create_engagement, engagement_dir, engagement_plan_dir

        engagement = create_engagement(self.app.output_root, "CORS review")
        asset = attach_asset(self.app.output_root, engagement.id, "https://app.example.test").asset
        plan_dir = engagement_plan_dir(self.app.output_root, engagement.id)
        plan_dir.mkdir(parents=True)
        (plan_dir / "plan.md").write_text("# Plan", encoding="utf-8")
        plan = {"test_hypotheses": [{
            "id": "CORS-001",
            "title": "Check CORS and response headers",
            "execution_mode": "live",
            "execution_readiness": "preflight_blocked",
            "readiness_blockers": ["Confirm the separate API host is in scope before its preflight request."],
            "requirements": ["No credentials required."],
        }]}
        (plan_dir / "memory.json").write_text(json.dumps([{"kind": "security_test_plan_final", "content": {"structured": plan}}]), encoding="utf-8")
        template = build_minimal_engagement_template()
        template["engagement"].update({"authorization_confirmed": True, "active_testing_allowed": True})
        template["targets"]["production"]["web"] = asset.locator
        (engagement_dir(self.app.output_root, engagement.id) / "engagement_template.yaml").write_text(json.dumps(template), encoding="utf-8")
        report_dir = self.app._testing_dir(engagement.id) / "executed_tests"
        report_dir.mkdir(parents=True)
        (report_dir / "CORS-001.md").write_text("# Earlier CORS report", encoding="utf-8")
        self.app._planning_current = lambda _: True

        page = self.get(f"/assessments/{engagement.id}/testing").body

        self.assertIn('class="planned-test-status blocked">Blocked</span>', page)
        self.assertIn("Confirm the separate API host is in scope", page)
        self.assertIn("View report", page)
        self.assertIn("Review scope", page)
        self.assertNotIn('class="planned-test-status rerun"', page)

    def test_testing_collects_credentials_and_test_data_without_leaving_testing(self) -> None:
        from mosh.engagement import build_minimal_engagement_template, load_engagement_file
        from mosh.engagements import attach_asset, create_engagement, engagement_dir, engagement_plan_dir

        engagement = create_engagement(self.app.output_root, "Required details")
        asset = attach_asset(self.app.output_root, engagement.id, "https://app.example.test").asset
        plan_dir = engagement_plan_dir(self.app.output_root, engagement.id)
        plan_dir.mkdir(parents=True)
        (plan_dir / "plan.md").write_text("# Plan", encoding="utf-8")
        plan = {"test_hypotheses": [{
            "id": "AUTH-001", "title": "Check admin form", "execution_mode": "live",
            "requirements": ["Admin credentials and test email"],
        }]}
        (plan_dir / "memory.json").write_text(json.dumps([{"kind": "security_test_plan_final", "content": {"structured": plan}}]), encoding="utf-8")
        template = build_minimal_engagement_template()
        template["engagement"].update(authorization_confirmed=True, active_testing_allowed=True)
        template["targets"]["production"]["web"] = asset.locator
        template_path = engagement_dir(self.app.output_root, engagement.id) / "engagement_template.yaml"
        template_path.write_text(json.dumps(template), encoding="utf-8")
        self.app._planning_current = lambda _: True
        testing_url = f"/assessments/{engagement.id}/testing"
        fields = {"return_to": "testing", "test_id": "AUTH-001"}

        page = self.get(testing_url).body
        self.assertIn("Planning identified 1 security test from the discovered assets", page)
        self.assertIn("The test has run and a result has been produced for the current plan", page)
        self.assertIn('data-open-requirements="test-requirements-0"', page)
        self.assertIn('name="role" value="admin"', page)
        self.assertIn('name="data_key" value="email"', page)
        self.assertIn("Saving does not start testing", page)

        invalid = self.post(f"/assessments/{engagement.id}/credentials", {
            **fields, "action": "save", "role": "admin", "username": "admin", "token": "secret-token",
        }).body
        self.assertIn("Enter a token or a username and password, not both", invalid)
        self.assertIn("data-auto-open", invalid)
        self.assertNotIn("secret-token", invalid)
        self.assertFalse(load_engagement_file(template_path)["credentials"].get("admin"))

        saved_credentials = self.post(f"/assessments/{engagement.id}/credentials", {
            **fields, "action": "save", "role": "admin", "token": "secret-token",
        })
        self.assertEqual(saved_credentials.location, testing_url + "?details=AUTH-001")
        self.assertEqual(load_engagement_file(template_path)["credentials"]["admin"]["token"], "secret-token")
        remaining = self.get(saved_credentials.location).body
        self.assertIn('name="data_key" value="email"', remaining)
        self.assertIn("data-auto-open", remaining)
        self.assertNotIn("secret-token", remaining)

        saved_data = self.post(f"/assessments/{engagement.id}/test-setup", {
            **fields, "action": "save-data", "data_key": "email", "data_value": "tester@example.test",
        })
        self.assertEqual(saved_data.location, testing_url + "?details=AUTH-001")
        self.assertEqual(load_engagement_file(template_path)["safe_test_data"]["email"], "tester@example.test")
        ready = self.get(saved_data.location).body
        self.assertIn('class="planned-test-status ready">Ready</span>', ready)
        self.assertNotIn("Add required details", ready)
        self.assertNotIn("tester@example.test", ready)

    def test_testing_collects_permissions_and_target_in_scope(self) -> None:
        from mosh.engagement import load_engagement_file
        from mosh.engagements import attach_asset, create_engagement, engagement_dir, engagement_plan_dir

        engagement = create_engagement(self.app.output_root, "Permission details")
        attach_asset(self.app.output_root, engagement.id, "https://app.example.test")
        plan_dir = engagement_plan_dir(self.app.output_root, engagement.id)
        plan_dir.mkdir(parents=True)
        (plan_dir / "plan.md").write_text("# Plan", encoding="utf-8")
        plan = {"test_hypotheses": [{"id": "PUBLIC-001", "title": "Check headers", "execution_mode": "live", "requirements": ["No credentials required."]}]}
        (plan_dir / "memory.json").write_text(json.dumps([{"kind": "security_test_plan_final", "content": {"structured": plan}}]), encoding="utf-8")
        self.app._planning_current = lambda _: True
        testing_url = f"/assessments/{engagement.id}/testing"
        fields = {"return_to": "testing", "test_id": "PUBLIC-001"}
        template_path = engagement_dir(self.app.output_root, engagement.id) / "engagement_template.yaml"
        page = self.get(testing_url).body
        self.assertIn('name="permission_key" value="authorization_confirmed"', page)
        self.assertIn('name="permission_key" value="active_testing_allowed"', page)
        self.assertIn('name="target_url" type="url"', page)

        denied = self.post(f"/assessments/{engagement.id}/test-setup", {
            **fields, "action": "save-permission", "permission_key": "authorization_confirmed", "permission_value": "",
        }).body
        self.assertIn("Choose Yes or No for a testing permission", denied)
        self.assertIn("data-auto-open", denied)
        self.assertFalse(template_path.exists())

        for key in ("authorization_confirmed", "active_testing_allowed"):
            response = self.post(f"/assessments/{engagement.id}/test-setup", {
                **fields, "action": "save-permission", "permission_key": key, "permission_value": "yes",
            })
            self.assertEqual(response.location, testing_url + "?details=PUBLIC-001")
            self.assertTrue(load_engagement_file(template_path)["engagement"][key])
        target = self.post(f"/assessments/{engagement.id}/test-setup", {
            **fields, "action": "save-target", "target_name": "website", "target_url": "https://app.example.test",
        })
        self.assertEqual(target.location, testing_url + "?details=PUBLIC-001")
        self.assertEqual(load_engagement_file(template_path)["targets"]["alternative"]["website"], "https://app.example.test")
        self.assertIn('class="planned-test-status ready">Ready</span>', self.get(target.location).body)

    def test_testing_shows_three_progress_steps_for_each_active_test(self) -> None:
        from mosh.crews.testing.crew import hypothesis_fingerprint
        from mosh.engagement import build_minimal_engagement_template
        from mosh.engagements import attach_asset, create_engagement, engagement_dir, engagement_plan_dir
        from mosh.models import Event
        from mosh.web import TestingRun

        engagement = create_engagement(self.app.output_root, "Test progress")
        asset = attach_asset(self.app.output_root, engagement.id, "https://app.example.test").asset
        plan_dir = engagement_plan_dir(self.app.output_root, engagement.id)
        plan_dir.mkdir(parents=True)
        (plan_dir / "plan.md").write_text("# Plan", encoding="utf-8")
        hypotheses = [
            {"id": "A-001", "title": "Check first issue", "requirements": ["No credentials required."]},
            {"id": "B-001", "title": "Check second issue", "requirements": ["No credentials required."]},
        ]
        (plan_dir / "memory.json").write_text(json.dumps([{"kind": "security_test_plan_final", "content": {"structured": {"test_hypotheses": hypotheses}}}]), encoding="utf-8")
        template = build_minimal_engagement_template()
        template["engagement"].update(authorization_confirmed=True, active_testing_allowed=True)
        template["targets"]["production"]["web"] = asset.locator
        (engagement_dir(self.app.output_root, engagement.id) / "engagement_template.yaml").write_text(json.dumps(template), encoding="utf-8")
        self.app._planning_current = lambda _: True
        run = TestingRun()
        self.app.testing_runs[engagement.id] = run
        url = f"/assessments/{engagement.id}/testing/status"

        def progress(action: str, test_id: str, revision: int = 1) -> str:
            run.events.append(Event("orchestrator", action, action, {"test_id": test_id, "revision": revision}))
            return json.loads(self.get(url).body)["html"]

        checks = progress("test_checks_started", "A-001")
        self.assertIn('class="planned-test-status running">Running</span>', checks)
        self.assertIn('<li class="current">Running planned checks</li><li class="waiting">Reviewing evidence</li>', checks)
        self.assertEqual(checks.count('class="discovery-steps testing-steps"'), 1)
        evidence = progress("test_evidence_ready", "A-001")
        self.assertIn('<li class="done">Running planned checks</li><li class="current">Reviewing evidence</li>', evidence)
        reviewed = progress("test_review_ready", "A-001")
        self.assertIn('<li class="done">Reviewing evidence</li><li class="current">Writing test report</li>', reviewed)

        report_dir = self.app.output_root / engagement.id / "security-testing" / "executed_tests"
        report_dir.mkdir(parents=True)
        (report_dir / "A-001.md").write_text('<!-- mosh-execution ' + json.dumps({
            "test_id": "A-001", "review_accepted": True,
            "hypothesis_fingerprint": hypothesis_fingerprint(hypotheses[0]),
        }) + ' -->\n# Result', encoding="utf-8")
        complete_a = progress("report_written", "A-001")
        self.assertIn('class="planned-test-status complete">Complete</span>', complete_a)
        self.assertIn('<li class="done">Writing test report</li>', complete_a)
        second = progress("test_checks_started", "B-001")
        self.assertEqual(second.count('class="discovery-steps testing-steps"'), 2)
        self.assertIn('class="planned-test-status running">Running</span>', second)
        progress("test_evidence_ready", "B-001")
        retry = progress("test_checks_started", "B-001", revision=2)
        self.assertIn('<li class="current">Running planned checks</li><li class="waiting">Reviewing evidence</li>', retry)
        run.status = "failed"
        failed = json.loads(self.get(url).body)["html"]
        self.assertIn('<li class="failed">Running planned checks</li>', failed)
        self.assertIn('class="planned-test-status rerun">Needs rerun</span>', failed)

    def test_web_testing_uses_existing_orchestrator(self) -> None:
        from mosh.config import AppConfig

        config = AppConfig.from_env(self.root / "mosh.yaml", self.root / ".env")
        sink = Mock()
        with patch("mosh.crews.testing.crew.SecurityTestingOrchestrator") as orchestrator:
            orchestrator.return_value.run.return_value = self.root / "report" / "security-testing"
            result = self.app._run_testing(config, self.app.output_root, "eng_12345678", sink)
        self.assertEqual(result, self.root / "report" / "security-testing")
        self.assertEqual(orchestrator.call_args.kwargs, {"output_root": self.app.output_root, "event_sink": sink})
        orchestrator.return_value.run.assert_called_once_with("eng_12345678", auto_refresh_feedback=False)

    def test_testing_waits_for_current_plan(self) -> None:
        from mosh.engagements import attach_asset, create_engagement, engagement_plan_dir

        engagement = create_engagement(self.app.output_root, "No plan yet")
        attach_asset(self.app.output_root, engagement.id, "https://app.example.test")
        testing_url = f"/assessments/{engagement.id}/testing"
        self.assertIn("Complete or update planning before testing", self.get(testing_url).body)
        self.assertNotIn("Start testing", self.get(testing_url).body)
        self.assertIn("Complete or update planning before testing", self.post(testing_url, {"action": "start"}).body)
        self.assertIsNone(self.app.testing_runs.get(engagement.id))
        plan_dir = engagement_plan_dir(self.app.output_root, engagement.id)
        plan_dir.mkdir(parents=True)
        (plan_dir / "plan.md").write_text("# Stale plan", encoding="utf-8")
        self.app._planning_current = lambda _: False
        self.assertIn("Complete or update planning before testing", self.post(testing_url, {"action": "start"}).body)
        self.assertIsNone(self.app.testing_runs.get(engagement.id))

    def test_planning_requires_discovery_and_can_retry_failure(self) -> None:
        from mosh.engagements import asset_discovery_dir, attach_asset, create_engagement, engagement_plan_dir

        engagement = create_engagement(self.app.output_root, "Planning retry")
        asset = attach_asset(self.app.output_root, engagement.id, "https://app.example.test").asset
        planning_url = f"/assessments/{engagement.id}/planning"
        self.app._planning_current = lambda _: (engagement_plan_dir(self.app.output_root, engagement.id) / "plan.md").is_file()
        calls = []

        def plan(config, output_root, engagement_id, event_sink):
            calls.append(engagement_id)
            if len(calls) == 1:
                raise RuntimeError("Model unavailable")
            plan_dir = engagement_plan_dir(output_root, engagement_id)
            plan_dir.mkdir(parents=True, exist_ok=True)
            (plan_dir / "plan.md").write_text("# Plan", encoding="utf-8")
            return plan_dir

        self.app.planning_runner = plan
        self.assertIn("Complete discovery", self.post(planning_url, {"action": "start"}).body)
        self.assertEqual(calls, [])
        discovery_dir = asset_discovery_dir(self.app.output_root, engagement.id, asset.id)
        discovery_dir.mkdir(parents=True)
        (discovery_dir / "report.md").write_text("# Discovery", encoding="utf-8")
        self.post(planning_url, {"action": "start"})
        self.wait_for_planning(engagement.id)
        failed = self.get(planning_url).body
        self.assertIn("Planning needs attention", failed)
        self.assertIn("Model unavailable", failed)
        self.assertIn("Retry planning", failed)
        self.assertIn('class="failed">Linking discovery evidence', failed)
        self.assertFalse(json.loads(self.get(planning_url + "/status").body)["poll"])
        self.post(planning_url, {"action": "retry"})
        self.wait_for_planning(engagement.id)
        self.assertEqual(calls, [engagement.id, engagement.id])
        self.assertIn("View plan", self.get(planning_url).body)
        self.assertEqual(self.app.handle("POST", planning_url, {"action": "start"}, {"Host": "127.0.0.1:8765"}).status, 403)

    def test_existing_assessment_adds_and_removes_local_asset(self) -> None:
        from mosh.engagements import asset_dir, create_engagement
        engagement = create_engagement(self.app.output_root, "Existing assessment")
        detail_url = f"/assessments/{engagement.id}"
        assets_url = detail_url + "/assets"
        source = self.root / "Projects" / "sample"
        source.mkdir(parents=True)

        empty = self.get(detail_url).body
        self.assertIn("No assets attached yet", empty)
        self.assertNotIn("Continue to discovery", empty)
        self.assertIn(f'href="{detail_url}/discovery"', empty)
        self.assertIn('href="' + detail_url + '/folders"', empty)
        self.assertIn("sample", self.get(detail_url + "/folders?path=" + quote(str(source.parent), safe="")).body)
        self.assertEqual(self.post(detail_url + "/select-folder", {"path": str(source)}).location, detail_url)
        first = load_engagement(self.app.output_root, engagement.id).assets[0]
        self.assertEqual((first.type, first.locator), ("source_tree", str(source.resolve())))
        self.assertNotIn("Continue to discovery", self.get(detail_url).body)
        self.assertIn('value="' + first.id + '"', self.get(detail_url).body)
        self.assertIn("already attached", self.post(detail_url + "/select-folder", {"path": str(source)}).body)
        self.assertIn("Choose an existing folder", self.post(detail_url + "/select-folder", {"path": str(self.root.parent)}).body)

        old_dir = asset_dir(self.app.output_root, engagement.id, first.id)
        (old_dir / "discovery").mkdir()
        (old_dir / "discovery" / "report.md").write_text("Old discovery", encoding="utf-8")
        self.assertIn("Unknown asset id", self.post(assets_url, {"action": "remove", "asset_id": "asset_source_99"}).body)
        self.assertEqual(self.post(assets_url, {"action": "remove", "asset_id": first.id}).location, detail_url)
        self.assertEqual(load_engagement(self.app.output_root, engagement.id).assets, [])
        self.assertEqual((old_dir / "discovery" / "report.md").read_text(encoding="utf-8"), "Old discovery")
        self.post(detail_url + "/select-folder", {"path": str(source)})
        self.assertEqual(load_engagement(self.app.output_root, engagement.id).assets[0].id, "asset_source_2")
        self.assertEqual(self.app.handle("POST", assets_url, {"action": "remove", "asset_id": first.id}, {"Host": "127.0.0.1:8765"}).status, 403)

    def test_existing_assessment_remote_asset_check_and_retry(self) -> None:
        from mosh.engagements import create_engagement
        engagement = create_engagement(self.app.output_root, "Remote assets")
        detail_url = f"/assessments/{engagement.id}"
        assets_url = detail_url + "/assets"
        started = threading.Event()
        release = threading.Event()
        self.addCleanup(release.set)

        def delayed_check(kind: str, locator: str) -> tuple[bool, str]:
            started.set()
            release.wait(2)
            return False, "The website did not respond."

        self.app.asset_checker = delayed_check
        self.assertEqual(self.post(assets_url, {"action": "add", "asset_type": "live_url", "locator": "https://app.example.test/"}).location, detail_url)
        self.assertTrue(started.wait(1))
        checking = self.get(detail_url).body
        self.assertIn("Checking website reachability", checking)
        self.assertIn('http-equiv="refresh"', checking)
        self.assertEqual(load_engagement(self.app.output_root, engagement.id).assets, [])
        self.assertIn("Resolve the current asset check", self.post(assets_url, {"action": "add", "asset_type": "source_repo", "locator": "https://github.com/example/repo"}).body)
        release.set()
        self.wait_for_assessment_asset_check(engagement.id)
        failed = self.get(detail_url).body
        self.assertIn("The website did not respond", failed)
        self.assertIn("Retry check", failed)
        self.assertIn("Add anyway", failed)
        self.app.asset_checker = lambda kind, locator: (True, "Reachable")
        self.assertEqual(self.post(assets_url, {"action": "retry"}).location, detail_url)
        self.wait_for_assessment_asset_check(engagement.id)
        attached = load_engagement(self.app.output_root, engagement.id).assets
        self.assertEqual([(asset.type, asset.locator) for asset in attached], [("live_url", "https://app.example.test")])
        self.assertIn("already attached", self.post(assets_url, {"action": "add", "asset_type": "live_url", "locator": "https://app.example.test/"}).body)

    def test_existing_assessment_failed_check_can_add_anyway_or_dismiss(self) -> None:
        from mosh.engagements import create_engagement
        engagement = create_engagement(self.app.output_root, "Unchecked assets")
        assets_url = f"/assessments/{engagement.id}/assets"
        self.app.asset_checker = lambda kind, locator: (False, "Repository unavailable")
        self.post(assets_url, {"action": "add", "asset_type": "source_repo", "locator": "https://github.com/example/repo"})
        self.wait_for_assessment_asset_check(engagement.id)
        self.assertEqual(self.post(assets_url, {"action": "dismiss"}).status, 303)
        self.assertEqual(load_engagement(self.app.output_root, engagement.id).assets, [])
        self.post(assets_url, {"action": "add", "asset_type": "source_repo", "locator": "https://github.com/example/repo"})
        self.wait_for_assessment_asset_check(engagement.id)
        self.assertEqual(self.post(assets_url, {"action": "add-anyway"}).status, 303)
        attached = load_engagement(self.app.output_root, engagement.id).assets
        self.assertEqual([(asset.type, asset.locator) for asset in attached], [("source_repo", "https://github.com/example/repo")])

    def test_live_asset_headers_are_saved_hidden_editable_and_removed_with_asset(self) -> None:
        from mosh.engagement import load_engagement_file
        from mosh.engagements import attach_asset, create_engagement

        engagement = create_engagement(self.app.output_root, "Protected site")
        asset = attach_asset(self.app.output_root, engagement.id, "https://app.example.test", asset_type="live_url").asset
        detail_url = f"/assessments/{engagement.id}"
        headers_url = detail_url + "/request-headers"
        template_path = self.app.output_root / engagement.id / "engagement_template.yaml"
        self.assertIn("Request headers (optional)", self.get(detail_url).body)
        self.assertIn('name="header_value"', self.get(detail_url + f"?headers=new:{asset.id}").body)

        invalid = self.post(headers_url, {"action": "save", "asset_id": asset.id, "header_name": "X-Gateway"})
        self.assertIn("Enter a header name and value", invalid.body)
        self.assertFalse(template_path.exists())
        saved = self.post(headers_url, {"action": "save", "asset_id": asset.id, "header_name": "X-Gateway", "header_value": "fixture-secret"})
        self.assertIn("Request header saved", saved.body)
        self.assertNotIn("fixture-secret", saved.body)
        self.assertEqual(load_engagement_file(template_path)["asset_request_headers"][asset.id]["X-Gateway"], "fixture-secret")
        self.assertNotIn("fixture-secret", self.get(detail_url + f"?headers=edit:{asset.id}:X-Gateway").body)
        self.post(headers_url, {"action": "save", "asset_id": asset.id, "header_name": "Authorization", "header_value": "Bearer another-secret"})
        self.assertEqual(len(load_engagement_file(template_path)["asset_request_headers"][asset.id]), 2)
        blocked = self.post(headers_url, {"action": "save", "asset_id": asset.id, "header_name": "Bad Name", "header_value": "value"})
        self.assertIn("valid request header name", blocked.body)
        blocked = self.post(headers_url, {"action": "save", "asset_id": asset.id, "header_name": "X-Other", "header_value": "line\r\nInjected: yes"})
        self.assertIn("single-line", blocked.body)
        self.assertEqual(load_engagement_file(template_path)["asset_request_headers"][asset.id]["X-Gateway"], "fixture-secret")
        edited = self.post(headers_url, {"action": "save", "asset_id": asset.id, "previous_name": "X-Gateway", "header_name": "X-Gateway", "header_value": "replacement"})
        self.assertIn("Request header saved", edited.body)
        self.assertEqual(load_engagement_file(template_path)["asset_request_headers"][asset.id]["X-Gateway"], "replacement")
        self.assertIn("Remove X-Gateway?", self.post(headers_url, {"action": "remove", "asset_id": asset.id, "header_name": "X-Gateway"}).body)
        self.assertIn("Request header removed", self.post(headers_url, {"action": "remove", "asset_id": asset.id, "header_name": "X-Gateway", "confirmed": "yes"}).body)
        self.assertNotIn("X-Gateway", load_engagement_file(template_path)["asset_request_headers"][asset.id])
        self.post(detail_url + "/assets", {"action": "remove", "asset_id": asset.id})
        self.assertNotIn(asset.id, load_engagement_file(template_path)["asset_request_headers"])

    def test_live_asset_headers_cannot_change_during_run(self) -> None:
        from mosh.engagements import attach_asset, create_engagement

        engagement = create_engagement(self.app.output_root, "Protected site")
        asset = attach_asset(self.app.output_root, engagement.id, "https://app.example.test", asset_type="live_url").asset
        self.app.discovery_runs[engagement.id] = DiscoveryRun(asset_ids=[asset.id], current_asset_id=asset.id)
        response = self.post(f"/assessments/{engagement.id}/request-headers", {
            "action": "save", "asset_id": asset.id, "header_name": "X-Gateway", "header_value": "secret",
        })
        self.assertIn("Wait for the current stage", response.body)
        self.assertFalse((self.app.output_root / engagement.id / "engagement_template.yaml").exists())

    def test_flexible_hints_save_reload_and_feed_analysis_without_changing_permissions(self) -> None:
        from mosh.engagements import create_engagement
        from mosh.engagement import load_engagement_file, load_engagement_steer, build_minimal_engagement_template, write_engagement_template_mapping
        engagement = create_engagement(self.app.output_root, "Hint test")
        url = f"/assessments/{engagement.id}"
        path = self.app.output_root / engagement.id / "engagement_template.yaml"
        template = build_minimal_engagement_template()
        template["credentials"] = {"analyst": {"username": "user", "password": "existing-secret"}}
        write_engagement_template_mapping(path.parent, template, reject_candidate_credentials=False)
        initial = self.get(url).body
        self.assertNotIn("Assessment created ·", initial)
        self.assertIn("<h2>Assessment guidance (optional)</h2>", initial)
        self.assertIn("Mosh discovers each asset automatically from its content, so guidance is optional", initial)
        self.assertIn("note relevant account roles", initial)
        self.assertIn("Hints are leads, not confirmed findings; they guide analysis but do not provide test access", initial)
        self.assertIn("edit it or add hints as the assessment progresses", initial)
        self.assertIn("Hints are leads, not confirmed findings", initial)
        self.assertIn('href="' + url + '?hint=new"', initial)
        self.assertIn('name="title"', self.get(url + "?hint=new").body)
        first = {"title": "Our hypothesis: tenants", "text": "Accounts may share an organisation.\nPlease verify this.", "action": "save-hint"}
        result = self.post(url + "/guidance", first)
        self.assertIn("Hint saved", result.body)
        self.assertIn('<span class="hint-title">Our hypothesis: tenants</span>', result.body)
        self.assertIn('href="' + url + '?hint=edit:0"', result.body)
        self.assertIn('value="delete:0"', result.body)
        self.assertNotIn('name="title"', result.body)
        self.post(url + "/guidance", {"title": "<script>custom</script>", "text": "Look at /admin?x=1&y=2", "action": "save-hint"})
        self.assertIn("General guidance saved", self.post(url + "/guidance", {"notes": "Prioritise account boundaries", "action": "save-notes"}).body)
        loaded = load_engagement_file(path)
        self.assertEqual(loaded["hints"][0]["title"], first["title"])
        self.assertEqual(loaded["hints"][0]["text"], first["text"])
        self.assertIsNone(loaded["engagement"]["active_testing_allowed"])
        self.assertEqual(loaded["credentials"]["analyst"]["password"], "existing-secret")
        page = self.get(url).body
        self.assertEqual(page.count('class="hint-row"'), 2)
        self.assertIn("&lt;script&gt;custom&lt;/script&gt;", page)
        self.assertNotIn("<script>custom</script>", page)
        self.assertIn("Our hypothesis: tenants", load_engagement_steer(path))
        self.assertIn("context to verify", load_engagement_steer(path))
        self.assertIn('value="Our hypothesis: tenants"', self.get(url + "?hint=edit:0").body)
        edited = self.post(url + "/guidance", {"index": "0", "title": "Tenant isolation", "text": "Check cross-tenant access.", "action": "save-hint"})
        self.assertIn('<span class="hint-title">Tenant isolation</span>', edited.body)
        self.assertEqual(load_engagement_file(path)["hints"][0]["text"], "Check cross-tenant access.")
        deleted = self.post(url + "/guidance", {"action": "delete:1"})
        self.assertIn("Hint deleted", deleted.body)
        self.assertEqual(deleted.body.count('class="hint-row"'), 1)
        generated = build_minimal_engagement_template()
        generated["hints"] = [{"title": "Generated", "text": "Must not replace user hints"}]
        write_engagement_template_mapping(path.parent, generated)
        self.assertEqual(load_engagement_file(path)["hints"][0]["title"], "Tenant isolation")
        self.post(url + "/guidance", {"action": "delete:0"})
        self.post(url + "/guidance", {"notes": "", "action": "save-notes"})
        self.assertEqual(load_engagement_file(path)["hints"], [])
        self.assertEqual(load_engagement_steer(path), "")

    def test_scope_credentials_save_replace_and_remove_without_echoing_secrets(self) -> None:
        from mosh.crews.testing.crew import run_testing_preflight
        from mosh.engagement import build_minimal_engagement_template, load_engagement_file, write_engagement_template_mapping
        from mosh.engagements import create_engagement
        from mosh.web import TestingRun

        engagement = create_engagement(self.app.output_root, "Credential editor")
        detail_url = f"/assessments/{engagement.id}"
        credentials_url = detail_url + "/credentials"
        template_path = self.app.output_root / engagement.id / "engagement_template.yaml"
        template = build_minimal_engagement_template()
        template["engagement"].update(authorization_confirmed=True, active_testing_allowed=True)
        template["targets"]["production"] = {"app": "https://example.test"}
        template["credentials"] = {"admin": {"username": None, "password": None, "token": None}}
        write_engagement_template_mapping(template_path.parent, template)

        initial = self.get(detail_url).body
        self.assertIn("<h2>Test credentials</h2>", initial)
        self.assertIn("Needs credentials", initial)
        self.assertIn(f'href="{detail_url}?credential=edit:admin"', initial)
        new_editor = self.get(detail_url + "?credential=new").body
        self.assertIn('<select id="credential-role" name="role">', new_editor)
        self.assertIn('<option value="sales">Sales</option>', new_editor)
        invalid_role = self.post(credentials_url, {"action": "save", "role": "unknown", "token": "secret-unknown"}).body
        self.assertIn("Choose an account role", invalid_role)
        self.assertNotIn("secret-unknown", invalid_role)
        self.assertNotIn("unknown", load_engagement_file(template_path)["credentials"])
        added_role = self.post(credentials_url, {"action": "save", "role": "sales", "token": "sales-secret"}).body
        self.assertIn("Credentials saved for Sales", added_role)
        self.assertNotIn("sales-secret", added_role)
        self.assertEqual(load_engagement_file(template_path)["credentials"]["sales"]["token"], "sales-secret")
        editor = self.get(detail_url + "?credential=edit:admin").body
        self.assertIn('name="token" type="password"', editor)
        self.assertIn('name="password" type="password"', editor)
        self.assertNotIn("existing-secret", editor)
        invalid = self.post(credentials_url, {"action": "save", "role": "admin", "username": "user", "token": "secret-token-123"}).body
        self.assertIn("Enter a token or a username and password, not both", invalid)
        self.assertNotIn("secret-token-123", invalid)
        self.assertIsNone(load_engagement_file(template_path)["credentials"]["admin"]["token"])

        saved = self.post(credentials_url, {"action": "save", "role": "admin", "token": "secret-token-123"}).body
        self.assertIn("Credentials saved for Admin", saved)
        self.assertIn("Ready", saved)
        self.assertNotIn("secret-token-123", saved)
        self.assertEqual(load_engagement_file(template_path)["credentials"]["admin"]["token"], "secret-token-123")
        self.assertEqual(stat.S_IMODE(template_path.stat().st_mode), 0o600)
        self.assertNotIn("secret-token-123", self.get(detail_url + "?credential=edit:admin").body)
        plan = {"test_hypotheses": [{"id": "AUTH-001", "title": "Admin access", "requirements": ["Admin credentials"], "execution_mode": "live"}]}
        self.assertEqual([item["id"] for item in run_testing_preflight(plan, load_engagement_file(template_path)).ready], ["AUTH-001"])

        replaced = self.post(credentials_url, {"action": "save", "role": "admin", "username": "admin-user", "password": "new-password-456"}).body
        self.assertNotIn("new-password-456", replaced)
        current = load_engagement_file(template_path)["credentials"]["admin"]
        self.assertEqual((current["username"], current["password"], current["token"]), ("admin-user", "new-password-456", None))
        self.app.testing_runs[engagement.id] = TestingRun()
        blocked = self.post(credentials_url, {"action": "save", "role": "admin", "token": "blocked-secret"}).body
        self.assertIn("Wait for the current stage to finish", blocked)
        self.assertNotIn("blocked-secret", blocked)
        self.assertEqual(load_engagement_file(template_path)["credentials"]["admin"]["password"], "new-password-456")
        self.app.testing_runs.clear()

        confirmation = self.get(detail_url + "?credential=remove:admin").body
        self.assertIn("Remove credentials?", confirmation)
        self.assertIn("Local template backups may still contain earlier values", confirmation)
        self.assertNotIn("new-password-456", confirmation)
        self.assertIn("Remove credentials?", self.post(credentials_url, {"action": "remove", "role": "admin"}).body)
        self.assertIn("admin", load_engagement_file(template_path)["credentials"])
        removed = self.post(credentials_url, {"action": "remove", "role": "admin", "confirmed": "yes"}).body
        self.assertIn("Credentials removed for Admin", removed)
        self.assertNotIn("admin", load_engagement_file(template_path)["credentials"])
        backups = list((template_path.parent / "engagement_template.backups").glob("*.yaml"))
        self.assertTrue(backups)
        self.assertTrue(all(stat.S_IMODE(path.stat().st_mode) == 0o600 for path in backups))
        self.assertEqual(self.app.handle("POST", credentials_url, {"action": "save", "role": "admin", "token": "secret"}, {"Host": "127.0.0.1:8765"}).status, 403)

    def test_scope_test_setup_unblocks_planned_test_without_echoing_data(self) -> None:
        from mosh.engagement import load_engagement_file
        from mosh.engagements import attach_asset, create_engagement, engagement_dir, engagement_plan_dir
        from mosh.web import TestingRun

        engagement = create_engagement(self.app.output_root, "Test setup")
        attach_asset(self.app.output_root, engagement.id, "https://app.example.test")
        plan_dir = engagement_plan_dir(self.app.output_root, engagement.id)
        plan_dir.mkdir(parents=True)
        (plan_dir / "plan.md").write_text("# Plan", encoding="utf-8")
        plan = {"test_hypotheses": [{"id": "FORM-001", "title": "Check form", "requirements": ["Test email for form"], "execution_mode": "live"}]}
        (plan_dir / "memory.json").write_text(json.dumps([{"kind": "security_test_plan_final", "content": {"structured": plan}}]), encoding="utf-8")
        self.app._planning_current = lambda _: True
        detail_url = f"/assessments/{engagement.id}"
        setup_url = detail_url + "/test-setup"
        testing_url = detail_url + "/testing"
        template_path = engagement_dir(self.app.output_root, engagement.id) / "engagement_template.yaml"

        self.assertIn("<h2>Requested test information</h2>", self.get(detail_url).body)
        testing_page = self.get(testing_url).body
        self.assertIn("Planning identified 1 security test from the discovered assets", testing_page)
        self.assertIn("What do these statuses mean?", testing_page)
        self.assertIn("The test has run and a result has been produced for the current plan", testing_page)
        self.assertIn("Add required details", testing_page)
        self.assertIn("1 blocked", testing_page)
        self.assertIn("Confirm authorization under Permissions in Scope", testing_page)
        saved_permissions = self.post(setup_url, {
            "action": "save-permissions", "authorization_confirmed": "yes",
            "active_testing_allowed": "yes", "state_changing_tests_allowed": "no",
        }).body
        self.assertIn("Testing permissions saved", saved_permissions)
        self.assertTrue(load_engagement_file(template_path)["engagement"]["authorization_confirmed"])
        self.assertFalse(load_engagement_file(template_path)["engagement"]["state_changing_tests_allowed"])

        invalid_target = self.post(setup_url, {"action": "save-target", "target_name": "website", "target_url": "https://user:secret@app.example.test"}).body
        self.assertIn("without credentials", invalid_target)
        self.assertNotIn("user:secret", invalid_target)
        self.assertEqual(load_engagement_file(template_path)["targets"]["alternative"], {})
        self.assertIn("Target website saved", self.post(setup_url, {"action": "save-target", "target_name": "website", "target_url": "https://app.example.test"}).body)
        saved_data = self.post(setup_url, {"action": "save-data", "data_key": "email", "data_value": "test-person@example.test"}).body
        self.assertIn("Test email saved", saved_data)
        self.assertNotIn("test-person@example.test", saved_data)
        self.assertEqual(load_engagement_file(template_path)["safe_test_data"]["email"], "test-person@example.test")
        self.assertIn("1 ready · 0 blocked · 0 deferred", self.get(testing_url).body)

        self.post(setup_url, {"action": "save-data", "data_key": "customer_ids", "data_value": "customer-1\ncustomer-2"})
        self.assertEqual(load_engagement_file(template_path)["safe_test_data"]["customer_ids"], ["customer-1", "customer-2"])
        self.app.testing_runs[engagement.id] = TestingRun()
        blocked_edit = self.post(setup_url, {"action": "save-data", "data_key": "email", "data_value": "changed@example.test"}).body
        self.assertIn("Wait for the current stage to finish", blocked_edit)
        self.assertIn('<p class="error" role="alert">Wait for the current stage to finish before changing test setup.</p>', blocked_edit)
        self.assertEqual(load_engagement_file(template_path)["safe_test_data"]["email"], "test-person@example.test")

    def test_hint_editor_and_errors_do_not_overwrite_saved_guidance(self) -> None:
        from mosh.engagements import create_engagement
        engagement = create_engagement(self.app.output_root, "Draft test")
        detail_url = f"/assessments/{engagement.id}"
        url = detail_url + "/guidance"
        path = self.app.output_root / engagement.id / "engagement_template.yaml"
        self.assertIn('name="title"', self.get(detail_url + "?hint=new").body)
        self.assertFalse(path.exists())
        form = {"title": "Custom topic", "text": "Custom detail", "action": "save-hint"}
        self.post(url, form)
        original = path.read_bytes()
        failed = self.post(url, {**form, "text": ""})
        self.assertIn("Each hint needs", failed.body)
        self.assertIn('value="Custom topic"', failed.body)
        self.assertEqual(path.read_bytes(), original)
        too_large = self.post(url, {**form, "text": "x" * 24001})
        self.assertIn("24,000", too_large.body)
        self.assertEqual(path.read_bytes(), original)
        self.assertIn("Choose a hint to delete", self.post(url, {"action": "delete:4"}).body)
        self.assertIn("Choose a hint to edit", self.get(detail_url + "?hint=edit:4").body)
        self.assertEqual(path.read_bytes(), original)
        self.assertEqual(self.app.handle("POST", url, form, {"Host": "127.0.0.1:8765"}).status, 403)
        self.assertEqual(self.post("/assessments/eng_missing/guidance", form).status, 404)

    def test_new_assessment_button_has_plus_sign(self) -> None:
        self.assertIn('<span class="button-plus" aria-hidden="true">+</span>New assessment</button>', self.get("/").body)

    def test_wizard_creates_canonical_engagement_without_running_discovery(self) -> None:
        source = self.root / "example-api"
        source.mkdir()
        self.assertEqual(self.post("/new/start").location, "/new?step=details")
        self.assertEqual(self.post("/new/details", {"title": "Example app"}).location, "/new?step=assets")
        self.assertEqual(
            self.add_asset("live_url", "https://app.example.test/").location,
            "/new?step=assets",
        )
        self.assertEqual(
            self.add_asset("source_tree", str(source)).location,
            "/new?step=assets",
        )
        self.assertIn("https://app.example.test", self.get("/new?step=assets").body)
        self.assertEqual(self.post("/new/assets-next", {"authorized": "yes"}).location, "/new?step=review")
        review = self.get("/new?step=review").body
        self.assertIn("Example app", review)
        self.assertIn("Authorization confirmed", review)
        result = self.post("/new/finish")
        self.assertEqual(result.status, 303)
        engagement_id = result.location.rsplit("/", 1)[1]
        engagement = load_engagement(self.root / "report", engagement_id)
        self.assertEqual(engagement.title, "Example app")
        self.assertEqual([(asset.type, asset.locator) for asset in engagement.assets], [
            ("live_url", "https://app.example.test"),
            ("source_tree", str(source.resolve())),
        ])
        manifest = json.loads((self.root / "report" / engagement_id / "engagement.json").read_text())
        self.assertEqual(set(manifest["assets"][0]), {"id", "created_at"})
        self.assertFalse((self.root / "report" / engagement_id / "plan").exists())
        self.assertFalse((self.root / "report" / engagement_id / "assets" / engagement.assets[0].id / "discovery").exists())
        detail = self.get(result.location).body
        self.assertIn(f'href="{result.location}/discovery"', detail)
        self.assertNotIn("Continue to discovery", detail)
        self.assertIn(engagement_id, self.get("/").body)

    def test_invalid_duplicate_and_unauthorized_assets_do_not_create_an_engagement(self) -> None:
        self.post("/new/start")
        self.post("/new/details", {"title": "Audit"})
        invalid = self.add_asset("source_repo", "git@github.com:example/repo.git")
        self.assertIn("HTTPS", invalid.body)
        self.add_asset("live_url", "https://app.example.test")
        duplicate = self.add_asset("live_url", "https://app.example.test/")
        self.assertIn("already added", duplicate.body)
        not_authorized = self.post("/new/assets-next")
        self.assertIn("permission", not_authorized.body)
        self.assertEqual(self.get("/new?step=review").location, "/new?step=assets")
        self.assertEqual(list((self.root / "report").glob("eng_*/engagement.json")) if (self.root / "report").exists() else [], [])

    def test_remove_cancel_and_new_wizard_reset_draft(self) -> None:
        self.post("/new/start")
        self.post("/new/details", {"title": "First"})
        self.add_asset("live_url", "https://app.example.test")
        self.assertEqual(self.post("/new/remove", {"index": "0"}).location, "/new?step=assets")
        self.assertIn("Add at least one asset", self.get("/new?step=assets").body)
        self.assertEqual(self.post("/new/cancel").location, "/")
        self.assertEqual(self.get("/new?step=assets").location, "/new?step=details")
        self.post("/new/start")
        self.assertNotIn("First", self.get("/new?step=details").body)

    def test_asset_locator_is_escaped_when_rendered(self) -> None:
        self.post("/new/start")
        self.post("/new/details", {"title": "Escaping"})
        source = self.root / '<source onmouseover="alert(1)">'
        source.mkdir()
        self.add_asset("source_tree", str(source))
        page = self.get("/new?step=assets").body
        self.assertNotIn(str(source), page)
        self.assertIn("&lt;source", page)

    def test_folder_browser_selects_directory_and_rejects_other_paths(self) -> None:
        source = self.root / "Projects" / "example-app"
        source.mkdir(parents=True)
        (source.parent / "notes.txt").write_text("notes", encoding="utf-8")
        (self.root / "<assets>").mkdir()
        self.post("/new/start")
        self.post("/new/details", {"title": "Folders"})
        assets_page = self.get("/new?step=assets").body
        self.assertIn('class="asset-entry"', assets_page)
        self.assertIn('class="folder-choice"', assets_page)
        self.assertIn('class="secondary folder-picker" href="/new/folders"', assets_page)
        self.assertIn("Choose folder", assets_page)
        self.assertNotIn("Browse local folders", assets_page)
        stylesheet = self.get("/web.css").body
        self.assertIn('.asset-form select { height: 40px; }', stylesheet)
        self.assertIn('option[value="source_tree"]:checked', stylesheet)
        root_page = self.get("/new/folders").body
        self.assertIn("Projects", root_page)
        self.assertIn("&lt;assets&gt;", root_page)
        self.assertNotIn("<assets>", root_page)
        projects_page = self.get("/new/folders?path=" + quote(str(source.parent), safe="")).body
        self.assertIn("example-app", projects_page)
        self.assertNotIn("notes.txt", projects_page)
        self.assertEqual(self.post("/new/select-folder", {"path": str(source)}).location, "/new?step=assets")
        self.assertIn("Folder found", self.get("/new?step=assets").body)
        self.assertIn("already added", self.post("/new/select-folder", {"path": str(source)}).body)
        self.assertIn("cannot be opened", self.get("/new/folders?path=" + quote(str(self.root.parent), safe="")).body)
        self.assertIn("Choose an existing folder", self.post("/new/select-folder", {"path": str(self.root.parent)}).body)
        self.assertIn("Choose an existing folder", self.post("/new/select-folder").body)
        self.assertIn("Source path not found", self.add_asset("source_tree", str(self.root / "missing")).body)
        self.post("/new/assets-next", {"authorized": "yes"})
        self.assertIn("Folder found", self.get("/new?step=review").body)
        source.rmdir()
        review = self.get("/new?step=review").body
        self.assertIn("Folder missing", review)
        self.assertIn('disabled>Create assessment</button>', review)
        self.assertIn("Source path not found", self.post("/new/finish").body)

    def test_remote_asset_check_shows_progress_and_blocks_review_until_done(self) -> None:
        started = threading.Event()
        release = threading.Event()
        self.addCleanup(release.set)

        def check(kind: str, locator: str) -> tuple[bool, str]:
            started.set()
            release.wait(2)
            return True, "Reachable when added"

        self.app.asset_checker = check
        self.post("/new/start")
        self.post("/new/details", {"title": "Check"})
        self.assertEqual(self.post("/new/add", {"asset_type": "live_url", "locator": "https://app.example.test"}).location, "/new?step=assets")
        self.assertTrue(started.wait(1))
        page = self.get("/new?step=assets").body
        self.assertIn("Checking website reachability", page)
        self.assertIn('http-equiv="refresh"', page)
        self.assertIn("Resolve the current asset check", self.post("/new/assets-next", {"authorized": "yes"}).body)
        self.assertEqual(self.get("/new?step=review").location, "/new?step=assets")
        release.set()
        deadline = time.monotonic() + 2
        while self.app.assessment_draft.check_state == "checking" and time.monotonic() < deadline:
            time.sleep(.001)
        self.assertEqual(self.app.assessment_draft.check_state, "")
        self.post("/new/assets-next", {"authorized": "yes"})
        self.assertIn("Reachable when added", self.get("/new?step=review").body)

    def test_failed_remote_check_can_retry_or_add_unverified(self) -> None:
        self.app.asset_checker = lambda kind, locator: (False, "Could not reach this repository.")
        self.post("/new/start")
        self.post("/new/details", {"title": "Private repo"})
        self.add_asset("source_repo", "https://github.com/example/private")
        page = self.get("/new?step=assets").body
        self.assertIn("Could not reach this repository", page)
        self.assertIn("Retry check", page)
        self.assertIn("Add anyway", page)
        self.assertIn("Resolve the current asset check", self.post("/new/assets-next", {"authorized": "yes"}).body)
        self.app.asset_checker = lambda kind, locator: (True, "Repository reachable when added")
        self.post("/new/retry")
        deadline = time.monotonic() + 2
        while self.app.assessment_draft.check_state == "checking" and time.monotonic() < deadline:
            time.sleep(.001)
        self.assertIn("Repository reachable when added", self.get("/new?step=assets").body)

        self.app.asset_checker = lambda kind, locator: (False, "Could not reach this website.")
        self.add_asset("live_url", "https://offline.example.test")
        self.assertEqual(self.post("/new/add-anyway").location, "/new?step=assets")
        self.assertIn("Not verified", self.get("/new?step=assets").body)
        self.post("/new/assets-next", {"authorized": "yes"})
        self.assertIn("Not verified", self.get("/new?step=review").body)
        self.post("/new/add", {"asset_type": "live_url", "locator": "https://another-offline.example.test"})
        deadline = time.monotonic() + 2
        while self.app.assessment_draft.check_state == "checking" and time.monotonic() < deadline:
            time.sleep(.001)
        self.assertEqual(self.post("/new/dismiss-check").location, "/new?step=assets")
        self.assertNotIn("another-offline.example.test", self.get("/new?step=assets").body)

    def test_reachability_probe_uses_bounded_requests_without_following_links(self) -> None:
        class Response:
            status = 200

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return None

        opener = Mock()
        opener.open.side_effect = [HTTPError("https://app.example.test", 405, "", None, None), Response()]
        with patch("mosh.web.build_opener", return_value=opener):
            self.assertEqual(check_asset_reachability("live_url", "https://app.example.test"), (True, "Reachable when added"))
        requests = [call.args[0] for call in opener.open.call_args_list]
        self.assertEqual([request.get_method() for request in requests], ["HEAD", "GET"])
        self.assertEqual([call.kwargs["timeout"] for call in opener.open.call_args_list], [8, 8])
        self.assertEqual(requests[1].get_header("Range"), "bytes=0-0")

        with patch("mosh.web.build_opener") as opener_factory:
            opener_factory.return_value.open.side_effect = HTTPError("https://app.example.test", 401, "", None, None)
            self.assertEqual(check_asset_reachability("live_url", "https://app.example.test"), (True, "Reachable · access restricted"))
            opener_factory.return_value.open.side_effect = HTTPError("https://app.example.test", 302, "", None, None)
            self.assertEqual(check_asset_reachability("live_url", "https://app.example.test"), (True, "Redirects when added"))
            opener_factory.return_value.open.side_effect = HTTPError("https://app.example.test", 404, "", None, None)
            self.assertEqual(check_asset_reachability("live_url", "https://app.example.test"), (False, "Website returned HTTP 404."))

        with patch("mosh.web.subprocess.run") as run:
            run.return_value.returncode = 0
            self.assertEqual(check_asset_reachability("source_repo", "https://github.com/example/repo"), (True, "Repository reachable when added"))
            args = run.call_args.args[0]
            self.assertIn("ls-remote", args)
            self.assertIn("http.followRedirects=false", args)
            self.assertEqual(run.call_args.kwargs["timeout"], 8)
            self.assertEqual(run.call_args.kwargs["env"]["GIT_TERMINAL_PROMPT"], "0")
            run.return_value.returncode = 128
            self.assertFalse(check_asset_reachability("source_repo", "https://github.com/example/repo")[0])
            run.side_effect = subprocess.TimeoutExpired("git", 8)
            self.assertEqual(check_asset_reachability("source_repo", "https://github.com/example/repo"), (False, "Could not reach this repository."))


class WebScriptTests(unittest.TestCase):
    def test_live_logs_keep_polling_and_errors_become_dismissible_toasts(self) -> None:
        node = shutil.which("node")
        if node is None:
            self.skipTest("Node.js is unavailable")
        result = subprocess.run(
            [node, str(Path(__file__).with_name("web_poller_test.js")), str(Path(__file__).parents[1] / "src/mosh/web.js")],
            capture_output=True, text=True, timeout=10, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_local_tool_warning_updates_without_reloading(self) -> None:
        node = shutil.which("node")
        if node is None:
            self.skipTest("Node.js is unavailable")
        result = subprocess.run(
            [node, str(Path(__file__).with_name("web_tool_health_test.js")), str(Path(__file__).parents[1] / "src/mosh/web.js")],
            capture_output=True, text=True, timeout=10, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
