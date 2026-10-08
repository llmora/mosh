from __future__ import annotations

import json
import io
import os
import shutil
import stat
import subprocess
import tempfile
import threading
import time
import unittest
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import quote
from unittest.mock import Mock, patch

from dotenv import dotenv_values

from mosh.engagements import load_engagement
from mosh.web import WebApp, check_asset_reachability, check_provider_api, main


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


class WebAssessmentTests(WebTestCase):
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
        self.assertIn("<h1>Report</h1>", report.body)
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
        self.assertIn("<h1>Security test plan</h1>", report.body)
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
        self.assertIn("Wait for testing to finish", self.post(f"/assessments/{engagement.id}/guidance", {"action": "save-notes", "notes": "changed"}).body)
        self.assertIn("Starting unified security test execution", self.get(testing_url + "?view=logs").body)
        release.set()
        self.assertTrue(planning_refresh_started.wait(1))
        refreshing = self.get(testing_url).body
        self.assertIn("Tests finished. Updating discovery and the security test plan from test results.", refreshing)
        self.assertIn('aria-label="Testing, Updating plan" aria-current="step"', refreshing)
        self.assertIn("1 complete", refreshing)
        self.assertTrue(json.loads(self.get(testing_url + "/status").body)["poll"])
        finish_planning_refresh.set()
        self.wait_for_testing(engagement.id)
        complete = self.get(testing_url).body
        self.assertIn("Testing complete", complete)
        self.assertIn('aria-label="Testing, Complete" aria-current="step"', complete)
        self.assertIn("AUTH-001", complete)
        self.assertIn("1 complete", complete)
        self.assertIn("View report", complete)
        self.assertNotIn("Start testing", complete)
        self.assertFalse(json.loads(self.get(testing_url + "/status").body)["poll"])
        self.assertIn("<h1>Preflight</h1>", self.get(testing_url + "/preflight").body)
        report = self.get(testing_url + "/reports/AUTH-001")
        self.assertIn("<h1>Authorization result</h1>", report.body)
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
        self.assertIn("The plan or testing guidance changed after the last run", updated)
        self.assertIn("Run remaining tests", updated)

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
        orchestrator.return_value.run.assert_called_once_with("eng_12345678")

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


if __name__ == "__main__":
    unittest.main()
