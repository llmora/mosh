from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from open_security_harness.config import AppConfig


class AppConfigTests(unittest.TestCase):
    def test_default_max_depth_is_five(self) -> None:
        with patch.dict(os.environ, {}, clear=True):
            config = AppConfig.from_env()

        self.assertEqual(config.max_depth, 5)

    def test_max_depth_can_be_overridden_from_env(self) -> None:
        with patch.dict(os.environ, {"OSH_MAX_DEPTH": "7"}, clear=True):
            config = AppConfig.from_env()

        self.assertEqual(config.max_depth, 7)

    def test_dirb_settings_can_be_overridden_from_env(self) -> None:
        with patch.dict(
            os.environ,
            {
                "OSH_DIRB_WORDLIST": "/tmp/words.txt",
                "OSH_DIRB_DOCKER_TIMEOUT": "45",
                "OSH_CANDIDATE_FOLLOW_UP_LIMIT": "2",
                "OSH_PLANNING_MAX_REVISIONS": "4",
            },
            clear=True,
        ):
            config = AppConfig.from_env()

        self.assertEqual(config.dirb_wordlist, "/tmp/words.txt")
        self.assertEqual(config.dirb_docker_timeout, 45)
        self.assertEqual(config.candidate_follow_up_limit, 2)
        self.assertEqual(config.planning_max_revisions, 4)

    def test_engagement_template_refinement_defaults_to_enabled(self) -> None:
        with patch.dict(os.environ, {}, clear=True):
            config = AppConfig.from_env()

        self.assertTrue(config.refine_engagement_template_with_llm)
        self.assertEqual(config.models.security_planning.engagement_refiner, "deepseek/deepseek-v4-flash")

    def test_models_can_be_loaded_from_osh_yaml(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config_path = Path(directory) / "osh.yaml"
            config_path.write_text(
                "\n".join(
                    [
                        "models:",
                        "  discovery:",
                        "    crawler: openai/gpt-5.2-mini",
                        "  security_planning:",
                        "    reviewer: openai/gpt-5.2",
                        "  security_testing:",
                        "    reviewer: 'anthropic/claude-sonnet-4.5'",
                    ]
                ),
                encoding="utf-8",
            )

            with patch.dict(os.environ, {}, clear=True):
                config = AppConfig.from_env(config_path=config_path)

        self.assertEqual(config.models.discovery.crawler, "openai/gpt-5.2-mini")
        self.assertEqual(config.models.security_planning.reviewer, "openai/gpt-5.2")
        self.assertEqual(config.models.security_testing.reviewer, "anthropic/claude-sonnet-4.5")
        self.assertEqual(config.models.discovery.reporter, "deepseek/deepseek-v4-flash")

    def test_missing_osh_yaml_keeps_default_models(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with patch.dict(os.environ, {}, clear=True):
                config = AppConfig.from_env(config_path=Path(directory) / "missing.yaml")

        self.assertEqual(config.models.discovery.crawler, "deepseek/deepseek-v4-flash")

    def test_unknown_model_key_in_osh_yaml_fails_clearly(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config_path = Path(directory) / "osh.yaml"
            config_path.write_text("models:\n  discovery:\n    crawlerr: openai/gpt-5.2\n", encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "Unknown model key `models.discovery.crawlerr`"):
                AppConfig.from_env(config_path=config_path)

    def test_deepseek_models_use_direct_deepseek_when_key_is_available(self) -> None:
        config = AppConfig(deepseek_api_key="deepseek-key")

        self.assertTrue(config.uses_direct_deepseek("deepseek/deepseek-v4-flash"))
        self.assertEqual(config.llm_api_key_for_model("deepseek/deepseek-v4-flash"), "deepseek-key")
        self.assertEqual(config.llm_api_key_name_for_model("deepseek/deepseek-v4-flash"), "DEEPSEEK_API_KEY")
        self.assertEqual(config.llm_provider_for_model("deepseek/deepseek-v4-flash"), "deepseek")
        self.assertEqual(config.llm_model_name("deepseek/deepseek-v4-flash"), "deepseek-v4-flash")
        self.assertEqual(config.llm_model_name("openrouter/deepseek/deepseek-v4-flash"), "deepseek-v4-flash")

    def test_deepseek_models_fall_back_to_openrouter_without_deepseek_key(self) -> None:
        config = AppConfig(openrouter_api_key="openrouter-key")

        self.assertFalse(config.uses_direct_deepseek("deepseek/deepseek-v4-flash"))
        self.assertEqual(config.llm_api_key_for_model("deepseek/deepseek-v4-flash"), "openrouter-key")
        self.assertEqual(config.llm_model_name("deepseek/deepseek-v4-flash"), "deepseek/deepseek-v4-flash")

    def test_non_deepseek_models_always_use_openrouter(self) -> None:
        config = AppConfig(deepseek_api_key="deepseek-key")

        self.assertFalse(config.uses_direct_deepseek("openai/gpt-5.2"))
        self.assertEqual(config.llm_api_key_for_model("openai/gpt-5.2"), None)
        self.assertEqual(config.missing_llm_api_keys_for_models(["deepseek/deepseek-v4-flash", "openai/gpt-5.2"]), ["OPENROUTER_API_KEY"])

    def test_openrouter_model_name_strips_provider_routing_prefix(self) -> None:
        config = AppConfig(openrouter_api_key="openrouter-key")

        self.assertEqual(config.llm_model_name("openrouter/openai/gpt-5.2"), "openai/gpt-5.2")
        self.assertEqual(config.llm_model_name("openrouter/deepseek/deepseek-v4-flash"), "deepseek/deepseek-v4-flash")

    def test_deepseek_api_key_is_loaded_from_env(self) -> None:
        with patch.dict(
            os.environ,
            {"DEEPSEEK_API_KEY": "deepseek-key"},
            clear=True,
        ):
            config = AppConfig.from_env()

        self.assertEqual(config.deepseek_api_key, "deepseek-key")

    def test_engagement_template_refinement_can_be_disabled_from_env(self) -> None:
        with patch.dict(
            os.environ,
            {"OSH_REFINE_ENGAGEMENT_TEMPLATE_WITH_LLM": "false"},
            clear=True,
        ):
            config = AppConfig.from_env()

        self.assertFalse(config.refine_engagement_template_with_llm)

    def test_security_testing_settings_can_be_overridden_from_env(self) -> None:
        with patch.dict(
            os.environ,
            {
                "OSH_SECURITY_TOOL_IMAGE": "security-tools:test",
                "OSH_SECURITY_COMMAND_TIMEOUT": "45",
                "OSH_SECURITY_EXECUTION_MAX_REVISIONS": "3",
            },
            clear=True,
        ):
            config = AppConfig.from_env()

        self.assertEqual(config.security_tool_image, "security-tools:test")
        self.assertEqual(config.security_command_timeout, 45)
        self.assertEqual(config.security_execution_max_revisions, 3)


if __name__ == "__main__":
    unittest.main()
