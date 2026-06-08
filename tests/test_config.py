from __future__ import annotations

import os
import unittest
from unittest.mock import patch

from appsec_harness.config import AppConfig


class AppConfigTests(unittest.TestCase):
    def test_default_max_depth_is_five(self) -> None:
        with patch.dict(os.environ, {}, clear=True):
            config = AppConfig.from_env()

        self.assertEqual(config.max_depth, 5)

    def test_max_depth_can_be_overridden_from_env(self) -> None:
        with patch.dict(os.environ, {"APPSEC_HARNESS_MAX_DEPTH": "7"}, clear=True):
            config = AppConfig.from_env()

        self.assertEqual(config.max_depth, 7)

    def test_dirb_settings_can_be_overridden_from_env(self) -> None:
        with patch.dict(
            os.environ,
            {
                "APPSEC_HARNESS_DIRB_WORDLIST": "/tmp/words.txt",
                "APPSEC_HARNESS_DIRB_DOCKER_TIMEOUT": "45",
                "APPSEC_HARNESS_CANDIDATE_FOLLOW_UP_LIMIT": "2",
                "APPSEC_HARNESS_PLANNING_MAX_REVISIONS": "4",
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
        self.assertEqual(config.models.engagement_template_refiner, "deepseek/deepseek-v4-flash")

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
        self.assertEqual(config.llm_model_name("deepseek/deepseek-v4-flash"), "openrouter/deepseek/deepseek-v4-flash")

    def test_non_deepseek_models_always_use_openrouter(self) -> None:
        config = AppConfig(deepseek_api_key="deepseek-key")

        self.assertFalse(config.uses_direct_deepseek("openai/gpt-5.2"))
        self.assertEqual(config.llm_api_key_for_model("openai/gpt-5.2"), None)
        self.assertEqual(config.missing_llm_api_keys_for_models(["deepseek/deepseek-v4-flash", "openai/gpt-5.2"]), ["OPENROUTER_API_KEY"])

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
            {"APPSEC_HARNESS_REFINE_ENGAGEMENT_TEMPLATE_WITH_LLM": "false"},
            clear=True,
        ):
            config = AppConfig.from_env()

        self.assertFalse(config.refine_engagement_template_with_llm)

    def test_security_testing_settings_can_be_overridden_from_env(self) -> None:
        with patch.dict(
            os.environ,
            {
                "APPSEC_HARNESS_SECURITY_TOOL_IMAGE": "security-tools:test",
                "APPSEC_HARNESS_SECURITY_COMMAND_TIMEOUT": "45",
                "APPSEC_HARNESS_SECURITY_EXECUTION_MAX_REVISIONS": "3",
            },
            clear=True,
        ):
            config = AppConfig.from_env()

        self.assertEqual(config.security_tool_image, "security-tools:test")
        self.assertEqual(config.security_command_timeout, 45)
        self.assertEqual(config.security_execution_max_revisions, 3)


if __name__ == "__main__":
    unittest.main()
