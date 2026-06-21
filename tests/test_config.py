from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from mosh.config import AppConfig


class AppConfigTests(unittest.TestCase):
    def _missing_dotenv_path(self) -> Path:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        return Path(directory.name) / ".env"

    def test_default_max_depth_is_five(self) -> None:
        with patch.dict(os.environ, {}, clear=True):
            config = AppConfig.from_env(dotenv_path=self._missing_dotenv_path())

        self.assertEqual(config.max_depth, 5)

    def test_max_depth_can_be_overridden_from_env(self) -> None:
        with patch.dict(os.environ, {"MOSH_MAX_DEPTH": "7"}, clear=True):
            config = AppConfig.from_env(dotenv_path=self._missing_dotenv_path())

        self.assertEqual(config.max_depth, 7)

    def test_dirb_settings_can_be_overridden_from_env(self) -> None:
        with patch.dict(
            os.environ,
            {
                "MOSH_DIRB_WORDLIST": "/tmp/words.txt",
                "MOSH_DIRB_DOCKER_TIMEOUT": "45",
                "MOSH_CANDIDATE_FOLLOW_UP_LIMIT": "2",
                "MOSH_PLANNING_MAX_REVISIONS": "4",
            },
            clear=True,
        ):
            config = AppConfig.from_env(dotenv_path=self._missing_dotenv_path())

        self.assertEqual(config.dirb_wordlist, "/tmp/words.txt")
        self.assertEqual(config.dirb_docker_timeout, 45)
        self.assertEqual(config.candidate_follow_up_limit, 2)
        self.assertEqual(config.planning_max_revisions, 4)

    def test_engagement_template_refinement_defaults_to_enabled(self) -> None:
        with patch.dict(os.environ, {}, clear=True):
            config = AppConfig.from_env(dotenv_path=self._missing_dotenv_path())

        self.assertTrue(config.refine_engagement_template_with_llm)
        self.assertEqual(config.models.planning.engagement_refiner, "deepseek/deepseek-v4-flash")

    def test_config_can_be_loaded_from_dotenv(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            dotenv_path = Path(directory) / ".env"
            dotenv_path.write_text(
                "\n".join(
                    [
                        "# local mosh settings",
                        'DEEPSEEK_API_KEY="dotenv-deepseek-key"',
                        "OPENROUTER_API_KEY=dotenv-openrouter-key",
                        "MOSH_LLM_API_KEY=dotenv-custom-key",
                        "MOSH_LLM_BASE_URL=http://localhost:11434/v1",
                        "MOSH_MAX_DEPTH=8",
                        "MOSH_SECURITY_COMMAND_TIMEOUT=45",
                        "MOSH_REFINE_ENGAGEMENT_TEMPLATE_WITH_LLM=false",
                        "export MOSH_DIRB_WORDLIST=/tmp/dotenv-words.txt",
                    ]
                ),
                encoding="utf-8",
            )

            with patch.dict(os.environ, {}, clear=True):
                config = AppConfig.from_env(
                    config_path=Path(directory) / "missing.yaml",
                    dotenv_path=dotenv_path,
                )

        self.assertEqual(config.deepseek_api_key, "dotenv-deepseek-key")
        self.assertEqual(config.openrouter_api_key, "dotenv-openrouter-key")
        self.assertEqual(config.custom_llm_api_key, "dotenv-custom-key")
        self.assertEqual(config.custom_llm_base_url, "http://localhost:11434/v1")
        self.assertEqual(config.max_depth, 8)
        self.assertEqual(config.security_command_timeout, 45)
        self.assertEqual(config.dirb_wordlist, "/tmp/dotenv-words.txt")
        self.assertFalse(config.refine_engagement_template_with_llm)

    def test_shell_env_overrides_dotenv(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            dotenv_path = Path(directory) / ".env"
            dotenv_path.write_text(
                "\n".join(
                    [
                        "DEEPSEEK_API_KEY=dotenv-deepseek-key",
                        "OPENROUTER_API_KEY=dotenv-openrouter-key",
                        "MOSH_LLM_API_KEY=dotenv-custom-key",
                        "MOSH_MAX_DEPTH=8",
                    ]
                ),
                encoding="utf-8",
            )

            with patch.dict(
                os.environ,
                    {
                        "DEEPSEEK_API_KEY": "shell-deepseek-key",
                        "MOSH_LLM_API_KEY": "shell-custom-key",
                        "MOSH_MAX_DEPTH": "9",
                    },
                    clear=True,
            ):
                config = AppConfig.from_env(
                    config_path=Path(directory) / "missing.yaml",
                    dotenv_path=dotenv_path,
                )

        self.assertEqual(config.deepseek_api_key, "shell-deepseek-key")
        self.assertEqual(config.openrouter_api_key, "dotenv-openrouter-key")
        self.assertEqual(config.custom_llm_api_key, "shell-custom-key")
        self.assertEqual(config.max_depth, 9)

    def test_missing_dotenv_keeps_defaults(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with patch.dict(os.environ, {}, clear=True):
                config = AppConfig.from_env(
                    config_path=Path(directory) / "missing.yaml",
                    dotenv_path=Path(directory) / ".env",
                )

        self.assertIsNone(config.deepseek_api_key)
        self.assertEqual(config.max_depth, 5)

    def test_default_dotenv_path_uses_current_working_directory(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            previous_cwd = Path.cwd()
            Path(directory, ".env").write_text("MOSH_MAX_DEPTH=11\n", encoding="utf-8")
            try:
                os.chdir(directory)
                with patch.dict(os.environ, {}, clear=True):
                    config = AppConfig.from_env(config_path=Path(directory) / "missing.yaml")
            finally:
                os.chdir(previous_cwd)

        self.assertEqual(config.max_depth, 11)

    def test_models_can_be_loaded_from_mosh_yaml(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config_path = Path(directory) / "mosh.yaml"
            config_path.write_text(
                "\n".join(
                    [
                        "models:",
                        "  discovery_live:",
                        "    crawler: openai/gpt-5.2-mini",
                        "  discovery_source:",
                        "    mapper: openai/gpt-5.2-mini",
                        "    route_resolver: openai/gpt-5.2-mini",
                        "    component_mapper: openai/gpt-5.2",
                        "    gap_analyst: openai/gpt-5.2-mini",
                        "  planning:",
                        "    evidence_linker: openai/gpt-5.2-mini",
                        "    reviewer: openai/gpt-5.2",
                        "  testing:",
                        "    reviewer: 'anthropic/claude-sonnet-4.5'",
                        "  reporting:",
                        "    writer: openai/gpt-5.2-mini",
                    ]
                ),
                encoding="utf-8",
            )

            with patch.dict(os.environ, {}, clear=True):
                config = AppConfig.from_env(config_path=config_path, dotenv_path=Path(directory) / ".env")

        self.assertEqual(config.models.discovery_live.crawler, "openai/gpt-5.2-mini")
        self.assertEqual(config.models.discovery_source.mapper, "openai/gpt-5.2-mini")
        self.assertEqual(config.models.discovery_source.route_resolver, "openai/gpt-5.2-mini")
        self.assertEqual(config.models.discovery_source.component_mapper, "openai/gpt-5.2")
        self.assertEqual(config.models.discovery_source.gap_analyst, "openai/gpt-5.2-mini")
        self.assertEqual(config.models.planning.evidence_linker, "openai/gpt-5.2-mini")
        self.assertEqual(config.models.planning.reviewer, "openai/gpt-5.2")
        self.assertEqual(config.models.testing.reviewer, "anthropic/claude-sonnet-4.5")
        self.assertEqual(config.models.reporting.writer, "openai/gpt-5.2-mini")
        self.assertEqual(config.models.discovery_live.reporter, "deepseek/deepseek-v4-flash")
        self.assertEqual(config.models.discovery_source.reporter, "deepseek/deepseek-v4-flash")

    def test_missing_mosh_yaml_keeps_default_models(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with patch.dict(os.environ, {}, clear=True):
                config = AppConfig.from_env(
                    config_path=Path(directory) / "missing.yaml",
                    dotenv_path=Path(directory) / ".env",
                )

        self.assertEqual(config.models.discovery_live.crawler, "deepseek/deepseek-v4-flash")

    def test_unknown_model_key_in_mosh_yaml_fails_clearly(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config_path = Path(directory) / "mosh.yaml"
            config_path.write_text("models:\n  discovery_live:\n    crawlerr: openai/gpt-5.2\n", encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "Unknown model key `models.discovery_live.crawlerr`"):
                AppConfig.from_env(config_path=config_path, dotenv_path=Path(directory) / ".env")

    def test_unknown_discovery_source_model_key_fails_clearly(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config_path = Path(directory) / "mosh.yaml"
            config_path.write_text("models:\n  discovery_source:\n    crawlerr: openai/gpt-5.2\n", encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "Unknown model key `models.discovery_source.crawlerr`"):
                AppConfig.from_env(config_path=config_path, dotenv_path=Path(directory) / ".env")

    def test_deepseek_models_use_direct_deepseek_when_key_is_available(self) -> None:
        config = AppConfig(deepseek_api_key="deepseek-key")

        self.assertTrue(config.uses_direct_deepseek("deepseek/deepseek-v4-flash"))
        self.assertEqual(config.llm_api_key_for_model("deepseek/deepseek-v4-flash"), "deepseek-key")
        self.assertEqual(config.llm_api_key_name_for_model("deepseek/deepseek-v4-flash"), "DEEPSEEK_API_KEY")
        self.assertEqual(config.llm_provider_for_model("deepseek/deepseek-v4-flash"), "deepseek")
        self.assertEqual(config.llm_model_name("deepseek/deepseek-v4-flash"), "deepseek-v4-flash")
        self.assertIsNone(config.llm_base_url_for_model("deepseek/deepseek-v4-flash"))
        self.assertEqual(config.llm_model_name("openrouter/deepseek/deepseek-v4-flash"), "deepseek-v4-flash")

    def test_deepseek_models_fall_back_to_openrouter_without_deepseek_key(self) -> None:
        config = AppConfig(openrouter_api_key="openrouter-key")

        self.assertFalse(config.uses_direct_deepseek("deepseek/deepseek-v4-flash"))
        self.assertEqual(config.llm_api_key_for_model("deepseek/deepseek-v4-flash"), "openrouter-key")
        self.assertEqual(config.llm_model_name("deepseek/deepseek-v4-flash"), "deepseek/deepseek-v4-flash")
        self.assertEqual(config.llm_base_url_for_model("deepseek/deepseek-v4-flash"), "https://openrouter.ai/api/v1")

    def test_non_deepseek_models_always_use_openrouter(self) -> None:
        config = AppConfig(deepseek_api_key="deepseek-key")

        self.assertFalse(config.uses_direct_deepseek("openai/gpt-5.2"))
        self.assertEqual(config.llm_api_key_for_model("openai/gpt-5.2"), None)
        self.assertEqual(config.missing_llm_api_keys_for_models(["deepseek/deepseek-v4-flash", "openai/gpt-5.2"]), ["OPENROUTER_API_KEY"])

    def test_openrouter_model_name_strips_provider_routing_prefix(self) -> None:
        config = AppConfig(openrouter_api_key="openrouter-key")

        self.assertEqual(config.llm_model_name("openrouter/openai/gpt-5.2"), "openai/gpt-5.2")
        self.assertEqual(config.llm_model_name("openrouter/deepseek/deepseek-v4-flash"), "deepseek/deepseek-v4-flash")

    def test_custom_llm_endpoint_routes_models_through_openai_compatible_backend(self) -> None:
        config = AppConfig(
            openrouter_api_key="openrouter-key",
            deepseek_api_key="deepseek-key",
            custom_llm_api_key="custom-key",
            custom_llm_base_url="http://localhost:11434/v1",
        )

        self.assertTrue(config.uses_custom_llm("deepseek/deepseek-v4-flash"))
        self.assertFalse(config.uses_direct_deepseek("deepseek/deepseek-v4-flash"))
        self.assertEqual(config.llm_api_key_for_model("deepseek/deepseek-v4-flash"), "custom-key")
        self.assertEqual(config.llm_api_key_name_for_model("deepseek/deepseek-v4-flash"), "MOSH_LLM_API_KEY")
        self.assertEqual(config.llm_provider_for_model("deepseek/deepseek-v4-flash"), "openai")
        self.assertEqual(config.llm_model_name("deepseek/deepseek-v4-flash"), "deepseek/deepseek-v4-flash")
        self.assertEqual(config.llm_base_url_for_model("deepseek/deepseek-v4-flash"), "http://localhost:11434/v1")
        self.assertEqual(config.llm_model_name("custom/llama3.1"), "llama3.1")

    def test_custom_model_prefix_requires_custom_llm_settings(self) -> None:
        config = AppConfig(openrouter_api_key="openrouter-key")

        self.assertTrue(config.uses_custom_llm("custom/llama3.1"))
        self.assertEqual(config.llm_model_name("custom/llama3.1"), "llama3.1")
        self.assertEqual(config.llm_api_key_for_model("custom/llama3.1"), None)
        self.assertEqual(
            config.missing_llm_settings_for_models(["custom/llama3.1"]),
            ["MOSH_LLM_API_KEY", "MOSH_LLM_BASE_URL"],
        )

    def test_deepseek_api_key_is_loaded_from_env(self) -> None:
        with patch.dict(
            os.environ,
            {"DEEPSEEK_API_KEY": "deepseek-key"},
            clear=True,
        ):
            config = AppConfig.from_env(dotenv_path=self._missing_dotenv_path())

        self.assertEqual(config.deepseek_api_key, "deepseek-key")

    def test_engagement_template_refinement_can_be_disabled_from_env(self) -> None:
        with patch.dict(
            os.environ,
            {"MOSH_REFINE_ENGAGEMENT_TEMPLATE_WITH_LLM": "false"},
            clear=True,
        ):
            config = AppConfig.from_env(dotenv_path=self._missing_dotenv_path())

        self.assertFalse(config.refine_engagement_template_with_llm)

    def test_testing_settings_can_be_overridden_from_env(self) -> None:
        with patch.dict(
            os.environ,
            {
                "MOSH_SECURITY_TOOL_IMAGE": "security-tools:test",
                "MOSH_SECURITY_COMMAND_TIMEOUT": "45",
                "MOSH_SECURITY_EXECUTION_MAX_REVISIONS": "3",
            },
            clear=True,
        ):
            config = AppConfig.from_env(dotenv_path=self._missing_dotenv_path())

        self.assertEqual(config.security_tool_image, "security-tools:test")
        self.assertEqual(config.security_command_timeout, 45)
        self.assertEqual(config.security_execution_max_revisions, 3)


if __name__ == "__main__":
    unittest.main()
