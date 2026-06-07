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

    def test_engagement_template_refinement_can_be_disabled_from_env(self) -> None:
        with patch.dict(
            os.environ,
            {"APPSEC_HARNESS_REFINE_ENGAGEMENT_TEMPLATE_WITH_LLM": "false"},
            clear=True,
        ):
            config = AppConfig.from_env()

        self.assertFalse(config.refine_engagement_template_with_llm)


if __name__ == "__main__":
    unittest.main()
