from __future__ import annotations

import os
import unittest
from unittest.mock import patch

from appsec_harness.config import AppConfig


class AppConfigTests(unittest.TestCase):
    def test_default_max_depth_is_three(self) -> None:
        with patch.dict(os.environ, {}, clear=True):
            config = AppConfig.from_env()

        self.assertEqual(config.max_depth, 3)

    def test_max_depth_can_be_overridden_from_env(self) -> None:
        with patch.dict(os.environ, {"APPSEC_HARNESS_MAX_DEPTH": "5"}, clear=True):
            config = AppConfig.from_env()

        self.assertEqual(config.max_depth, 5)


if __name__ == "__main__":
    unittest.main()
