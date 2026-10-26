"""环境变量前缀迁移：INKBLADE_* 优先，旧 TRIDENT_* 回退并发出弃用警告。"""

import os
import unittest
import warnings
from unittest import mock

from inkblade.core import env as envmod
from inkblade.core import explorer


class TestEnvCompat(unittest.TestCase):
    def setUp(self):
        envmod.reset_warnings()

    def test_new_prefix_wins(self):
        with mock.patch.dict(
            os.environ,
            {"INKBLADE_TEST_ENV_COMPAT": "new", "TRIDENT_TEST_ENV_COMPAT": "old"},
        ):
            with warnings.catch_warnings(record=True) as caught:
                warnings.simplefilter("always")
                self.assertEqual(envmod.getenv("TEST_ENV_COMPAT"), "new")
            self.assertFalse(
                [w for w in caught if issubclass(w.category, DeprecationWarning)]
            )

    def test_legacy_prefix_falls_back_and_warns(self):
        with mock.patch.dict(os.environ, {"TRIDENT_TEST_ENV_LEGACY": "old"}):
            with warnings.catch_warnings(record=True) as caught:
                warnings.simplefilter("always")
                self.assertEqual(envmod.getenv("TEST_ENV_LEGACY"), "old")
            self.assertTrue(
                any("TRIDENT_TEST_ENV_LEGACY" in str(w.message) for w in caught),
                "旧变量回退必须发出 DeprecationWarning",
            )

    def test_full_name_and_default(self):
        with mock.patch.dict(os.environ, {"INKBLADE_TEST_ENV_FULL": "x"}):
            self.assertEqual(envmod.getenv("INKBLADE_TEST_ENV_FULL"), "x")
        self.assertEqual(envmod.getenv("TEST_ENV_MISSING", "fallback"), "fallback")

    def test_lookup_keeps_custom_names_verbatim(self):
        with mock.patch.dict(os.environ, {"CUSTOM_KEY_ENV": "secret"}):
            self.assertEqual(envmod.lookup("CUSTOM_KEY_ENV"), "secret")
            self.assertIsNone(envmod.lookup("INKBLADE_CUSTOM_MISSING"))

    def test_lookup_maps_legacy_namespace_aliases(self):
        with mock.patch.dict(os.environ, {"TRIDENT_TEST_ENV_ALIAS": "old"}):
            self.assertEqual(envmod.lookup("INKBLADE_TEST_ENV_ALIAS"), "old")

    def test_explorer_accepts_legacy_llm_base_url(self):
        with mock.patch.dict(
            os.environ, {"TRIDENT_LLM_BASE_URL": "http://127.0.0.1:9/v1"}
        ):
            os.environ.pop("INKBLADE_LLM_BASE_URL", None)
            with warnings.catch_warnings(record=True):
                warnings.simplefilter("always")
                self.assertTrue(explorer.llm_available())


if __name__ == "__main__":
    unittest.main()
