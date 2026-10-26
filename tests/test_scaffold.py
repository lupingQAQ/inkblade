import unittest


class TestScaffold(unittest.TestCase):
    def test_version(self):
        import inkblade
        self.assertEqual(inkblade.VERSION, "0.2.0")

    def test_core_namespace(self):
        import inkblade.core
        self.assertTrue(hasattr(inkblade.core, "__name__"))


if __name__ == "__main__":
    unittest.main()
