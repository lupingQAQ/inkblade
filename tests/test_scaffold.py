import unittest


class TestScaffold(unittest.TestCase):
    def test_version(self):
        import trident
        self.assertEqual(trident.VERSION, "0.1.0")

    def test_core_namespace(self):
        import trident.core
        self.assertTrue(hasattr(trident.core, "__name__"))


if __name__ == "__main__":
    unittest.main()
