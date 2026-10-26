import unittest

from inkblade.core.yamlish import dump


class TestYamlish(unittest.TestCase):
    def test_dump_policy(self):
        obj = {
            "apiVersion": "kyverno.io/v1",
            "kind": "ClusterPolicy",
            "spec": {
                "validationFailureAction": "Enforce",
                "rules": [
                    {"name": "deny-privileged", "match": {"resources": {"kinds": ["Pod"]}}}
                ],
            },
        }
        out = dump(obj)
        self.assertIn("apiVersion: kyverno.io/v1", out)
        self.assertIn("kind: ClusterPolicy", out)
        self.assertIn("validationFailureAction: Enforce", out)
        self.assertIn("rules:", out)
        self.assertIn("- name: deny-privileged", out)
        self.assertIn("  - name: deny-privileged", out)  # 嵌套列表缩进

    def test_special_strings(self):
        out = dump(
            {
                "a": "has: colon",
                "b": "#hash",
                "c": "line1\nline2",
                "d": None,
                "e": True,
                "f": 3.5,
                "g": ["x", 1],
            }
        )
        self.assertIn('"has: colon"', out)
        self.assertIn('"#hash"', out)
        self.assertIn("d: null", out)
        self.assertIn("e: true", out)
        self.assertIn("f: 3.5", out)
        self.assertIn("- x", out)
        self.assertIn("- 1", out)

    def test_top_level_list(self):
        out = dump([{"sig": "sigma-rule"}, {"sig": "another"}])
        self.assertIn("- sig: sigma-rule", out)
        self.assertIn("- sig: another", out)


if __name__ == "__main__":
    unittest.main()
