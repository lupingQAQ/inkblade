import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from lab.bench import perf_compare  # noqa: E402


class TestPerfCompare(unittest.TestCase):
    def test_stats_distribution(self):
        s = perf_compare.stats([1, 2, 3, 4, 5, 6, 7, 8, 9, 10])
        self.assertEqual(s["n"], 10)
        self.assertEqual(s["min_ms"], 1)
        self.assertEqual(s["median_ms"], 5.5)
        self.assertLessEqual(s["p95_ms"], s["max_ms"])

    def test_load_routes_and_offline_grid(self):
        routes = ROOT / "reports" / "samples" / "perf" / "grid" / "routes-artex.json"
        self.assertTrue(routes.exists())
        parsed = perf_compare.load_routes(routes)
        self.assertGreaterEqual(len(parsed), 200)
        out = ROOT / "reports" / "samples" / "perf" / "grid" / "offline-check.json"
        rc = perf_compare.main(["--routes", str(routes), "--offline", "--out", str(out)])
        self.assertEqual(rc, 0)
        data = json.loads(out.read_text(encoding="utf-8"))
        self.assertEqual(data["mode"], "offline")
        self.assertEqual(data["route_count"], len(parsed))
        self.assertTrue(all("skipped" in e for e in data["endpoints"]))

    def test_mutating_routes_are_skipped_not_faked(self):
        r = perf_compare.measure_endpoint("http://127.0.0.1:9", {"id": "POST /x", "method": "POST", "path": "/x"}, None, 1)
        self.assertEqual(r["skipped"], "mutating-method")


if __name__ == "__main__":
    unittest.main()

