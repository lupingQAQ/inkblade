import os
import tarfile
import io
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from trident.core.evidence import EvidenceStore, SCHEMA_TABLES


class TestEvidence(unittest.TestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.store = EvidenceStore(self.root, workspace="local-lab")

    def tearDown(self):
        self.tmp.cleanup()

    def test_three_layers_written(self):
        run = self.store.create_run("run-alpha")
        art = self.root / "artifact.txt"
        art.write_text("hello-trident", encoding="utf-8")
        ref = run.add_step(
            "probe-one",
            prompt_or_cmd="curl http://127.0.0.1:30000/health",
            env={"host": "lab", "user": "tester"},
            result_summary="200 ok, admin fail-open detected",
            artifacts=[art],
        )
        run_dir = self.root / "evidence" / "local-lab" / "run-alpha"
        # 归档层
        self.assertTrue((run_dir / "steps").exists())
        arch = run_dir / "steps" / "probe-one.tar.gz"
        self.assertTrue(arch.exists(), "archive layer missing")
        with tarfile.open(arch) as tf:
            names = tf.getnames()
        self.assertIn("artifact.txt", names)
        # 数据库层
        rows = run.query("SELECT step_key, result_summary FROM steps")
        self.assertEqual(rows[0][0], "probe-one")
        # 上下文摘要层
        ctx = run_dir / "context.jsonl.gz"
        self.assertTrue(ctx.exists())
        import gzip

        text = gzip.decompress(ctx.read_bytes()).decode("utf-8")
        self.assertIn("probe-one", text)
        self.assertIn(ref["archive"], text)

    def test_manifest_detects_tamper(self):
        run = self.store.create_run("run-beta")
        art = self.root / "a.txt"
        art.write_text("x" * 16, encoding="utf-8")
        run.add_step("s", "cmd", {}, "ok", artifacts=[art])
        run_dir = self.root / "evidence" / "local-lab" / "run-beta"
        self.assertTrue(self.store.verify_manifest("run-beta"))
        # 篡改：用同文件名重建内容不同的归档
        arch = run_dir / "steps" / "s.tar.gz"
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tf:
            data = b"tampered"
            ti = tarfile.TarInfo("a.txt")
            ti.size = len(data)
            tf.addfile(ti, io.BytesIO(data))
        arch.write_bytes(buf.getvalue())
        self.assertFalse(self.store.verify_manifest("run-beta"))

    def test_findings_roundtrip(self):
        run = self.store.create_run("run-gamma")
        run.add_step("p", "cmd", {}, "ok")
        run.add_finding(
            "p", sev="high", title="SGLang 管理面 fail-open",
            detail="30000 无 key 放行", evidence_path="steps/p.tar.gz",
        )
        got = run.findings
        self.assertEqual(len(got), 1)
        self.assertEqual(got[0]["severity"], "high")
        self.assertEqual(got[0]["title"], "SGLang 管理面 fail-open")

    def test_finalize_run_progressive_summary(self):
        run = self.store.create_run("run-delta")
        run.add_step("a", "c1", {}, "r1")
        run.add_step("b", "c2", {}, "r2")
        run.finalize_run()
        import gzip

        text = gzip.decompress(
            (self.root / "evidence" / "local-lab" / "run-delta" / "context.jsonl.gz").read_bytes()
        ).decode("utf-8")
        self.assertIn("summary", text)

    def test_forced_gzip_without_zstd(self):
        os.environ["TRIDENT_FORCE_NO_ZSTD"] = "1"
        try:
            run = self.store.create_run("run-eps")
            run.add_step("z", "cmd", {}, "ok")
            self.assertTrue(
                (self.root / "evidence" / "local-lab" / "run-eps" / "steps" / "z.tar.gz").exists()
            )
        finally:
            del os.environ["TRIDENT_FORCE_NO_ZSTD"]

    def test_schema_tables_exist(self):
        run = self.store.create_run("run-zeta")
        names = [r[0] for r in run.query("SELECT name FROM sqlite_master WHERE type='table'")]
        for t in SCHEMA_TABLES:
            self.assertIn(t, names)


if __name__ == "__main__":
    unittest.main()
