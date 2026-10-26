"""终审 Important#1 + Minor#6：consent 工作区密钥 HMAC 签名 + 授权时间窗校验。

- 工作区密钥首次生成后落 ``workspace.json``（0600 语义），签名覆盖规范化 fields；
- consent.json 任何字段被改（含 level 提升）→ HMAC 校验失败 → 一切执行路径拒绝；
- 时间窗 start/end 过期 → ExecutionLocked；未声明/无法解析 → 不阻断（存量授权兼容）。
"""

import json
import time
import unittest
from datetime import date, datetime, timedelta
from pathlib import Path
from tempfile import TemporaryDirectory

from inkblade.core.evidence import EvidenceStore
from inkblade.core.roe import (
    ExecutionLocked,
    assert_execution_allowed,
    init_roe,
    in_scope,
    roe_status,
    window_status,
)


def _meta(min_level="只读侦察", writes=False):
    return {"key": "probe", "series": "侦察", "min_level": min_level, "writes": writes}


def _iso(d: date) -> str:
    return d.isoformat()


class TestConsentSignature(unittest.TestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.store = EvidenceStore(self.root, workspace="client-h")

    def tearDown(self):
        self.tmp.cleanup()

    def _consent_path(self) -> Path:
        return self.store.ws_dir / "consent.json"

    def _ws_path(self) -> Path:
        return self.store.ws_dir / "workspace.json"

    def test_workspace_key_generated_persisted_and_stable(self):
        init_roe(self.store, fields={"level": "只读侦察", "client": "甲"})
        cfg = json.loads(self._ws_path().read_text(encoding="utf-8"))
        key = cfg.get("consent_key")
        self.assertIsInstance(key, str)
        self.assertEqual(len(key), 64, "工作区密钥须为 32 字节 hex")
        int(key, 16)  # 合法十六进制
        # 再次读取/再签一次不得换钥
        init_roe(self.store, fields={"level": "主动探测", "client": "甲"})
        cfg2 = json.loads(self._ws_path().read_text(encoding="utf-8"))
        self.assertEqual(cfg2["consent_key"], key)
        # 0600 语义：POSIX 上其他用户位必须关闭（Windows 无 POSIX 位，跳过断言）
        import os

        if os.name == "posix":
            self.assertEqual(self._ws_path().stat().st_mode & 0o077, 0)

    def test_consent_carries_signature_and_verifies(self):
        init_roe(self.store, fields={"level": "只读侦察", "namespaces": ["train"]})
        doc = json.loads(self._consent_path().read_text(encoding="utf-8"))
        self.assertEqual(len(doc["hmac_sha256"]), 64)
        self.assertEqual(len(doc["sha256"]), 64)
        self.assertTrue(self.store.verify_consent(), "新签授权必须验签通过")
        self.assertEqual(roe_status(self.store), "complete")

    def test_tampered_level_fails_hard(self):
        init_roe(self.store, fields={"level": "只读侦察", "namespaces": ["train"],
                                     "cidrs": ["127.0.0.0/8"]})
        doc = json.loads(self._consent_path().read_text(encoding="utf-8"))
        doc["fields"]["level"] = "全影响演示"          # 提权篡改
        self._consent_path().write_text(
            json.dumps(doc, ensure_ascii=False, indent=2), encoding="utf-8")

        self.assertFalse(self.store.verify_consent(), "篡改后验签必须失败")
        self.assertEqual(roe_status(self.store), "tampered")
        with self.assertRaises(ExecutionLocked):
            assert_execution_allowed(self.store, _meta(min_level="全影响演示"))
        self.assertFalse(in_scope(self.store, target_ns="train", target_addr=None))

    def test_tamper_with_recomputed_sha_still_fails(self):
        """攻击者连 sha256 一起重算也过不了 HMAC（密钥不在文件里）。"""
        import hashlib

        init_roe(self.store, fields={"level": "只读侦察"})
        doc = json.loads(self._consent_path().read_text(encoding="utf-8"))
        doc["fields"]["level"] = "全影响演示"
        payload = json.dumps(doc["fields"], ensure_ascii=False, sort_keys=True,
                             separators=(",", ":"))
        doc["sha256"] = hashlib.sha256(payload.encode("utf-8")).hexdigest()
        self._consent_path().write_text(
            json.dumps(doc, ensure_ascii=False, indent=2), encoding="utf-8")
        self.assertFalse(self.store.verify_consent(), "仅重算 sha 不得绕过 HMAC")
        with self.assertRaises(ExecutionLocked):
            assert_execution_allowed(self.store, _meta())

    def test_key_replacement_detected(self):
        """工作区密钥被换掉（重签前）→ 旧 consent 签名失配。"""
        init_roe(self.store, fields={"level": "只读侦察"})
        cfg = json.loads(self._ws_path().read_text(encoding="utf-8"))
        cfg["consent_key"] = "ab" * 32
        self._ws_path().write_text(json.dumps(cfg), encoding="utf-8")
        self.assertEqual(roe_status(self.store), "tampered")


class TestConsentWindow(unittest.TestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.store = EvidenceStore(self.root, workspace="client-w")

    def tearDown(self):
        self.tmp.cleanup()

    def test_expired_window_locks_execution(self):
        init_roe(self.store, fields={
            "level": "只读侦察",
            "window": {"start": "2020-01-01", "end": "2020-01-02"},
        })
        self.assertEqual(roe_status(self.store), "complete")
        ok, reason = window_status({"window": {"start": "2020-01-01", "end": "2020-01-02"}})
        self.assertFalse(ok)
        self.assertIn("时间窗", reason)
        with self.assertRaises(ExecutionLocked) as cm:
            assert_execution_allowed(self.store, _meta())
        self.assertIn("时间窗", str(cm.exception))

    def test_future_window_locks_execution(self):
        start = date.today() + timedelta(days=30)
        end = start + timedelta(days=1)
        fields = {"level": "只读侦察", "window": {"start": _iso(start), "end": _iso(end)}}
        init_roe(self.store, fields=fields)
        ok, _ = window_status(fields)
        self.assertFalse(ok)
        with self.assertRaises(ExecutionLocked):
            assert_execution_allowed(self.store, _meta())

    def test_current_window_allows_execution(self):
        today = date.today()
        fields = {"level": "只读侦察",
                  "window": {"start": _iso(today - timedelta(days=1)),
                             "end": _iso(today + timedelta(days=1))}}
        init_roe(self.store, fields=fields)
        self.assertTrue(window_status(fields)[0])
        assert_execution_allowed(self.store, _meta())  # 不抛

    def test_single_day_string_window(self):
        """e2e 风格字符串窗：``2026-10-25 00:00 – 23:59（说明文字）``。"""
        today = date.today().isoformat()
        ok, _ = window_status({"window": f"{today} 00:00 – 23:59（验收实验室）"})
        self.assertTrue(ok, "当天字符串窗应放行")
        past = (date.today() - timedelta(days=400)).isoformat()
        ok, reason = window_status({"window": f"{past} 00:00 – 23:59（历史实验室）"})
        self.assertFalse(ok)
        self.assertIn("时间窗", reason)

    def test_two_date_string_window(self):
        today = date.today()
        text = f"{_iso(today - timedelta(days=2))} ~ {_iso(today + timedelta(days=2))}"
        self.assertTrue(window_status({"window": text})[0])
        old = f"2021-01-01 ~ 2021-01-31"
        self.assertFalse(window_status({"window": old})[0])

    def test_unparseable_or_missing_window_is_not_blocking(self):
        """存量授权里的自由文本窗（effects / qemu 标签）不阻断，避免假阴性。"""
        self.assertTrue(window_status({})[0])
        self.assertTrue(window_status({"window": ""})[0])
        self.assertTrue(window_status({"window": "effects-verification 20261025"})[0])
        self.assertTrue(window_status({"window": "inkblade qemu tcg lab run-7"})[0])

    def test_datetime_window_boundaries_respected(self):
        now = datetime.now()
        fields = {"window": {"start": (now - timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M:%S"),
                             "end": (now + timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M:%S")}}
        self.assertTrue(window_status(fields, now=time.time())[0])
        fields2 = {"window": {"start": (now - timedelta(hours=2)).strftime("%Y-%m-%dT%H:%M:%S"),
                              "end": (now - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%S")}}
        self.assertFalse(window_status(fields2, now=time.time())[0])


if __name__ == "__main__":
    unittest.main()
