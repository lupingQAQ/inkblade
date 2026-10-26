"""Plugin SDK contract tests.

Covers the promise made in `docs/PLUGIN-SDK.md`:

- every built-in `module.json` still parses through the SDK (legacy profile);
- an SDK-validated plugin directory is also loadable by the built-in registry;
- strict profile guardrails: unknown keys, key/directory match, entrypoint
  containment, write-level floor, research-only default, trust pinning;
- scaffold -> lint -> load -> run round trip, including result validation.
"""

import contextlib
import io
import json
import shutil
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from inkblade.core.registry import load_modules
from inkblade.sdk import (
    PluginError,
    PluginResultError,
    PluginUntrusted,
    encode_detail,
    lint_manifest,
    load_manifest,
    load_plugin,
    plugin_fingerprint,
    read_trust_store,
    run_plugin,
    scaffold_plugin,
    validate_manifest,
)
from inkblade.sdk import __main__ as sdk_cli

REPO = Path(__file__).resolve().parents[1]
PACKAGE = REPO / "inkblade"
MODULES = PACKAGE / "modules"
EXAMPLE = PACKAGE / "sdk" / "examples" / "hello-surface"


def minimal_manifest(**overrides):
    doc = {
        "key": "demo-plugin",
        "name": {"en": "Demo Plugin"},
        "series": "recon",
        "description": "demo",
        "min_level": "read-only",
        "writes": False,
        "requires": [],
        "params_schema": {"target": "target identifier"},
        "sdk": {"api": 1, "entrypoint": "run.py", "license": "Apache-2.0"},
    }
    doc.update(overrides)
    return doc


class TestBuiltinCompatibility(unittest.TestCase):
    def test_every_builtin_module_parses(self):
        dirs = sorted(p for p in MODULES.iterdir() if (p / "module.json").is_file())
        self.assertGreaterEqual(len(dirs), 200, "built-in module corpus shrank unexpectedly")
        failures = []
        for directory in dirs:
            try:
                load_manifest(directory, strict=False)
            except PluginError as exc:  # pragma: no cover - failure detail
                failures.append(f"{directory.name}: {exc}")
        self.assertEqual(failures, [], "\n".join(failures[:10]))

    def test_legacy_profile_tolerates_registry_specific_keys(self):
        manifest = validate_manifest(
            minimal_manifest(private=True, necessity="optional", combo_signature="x"),
            dir_name="demo-plugin",
            strict=False,
        )
        self.assertTrue(manifest.private)
        self.assertEqual(manifest.necessity, "optional")

    def test_strict_profile_requires_sdk_api(self):
        doc = minimal_manifest()
        doc.pop("sdk")
        with self.assertRaises(PluginError) as ctx:
            validate_manifest(doc, dir_name="demo-plugin")
        self.assertIn("sdk.api", str(ctx.exception))

    def test_ascii_aliases_normalise_to_canonical(self):
        manifest = validate_manifest(minimal_manifest(), dir_name="demo-plugin")
        self.assertEqual(manifest.series, "侦察")
        self.assertEqual(manifest.min_level, "只读侦察")
        self.assertEqual(manifest.to_module_json()["series"], "侦察")


class TestGuardrails(unittest.TestCase):
    def test_key_must_equal_directory(self):
        with self.assertRaises(PluginError) as ctx:
            validate_manifest(minimal_manifest(key="other-key"), dir_name="demo-plugin")
        self.assertIn("directory name", str(ctx.exception))

    def test_key_format(self):
        with self.assertRaises(PluginError):
            validate_manifest(minimal_manifest(key="Bad Key"), dir_name="Bad Key")

    def test_unknown_top_level_key_rejected(self):
        doc = minimal_manifest(surprise="nope")
        with self.assertRaises(PluginError) as ctx:
            validate_manifest(doc, dir_name="demo-plugin", strict=True)
        self.assertIn("unknown top-level keys", str(ctx.exception))

    def test_vendor_extension_prefix_allowed(self):
        manifest = validate_manifest(
            minimal_manifest(**{"x-acme-risk": "low"}), dir_name="demo-plugin"
        )
        self.assertEqual(manifest.key, "demo-plugin")

    def test_entrypoint_traversal_rejected(self):
        doc = minimal_manifest(sdk={"api": 1, "entrypoint": "../../evil.py"})
        with self.assertRaises(PluginError):
            validate_manifest(doc, dir_name="demo-plugin")

    def test_entrypoint_must_be_python(self):
        doc = minimal_manifest(sdk={"api": 1, "entrypoint": "run.sh"})
        with self.assertRaises(PluginError):
            validate_manifest(doc, dir_name="demo-plugin")

    def test_writes_require_exploit_level(self):
        doc = minimal_manifest(writes=True, min_level="probe")
        with self.assertRaises(PluginError) as ctx:
            validate_manifest(doc, dir_name="demo-plugin")
        self.assertIn("writes=true requires", str(ctx.exception))

    def test_writes_allowed_at_exploit_level(self):
        doc = minimal_manifest(writes=True, min_level="exploit",
                               required_surfaces=[{"type": "k8s-object",
                                                   "selector": "Pod"}])
        manifest = validate_manifest(doc, dir_name="demo-plugin")
        self.assertTrue(manifest.writes)
        self.assertEqual(manifest.required_surfaces[0]["type"], "k8s-object")

    def test_research_only_must_be_disabled(self):
        doc = minimal_manifest(research_only=True, default_enabled=True)
        with self.assertRaises(PluginError) as ctx:
            validate_manifest(doc, dir_name="demo-plugin")
        self.assertIn("default_enabled=false", str(ctx.exception))

    def test_params_schema_must_be_descriptions(self):
        with self.assertRaises(PluginError):
            validate_manifest(minimal_manifest(params_schema={"target": 3}),
                              dir_name="demo-plugin")

    def test_name_requires_english(self):
        with self.assertRaises(PluginError) as ctx:
            validate_manifest(minimal_manifest(name={"zh": "示例"}),
                              dir_name="demo-plugin")
        self.assertIn("name.en", str(ctx.exception))

    def test_manifest_size_limit(self):
        with TemporaryDirectory() as tmp:
            plugin = Path(tmp) / "big"
            plugin.mkdir()
            (plugin / "module.json").write_text(
                "{" + " " * (300 * 1024) + "}", encoding="utf-8"
            )
            with self.assertRaises(PluginError) as ctx:
                load_manifest(plugin)
            self.assertIn("too large", str(ctx.exception))


class TestExamplePlugin(unittest.TestCase):
    def test_example_lints_clean(self):
        report = lint_manifest(EXAMPLE)
        self.assertEqual(report["errors"], [])
        self.assertEqual(report["warnings"], [])
        self.assertEqual(report["series"], "侦察")
        self.assertFalse(report["writes"])

    def test_example_runs_and_writes_artifact(self):
        plugin = load_plugin(EXAMPLE, allow_unsigned=True)
        self.assertFalse(plugin.trusted)
        with TemporaryDirectory() as tmp:
            result = run_plugin(plugin, {"target": "http://127.0.0.1:8000", "note": "t"},
                                workspace=tmp, marker="TRIAL")
            self.assertEqual(len(result["findings"]), 1)
            self.assertEqual(result["findings"][0]["sev"], "info")
            self.assertTrue(result["artifacts"])
            artifact = Path(result["artifacts"][0])
            self.assertTrue(artifact.is_file())
            body = json.loads(artifact.read_text(encoding="utf-8"))
            self.assertEqual(body["marker"], "TRIAL")
            self.assertEqual(body["target"], "http://127.0.0.1:8000")
            self.assertTrue(Path(result["run_dir"]).is_dir())

    def test_example_is_registry_compatible(self):
        with TemporaryDirectory() as tmp:
            mods = Path(tmp) / "modules"
            mods.mkdir()
            shutil.copytree(EXAMPLE, mods / "hello-surface")
            loaded = load_modules(mods)
        self.assertIn("hello-surface", loaded)
        meta = loaded["hello-surface"]
        self.assertEqual(meta.name["en"], "Hello Surface (SDK reference plugin)")
        self.assertFalse(meta.writes)
        self.assertEqual(meta.min_level, "只读侦察")


class TestScaffoldAndRun(unittest.TestCase):
    def test_scaffold_lint_load_run(self):
        with TemporaryDirectory() as tmp:
            plugin_dir = scaffold_plugin(
                tmp, "acme-scope-check", title="ACME Scope Check",
                description="records the declared target", series="recon",
                min_level="read-only", publisher="ACME",
            )
            self.assertTrue((plugin_dir / "module.json").is_file())
            self.assertTrue((plugin_dir / "run.py").is_file())
            self.assertTrue((plugin_dir / "README.md").is_file())

            report = lint_manifest(plugin_dir)
            self.assertEqual(report["errors"], [])

            plugin = load_plugin(plugin_dir, allow_unsigned=True)
            result = run_plugin(plugin, {"target": "asset-17"}, workspace=Path(tmp) / "ws")
            self.assertEqual(len(result["findings"]), 1)
            self.assertIn("1 finding", result["summary"])

    def test_scaffold_refuses_overwrite(self):
        with TemporaryDirectory() as tmp:
            scaffold_plugin(tmp, "twice-plugin")
            with self.assertRaises(PluginError):
                scaffold_plugin(tmp, "twice-plugin")
            scaffold_plugin(tmp, "twice-plugin", force=True)

    def test_scaffold_rejects_write_below_exploit(self):
        with TemporaryDirectory() as tmp:
            with self.assertRaises(PluginError):
                scaffold_plugin(tmp, "bad-writer", writes=True, min_level="probe")

    def test_scaffold_accepts_canonical_names(self):
        with TemporaryDirectory() as tmp:
            plugin_dir = scaffold_plugin(tmp, "canonical-plugin", series="权限链",
                                         min_level="利用验证", writes=True)
            report = lint_manifest(plugin_dir)
            self.assertEqual(report["errors"], [])


class TestTrustAndFingerprint(unittest.TestCase):
    def test_fingerprint_deterministic_and_content_sensitive(self):
        first = plugin_fingerprint(EXAMPLE)
        second = plugin_fingerprint(EXAMPLE)
        self.assertEqual(first, second)
        self.assertEqual(len(first), 64)

        with TemporaryDirectory() as tmp:
            copy = Path(tmp) / "hello-surface"
            shutil.copytree(EXAMPLE, copy)
            (copy / "run.py").write_text(
                (copy / "run.py").read_text(encoding="utf-8") + "\n# tampered\n",
                encoding="utf-8",
            )
            self.assertNotEqual(plugin_fingerprint(copy), first)

    def test_unsigned_plugin_refused_without_opt_in(self):
        with self.assertRaises(PluginUntrusted) as ctx:
            load_plugin(EXAMPLE)
        self.assertIn("refusing to execute", str(ctx.exception))

    def test_trust_store_pin_accepts_matching_fingerprint(self):
        with TemporaryDirectory() as tmp:
            store_path = Path(tmp) / "trust.json"
            store_path.write_text(json.dumps({
                "version": 1,
                "plugins": {
                    "hello-surface": {
                        "fingerprint": plugin_fingerprint(EXAMPLE),
                        "publisher": "inkblade",
                        "allow": True,
                    }
                },
            }), encoding="utf-8")
            store = read_trust_store(store_path)
            plugin = load_plugin(EXAMPLE, trust_store=store_path)
        self.assertTrue(plugin.trusted)
        self.assertEqual(plugin.trust_source, "inkblade")
        self.assertEqual(store["plugins"]["hello-surface"]["allow"], True)

    def test_trust_store_rejects_changed_plugin(self):
        with TemporaryDirectory() as tmp:
            store = {"version": 1, "plugins": {
                "hello-surface": {"fingerprint": "0" * 64, "allow": True}}}
            with self.assertRaises(PluginUntrusted) as ctx:
                load_plugin(EXAMPLE, trust_store=store)
            self.assertIn("fingerprint mismatch", str(ctx.exception))

    def test_trust_store_can_block_plugin(self):
        with TemporaryDirectory() as tmp:
            store = {"version": 1, "plugins": {
                "hello-surface": {"allow": False}}}
            with self.assertRaises(PluginUntrusted) as ctx:
                load_plugin(EXAMPLE, trust_store=store, allow_unsigned=True)
            self.assertIn("blocked", str(ctx.exception))


class TestResultValidation(unittest.TestCase):
    def _plugin_with_body(self, tmp: Path, body: str):
        plugin_dir = scaffold_plugin(tmp, "result-shape")
        run_py = plugin_dir / "run.py"
        run_py.write_text(
            "def run(ctx, params):\n"
            + "".join("    " + line + "\n" for line in body.strip().splitlines()),
            encoding="utf-8",
        )
        return load_plugin(plugin_dir, allow_unsigned=True)

    def test_unknown_severity_rejected(self):
        with TemporaryDirectory() as tmp:
            plugin = self._plugin_with_body(tmp, """
return {"summary": "x", "findings": [{"sev": "urgent", "title": "t"}], "artifacts": []}
""")
            with self.assertRaises(PluginResultError) as ctx:
                run_plugin(plugin, {}, workspace=Path(tmp) / "ws")
            self.assertIn("sev must be one of", str(ctx.exception))

    def test_non_mapping_result_rejected(self):
        with TemporaryDirectory() as tmp:
            plugin = self._plugin_with_body(tmp, """
return ["not", "a", "result"]
""")
            with self.assertRaises(PluginResultError):
                run_plugin(plugin, {}, workspace=Path(tmp) / "ws")

    def test_encode_detail_is_json(self):
        self.assertEqual(encode_detail(None), "")
        self.assertEqual(encode_detail("plain"), "plain")
        self.assertEqual(json.loads(encode_detail({"a": 1})), {"a": 1})


class TestSdkCli(unittest.TestCase):
    def _run(self, argv):
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer), contextlib.redirect_stderr(buffer):
            code = sdk_cli.main(argv)
        return code, buffer.getvalue()

    def test_lint_ok(self):
        code, out = self._run(["lint", str(EXAMPLE)])
        self.assertEqual(code, 0, out)
        self.assertIn("ok   hello-surface", out)

    def test_lint_reports_failure(self):
        with TemporaryDirectory() as tmp:
            broken = Path(tmp) / "broken"
            broken.mkdir()
            (broken / "module.json").write_text("{}", encoding="utf-8")
            code, out = self._run(["lint", str(broken)])
        self.assertEqual(code, 1)
        self.assertIn("FAIL", out)

    def test_run_requires_trust_or_flag(self):
        code, out = self._run(["run", str(EXAMPLE), "--json"])
        self.assertEqual(code, 1)
        self.assertIn("refusing to execute", out)

    def test_run_with_allow_unsigned(self):
        with TemporaryDirectory() as tmp:
            code, out = self._run([
                "run", str(EXAMPLE), "--allow-unsigned", "--json",
                "--workspace", tmp,
                "--params-json", '{"target": "http://127.0.0.1:9000"}',
            ])
        self.assertEqual(code, 0, out)
        payload = json.loads(out)
        self.assertEqual(payload["plugin"]["key"], "hello-surface")

    def test_new_and_list(self):
        with TemporaryDirectory() as tmp:
            code, out = self._run(["new", "cli-made", "--dest", tmp])
            self.assertEqual(code, 0, out)
            code, listing = self._run(["list", tmp])
        self.assertEqual(code, 0)
        self.assertIn("cli-made", listing)

    def test_main_cli_delegates_sdk_subcommand(self):
        from inkblade import cli

        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer), contextlib.redirect_stderr(buffer):
            code = cli.main(["sdk", "lint", str(EXAMPLE)])
        self.assertEqual(code, 0, buffer.getvalue())
        self.assertIn("hello-surface", buffer.getvalue())


if __name__ == "__main__":
    unittest.main()
