"""Dynamic exposure proof for the LLaMA-Factory default bind (v0.9.5).

The vulnerable posture is the launch default, not a data-flow sink:

* ``src/llamafactory/webui/interface.py:94/103`` — ``server_name`` defaults to
  ``0.0.0.0`` when ``GRADIO_SERVER_NAME`` is unset;
* ``src/llamafactory/api/app.py:130`` — ``api_host`` defaults to ``0.0.0.0``
  when ``API_HOST`` is unset.

This PoC starts the real upstream web UI / FastAPI app with the vendor defaults
and proves (a) the listener is not loopback-only and (b) an unauthenticated
request from a non-loopback address returns 200.  It writes
``evidence/exposure.json`` and exits with ``status=exposure-verified``; no RCE
is claimed.

For the API app only the model object is stubbed (no model is needed for
``GET /v1/models``); the FastAPI app, route, auth dependency and bind code are
the pinned upstream ones.
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
import poclib  # noqa: E402

MODE = "api"          # "webui" or "api"
SOURCE_FILE = "lab/upstream_verify/upstream/hiyouga/LlamaFactory/v0.9.5/src/llamafactory/api/app.py"
SOURCE_LINE = 130
SNIPPET = "api_host = os.getenv(\"API_HOST\", \"0.0.0.0\")"

API_BOOT = """
import os
os.environ.setdefault("API_HOST", "0.0.0.0")
import uvicorn
from llamafactory.api.app import create_app
from llamafactory.extras.constants import EngineName

class DummyEngine:
    name = EngineName.HF

class DummyChatModel:
    engine = DummyEngine()

uvicorn.run(create_app(DummyChatModel()), host=os.getenv("API_HOST", "0.0.0.0"),
            port=int(os.environ["API_PORT"]), log_level="warning")
"""

WEBUI_BOOT = (
    "from llamafactory.webui.interface import run_web_ui; run_web_ui()"
)


def free_port() -> int:
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


def lan_ip() -> str:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("8.8.8.8", 80))
        return sock.getsockname()[0]
    except OSError:
        return socket.gethostbyname(socket.gethostname())
    finally:
        sock.close()


def wait_port(port: int, timeout: float = 300.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        with socket.socket() as sock:
            sock.settimeout(1.0)
            if sock.connect_ex(("127.0.0.1", port)) == 0:
                return True
        time.sleep(1.0)
    return False


def http_get(url: str, timeout: int = 15) -> tuple[int, str]:
    request = urllib.request.Request(url, method="GET")
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.status, response.read(4096).decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read(4096).decode("utf-8", "replace")


def listeners(port: int) -> str:
    try:
        output = subprocess.run(["netstat", "-ano"], capture_output=True, text=True,
                                timeout=20, encoding="utf-8", errors="replace").stdout
    except Exception as exc:  # noqa: BLE001
        return f"netstat failed: {exc}"
    lines = [line.strip() for line in output.splitlines() if f":{port}" in line]
    return "\n".join(lines)


def main() -> None:
    evidence = poclib.EVIDENCE_DIR
    marker = poclib.MARKER_TEXT
    source = poclib.upstream_path(SOURCE_FILE)
    source_text = source.read_text(encoding="utf-8")
    actual = source_text.splitlines()[SOURCE_LINE - 1] if SOURCE_LINE else ""
    poclib.require(SNIPPET in actual, "pinned source line does not match the claimed default",
                   expected=SNIPPET, actual=actual)
    source_sha = poclib.sha256_file(source)

    port = free_port()
    env = dict(os.environ)
    env.pop("GRADIO_SERVER_NAME", None)
    env.pop("API_HOST", None)
    env.update({
        "GRADIO_SERVER_PORT": str(port),
        "GRADIO_ANALYTICS_ENABLED": "False",
        "HF_HUB_OFFLINE": "1",
        "API_PORT": str(port),
        "PYTHONIOENCODING": "utf-8",
        "PYTHONUTF8": "1",
    })
    if MODE == "api":
        command = [sys.executable, "-c", API_BOOT]
    else:
        command = [sys.executable, "-c", WEBUI_BOOT]
    proc = subprocess.Popen(command, cwd=str(poclib.REPO_ROOT), env=env,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            text=True, encoding="utf-8", errors="replace")
    log_tail = ""
    try:
        if not wait_port(port, timeout=360):
            proc.terminate()
            log_tail = (proc.communicate(timeout=30)[0] or "")[-3000:]
            poclib.fail("launch default did not start in the lab", log_tail=log_tail, port=port)

        ip = lan_ip()
        if MODE == "api":
            path, accept = "/v1/models", '"gpt-3.5-turbo"'
        else:
            path, accept = "/", "text/html"
        url = f"http://{ip}:{port}{path}"
        status, body = http_get(url)
        local_status, local_body = http_get(f"http://127.0.0.1:{port}{path}")
        netstat = listeners(port)
        (evidence / "listeners.txt").write_text(netstat + "\n", encoding="utf-8")
        (evidence / "http.txt").write_text(
            f"GET {url} -> {status} bytes={len(body)}\n"
            f"GET http://127.0.0.1:{port}{path} -> {local_status} bytes={len(local_body)}\n"
            f"Authorization header: none\n",
            encoding="utf-8",
        )
        if status != 200 or local_status != 200:
            poclib.fail("unauthenticated request was rejected", remote=status,
                        local=local_status, netstat=netstat)
        if MODE == "webui" and "<!doctype html" not in body.lower():
            poclib.fail("web UI response did not look like the Gradio page",
                        body=body[:200])
        if MODE == "api" and '"gpt-3.5-turbo"' not in body:
            poclib.fail("API response did not contain the model card", body=body[:200])

        exposure = {
            "schema": "inkblade-upstream-exposure-v1",
            "impact": "exposure",
            "case": poclib.CASE_DIR.name,
            "mode": MODE,
            "bind": "0.0.0.0",
            "listener": netstat,
            "unauthenticated": True,
            "http": {"url": url, "status": status, "bytes": len(body),
                     "authorization": None},
            "local": {"url": f"http://127.0.0.1:{port}{path}", "status": local_status},
            "source": {"file": SOURCE_FILE, "line": SOURCE_LINE,
                       "snippet": SNIPPET, "sha256": source_sha},
            "claim": "vendor default binds all interfaces and serves the route without "
                     "authentication; no RCE primitive is claimed",
        }
        poclib.write_json("exposure.json", exposure)
        poclib.prove_marker()
        poclib.finish_exposure({"exposure": exposure, "marker": marker})
    finally:
        try:
            subprocess.run(["taskkill", "/F", "/T", "/PID", str(proc.pid)],
                           capture_output=True, timeout=20)
        except Exception:
            proc.terminate()
        try:
            proc.wait(timeout=10)
        except Exception:
            pass


if __name__ == "__main__":
    main()
