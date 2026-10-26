import os
os.environ.setdefault("LITELLM_LOCAL_MODEL_COST_MAP", "True")
os.environ.pop("LITELLM_MASTER_KEY", None)
os.environ.pop("DATABASE_URL", None)

import json
import socket
import threading
import time
import urllib.request
import urllib.error

import uvicorn
import litellm.proxy.proxy_server as ps


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


port = free_port()
config = uvicorn.Config(ps.app, host="127.0.0.1", port=port, log_level="warning")
server = uvicorn.Server(config)
t = threading.Thread(target=server.run, daemon=True)
t.start()
for _ in range(120):
    if server.started:
        break
    time.sleep(0.25)
print("started", server.started, "port", port)


def call(method, path, headers=None, body=None):
    url = f"http://127.0.0.1:{port}{path}"
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, r.read()[:600].decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read()[:600].decode("utf-8", "replace")
    except Exception as e:
        return "ERR", repr(e)


print("== no auth /v1/models ==")
print(call("GET", "/v1/models"))
print("== no auth /config/update ==")
print(call("POST", "/config/update", body={"general_settings": {"master_key": "sk-pwned"}}))
print("== no auth /key/list ==")
print(call("GET", "/key/list"))
print("== bogus bearer /v1/models ==")
print(call("GET", "/v1/models", headers={"Authorization": "Bearer sk-1234"}))
server.should_exit = True
t.join(timeout=15)
print("stopped")
