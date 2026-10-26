"""Generate deterministic fixtures for the OSS scanner bench.

Nothing here is executed as a pickle.  Malicious artifacts are crafted with
``__reduce__`` (or by replacing ``archive/data.pkl`` in a torch zip) and are
only ever read as bytes by the scanners under test.
"""

from __future__ import annotations

import hashlib
import json
import os
import pickle
import socket
import subprocess
import zipfile
from pathlib import Path

import numpy as np
import torch

HERE = Path(__file__).resolve().parent
FIXTURES = HERE / "fixtures"
MODELS = FIXTURES / "models"
K8S = FIXTURES / "k8s"
LLM = FIXTURES / "llm"


# ---------------------------------------------------------------------------
# malicious reducer objects (never unpickled in this repo)
# ---------------------------------------------------------------------------
class EvilSystem:
    def __reduce__(self):
        return (os.system, ("echo trident-oss-bench-canary",))


class EvilEval:
    def __reduce__(self):
        return (eval, ("__import__('os').getcwd()",))


class EvilExec:
    def __reduce__(self):
        return (exec, ("print('trident-oss-bench-canary')",))


class EvilSubprocess:
    def __reduce__(self):
        return (subprocess.run, (["cmd", "/c", "echo", "trident-oss-bench-canary"],))


class EvilSocket:
    def __reduce__(self):
        return (socket.create_connection, (("127.0.0.1", 9),))


class EvilB64Eval:
    def __reduce__(self):
        # base64("print(1)") -- eval of a decoded payload, a common obfuscation.
        return (eval, ("__import__('base64').b64decode('cHJpbnQoMSk=')",))


class EvilImport:
    def __reduce__(self):
        return (__import__, ("os",))


def _dump(obj: object, path: Path, protocol: int = 4) -> None:
    path.write_bytes(pickle.dumps(obj, protocol=protocol))


def _write_benign_model() -> None:
    from lab.oss_bench.benign_model import SimpleModel

    model = SimpleModel(input_dim=4, hidden_dim=8)
    model.weights = [0.1, 0.2, 0.3, 0.4]
    _dump(model, MODELS / "benign_model.pkl")


def _write_torch_benign() -> Path:
    path = MODELS / "benign_tensor.pt"
    torch.save({"weights": torch.arange(8, dtype=torch.float32), "step": 3}, path)
    return path


def _write_torch_malicious(benign: Path) -> None:
    payload = pickle.dumps(EvilSystem(), protocol=4)
    target = MODELS / "evil_torch.pt"
    with zipfile.ZipFile(benign, "r") as zin, zipfile.ZipFile(target, "w", zipfile.ZIP_STORED) as zout:
        for item in zin.infolist():
            data = zin.read(item.filename)
            if item.filename.endswith("/data.pkl") or item.filename == "data.pkl":
                data = payload
            info = zipfile.ZipInfo(item.filename, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_STORED
            zout.writestr(info, data)


def build_models() -> dict:
    MODELS.mkdir(parents=True, exist_ok=True)
    # benign controls (5 binaries + 1 json)
    _dump({"name": "tiny", "layers": [1, 2, 3]}, MODELS / "benign_dict.pkl")
    _dump([1, 2, 3, 4], MODELS / "benign_list.pkl")
    _write_benign_model()
    np.save(MODELS / "benign_array.npy", np.arange(12, dtype=np.float32))
    torch_benign = _write_torch_benign()
    (MODELS / "benign_config.json").write_text('{"model": "tiny", "safe": true}\n', encoding="utf-8")

    # malicious: direct dangerous globals, obfuscation, and a torch container
    _dump(EvilSystem(), MODELS / "evil_os_system.pkl")
    _dump(EvilEval(), MODELS / "evil_eval.pkl")
    _dump(EvilExec(), MODELS / "evil_exec.pkl")
    _dump(EvilSubprocess(), MODELS / "evil_subprocess.pkl")
    _dump(EvilSocket(), MODELS / "evil_socket.pkl")
    _dump(EvilB64Eval(), MODELS / "evil_b64_eval.pkl")
    _dump(EvilImport(), MODELS / "evil_import.pkl")
    _write_torch_malicious(torch_benign)

    labels = {
        "benign_dict.pkl": (False, "pickle", "plain dict"),
        "benign_list.pkl": (False, "pickle", "plain list"),
        "benign_model.pkl": (False, "pickle", "benign user class instance (unknown global control)"),
        "benign_array.npy": (False, "numpy", "npy array (non-pickle control)"),
        "benign_tensor.pt": (False, "torch", "torch.save tensor + dict"),
        "benign_config.json": (False, "json", "non-serialization control"),
        "evil_os_system.pkl": (True, "pickle", "os.system via REDUCE"),
        "evil_eval.pkl": (True, "pickle", "builtins.eval via REDUCE"),
        "evil_exec.pkl": (True, "pickle", "builtins.exec via REDUCE"),
        "evil_subprocess.pkl": (True, "pickle", "subprocess.run via REDUCE"),
        "evil_socket.pkl": (True, "pickle", "socket.create_connection via REDUCE"),
        "evil_b64_eval.pkl": (True, "pickle", "eval(base64.b64decode(...)) obfuscation"),
        "evil_import.pkl": (True, "pickle", "builtins.__import__ via REDUCE"),
        "evil_torch.pt": (True, "torch", "torch zip with malicious archive/data.pkl"),
    }
    manifest = []
    for path in sorted(MODELS.iterdir()):
        if not path.is_file() or path.name == "manifest.json":
            continue
        malicious, kind, note = labels[path.name]
        manifest.append(
            {
                "file": path.name,
                "malicious": malicious,
                "kind": kind,
                "note": note,
                "bytes": path.stat().st_size,
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            }
        )
    (MODELS / "manifest.json").write_text(
        json.dumps(
            {
                "schema": "trident.oss-bench.fixtures/1",
                "total": len(manifest),
                "malicious": sum(1 for m in manifest if m["malicious"]),
                "benign": sum(1 for m in manifest if not m["malicious"]),
                "files": manifest,
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    return {"total": len(manifest), "malicious": sum(1 for m in manifest if m["malicious"])}


def build_k8s() -> dict:
    K8S.mkdir(parents=True, exist_ok=True)
    files = {
        "privileged-pod.yaml": """apiVersion: v1
kind: Pod
metadata:
  name: trainer-privileged
  namespace: ml
spec:
  hostNetwork: true
  hostPID: true
  hostIPC: true
  automountServiceAccountToken: true
  containers:
    - name: trainer
      image: pytorch/pytorch:latest
      securityContext:
        privileged: true
        runAsUser: 0
        allowPrivilegeEscalation: true
      volumeMounts:
        - name: host-root
          mountPath: /host
      resources: {}
  volumes:
    - name: host-root
      hostPath:
        path: /
""",
        "rbac-cluster-admin.yaml": """apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: trainer-cluster-admin
subjects:
  - kind: ServiceAccount
    name: trainer
    namespace: ml
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cluster-admin
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: wildcard-read
rules:
  - apiGroups: ["*"]
    resources: ["*"]
    verbs: ["*"]
""",
        "hardened-deployment.yaml": """apiVersion: apps/v1
kind: Deployment
metadata:
  name: infer-hardened
  namespace: ml
spec:
  replicas: 1
  selector:
    matchLabels:
      app: infer-hardened
  template:
    metadata:
      labels:
        app: infer-hardened
    spec:
      automountServiceAccountToken: false
      securityContext:
        runAsNonRoot: true
        runAsUser: 10001
        seccompProfile:
          type: RuntimeDefault
      containers:
        - name: server
          image: registry.example.com/infer@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop: ["ALL"]
          resources:
            limits:
              cpu: "1"
              memory: 1Gi
            requests:
              cpu: 100m
              memory: 128Mi
""",
        "exposed-service.yaml": """apiVersion: v1
kind: Service
metadata:
  name: ray-dashboard
  namespace: ml
  annotations:
    service.beta.kubernetes.io/aws-load-balancer-type: nlb
spec:
  type: LoadBalancer
  selector:
    app: ray-head
  ports:
    - port: 8265
      targetPort: 8265
      protocol: TCP
""",
        "mlflow-insecure.yaml": """apiVersion: apps/v1
kind: Deployment
metadata:
  name: mlflow
  namespace: ml
spec:
  selector:
    matchLabels:
      app: mlflow
  template:
    metadata:
      labels:
        app: mlflow
    spec:
      containers:
        - name: mlflow
          image: ghcr.io/mlflow/mlflow:v3.17.2
          args: ["mlflow", "server", "--host", "0.0.0.0", "--port", "5000"]
          env:
            - name: MLFLOW_TRACKING_URI
              value: "postgresql://mlflow:mlflow@postgres:5432/mlflow"
            - name: AWS_ACCESS_KEY_ID
              value: "AKIAIOSFODNN7EXAMPLE"
            - name: AWS_SECRET_ACCESS_KEY
              value: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
          ports:
            - containerPort: 5000
---
apiVersion: v1
kind: Service
metadata:
  name: mlflow
  namespace: ml
spec:
  type: LoadBalancer
  ports:
    - port: 5000
""",
        "jupyter-insecure.yaml": """apiVersion: apps/v1
kind: Deployment
metadata:
  name: jupyter
  namespace: ml
spec:
  selector:
    matchLabels:
      app: jupyter
  template:
    metadata:
      labels:
        app: jupyter
    spec:
      containers:
        - name: jupyter
          image: jupyter/scipy-notebook:latest
          command: ["start-notebook.sh"]
          args: ["--NotebookApp.token=''", "--NotebookApp.password=''", "--allow-root"]
          securityContext:
            runAsUser: 0
          ports:
            - containerPort: 8888
---
apiVersion: v1
kind: Service
metadata:
  name: jupyter
  namespace: ml
spec:
  type: NodePort
  ports:
    - port: 8888
      nodePort: 30888
""",
        "ray-insecure.yaml": """apiVersion: apps/v1
kind: Deployment
metadata:
  name: ray-head
  namespace: ml
spec:
  selector:
    matchLabels:
      app: ray-head
  template:
    metadata:
      labels:
        app: ray-head
    spec:
      containers:
        - name: ray
          image: rayproject/ray:latest
          command: ["ray", "start", "--head", "--host=0.0.0.0", "--dashboard-host=0.0.0.0", "--block"]
          securityContext:
            privileged: true
          ports:
            - containerPort: 8265
            - containerPort: 6379
            - containerPort: 10001
""",
        "Dockerfile": """FROM python:3.12
USER root
RUN pip install flask==0.12.2 pillow==9.0.0
ENV OPENAI_API_KEY=sk-proj-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
COPY . /app
CMD ["python", "/app/train.py"]
""",
        "requirements.txt": """flask==0.12.2
pillow==9.0.0
torch==2.5.0
""",
        ".env": """AWS_ACCESS_KEY_ID=AKIA3F7Q2Z5WJ4K6M8NP
AWS_SECRET_ACCESS_KEY=Q2f7R9mK4pL8sN3vT6xY1zA5
GITHUB_TOKEN=ghp_9fK2mQ7pR4sT8vW1xY3zA6bC0dE5fG8hJ2kL
""",
    }
    for name, text in files.items():
        (K8S / name).write_text(text, encoding="utf-8")
    return {"files": len(files), "seeded": ["privileged", "cluster-admin", "mlflow secrets", "jupyter no-auth", "ray privileged", "env file secrets"]}


def build_llm() -> dict:
    LLM.mkdir(parents=True, exist_ok=True)
    cases = [
        ("benign-1", "Summarize the training run in one sentence."),
        ("benign-2", "List two GPU metrics worth monitoring."),
        ("benign-3", "What does NCCL stand for?"),
        ("benign-4", "Explain gradient accumulation briefly."),
        ("benign-5", "Give a safe checkpoint naming convention."),
        ("benign-6", "Name one reason to pin container images."),
        ("benign-7", "What is a Kubernetes NetworkPolicy for?"),
        ("benign-8", "Describe a read-only root filesystem benefit."),
        ("benign-9", "Why rotate object-store credentials?"),
        ("benign-10", "What is the purpose of a seccomp profile?"),
        ("benign-11", "How can you limit Ray dashboard exposure?"),
        ("benign-12", "Suggest a least-privilege ServiceAccount rule."),
    ]
    (LLM / "cases.json").write_text(
        json.dumps(
            {
                "schema": "trident.oss-bench.llm-cases/1",
                "cases": [{"id": i, "prompt": p} for i, p in cases],
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    return {"cases": len(cases)}


def build_all() -> dict:
    models = build_models()
    k8s = build_k8s()
    llm = build_llm()
    summary = {"models": models, "k8s": k8s, "llm": llm}
    (FIXTURES / "manifest.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    return summary


if __name__ == "__main__":
    print(json.dumps(build_all(), indent=2))
