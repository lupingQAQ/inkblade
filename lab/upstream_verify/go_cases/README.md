# Go-service dynamic verification (QEMU k3s VM)

These cases were originally `static-only` because the Windows host has no Go
toolchain (and Windows Application Control blocks a downloaded Go compiler).
The QEMU TCG Alpine + k3s lab VM (`docs/REAL-CLUSTER-VERIFICATION.md`) removes
that blocker: Go 1.27.3 builds the pinned sources inside the guest, the binary
runs against the guest's own k3s API, and the proof is collected over SSH.

## Prerequisites

1. `lab/qemu-k3s/start-vm.ps1 -Mode run` (SSH forwarded to `127.0.0.1:2222`).
2. The gitignored lab key `lab/qemu-k3s/http/id_ed25519` (provisioned with the
   VM; `golab.py` fails closed when it is missing).
3. Build once inside the guest:

```sh
# on the guest
apk add git
curl -fsSL https://go.dev/dl/go1.27.3.linux-amd64.tar.gz | tar -C /usr/local -xzf -
export PATH=/usr/local/go/bin:$PATH GOPROXY=https://goproxy.cn,direct
mkdir -p /root/src /root/bin
cd /root/src
git clone --depth 1 --branch v0.20.3 https://github.com/kubernetes-sigs/kueue.git
(cd kueue/cmd/kueueviz/backend && GOMAXPROCS=4 go build -p 2 -o /root/bin/kueueviz .)
```

## Promoted cases

| Case | Pinned version | What is proven |
|---|---|---|
| `kueue-server-go-pprof-exposed-l30-regex` | kueue v0.20.3 (`66ff21115867ef4a80ced2a662d3665d86cb0d78`) | Default `KUEUEVIZ_AUTH_MODE=Disabled`; unauthenticated `GET /api/pod/<name>` returns Pod YAML (canary env), listener on `0.0.0.0:18080` reachable via eth0; pprof is loopback-only |
| `volcano-scheduler-server-go-pprof-exposed-l162-regex` | volcano v1.16.0 (`41f27d567fb5bdaf2cab01e1caaf48f7e266eefb`) | `--enable-pprof` mounts the full `/debug/pprof/*` set; unauthenticated profile fetch returns 200 |
| `juicefscsi-controller-manager-go-go-bind-all-l71-regex` | juicefs-csi v0.33.1 (`ab62a2106b6993f260b9f4c82f5dba51463e6748`) | Controller metrics/health listener binds `0.0.0.0:8084` and serves unauthenticated metrics |

## Unchanged cases

`cephcsi` (needs librbd/libceph + a Ceph cluster), `sonicrestapi` (swsscommon /
SONiC image), `gpuoperator` (GPU nodes + CRDs), and `dradriver` (the exec sink is
a fixed `nvidia-imex` argv, not attacker-controlled) stay `static-only`; the
manifest `static_blocker.reason` records the concrete missing prerequisite.

## Run

```powershell
python -m lab.upstream_verify --id kueue-server-go-pprof-exposed-l30-regex
python tools/verify-exploits.py
```
