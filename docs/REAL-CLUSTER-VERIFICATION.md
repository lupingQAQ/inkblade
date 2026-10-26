# 真实 Kubernetes 集群验证 — QEMU TCG + Alpine + k3s

> 状态：**已达成真集群**（单节点 k3s，真实 apiserver / Service 网络 / NetworkPolicy 数据面）。
> 约束：不重启、不使用 WSL / Hyper-V / WHPX / KVM，纯 QEMU 软件仿真（`-accel tcg`）。
> 本文件只陈述实际观测到的结果；失败与弯路记录在第 6 节，未达成的部分不做推断。

## 0. 结论摘要

| 验证项 | 结果 | 证据 |
|---|---|---|
| 真实 K8s 集群 | 单节点 k3s `v1.36.5+k3s1`，node `k3s` **Ready**，containerd `2.3.4-k3s1.36` | `reports/samples/real-cluster/cluster-info.json`、`kubectl-nodes.txt` |
| Windows → 真 API | `kubectl --kubeconfig out/k3s.yaml get nodes` 成功（QEMU hostfwd `127.0.0.1:6445 → :6443`） | 同上 |
| 真 snapshot 跑 InkBlade 侦察 | 6/6 模块成功，**16 条 findings**（critical 11 / high 3 / medium 2） | `recon-findings.json`、`snapshot.json` |
| 真 Service 网络 | `mock_targets.py` 以 Pod 部署 + NodePort 30080；Windows 直连 HTTP 200（19 ms） | `service-probe.json` |
| InkBlade 模块打真 Service | `/plugins/list=200`、对照面 `/v1/models=401`、`/plugins/invoke=200` | `service-probe.json`（trace） |
| NetworkPolicy vs hostNetwork | 普通 Pod 被 default-deny 拒绝（connection refused），hostNetwork Pod 可达 → **bypass-confirmed** | `netpol-proof.json` |
| 规模声明 | **非生产规模**：单节点、2 GB 内存、无 HA、TCG 纯仿真 | 第 5 节 |

总墙钟：**约 45 分钟**（03:00 → 03:45，含 25 分钟排障；见第 6 节）。

## 1. 环境

| 项 | 值 |
|---|---|
| 宿主 | Windows 10/11 x64，Intel i5-10600KF（6C/12T），验证时可用内存 ~3.7 GB |
| 虚拟化 | 无 KVM / 无 Hyper-V / 无 WSL；QEMU `-accel tcg`，`-smp 4 -m 2048` |
| QEMU | `11.1.0 (v11.1.0-12130-ge470268ff4)`，qemu.weilnetz.de w64 包（197 MB，NSIS `/S /D=` 解到 `lab/qemu-k3s/qemu/`） |
| Guest OS | Alpine Linux `3.24.3`，kernel `6.18.58-0-virt`，ext4 + syslinux，磁盘 `disk/k3s.qcow2`（8 GB qcow2） |
| K8s | k3s `v1.36.5+k3s1`（`--disable traefik --disable metrics-server`），单节点 control-plane |
| kubectl | `v1.36.5`（与集群同 minor；1.37 的 Table 输出在 1.36 上异常，见 6.8） |

## 2. 构建步骤（脚本已交付）

所有脚本位于 `lab/qemu-k3s/`，下载物均在 `.gitignore` 中（不提交二进制）。

1. **QEMU**：`qemu-w64-setup-20260811.exe` → `qemu\qemu-system-x86_64.exe`，`--version` 校验通过。
2. **Alpine 介质**：官方 `alpine-virt-3.24.3-x86_64.iso`（70 MB）已下载；实际引导使用同版本 netboot 的
   `vmlinuz-virt` + `initramfs-virt`（原因见 6.1/6.2）。启动参数：
   ```
   -accel tcg -m 2048 -smp 4 -cpu max -display none
   -chardev socket,id=ser0,...,port=4555,server=on,wait=off,logfile=out/serial-install.log
   -serial chardev:ser0
   -netdev user,id=n0,hostfwd=tcp::2222-:22,hostfwd=tcp::6445-:6443,hostfwd=tcp::30080-:30080
   -device virtio-net-pci,netdev=n0 -device virtio-rng-pci
   -drive file=disk/k3s.qcow2,if=virtio,format=qcow2
   -kernel vmlinuz-virt -initrd initramfs-virt
   -append "console=ttyS0,115200 ip=dhcp alpine_repo=http://.../main modloop=http://.../netboot/modloop-virt"
   ```
3. **非交互安装**：`http/answers`（hostname k3s、eth0 dhcp、openssh、chrony、`DISKOPTS="-m sys /dev/vda"`）
   由 `setup-alpine.sh` 在 guest 内经 `10.0.2.2:8000` 拉取并执行；安装后注入 root SSH 公钥、把
   `console=ttyS0,115200` 写入 `/boot/extlinux.conf`、开 ttyS0 getty，然后 `poweroff`。
4. **磁盘启动**：`start-vm.ps1 -Mode run`；冷启动到 SSH 可用 **33 s**。
5. **k3s**：`install-k3s.sh`（apk 装 curl/iptables/conntrack、swapoff、`br_netfilter`/`overlay`、
   `INSTALL_K3S_SKIP_SELINUX_RUNTIME=1` + `INSTALL_K3S_EXEC="--disable traefik --disable metrics-server"`），
   等待 node Ready 后输出 `K3S-READY`。
6. **kubeconfig**：`scp -P 2222 /etc/rancher/k3s/k3s.yaml out/k3s.yaml`，`server` 改为
   `https://127.0.0.1:6445`；Windows kubectl 直接管理集群。

复现入口：`powershell -ExecutionPolicy Bypass -File lab/qemu-k3s/run-real-cluster-check.ps1`
（`-SkipInstall` / `-SkipK3s` 可续跑）。串口会话由 `vm_console.py` 驱动，`provision_alpine.py` /
`resume_provision.py` 负责答交互问题。

## 3. 真集群证据

### 3.1 真 API（不是 fixture）

```
NAME   STATUS   ROLES           AGE   VERSION        INTERNAL-IP   EXTERNAL-IP   OS-IMAGE             KERNEL-VERSION           CONTAINER-RUNTIME
k3s    Ready    control-plane   9m8s  v1.36.5+k3s1   10.0.2.15     <none>        Alpine Linux v3.24   6.18.58-0-virt (amd64)   containerd://2.3.4-k3s1.36
```

`cluster-info.json` 记录了 `kubectl version -o json`、`/readyz` 原文、node capacity/conditions、
kube-system Pod 状态与每次 kubectl 调用的 rc/耗时/输出。

### 3.2 真 snapshot → InkBlade 侦察模块

`collect_snapshot.py` 逐资源执行 `kubectl get <res> -o json`（无 fixture 合并），产出
`snapshot.json`（133 KB，`source: live-kubectl`）：

| 对象 | 数量 |
|---|---|
| pods | 5 |
| services | 3 |
| networkpolicies | 1 |
| roles / rolebindings | 7 / 8 |
| clusterroles / clusterrolebindings | 74 / 57 |
| serviceaccounts | 44 |
| nodes | 1 |
| ingresses | 0 |

`verify_real_cluster.py` 用该 snapshot 通过 `run_module()` 跑 6 个真实模块（ROE + EvidenceStore 全流程）：
`exposure-mapping`、`network-policy-coverage`、`rbac-mapping`、`framework-port-matching`、
`escape-primitives`、`observability-exposure`。结果 **6/6 ok，16 条 findings**，例如：

- `exposure-mapping` medium —— `inkblade-proof/mock-target` NodePort 暴露（8000）；
- `network-policy-coverage` high —— `kube-system` 的 2 个 Pod 未被任何入站策略选择；
- `rbac-mapping` critical —— `cluster-admin` / `system:kube-controller-manager` 等通配符 ClusterRole；
- `escape-primitives` medium —— `inkblade-proof/proof-hostnet` hostNetwork=true 共享宿主网络命名空间。

### 3.3 mock_targets 部署为 Pod + 真 Service 网络

`lab/mock_targets.py` 通过 ConfigMap 挂载进 Pod（源文件未修改）；因其默认绑定 `127.0.0.1`，
容器内启动前把模块级 `HOST` 改为 `0.0.0.0`（见 `manifests/20-mock-target.yaml` 注释）。
Service 为 `NodePort 8000:30080`，QEMU 预映射 `127.0.0.1:30080 → :30080`。

- Windows 侧 HTTP 探测：`HTTP 200`，连续三次 0.03 / 0.02 / 0.01 s，返回 25 条路由；
- InkBlade 模块 `vllm-plugin-auth-bypass`（writes=false，真实 HTTP）target=`http://127.0.0.1:30080`：
  - `GET /plugins/list` → **200**（无 api-key）
  - `GET /v1/models`（对照面）→ **401**
  - `POST /plugins/invoke` → **200**
  - 结论：mock target 的“插件路由绕过”在真实 Service 链路上可复现，trace 全文见 `service-probe.json`。

### 3.4 hostNetwork 绕过 NetworkPolicy（真数据面）

`manifests/10-default-deny.yaml` 在 `inkblade-proof` 建立 `podSelector:{}`、`Ingress+Egress` 全拒策略；
k3s 内置 network policy controller（kube-router v2.6.3-k3s1）已启动并下发规则。

| 源 Pod | 目标 | 结果 | wget 输出 |
|---|---|---|---|
| `proof-normal`（普通 Pod） | ClusterIP `10.43.41.60:8000` | **blocked** | `can't connect ... Connection refused` |
| `proof-normal` | Pod IP `10.42.0.13:8000` | **blocked** | `Connection refused` |
| `proof-hostnet`（hostNetwork=true） | ClusterIP | **connected** | rc=0 |
| `proof-hostnet` | Pod IP | **connected** | rc=0 |

判定：`bypass-confirmed` —— 策略确实生效（普通 Pod 全拒），hostNetwork Pod 不经过 CNI/veth
数据面，因此不受 NetworkPolicy 约束。策略生效后再从 Windows 打 NodePort 也不可达
（`service-probe.json.after_policy.reprobe_status = 0`）。

## 4. 证据清单

| 文件 | 内容 |
|---|---|
| `reports/samples/real-cluster/cluster-info.json` | kubectl 版本、/readyz、node 状态、API 延迟、kubectl 调用日志 |
| `reports/samples/real-cluster/snapshot.json` | 真实 `kubectl get -o json` 归一化快照（pods/services/netpol/rbac/nodes） |
| `reports/samples/real-cluster/recon-findings.json` | 6 模块运行记录 + 16 findings + 每步摘要/归档路径 |
| `reports/samples/real-cluster/service-deploy.json` | ConfigMap/Deployment/Service 应用与 rollout 记录 |
| `reports/samples/real-cluster/service-probe.json` | Windows HTTP + InkBlade 模块 trace（200/401/200） |
| `reports/samples/real-cluster/netpol-proof.json` | 4 条 wget 探测、策略 YAML、verdict |
| `reports/samples/real-cluster/verification-summary.json` | 全流程汇总 + TCG 声明 |
| `reports/samples/real-cluster/kubectl-nodes.txt` | 人读版 nodes/pods/svc/netpol |
| `docs/REAL-CLUSTER-VERIFICATION.md` | 本文件 |

EvidenceStore 原始运行目录（gitignored）：`lab/qemu-k3s/out/evidence-home/evidence/local-lab/real-cluster-*`
（含 `evidence.db`、步骤 tar.gz、manifest.sha256）。

## 5. QEMU TCG 性能与局限（如实声明）

| 指标 | 实测 |
|---|---|
| 已装系统冷启动 → SSH 可用 | **33 s** |
| k3s 安装（apk + 二进制下载 + 服务启动）→ node Ready | **≈ 3 min** |
| 首批镜像拉取（pause/coredns/local-path/python:3.12-alpine，经宿主代理） | **≈ 3 min** |
| `kubectl get nodes`（Windows，热路径，3 次） | 0.16 / 0.15 / 0.12 s |
| `/readyz`（服务端，首个 / 后续） | 1.25 s / 0.125 s、0.096 s |
| QEMU 进程 CPU 占用 | ~931 CPU-s / 约 12 min 运行 ≈ 1.3 核持续；RSS ≈ 2.5 GB |
| 干净 Alpine 安装（netboot 引导 → setup-alpine → poweroff） | ≈ 13 min（含包下载与 initramfs 生成） |

**局限（非生产规模）**：

1. 单节点、无 HA、无多节点调度/驱逐验证；`--disable traefik --disable metrics-server` 以保 2 GB 内存可用。
2. TCG 纯软件仿真，CPU 密集操作显著慢于原生；镜像拉取与压缩/解压是主要瓶颈。
3. NetworkPolicy 由 k3s 内置 controller（kube-router）执行，**不是** Calico/Cilium；hostNetwork
   绕过结论对该数据面成立，换 CNI 需重测（`lab/kind/run-proof.sh` 的 Calico 路径仍保留）。
4. Windows 只能经 NodePort（hostfwd）访问；ClusterIP 仅集群内可达，未做跨主机验证。
5. `mock_targets.py` 原本绑定 127.0.0.1，Pod 内通过运行时改 `HOST` 暴露，未改源文件；这是实验适配，
   不代表真实推理服务默认配置。
6. 镜像拉取依赖宿主本地代理（见 6.7）；无代理环境下需改用可达 mirror。
7. `snapshot.cani` 为空（未归一化 `kubectl auth can-i --list`），不影响本次 6 个模块结论。

## 6. 失败点与处置（精确记录，不掩盖）

1. **isolinux 串口输入不可靠**：Alpine ISO 在串口打印 `boot:`，但键入内核参数经常无响应（TCG 下
   bootloader 输入时序问题）；`-nographic` 直通 stdio 也无法稳定交互。→ 改为 `-kernel/-initrd` 直接
   引导同版本 `vmlinuz-virt/initramfs-virt`，串口从第一行内核日志起可用。
2. **initramfs 看不到 CD-ROM**：`/sys/block` 只有 `vda`，无 `sr0`（IDE/ATA 与 sr_mod 未加载），
   `alpine_dev=cdrom` 失败并落入 emergency shell。→ 改用 netboot 介质：`alpine_repo=` +
   `modloop=` 从 dl-cdn 拉取，引导成功（ISO 仍保留在目录中作为备用介质）。
3. **PowerShell 参数拆分**：`-append "console=... alpine_dev=cdrom"` 被 `Start-Process -ArgumentList`
   按空格拆开，QEMU 把 `alpine_dev=cdrom` 当成块设备报错。→ 对 append 值显式加引号。
4. **串口提示符匹配失败**：guest 在每个提示符后输出 DSR 序列 `ESC[6n`，`#\s*$` 永不匹配，导致驱动
   误判“仍在等登录”。→ `vm_console.py` 在匹配缓冲区剥离 ANSI（原始日志保留）。
5. **HTTP 404**：`setup-alpine.sh` 不在 HTTP 根目录（`http/`），guest 取不到。→ 编排脚本把
   `setup-alpine.sh`/`install-k3s.sh` 复制进 `http/` 再启动服务。
6. **setup-alpine 仍有交互问题**：root 密码（`inkblade`，弱口令提示后仍接受）、`Setup a user? [no]`、
   擦盘确认 `(y/n)`。→ `resume_provision.py` 按提示符应答，可断线续跑。
7. **guest 无法访问 Docker Hub**：`registry-1.docker.io` 被解析到 `31.13.73.9`（DNS 污染），
   拉取 pause 镜像 `i/o timeout`，所有 Pod 卡在 ContainerCreating。→ 宿主可直连 Docker Hub；
   在 guest 的 `/etc/rancher/k3s/k3s.env` 设置 `HTTP(S)_PROXY=http://10.0.2.2:7897`（QEMU 用户网
   关指向宿主本地代理）+ `NO_PROXY` 集群网段，重启 k3s 后镜像全部拉取成功。
   该依赖已写入本文档；无代理环境需替换为可达 registry mirror。
8. **kubectl 1.37 与 k3s 1.36 的 Table 输出异常**：`kubectl get nodes` 返回 “No resources found”，
   而 `get --raw /api/v1/nodes` 与 `-o json` 均有数据。→ 换用 `v1.36.5` kubectl，表格恢复正常。

以上均已修复；最终验证在修复后的路径上完成。

## 7. 复现

```powershell
# 一次性（下载 QEMU/Alpine/kubectl 见第 2 节；磁盘会重建）
powershell -ExecutionPolicy Bypass -File lab\qemu-k3s\run-real-cluster-check.ps1

# 已有磁盘与 k3s，仅重跑证据采集
powershell -ExecutionPolicy Bypass -File lab\qemu-k3s\run-real-cluster-check.ps1 -SkipInstall -SkipK3s

# 手动停 VM
powershell -ExecutionPolicy Bypass -File lab\qemu-k3s\start-vm.ps1 -Stop
```

验证脚本本身：`python lab/qemu-k3s/verify_real_cluster.py --kubectl lab/qemu-k3s/kubectl.exe
--kubeconfig lab/qemu-k3s/out/k3s.yaml --out reports/samples/real-cluster`。
回归测试：`python -m unittest tests.test_real_cluster_artifacts -v`（校验脚本/文档/证据结构）。

## 8. 与既有 KIND 方案的关系

`lab/kind/run-proof.sh` 面向 WSL + KIND + Calico；本机 WSL/Hyper-V 不可用（既有记录），因此该路径
无法执行。本文的 QEMU TCG 方案在**不依赖任何宿主虚拟化**的前提下提供了等价（单节点）验证：
真 apiserver、真 CNI、真 NetworkPolicy 数据面。KIND 脚本保留，两者结论口径一致
（普通 Pod blocked + hostNetwork connected ⇒ bypass-confirmed）。
