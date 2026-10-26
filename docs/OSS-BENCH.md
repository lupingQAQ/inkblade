# 开源工具性能实测（OSS-BENCH）

> 生成：2026-10-26 · 数据：[reports/samples/oss-bench/summary.json](../reports/samples/oss-bench/summary.json)（schema `trident.oss-bench/1`）·
> 原始证据：`reports/samples/oss-bench/raw/` · 工具全景：[OSS-ML-CLUSTER-TOOLS.md](OSS-ML-CLUSTER-TOOLS.md)

## 1. 方法

- **同 fixture / 同目标**：模型扫描器共用同一批 14 个文件（8 恶意 / 6 良性，`lab/oss_bench/fixtures/models/manifest.json` 为判定基准，逐文件 sha256 锚定）；K8s 扫描器共用 `fixtures/k8s`（10 文件、6 类种子发现）与 QEMU TCG k3s v1.36.5+k3s1 真集群；LLM 评测共用本地 echo mock（12 用例，零外部 API）。
- **每项跑 3 轮取中位数**（kube-bench 在 TCG guest 内 3 轮，秒级分辨率）；峰值 RSS 以 psutil 25ms 采样进程树；`raw/` 保存各工具原始输出（JSON/日志/journal）。
- **检出统计口径**：恶意文件被标警=TP、漏报=FN、良性被标警=FP；解析不了的文件按工具语义归类（fickling rc=2 视为不支持，其中恶意件计入 FN、良性件剔除防止虚高 TN）。
- 复现：`D:\llm-audit-2026-10\.slim\oss-bench-venv\Scripts\python.exe lab/oss_bench/run_bench.py --out reports/samples/oss-bench --runs 3`；venv 内含被测工具（kube-hunter/fickling/modelscan/picklescan/chaostoolkit），trivy/toxiproxy 为官方 release 二进制，promptfoo 为 npm 安装。

**环境**：Windows 11 宿主（python 3.12，QEMU TCG 6 vCPU Alpine 3.24 guest 承载 k3s）。TCG guest 计时带模拟放大，跨类对比只看同环境数字。

## 2. 结果总表（中位数）

| 工具 | 版本 | 目标 | 耗时 | 峰值 RSS | 输出量 | 关键结果 |
|---|---|---|---|---|---|---|
| kube-bench | 0.16.0 | QEMU TCG k3s v1.36.5（guest 内 docker，KUBECONFIG 自动检测） | 58.00s（guest 秒级分辨率） | 未采样（guest 容器 `--rm`；镜像 227MB） | 71,280 B JSON | 自动选中 **k3s-cis-1.9**：PASS 18 / FAIL 3 / WARN 33 / INFO 5（2 controls） |
| kube-hunter | 0.6.8 | mock 集群（:6443 匿名读 API + :10255 只读 kubelet + 特权 Pod） | 10.08s | 107,880 kB | 4,341 B | 8 findings（4 high/3 medium/1 low），**种子 2/2 命中**（特权容器 + 只读 kubelet） |
| trivy-fs | 0.76.1 | fixtures/k8s（10 文件 6 类种子） | 0.88s | 148,176 kB | 429,537 B | 86 misconfig（31 类）+2 secret 规则；**种子 6/6 类命中** |
| trivy-k8s | 0.76.1 | k3s 全集群快照（kubectl 20 类资源 -A，227 对象；dump 另计 0.60s） | 3.90s | 231,656 kB | 1,169,499 B | 247 misconfig（33 类；Top: KSV-0048×38/KSV-0118×19/KSV-0056×14） |
| modelscan | 0.8.8 | fixtures/models（14 件，8 恶意/6 良性） | 0.28s | 38,748 kB | 2,688 B | **TP 8/8，FP 0，precision/recall=1.0**（rc=2=有问题退出码） |
| fickling | 0.1.12 | 同上（逐文件 CLI ×14） | 1.54s（含 14 次解释器启动） | 22,196 kB（单进程峰值） | 6,891 B | TP 7/8（**torch zip 不支持→FN**）、FP 1（未知全局类保守判 LIKELY_UNSAFE）、3 件不支持（npy/json/pt） |
| picklescan | 1.0.5 | 同上（目录扫描） | 0.15s | 25,544 kB | 1,083 B | TP 7/8（**漏 `__import__`**）、FP 0；rc 恒 0（无 --strict 语义） |
| promptfoo | 0.125.1 | 12 用例→本地 echo provider | 2.33s（热启；冷启另计 ≈48 s） | 277,056 kB | 80,473 B | 断言 **12/12 通过**（pass_rate 1.0） |
| toxiproxy | 2.13.0 | 代理→mock 靶场；latency 200ms + timeout 0 toxic | 3.13s（含对照采样全流程） | 15,464 kB | 210 B | **注入 200ms → 客户端实测 +200.7ms**（基线 2.1ms→202.8ms）；timeout toxic 连接断开（RemoteDisconnected） |
| Chaos Toolkit | 1.21.4 | 本地进程实验（稳态探针→taskkill→复检） | 5.63s | 64,596 kB | 54,339 B | **3/3 检测到稳态破坏**（deviated=true；rc=1 为预期退出码；journal.json 留证） |

## 3. 逐项发现与工具行为记录（实测得到的行为事实）

- **modelscan 是本轮参考扫描器**：14 件里唯一全检出零误报，且唯一正确扫入 torch zip 内层 data.pkl（扫描 12 件=json/npy 不在其格式表）。
- **fickling**：CLI 仅单文件（总耗时含 14 次解释器启动，与批量工具对比需注意）；`--json-output` 对已存在文件**追加写**（二次运行产生拼接 JSON，bench 已规避并记录）；torch zip/npy/json 解析不了（rc=2）；对未知全局类（benign_model.pkl）保守判 LIKELY_UNSAFE——设计如此（保守安全），但在 ML 生态全是自定义类时会高误报。
- **picklescan**：最快（0.15s）但**漏检 `__import__('os')`**（evil_import.pkl 无 FOUND 行）；对 torch zip 可扫（evil_torch.pt 命中）。
- **trivy**：secret 引擎**不报 AWS 官方示例密钥** AKIAIOSFODNN7EXAMPLE（文档示例密钥黑名单），合成密钥（.env 内 AKIA3F.../ghp_...）正常检出；`trivy k8s` 直连真集群在本环境不可稳定复现——node-collector Job 镜像经 TCG guest 代理拉取失败，报 `get k8s artifacts with node info error: no compliance commands found` 后**不写任何报告**（早前一次成功跑出过 86 misconfig/8 results 的完整报告）；`--disable-node-collector` 在 0.76.1 只输出退化报告 `{"ClusterName": "default"}`。因此 bench 采用**集群快照**（kubectl 全量 dump→拆 List 为多文档→`trivy fs`），同检查集、可复现；直连失败过程原样记录于 `trivy-k8s.json` 的 `live_scan_notes`。
- **kube-bench**：0.16.0 无 Windows 构建（linux 二进制/容器），在 guest 内以 docker 运行；挂载 `/etc`（含 `/etc/rancher/k3s/k3s.yaml`）+`KUBECONFIG` 后自动检测 k3s 并选中 **k3s-cis-1.9**（对 v1.36.5 而言这是其 k3s 档位表的最新映射），未挂 kubeconfig 时回退 cis-1.6/假想 1.18（对比运行记录在 guest 脚本输出里）。
- **kube-hunter**：对匿名读 API 之外的接口（mock 只开两个端口）能给出 8 findings；注意其上游已声明**不再积极开发**（推荐迁移 Trivy）。
- **promptfoo**：echo provider 12/12；一次冷启 ≈48 s（node 模块加载），热启 2.33s——CI 场景需预热。
- **toxiproxy**：200ms 下行延迟注入实测 +200.7ms（误差 0.7ms）；timeout toxic 直接断连——损伤注入面完整可用，是网络损伤 backlog（OSS-S1）的现成执行件。
- **Chaos Toolkit**：steady-state-hypothesis+tolerance 200+process provider（taskkill）三件套在 Windows 本地进程面可用；稳态破坏被正确判定为 deviated 且 journal.json 落证——证据结构与 Trident 三层证据同型（OSS-S2 导出对接点）。

## 4. 未实测项与原因（与全景表 `local_runnable` 一一对应）

| 工具 | 未跑原因 |
|---|---|
| Kubescape / kubeaudit / KubiScan / kdigger / Peirates / CDK / KubeHound | bench 名单外或需集群内/pod 内执行环境（逐工具口径见全景 §3；避免与已测 kube-bench/Trivy/kube-hunter 重复计费） |
| garak / PyRIT / Giskard / DeepTeam | 需真实 LLM 端点/外部 API（本机离线红线），名单外未纳入本轮 |
| sonobuoy | 需在目标集群执行诊断插件（conformance 口径 ≠ 安全扫描口径） |
| nccl-tests / perftest / ibdiagnet | 无 NVIDIA GPU / 无 RDMA NIC / 无 InfiniBand fabric（硬件缺失） |
| DCGM diag | 无 NVIDIA GPU（硬件缺失） |
| Chaos Mesh / Litmus | 需在 K8s 内部署 controller+CRD（QEMU TCG 下部署面过大） |
| Pumba | 依赖 docker 守护进程对容器注入（本机无 docker runtime） |
| tc/netem | Windows 宿主不可用（WSL2 不可用）；需在目标 Linux netns 内执行 |
| torch distributed / Ray / DeepSpeed 测试套件 | 需多进程/GPU/集群口径（官方套件本身可 pip 装但完整跑法需专用环境） |

## 5. 与 Trident 的同量级参照

同靶场（QEMU TCG k3s + mock）下：Trident 11 个侦察模块跑真实 kubectl 快照 **199.7ms / 145 findings / RSS 34–54MB**（docs/SCALE-RESULTS.md k3s 实测点）；trivy-k8s 快照路径 3.90s / 247 misconfig / RSS 226MB——不同检查哲学（Trident=ML 面专项检查，Trivy=通用 misconfig 规则集），数字不可直接优劣化，仅作资源量级参照。ARTEX 同靶场 13510ms vs Trident 105.6ms 见 docs/ARTEX-BENCH-RESULT.md。
