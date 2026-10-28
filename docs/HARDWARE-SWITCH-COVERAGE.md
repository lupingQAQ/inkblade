# 硬件与交换机面覆盖（HARDWARE / SWITCH COVERAGE）

本文件说明 InkBlade 在 **GPU 驱动/固件、BMC/Redfish、NVSwitch/NVLink、DPU、交换机 OS、
IB SM/Partition、SHARP、fabric 遥测、固件供应链** 九个面上的只读审计能力、证据等级与
生产使用边界。

> **边界声明（必须随交付阅读）**：当前仓库**无真实 GPU/BMC/交换机验证**。所有硬件面结论
> 来自 `lab/hardware_sim.py` 的配置/遥测双态 **仿真** 与 `lab/hardware-fixtures/` 的
> **fixture**；仿真/固件清单 **不等于** 客户现场设备事实。三级矩阵中的「必须真实硬件」
> 项一律记为未达成，不得写成「已实测」「生产验证通过」「厂商兼容性认证」。

---

## 1. 为什么单列硬件面

K8s 控制面审计能看到 Pod、Service、RBAC，却看不到下面四类真实信任边界：

1. **GPU 固件/驱动**：Xid、ECC、VBIOS、CUDA 版本决定训练是否静默损坏或整机复位；
2. **BMC/Redfish/IPMI**：带外管理面一旦默认凭据可登录，等于绕过主机与 K8s 的全部控制；
3. **NVSwitch/NVLink/IMEX**：GPU 直连域的分区错误会把租户 A 的集合通信暴露给租户 B；
4. **交换机 OS / IB SM / SHARP / 遥测**：PFC/ECN/ACL、Partition、在网聚合与 gNMI/SNMP
   是 fabric 的原生控制面，通常不受 Kubernetes NetworkPolicy 覆盖。

这些面**只读检查优先**：先拿客户导出的 `nvidia-smi`/NVML、Redfish GET、`config_db.json`、
`nvswitch` 拓扑 JSON、IB/SHARP 配置、固件清单做离线核验；只有获得书面授权和明确窗口，
才做主动连接探测。任何写操作（固件刷新、PFC 下发、Partition 变更、BMC 改密）都不在
本仓库模块内。

---

## 2. 三级矩阵（只读 / 需授权主动 / 必须真实硬件）

| 层级 | 定义 | 模块 | 当前证据 | 能做 | 不能做 |
|---|---|---|---|---|---|
| **T1 只读** | 只解析客户提供的导出文件或 fixture，不连接设备、不登录、不写 | `gpu-driver-firmware-surface`、`nvswitch-nvlink-topology`、`switch-os-config-surface`、`ib-sm-partition-audit`、`sharp-collective-config`、`hardware-supply-chain` | `lab/hardware-fixtures/` 的合成 fixture + 单元测试 | 版本/配置/拓扑/哈希清单核验；输出可复核 finding | 不能证明导出文件是最新、完整、未被篡改；不能替代设备实时状态 |
| **T2 需授权主动** | 对已授权资产做**只读 HTTP GET / 单次默认凭据验证**（不写、不爆破、不改配置） | `bmc-ipmi-exposure`、`dpu-smartnic-surface`、`fabric-observability-exposure` | `lab/hardware_sim.py` 的 127.0.0.1 mock（vulnerable/fixed 两态） | 发现匿名管理面、默认凭据可登录、IPMI over LAN、DPU 未鉴权服务、gNMI/SNMP 暴露 | 不能在未授权/未窗口时扫生产；默认凭据验证可能触发锁定，必须先在实验环境演练 |
| **T3 必须真实硬件** | 需要厂商设备、真实 ASIC/固件/带外网络，且通常需要变更审批 | 无（当前不提供） | **无真实 GPU/BMC/交换机验证** | 只有客户现场 + 厂商配合 + 变更窗口才能做 | 不能拿仿真结果冒充 PFC/ECN 行为、NVSwitch 分区生效、SHARP 真实聚合、固件刷写/回滚 |

### 2.1 按模块展开

| 模块 | 级别 / 写 | 输入 | 只读证据 | 典型 finding | 当前限制 |
|---|---|---|---|---|---|
| `gpu-driver-firmware-surface` | 只读侦察 / `writes=false` | `nvidia-smi --query-gpu` CSV、NVML JSON、Xid 事件 | 设备数、驱动/CUDA/VBIOS 版本、ECC、Xid、持久化模式 | 驱动低于基线、同池版本不一致、VBIOS 不一致、ECC 关闭、Xid 复位族 | fixture 解析；未执行真实 `nvidia-smi`，未接 NVML |
| `bmc-ipmi-exposure` | 主动探测 / `writes=false` | Redfish 基址（可选 Basic 默认凭据）、`UpdateService`、`FirmwareInventory` | 服务根、Manager、NetworkProtocol、Accounts、Systems 状态；更新服务认证/传输；固件清单签名标记 | 默认凭据可登录、IPMI over LAN、SSH 密码认证、管理详情匿名可读、更新服务匿名/明文、固件清单未签名 | mock 只读；生产默认凭据验证需授权并评估锁定策略 |
| `nvswitch-nvlink-topology` | 只读侦察 / `writes=false` | NVSwitch/NVLink/IMEX 拓扑 JSON | 交换机固件、链路状态、分区、IMEX 通道 | 分区跨租户、IMEX 跨租户、共享交换机、链路 down/degraded、固件不一致 | fixture 解析；未读取真实 NVSwitch |
| `dpu-smartnic-surface` | 主动探测 / `writes=false` | DPU 服务清单 HTTP、可选凭据面 | 服务/端口/鉴权标记、SSH 密码认证、rshim、凭据面状态 | 管理服务未鉴权、工厂/默认凭据明文暴露、SSH 密码认证、rshim 暴露 | mock 只读；未登录 BlueField/DOCA，未验证真实服务 |
| `switch-os-config-surface` | 只读侦察 / `writes=false` | SONiC `config_db.json` 或 Cumulus 导出 JSON | PFC watchdog、ECN/WRED、管理 ACL、SNMP、NTP、AAA | PFC watchdog 关闭、ECN 未启用、管理 ACL 放行任意来源、SNMP public、缺少远程 AAA | 只解析 JSON 导出；**不登录设备**，不解析二进制/私有格式 |
| `ib-sm-partition-audit` | 只读侦察 / `writes=false` | SM/Partition/节点导出 JSON | SM 冗余、默认分区、PKey 成员、IPoIB、SM 主机位置 | 单 SM 无冗余、默认分区覆盖全部 HCA、Partition 跨租户、SM 跑在计算节点 | fixture 解析；未连接 UFM/OpenSM，未验证真实成员 |
| `sharp-collective-config` | 只读侦察 / `writes=false` | SHARP 会话/AM/collective 导出 JSON | 会话鉴权、成员租户、聚合节点、缓冲隔离 | 会话无鉴权、聚合节点跨租户共享、成员跨租户、缓冲未隔离 | fixture 解析；未触发真实 SHARP reduce |
| `fabric-observability-exposure` | 主动探测 / `writes=false` | gNMI/SNMP/TSDB 配置 + 指标 JSON | gNMI TLS/鉴权、SNMP 版本/团体名、tenant/serial 标签 | 遥测匿名暴露租户/序列号、gNMI 明文/无鉴权、SNMP v2c public | mock 只读；未连真实 gNMI/SNMP 设备 |
| `hardware-supply-chain` | 只读侦察 / `writes=false` | 固件清单 + 实际 blob + 可选签名密钥 | 组件哈希、缺失文件、签名状态、签名者/供应商 | 固件哈希不匹配、清单签名无效、组件缺签名者、供应商不一致 | fixture 使用 **HMAC**；生产必须换厂商非对称签名/PKI，不能把 HMAC 当供应链信任 |

---

## 3. 实验室：配置/遥测双态仿真

`lab/hardware_sim.py` 只在 `127.0.0.1` 启动，**所有路由均为 GET、`writes=false`**，
POST/PUT/PATCH/DELETE 一律 405。它模拟两个平面 × 两种姿态：

| 平面 | vulnerable 姿态 | fixed 姿态 |
|---|---|---|
| **配置面** | Redfish 管理详情匿名可读、`root/calvin` 默认凭据 200、IPMI 623 开启、PFC watchdog `disable`、NVSwitch 分区跨租户、DPU `redfish/grpc-doca` 未鉴权且 `/dpu/credentials` 200、固件清单可读 | Manager/NetworkProtocol/Accounts 401、默认凭据 401、IPMI 关闭、PFC watchdog `detect`、NVSwitch 租户隔离、DPU 全鉴权且凭据 404 |
| **遥测面** | gNMI `tls=false`/`auth=false`、SNMP `2c/public`、metrics 200 且带 `tenant`/`serial` 标签 | gNMI `tls=true`/`auth=true`、SNMPv3、metrics 401 |

### 3.1 fixture 清单（全部合成）

| 路径 | 内容 | 用途 |
|---|---|---|
| `lab/hardware-fixtures/gpu/nvidia-smi.csv` | 4 卡混合驱动/ECC/VBIOS | 驱动/固件面解析（风险态） |
| `lab/hardware-fixtures/gpu/nvml.json` | CUDA 13.0、Xid 79 | Xid/ECC/版本核验（风险态） |
| `lab/hardware-fixtures/gpu/nvidia-smi-clean.csv`、`nvml-clean.json` | 2 卡一致且健康 | 无 finding 负例 |
| `lab/hardware-fixtures/sonic/config_db.json` | PFC watchdog 关闭、ECN 关闭、管理 ACL 放行、SNMP public | SONiC 风险态 |
| `lab/hardware-fixtures/sonic/config_db_hardened.json` | watchdog detect、ECN、deny ACL、SNMPv3、NTP、TACACS+ | SONiC 加固态 |
| `lab/hardware-fixtures/cumulus/config.json` | Cumulus 风格 PFC/ECN/ACL/SNMP/NTP/AAA | 第二厂商格式解析 |
| `lab/hardware-fixtures/nvswitch/topology.json` | 跨租户 GPU 0、共享交换机、固件不一致、link down/degraded | NVSwitch 风险态 |
| `lab/hardware-fixtures/nvswitch/topology-clean.json` | 租户隔离、全链路 up、固件一致 | 负例 |
| `lab/hardware-fixtures/ib/partition-dump.json` | 单 SM、默认分区 `*`、Partition 跨租户、SM 在计算节点 | IB 风险态 |
| `lab/hardware-fixtures/ib/partition-dump-clean.json` | 双 SM、默认分区最小、租户隔离 | 负例 |
| `lab/hardware-fixtures/sharp/config-dump.json` | 无鉴权会话、聚合节点跨租户、成员跨租户、缓冲未隔离 | SHARP 风险态 |
| `lab/hardware-fixtures/sharp/config-dump-clean.json` | mTLS、独立聚合节点、缓冲隔离 | 负例 |
| `lab/hardware-fixtures/firmware/manifest.json` | 4 个组件哈希 + HMAC fixture 签名 | 固件清单核验 |
| `lab/hardware-fixtures/firmware/blobs/*.bin` | 合成固件字节 | 哈希比对 |
| `lab/hardware-fixtures/firmware/fixture-signing-key.txt` | fixture HMAC 密钥（仅测试） | 签名路径验证 |

> **签名口径**：`hmac-sha256-fixture` 只能证明「签名校验代码会拒绝篡改」，**不能**证明
> 厂商签名链、密钥轮换、离线根、TUF/in-toto 或生产供应链完整性。生产应以厂商
> 非对称签名（如 RSA/ECDSA/Ed25519）+ 公钥指纹 + 独立下载渠道 + 双人复核替代。

### 3.2 实效验证（硬件 +2，芯片 +4）

`inkblade/verify-effects.py` 新增硬件两项与芯片四项（本文件相关六项；全套 47 项）：

1. `hardware-bmc-default-credential`：对 `lab/hardware_sim.py` vulnerable 态执行
   `bmc-ipmi-exposure`，断言默认凭据登录 HTTP 200、IPMI over LAN 开启、finding 为 high；
   同一模块在 fixed 态无 high finding。
2. `hardware-firmware-manifest-tamper`：复制固件 fixture 到临时目录，篡改
   `nvswitch-fw` blob，执行 `hardware-supply-chain`，断言清单签名仍有效但哈希不匹配，
   finding 为 high 且 `tampered_components` 含 `nvswitch-fw`。
3. `chip-cc-attestation-tamper`：有效 NRAS 风格 JWT 通过；改 payload 后同一 JWKS
   验签失败，finding 为 high。
4. `chip-iommu-passthrough`：vulnerable `iommu=pt` + 多设备 identity 组 → high；
   fixed 无 high。
5. `chip-pcr-baseline-offset`：PCR 0/4 与 golden 不一致 → high；fixed 0 偏移。
6. `chip-gpu-memory-residue`：benign marker 释放后读回且 sha256 一致 → high；
   fixed 释放即清零并 404。

这六项证明的是「检测逻辑在本机 mock/fixture 上真实触发」，**不是**真实 BMC/固件/GPU
被攻破。芯片/加速器范围的 A/B/C/D 分级见 `docs/CHIP-SECURITY-SCOPE.md`。

---

## 4. 已证明 / 未证明

| 结论 | 状态 | 证据 |
|---|---|---|
| 九个模块可注册、全部 `writes=false`、无写面 | 已证明 | `tests/test_modules_hardware.py` 注册表契约 |
| fixture 驱动解析（GPU/SONiC/Cumulus/NVSwitch/IB/SHARP/固件） | 已证明（fixture 级） | `tests/test_modules_hardware.py` |
| BMC 默认凭据/匿名管理面检测逻辑 | 已证明（mock HTTP 级） | `tests/test_hardware_sim.py` + effects |
| 固件清单篡改检测逻辑 | 已证明（fixture 级） | effects + `tests/test_modules_hardware.py` |
| PFC/ECN 在真实 ASIC 上的行为 | **未证明** | 无真实交换机 |
| NVSwitch/NVLink 分区真实生效 | **未证明** | 无真实 NVSwitch |
| SHARP 真实在网聚合/会话鉴权 | **未证明** | 无真实 Quantum/Spectrum 设备 |
| 真实 BMC（iDRAC/iLO/Supermicro）默认凭据与锁定策略 | **未证明** | 仅 mock |
| BlueField/DPU DOCA 真实服务与凭据 | **未证明** | 仅 mock |
| 厂商固件签名/PKI 信任链 | **未证明** | fixture 仅 HMAC |

**明确：无真实 GPU/BMC/交换机验证。** 仿真与 fixture 不等于现场设备事实；任何对外报告
必须把上表「未证明」项原样带上。

---

## 5. 生产建议

1. **先只读清点**：先收集 `nvidia-smi`/NVML、Redfish GET、SONiC `config_db.json`、
   NVSwitch 拓扑、IB/SHARP 导出、固件清单；离线跑 T1 模块，确认资产/版本/配置基线。
2. **变更窗口**：主动探测（T2）必须放在书面授权 + 变更窗口内；BMC 默认凭据验证可能触发
   账号锁定/告警，先在实验环境演练，生产只做**单次**厂商默认值尝试或改为只读账号枚举。
3. **厂商配合**：NVSwitch 分区、SHARP、DPU DOCA、交换机 OS 私有字段需厂商/集成商确认
   语义；不要把社区默认值当厂商基线。
4. **备件与回滚**：任何固件刷新、PFC/ECN 下发、Partition 变更前准备**同型号备件**、
   带外回滚路径、配置备份与双人复核；T3 操作不由本仓库模块执行。
5. **默认凭据治理**：把「默认凭据仍启用」列为 high；改密后验证旧凭据 401，并检查 IPMI
   623/UDP、SSH、Redfish 是否只开在带外管理网。
6. **遥测最小暴露**：gNMI 必须 TLS + 鉴权；SNMP 禁 v1/v2c public/private；指标去掉
   tenant/serial 等敏感标签或做聚合。
7. **固件供应链**：以厂商非对称签名 + 公钥指纹 + 独立下载渠道为准；本仓库 HMAC fixture
   只用于回归测试，不能作为生产信任根。
8. **证据留痕**：保存原始导出、命令、时间、设备序列号（脱敏）与哈希；报告注明「fixture/
   仿真/现场」证据等级，禁止把 T1/T2 结果写成 T3 实测。

---

## 6. 复现

```bash
# 生成 fixture（可重复；全部合成数据）
python lab/hardware-fixtures/build_fixtures.py

# 只读仿真（vulnerable / fixed）
python lab/hardware_sim.py --mode vulnerable
python lab/hardware_sim.py --mode fixed

# 模块与仿真测试
python -m unittest tests.test_hardware_sim tests.test_modules_hardware tests.test_hardware_docs -v

# 实效验证（含 hardware-* 两项）
python -m inkblade.verify-effects --out reports/samples/effects/ --no-docs
```

## 7. 相关文档

- `docs/FABRIC-ATTACK-SURFACE.md`：万卡 fabric 控制面/数据面威胁模型（PFC/IB/SHARP 等）。
- `docs/FABRIC-SIM-RESULTS.md`：1,024/10,000 节点离散事件仿真（模拟，非真实硬件）。
- `docs/EFFECT-VERIFICATION.md`：本机真实进程/HTTP 效果验证（硬件两项为 mock/fixture）。
- `docs/SOTA-2026-10.md`：能力三态矩阵；真实硬件项仍列未达成。
