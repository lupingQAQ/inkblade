# 芯片/加速器安全姿态范围（CHIP SECURITY SCOPE）

本文件定义 InkBlade 在 **集群内可触达** 的芯片/加速器安全姿态审计范围、必要性分级、
部署画像映射与明确排除项。目标是回答一个窄问题：

> 在不接触硅片实验室、不拆机、不开盖、不做故障注入的前提下，攻击者或审计者
> 能从已部署的 Kubernetes / Slurm / BMC / 固件导出面看到什么、验证什么、拿不下什么？

**结论先行**：本仓库只做 **部署面可达** 的证明链、配置、隔离与供应链核验；
**不做硅片实验室**（RTL/GDSII/DFT、功耗电磁侧信道、电压毛刺/激光、开盖探针、
芯片逆向、counterfeit 检测、Rowhammer 实操、微架构侧信道实操）。这些项没有
集群内可测面，或风险/资源不可控，已写入本文第 4 节 out-of-scope。

> 证据等级口径：`fixture`（合成样本）< `mock`（127.0.0.1 双态仿真）<
> `export`（客户真实导出）< `live`（真实设备在线只读）。本文所有“已实现”均指
> 代码与测试，不指“真实芯片已验证”。详见第 6 节。

---

## 1. 必要性分级（A > B > C > D）

| 级别 | 定义 | 是否计入“芯片渗透能力” | 交付口径 |
|---|---|---|---|
| **A 真攻击路径** | 能实际导致节点接管、DMA 越权、带外接管或跨租户数据读取；必须做深、做对抗用例 | **计入** | 允许写类对抗（benign marker + 备份闸门）；报告写“可验证攻击路径” |
| **B 保障性审计** | 不直接“打进去”，但 false trust、持久化、供应链伪造会放大真实攻击；做检测不做攻击 | **计入“保障性检测”**，不计入“攻击拿下” | 只读/检测；报告写“证明链/签名/基线核验” |
| **C 前瞻/低必要性** | 只有特定客户（GB200/NVL、CXL、明确 SPDM 部署）才有面；默认关闭 | **不计入** | `research-only`；默认 `default_enabled=false`；无面即 `no-surface` |
| **D 明确不做** | 硅片实验室/物理/微架构实操；集群内无可测面或风险不可控 | **不计入** | 写入 out-of-scope，不实现、不宣传 |

**裁剪规则**：报告、SOTA、销售材料不得把 C/D 类模块数、fixture 数或“支持项”
写成“芯片渗透能力”。C 类最多写“research-only 配置审计，默认关闭”；D 类只写
“明确不做及原因”。

---

## 2. In-scope：部署面可达的芯片/加速器姿态

### 2.1 总表（含必要性分级）

| ID | 能力 | 必要性分级 | 为什么与真实攻击面 | 所需资源（最小） | 模块/证据 |
|---|---|---|---|---|---|
| **A1** | **IOMMU/SMMU 直通与 DMA 隔离** | **A 真攻击路径** | `iommu=off` / `iommu=pt` / 多设备 identity 组 / ACS 缺失 / ATS 无保护，可让不可信负载或设备 DMA 到宿主/他租户内存；这是“集群内可实际拿下节点/越权设备”的路径 | 节点 `/proc/cmdline`、`/sys/kernel/iommu_groups/*`、`lspci -vv` ACS/ATS 导出；无需物理接触 | `iommu-smmu-config`（只读解析）；证据：cmdline + group + ACS/ATS + SMMU 状态 |
| **A2** | **BMC/DPU/IPMI 带外接管（补 Redfish/固件面）** | **A 真攻击路径** | BMC 默认凭据、匿名 Redfish、IPMI over LAN、DPU 未鉴权服务、Redfish UpdateService/固件清单匿名可读，均可绕过 K8s 直接控制节点/固件；已有模块已覆盖默认凭据与 DPU 服务，本任务补 Redfish 固件清单/更新服务面 | 带外管理网可达；Redfish GET（可选单次厂商默认凭据验证）；DPU 服务清单；固件清单/更新服务 | `bmc-ipmi-exposure`、`dpu-smartnic-surface`、`redfish-default-credentials`、`ipmi-cipher-zero-bypass`；本任务扩展 Redfish `UpdateService`/`FirmwareInventory` 只读面 |
| **A3** | **GPU 显存残留 / MIG / MPS 跨租户残留与隔离绕过** | **A 真攻击路径** | MIG 释放未清零、MPS 共享上下文、跨租户 residue 可读，直接泄露他租户模型/激活/进程信息；已有模块覆盖跨租户读取，本任务补“分配→写 benign marker→释放→读回”对抗用例 | 池化/共享 GPU 的分配/释放生命周期导出；授权靶场可写 benign marker；备份回执 | `gpu-tenant-residue`（已有）、`gpu-memory-residue-isolation`（本任务，写类走备份闸门） |
| **B1** | **GPU CC 证明链（NRAS JWKS + nonce + claims）** | **B 保障性审计** | CC 的 false trust 风险：不验签、不绑 nonce、不校验 `dbgstat/secboot/overall-att-result` 就把密钥/模型交给“自称 CC”的 GPU；合规场景必须做检测 | NRAS JWKS（公开）、attestation JWT（设备/证明服务导出）、请求 nonce；无需物理接触 | `gpu-cc-attestation-chain`（复用 `inkblade/tee` 在线校验器）；证据：JWKS/验签/claims/nonce |
| **B2** | **固件签名 / 安全启动 / TPM / 微码吊销** | **B 保障性审计** | 固件/引导链持久化与供应链伪造：签名无效、证书过期、信任根未固定、PCR 偏移、dbx 缺失、微码低于厂商基线；检测为主，不刷新固件 | 固件清单 + 厂商根/证书链 + 分离签名；TPM eventlog/PCR/dbx 导出；CPU 微码 revision；无需物理接触 | `firmware-signature-inventory`、`secure-boot-chain`（本任务）；`hardware-supply-chain`（HMAC fixture，仅回归，不冒充厂商 PKI） |
| **C1** | **SPDM / PCIe DOE 细项** | **C 前瞻/低必要性（research-only）** | 只有明确部署 CMA/SPDM 的设备（部分 GB200/NVL、TEE-IO 场景）才有面；证书/测量/DOE 细项对普通 K8s 客户不是可测攻击路径 | 设备 SPDM 导出（版本/证书链/MeasurementRecord/DOE 能力）；多数客户无此导出 | `spdm-pcie-doe`；**默认关闭**，仅 `--probe` 或客户面显式启用 |
| **C2** | **NVLink/IMEX 域与分区配置审计** | **C 前瞻/低必要性（research-only）** | 只有 GB200/NVL 多节点 NVLink 客户才有 IMEX 域/分区面；普通 PCIe GPU 集群无此面 | IMEX `nodes_config.cfg`/域/通道导出；NVLink partition/Fabric Manager 导出 | `nvlink-imex-isolation`；**默认关闭**，仅按需启用 |
| **C3** | **CXL 内存安全** | **C 前瞻/低必要性（research-only）** | 六个主流画像均无 CXL 面；只有客户实际部署 CXL 内存/加速器时才有 IDE/TSP/decoder 可测面 | CXL 设备/decoder/TSP/IDE/mailbox 导出 | `cxl-memory-security`；**默认关闭**，无面即 `no-surface` |

### 2.2 A 类必须做深的三条路径

#### A1 — IOMMU/SMMU 直通与 DMA

- **真实攻击路径**：不可信 Pod/VM 绑定到多设备 IOMMU 组或 identity 域后，可对宿主/他租户内存发起 DMA；`iommu=pt` 让内核 DMA API 走 passthrough，放大风险。
- **必须核验**：`iommu=off`、`intel_iommu=off`、`amd_iommu=off`、`iommu=pt`、`iommu.passthrough=1`、`iommu.strict=0`、多设备 identity/passthrough 组、ACS 未启用、ATS 无保护、ARM64 无 SMMU。
- **资源**：只读导出即可；不需要 vfio 绑定、不需要写 sysfs、不需要重启。
- **不做**：不实际触发 DMA 攻击、不绑定 vfio、不写 PCI 配置空间；finding 只给配置风险与利用前置条件。

#### A2 — BMC/DPU/IPMI 带外接管

- **真实攻击路径**：BMC 默认凭据/匿名 Redfish/IPMI over LAN/DPU 未鉴权服务 → 带外控制节点、改固件、绕过 K8s RBAC 与审计。
- **已有模块**：`bmc-ipmi-exposure`（Redfish 只读 + 单次厂商默认凭据）、`dpu-smartnic-surface`、`redfish-default-credentials`、`ipmi-cipher-zero-bypass`。
- **本任务补面**：Redfish `UpdateService` 与 `FirmwareInventory` 的匿名可读/更新服务暴露/固件签名标记；仍只 GET，不触发固件更新。
- **资源**：带外管理网可达 + 授权；默认凭据验证最多 2 次、命中即停；固件清单只读。
- **不做**：不改密、不刷固件、不爆破、不写 Redfish。

#### A3 — GPU 显存 / MIG / MPS 残留

- **真实攻击路径**：租户 A 在 MIG 实例/MPS 客户端释放后读到他租户 B 的显存快照/进程信息；MPS 共享上下文进一步降低隔离。
- **已有模块**：`gpu-tenant-residue`（跨租户读取 + 写读回）。
- **本任务补对抗用例**：`gpu-memory-residue-isolation` 在授权靶场执行 `allocate → 写 benign marker → release → residue 读回`，断言释放后仍可读且 `marker_sha256` 一致；fixed 姿态释放即清零并 404。
- **资源**：池化/共享 GPU 生命周期导出；写类需 `backup_targets` 备份回执；只写 benign marker。
- **不做**：不读取/覆盖真实租户数据、不调用真实 `nvidia-smi`/NVML、不直接读 `/dev/nvidia*`。

### 2.3 B 类：做检测，不做“攻击”

#### B1 — GPU CC 证明链

- **核验**：JWKS 结构（kid/alg/kty）、RS256/ES384/ES256 验签、`exp/nbf/iat/iss/aud`、`eat_nonce`、`x-nvidia-overall-att-result=true`、`dbgstat=disabled`、`secboot=true`、`x-nvidia-ver` 下限、`expected_claims` 固定。
- **false trust 风险**：只看到 JWT 存在就释放密钥；不绑 nonce 导致重放；不校验 `dbgstat` 导致 CC-DevTools 被当成 CC-On。
- **资源**：NRAS JWKS（公开）+ 设备/证明服务导出的 JWT + 请求 nonce。
- **边界**：本仓库没有 NVIDIA 签发的生产 JWT；fixture 只证明验签/claims 逻辑。真实环境必须用 NRAS JWKS 与真实设备证明。

#### B2 — 固件签名 / 安全启动 / TPM / 微码吊销

- **核验**：厂商 X.509 链（pinned 根、有效期、CA 位）、组件分离签名（RSA/ECDSA，**非 HMAC**）、哈希、吊销 serial、弱算法；Secure Boot/Setup Mode、eventlog 重放、PCR 0/4/7/11 与 golden 基线、dbx 年龄；CPU 微码 revision 与厂商安全基线。
- **持久化/供应链意义**：引导链/固件是 K8s 之上的信任根；签名无效或 PCR 偏移意味着“节点看起来正常，但引导链已变”。
- **资源**：固件清单 + 厂商根/证书链 + 签名；TPM eventlog/PCR/dbx 导出；微码 revision。全部离线/只读。
- **边界**：不刷新固件、不写 NVRAM、不扩展 PCR；UKI 本地只验 detached raw 签名，Authenticode/PKCS#7 需外部 `sbverify`/`pesign` 结果，模块只记为 `reported` 证据。

---

## 3. 部署画像映射（默认暴露 / 需配置 / 无面）

“默认暴露”指不需要额外配置就能从该画像声明的面观察到；“需配置”指必须显式启用/导出
（CC 模式、MIG/MPS、SPDM、IMEX、CXL 等）；“无面”指该画像没有声明相应面，模块
`no-surface`，不执行、不产 finding、不计覆盖。

| 能力 | `bare-k8s-gpu` | `ray-vllm` | `managed-ack-tke` | `slurm-hpc` | `airgapped` | `gpu-pooling` |
|---|---|---|---|---|---|---|
| A1 IOMMU/SMMU | 需配置（导出 cmdline/sysfs） | 无面（未声明导出） | 无面（无节点管理面） | 需配置（导出 cmdline/sysfs） | 需配置（导出 cmdline/sysfs） | 无面（未声明导出） |
| A2 BMC/DPU/IPMI | **默认暴露**（Redfish/BMC 可达） | 无面（无 BMC） | 无面（托管控制面，无直接 BMC） | **默认暴露**（BMC/DPU 可达） | **默认暴露**（BMC/交换机可达） | 无面（无 BMC） |
| A3 GPU 显存/MIG/MPS | 需配置（GPU 有面，未声明共享配置） | 需配置（GPU 有面，未声明共享配置） | 需配置（GPU 有面，未声明共享配置） | 无面（本构建无 K8s Node 面） | 需配置（GPU 有面，未声明共享配置） | **需配置**（HAMi/cGPU + `gpu/sharing.json`） |
| B1 GPU CC 证明链 | **需配置/已配置**（`attest/gpu-cc.json`） | 需配置（有 GPU 无 attest 导出） | 需配置（有 GPU 无 attest 导出） | 无面（无 K8s Node 面） | **需配置/已配置**（`attest/gpu-cc.json`） | 需配置（有 GPU 无 attest 导出） |
| B2 固件/安全启动/TPM | **需配置**（TPM+firmware 导出） | 无面（无 TPM/BMC） | 无面（无 TPM/BMC） | **需配置**（TPM+firmware 导出） | **需配置**（TPM+firmware 导出） | 无面（无 TPM/BMC） |
| C1 SPDM | research-only；需配置 | 无面 | 无面 | research-only；需配置 | research-only；需配置 | 无面 |
| C2 NVLink/IMEX | research-only；需配置 | 无面 | 无面 | research-only；需配置 | research-only；需配置 | 无面 |
| C3 CXL | 无面 | 无面 | 无面 | 无面 | 无面 | 无面 |

**读法**：A2 的“默认暴露”是真实带外管理面，不是“默认一定弱口令”；A1/A3 的“需配置”
是审计入口需要客户导出，而不是攻击一定成功。C 类即使有面也默认关闭，只有客户显式
`--probe`/profile 才执行。

### 3.1 模块 × 画像 verdict（由 `inkblade surfaces` 可复算）

| 模块 | 必要性 | 默认 | 主要面 | 典型 verdict |
|---|---|---|---|---|
| `iommu-smmu-config` | A | on | `iommu/kernel-cmdline.txt` | bare/airgapped/slurm production-testable；其余 no-surface |
| `bmc-ipmi-exposure`（扩展） | A | on | `bmc/redfish` + Redfish UpdateService/FirmwareInventory | bare/airgapped/slurm production-testable；其余 no-surface |
| `gpu-tenant-residue`（已有） | A | on | 池化/共享 GPU HTTP 面 | 取决于池化面 |
| `gpu-memory-residue-isolation` | A（写类） | on | `Node/gpu-0` + `gpu/sharing.json` | gpu-pooling production-testable；其他 K8s conditional；slurm no-surface |
| `gpu-cc-attestation-chain` | B | on | `Node/gpu-0` + `attest/gpu-cc.json` | bare/airgapped production-testable；其他 K8s conditional；slurm no-surface |
| `firmware-signature-inventory` | B | on | `firmware/vendor-inventory.json` | bare/airgapped/slurm production-testable；其余 no-surface |
| `secure-boot-chain` | B | on | `bmc:tpm` + `attest/tpm.json` | bare/airgapped/slurm production-testable；其余 no-surface |
| `spdm-pcie-doe` | C | **off / research-only** | `spdm/device-export.json` | 有面但也默认关闭；显式启用后按 profile 计算 |
| `nvlink-imex-isolation` | C | **off / research-only** | `nvswitch/imex.json` | 有面但也默认关闭；显式启用后按 profile 计算 |
| `cxl-memory-security` | C | **off / research-only** | `cxl/inventory.json` | 六个画像全 no-surface；仅客户 CXL 面显式 `--probe` |

---

## 4. Out-of-scope：明确不做（D 级）

以下内容需要 **硅片实验室/物理接触/不可控故障注入**，没有集群内可测面，或一旦执行
会破坏生产数据/硬件、无法在授权远程评估中复现。**本仓库不实现、不提供脚本、不把
fixture 结果写成这些能力的证据。**

| 排除项 | 为什么不做（集群内无面/风险不可控） | 所需资源（真实开展时） |
|---|---|---|
| **RTL / GDSII / DFT** | 需要芯片设计源文件、扫描链/测试访问；集群内只有成品设备，没有 RTL/GDSII/DFT 接口 | EDA 许可证、代工厂 PDK、DFT/ATE 访问、NDA、洁净室 |
| **功耗/电磁侧信道** | 需要物理探头/屏蔽环境与大量统计采集；集群内只能看到性能计数器，不能定位功耗/电磁泄漏 | 示波器、EM 探头、屏蔽室、低噪声电源、统计/CPA 工具 |
| **电压毛刺 / 激光故障注入** | 需要拆机/开盖/精确时序与物理定位；可能永久损坏硬件，风险不可控 | 故障注入台、激光/电磁注入器、探针台、时序控制器、备件 |
| **开盖/探针** | 需要化学开盖、显微探针、微焊接；破坏封装且不可远程复现 | 发烟硝酸/开盖台、显微镜、微探针、微焊接台、洁净室 |
| **芯片逆向 / die imaging** | 需要去层、SEM/FIB/X 射线（X-ray）、版图重建；与集群审计无关 | SEM/FIB、X 射线（X-ray）、去层设备、版图/网表工具、专家 |
| **Counterfeit 检测** | 需要 X 射线（X-ray）/开盖/XRF/授权分销链核验；集群内无法证明器件真伪 | X 射线（X-ray）、XRF、开盖、显微、授权分销/溯源链 |
| **Rowhammer 实操** | 需要可控 DIMM/大量内存访问与可接受的数据损坏风险；生产集群内执行会破坏数据，且结果依赖颗粒/刷新策略 | DIMM 测试平台、巨量内存访问、错误注入/监测、备用硬件 |
| **微架构侧信道实操** | 需要受控共置、性能计数器、统计分析与大量重复；生产环境噪声大、误报高、可能影响 SLA | 受控宿主机、PMU 访问、统计工具、长时间窗口、隔离实验环境 |

**“硅片实验室”总声明**：上述 D 项属于硅片/物理实验室工作，**不是本仓库的交付范围**。
本仓库只做“部署面可达”的证明链、配置、隔离与供应链核验；任何把 D 项写成
“已支持/可实测”的表述都是不诚实的。

**为什么仍保留 B/C**：B 类是“保障性审计”，用于发现 false trust/持久化/供应链问题；
C 类是“前瞻配置审计”，只在客户确有面时启用。二者都不等于“芯片渗透能力”。

---

## 5. 与真实攻击路径的关系（避免夸大）

| 问题 | 诚实回答 |
|---|---|
| 这些模块能“攻破芯片”吗？ | 不能。A1/A2/A3 是节点/带外/显存层面的真实路径；B 是检测；C 是配置审计；D 不做。 |
| fixture/mock 通过等于现场通过吗？ | 不等于。fixture 只证明解析/验签/差分逻辑；现场必须用客户导出或在线只读。 |
| GPU CC 验签通过等于 GPU 真可信吗？ | 不等于。还取决于 JWKS 来源、nonce 新鲜性、claims 策略、CPU TEE/驱动/固件链；本模块只覆盖 JWT/JWKS/claims。 |
| 固件签名有效等于供应链可信吗？ | 不等于。还取决于 pinned 根、证书轮换、吊销、下载渠道、双人复核；HMAC fixture 明确不算厂商 PKI。 |
| IOMMU 配置有风险等于可利用吗？ | 不等于。还需要设备直通/不可信负载/驱动/内核条件；finding 给前置条件，不执行 DMA 攻击。 |
| MIG/MPS 残留读回等于拿到模型吗？ | 不等于。benign marker 证明“残留可读”；真实数据敏感度取决于租户/生命周期/清零策略。 |

---

## 6. 证据等级与测试映射

| 证据等级 | 本仓库来源 | 能证明 | 不能证明 |
|---|---|---|---|
| fixture | `lab/chipsec_sim.py` 自签 PKI/JWT/固件签名 | 解析、验签、claims、哈希、差分逻辑 | 厂商真实签名、真实设备、生产信任 |
| mock | `lab/chipsec_sim.py` vulnerable/fixed 双态 HTTP | 模块在真实 HTTP/真实文件上的行为差分 | live K8s/GPU/BMC/交换机 |
| export | 客户导出的 cmdline/PCI/TPM/SPDM/IMEX/CXL/固件清单 | 客户现场配置事实（导出可信前提下） | 导出是否最新/完整/未被篡改 |
| live | 在线只读 GET（NRAS JWKS、BMC Redfish） | 端点/证书链/服务状态 | 设备内部执行、真实攻击效果 |

测试入口：

```bash
python -m unittest tests.test_chipsec_sim tests.test_chip_modules tests.test_chip_docs -v
python -m unittest tests.test_verify_effects_chip -v
python -m inkblade.verify-effects --out reports/samples/effects/ --no-docs
```

## 7. 公开来源（2026-10-26 核验）

以下 URL 在 2026-10-26 通过公开文档页核验；只引用规范/厂商文档，不把厂商文档
当作对本仓库的背书。AMD 文档门户为 JS 应用，引用其公开文档编号/直链。

| 来源 | URL | 用途 |
|---|---|---|
| NVIDIA Attestation Suite | https://docs.nvidia.com/attestation/index.html | NRAS/RIM/OCSP 套件、attestation 概念 |
| NVIDIA Attestation Claims Guide | https://docs.nvidia.com/attestation/advanced-documentation/latest/claims-guide/introduction.html | EAT bundle、overall/detached JWT、GPU claims |
| NVIDIA Confidential Computing Attestation | https://docs.nvidia.com/confidential-computing/containers/attestation | CoCo/Trustee 证明流程、TEE 概念 |
| NVIDIA CC 产品页 | https://www.nvidia.com/en-us/data-center/solutions/confidential-computing | Hopper/Blackwell/Rubin CC 支持范围 |
| NVIDIA H100 CC 技术博客 | https://developer.nvidia.com/blog/confidential-computing-on-h100-gpus-for-secure-and-trustworthy-ai | CC-On/DevTools、SPDM 会话、attestation |
| NVIDIA MIG User Guide | https://docs.nvidia.com/datacenter/tesla/mig-user-guide/latest/index.html | MIG 隔离/实例边界 |
| NVIDIA IMEX Guide | https://docs.nvidia.com/multi-node-nvlink-systems/imex-guide/overview.html | IMEX 域、通道、Fabric Manager/NVLSM |
| DMTF SPDM DSP0274 | https://www.dmtf.org/dsp/DSP0274 | SPDM 版本历史（1.4.1 2026-07-02；1.3.3 2025-10-24） |
| DMTF SPDM 1.2 Overview | https://www.dmtf.org/sites/default/files/SPDM_1.2_Overview.pdf | 1.1 安全会话/双向认证、1.2 证书配置 |
| DMTF SPDM 1.3.1 | https://www.dmtf.org/sites/default/files/standards/documents/DSP0274_1.3.1.pdf | SPDM 1.3 规范文本 |
| PCI-SIG DOE ECN | https://pcisig.com/PCI%20Express/ECN/Base/DataObjectExchange | PCIe DOE 扩展能力（2020-03-26） |
| PCI-SIG DOE 1.1 | https://pcisig.com/PCIExpress/ECN/Base/DataObjectExchange_1.1 | DOE 1.1（2022-10-11） |
| PCI-SIG TDISP | https://pcisig.com/PCI%20Express/ECN/Base/TEEDeviceInterfaceSecurityProtocol | TDISP/CMA/SPDM/IDE 关系（2022-08-11） |
| AMD SEV | https://www.amd.com/en/developer/sev.html | SEV/SEV-ES/SEV-SNP 内存加密与证明 |
| AMD VCEK/KDS 规范 | https://docs.amd.com/api/khub/documents/dWGhwYpo1Wv51rJN4d~47g/content | VCEK 证书与 KDS 接口（57230 Rev 1.00） |
| Intel TDX | https://www.intel.com/content/www/us/en/developer/tools/trust-domain-extensions/overview.html | TDX、TME-MK、远程证明 |
| Intel 微码更新指南 | https://www.intel.com/content/www/us/en/developer/articles/technical/software-security-guidance/best-practices/microcode-update-guidance.html | 微码加载/版本/revision 语义 |
| CXL 3.2 发布 | https://computeexpresslink.org/wp-content/uploads/2024/12/CXL_3.2-Spec-Announcement_FINAL-1.pdf | CXL 3.2、TSP/IDE 扩展 |
| CXL IDE 说明 | https://computeexpresslink.org/blog/integrity-and-data-encryption-ide-trends-and-verification-challenges-in-cxl-compute-express-link-2797/ | CXL 2.0 IDE、AES-GCM、TSP 关系 |
| Linux 内核参数 | https://docs.kernel.org/admin-guide/kernel-parameters.html | `iommu=off/pt`、`iommu.passthrough=1`、`iommu.strict=0` |
| Arm SMMUv3 | https://support.arm.com/documentation/ihi0070/ha | SMMUv3 架构（IHI 0070） |
| TCG PC Client Platform Firmware Profile | https://www.trustedcomputinggroup.org/resources/documents/pc-client-specific-platform-firmware-profile-specification | PCR/measured boot/eventlog |
| UAPI UKI | https://uapi-group.org/specifications/specs/unified_kernel_image | UKI 签名、PCR 11、`.pcrsig`/`.pcrpkey` |
| Microsoft Secure Boot db/dbx | https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/oem-secure-boot | Secure Boot db/dbx 语义 |
| NIST SP 800-193 | https://csrc.nist.gov/pubs/sp/800/193/final | 平台固件韧性/签名更新 |

---

## 8. 诚实边界（必须随报告阅读）

1. **无真实 GPU/BMC/交换机/CXL 验证**：所有芯片姿态结论来自 fixture/mock/客户导出；
   没有在真实 H100/H200/GB200、真实 BMC、真实 CXL 设备上执行。以下能力**未证明**：
   真实厂商证明链、真实固件签名链、真实 IOMMU 直通利用、真实 MIG/MPS 残留读取。
2. **没有 NRAS 生产 JWT**：仓库 fixture 使用公开的自签 RSA 密钥；真实环境必须换
   NRAS JWKS 与设备证明。`JWKS 缓存`不等于实时信任。
3. **SPDM/IMEX/CXL 是 C 级 research-only**：默认关闭；即使有面也不进入默认链；
   报告不得把它们计入“芯片渗透能力”。
4. **D 级实验室项不做**：RTL/GDSII/DFT、功耗电磁、毛刺/激光、开盖、逆向、
   counterfeit、Rowhammer/微架构侧信道实操均不在本仓库范围。
5. **写类只有 benign marker**：`gpu-memory-residue-isolation` 是唯一写类芯片模块，
   必须经 runner 备份闸门；不读取/覆盖真实租户数据。
6. **不把 A 类 finding 写成“已攻破”**：A1/A2/A3 给的是可复核的配置/生命周期证据与
   前置条件；真实利用仍需授权、目标和窗口。
