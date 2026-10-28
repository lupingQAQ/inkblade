# 预训练 / SFT / RL 训练栈覆盖矩阵（2026-10-26）

本文回答三个问题：**训练栈的攻击面我们覆盖到哪、证据是什么、离真实企业还差什么**。
范围：预训练（Megatron-LM / DeepSpeed 配置与 checkpoint）、SFT（LLaMA-Factory /
ms-swift / TRL）、RL（rollout 缓冲 / 奖励信号）三条栈，共 10 个新增模块。

> 边界先行：全部证据来自本机 `127.0.0.1` 的 `lab/trainstack_sim.py`（真实 HTTP + 真实文件
> 落盘）与上游源码只读快照；**不是真实 GPU 集群 / 真实训练作业**。真实环境缺口逐项列在第 3 节。

## 1. 结论

| 项 | 结果 |
|---|---|
| 新增模块 | 10（纯小写键，只读 4 / 写类 6；写类全部走 `backup_targets` 备份校验） |
| 两态差分 | vulnerable 10/10 产出 high；fixed 10/10 无 high（读面 401 / 写面 401/403 / 奖励指标健康） |
| 实效验证 | `verify-effects` 新增 3 项：optimizer state 写读回、数据篡改检出、模板注入检出（均 PASS） |
| 0day 挖掘 | 5 个最新 release 快照、70 条 `pending-manual-review` 候选（high 10 / medium 60），**不自动入库** |
| 测试 | `tests/test_trainstack_sim.py` 21 + `tests/test_trainstack_modules.py` 18 + `tests/test_trainstack_mining.py` 10 |

## 2. 逐项覆盖矩阵（栈 × 攻击面 × 模块 × 证据）

| # | 栈 | 攻击面 | 模块（系列/级别） | 靶场可复现证据 | 真实环境缺口 |
|---|---|---|---|---|---|
| 1 | 预训练 | Megatron/DeepSpeed 主配置：world_size、TP/PP/EP/CP/SP、共享 checkpoint/optimizer 目录、`trust_remote_code`、rendezvous 后端 | `megatron-deepspeed-config-surface`（侦察/主动探测） | `GET /train/config` 200；world_size=512、五维并行度齐全、`HF_TOKEN`/`WANDB_API_KEY` 可读；fixed 401 + 脱敏 | 真实 Megatron `arguments.py` 的参数面更宽（--use-distributed-optimizer、--data-path 等），需真实作业模板才可核对 |
| 2 | 预训练 | torchrun 弹性 rendezvous：etcd 无鉴权/无 TLS/动态成员/伪 rank 注入 | `torchrun-elastic-surface`（网络架构/主动探测） | `GET /train/elastic` 200：`rdzv_backend=etcd`、`etcd_auth=none`、`tls=false`、4 成员可见；fixed 401（mTLS+固定成员） | 真实 `c10d`/etcd 注册握手、成员超时与 re-rendezvous 行为未实测 |
| 3 | 预训练 | checkpoint optimizer state（step/exp_avg/exp_avg_sq）分片写面 | `checkpoint-optimizer-state-poison`（横向利用/利用验证） | POST 写 benign marker → GET 读回 sha256 一致 → 文件真实变更 → rollback 精确复原 | 真实 ZeRO-3/Megatron 分片格式（`zero_pp_rank_*.pt`、`optim_states.pt`）与加载器校验未验证 |
| 4 | 预训练/SFT | 数据管线：webdataset/Arrow/parquet 分片追加、重复/未知 id、采样顺序 | `data-pipeline-poison`（横向利用/利用验证） | manifest vs sampler 重算 sha256：`tamper_detected=true`、expected≠actual、duplicate≥1、unknown≥1、order_changed=true | 真实 WebDataset tar/Arrow IPC 分片需对象存储与 `datasets` 缓存层验证；当前为 JSONL 语义等价 |
| 5 | SFT | chat template / default_system / 特殊 token 注入 | `tokenizer-template-injection`（横向利用/利用验证） | 模板 sha256 变化 + `system_block` 含 run marker + `injected_directive=true` + `sanitized=false`；fixed 写面 401 + 渲染转义 | 真实 Jinja2 沙箱边界、`apply_chat_template` 的 `add_generation_prompt` 分支与 tokenizer 保留 token 白名单未逐一核对 |
| 6 | 全栈 | MLflow / W&B / TensorBoard 未授权与凭据 | `experiment-tracker-exposure`（窃取与数据泄露/主动探测） | 跨租户 run 列表、MLflow `auth=none` + s3 artifact root、W&B key 仅尾 4 位入 finding；fixed 401 | 真实 MLflow `--backend-store-uri` + basic-auth 插件、W&B service account、TensorBoard 多租户目录策略未验证 |
| 7 | SFT | LLaMA-Factory / ms-swift / TRL 无鉴权、`file://` 数据路径、`trust_remote_code`、跨租户数据集 | `sft-framework-surface`（横向利用/利用验证） | `0.0.0.0:7860` + `auth=false` + `allow_file_scheme=true` + 提交任务被接受 + `tenant-b` 数据集可见；fixed 401 | 真实 WebUI 鉴权（`.env`/反代）、训练任务真实执行与数据读取路径未验证（只记录不执行） |
| 8 | RL | rollout/replay 缓冲跨租户写读、轨迹篡改 | `rl-rollout-buffer-poison`（横向利用/利用验证） | tenant-a 以 tenant-b 身份写入 → 服务端 `cross_tenant=true` → 读回 marker + sha256；fixed 跨租户 403 | 真实 vLLM rollout worker / GRPO 采样器、Ray 对象存储与 IPC 桶隔离未验证 |
| 9 | RL | 奖励作弊：奖励升但能力不升、长度膨胀、KL 坍塌、熵下降、裁判一致率下降、同质化、训练-评测差距 | `reward-hacking-detect`（情报/主动探测） | 7 项独立信号中 ≥3 项命中才 high（vulnerable 7/7；fixed 0/7）；单指标不结论 | 真实 reward model / LLM-as-judge 的评分分布与人工标注一致性需真实训练数据 |
| 10 | 预训练 | K8s Job / Ray / Slurm 提交面：共享 trainer-admin SA、hostPath=/、privileged、hostNetwork | `pretrain-job-escape`（权限链/利用验证） | 提交 200 + 读回 `service_account=trainer-admin`、`host_path=/`、`privileged=true`（3/3 原语）；fixed 403 | 真实 K8s 准入（PSA/Kyverno）、Ray job submission、Slurm `sbatch` 包装与 cgroup 逃逸未执行 |
| G1 | 预训练 | NCCL/IB 集合通信与 checkpoint 原子性（真实训练步） | 未新增（已有 `nccl-*`/`fabric-*` 系列覆盖网络层） | 见 `docs/FABRIC-ATTACK-SURFACE.md` 与 `verify-effects` 的 SHARP/PFC/straggler 三项 | **必须真集群**：真实 NCCL 版本、IB SHARP 交换机、NVLink/NVSwitch 拓扑 |
| G2 | 预训练 | WebDataset 对象存储（S3/MinIO）分片投毒与缓存投毒 | 未新增（`cloud-bucket-cross-tenant` 覆盖桶策略面） | 桶策略/列目录 mock 证据 | **必须真实对象存储**：S3 版本化/对象锁、`datasets` 本地缓存哈希 |

## 3. 与真实企业的差距（哪些必须真集群）

必须真实环境才能成立的结论（当前一律不宣称）：

1. **真实训练作业与权重格式**：ZeRO-3 分片命名、Megatron `torch_dist` checkpoint、`.safetensors` 校验；
   本仓库以 JSON/文本分片表达"可写面"，证明的是**访问控制与完整性检测语义**，不是具体序列化漏洞。
2. **真实 rendezvous 与集合通信**：etcd/c10d 注册、成员超时、NCCL bootstrap、IB SHARP 聚合；
   仿真只覆盖"配置可读 + 无鉴权 + 动态成员"这一层。
3. **真实调度器准入**：K8s PSA/Kyverno/Gatekeeper、Ray job submission、Slurm `sbatch`/`srun`；
   仿真验证的是"提交面接受危险原语"，不是"Pod 真的挂载了宿主根"。
4. **真实 SFT/RL 框架运行**：LLaMA-Factory WebUI 鉴权、ms-swift/TRL 训练入口、vLLM rollout worker；
   模块只读配置与提交记录，不执行训练。
5. **真实实验追踪器**：MLflow backend store 鉴权、W&B service account、TensorBoard 多租户目录 ACL。
6. **版本矩阵未扩展**：`core/data/version-matrix.json` 尚未为 Megatron/DeepSpeed/LLaMA-Factory/
   ms-swift 建立"指纹 → 受影响版本 → 修复版本"条目；在人工复核候选前**不臆造修复版本**
   （与矩阵 `fixed=null` 诚实性约束一致）。TRL 已有产品条目，但新增模块未挂矩阵。
7. **许可边界**：上游快照仅只读分析（Apache-2.0，SPDX 保留）；不复制上游代码进模块。

## 4. 只读试点建议（企业落地顺序）

阶段 0（只读，1–2 天，零写面）：

- 运行 `megatron-deepspeed-config-surface`、`torchrun-elastic-surface`、
  `experiment-tracker-exposure`、`reward-hacking-detect` 四个只读模块；
- 采集：训练配置/环境变量名（值脱敏）、rendezvous 端点与成员、追踪器 run 列表与鉴权姿态、
  RL 指标序列；
- 出口：一份"训练栈暴露面基线"报告 + 需整改项（401/鉴权/脱敏/TLS）。

阶段 1（读 + 提交面观察，需变更审批）：

- 增加 `sft-framework-surface` 的 probe-only 与 `pretrain-job-escape` 的 probe-only；
- 只读调度器提交面与数据集可见性，不提交任何作业；
- 出口：SFT/作业提交面的鉴权与租户隔离结论。

阶段 2（写类，需书面授权 + 备份校验 + 回滚演练）：

- `checkpoint-optimizer-state-poison` / `data-pipeline-poison` / `tokenizer-template-injection` /
  `rl-rollout-buffer-poison` / `pretrain-job-escape`（backup-write）；
- 先在**非生产副本**（checkpoint 副本、数据分片副本、模板副本、回放缓冲副本）验证；
- 每步必须提供 `backup_targets`（file 快照），执行后立即 `rollback` 并核对 sha256；
- 出口：写面可回滚证明 + 检出规则（sha256/采样顺序/模板基线）落地为监控项。

阶段 3（真集群，按 G1/G2 缺口补测）：

- KIND/k3s 验证 PSA 与 NetworkPolicy；真实 Slurm/Ray 提交面；
- 真实对象存储（MinIO/S3）分片与缓存投毒；
- 真实 MLflow/W&B 鉴权；
- 出口：把仿真结论升级为真实环境结论，或在报告中明确标注"未验证"。

## 5. 0day 挖掘结果（pending，不自动入库）

| 目标 | 仓库 | tag（2026-10-26 核验） | 候选数 | 主要命中规则 |
|---|---|---|---|---|
| megatron | NVIDIA/Megatron-LM | `core_v0.19.2` | 4 | `torch-load-any`、`wandb-checkpoint-hook` |
| deepspeed | deepspeedai/DeepSpeed | `v0.19.8` | 14 | `torch-load-unsafe`（stage3 optimizer state）、`subprocess-popen`、`env-rank-read` |
| llamafactory | hiyouga/LlamaFactory | `v0.9.5` | 20 | `apply-chat-template-dynamic`、`bind-all-interfaces`、`trust-remote-code-propagated` |
| msswift | modelscope/ms-swift | `v4.6.0` | 7 | `load-dataset-any`、`apply-chat-template-dynamic` |
| trl | huggingface/trl | `v1.16.0` | 25 | `apply-chat-template-dynamic`、`load-dataset-any`、`trust-remote-code-propagated` |

- 登记册：`reports/samples/mining-trainstack/zeroday/registry/candidates/*.json`（70 条）；
- 报告：`reports/samples/mining-trainstack/mining-report.json`；
- 独立基线：`inkblade/data/trainstack-mining-baseline.json`（不污染推理栈基线）；
- 每条候选均为 `status=pending-manual-review`，note 明示"规则命中≠漏洞；须人工复核可达性与
  可利用性后方可建模块；不自动入库"。
- 复核优先级建议：`torch-load-unsafe`（DeepSpeed stage3 optimizer state，`weights_only=False`
  直接反序列化）> `trust-remote-code-propagated`（配置可控 → 任意仓库代码执行）>
  `subprocess-popen`（launcher 参数拼接）> 模板/数据链。

**诚实声明**：70 条候选全部是"静态规则命中"，不是 0day 结论；其中可能包含设计内行为
（例如 `torch.load` 用于加载本机可信 checkpoint）。未做人工可达性复核前，不得对外称"发现 N 个 0day"。

## 6. 证据与复现

```bash
python -m unittest tests.test_trainstack_sim tests.test_trainstack_modules tests.test_trainstack_mining -v
python -m inkblade.verify-effects --out reports/samples/effects/       # 含 3 项训练栈实效
python -m inkblade mine --trainstack --out reports/samples/mining-trainstack
```

| 产物 | 路径 |
|---|---|
| 靶场 | `lab/trainstack_sim.py`（29 路由，双态） |
| 模块 | `inkblade/modules/{megatron-deepspeed-config-surface,torchrun-elastic-surface,checkpoint-optimizer-state-poison,data-pipeline-poison,tokenizer-template-injection,experiment-tracker-exposure,sft-framework-surface,rl-rollout-buffer-poison,reward-hacking-detect,pretrain-job-escape}/` |
| 共享库 | `inkblade/modules/_trainstack-common.py` |
| 静态规则 | `inkblade/core/data/sink-rules.json`（新增 9 条 + 2 组合签名；样本锚 `lab/sample-vuln-repo/trainstack.py`、`job.yaml`） |
| 上游快照 | `lab/mining-fixture/{megatron,deepspeed,llamafactory,msswift,trl}/` |
| 实效验证 | `inkblade/verify-effects.py` 的 `trainstack-*` 三项；报告 `docs/EFFECT-VERIFICATION.md` |
| 覆盖文档 | 本文件 |

## 7. 未覆盖与后续

- **未覆盖**：真实 GPU 训练步/集合通信（G1）、真实对象存储分片（G2）、真实调度器准入执行、
  真实 SFT/RL 训练执行、DeepSpeed/Megatron 具体 CVE 版本区间（版本矩阵未扩展）。
- **下一步**：对 70 条候选中 high 的 10 条做人工可达性复核（输入是否来自请求/配置/租户数据）；
  复核通过者再建私有模块（走零日校验），未通过者在候选 note 中记录"设计内行为"。
- **反向收益**：把 `checkpoint sha256`、`sampler manifest 校验`、`模板基线 sha256`、
  `跨租户轨迹隔离` 四条检测语义固化为企业监控项，可在不写任何数据的前提下持续发现篡改。
