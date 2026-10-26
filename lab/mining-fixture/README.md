# mining-fixture — 挖掘流水线上游源码快照（最新 release tag）

用途：`inkblade/mining.py`（漏洞挖掘流水线闭环）对「最新版本差异复核」环的输入。
每目录 = 一个上游仓库在最新 release tag 的代表性源文件（raw.githubusercontent.com / jsDelivr
GitHub 镜像快照，逐文件 HTTP 200），供 `codescan` 双通道（regex；.py 走 ast）提取 sink 命中
并与 `core/data/sink-rules.json` 差异（基线：`inkblade/data/mining-baseline.json`）。

## 推理栈（2026-10-25 抓取，基线 `inkblade/data/mining-baseline.json`）

| 目标 | 仓库 | tag | 文件 | 抓取方式 |
|---|---|---|---|---|
| vllm | vllm-project/vllm | v0.32.0 | api_server.py（弃用 shim）、routers.py、api_server_entry.py、serve_init.py、models_api_router.py | Invoke-WebRequest raw |
| sglang | sgl-project/sglang | v0.5.22 | http_server.py（管理路由面） | 同上 |
| kuberay | kuberay-project/kuberay | v1.7.1 | raycluster_controller.go（控制器） | 同上 |
| hami | Project-HAMi/HAMi | v2.10.0 | main.go（scheduler 入口：/filter /bind /webhook 路由 + pprof 旗标） | 同上 |
| litellm | BerriAI/litellm | v1.106.4 | proxy_server.py（proxy 管理面） | 同上 |

## 训练栈（2026-10-26 抓取，基线 `inkblade/data/trainstack-mining-baseline.json`）

tag 以 GitHub `releases/latest`（2026-10-26 核验）为准；文件经 raw.githubusercontent.com /
`cdn.jsdelivr.net/gh/<repo>@<tag>/<path>` 取回（字节一致）。

| 目标 | 仓库 | tag | 文件 | 关注面 |
|---|---|---|---|---|
| megatron | NVIDIA/Megatron-LM | core_v0.19.2 | yaml_arguments.py、checkpointing.py、dist_checkpointing/strategies/torch.py（落盘名 torch.py） | 训练配置 yaml 解析、checkpoint torch.load、wandb checkpoint 回调 |
| deepspeed | deepspeedai/DeepSpeed | v0.19.8 | runtime/engine.py、runtime/zero/stage3.py、launcher/runner.py、launcher/multinode_runner.py | optimizer state 加载（weights_only=False）、Slurm/ssh 拉起的 subprocess、LOCAL_RANK 环境变量 |
| llamafactory | hiyouga/LlamaFactory | v0.9.5 | src/llamafactory/data/template.py、model/loader.py、api/app.py、webui/interface.py | chat template 渲染、trust_remote_code 传播、0.0.0.0 绑定、file:// 数据路径 |
| msswift | modelscope/ms-swift | v4.6.0 | swift/template/base.py、dataset/loader.py、pipelines/train/sft.py、rollout/agent_loop.py | apply_chat_template、load_dataset、SFT 数据链、rollout 回放 |
| trl | huggingface/trl | v1.16.0 | trl/trainer/sft_trainer.py、trainer/utils.py、scripts/sft.py、data_utils.py | SFT 数据装载、trust_remote_code 传播、chat template 工具、MASTER_ADDR 默认值 |

许可：上游均为 Apache-2.0（Megatron-LM/DeepSpeed/LLaMA-Factory/TRL）或 Apache-2.0
（ms-swift），源文件头 SPDX 保留；快照仅作只读分析输入，零代码复用。

边界：命中 = sink 规则命中，非可利用性结论；候选一律 `pending-manual-review`（不自动入库）。
新增训练栈 sink 规则的样本锚在 `lab/sample-vuln-repo/trainstack.py` 与 `job.yaml`
（编造代码，仅用于规则自检）。
