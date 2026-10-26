# 语料检索覆盖声明（RESEARCH-COVERAGE）— 万卡语料推倒重收

- 检索/核验日期：**2026-10-25**（全部来源当日完成）
- 检索工具：`websearch`（检索式见下）+ `webfetch`（官方页直读，原文摘录入库）
- 语料与门槛：`inkblade/arch-intel/corpus/{official-cn,official-en,paper}/`（80 源）+ `inkblade/arch-intel/coverage-matrix.json`；门槛校验 `inkblade/arch-intel/check.py`（全绿）
- 任务口径：≥10k GPU/加速器实践（万卡证据源）＋ 官方技术博客优先 ＋ 中外并收

## 1. 中文官方源检索式（websearch，2026-10-25）

| 目标组织 | 检索式（可复现） | 命中与入库 |
|---|---|---|
| 字节/火山引擎 | `火山引擎 万卡集群 官方 新闻 大模型训练`；`火山引擎 官网 新闻 veInfra 高性能计算网络 RDMA 发布会`；`火山引擎 机器学习平台 万卡` | 官方文档（HPC 集群 RDMA 互通/隔离）入库：volcengine-hpc-rdma；万卡级表述为 2023-04 发布会口径（媒体通稿佐证，不计万卡证据）；MegaScale 12,288 卡证据保留在 paper/bytedance-megascale |
| 阿里云 | `阿里云 官方 单一集群 10万卡 GPU 灵骏 智算`；`阿里云 HPN 8.0 云栖大会 官方 AI基础设施 13万卡` | aliyun-lingjun（官方产品页+帮助中心：十万卡级 HPN、单层千卡/两层万卡）入库；HPN 8.0/13 万卡为云栖发布会经媒体转述（财联社/eet-china），未取得官方页原文——**不单独入库，仅背景**；ACES 未检索到官方原文（见未找到项） |
| 腾讯云/腾讯 | `腾讯 星脉网络 2.0 官方发布 10万卡 AI算力网络`；`腾讯云 官网 新闻发布 星脉网络2.0 自研 tencent.com`；`TCCL 星脉 通信库 文档` | tencent-xingmai-2（10 万卡/TiTa2.0/TCCL2.0/分钟级故障定位）+ tencent-tccl-docs（官方文档）入库 |
| 华为云/昇腾 | `华为云 昇腾 万卡集群 官方 发布 ModelArts`；`昇腾 万卡级 算力集群 稳定性` | huawei-ascend-cloud（16 万卡/总线替代以太）+ huawei-ascend-10k-stability（可用度 98%/秒级恢复）入库 |
| 百度 | `百度智能云 万卡集群 官方发布 昆仑芯 PaddlePaddle` | baidu-kunlun-10k（国内首个自研万卡点亮+3 万卡+HPN 网络带宽有效性 90%）入库；PaddlePetal 未检出（疑为任务笔误，未找到该名称官方物） |
| DeepSeek | `DeepSeek 官方 公众号 技术报告 V3 基础设施 集群 H800` | deepseek-api-docs（官方更新日志，无集群规模披露，如实入库）；V3 规模口径 2048×H800 保留在 paper/deepseek-prefill-decode |
| 月之暗面 Kimi | `月之暗面 Kimi K2 官方 发布 训练集群 公众号` | 官方站（kimi.com/platform）无集群规模披露；K2/K2.5 报告规模未见 ≥10k 官方口径——**未入库**（避免以媒体推测入库） |
| 智谱 GLM | `智谱 GLM 万卡集群 昇腾 官方 训练`；`智谱 1吉瓦 数据中心 国产芯片 万卡 官方公告 GLM-5` | 1GW 数据中心/10 万卡经彭博/财联社报道（智谱官方确认转述），未见官方页面原文；hiascend 官方动态（GLM-5 训练复现）无规模与网络细节——**未入库，记录缺口** |
| MiniMax | `MiniMax 官方 公众号 万卡集群 训练 infra M1 H800` | minimax-m1（官方新闻：512×H800，如实标注未达万卡）入库 |
| 阶跃星辰 | `阶跃星辰 StepFun 官方 万卡集群 Step-2 昇腾 训练` | 官方渠道无万卡披露（媒体访谈提"团队实践过单集群万卡以上"）——**未入库，记录缺口** |
| 商汤大装置 | `商汤 大装置 SenseCore 万卡集群 临港 官方` | 官方站仅总算力 1.2 万 PFLOPS 与"千卡级国产集群"口径，无 ≥10k 卡数官方原文——**未入库，记录缺口** |
| 快手 | `快手 可灵 万卡集群 官方 快手技术团队 大模型训练` | 官方 IR 新闻（可灵发布）无集群规模/网络细节——**未入库，记录缺口** |
| 美团 | `tech.meituan.com 美团技术团队 LongCat 万卡 国产算力 集群 训练` | meituan-longcat-2（官方博客：五万卡国产集群全流程训练推理，原文摘录）入库 |
| 京东 | `美团 京东 官方 万卡集群 大模型 训练 GPU 算力`＋直读 developer.jdcloud.com/article/4224；`京东云 摩尔线程 十万卡` | jdcloud-jiushu（千卡已建+25 年万卡规划，如实标注）+ jd-mthreads-10w（拟建十万卡，规划口径）入库 |
| 运营商/国家级 | `中国电信 官方 万卡池 京津冀 智算集群 发布`；`中国移动 智算中心（呼和浩特）万卡 官方`（检索工具 401 中断未复跑） | china-telecom-10k（两大单集群万卡池）+ sasac-telecom-10k（国资委：全国首个投运单池万卡，21.5EFLOPS/400G 全光骨干）入库；人民日报 42 万卡集群统计（快照佐证，partial）入库 |

## 2. 外文官方源检索式（websearch，2026-10-25）

| 目标组织 | 检索式（可复现） | 命中与入库 |
|---|---|---|
| Meta Engineering | `engineering.fb.com Building Meta's GenAI Infrastructure 24k H100 clusters`；`engineering.fb.com "RDMA over Ethernet" distributed AI training Meta scale blog`；`Meta infrastructure evolution 129K-GPU` | meta-genai-infra（24,576×2+350k H100）、meta-roce-blog（Clos/ECMP/QP scaling/弃 DCQCN+CTS）、meta-infra-evolution（129k→Prometheus 1GW→Hyperion 5GW）入库 |
| xAI | `xAI Colossus 2 official blog 200,000 GPUs gigawatt x.ai` | x.ai ECONNREFUSED（不可达）；xai-colossus 维持 verified-partial（快照：doubled in 92 days to 200k GPUs）；Colossus 2 细节由 gen-26 批次 xai-colossus-two 覆盖 |
| Microsoft/OpenAI | `Microsoft Azure official blog AI supercomputer OpenAI "tens of thousands" GPUs InfiniBand ND series`；`Microsoft "Aether" AI supercomputer Azure official`；`Azure AI superfactory Aether architecture blog infinite scale` | msft-fairwater-superfactory、msft-fairwater-wisconsin、msft-openai-sc-2020（10,000 GPU/400G 原句）入库；openai-nvidia-10gw（10GW/数百万 GPU）入库；**"Aether"未在官方博文正文出现**（仅评论区/转述提及）——以 Fairwater/AI superfactory 官方口径收录并在此声明 |
| Google | `Google official blog Jupiter data center network Ironwood TPU pod 9216 chips`；`blog.google Jupiter network data center era` | google-ironwood（blog.google：9,216 芯片 superpod+ICI 9.6Tb/s）入库；cloud.google.com 拒连（既有缺口延续），google-next26-80k 以快照佐证（80k GPU/单 DC、960k 跨区域）partial 入库；Jupiter 论文（OCS）partial 入库 jupiter-evolving |
| AWS | `AWS News Blog Project Rainier Trainium2 nearly 500,000 chips Anthropic official` | aws-project-rainier（近 50 万 Trainium2/NeuronLink+EFA 两级）入库；P6e-GB200/Trn2 UltraServer 官方页本轮未直读（gen-26 批次 aws-trainium-ultraserver 已覆盖） |
| NVIDIA | `NVIDIA newsroom Spectrum-X 800G Quantum-X800 InfiniBand SHARP in-network computing announcement`；`NVIDIA Spectrum-X Ethernet AI fabric official page adaptive routing congestion control` | nvidia-spectrum-x（multiplane/128K/100k-GPU xAI 系统/性能隔离/XGS 跨 DC）入库；nvidia-quantum-x800 撞名条目归 gen-26 批次（其内容含 SHARP v4/遥测 CC）；SHARP 专条见 gen-26 nvidia-sharp-in-network |
| Anthropic/Mistral/Cohere | `Anthropic engineering blog cluster infrastructure OR Cohere training infrastructure blog OR Mistral AI infrastructure blog GPUs` | 三家均无集群/网络架构官方披露（Anthropic 工程博客无 infra 集群文；Cohere 仅为科普文）——**未找到，如实声明**；Anthropic 侧容量证据经 aws-project-rainier（官方）覆盖 |
| Ultra Ethernet | `Ultra Ethernet Consortium 1.0 specification announcement official ultraethernet.org`；`UEC specification 1.1` | uec-spec（1.0 2025-06-11+1.1 2026-10：INC/CSIG/PCM 原句）入库；生态条目见 gen-26 批次（ultra-ethernet-*） |
| Meta Polar/智能网卡 | `Meta "Polar" smart NIC AI network OCP 2025` | **未检索到任何官方来源**（疑为口误/未公开项目），未入库 |
| OCS/光交换 | `Google OCS Jupiter`；`optical circuit switching data center network Google Arista` | google-tpu-oci（既有 ISCA 论文条目，OCS 重构即安全边界）+ jupiter-evolving（partial）覆盖；Arista 未单独入库（其官方博客为 UEC 解读，非万卡实践） |
| SONiC | `SONiC software open network Linux Foundation sonic-net official Microsoft Azure blog announcement` | sonic-foundation（LF 官方站+Azure 官方博文原句）入库；白盒安全条目见 gen-26 sonic-whitebox-security |
| Oracle | `Oracle OCI supercluster 16384 H100 official newsroom zettascale` | oracle.com 403（WAF 不可达）——oracle-zettascale 以官网快照原句 partial 入库（16,384 H100/13Pb/s；131,072 B200） |

## 3. 检索缺口与处理（未找到/不可达清单）

1. **不可达（显式标注于矩阵 notes 与各源 verification.method）**：x.ai、cloud.google.com、oracle.com、dl.acm.org、paper.people.com.cn、docs.volcengine.com（JS）、mthreads.com（JS）、azure.microsoft.com（单篇超时，改用 sonicfoundation.dev+Fairwater 博文替代）。
2. **未找到官方来源（不编造）**：Anthropic/Mistral/Cohere 集群官方博客、Meta Polar 智能网卡、阿里云 ACES 官方原文、HPN 8.0 官方页原文、Kimi/智谱/阶跃/商汤/快手的官方万卡口径、百度 "PaddlePetal"。
3. **规划/能力口径不计万卡证据**：jd-mthreads-10w（拟建）、jdcloud-jiushu（25 年规划）、nvidia-quantum-x800 与 uec-spec（平台能力宣称）。
4. **partial 源不计门槛**：xai-colossus、google-next26-80k、oracle-zettascale、jupiter-evolving、people-daily-42-wanka。

## 4. 与并行任务的边界

- gen-26 fabric 面任务新增 13 源（`batch=gen-26-fabric`）与本任务 32 新增源合并为一套矩阵/门槛；`nvidia-quantum-x800` 同名条目归 gen-26（内容一致覆盖 SHARP v4）。
- 若 gen-26 后续再写 `coverage-matrix.json`，以其重建逻辑（从 corpus 目录+其条目）会保留本任务 corpus 文件；`added_this_round`/`wanka_evidence` 字段如被剥离，以本文件与 git 历史（本 commit）为准恢复。
