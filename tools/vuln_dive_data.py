"""Narrative data for the six architecture primers inside the ten layers.

Each primer is rendered inside its host layer, before the per-entry attack
surface list.  Terms are also merged into the global glossary by the document
builder, so the primer and the glossary cannot drift.
"""

from __future__ import annotations

PRIMERS = {
    "cache": {
        "layer": 8,
        "title": "缓存：命中、复用与残留",
        "intro": (
            "推理缓存把“相同前缀”当成“相同计算”：命中就跳过 prefill，直接复用 KV。"
            "收益来自复用，风险也来自复用——缓存键一旦不含租户/盐，命中就等价于跨租户读状态。"
        ),
        "analogy": "像共享自习室的储物柜：柜号只按书包花色算，不看是谁的卡；同花色书包就能开同一个柜。",
        "diagram": """\
client A ──prefix P──> [ gateway ] ──key=hash(P)+tenant+salt──> [ cache index ]
                                                             │ hit
                                                             ▼
                                              [ KV blocks / response ] ──> A
client B ──prefix P──> [ gateway ] ──key=hash(P)──────────────┘
                                                             │ miss? 否：命中 A 的块
                                                             ▼
                                              [ 读到 A 的 KV / 响应 / 残留 ]
""",
        "terms": [
            ("KV cache", "推理时缓存的 key/value 张量；每个 token 一层，序列越长占用越大，是缓存泄露的载体。"),
            ("prefix cache", "按 token 前缀哈希复用 KV 的机制；命中跳过 prefill，键的隔离强度决定租户边界。"),
            ("radix tree", "SGLang RadixAttention 用的前缀树；共享节点省显存，但树命中统计会暴露“谁来过”。"),
            ("PagedAttention", "把 KV 切成固定大小 block、按页表映射的显存管理法；块 ID 可枚举时也是越权入口。"),
            ("semantic cache", "按语义相似度而非精确 token 命中；阈值越宽，越容易把别人的答案当成自己的。"),
            ("approximate cache", "近似缓存/向量检索缓存的统称；先检索后按租户过滤的顺序错了就会跨租户。"),
            ("cache key", "缓存条目的身份；正确形式是 hash(prefix)+tenant+salt，缺一项都不是租户隔离。"),
            ("cache salt", "请求级盐，参与缓存键派生；服务端强制才有效，请求可选就等于可关闭。"),
            ("TTL", "条目存活时间；TTL 太长放大残留窗口，太短降低命中率，安全与成本在这里拉扯。"),
            ("eviction", "逐出策略（LRU/LFU/容量压力）；只释放索引不清零，块仍可能被下一个租户读到。"),
            ("hit / miss", "命中/未命中；命中差异会同时改变 TTFT、计费、日志与可观测指标。"),
            ("TTFT", "Time To First Token；命中通常显著下降，因此时延差可以反推前缀成员关系。"),
            ("remote KV pool", "Mooncake/LMCache 风格的跨实例 KV 池；块 ID、命名空间、后端 ACL 三者共同构成边界。"),
            ("PD KV transfer", "Prefill 节点把 KV 块传给 Decode 节点的通道；NIXL/RDMA 常缺 mTLS 与块归属校验。"),
        ],
        "rows": [
            ("跨租户前缀命中", "懂 prefix cache 键派生与 cached_tokens 语义", "KV/响应泄露、成员推断、计费污染", "第 8 层逐条"),
            ("近似缓存误命中", "懂向量相似度阈值与租户过滤顺序", "商业数据/系统提示泄露、错误归因", "第 8 层逐条"),
            ("逐出残留", "懂 LRU 索引与显存清零的差别", "前租户模型/激活残留、持久化投毒", "第 8 层逐条"),
            ("远程 KV 池越权", "懂块 ID、命名空间与后端 ACL", "跨租户 KV 读写、推理操纵", "第 8 层逐条"),
            ("TTFT 侧信道", "懂命中/未命中时延分布与统计功效", "前缀字典提取、成员确认、隐蔽侦察", "第 8 层逐条"),
        ],
    },
    "longctx": {
        "layer": 1,
        "title": "长上下文：窗口、prefill 与 KV 增长",
        "intro": (
            "长上下文不是“把 max_tokens 调大”。窗口决定准入与 KV 预留，prefill 决定首 token 成本，"
            "decode 决定持续显存；三者任一没按实际 token 计数，就会把长度变成 DoS 或泄露面。"
        ),
        "analogy": "像电影院按票面座位卖票，却不数实际进场人数；一张“全场通票”能把整厅占满。",
        "diagram": """\
prompt (128K..1M tokens)
      │
      ▼
[ tokenizer ] -> token 数 -> [ admission: window / quota ]
      │
      ▼
[ prefill: attention over prompt ] ──> KV blocks (O(n) 显存)
      │                                   │
      ▼                                   ▼
[ first token / TTFT ]             [ decode: 逐 token 追加 KV ]
                                          │
                                          ▼
                              [ prefix cache / PD transfer / eviction ]
""",
        "terms": [
            ("context window", "模型单次可处理的最大 token 数（128K/1M）；准入必须按实际 token，不是声明值。"),
            ("token", "模型的最小输入单位；字节数≠token 数，按字符估算会给超窗留下空间。"),
            ("prefill", "一次性计算整段 prompt 的阶段；算力密集、决定 TTFT，也是 KV 分配的起点。"),
            ("decode", "逐 token 生成阶段；每步追加 KV，长输出把显存占用线性拉长。"),
            ("attention 复杂度", "标准 attention 对序列长度是 O(n²)；FlashAttention/稀疏化降低常数但不改变增长趋势。"),
            ("RoPE", "旋转位置编码；把位置写进 Q/K 的旋转角，外推能力决定超长窗口是否还可信。"),
            ("位置外推", "YaRN/NTK/线性缩放等把训练窗口拉长的方法；外推过头会输出退化而非直接报错。"),
            ("KV 增长", "KV 字节随层数×头数×维度×token 数增长；1M 窗口下单请求可达 GB 级。"),
            ("context flooding", "用大量超长请求占满 prefill 队列/KV 配额；单请求成本低，集群影响大。"),
            ("attention sink", "模型把大量注意力放在首 token 的现象；滑窗/截断会改变 sink，导致行为漂移。"),
            ("滑窗 / 截断", "只保留最近 N 个 token 或截断超长输入；静默截断会让模型“看不见”关键指令。"),
            ("cache 复用", "长上下文与 prefix cache 叠加时，前缀命中既省算力也放大跨租户泄露面。"),
            ("ring attention", "Context Parallel 下 KV 沿 ring 逐跳传递；环成员就是信任边界。"),
            ("context limit bypass", "声明窗口与实际 token 不一致仍被接受；后果是队列 DoS 与 KV 放大。"),
        ],
        "rows": [
            ("超窗请求被接受", "懂 token 计数、准入与 prefill 队列", "prefill DoS、GPU 饥饿、SLA 违约", "第 1 层逐条"),
            ("KV 内存放大", "懂按声明窗口预留与按实际 token 预留的差别", "单请求 GB 级 KV、OOM、邻居受影响", "第 1 层逐条"),
            ("长上下文训练通信面", "懂 TP/PP/EP/CP/SP 与 ring attention", "梯度/KV 泄露、训练静默变慢", "第 1 层逐条"),
            ("静默截断", "懂滑窗、attention sink 与位置外推", "指令丢失、评测失真、合规风险", "第 1 层逐条"),
        ],
    },
    "gateway": {
        "layer": 2,
        "title": "AI 网关：身份、路由与配额",
        "intro": (
            "AI 网关是模型流量的唯一入口：它同时持有上游 provider key、租户 key、模型别名、"
            "语义缓存与 guardrail。网关把“网络位置”当身份的那一刻，后面的资产都在同一信任链上。"
        ),
        "analogy": "像小区大门保安只看你站在门里就放行；门禁卡、访客登记、快递柜都在同一道门后。",
        "diagram": """\
tenant A key ─┐
tenant B key ─┼─> [ reverse proxy / auth ] ─> [ model router / alias ]
master key ───┘             │                         │
                           ▼                         ▼
                   [ quota / rate limit ]     [ provider key pool ]
                           │                         │
                           ▼                         ▼
                   [ semantic cache ] <──────> [ guardrail / logs ]
                           │
                           ▼
                    response / TTFT / billing
""",
        "terms": [
            ("反向代理", "网关站在模型前面转发请求；它看到的身份头不一定可信，除非入口剥离了外部同名头。"),
            ("模型路由/别名", "把公共模型名映射到具体后端；别名可写且无 allowlist 时，流量可被整体劫持。"),
            ("master key", "网关的最高权限密钥；示例默认值未轮换时，等于把管理面交给任何读到示例的人。"),
            ("virtual key", "按租户/项目签发的子密钥；必须绑定租户、额度、模型白名单，否则只是换名的 master key。"),
            ("租户", "计费、配额、缓存、日志的最小隔离单位；请求头里的 tenant 不能替代服务端身份。"),
            ("配额/限流", "按 key/租户/模型限制 QPS 与 token；按 X-Forwarded-For 分桶可被轮换伪造绕过。"),
            ("语义缓存", "网关侧按相似度复用响应；键不含租户/模型/策略版本时会跨租户命中。"),
            ("guardrail", "内容护栏；只检查首条消息、只识别 user 角色时可被多消息/角色分层绕过。"),
            ("InferencePool", "Gateway API Inference Extension 的推理后端池；EPP 在其上做端点选择。"),
            ("EPP", "Endpoint Picker；按 KV 利用率/队列深度选端点，指标过宽时泄露租户缓存状态。"),
            ("llm-d", "Kubernetes 上的分布式推理编排；PD 分离、KV 感知路由与 InferencePool 常一起出现。"),
            ("FailOpen", "鉴权/策略组件故障时放行；可用性优先的默认值会把故障放大成全网越权。"),
            ("provider key", "上游模型厂商密钥；泄露等于计费面、模型清单与配额控制权一起丢失。"),
            ("X-Forwarded-For", "代理链客户端 IP 头；可伪造，不能作为配额或审计的唯一身份。"),
        ],
        "rows": [
            ("默认 master key", "懂网关管理面与示例默认值", "全租户管理权、上游 key 外泄、计费盗刷", "第 2 层逐条"),
            ("别名路由劫持", "懂模型别名与后端 allowlist", "全量 prompt/响应中继、模型替换", "第 2 层逐条"),
            ("语义缓存跨租户", "懂缓存键、相似度阈值与租户过滤顺序", "商业数据/系统提示泄露", "第 2 层逐条"),
            ("guardrail 多消息绕过", "懂消息角色与护栏检查范围", "注入指令直达模型、合规失效", "第 2 层逐条"),
            ("配额按 XFF 分桶", "懂代理头伪造与令牌桶", "成本型滥用、共享池饥饿", "第 2 层逐条"),
        ],
    },
    "gpu": {
        "layer": 6,
        "title": "GPU 租户：分区、上下文与残留",
        "intro": (
            "GPU 共享有三层：硬件分区（MIG）、软件上下文（MPS/vGPU/时间片）、调度器配额（HAMi/cGPU/分数卡）。"
            "三层都不是默认安全边界；释放不等于清零，分配记录不等于隔离证明。"
        ),
        "analogy": "像合租公寓按房间/时段分床位，但退租不换床单；下一个租客还能看到上一位的枕头。",
        "diagram": """\
physical GPU
  ├─ MIG instance 1g.10gb ── tenant A
  ├─ MIG instance 2g.20gb ── tenant B
  └─ MPS server / pipe ───── tenant A + B (shared context)
             │
             ▼
   [ pool scheduler: HAMi / cGPU / OrionX ]
             │ allocate / release / migrate
             ▼
   [ residue: VRAM snapshot / context / temp volume ]
             │
             ▼
   next tenant can read previous marker
""",
        "terms": [
            ("MIG", "把一张 GPU 切成多个 GPU instance 的硬件分区；切资源不切身份，profile 错配会改写邻居边界。"),
            ("MPS", "CUDA Multi-Process Service；多进程共享一个 context/pipe，默认假设是单用户。"),
            ("time-slicing", "按时间片轮转共享 GPU；上下文切换残留与时间侧信道是主要风险。"),
            ("vGPU", "虚拟 GPU 实例；调度器把物理卡切片给多个租户，释放路径必须销毁实例。"),
            ("HAMi", "Kubernetes GPU 池化调度器；admin API 与租户过滤是隔离决策的实际执行点。"),
            ("cGPU", "容器级 GPU 隔离/分数卡方案；配额、上下文与指标面需要与 K8s RBAC 对齐。"),
            ("GPU 池化调度", "把物理卡按显存/算力切片并跨 namespace 分配；分配、释放、迁移三个动作都要鉴权。"),
            ("显存残留", "释放后未清零的 VRAM/快照/临时卷；下一个租户可读前一个租户的模型或激活。"),
            ("隔离边界", "从“同卡”到“同 MIG 实例”到“同 context”的层级；边界越细，越需要生命周期证明。"),
            ("CUDA context", "进程在 GPU 上的执行上下文；MPS 共享 context 时，client/pid 可能跨租户可见。"),
            ("MIG profile", "1g/2g/3g/7g 等切片档位；请求档位与设备实际档位不一致就是隔离降级。"),
            ("DCGM", "GPU 指标采集器；进程名、namespace、模型标签是无鉴权时的租户画像源。"),
        ],
        "rows": [
            ("MIG profile 错配", "懂 MIG 档位与在线重配语义", "邻居边界降级、跨租户干扰", "第 6 层逐条"),
            ("MPS context 共享", "懂 MPS server/pipe 与 context", "进程/上下文泄露、时间片侧信道", "第 6 层逐条"),
            ("释放后残留", "懂分配/释放/清零三步", "模型/激活/快照泄露、持久化投毒", "第 6 层逐条"),
            ("池调度 admin 无鉴权", "懂 HAMi/cGPU admin API 与租户作用域", "跨租户 allocate/migrate、设备占用", "第 6 层逐条"),
            ("指标跨租户", "懂 DCGM/EPP 指标粒度", "租户画像、缓存状态侧信道", "第 6 层逐条"),
        ],
    },
    "chip": {
        "layer": 3,
        "title": "芯片与证明链：信任根、IOMMU 与固件",
        "intro": (
            "芯片安全在集群内能看到的不是硅片，而是“证明链 + 隔离配置 + 固件/微码姿态”："
            "CPU TEE 报价、GPU CC JWT、PCIe SPDM、IOMMU/SMMU、TPM PCR、固件签名。"
            "任何一环只看“存在”不验“内容”，都会变成 false trust。"
        ),
        "analogy": "像验护照只看封面有国徽，不验芯片、签名和有效期；假护照也能过。",
        "diagram": """\
[ CPU TEE: TDX / SEV-SNP ] ── quote ──> [ verifier: nonce + measurement ]
             │
[ GPU CC ] ── EAT/JWT ──> [ NRAS JWKS + claims: dbgstat/secboot/overall ]
             │
[ PCIe device ] ── SPDM/DOE ──> [ cert chain + measurement ]
             │
[ IOMMU/SMMU ] ── DMA isolation ──> [ device assignment / ATS / ACS ]
             │
[ TPM + Secure Boot ] ── PCR/eventlog ──> [ measured boot baseline ]
             │
[ firmware / microcode ] ── signature ──> [ vendor root + revocation ]
""",
        "terms": [
            ("TDX", "Intel Trust Domain Extensions；把 VM 放进受保护的 TD，证明报价要绑 nonce/measurement。"),
            ("SEV-SNP", "AMD 安全加密虚拟化；report 由 VCEK 签名，验签要走到 ASK/ARK 根。"),
            ("NVIDIA CC", "GPU Confidential Computing；CC-On/DevTools 的差别必须由 claims 证明，不看自报。"),
            ("attestation", "远程证明：把“我在什么环境运行”变成可验签的 claims；不绑 nonce 就可重放。"),
            ("NRAS", "NVIDIA Remote Attestation Service；提供 GPU EAT/JWT 与 JWKS，是 GPU CC 的信任源。"),
            ("PCS/KDS", "AMD 的证书服务；VCEK/ASK/ARK 链从 KDS 取，缓存不等于实时信任。"),
            ("SPDM", "DMTF 的设备安全协议；证书、测量、会话能力决定 PCIe 设备能否被证明。"),
            ("IOMMU/SMMU", "把设备 DMA 限制在授权地址空间；iommu=off/pt 或 identity 组会放大 DMA 越权。"),
            ("TPM / measured boot", "用 PCR 记录引导链；PCR 偏移或 dbx 缺失意味着“看起来正常但引导链已变”。"),
            ("固件签名", "厂商用非对称私钥签固件；HMAC fixture 不能冒充厂商 PKI。"),
            ("微码", "CPU 微码 revision 低于厂商基线时，已知硬件缺陷可能未修。"),
            ("EAT/JWT", "实体证明令牌；验签、过期、issuer/audience 与 claims 策略缺一不可。"),
            ("nonce", "一次性挑战；不绑 nonce 的证明可被旧 JWT 重放。"),
            ("dbgstat/secboot", "GPU CC claims：调试是否关闭、安全启动是否成立；不看这两项就是 false trust。"),
            ("CXL IDE", "CXL 链路上的完整性与数据加密；CXL 设备才有的面，普通 GPU 集群无此面。"),
        ],
        "rows": [
            ("GPU CC false trust", "懂 NRAS JWT/JWKS、nonce 与 claims", "密钥/模型交给不可信环境、合规失真", "第 3/7 层逐条"),
            ("IOMMU 直通", "懂 DMA、ACS/ATS 与 SMMU", "节点/他租户内存 DMA 越权", "第 3 层逐条"),
            ("固件/引导链替换", "懂 Secure Boot、TPM PCR、固件签名", "持久化、供应链伪造、审计失真", "第 3/7 层逐条"),
            ("SPDM 降级", "懂 SPDM 版本/证书/测量", "设备证明不可信、TEE-IO 失效", "第 3 层逐条"),
        ],
    },
    "network": {
        "layer": 4,
        "title": "网络 fabric：rail、无损与在网聚合",
        "intro": (
            "训练集群的网络分三层：Pod 网络、RDMA 网络、带外/交换机管理网。"
            "NetworkPolicy 只覆盖第一层；rail 绑定、PFC/ECN、SHARP 会话、IB Partition 是 fabric 自己的控制面，"
            "也是租户隔离真正落地的地方。"
        ),
        "analogy": "像高速公路按车牌尾号分车道，但匝道口没人查票；一辆车变道就能堵死整条路。",
        "diagram": """\
GPU0 ─ NIC0 ─ leaf0 ┐
GPU1 ─ NIC1 ─ leaf1 ┼─> spine ─> spine ─> leafN ─ NICn ─ GPUn
GPU2 ─ NIC2 ─ leaf2 ┘         (fat-tree / multi-plane)
      rail 0..N                │
                               ├─ PFC/ECN: 无损队列，全局配置
                               ├─ SHARP: 交换机内 reduce，会话即信任域
                               └─ IB SM/Partition: RDMA 租户边界

Pod network: CNI + NetworkPolicy
RDMA network: SR-IOV / Multus / IMEX (bypasses NetworkPolicy)
""",
        "terms": [
            ("rail", "GPU 服务器内 GPU↔NIC↔leaf 的固定编号绑定；错轨会把集合通信挤到错误平面。"),
            ("多平面", "用多个并行 fabric 平面分担流量；平面间路由/隔离错配会绕过按轨策略。"),
            ("fat-tree", "三层 CLOS 拓扑；spine/leaf 的 oversubscription 决定拥塞与故障域。"),
            ("RoCEv2", "在以太网上跑 RDMA；依赖 PFC/ECN 做无损，配置是全局的。"),
            ("PFC", "Priority Flow Control；暂停帧可止血也可形成风暴，watchdog 关闭时更危险。"),
            ("ECN", "显式拥塞通知；与 PFC 配合做无损，缺失时靠丢包回退会拖垮吞吐。"),
            ("SHARP", "交换机在网聚合；reduce 发生在交换机内，主机策略看不到会话成员与结果。"),
            ("NCCL ring/tree", "NCCL 的两种集合通信算法；ring 省带宽、tree 低时延，bootstrap 不认证。"),
            ("IB SM", "InfiniBand 子网管理器；在 K8s 之外，默认分区 `*` 会把信任域放大到全 fabric。"),
            ("IB Partition", "IB 的租户隔离单位（PKey）；成员不按租户收敛时，RDMA 就是平网。"),
            ("NetworkPolicy", "K8s 的 L3/L4 策略；只覆盖主 CNI，hostNetwork/SR-IOV/RDMA 不经过它。"),
            ("SR-IOV", "把一张网卡切成多个 VF 直通给 Pod；绕过 kube-proxy 与策略钩子。"),
            ("Multus", "给 Pod 挂多张网卡；第二张网卡的策略覆盖常被忽略。"),
            ("IMEX", "多节点 NVLink 显存共享；域成员/通道权限就是跨节点内存边界。"),
            ("NVLink", "GPU 间高带宽互联；NVSwitch/IMEX 把单机信任域扩展到机架。"),
        ],
        "rows": [
            ("rail 错配", "懂 GPU-NIC-leaf 三元组与 NCCL 环境变量", "跨轨拥塞、PFC 风暴、straggler", "第 4 层逐条"),
            ("PFC/ECN 配置可写", "懂无损以太与全局队列", "fabric 级停摆、训练中断", "第 4 层逐条"),
            ("SHARP 会话无鉴权", "懂在网聚合与 reduce 语义", "all-reduce 静默篡改、训练无效", "第 4 层逐条"),
            ("IB Partition 过宽", "懂 SM/PKey 与 RDMA 信任域", "跨租户加入、窃听、注入", "第 4 层逐条"),
            ("SR-IOV/Multus 旁路", "懂第二张网卡与策略钩子", "跨 namespace 直达训练/推理端口", "第 4 层逐条"),
        ],
    },
}
