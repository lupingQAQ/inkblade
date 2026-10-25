# XBOW — 「数千 agent 并行」的商业自主渗透

- 分类：agent-2026 / 商业竞品
- 来源：XBOW 官网（商业产品，无开源代码）
- 核验日期：2026-10-25；核验状态：verified（webfetch 200，正文命中）

## 来源
- https://xbow.com/

## 核验（实际读到的）
- 规模声明：**Thousands of agents test your applications and APIs in parallel**，链式组合漏洞；每发现附 working exploit、request/response、复现步骤。
- 战绩：HackerOne **首个排名第一的自主系统**，**1,500+ reproducible exploits** on production targets；Microsoft MSRC 榜上有名，3 个 critical CVE 自主发现并证明；2026-10 一名 XBOW 研究员 + agents 用 **3 个未知 Chrome bug、6 天** 链成完整 sandbox escape，Google 支付当年首个 **$250K** full-chain 奖励。
- 验证口径：GA 类 finding 由**确定性 check** 复核；preview 类明确标注。
- 运营：持续或按需，小时级首批 finding；免费无限复测；工单直投 + 代码级修复建议。
- 护栏：客户定 scope/impact/window；**command checker 阻断破坏性动作**；每动作留日志；finding 先 review 再交付；不拿客户数据训练。
- 合规：SOC 2、ISO 27001、ISO 42001、PCI DSS、NIS 2。

## 架构要素
- 并行 agent 群 + 共享目标状态 + 统一验证器；规模来自并发，不来自单 agent 更聪明。
- 证据=可执行 exploit + 完整决策/战术日志；「验证」是产品的一等公民。
- 安全靠 scope/impact/window 三参数 + 命令检查器，而不是靠模型自觉。

## 对我们的启示
- 我们在**并发规模**（单进程串行，G02/G10）与**战绩**（无自主多步闭环）上落后；在**证据链**（三层证据+manifest sha256）与**审批闸门**上不落后。
- 不应追「无人驱动」形态：我们的客户要的是可复核证据与可审计授权；但应补「并行 worker + 共享黑板 + 统一验证器」的工程架构。
- XBOW 的「GA 类确定性 check」与我们的 `verify-effects` 同源思路；可把「确定性复核」作为 agent 输出的强制后置步骤。
