# 0day 披露流程（Trident Reserve）

> 适用对象：`trident/core/zeroday-registry.json` 中状态为 `novelty-checked` 且查新结论为
> `confirmed-unpublished` 的条目。**本流程不自动外发任何邮件/工单/表单**；每一步都需要人工确认、
> 法务/授权范围核对和证据脱敏复核。

## 1. 准入条件（缺一不可）

1. `verification.status = verified` 且 `verification.dynamic = true`：有真实上游代码/服务的动态复现，
   证据文件带 SHA-256，能按 `lab/zeroday_reserve/` 或历史 repro harness 重跑。
2. `novelty.verdict = confirmed-unpublished`：OSV、NVD、GitHub Advisory、GitHub commit/code 搜索、
   厂商 security/advisory 页面均无公开匹配；缓存原始响应在 `corpus/novelty/cache/`。
3. 影响面、前置条件、版本边界、根因 `file:line`、利用步骤和修复建议已写入 registry。
4. 已排除：已知 CVE/GHSA、公开 commit/PR、厂商公告、static-only、inconclusive、纯加固建议、
   需要受害者主动执行明显恶意文件且无信任边界跨越的“按设计”行为。

## 2. 披露渠道与优先级

| 优先级 | 渠道 | 适用 | 入口/备注 |
|---|---|---|---|
| P0 | 厂商 security policy / GitHub Security Advisory | vLLM、SGLang、DeepSpeed、ms-swift、Open WebUI、Dify | 先查仓库 `SECURITY.md` / `security/advisories`；GitHub 私密 advisory 可附 PoC |
| P0 | CNVD | 国内产品/单位（Dify、ms-swift、ModelScope 生态） | https://www.cnvd.org.cn/ 报送；需单位/个人实名与联系信息 |
| P1 | CNNVD | 同上，作为 CNVD 并行/补充 | https://www.cnnvd.org.cn/ |
| P1 | huntr / 厂商漏洞赏金 | Dify、Open WebUI 等有赏金计划的项目 | 先确认项目 policy，避免与 GitHub advisory 重复 |
| P2 | 上游 maintainer 邮件列表/私信 | 无 security policy 的项目 | 仅在没有其他私密渠道时使用 |

**顺序**：厂商私密渠道 → CNVD/CNNVD（如适用）→ 公开 advisory/CVE。不要先发公开 issue。
同一根因/同一修复批次的条目合并为一份报告；不同信任边界/不同修复动作的条目分开。

## 3. 90 天协调披露时间线

以首次私密报告送达日 `T0` 计：

| 时间 | 动作 |
|---|---|
| T0 | 私密报告 + 脱敏 PoC + 复现环境说明；要求确认收悉 |
| T0+7 | 未收悉则换渠道重发（security@ / GitHub advisory / CNVD） |
| T0+30 | 提醒并询问修复计划/是否分配 CVE；补充版本边界 |
| T0+60 | 二次提醒；如已修复，协调 advisory 发布时间 |
| T0+90 | 默认公开（技术细节 + 修复版本 + 致谢）；如厂商有合理延期，记录新的书面日期 |
| T0+90+ | 公开后把 registry 状态推进到 `public`，并在 `docs/0DAY-RESERVE.md` 标注 CVE/GHSA/commit |

延期只接受书面、可核验的理由（例如需要跨版本回移/大规模镜像重建）。超过 90 天且无修复/无有效沟通，
按“厂商无响应”公开，但先做一次法律/客户授权复核。

## 4. 证据脱敏清单

- 删除主机绝对路径（`<drive>:\...`、`/home/...`）、用户名、租户 ID、客户域名、内网 IP、云账号 ID。
- 删除/替换 token、cookie、API key、JWT、私钥、数据库连接串；PoC 只用 canary 值。
- 截图/日志裁掉浏览器书签、终端历史、IDE 最近项目、桌面文件。
- 证据保留：组件/版本/commit、`file:line`、请求/响应状态、marker 的 SHA-256、复现命令。
- PoC 使用最小 canary（写文件/读固定字符串），不包含真实凭据、不包含对第三方系统的扫描。
- 压缩包加密（密码单独渠道发送）；先给厂商 hash 清单，确认后再给密码。
- 公开材料延迟到修复版本发布后；公开前再次核对 registry 的 `novelty.verdict` 未变成 `already-public`。

## 5. 报告模板

```text
标题：[组件] <一句话影响>（<版本范围>）
报告类型：Coordinated vulnerability disclosure / 0day
报告日期：YYYY-MM-DD
报告人/组织：<name / affiliation / contact>
授权声明：<authorized security testing / bug bounty scope / 自研环境>

1. 摘要
   - 组件：
   - 受影响版本/commit：
   - 修复版本（如已知）：
   - 影响：RCE / 未授权控制 / 任意文件读 / SSRF / 跨租户 / DoS
   - CVSS 3.1 向量与评分（建议）：
   - CWE：

2. 根因
   - file:line:
   - 函数/数据流（source -> sink）：
   - 为什么现有鉴权/沙箱/校验没有覆盖：

3. 前置条件
   - 部署形态、端口、配置、账号权限、网络位置
   - 默认配置是否满足；是否需要管理员开启某开关

4. 复现
   - 环境：OS / Python / 组件 commit / 依赖
   - 步骤 1..N（命令/请求）
   - 预期结果 vs 实际结果
   - 证明：marker 内容 + SHA-256；请求/响应；日志片段

5. 影响与利用场景
   - 单租户 / 跨租户 / 节点 / 集群 / 供应链
   - 与已知 CVE/GHSA 的区别（查新证据）

6. 修复建议
   - 代码级：fail-closed、allowlist、weights_only=True、鉴权前缀、路径规范化
   - 配置级：回环绑定、关闭 dev-mode、最小权限、NetworkPolicy
   - 回归测试建议

7. 披露计划
   - 首次私密报告日期、90 天截止日、计划公开日期
   - 是否申请 CVE/GHSA；致谢名称

8. 附件
   - PoC（脱敏）、evidence hash 清单、查新缓存摘要
```

## 6. 本 reserve 的建议渠道映射

| 组件 | 私密渠道 | 备注 |
|---|---|---|
| vLLM | GitHub Security Advisory（`vllm-project/vllm`） | 附 `lab/zeroday_reserve/cases/vllm-rl-dev-auth-bypass/` |
| DeepSpeed | GitHub Security Advisory（`deepspeedai/DeepSpeed`） / Microsoft security | 附 AutoEP case；说明需要可写 checkpoint 目录 |
| ms-swift | GitHub Security Advisory（`modelscope/ms-swift`） / ModelScope security | 附 media local-read case；说明 `SWIFT_MEDIA_ALLOWED_DIRS` 默认未设置 |
| SGLang | GitHub Security Advisory（`sgl-project/sglang`） | **已公开 CVE-2026-15976，不进入 reserve**；仅保留为已公开降级样本 |
| Dify | security@dify.ai / huntr / CNVD | 先确认 dify-agent 是否在 bounty scope |
| Open WebUI | GitHub Security Advisory（`open-webui/open-webui`） | 条件项：jupyter engine |

## 7. 状态推进与审计

```powershell
# 1) 动态复现（新增发现）
python -m lab.zeroday_reserve.harness --all

# 2) 查新（可离线复跑；缓存缺失 => inconclusive）
python tools/novelty-check.py --inventory corpus/zeroday/inventory.json --only-verified `
  --out corpus/novelty/results.json

# 3) 生成 registry 与报告（不会外发）
python -m trident.core.reserve

# 4) 人工确认后，才允许把 disclosure.status 改为 disclosed / public
```

任何 `already-public` 条目必须降级到 `public`，并从 reserve 计数中移除；任何 `inconclusive` 条目
单列，不得以“应该没公开”为由计入储备。
