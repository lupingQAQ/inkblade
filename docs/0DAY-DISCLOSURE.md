# 0day 披露流程（InkBlade / 墨刃零 Reserve）

> 适用对象：`inkblade/core/zeroday-registry.json` 中状态为 `novelty-checked` 且查新结论为
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
python -m inkblade.core.reserve

# 4) 人工确认后，才允许把 disclosure.status 改为 disclosed / public
```

任何 `already-public` 条目必须降级到 `public`，并从 reserve 计数中移除；任何 `inconclusive` 条目
单列，不得以“应该没公开”为由计入储备。

## 8. 披露包索引（CVE 就绪，未外发）

<!-- DISCLOSURE-INDEX:START -->
Generated: `2026-10-27T00:00:00+00:00` ｜ **NOT SENT** ｜ screened reserve entries: **46** ｜ CVE-ready packages: **30** ｜ hardening-only: **6**

| ID | Decision | Placeholder | CVSS | Severity | State |
|---|---|---|---:|---|---|
| `areal-awex` | cve | CVE-0000-0001 | 8.2 | HIGH | draft-not-sent |
| `areal-dataservice-pickle` | cve | CVE-0000-0002 | 9.8 | CRITICAL | draft-not-sent |
| `areal-unauth-engine-control` | cve | CVE-0000-0003 | 9.8 | CRITICAL | draft-not-sent |
| `areal-v2-worker` | cve | CVE-0000-0004 | 9.8 | CRITICAL | draft-not-sent |
| `deepspeed-autoep-unsafe-load` | cve | CVE-0000-0005 | 8.8 | HIGH | draft-not-sent |
| `dify-agent-auth-failopen` | cve | CVE-0000-0006 | 9.1 | CRITICAL | draft-not-sent |
| `dify-home-snapshot-cross-tenant` | cve | CVE-0000-0007 | 7.7 | HIGH | draft-not-sent |
| `dify-shellctl-unauth-rce` | cve | CVE-0000-0008 | 9.8 | CRITICAL | draft-not-sent |
| `dify-stub-jwe-default-key` | cve | CVE-0000-0009 | 9.1 | CRITICAL | draft-not-sent |
| `djev-open-proxy` | cve | CVE-0000-0010 | 8.2 | HIGH | draft-not-sent |
| `llm2jev-image-file` | cve | CVE-0000-0011 | 7.5 | HIGH | draft-not-sent |
| `msswift-eval-escape` | cve | CVE-0000-0012 | 8.8 | HIGH | draft-not-sent |
| `msswift-indexed-dataset-py-pickle-loads-l112-ast` | cve | CVE-0000-0013 | 8.8 | HIGH | draft-not-sent |
| `msswift-media-local-read` | cve | CVE-0000-0014 | 7.5 | HIGH | draft-not-sent |
| `msswift-torch-utils-py-pickle-loads-l340-ast` | cve | CVE-0000-0015 | 8.8 | HIGH | draft-not-sent |
| `msswift-trust-remote-code` | cve | CVE-0000-0016 | 8.8 | HIGH | draft-not-sent |
| `onejev-media-ssrf` | cve | CVE-0000-0017 | 7.5 | HIGH | draft-not-sent |
| `openjev-clef-release-module` | cve | CVE-0000-0018 | 8.8 | HIGH | draft-not-sent |
| `openrlhf-serve-rm` | cve | CVE-0000-0019 | 7.5 | HIGH | draft-not-sent |
| `openwebui-code-interpreter-bypass` | cve | CVE-0000-0020 | 9.6 | CRITICAL | draft-not-sent |
| `sglang-omni-admin-failopen` | cve | CVE-0000-0021 | 9.1 | CRITICAL | draft-not-sent |
| `siliconlab-credential-exfil` | cve | CVE-0000-0022 | 8.2 | HIGH | draft-not-sent |
| `skyrl-fetch-weights` | cve | CVE-0000-0023 | 8.2 | HIGH | draft-not-sent |
| `skyrl-tinker-api` | cve | CVE-0000-0024 | 8.2 | HIGH | draft-not-sent |
| `slime-pull-weights` | cve | CVE-0000-0025 | 8.2 | HIGH | draft-not-sent |
| `slime-torch-load` | cve | CVE-0000-0026 | 8.8 | HIGH | draft-not-sent |
| `verl-checkpoint-pickle` | cve | CVE-0000-0027 | 9.8 | CRITICAL | draft-not-sent |
| `verl-hdfs-command-injection` | cve | CVE-0000-0028 | 8.8 | HIGH | draft-not-sent |
| `vllm-jev-plugin-auth-bypass` | cve | CVE-0000-0029 | 8.2 | HIGH | draft-not-sent |
| `vllm-rl-dev-auth-bypass` | cve | CVE-0000-0030 | 9.1 | CRITICAL | draft-not-sent |
| `llamafactory-checkpoint-py-torch-load-unsafe-l334-ast` | hardening | — | 8.8 | HIGH | hardening-only |
| `megatron-checkpointing-py-torch-load-any-l1739-regex` | hardening | — | 8.8 | HIGH | hardening-only |
| `openrlhf-vllm-insecure` | hardening | — | 8.8 | HIGH | hardening-only |
| `skyrl-vllm-devmode` | hardening | — | 9.1 | CRITICAL | hardening-only |
| `trl-vllm-serve-devmode` | hardening | — | 9.1 | CRITICAL | hardening-only |
| `verl-prime-code-exec` | hardening | — | 8.8 | HIGH | hardening-only |

> CVSS 为条目自身弱点评分；`hardening` 行不申请 CVE，分数仅用于排序与修复优先级。所有 `CVE-0000-xxxx` 均为占位符，未提交 CNA。
<!-- DISCLOSURE-INDEX:END -->

## 9. CVE 适格筛选（2026-10-27）

筛选口径（详见 `corpus/zeroday/disclosure-eligibility.json` 的 `policy`）：

1. **可利用性**：必须有真实上游代码的动态复现与明确的攻击者可控路径；仅"默认绑定 0.0.0.0"或
   "暴露面"不单独构成 CVE。
2. **影响面**：RCE、认证绕过并可控制、任意文件读写、跨租户、凭据泄露等直接机密性/完整性影响。
3. **非纯配置**：仅"不安全默认开关"且真正 sink 在依赖方的条目（如 SkyRL/TRL/OpenRLHF 强制
   vLLM dev mode）归入加固建议，避免与 vLLM 自身的 CVE 重复。
4. **去重**：同一产品/同一修复批次合并为一条；与已知公开 CVE 重复的（如 LLaMA-Factory
   checkpoint RCE 与 CVE-2026-1839）不重复申请。
5. **非设计行为**：`prime_code` 的"执行模型生成代码"是功能设计，只给沙箱加固建议。

筛选结果：`46` 条 reserve 记录（去重 `39` 条）中 **30 条进入 CVE 就绪包**，
**6 条仅保留加固建议**：

| 条目 | 不适格原因 |
|---|---|
| `megatron-checkpointing-py-torch-load-any-l1739-regex` | 依赖默认值阻断：torch ≥ 2.6 默认 `weights_only=True`，仅在 torch < 2.6 的钉版组合下受影响 |
| `llamafactory-checkpoint-py-torch-load-unsafe-l334-ast` | 与已公开 CVE-2026-1839 同产品/同信任边界，重复 |
| `verl-prime-code-exec` | 设计内行为（reward 评分需要执行生成代码），应做沙箱加固 |
| `skyrl-vllm-devmode` | 不安全默认，sink 在 vLLM，已由 `vllm-rl-dev-auth-bypass` 覆盖 |
| `trl-vllm-serve-devmode` | 同上 |
| `openrlhf-vllm-insecure` | 同上（强制 `VLLM_ALLOW_INSECURE_SERIALIZATION=1`） |

## 10. 发布协同

- 默认流程：**厂商优先通知 → 90 天 → CVE 分配（厂商 CNA / MITRE CNA of last resort /
  CNVD / CNNVD）→ 与工具开源同版本发布 advisory**。
- 可选"同步公开"模式：需要用户**书面确认**与**法律复核**，且满足修复可用/厂商同意/超时条件。
- 发布门禁、RACI、状态机与禁止事项：见 `docs/DISCLOSURE-RELEASE-PLAN.md`。
- 当前状态：**0 已发送 / 0 CVE 申请 / 0 公开**；所有 `disclosure/<id>/status.json` 为
  `draft-not-sent` 或 `hardening-only`，所有 CVE ID 为 `CVE-0000-xxxx` 占位符。

## 11. 校验

```powershell
python -m unittest tests.test_disclosure_packages -v   # schema/脱敏/时间线/未发送
python tools/build-disclosure.py                        # 仅本地重建，不外发
```

