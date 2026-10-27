# 披露与发布协同计划（Disclosure Release Plan）

> 状态：**草案，未外发**。本计划描述的是一套人工执行的协调披露流程。仓库中的任何代码都不会
> 自动发送邮件、调用 CVE 服务、提交 CNVD/CNNVD 工单或创建公开 advisory。
>
> 关联产物：`disclosure/INDEX.json`、`disclosure/<id>/`、`docs/0DAY-DISCLOSURE.md`、
> `corpus/zeroday/disclosure-eligibility.json`。

## 1. 范围与原则

- 适用范围：`inkblade/core/zeroday-registry.json` 中 `state=novelty-checked` 且
  `verification=verified, dynamic=true` + `confirmed-unpublished` 的储备条目。
- 先筛选后披露：只有通过 CVE 适格筛选的条目进入 `disclosure/<id>/` 的 CVE 就绪包；
  不合格条目只保留 `hardening-advice.md`，不申请 CVE、不进入发布队列。
- 厂商优先：默认先走厂商私有渠道，90 天后才考虑公开或转交 CNA。
- 最小必要：报告只包含复现所需的最小信息；武器化 PoC 不随报告外发，先给哈希清单。
- 一次授权：每条披露必须有明确的人类 owner、客户授权范围和法律复核记录。

## 2. 三种发布模式

| 模式 | 触发条件 | 行为 | 风险 |
|---|---|---|---|
| **A. 厂商优先（默认）** | 所有 CVE 适格条目 | T0 私有通知 → 90 天协调 → 修复后与工具同版本发布 advisory | 低；符合 CVD 惯例 |
| **B. 同步公开（可选）** | 厂商已修复/书面同意，或存在在野利用且厂商失联 | 修复版本发布日同步公开 advisory + CVE | 中；**必须**用户书面确认 + 法律复核 |
| **C. 永久保留（不发布）** | 厂商明确拒绝修复、法律风险高、或仅加固建议 | 只保留在内部 registry 与 hardening 列表 | 最低；但需定期复查 |

模式 B 的额外前置条件（缺一不可）：

1. 用户以书面形式（工单/邮件/签字）确认选择同步公开；
2. 法务完成出口管制、合同保密义务、客户授权范围复核；
3. 厂商已收到通知且满足以下任一：已发布修复、书面同意、或超过 90 天且两次提醒无回应；
4. 公开材料已脱敏并通过 `tests/test_disclosure_packages.py`；
5. 公开时间与修复版本/工具 release 绑定，不得早于修复可用时间。

## 3. 90 天时间线（默认模式）

以首次私有通知送达日 `T0` 计：

| 节点 | 动作 | 产出/状态 |
|---|---|---|
| T0 | 通过厂商 GitHub 私有 advisory / security.txt / PSIRT 发送报告 + 哈希清单 | `status.sent=true`, `vendor_notified=true` |
| T0+7 | 未收到回执则换第二私有渠道重发（不公开） | 渠道记录写入 `timeline.json` |
| T0+30 | 询问修复计划、CVE 分配意向、受影响版本边界 | 更新 `cve_state` |
| T0+60 | 二次提醒；如已修复，协商 advisory 发布日期 | `fix-coordinated` |
| T0+90 | 默认协调公开；否则转 CNA 路径 | `advisory-ready` 或 `public` |
| T0+90+ | 记录 CVE/GHSA/commit；registry 推进到 `public` | registry `disclosure.status=public` |

延期只接受厂商书面、可核验的理由（跨版本回移、大规模镜像重建等），并在 `timeline.json`
记录新日期与批准人。超过 90 天且无修复/无有效沟通，按"厂商无响应"处理，但公开前仍需一次
法律/客户授权复核。

## 4. CVE 分配路径

优先级从高到低：

1. **厂商 CNA**：厂商自己的 CNA 或 GitHub Security Advisory（GHSA 可关联 CVE）。
2. **MITRE CNA of Last Resort**：厂商不是 CNA、拒绝分配或 90 天无响应时，通过
   <https://www.cve.org/ReportRequest> 提交；MITRE 作为 CNA of last resort 受理。
3. **CNVD**：<https://www.cnvd.org.cn/>，国内产品/单位优先；需实名与联系人信息。
4. **CNNVD**：<https://www.cnnvd.org.cn/>，可与 CNVD 并行/补充。

约束：

- 本仓库**不生成真实 CVE ID**；`cve-request.json` 中只有 `CVE-0000-xxxx` 占位符，
  `cveMetadata.state` 仅用于满足 CVE 5.1 schema，`x_inkblade.state=draft-request-not-submitted`
  明确标注未提交。
- 只有收到 CNA 分配的 ID 后，才允许把 `status.cve_id` 从 `null` 改为真实值，并记录分配日期。
- CVE 记录必须能通过 `disclosure/schema/CVE_Record_Format.json`（官方 5.x schema）校验；
  测试 `tests/test_disclosure_packages.py` 会逐条验证。

## 5. 与工具开源同版本发布

发布单位是"一个版本"：修复版本、工具 release、advisory、CVE 记录同批上线，避免披露与
修复错位。

发布清单：

- [ ] 修复 PR/commit 已合入并发布（记录版本号与 commit）。
- [ ] 工具 release tag（例如 `vX.Y.Z`）与 advisory 同一发布窗口。
- [ ] advisory 页：GitHub Security Advisory 或 `docs/security/advisories/<id>.md`。
- [ ] CVE JSON 5.1 记录已通过 schema 校验；占位符已替换为真实 ID（如已分配）。
- [ ] 修复版本、受影响版本、CVSS、CWE、credit 与 `disclosure/<id>/` 一致。
- [ ] `SECURITY.md` / `security.txt` 可访问，报告入口有效。
- [ ] 发布说明链接 advisory，且不含未修复条目的细节。
- [ ] 发布后 7 天内监控误报/回归，准备撤回或修订公告。

## 6. 发布门禁清单（Checklist）

任何对外动作之前逐项确认并留痕：

- [ ] **厂商已通知**：渠道、时间、回执、联系人记录在 `timeline.json`。
- [ ] **修复或豁免**：修复已发布，或厂商书面豁免，或 90 天无响应且已两次提醒。
- [ ] **证据脱敏**：无主机绝对路径、用户名、租户 ID、客户域名、内网 IP、token、cookie、
      API key、JWT、私钥、数据库连接串；PoC 只用 canary。
- [ ] **许可证合规**：引用的第三方代码/工具许可证允许再分发；不复制 AGPL 代码
      （Cairn、LuaN1aoAgent 等仅阅读，不链接/不派生）。
- [ ] **security.txt / SECURITY.md**：存在、可达、指向有效私有渠道。
- [ ] **advisory 页**：英文草稿完成，链接 CVE/修复版本/credit。
- [ ] **法律复核**：出口管制、保密义务、客户授权范围、漏洞披露政策。
- [ ] **用户书面确认**：仅模式 B 必需；模式 A 需 owner 批准。
- [ ] **不自动外发**：确认没有任何脚本/CI 会发送报告或提交 CVE。
- [ ] **发布后计划**：监控、撤回、补丁版本、registry 状态推进。

## 7. 角色与职责（RACI）

| 活动 | 研究 owner | 法务 | 客户/授权方 | 发布经理 |
|---|---|---|---|---|
| 适格筛选与报告 | R/A | C | I | I |
| 厂商通知 | R | C | I | A |
| CVE 申请 | R | C | I | A |
| 脱敏与 schema 校验 | R/A | C | I | I |
| 公开发布（模式 B） | R | A | **A（书面）** | R |
| registry 状态推进 | R/A | I | I | C |

## 8. 状态机

```text
draft-not-sent
  ├─(人工发送)─> vendor-notified
  │                ├─(修复发布)─> fix-coordinated ─> advisory-ready ─> published
  │                ├─(90 天无响应)─> cna-escalated ─> advisory-ready ─> published
  │                └─(厂商拒绝/法律风险)─> hardening-only / withdrawn
  └─(不适格)─> hardening-only
```

`status.json` 只允许人工推进；任何脚本都不得把 `sent`、`vendor_notified`、`cve_id`、
`public_disclosure` 从 `false/null` 自动改为真值。

## 9. 禁止事项

- 不自动发送邮件、不调用 CVE/CNVD/CNNVD API、不创建公开 GitHub advisory。
- 不生成真实 CVE ID，不冒充 CNA。
- 不在公开材料中包含武器化 PoC、真实凭据、客户数据或内部路径。
- 不对第三方系统进行扫描或验证；所有动态证据来自本地授权实验环境。
- 不在修复可用前公开 0day 细节（模式 B 的厂商同意/在野利用例外需法律复核）。

## 10. 复现与校验

```powershell
# 1) 生成/刷新披露包（只写本地文件，不外发）
python tools/build-disclosure.py

# 2) 校验 CVE 5.1 schema、脱敏、时间线、未发送状态
python -m unittest tests.test_disclosure_packages -v

# 3) 查看索引
python -c "import json;d=json.load(open('disclosure/INDEX.json',encoding='utf-8'));print(d['eligible_cve_packages'], d['hardening_only'])"
```

## 11. 当前快照

<!-- RELEASE-SNAPSHOT:START -->
- 适格筛选覆盖：`46` 条 reserve 记录（去重后 `39` 条唯一根因）。
- CVE 就绪包：`30`；仅加固建议：`6`。
- 已发送：`0`；已申请 CVE：`0`；已公开：`0`。
- 所有包状态：`draft-not-sent` / `hardening-only`。
<!-- RELEASE-SNAPSHOT:END -->
