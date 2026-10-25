# Google Big Sleep — 验证状态：不可达（本轮不引用其数字）

- 分类：agent-2026 / 漏洞发现 agent
- 来源：Google Project Zero / DeepMind（公开博客）
- 核验日期：2026-10-25；核验状态：**blocked**（原站 ECONNREFUSED，镜像 r.jina.ai 亦 ECONNREFUSED；两次尝试均失败）

## 来源（尝试）
- https://googleprojectzero.blogspot.com/2024/10/from-deepmind-big-sleep-to-naptime.html
- https://projectzero.google/2024/10/from-deepmind-big-sleep-to-naptime.html

## 核验（实际结果）
- 本轮**无法取得原文**；因此不引用其任何数字、漏洞名或战术细节。
- 仅记录公开定位（待核验）：Google 的 LLM agent 漏洞发现项目，与 Project Zero/DeepMind 相关。
- 处理原则：**宁可缺失，不可臆造**。本文档正文不将其作为论据；如后续网络可达，再补核验并升级为 verified。

## 架构要素
- （未核验，留空。）

## 对我们的启示
- 方法论启示：任何「AI 发现漏洞」的宣称都必须带**可复现证据**（目标、版本、PoC、修复），否则不能进入我们的竞品/能力矩阵。
- 这与我们 `docs/COMPETITIVE-MATRIX.md` 的来源纪律一致：不可达的源标注 404/blocked，不用传闻填空。
