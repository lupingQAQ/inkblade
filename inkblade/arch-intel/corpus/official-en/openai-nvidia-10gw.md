# OpenAI × NVIDIA — 10GW / 数百万 GPU 战略合作（官方公告）

- 分类：official-en（外文官方源）
- 组织 / 系统：OpenAI / 下一代 AI 基础设施（NVIDIA Vera Rubin 平台）
- 源类型：newsroom（openai.com 官方公告，2025-09-22）
- 核验日期：2026-10-25；核验状态：verified（webfetch openai.com 官方公告直读，原句摘录）

## 来源
- https://openai.com/index/openai-nvidia-systems-partnership/

## 万卡证据（原文摘录）
- ✅ "Strategic partnership enables OpenAI to build and deploy at least 10 gigawatts of AI datacenters with NVIDIA systems representing millions of GPUs for OpenAI's next-generation AI infrastructure."
- ✅ "The first gigawatt of NVIDIA systems will be deployed in the second half of 2026 on NVIDIA's Vera Rubin platform."

## 网络要素
- 规模口径：GW 级数据中心 + 数百万 GPU（fabric 细节未披露——以 NVIDIA 平台条目承载网络要素）

## 架构要素
- 算力形态：10GW 多站点；NVIDIA 投资 up to $100B 随 GW 交付

## 安全问题点（放大前提 × 模块机器键）
- 超大单租部署=供应链与物理边界成为主要攻击面 → `supply-chain-credential-theft`
- 多站点协同训练（跨 fabric）→ `hybrid-cloud-egress-pivot`

## 横向思路
- 公告级源：为“万卡→百万卡”趋势与 UEC/Scale-XGS 跨 DC 组网需求提供官方依据锚点
