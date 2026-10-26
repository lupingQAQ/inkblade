"""perf — 笛卡尔积全扫掠性能对比基准（Trident vs ARTEX vs KubeTrail-尽力）。

维度（PERFORMANCE-COMPARISON.md 矩阵的行）：
    routes       端点全集枚举（静态提取：ARTEX server/*.go、Trident webui/server.py）
    latency      逐端点延迟扫掠（N>=10，全分布 min/median/p95/p99/max+方差，读写分类）
    concurrency  1/2/4/8/16/32/64 并发 × 全端点（吞吐-并发曲线、错误率曲线）
    scale        100/1k/2k/5k/10k/20k/50k 对象 × {侦察,可达性,规则,报告,DB大小,内存}
    stability    >=1000 迭代（Trident）或 >=20min 连续任务（ARTEX）：RSS 线性拟合斜率+错误率
    startup      冷/热启动、重启恢复、依赖耗时分解
    ui           10k findings 数据集下首屏/各视图文档+数据获取时长（渲染=N/A+原因）
    db           10 万行证据插入后的查询延迟（SQLite 应用级 / PG 引擎级灰盒）
    disk         镜像/仓库/数据目录磁盘足迹
    kubetrail    同 k3s 全量采集时长+资源+逐采集器分解（构建可行时）
    calibration  TCG 换算系数（宿主 vs guest 同一纯计算/HTTP 内核基准）

环境双口径：宿主（Windows 原生）与 VM guest（QEMU TCG Alpine）各跑一遍；
TCG 放大声明：guest 内一切绝对值都被纯软件仿真放大，跨环境绝对值不可直接比较，
只能用 calibration 维度的系数做换算或只看同环境内两工具的比值。
"""
