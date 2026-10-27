# openjev-clef-release-module

- 组件：openjev
- 版本：b4339c6
- 风险：OpenJev Clef release_module() executes model-directory joint_schema_model.py; revision missing
- 入口：模型/插件: CLEF release module
- 可控参数：module path
- 认证前置：需加载
- 网络位置：服务进程
- 预期效果：import-time marker
- 标记：`INKBLADE-BENIGN-openjev-clef-release-module`
- 默认目标：`127.0.0.1:0`（仅回环，端口 0 为随机）
- 运行：`./run.sh --help`、`./run.sh`、`./run.sh --marker INKBLADE-BENIGN-DEMO`
- 清理：`./run.sh --cleanup`；脚本默认在 `finally` 中清理 `demos/.work/<id>/`
- 安全边界：本地 mock 原语；不访问公网、不使用真实凭据、不写持久化。
