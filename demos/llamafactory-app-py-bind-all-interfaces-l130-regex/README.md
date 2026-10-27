# llamafactory-app-py-bind-all-interfaces-l130-regex

- 组件：llamafactory
- 版本：v0.9.5
- 风险：llamafactory: bind-all-interfaces @ app.py:130
- 演示状态：N/A
- 原因：纯配置暴露面（0.0.0.0 绑定）；按安全边界不在本机监听非回环地址，静态证据见 registry 与 lab/upstream_verify fixture。
- 安全边界：不访问公网、不使用真实凭据、不写持久化。
