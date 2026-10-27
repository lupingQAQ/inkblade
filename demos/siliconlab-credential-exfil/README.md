# siliconlab-credential-exfil

- 组件：siliconlab
- 版本：a08e969
- 风险：OpenJev-SiliconLabAI request-controlled base_url/decider_url + server-side API key leakage
- 演示状态：N/A
- 原因：纯凭据/云账号面；按安全边界不使用真实凭据。
- 安全边界：不访问公网、不使用真实凭据、不写持久化。
