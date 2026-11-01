# 本机工具与模型核对（2026-11-01）

| 工具 | 本机路径/版本 | 本轮实际使用 |
| --- | --- | --- |
| agy | ~/.local/bin/agy；启动日志 language server 1.4.12 | 真实 Gemini 实现、Claude 审查与验收 |
| Codex CLI | /opt/homebrew/bin/codex 0.166.0 | 仅探测版本；本轮协调来自 Codex Desktop，不冒称启动了该 CLI |
| pi | /opt/homebrew/bin/pi 1.4.0 | 已查本机模型目录，未实际调用 |
| omp | ~/.local/bin/omp 18.14.1 | 已查本机模型目录，未实际调用 |

agy 目录返回 gemini-4-argon-{medium,high,low}、gemini-3.8-flash-{high,medium,low}、
claude-opus-5-5-{low,medium,high}、claude-sonnet-5-5-{low,medium,high}、gpt-oss-120b-medium。
目录可见不是可用性保证；本轮仅 Gemini Argon High 与 Claude Sonnet Medium 做过真实成功调用。
调用使用本机已有登录状态；未读取或归档认证配置。

请求模型由 CLI --model 明确指定，agy 返回会话 ID、状态和用量，但没有后端身份认证字段。
本报告不将请求 ID 冒称独立验证过的后端模型身份。协调器精确基础模型版本未获得可核验记录，仅标记 GPT/Codex。
