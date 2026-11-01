# YC-005 / YC-006 真实运行证据

本目录保存本次授权范围内的运行回执和脱敏验证证据，不包含 token、认证配置或完整 Git 元数据。
原始 prompt 和 SQLite 数据库只保留本机；回执中的绝对路径为历史运行路径，worktree 清理后不再存在。

- [工具与模型](inventory.md)
- [真实任务契约](task.json)、[集成前台账公开摘要](task-summary.json)
- run-1：Gemini 首次执行，命令权限拒绝，空响应，失败；草稿在 attempt-1-interrupted.patch。
- run-2：Gemini 第二次执行，成功，a85fe64f-2a58-42c7-8cbf-067fabaa3ce7。
- run-3：Claude 说 PASS 但 findings 非空，格式校验拒绝，未批准。
- run-4：Claude 重新验收成功，78e78880-e6b0-4ba4-8395-3882f3dc7da4，绑定 fe2ea420ff0328ee8f3aaf88876f4497a5fa9753。
- adapter-review 系列是对运行器本身的独立审查；先记录问题、修复，再复验。不是 YC-006 的实现会话。
- *.log.gz 是实际完整门禁或旧实现失败日志；SHA256SUMS 校验归档字节。

失败记录按原样保留，不把 SUCCESS 空答复、非合规 PASS 或沙箱检查失败写成成功。
