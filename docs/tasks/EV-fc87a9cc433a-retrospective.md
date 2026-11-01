# EV-fc87a9cc433a 自动复盘

```json
{
  "id": "EV-fc87a9cc433a",
  "state": "integrated",
  "source": {
    "kind": "snapshot_directory_replacement",
    "key": "snapshot_directory_replacement",
    "path": "scripts/agy_runner.py",
    "head": "e423762366a47a2a422e58f7edf168f42c637d7a",
    "evidence": {
      "before": "d590e9519849fc07e1c0f54c1721b2a8a3333751c2313d5b778d69143ea39daf",
      "after": "fe0628def94e7da97949aa84624029e54898549b1baf9dcc2a0df4b747181fc5",
      "stable": false
    },
    "goal": "Fix worktree_digest so replacing a tracked file with a directory has the same snapshot before and after commit. Preserve deletion, rename, symlink and coordinator-edit detection; add a meaningful regression.",
    "allowed_paths": [
      "scripts/agy_runner.py",
      "scripts/test_agy_runner.py",
      "docs/subsystems/coordination.md"
    ],
    "state": "queued",
    "generation": 2,
    "seen": 1793517983.98119,
    "previous_task": "EV-09449b9b0222",
    "reconciled_reason": "PI exited normally and the supervisor stopped its group; transport parser rejected a legitimate settlement event. Draft and failed retrospective preserved. Authorize one fresh bounded generation after parser fix.",
    "task": "EV-fc87a9cc433a"
  },
  "policy": {
    "automatic_kinds": [
      "snapshot_directory_replacement",
      "broken_markdown_link"
    ],
    "author": {
      "harness": "pi",
      "model": "magpie/agentrouter/gpt-6.1-sol"
    },
    "reviewer": {
      "harness": "omp",
      "model": "magpie/amd/DeepSeek-V4.1-Flash"
    },
    "run_seconds": 900,
    "gate_seconds": 900
  },
  "author_run": "058b6e5bc7041a79a4970eec",
  "review_run": "1ca2b97c4467aaf1d6db0386",
  "head": "9a27ea19ef03f1993871e5bc98e37a2ab4877555",
  "verdict": "PASS",
  "integrated_head": "9a27ea19ef03f1993871e5bc98e37a2ab4877555",
  "error": null,
  "prior_error": "Error: Independent review did not pass; automatic retry disabled",
  "resume_reason": "复核首轮非阻塞意见，以相同提交完整门禁及原始回执为依据，明确追加一次独立验收",
  "agent_runs": 3
}
```

已验证事实：发现探针、完整门禁及独立验收通过；代码已集成到上述候选分支。
运行日志与原始回执保留在本机 Git common dir/agentctl/evolution 和 runs。未合并 main、未推送或发布。
