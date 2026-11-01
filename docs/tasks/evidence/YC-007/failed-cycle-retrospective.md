# EV-09449b9b0222 自动复盘

```json
{
  "id": "EV-09449b9b0222",
  "state": "failed",
  "source": {
    "kind": "snapshot_directory_replacement",
    "key": "snapshot_directory_replacement",
    "path": "scripts/agy_runner.py",
    "head": "38b4b03df3d384c261b61163f35e6e5bbc4ae633",
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
    "generation": 1,
    "seen": 1793517296.9874449,
    "task": "EV-09449b9b0222"
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
  "author_run": null,
  "review_run": null,
  "head": null,
  "verdict": null,
  "integrated_head": null,
  "error": "Error: Author runtime failed; preserve draft and inspect receipt",
  "agent_runs": 1
}
```

已验证事实：本轮未完成；保留现场，需人工检查，不自动重新领取。
运行日志与原始回执保留在本机 Git common dir/agentctl/evolution 和 runs。未合并 main、未推送或发布。
