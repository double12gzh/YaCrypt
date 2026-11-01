# QP-f9cdaa40e2b1456a Keep selected file visible in a short TUI file browser

待批准；来源内容不是执行权限。复现步骤仅供审查，不作为 shell 命令执行。

```json
{
  "id": "QP-f9cdaa40e2b1456a",
  "payload": {
    "head": "940b2ea36815a659beea1aea6c7afb90a169c208",
    "spec": {
      "title": "Keep selected file visible in a short TUI file browser",
      "goal": "Fix file browser rendering so the selected entry remains visible after navigation and terminal resizing whenever there is room for an entry row. At 80x12 with 12 entries and selected_idx=4, item_04.txt is currently invisible because the list assumes at least five rows and wrapped headers consume space. Compute the actual list viewport and ensure long paths/filenames do not make selection disappear. Preserve keyboard selection, file operations, keystore/crypto behavior and unrelated UI.",
      "allowed_paths": [
        "src/tui/ui.rs",
        "tests/tui_viewport.rs",
        "docs/subsystems/interfaces.md"
      ],
      "acceptance": [
        "Reproduce and fix the archived 80x12 selected_idx=4 case; add a permanent regression that fails on the old implementation.",
        "Cover navigation down/up, shrinking/resizing, and long or Unicode paths/names. At extremely tiny dimensions render safely; only promise selected text when at least one row fits.",
        "Keep browsing selection and cryptographic/file-operation behavior unchanged; update interface contract and pass the full gate."
      ],
      "reproduction": [
        "Read docs/tasks/evidence/YC-009/viewport-repro.rs.txt (isolated TestBackend fixture, no real keys).",
        "Copy that fixture to tests/viewport_repro.rs in a temporary checkout and run cargo test --locked --test viewport_repro selected_file_visible_in_short_terminal -- --exact. Original implementation fails the visibility assertion, not compilation.",
        "Integrate equivalent permanent regressions within allowed files; coordinator separately reruns the archived original probe."
      ],
      "evidence": "Operator reproduced against unmodified product code at 772b1a0 in .worktrees/viewport-repro. Log docs/tasks/evidence/YC-009/viewport-red.log SHA256 56d3e4252cee3c9ddec9b120b86db34859db1b6f81c61a2e2c01b3cd9cce7d63. Existing headless tests only asserted no panic, missing selection visibility. Gate failure was from an added temporary regression, not the baseline full gate."
    },
    "diagnostic": {
      "id": "DG-a28c90bf5f1ee7fa",
      "head": "940b2ea36815a659beea1aea6c7afb90a169c208",
      "worktree": "/Users/jeffreyguan/Desktop/YaCrypt/.worktrees/quality-intake",
      "source_digest": "937803cc63388319b33aecd451ebeb34c0b51bfe5552db7efeeb0bfceeec2175",
      "command": [
        "bash",
        "scripts/verify.sh"
      ],
      "status": "passed",
      "category": "none",
      "failed_stage": null,
      "exit_code": 0,
      "error": null,
      "log": "/Users/jeffreyguan/Desktop/YaCrypt/.git/agentctl/evolution/quality/DG-a28c90bf5f1ee7fa.log",
      "log_sha256": "3f63d75e2e0e8e4b4f78f56fa5d8f63eb9280c30a43e6ab034baaf0ff153330a",
      "started": 1793529416.7803671,
      "finished": 1793529461.0305889,
      "fingerprint": "e3e45a5c89a7f77c540ced8e5220a44d8d8950068657272652b068bd37c49912"
    },
    "risk": "needs_approval"
  },
  "payload_sha256": "09601aa4dca546b46051c458b001b1065976371cdec3ec22001e4e99fb6b9209",
  "state": "pending",
  "created": 1793529506.1722329
}
```
