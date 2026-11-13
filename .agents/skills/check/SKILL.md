---
name: check
description: >-
  Use this skill when the user asks to run the pre-commit quality gate, verify code quality,
  or check formatting, clippy lints, unit tests, and cargo-deny audits before committing.
---

# Workspace quality gate

There is exactly one gate entry: `bash scripts/verify.sh` from the repository root.
It runs the harness contract checks (`scripts/test_harness.py`), the Python
regressions, then the five Cargo stages (format, clippy, test, build, deny).
CI, the native hook and the pre-commit config all call this same script, so never
reconstruct a private command list from memory: a second, weaker list silently
diverges from what actually gates the merge.

Prerequisites and evidence format: [verification](../../../docs/verification.md).
Recorded failure modes behind this checklist: [AGENTS.md §1.7](../../../AGENTS.md)
and the weekly reports in `docs/harness/`.

## Before running

- Confirm the pinned toolchain is the active one (`rustup show active-toolchain`
  must match the `channel` in `rust-toolchain.toml`). Local green with a
  different toolchain than CI is not evidence for CI (`H-01`).
- Confirm `cargo-deny` is on `PATH` (`cargo-deny --version`). If it is missing,
  install it into an explicit tool directory and extend `PATH` for this shell
  only; never edit global Cargo configuration, `deny.toml`, or `ignore` lists to
  reach green (`H-05`).
- Bind the run to a commit: record `git rev-parse HEAD` and confirm the tree is
  clean, so the verdict cannot silently describe older code.

## Verdicts are three-state

- **PASS** — `scripts/verify.sh` exited 0 on the recorded commit, and every
  warning it printed is disclosed verbatim. `exit 0` alone is not PASS.
- **FAIL** — a stage exited non-zero. Report the stage name, exit status and the
  failing output; do not proceed past the first failure.
- **BLOCKED** — a required tool, network reachability for the advisory database,
  or the run itself is unavailable (timeout, watchdog, upstream interruption).
  BLOCKED is never reported as PASS or as FAIL. Resume from the recorded
  commit; do not re-describe an interrupted run as a failed verification (`H-02`).

## Claiming a fix

- A regression that never ran in the gate does not exist: wire new
  `scripts/test_*.py` or Rust tests into `scripts/verify.sh`, where
  `scripts/test_harness.py` enforces the wiring (`H-08`).
- A fix is only verified when the new regression fails on the old implementation
  (revert the fix or inject the fault, observe the behavioural failure, restore).
  A compile error, a skipped test or a missing tool is not that evidence.
- Keep each claim tied to where the assertion actually lives; do not label a test
  by its file or name alone (`H-06`).
