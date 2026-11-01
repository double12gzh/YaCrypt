---
name: check
description: >-
  Use this skill when the user asks to run the pre-commit quality gate, verify code quality,
  or check formatting, clippy lints, unit tests, and cargo-deny audits before committing.
---

# Workspace quality gate

Run `bash scripts/verify.sh` from the repository root. This is the same gate
used by CI and both pre-commit entry points. See [verification](../../../docs/verification.md)
for prerequisites and evidence requirements (resolve this link from the skill directory).

Stop on failure. Report the failing stage and exit status; a missing tool or
unavailable advisory database is blocked verification, never a pass.
Do not install tools or change audit policy silently to make the result green.
