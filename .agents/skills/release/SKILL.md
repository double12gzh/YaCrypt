---
name: release
description: >-
  Use this skill when the user asks to prepare a new YaCrypt release, including running
  security audits, bumping the version in Cargo.toml, building the optimized release binary,
  and summarizing changelog entries.
---

# Release Preparation Workflow (`release`)

Prepare a new release of `yacrypt` following these steps:

1. **Run the shared gate**: `bash scripts/verify.sh`. Stop on any failure.
2. **Record evidence** using [the acceptance template](../../../docs/templates/acceptance.md).
3. **Determine Target Version**:
   - Read the current version from `Cargo.toml` using the file viewing tool (never use bare `cat`).
   - Ask the user for the new target version number.
4. **Update Version**:
   - Update `version = "<new_version>"` in `Cargo.toml`.
5. **Re-run `bash scripts/verify.sh` after the version/lockfile changes, then build the release binary**:
   ```bash
   cargo build --locked --workspace --release
   ```
6. **Verify Binary Size**:
   ```bash
   ls -lh target/release/yacrypt
   ```
7. **Summarize Changes**:
   - Summarize commits since the last tag using `git log --oneline <last_tag>..HEAD` (aligned with `cliff.toml` Conventional Commits groups).

> **Important**: Do NOT automatically `git commit` or `git tag` the release unless explicitly instructed by the user. When committing, strictly follow the 3-part `-m` format and `Co-Authored-By` rules in `AGENTS.md`.
