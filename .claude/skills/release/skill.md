---
name: release
description: Prepare a release — audit, bump version, build release binary
---
Prepare a new release:

1. Run `cargo deny check` to verify licenses and vulnerabilities
2. Run `cargo test` to confirm all tests pass
3. Ask the user for the new version number (current version from Cargo.toml)
4. Update version in Cargo.toml
5. Run `cargo build --release`
6. Report the binary size with `ls -lh target/release/yacrypt`
7. Summarize changes since last release with `git log --oneline <last_tag>..HEAD`

Do NOT commit or tag — leave that for the user to review.
