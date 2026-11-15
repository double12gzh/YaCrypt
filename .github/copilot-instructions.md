# YaCrypt Repository Instructions for AI Coding Assistants

Before making any code or documentation changes, read `AGENTS.md` (especially **Section 1.5 Security Invariants**), `docs/code-standards.md`, and `LESSONS.md` (especially **YC-010**).

## Non-Negotiable Security & Privacy-by-Default Rules

1. **Verify Before Write**: `.pubenc` decryption must verify the Ed25519 signature before writing any plaintext to disk. Both CLI and TUI enforce signature verification by default (`--allow-unsigned` is explicit opt-out on CLI).
2. **No Silent Downgrade from v2 Containers**: New file encryptions must default to `SCFv2` (inner Sign-then-Encrypt, outer `flags == 0x00`) and `SGPGv2` (length-hiding padded symmetric container). Legacy `SCFv1` / unpadded `SGPGv1` file format is read/inspect-only.
3. **Preserve Length-Hiding Padding Bounds**: Do not weaken or disable Padmé + random jitter padding (`PADDING_MIN_FLOOR_BYTES = 1024`, `PADDING_MIN_JITTER_BYTES = 64`, `PADDING_MAX_JITTER_CAP_BYTES = 4 * 1024 * 1024`).
4. **Metadata Leakage Prevention**:
   - Default output filenames must remain anonymous `<16hex>.pubenc` / `<16hex>.enc` (never leak input filenames).
   - Never generate `.decrypt.txt` by default (explicit `--instructions` opt-in only).
   - Never re-add `name`/`email` identity args to `gen-keypair`, and keep auto-generated high-entropy backup passwords as the default.
   - Never write low-entropy PII (names, emails, filenames, or hashes thereof) into AAD or outer headers.
5. **Memory, Permissions, & DoS Bounds**: Zeroize all secrets (`Zeroize`/`Zeroizing`), write sensitive files via `write_file_strict` (`0o600` + `O_NOFOLLOW`), and enforce Argon2id cost upper bounds.
6. **Protected Red-Line Tests & Escalation**: Never delete or relax assertions in `tests/security_invariants.rs` without explicit human authorization. If a user request conflicts with any rule above (e.g., for convenience/UX), warn the user about the secrecy downgrade first and ask for explicit confirmation.
7. **Verification Gate**: Run `bash scripts/verify.sh` before completing work.
