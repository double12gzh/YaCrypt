# TUI File Browser & Tab Path Completion Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add a built-in interactive File Browser modal (`Ctrl+O` / `f`) and inline `Tab` path completion to the TUI `Encrypt` and `Decrypt & Verify` tabs.

**Architecture:** Extend `ModalState` in `src/tui/app.rs` with `FileBrowser`, add directory scanning and prefix completion helpers, and render a scrollable file list popup in `src/tui/ui.rs`.

---

### Task 1: State Machine & Directory Scanning (`src/tui/app.rs`)
- **Files:** `src/tui/app.rs`
- **Steps:**
  1. Add `FileBrowserTarget`, `FileBrowserEntry`, and `ModalState::FileBrowser`.
  2. Implement `open_file_browser`, `load_directory_entries`, `handle_file_browser_key`, and `complete_path_prefix`.
  3. Wire `Ctrl+O`, `f`, and `Tab` in `Encrypt` and `Decrypt` tabs.
  4. Add unit test `file_browser_navigation_selection_and_tab_completion` in `src/tui/app.rs`.

### Task 2: Modal Rendering & UI Hints (`src/tui/ui.rs`)
- **Files:** `src/tui/ui.rs`, `README.md`, `README_EN.md`
- **Steps:**
  1. Update field hints in `render_encrypt_tab` and `render_decrypt_tab` to mention `Ctrl+O / f: Browse` and `Tab: Complete`.
  2. Render `ModalState::FileBrowser` in `render_modal` with directory/file icons (`📁`, `🔒`, `🔐`, `📄`), human-readable file sizes, and scroll windowing.
  3. Update `headless_render_all_tabs_and_modals_succeeds` in `src/tui/ui.rs` to test `ModalState::FileBrowser` rendering.
