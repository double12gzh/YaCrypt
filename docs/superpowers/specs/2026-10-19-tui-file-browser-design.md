# TUI Built-in File Browser Modal & Tab Path Completion Design

## 1. Goal
Eliminate manual file path typing friction in the `Encrypt` and `Decrypt & Verify` tabs of the YaCrypt TUI workbench by adding:
1. **Built-in Interactive File Browser Modal (`Ctrl+O` or `f`)**: Browse directories, filter hidden files, preview file sizes and `.pubenc` / `.enc` badges, and select input/output paths with `Enter`.
2. **Inline `Tab` Path Auto-Completion**: Complete partial file/directory prefixes while editing a path field, or open the File Browser Modal when pressing `Tab` on an empty/ambiguous field.

## 2. State Machine & Data Structures (`src/tui/app.rs`)
- `FileBrowserTarget`:
  - `EncryptInput`
  - `EncryptOutput`
  - `DecryptInput`
  - `DecryptOutput`
- `FileBrowserEntry`:
  - `name: String`
  - `path: PathBuf`
  - `is_dir: bool`
  - `is_parent: bool`
  - `size: u64`
- `ModalState::FileBrowser`:
  - `target: FileBrowserTarget`
  - `current_dir: PathBuf`
  - `entries: Vec<FileBrowserEntry>`
  - `selected_idx: usize`
  - `show_hidden: bool`

## 3. Interaction & Keyboard Shortcuts
- **Opening the File Browser**:
  - In `Encrypt` tab (when focused on Input File `0` or Output File `1`) or `Decrypt` tab (when focused on Encrypted File `0` or Output File `1`):
    - Press `Ctrl+O` (works both in field navigation mode and inline text editing mode).
    - Press `f` (in field navigation mode).
    - Press `Tab` while inline editing if the path is empty or has no further common prefix completion.
- **Inside `ModalState::FileBrowser`**:
  - `↑` / `k`, `↓` / `j`: Move cursor across directory entries.
  - `Enter` on directory (`..` or subdirectory): Enter directory and reload entries.
  - `Enter` on file: Populate target path field (relative to current working directory when under CWD, otherwise full path), close modal, and if `target == DecryptInput`, immediately run `update_decrypt_inspection()`.
  - `Backspace` or `←` / `h`: Navigate to parent directory (`..`).
  - `.`: Toggle `show_hidden` (dotfiles hidden by default).
  - `Esc`: Cancel and close modal.

## 4. Security Invariants
- Never follow symlinks loops or panic on unreadable directories (`fs::read_dir` errors are reported cleanly in the status bar).
- Preserve all existing `Zeroizing` password buffer guarantees on modal transitions and `Esc`.
