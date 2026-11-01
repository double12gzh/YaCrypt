// The application is a binary crate. Exercise its real renderer and state machine.
#[path = "../src/tui/mod.rs"]
pub mod tui;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::{
    backend::TestBackend,
    buffer::Buffer,
    layout::Rect,
    style::{Color, Modifier},
    text::Line,
    Terminal,
};
use std::{
    fs,
    io::ErrorKind,
    path::{Path, PathBuf},
    sync::atomic::{AtomicUsize, Ordering},
};
use tui::app::{ActiveTab, FileBrowserEntry, FileBrowserTarget, ModalState, TuiApp};

static NEXT_FIXTURE: AtomicUsize = AtomicUsize::new(0);

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Self {
        loop {
            let id = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
            let pid = std::process::id();
            let dir = std::env::temp_dir().join(format!("yacrypt_tui_viewport_{pid}_{id}"));
            match fs::create_dir(&dir) {
                Ok(()) => return Self(dir.canonicalize().unwrap()),
                Err(err) if err.kind() == ErrorKind::AlreadyExists => continue,
                Err(err) => panic!("cannot create viewport fixture {}: {}", dir.display(), err),
            }
        }
    }

    fn app(&self, selected_idx: usize) -> TuiApp {
        // This path is inside a newly created fixture and contains no keys.
        let mut app = TuiApp::new(self.0.join("unused-keystore"));
        app.switch_tab(ActiveTab::Encrypt);
        let dir = self.0.join("files");
        app.modal = ModalState::FileBrowser {
            target: FileBrowserTarget::EncryptInput,
            current_dir: dir.clone(),
            entries: numbered_entries(&dir, 12),
            selected_idx,
            show_hidden: false,
        };
        app
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn numbered_entries(dir: &Path, count: usize) -> Vec<FileBrowserEntry> {
    (0..count)
        .map(|idx| {
            let name = format!("item_{idx:02}.txt");
            FileBrowserEntry {
                path: dir.join(&name),
                name,
                is_dir: false,
                is_parent: false,
                size: 42,
            }
        })
        .collect()
}

fn press(app: &mut TuiApp, code: KeyCode) {
    app.handle_key_event(KeyEvent::new(code, KeyModifiers::NONE));
}

fn selected_idx(app: &TuiApp) -> usize {
    match &app.modal {
        ModalState::FileBrowser { selected_idx, .. } => *selected_idx,
        _ => panic!("expected file browser"),
    }
}

fn draw(terminal: &mut Terminal<TestBackend>, app: &TuiApp) -> Buffer {
    let before = app.modal.clone();
    terminal.draw(|frame| tui::ui::render(frame, app)).unwrap();
    assert_eq!(app.modal, before, "drawing must not change browser data or selection");
    terminal.backend().buffer().clone()
}

fn resize_and_draw(
    terminal: &mut Terminal<TestBackend>,
    app: &TuiApp,
    width: u16,
    height: u16,
) -> Buffer {
    terminal.backend_mut().resize(width, height);
    terminal.resize(Rect::new(0, 0, width, height)).unwrap();
    draw(terminal, app)
}

fn text_rows(buffer: &Buffer, selected_only: bool) -> Vec<String> {
    let area = buffer.area;
    (area.y..area.bottom())
        .map(|y| {
            let mut row = String::new();
            let mut x = area.x;
            while x < area.right() {
                let cell = &buffer[(x, y)];
                if !selected_only
                    || (cell.fg == Color::Yellow && cell.modifier.contains(Modifier::BOLD))
                {
                    row.push_str(cell.symbol());
                } else {
                    row.push(' ');
                }
                // Skip continuation cells of wide graphemes, keeping Unicode text
                // (including combining marks and ZWJ emoji) intact in assertions.
                let width = Line::from(cell.symbol()).width().max(1) as u16;
                x = x.saturating_add(width);
            }
            row
        })
        .collect()
}

fn assert_selected_visible(buffer: &Buffer, preview: &str) {
    assert!(
        text_rows(buffer, true).iter().any(|row| row.contains(preview)),
        "selected filename preview {preview:?} missing from {}x{} frame:\n{}",
        buffer.area.width,
        buffer.area.height,
        text_rows(buffer, false).join("\n")
    );
}

#[test]
fn archived_80x12_selected_idx_4_remains_visible() {
    let fixture = Fixture::new();
    let mut app = fixture.app(4);
    if let ModalState::FileBrowser { current_dir, .. } = &mut app.modal {
        // A short label isolates the archived help-wrap/minimum-five-rows failure.
        *current_dir = PathBuf::from("/fixtures");
    }
    let mut terminal = Terminal::new(TestBackend::new(80, 12)).unwrap();

    // Archived discovery: 12 entries, selected_idx=4, terminal size 80x12.
    // The old wrapping paragraph placed item_04.txt below the visible list.
    let buffer = draw(&mut terminal, &app);
    assert_eq!(selected_idx(&app), 4);
    assert_selected_visible(&buffer, "item_04.txt");
}

#[test]
fn down_and_up_keep_the_keyboard_selection_visible() {
    let fixture = Fixture::new();
    let mut app = fixture.app(0);
    let mut terminal = Terminal::new(TestBackend::new(80, 12)).unwrap();
    for (width, height) in [(80, 12), (40, 8), (80, 6)] {
        let buffer = resize_and_draw(&mut terminal, &app, width, height);
        assert_eq!(selected_idx(&app), 0);
        assert_selected_visible(&buffer, "item_00.txt");

        for idx in 1..12 {
            press(&mut app, if idx % 2 == 0 { KeyCode::Char('j') } else { KeyCode::Down });
            assert_eq!(selected_idx(&app), idx);
            assert_selected_visible(&draw(&mut terminal, &app), &format!("item_{idx:02}.txt"));
        }
        press(&mut app, KeyCode::Down);
        press(&mut app, KeyCode::Char('j'));
        assert_eq!(selected_idx(&app), 11);
        assert_selected_visible(&draw(&mut terminal, &app), "item_11.txt");

        for idx in (0..11).rev() {
            press(&mut app, if idx % 2 == 0 { KeyCode::Char('k') } else { KeyCode::Up });
            assert_eq!(selected_idx(&app), idx);
            assert_selected_visible(&draw(&mut terminal, &app), &format!("item_{idx:02}.txt"));
        }
        press(&mut app, KeyCode::Up);
        press(&mut app, KeyCode::Char('k'));
        assert_eq!(selected_idx(&app), 0);
        assert_selected_visible(&draw(&mut terminal, &app), "item_00.txt");
    }
}

#[test]
fn shrinking_and_growing_recompute_the_viewport_without_changing_selection() {
    let fixture = Fixture::new();
    let app = fixture.app(11);
    let mut terminal = Terminal::new(TestBackend::new(120, 30)).unwrap();

    for (width, height, preview) in [
        (120, 30, "item_11.txt"),
        (80, 12, "item_11.txt"),
        (40, 8, "item_11.txt"),
        (20, 6, "item_11.txt"),
        // Header rows must yield to the sole entry row.
        (80, 6, "item_11.txt"),
        // Drop decoration when only a filename preview fits.
        (6, 6, "it"),
        (80, 12, "item_11.txt"),
        (120, 30, "item_11.txt"),
    ] {
        let buffer = resize_and_draw(&mut terminal, &app, width, height);
        assert_eq!(selected_idx(&app), 11);
        assert_selected_visible(&buffer, preview);
        assert!(app.enc_input_path.is_empty());
    }
}

#[test]
fn long_unicode_paths_and_names_cannot_consume_entry_rows() {
    let fixture = Fixture::new();
    let mut app = fixture.app(4);
    if let ModalState::FileBrowser { current_dir, entries, .. } = &mut app.modal {
        *current_dir = fixture.0.join("长目录_🗃️_\n".repeat(80));
        for (idx, entry) in entries.iter_mut().enumerate() {
            entry.name = format!("entry_{idx:02}_{}.txt", "文件_👩🏽‍💻_cafe\u{301}_".repeat(40));
            entry.path = fixture.0.join(&entry.name);
        }
        entries[4].name = format!("chosen_04_{}.txt", "文件_👩🏽‍💻_cafe\u{301}_".repeat(40));
        entries[4].path = fixture.0.join(&entries[4].name);
    }
    let mut terminal = Terminal::new(TestBackend::new(80, 12)).unwrap();
    for (width, height) in [(80, 12), (40, 8), (20, 6)] {
        let buffer = resize_and_draw(&mut terminal, &app, width, height);
        assert_selected_visible(&buffer, "chosen_04_");
    }

    if let ModalState::FileBrowser { entries, .. } = &mut app.modal {
        entries[4].name = "文件_👩🏽‍💻_cafe\u{301}\nnotes\tfinal\r.txt".into();
        entries[4].path = fixture.0.join(&entries[4].name);
    }
    let buffer = resize_and_draw(&mut terminal, &app, 100, 24);
    assert_selected_visible(&buffer, "文件_👩🏽‍💻_cafe\u{301} notes final .txt");
    let buffer = resize_and_draw(&mut terminal, &app, 6, 6);
    assert_selected_visible(&buffer, "文");
}

#[test]
fn directory_navigation_still_selects_and_renders_the_current_entry() {
    let fixture = Fixture::new();
    let sub = fixture.0.join("sub");
    fs::create_dir(&sub).unwrap();
    for entry in numbered_entries(&sub, 12) {
        fs::write(entry.path, b"viewport fixture").unwrap();
    }
    let mut app = fixture.app(0);
    app.open_file_browser_in_dir(FileBrowserTarget::EncryptInput, fixture.0.clone(), false);
    press(&mut app, KeyCode::Down); // Parent entry is first, then 'sub'.
    press(&mut app, KeyCode::Right);
    if let ModalState::FileBrowser { current_dir, .. } = &app.modal {
        assert_eq!(current_dir, &sub);
    } else {
        panic!("expected file browser");
    }
    assert_eq!(selected_idx(&app), 0);
    let mut terminal = Terminal::new(TestBackend::new(80, 12)).unwrap();
    assert_selected_visible(&draw(&mut terminal, &app), ".. (Parent Directory)");

    for _ in 0..5 {
        press(&mut app, KeyCode::Down);
    }
    assert_eq!(selected_idx(&app), 5);
    assert_selected_visible(&draw(&mut terminal, &app), "item_04.txt");

    press(&mut app, KeyCode::Backspace);
    if let ModalState::FileBrowser { current_dir, .. } = &app.modal {
        assert_eq!(current_dir, &fixture.0);
    } else {
        panic!("expected file browser");
    }
    assert_eq!(selected_idx(&app), 0);
    assert_selected_visible(&resize_and_draw(&mut terminal, &app, 80, 6), ".. (Parent Directory)");
}

#[test]
fn empty_and_extremely_tiny_viewports_render_safely() {
    let fixture = Fixture::new();
    let mut app = fixture.app(11);
    let mut terminal = Terminal::new(TestBackend::new(80, 12)).unwrap();
    // No text promise where the bordered modal cannot fit an entry row or glyph.
    for width in 0..=8 {
        for height in 0..=6 {
            resize_and_draw(&mut terminal, &app, width, height);
            assert_eq!(selected_idx(&app), 11);
        }
    }

    if let ModalState::FileBrowser { entries, selected_idx, .. } = &mut app.modal {
        entries.clear();
        *selected_idx = 0;
    }
    for (width, height) in [(80, 12), (80, 6)] {
        let buffer = resize_and_draw(&mut terminal, &app, width, height);
        assert!(text_rows(&buffer, false).iter().any(|row| row.contains("(Empty directory)")));
    }
    for (width, height) in [(0, 0), (1, 1), (2, 3), (80, 2)] {
        resize_and_draw(&mut terminal, &app, width, height);
    }
}

#[test]
fn confirming_a_clipped_filename_preserves_the_full_path_for_all_targets() {
    let fixture = Fixture::new();
    let cwd = std::env::current_dir().unwrap().canonicalize().unwrap();
    for browser_target in [
        FileBrowserTarget::EncryptInput,
        FileBrowserTarget::EncryptOutput,
        FileBrowserTarget::DecryptInput,
        FileBrowserTarget::DecryptOutput,
    ] {
        let mut app = fixture.app(4);
        let chosen_path = if let ModalState::FileBrowser { target, entries, .. } = &mut app.modal {
            *target = browser_target;
            entries[4].name = format!("chosen_04_{}.txt", "文件_cafe\u{301}_".repeat(30));
            entries[4].path = fixture.0.join("files").join(&entries[4].name);
            entries[4].path.clone()
        } else {
            panic!("expected file browser");
        };
        let expected = chosen_path.strip_prefix(&cwd).unwrap_or(&chosen_path).to_string_lossy();
        app.enc_input_path = "keep encrypt input".into();
        app.enc_output_path = "keep encrypt output".into();
        app.dec_input_path = "keep decrypt input".into();
        app.dec_output_path = "keep decrypt output".into();
        app.enc_key_choice = 1;
        app.enc_sign_file = false;
        app.enc_force = true;
        app.dec_require_sig = false;
        app.dec_force = true;
        let mut terminal = Terminal::new(TestBackend::new(80, 12)).unwrap();
        assert_selected_visible(&draw(&mut terminal, &app), "chosen_04_");

        press(&mut app, KeyCode::Enter);
        assert_eq!(app.modal, ModalState::None);
        let expected_paths = match browser_target {
            FileBrowserTarget::EncryptInput => [
                expected.as_ref(),
                "keep encrypt output",
                "keep decrypt input",
                "keep decrypt output",
            ],
            FileBrowserTarget::EncryptOutput => [
                "keep encrypt input",
                expected.as_ref(),
                "keep decrypt input",
                "keep decrypt output",
            ],
            FileBrowserTarget::DecryptInput => [
                "keep encrypt input",
                "keep encrypt output",
                expected.as_ref(),
                "keep decrypt output",
            ],
            FileBrowserTarget::DecryptOutput => [
                "keep encrypt input",
                "keep encrypt output",
                "keep decrypt input",
                expected.as_ref(),
            ],
        };
        assert_eq!(
            [
                app.enc_input_path.as_str(),
                app.enc_output_path.as_str(),
                app.dec_input_path.as_str(),
                app.dec_output_path.as_str(),
            ],
            expected_paths
        );
        assert_eq!((app.enc_key_choice, app.enc_sign_file, app.enc_force), (1, false, true));
        assert_eq!((app.dec_key_idx, app.dec_require_sig, app.dec_force), (0, false, true));
        if browser_target == FileBrowserTarget::DecryptInput {
            // Only the normal header-inspection failure for this nonexistent fixture;
            // confirming a browser entry must not execute any crypto/file workflow.
            assert!(matches!(app.dec_inspected, Some(Err(_))));
        }
    }
}
