//! YaCrypt TUI Workbench — Ratatui + Crossterm 终端交互工作台
pub mod app;
pub mod ui;

use app::TuiApp;
use crossterm::{
    event::{self, Event, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{backend::CrosstermBackend, Terminal};
use std::{io, path::PathBuf, time::Duration};

/// 启动交互式 TUI 工作台，确保退出或 panic 时安全恢复终端状态并擦除敏感缓冲
pub fn run() -> Result<(), Box<dyn std::error::Error>> {
    // 安装 Panic Hook，防止未预期异常导致用户终端卡在 Raw Mode / Alternate Screen
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |panic_info| {
        let _ = disable_raw_mode();
        let _ = execute!(io::stdout(), LeaveAlternateScreen);
        default_hook(panic_info);
    }));

    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut app = TuiApp::new(PathBuf::from("keystore"));
    let loop_res = run_event_loop(&mut terminal, &mut app);

    // 退出前强制擦除所有口令缓冲
    app.clear_secret_buffers();
    app.clear_generated_password();

    let _ = disable_raw_mode();
    let _ = execute!(terminal.backend_mut(), LeaveAlternateScreen);
    let _ = terminal.show_cursor();

    loop_res
}

fn run_event_loop(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    app: &mut TuiApp,
) -> Result<(), Box<dyn std::error::Error>> {
    loop {
        terminal.draw(|f| ui::render(f, app))?;

        if event::poll(Duration::from_millis(200))? {
            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press {
                    app.handle_key_event(key);
                }
            }
        }

        if app.should_quit {
            break;
        }
    }
    Ok(())
}
