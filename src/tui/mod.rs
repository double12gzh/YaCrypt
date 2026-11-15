//! YaCrypt TUI Workbench — Ratatui + Crossterm 终端交互工作台
pub mod app;
pub mod i18n;
pub mod ui;

use app::TuiApp;
use crossterm::{
    cursor::Show,
    event::{self, Event, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{backend::CrosstermBackend, Terminal};
use std::{
    io,
    panic::{self, PanicHookInfo},
    path::PathBuf,
    time::Duration,
};

type PanicHookBox = Box<dyn Fn(&PanicHookInfo<'_>) + Sync + Send + 'static>;

/// 抽象终端模式切换操作，便于对初始化半途失败与 Drop 恢复路径执行确定性单元测试
trait TerminalLifecycleOps {
    fn enable_raw(&mut self) -> io::Result<()>;
    fn disable_raw(&mut self) -> io::Result<()>;
    fn enter_alt_screen(&mut self) -> io::Result<()>;
    fn leave_alt_screen_and_show_cursor(&mut self) -> io::Result<()>;
}

struct CrosstermLifecycleOps;

impl TerminalLifecycleOps for CrosstermLifecycleOps {
    fn enable_raw(&mut self) -> io::Result<()> {
        enable_raw_mode()
    }

    fn disable_raw(&mut self) -> io::Result<()> {
        disable_raw_mode()
    }

    fn enter_alt_screen(&mut self) -> io::Result<()> {
        execute!(io::stdout(), EnterAlternateScreen)
    }

    fn leave_alt_screen_and_show_cursor(&mut self) -> io::Result<()> {
        execute!(io::stdout(), LeaveAlternateScreen, Show)
    }
}

/// RAII 终端会话恢复守卫：无论正常退出、半途 `?` 提前返回还是 panic 展开，
/// 均严格按已进入的状态逆序恢复 Alternate Screen、光标可见性、Raw Mode 与 Panic Hook。
struct TerminalSessionGuard<O: TerminalLifecycleOps> {
    ops: O,
    raw_enabled: bool,
    alt_entered: bool,
    prev_panic_hook: Option<PanicHookBox>,
}

impl<O: TerminalLifecycleOps> TerminalSessionGuard<O> {
    fn enter(ops: O, install_panic_hook: bool) -> io::Result<Self> {
        let prev_panic_hook = if install_panic_hook {
            let prev = panic::take_hook();
            // 临时安装基础恢复钩子，确保即便初始化阶段或事件循环触发 panic 也能恢复终端
            let shared_prev = std::sync::Arc::new(prev);
            let hook_prev = std::sync::Arc::clone(&shared_prev);
            panic::set_hook(Box::new(move |panic_info| {
                let _ = disable_raw_mode();
                let _ = execute!(io::stdout(), LeaveAlternateScreen, Show);
                hook_prev(panic_info);
            }));
            // 保存一个在正常退出时可还原默认行为的包装钩子（避免多次进入 TUI 累积多层恢复闭包）
            Some(Box::new(move |panic_info: &PanicHookInfo<'_>| {
                shared_prev(panic_info);
            }) as PanicHookBox)
        } else {
            None
        };

        let mut guard = Self { ops, raw_enabled: false, alt_entered: false, prev_panic_hook };
        guard.ops.enable_raw()?;
        guard.raw_enabled = true;
        guard.ops.enter_alt_screen()?;
        guard.alt_entered = true;
        Ok(guard)
    }
}

impl<O: TerminalLifecycleOps> Drop for TerminalSessionGuard<O> {
    fn drop(&mut self) {
        if self.alt_entered {
            let _ = self.ops.leave_alt_screen_and_show_cursor();
            self.alt_entered = false;
        }
        if self.raw_enabled {
            let _ = self.ops.disable_raw();
            self.raw_enabled = false;
        }
        if let Some(prev_hook) = self.prev_panic_hook.take() {
            let _ = panic::take_hook();
            panic::set_hook(prev_hook);
        }
    }
}

/// 启动交互式 TUI 工作台，确保退出、半途错误或 panic 时安全恢复终端状态并擦除敏感缓冲
pub fn run(keystore_dir: PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    let _session_guard = TerminalSessionGuard::enter(CrosstermLifecycleOps, true)?;
    let backend = CrosstermBackend::new(io::stdout());
    let mut terminal = Terminal::new(backend)?;

    let lang = i18n::UiLang::detect_initial(&keystore_dir);
    let mut app = TuiApp::new_with_lang(keystore_dir, lang);
    let loop_res = run_event_loop(&mut terminal, &mut app);

    // 显式擦除口令缓冲（TuiApp::drop 亦提供兜底清零）
    app.clear_secret_buffers();
    app.clear_generated_password();
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
                    app.handle_key_event_with_hook(key, |busy_state| {
                        let _ = terminal.draw(|f| ui::render(f, busy_state));
                    });
                    // 耗时 Argon2id 完成后排空阻塞期间积压的按键，防止误关闭一次性备份口令弹窗
                    if app.take_drain_events_flag() {
                        while event::poll(Duration::ZERO)? {
                            let _ = event::read()?;
                        }
                    }
                }
            }
        }

        if app.should_quit {
            break;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{cell::RefCell, rc::Rc};

    #[derive(Default, Debug, PartialEq, Eq)]
    struct RecordedCalls {
        enable_raw: usize,
        disable_raw: usize,
        enter_alt: usize,
        leave_alt: usize,
    }

    struct MockOps {
        log: Rc<RefCell<RecordedCalls>>,
        fail_enable_raw: bool,
        fail_enter_alt: bool,
    }

    impl TerminalLifecycleOps for MockOps {
        fn enable_raw(&mut self) -> io::Result<()> {
            self.log.borrow_mut().enable_raw += 1;
            if self.fail_enable_raw {
                return Err(io::Error::other("injected enable_raw failure"));
            }
            Ok(())
        }

        fn disable_raw(&mut self) -> io::Result<()> {
            self.log.borrow_mut().disable_raw += 1;
            Ok(())
        }

        fn enter_alt_screen(&mut self) -> io::Result<()> {
            self.log.borrow_mut().enter_alt += 1;
            if self.fail_enter_alt {
                return Err(io::Error::other("injected enter_alt failure"));
            }
            Ok(())
        }

        fn leave_alt_screen_and_show_cursor(&mut self) -> io::Result<()> {
            self.log.borrow_mut().leave_alt += 1;
            Ok(())
        }
    }

    #[test]
    fn guard_rolls_back_raw_mode_when_enter_alt_screen_fails() {
        let log = Rc::new(RefCell::new(RecordedCalls::default()));
        let ops = MockOps { log: Rc::clone(&log), fail_enable_raw: false, fail_enter_alt: true };

        let res = TerminalSessionGuard::enter(ops, false);
        assert!(res.is_err());
        assert_eq!(
            *log.borrow(),
            RecordedCalls { enable_raw: 1, disable_raw: 1, enter_alt: 1, leave_alt: 0 }
        );
    }

    #[test]
    fn guard_does_not_disable_unentered_modes_when_enable_raw_fails() {
        let log = Rc::new(RefCell::new(RecordedCalls::default()));
        let ops = MockOps { log: Rc::clone(&log), fail_enable_raw: true, fail_enter_alt: false };

        let res = TerminalSessionGuard::enter(ops, false);
        assert!(res.is_err());
        assert_eq!(
            *log.borrow(),
            RecordedCalls { enable_raw: 1, disable_raw: 0, enter_alt: 0, leave_alt: 0 }
        );
    }

    #[test]
    fn guard_restores_alt_screen_and_raw_mode_when_terminal_creation_fails_later() {
        let log = Rc::new(RefCell::new(RecordedCalls::default()));
        {
            let ops =
                MockOps { log: Rc::clone(&log), fail_enable_raw: false, fail_enter_alt: false };
            let _guard = TerminalSessionGuard::enter(ops, false).unwrap();
            assert_eq!(
                *log.borrow(),
                RecordedCalls { enable_raw: 1, disable_raw: 0, enter_alt: 1, leave_alt: 0 }
            );
            // Simulate early `?` return during Terminal::new(backend)
        }
        assert_eq!(
            *log.borrow(),
            RecordedCalls { enable_raw: 1, disable_raw: 1, enter_alt: 1, leave_alt: 1 }
        );
    }
}
