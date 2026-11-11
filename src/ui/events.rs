use std::time::Duration;
use crossterm::event::{self, Event, KeyCode, KeyModifiers};

use crate::app::{App, InspectorTab};

pub enum AppAction {
    Continue,
    Quit,
}

/// Xử lý sự kiện bàn phím không chặn (Non-blocking I/O)
pub fn handle_events(app: &mut App, poll_timeout: Duration) -> std::io::Result<AppAction> {
    if event::poll(poll_timeout)? {
        if let Event::Key(key) = event::read()? {
            // 1. Nếu đang mở Modal Packet Inspector
            if app.is_inspector_open {
                match key.code {
                    // Đóng modal
                    KeyCode::Esc | KeyCode::Char('q') | KeyCode::Enter => {
                        app.close_inspector();
                    }
                    // Chuyển đổi giữa 2 Tab: Decoded <-> Raw Hex
                    KeyCode::Tab | KeyCode::Left | KeyCode::Right => {
                        app.switch_inspector_tab();
                    }
                    KeyCode::Char('1') => {
                        app.set_inspector_tab(InspectorTab::Decoded);
                    }
                    KeyCode::Char('2') => {
                        app.set_inspector_tab(InspectorTab::RawHex);
                    }
                    // Cuộn nội dung trong tab hiện tại
                    KeyCode::Up | KeyCode::Char('k') => {
                        app.scroll_inspector_up();
                    }
                    KeyCode::Down | KeyCode::Char('j') => {
                        app.scroll_inspector_down();
                    }
                    KeyCode::PageUp => {
                        for _ in 0..6 {
                            app.scroll_inspector_up();
                        }
                    }
                    KeyCode::PageDown => {
                        for _ in 0..6 {
                            app.scroll_inspector_down();
                        }
                    }
                    KeyCode::Home | KeyCode::Char('g') => {
                        app.inspector_scroll = 0;
                    }
                    _ => {}
                }
                return Ok(AppAction::Continue);
            }

            // 2. Xử lý phím tắt ở màn hình chính (Main Dashboard)
            match (key.code, key.modifiers) {
                (KeyCode::Char('c'), KeyModifiers::CONTROL) | (KeyCode::Char('q'), _) => {
                    return Ok(AppAction::Quit);
                }
                (KeyCode::Enter, _) => {
                    app.open_inspector();
                }
                (KeyCode::Char(' '), _) => {
                    app.toggle_pause();
                }
                (KeyCode::Tab, _) | (KeyCode::Char('f'), _) => {
                    app.cycle_filter();
                }
                (KeyCode::Char('a'), _) => {
                    app.toggle_auto_scroll();
                }
                (KeyCode::Char('s'), _) | (KeyCode::Char('p'), _) => {
                    app.save_current_pcap();
                }
                (KeyCode::Char('c'), _) => {
                    app.clear_history();
                }
                (KeyCode::Char('G'), _) | (KeyCode::End, _) => {
                    app.jump_to_latest();
                }
                (KeyCode::Char('g'), _) | (KeyCode::Home, _) => {
                    app.jump_to_top();
                }
                (KeyCode::Up, _) | (KeyCode::Char('k'), _) => {
                    app.scroll_up();
                }
                (KeyCode::Down, _) | (KeyCode::Char('j'), _) => {
                    let total = app.filtered_packets().len();
                    app.scroll_down(total);
                }
                _ => {}
            }
        }
    }
    Ok(AppAction::Continue)
}
