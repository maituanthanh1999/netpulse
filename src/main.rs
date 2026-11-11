use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use crossterm::{
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{backend::CrosstermBackend, Terminal};

mod app;
mod capture;
mod cli;
mod errors;
mod ui;

use app::App;
use capture::{find_interface, list_interfaces, start_sniffer_thread, PacketSummary};
use cli::CliArgs;
use errors::NetPulseError;
use ui::{handle_events, render, AppAction};

fn main() -> anyhow::Result<()> {
    let args = CliArgs::parse();

    // 1. List network interfaces mode (--list)
    if args.list {
        println!("Available network interfaces on system:");
        for iface in list_interfaces() {
            println!("  - {}", iface);
        }
        return Ok(());
    }

    // 2. Select target network interface
    let iface_name = match args.interface {
        Some(name) => name,
        None => {
            let available = list_interfaces();
            let picked = available
                .iter()
                .find(|name| !name.starts_with("lo") && !name.starts_with("docker") && !name.starts_with("veth"))
                .cloned()
                .unwrap_or_else(|| "lo".to_string());

            println!(
                "No interface specified via -i. Auto-selected: '{}' (Use --list to view all interfaces)",
                picked
            );
            picked
        }
    };

    let target_iface = match find_interface(&iface_name) {
        Ok(iface) => iface,
        Err(e) => {
            eprintln!("Error: {}", e);
            eprintln!("Available interfaces: {:?}", list_interfaces());
            std::process::exit(1);
        }
    };

    // 3. Setup MPSC channel between Sniffer thread and UI thread
    let (tx, rx) = crossbeam_channel::unbounded::<PacketSummary>();
    let running = Arc::new(AtomicBool::new(true));

    // 4. Spawn Sniffer thread
    let sniffer_handle = match start_sniffer_thread(target_iface, tx, running.clone()) {
        Ok(handle) => handle,
        Err(NetPulseError::PermissionDenied) => {
            eprintln!("\n❌ PERMISSION DENIED:");
            eprintln!("Capturing raw packets at datalink level requires root privileges or Linux Capabilities.");
            eprintln!("Please run with sudo:");
            eprintln!("  sudo cargo run -- -i {}\n", iface_name);
            eprintln!("Or grant capability to the binary (run without sudo):");
            eprintln!("  sudo setcap cap_net_raw,cap_net_admin=eip ./target/debug/netpulse\n");
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("Failed to start sniffer: {}", e);
            std::process::exit(1);
        }
    };

    // 5. Initialize Terminal TUI
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut app = App::new(iface_name, args.buffer_size);

    // Initialize continuous PCAP Stream Dump if -d / --dump flag is provided
    let mut pcap_stream = if let Some(ref dump_path) = args.dump {
        match capture::PcapWriter::create(dump_path) {
            Ok(writer) => {
                app.set_notification(format!("🔴 Live streaming PCAP to '{}'", dump_path));
                Some(writer)
            }
            Err(e) => {
                eprintln!("Failed to create PCAP dump file '{}': {}", dump_path, e);
                std::process::exit(1);
            }
        }
    } else {
        None
    };

    // 6. Vòng lặp sự kiện chính (Main Event Loop)
    let loop_result = run_app(&mut terminal, &mut app, &rx, &mut pcap_stream);

    // Đảm bảo flush dữ liệu pcap còn dư
    if let Some(ref mut writer) = pcap_stream {
        let _ = writer.flush();
    }

    // 7. Dọn dẹp an toàn khi thoát (Clean teardown)
    running.store(false, Ordering::Relaxed);
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    // Đợi sniffer thread dừng an toàn
    let _ = sniffer_handle.join();

    if let Err(err) = loop_result {
        eprintln!("Lỗi ứng dụng: {:?}", err);
    }

    Ok(())
}

fn run_app(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    app: &mut App,
    rx: &crossbeam_channel::Receiver<PacketSummary>,
    pcap_stream: &mut Option<capture::PcapWriter>,
) -> io::Result<()> {
    loop {
        // Rút cạn các gói tin đang chờ trong queue (Non-blocking) để cập nhật state
        while let Ok(packet) = rx.try_recv() {
            if let Some(ref mut writer) = pcap_stream {
                let _ = writer.write_packet(&packet);
            }
            app.push_packet(packet);
        }

        // Cập nhật tốc độ băng thông
        app.update_rate_metrics();

        // Render giao diện TUI
        terminal.draw(|frame| render(frame, app))?;

        // Lắng nghe sự kiện phím với timeout 20ms (~50 FPS)
        match handle_events(app, Duration::from_millis(20))? {
            AppAction::Quit => break,
            AppAction::Continue => {}
        }
    }
    Ok(())
}
