use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use crossbeam_channel::Sender;
use pnet::datalink::{self, Channel::Ethernet, NetworkInterface};

use crate::capture::parser::PacketSummary;
use crate::errors::{NetPulseError, Result};

/// Tìm kiếm interface mạng dựa theo tên (ví dụ: "eth0", "wlan0", "lo").
pub fn find_interface(name: &str) -> Result<NetworkInterface> {
    datalink::interfaces()
        .into_iter()
        .find(|iface| iface.name == name)
        .ok_or_else(|| NetPulseError::InterfaceNotFound(name.to_string()))
}

/// Liệt kê danh sách tất cả các interface mạng đang hoạt động trên hệ thống.
pub fn list_interfaces() -> Vec<String> {
    datalink::interfaces()
        .into_iter()
        .map(|iface| iface.name)
        .collect()
}

/// Khởi chạy luồng bắt gói tin trực tiếp từ tầng Datalink (Raw Socket / AF_PACKET trên Linux).
///
/// **Góc nhìn đa luồng & an toàn bộ nhớ:**
/// - `running: Arc<AtomicBool>`: Đóng vai trò con trỏ đếm tham chiếu đa luồng (Thread-safe Reference Counting)
///   giúp luồng UI ra lệnh dừng luồng Sniffer một cách an toàn mà không bị Data Race.
/// - `tx: Sender<PacketSummary>`: Kênh truyền thông đa luồng MPSC lock-free của `crossbeam-channel`.
///   Capture thread chỉ gửi metadata nhỏ gọn (Stack-allocated), không clone toàn bộ packet buffer.
pub fn start_sniffer_thread(
    interface: NetworkInterface,
    tx: Sender<PacketSummary>,
    running: Arc<AtomicBool>,
) -> Result<thread::JoinHandle<()>> {
    // Mở datalink channel ở chế độ Ethernet (bắt trực tiếp frame L2)
    let (_, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(tx_channel, rx_channel)) => {
            // Drop tx_channel vì sniffer passive chỉ cần nhận
            drop(tx_channel);
            ( (), rx_channel )
        }
        Ok(_) => {
            return Err(NetPulseError::UnsupportedProtocol(
                "Unsupported datalink channel type (only Ethernet L2 is supported)".into(),
            ));
        }
        Err(e) => {
            if e.kind() == std::io::ErrorKind::PermissionDenied {
                return Err(NetPulseError::PermissionDenied);
            }
            return Err(NetPulseError::SocketError(e));
        }
    };

    let handle = thread::Builder::new()
        .name("netpulse-sniffer".into())
        .spawn(move || {
            while running.load(Ordering::Relaxed) {
                match rx.next() {
                    Ok(packet_bytes) => {
                        // Bóc tách zero-copy
                        if let Ok(summary) = PacketSummary::parse(packet_bytes) {
                            if tx.send(summary).is_err() {
                                // Phía nhận (UI / App) đã đóng kênh, thoát luồng an toàn
                                break;
                            }
                        }
                    }
                    Err(e) => {
                        // Tránh tiêu tốn 100% CPU khi có lỗi socket ngắt quãng
                        if e.kind() == std::io::ErrorKind::TimedOut {
                            continue;
                        }
                        thread::sleep(Duration::from_millis(5));
                    }
                }
            }
        })
        .map_err(NetPulseError::SocketError)?;

    Ok(handle)
}

