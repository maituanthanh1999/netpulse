use std::collections::VecDeque;
use std::time::Instant;

use crate::capture::{L4Protocol, PacketSummary};

/// Các tab hiển thị bên trong Modal Packet Inspector
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InspectorTab {
    Decoded, // Tab 1: Phân giải chi tiết các tầng + Decode Payload
    RawHex,  // Tab 2: Hex Dump + ASCII View
}

/// Trạng thái quản lý dữ liệu toàn cục của ứng dụng NetPulse.
pub struct App {
    pub interface_name: String,
    pub packets: VecDeque<PacketSummary>,
    pub max_history: usize,
    pub is_paused: bool,
    pub selected_index: usize,
    pub auto_scroll: bool,
    pub protocol_filter: Option<L4Protocol>,
    pub notification: Option<(String, Instant)>,

    // Trạng thái modal Packet Inspector
    pub is_inspector_open: bool,
    pub inspector_tab: InspectorTab,
    pub inspector_scroll: usize,

    // Thống kê lũy kế
    pub total_packets: u64,
    pub total_bytes: u64,
    pub tcp_count: u64,
    pub udp_count: u64,
    pub icmp_count: u64,
    pub arp_count: u64,
    pub other_count: u64,

    // Thống kê tốc độ thời gian thực (Speed metrics)
    pub current_kbps: f64,
    pub current_pps: f64,
    last_tick: Instant,
    bytes_in_window: u64,
    packets_in_window: u64,
}

impl App {
    pub fn new(interface_name: String, max_history: usize) -> Self {
        Self {
            interface_name,
            packets: VecDeque::with_capacity(max_history),
            max_history,
            is_paused: false,
            selected_index: 0,
            auto_scroll: true, // Mặc định tự động bám theo gói tin mới nhất ở cuối danh sách
            protocol_filter: None,
            notification: None,

            is_inspector_open: false,
            inspector_tab: InspectorTab::Decoded,
            inspector_scroll: 0,

            total_packets: 0,
            total_bytes: 0,
            tcp_count: 0,
            udp_count: 0,
            icmp_count: 0,
            arp_count: 0,
            other_count: 0,

            current_kbps: 0.0,
            current_pps: 0.0,
            last_tick: Instant::now(),
            bytes_in_window: 0,
            packets_in_window: 0,
        }
    }

    /// Thêm một gói tin mới vào Ring Buffer và cập nhật thống kê
    pub fn push_packet(&mut self, packet: PacketSummary) {
        if self.is_paused {
            return;
        }

        self.total_packets += 1;
        self.total_bytes += packet.packet_len as u64;
        self.bytes_in_window += packet.packet_len as u64;
        self.packets_in_window += 1;

        match packet.protocol {
            L4Protocol::Tcp => self.tcp_count += 1,
            L4Protocol::Udp => self.udp_count += 1,
            L4Protocol::Icmp | L4Protocol::Icmpv6 => self.icmp_count += 1,
            L4Protocol::Arp => self.arp_count += 1,
            _ => self.other_count += 1,
        }

        if self.packets.len() >= self.max_history {
            self.packets.pop_front();
        }
        self.packets.push_back(packet);

        // Nếu bật Auto-scroll, con trỏ luôn nhảy tới gói tin mới nhất vừa tới
        if self.auto_scroll {
            let total = self.filtered_packets().len();
            self.selected_index = total.saturating_sub(1);
        }
    }

    /// Cập nhật tốc độ băng thông và số gói/giây mỗi chu kỳ
    pub fn update_rate_metrics(&mut self) {
        let elapsed = self.last_tick.elapsed().as_secs_f64();
        if elapsed >= 0.5 {
            self.current_kbps = (self.bytes_in_window as f64 / 1024.0) / elapsed;
            self.current_pps = self.packets_in_window as f64 / elapsed;

            self.bytes_in_window = 0;
            self.packets_in_window = 0;
            self.last_tick = Instant::now();
        }
    }

    /// Lọc danh sách gói tin theo bộ lọc giao thức hiện tại
    pub fn filtered_packets(&self) -> Vec<&PacketSummary> {
        self.packets
            .iter()
            .filter(|pkt| {
                if let Some(proto) = self.protocol_filter {
                    pkt.protocol == proto
                } else {
                    true
                }
            })
            .collect()
    }

    pub fn toggle_pause(&mut self) {
        self.is_paused = !self.is_paused;
    }

    pub fn clear_history(&mut self) {
        self.packets.clear();
        self.selected_index = 0;
    }

    pub fn cycle_filter(&mut self) {
        self.protocol_filter = match self.protocol_filter {
            None => Some(L4Protocol::Tcp),
            Some(L4Protocol::Tcp) => Some(L4Protocol::Udp),
            Some(L4Protocol::Udp) => Some(L4Protocol::Icmp),
            Some(L4Protocol::Icmp) => Some(L4Protocol::Arp),
            Some(L4Protocol::Arp) => Some(L4Protocol::Pppoe),
            Some(L4Protocol::Pppoe) => Some(L4Protocol::Igmp),
            _ => None,
        };
        // Cập nhật lại con trỏ trong danh sách đã lọc
        let total = self.filtered_packets().len();
        self.selected_index = total.saturating_sub(1);
    }

    pub fn scroll_up(&mut self) {
        self.auto_scroll = false; // Người dùng chủ động xem lại lịch sử -> tạm dừng auto-scroll
        if self.selected_index > 0 {
            self.selected_index -= 1;
        }
    }

    pub fn scroll_down(&mut self, max_rows: usize) {
        if max_rows > 0 && self.selected_index < max_rows.saturating_sub(1) {
            self.selected_index += 1;
            // Nếu đã cuộn xuống dòng cuối cùng, tự động kích hoạt lại auto-scroll
            if self.selected_index == max_rows.saturating_sub(1) {
                self.auto_scroll = true;
            }
        }
    }

    pub fn jump_to_latest(&mut self) {
        let total = self.filtered_packets().len();
        self.selected_index = total.saturating_sub(1);
        self.auto_scroll = true;
    }

    pub fn jump_to_top(&mut self) {
        self.selected_index = 0;
        self.auto_scroll = false;
    }

    pub fn toggle_auto_scroll(&mut self) {
        self.auto_scroll = !self.auto_scroll;
        if self.auto_scroll {
            self.jump_to_latest();
        }
    }

    pub fn open_inspector(&mut self) {
        if !self.filtered_packets().is_empty() {
            self.is_inspector_open = true;
            self.inspector_tab = InspectorTab::Decoded;
            self.inspector_scroll = 0;
        }
    }

    pub fn close_inspector(&mut self) {
        self.is_inspector_open = false;
        self.inspector_scroll = 0;
    }

    pub fn switch_inspector_tab(&mut self) {
        self.inspector_tab = match self.inspector_tab {
            InspectorTab::Decoded => InspectorTab::RawHex,
            InspectorTab::RawHex => InspectorTab::Decoded,
        };
        self.inspector_scroll = 0;
    }

    pub fn set_inspector_tab(&mut self, tab: InspectorTab) {
        self.inspector_tab = tab;
        self.inspector_scroll = 0;
    }

    pub fn scroll_inspector_up(&mut self) {
        if self.inspector_scroll > 0 {
            self.inspector_scroll -= 1;
        }
    }

    pub fn scroll_inspector_down(&mut self) {
        self.inspector_scroll += 1;
    }

    pub fn selected_packet(&self) -> Option<&PacketSummary> {
        let list = self.filtered_packets();
        if list.is_empty() {
            None
        } else {
            let idx = self.selected_index.min(list.len() - 1);
            Some(list[idx])
        }
    }

    pub fn set_notification(&mut self, msg: String) {
        self.notification = Some((msg, Instant::now()));
    }

    /// Export all current buffered packets to a .pcap file
    pub fn save_current_pcap(&mut self) {
        let list = self.filtered_packets();
        if list.is_empty() {
            self.set_notification("⚠️ Buffer is empty, no packets to export".to_string());
            return;
        }

        let timestamp_str = match std::time::SystemTime::now().duration_since(std::time::SystemTime::UNIX_EPOCH) {
            Ok(d) => d.as_secs().to_string(),
            Err(_) => "0".to_string(),
        };

        let filename = format!("netpulse_{}_{}.pcap", self.interface_name, timestamp_str);
        match crate::capture::export_to_pcap(&filename, &list) {
            Ok(count) => {
                self.set_notification(format!("💾 Exported {} packets to '{}' (Wireshark PCAP)", count, filename));
            }
            Err(e) => {
                self.set_notification(format!("❌ PCAP export error: {}", e));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ring_buffer_bounds() {
        let mut app = App::new("lo".into(), 3);
        let dummy = PacketSummary {
            timestamp: std::time::SystemTime::now(),
            src_mac: [0; 6],
            dst_mac: [0; 6],
            ether_type: 0x0800,
            vlan_tags: Vec::new(),
            src_ip: None,
            dst_ip: None,
            src_port: None,
            dst_port: None,
            protocol: L4Protocol::Tcp,
            packet_len: 64,
            payload_len: 0,
            payload_offset: 64,
            tcp_flags: None,
            ttl: None,
            ip_id: None,
            ip_flags_df: false,
            seq_num: None,
            ack_num: None,
            window_size: None,
            icmp_type: None,
            icmp_code: None,
            arp_details: None,
            app_protocol: "TCP".to_string(),
            raw_data: vec![0u8; 64],
        };

        app.push_packet(dummy.clone());
        app.push_packet(dummy.clone());
        app.push_packet(dummy.clone());
        assert_eq!(app.packets.len(), 3);

        app.push_packet(dummy.clone());
        assert_eq!(app.packets.len(), 3);
        assert_eq!(app.total_packets, 4);
    }

    #[test]
    fn test_auto_scroll_behavior() {
        let mut app = App::new("lo".into(), 10);
        let dummy = PacketSummary {
            timestamp: std::time::SystemTime::now(),
            src_mac: [0; 6],
            dst_mac: [0; 6],
            ether_type: 0x0800,
            vlan_tags: Vec::new(),
            src_ip: None,
            dst_ip: None,
            src_port: None,
            dst_port: None,
            protocol: L4Protocol::Tcp,
            packet_len: 64,
            payload_len: 0,
            payload_offset: 64,
            tcp_flags: None,
            ttl: None,
            ip_id: None,
            ip_flags_df: false,
            seq_num: None,
            ack_num: None,
            window_size: None,
            icmp_type: None,
            icmp_code: None,
            arp_details: None,
            app_protocol: "TCP".to_string(),
            raw_data: vec![0u8; 64],
        };

        app.push_packet(dummy.clone());
        assert_eq!(app.selected_index, 0);

        app.push_packet(dummy.clone());
        assert_eq!(app.selected_index, 1);

        app.push_packet(dummy.clone());
        assert_eq!(app.selected_index, 2);

        // Người dùng cuộn lên -> tắt auto-scroll
        app.scroll_up();
        assert_eq!(app.selected_index, 1);
        assert_eq!(app.auto_scroll, false);

        // Có gói mới tới nhưng cursor vẫn ở vị trí người dùng đang đọc
        app.push_packet(dummy.clone());
        assert_eq!(app.selected_index, 1);

        // Bấm G nhảy tới gói mới nhất -> bật lại auto-scroll
        app.jump_to_latest();
        assert_eq!(app.selected_index, 3);
        assert_eq!(app.auto_scroll, true);
    }
}
