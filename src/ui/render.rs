use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, BorderType, Borders, Cell, Clear, Paragraph, Row, Table, Tabs},
    Frame,
};

use crate::app::{App, InspectorTab};
use crate::capture::{L4Protocol, PacketSummary};

pub fn render(frame: &mut Frame, app: &mut App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(4), // Chunk 1: Metrics & System Status
            Constraint::Min(8),    // Chunk 2: Packet Stream Table
            Constraint::Length(3), // Chunk 3: Command & Keybind Footer
        ])
        .split(frame.area());

    render_header(frame, app, chunks[0]);
    render_packet_table(frame, app, chunks[1]);
    render_footer(frame, app, chunks[2]);

    // Render Inspector Modal if open
    if app.is_inspector_open {
        render_inspector_modal(frame, app);
    }
}

fn render_header(frame: &mut Frame, app: &App, area: Rect) {
    let status_style = if app.is_paused {
        Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)
    };
    let status_text = if app.is_paused { "[PAUSED]" } else { "[CAPTURING]" };

    let auto_scroll_span = if app.auto_scroll {
        Span::styled(" [ON] ", Style::default().fg(Color::Green).add_modifier(Modifier::BOLD))
    } else {
        Span::styled(" [OFF - Press 'G' to follow] ", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD))
    };

    let stats_line = Line::from(vec![
        Span::raw(" Total: "),
        Span::styled(format!("{} pkts", app.total_packets), Style::default().fg(Color::White).add_modifier(Modifier::BOLD)),
        Span::raw(" ("),
        Span::styled(format!("{:.2} MB", app.total_bytes as f64 / 1_048_576.0), Style::default().fg(Color::White)),
        Span::raw(") | TCP: "),
        Span::styled(format!("{}", app.tcp_count), Style::default().fg(Color::LightBlue)),
        Span::raw(" | UDP: "),
        Span::styled(format!("{}", app.udp_count), Style::default().fg(Color::LightGreen)),
        Span::raw(" | ICMP: "),
        Span::styled(format!("{}", app.icmp_count), Style::default().fg(Color::LightRed)),
        Span::raw(" | ARP: "),
        Span::styled(format!("{}", app.arp_count), Style::default().fg(Color::LightMagenta)),
    ]);

    let second_line = if let Some((ref msg, instant)) = app.notification {
        if instant.elapsed() < std::time::Duration::from_secs(5) {
            Line::from(vec![
                Span::styled(" [NOTIFICATION] ", Style::default().fg(Color::Black).bg(Color::Yellow).add_modifier(Modifier::BOLD)),
                Span::styled(format!(" {} ", msg), Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
            ])
        } else {
            stats_line
        }
    } else {
        stats_line
    };

    let header_lines = vec![
        Line::from(vec![
            Span::raw(" Interface: "),
            Span::styled(&app.interface_name, Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
            Span::raw(" | Status: "),
            Span::styled(status_text, status_style),
            Span::raw(" | Auto-scroll: "),
            auto_scroll_span,
            Span::raw(" | Bandwidth: "),
            Span::styled(format!("{:.2} KB/s", app.current_kbps), Style::default().fg(Color::Yellow)),
            Span::raw(" | Rate: "),
            Span::styled(format!("{:.0} pps", app.current_pps), Style::default().fg(Color::Yellow)),
            Span::raw(" | Ring Buffer: "),
            Span::styled(format!("{}/{}", app.packets.len(), app.max_history), Style::default().fg(Color::Magenta)),
        ]),
        second_line,
    ];

    let header_block = Paragraph::new(header_lines).block(
        Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .title(" 📡 NetPulse Embedded Monitor ")
            .title_style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
    );

    frame.render_widget(header_block, area);
}

fn render_packet_table(frame: &mut Frame, app: &App, area: Rect) {
    let filtered_list = app.filtered_packets();
    let total_items = filtered_list.len();

    let header_cells = ["No.", "Timestamp", "Proto", "Source", "Destination", "Bytes", "Protocol / Flags"]
        .iter()
        .map(|h| Cell::from(*h).style(Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)));
    let header = Row::new(header_cells).height(1).bottom_margin(1);

    // Calculate pagination / scroll offset ensuring selected row remains visible
    let visible_rows = area.height.saturating_sub(4) as usize;

    let start_idx = if total_items > visible_rows {
        if app.selected_index >= visible_rows {
            (app.selected_index + 1).saturating_sub(visible_rows)
        } else {
            0
        }
    } else {
        0
    };

    let rows: Vec<Row> = filtered_list
        .iter()
        .skip(start_idx)
        .take(visible_rows)
        .enumerate()
        .map(|(rel_idx, pkt)| {
            let abs_idx = start_idx + rel_idx;
            let is_selected = abs_idx == app.selected_index;

            let proto_color = match pkt.protocol {
                L4Protocol::Tcp => Color::LightBlue,
                L4Protocol::Udp => Color::LightGreen,
                L4Protocol::Icmp | L4Protocol::Icmpv6 => Color::LightRed,
                L4Protocol::Arp => Color::LightMagenta,
                _ => Color::Gray,
            };

            let src_str = match (pkt.src_ip, pkt.src_port) {
                (Some(ip), Some(port)) => format!("{}:{}", ip, port),
                (Some(ip), None) => format!("{}", ip),
                _ => format_mac(&pkt.src_mac),
            };

            let dst_str = match (pkt.dst_ip, pkt.dst_port) {
                (Some(ip), Some(port)) => format!("{}:{}", ip, port),
                (Some(ip), None) => format!("{}", ip),
                _ => format_mac(&pkt.dst_mac),
            };

            let details = if !pkt.app_protocol.is_empty() && pkt.app_protocol != pkt.protocol.to_string() {
                if let Some(ref flags) = pkt.tcp_flags {
                    format!("{} [{}]", pkt.app_protocol, flags)
                } else if pkt.payload_len > 0 {
                    format!("{} ({}B)", pkt.app_protocol, pkt.payload_len)
                } else {
                    pkt.app_protocol.clone()
                }
            } else if let Some(ref flags) = pkt.tcp_flags {
                flags.clone()
            } else if pkt.payload_len > 0 {
                format!("Payload: {}B", pkt.payload_len)
            } else {
                "-".into()
            };

            let cursor_prefix = if is_selected { "▶ " } else { "  " };

            let mut row = Row::new(vec![
                Cell::from(format!("{}{}", cursor_prefix, abs_idx + 1)),
                Cell::from(format_timestamp(pkt.timestamp)),
                Cell::from(pkt.protocol.to_string()).style(Style::default().fg(proto_color)),
                Cell::from(src_str),
                Cell::from(dst_str),
                Cell::from(format!("{}", pkt.packet_len)),
                Cell::from(details),
            ]);

            if is_selected {
                row = row.style(
                    Style::default()
                        .bg(Color::Rgb(40, 55, 80))
                        .fg(Color::White)
                        .add_modifier(Modifier::BOLD),
                );
            }

            row
        })
        .collect();

    let cur_pos = if total_items > 0 { app.selected_index + 1 } else { 0 };
    let title = match app.protocol_filter {
        Some(proto) => format!(" 📋 Packet Stream [Filter: {}] | Total: {} | Cursor: #{}/{} ", proto, total_items, cur_pos, total_items),
        None => format!(" 📋 Packet Stream [All Protocols] | Total: {} | Cursor: #{}/{} ", total_items, cur_pos, total_items),
    };

    let table = Table::new(
        rows,
        [
            Constraint::Length(7),      // No.
            Constraint::Length(13),     // Timestamp
            Constraint::Length(7),      // Proto
            Constraint::Percentage(24), // Src
            Constraint::Percentage(24), // Dst
            Constraint::Length(7),      // Bytes
            Constraint::Percentage(25), // Details
        ],
    )
    .header(header)
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .title(title)
            .title_style(Style::default().fg(Color::White).add_modifier(Modifier::BOLD)),
    );

    frame.render_widget(table, area);
}

fn render_footer(frame: &mut Frame, _app: &App, area: Rect) {
    let keybinds = Line::from(vec![
        Span::styled(" [q] ", Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)),
        Span::raw("Quit  "),
        Span::styled("[Enter] ", Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)),
        Span::raw("Inspect  "),
        Span::styled("[G] ", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
        Span::raw("Live Bottom  "),
        Span::styled("[a] ", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
        Span::raw("Auto-scroll  "),
        Span::styled("[Space] ", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
        Span::raw("Pause  "),
        Span::styled("[Tab/f] ", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
        Span::raw("Filter  "),
        Span::styled("[c] ", Style::default().fg(Color::Magenta).add_modifier(Modifier::BOLD)),
        Span::raw("Clear  "),
        Span::styled("[s] ", Style::default().fg(Color::LightGreen).add_modifier(Modifier::BOLD)),
        Span::raw("Export PCAP  "),
        Span::styled("[↑/↓] ", Style::default().fg(Color::White).add_modifier(Modifier::BOLD)),
        Span::raw("Select"),
    ]);

    let footer = Paragraph::new(keybinds).block(
        Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded),
    );

    frame.render_widget(footer, area);
}

/// Renders Popup Modal with two tabs: [1. Decoded Dissector] and [2. Raw Hex Dump]
fn render_inspector_modal(frame: &mut Frame, app: &App) {
    let selected = match app.selected_packet() {
        Some(pkt) => pkt,
        None => return,
    };

    let area = centered_rect(90, 88, frame.area());
    frame.render_widget(Clear, area);

    let modal_block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Double)
        .title(format!(
            " 🔬 Packet Inspector [Packet #{}] - {} ({} Bytes) | Timestamp: {} ",
            app.selected_index + 1,
            selected.app_protocol,
            selected.packet_len,
            format_timestamp(selected.timestamp)
        ))
        .title_style(Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD));

    let inner_area = modal_block.inner(area);
    frame.render_widget(modal_block, area);

    // Modal layout:
    // Row 0: Tab selection bar
    // Row 1: Selected Tab Content
    // Row 2: Footer keybind hints
    let modal_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Tab bar
            Constraint::Min(8),    // Body content
            Constraint::Length(2), // Footer hints
        ])
        .split(inner_area);

    // 1. Render Tab Bar
    let tab_titles = vec![
        Line::from(" [1] 📜 Decoded Dissector "),
        Line::from(" [2] 🔍 Raw Hex Dump + ASCII "),
    ];
    let selected_tab_idx = match app.inspector_tab {
        InspectorTab::Decoded => 0,
        InspectorTab::RawHex => 1,
    };
    let tabs = Tabs::new(tab_titles)
        .select(selected_tab_idx)
        .block(Block::default().borders(Borders::BOTTOM))
        .style(Style::default().fg(Color::Gray))
        .highlight_style(
            Style::default()
                .fg(Color::Yellow)
                .bg(Color::Rgb(30, 45, 70))
                .add_modifier(Modifier::BOLD),
        );
    frame.render_widget(tabs, modal_chunks[0]);

    // 2. Render Selected Tab Content
    match app.inspector_tab {
        InspectorTab::Decoded => {
            render_decoded_tab(frame, selected, app.inspector_scroll, modal_chunks[1]);
        }
        InspectorTab::RawHex => {
            render_hex_dump_tab(frame, &selected.raw_data, app.inspector_scroll, modal_chunks[1]);
        }
    }

    // 3. Footer hints
    let hint = Line::from(vec![
        Span::styled(" [Tab / 1-2 / ← →] ", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
        Span::raw("Switch Tab   "),
        Span::styled("[↑ / ↓ / j / k] ", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
        Span::raw("Scroll   "),
        Span::styled("[PgUp / PgDn] ", Style::default().fg(Color::LightGreen).add_modifier(Modifier::BOLD)),
        Span::raw("Scroll Fast   "),
        Span::styled("[Esc / Enter / q] ", Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)),
        Span::raw("Close"),
    ]);
    frame.render_widget(Paragraph::new(hint), modal_chunks[2]);
}

/// TAB 1: PROTOCOL DISSECTION & APPLICATION DECODE (DECODED VIEW)
fn render_decoded_tab(frame: &mut Frame, pkt: &PacketSummary, scroll: usize, area: Rect) {
    let mut lines = Vec::new();

    // 1. Layer 2: Ethernet II & 802.1Q / QinQ VLAN
    lines.push(Line::from(Span::styled("▼ [LAYER 2] Ethernet II", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD))));
    lines.push(Line::from(format!("  ├─ Destination MAC : {}", format_mac(&pkt.dst_mac))));
    lines.push(Line::from(format!("  ├─ Source MAC      : {}", format_mac(&pkt.src_mac))));

    if !pkt.vlan_tags.is_empty() {
        for (v_idx, tag) in pkt.vlan_tags.iter().enumerate() {
            let tag_name = if tag.tpid == 0x88a8 { "802.1ad S-VLAN (QinQ / Service)" } else { "802.1Q C-VLAN (Customer / Access)" };
            let pcp_desc = match tag.pcp {
                0 => "Best Effort (0)",
                1 => "Background (1)",
                2 => "Excellent Effort (2)",
                3 => "Critical App (3)",
                4 => "Video / Low Latency (4)",
                5 => "Voice / IPTV (5)",
                6 => "Internetwork Control (6)",
                7 => "Network Control (7)",
                _ => "",
            };
            lines.push(Line::from(vec![
                Span::raw(format!("  ├─ VLAN Tag #{}: ", v_idx + 1)),
                Span::styled(format!("VLAN ID {} ", tag.vid), Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
                Span::styled(format!("[{}] | PCP/CoS: {} | DEI: {}", tag_name, pcp_desc, if tag.dei { "1" } else { "0" }), Style::default().fg(Color::LightMagenta)),
            ]));
        }
    }

    let eth_type_desc = match pkt.ether_type {
        0x0800 => "IPv4 (0x0800)",
        0x86dd => "IPv6 (0x86dd)",
        0x0806 => "ARP (0x0806)",
        0x8863 => "PPPoE Discovery (0x8863)",
        0x8864 => "PPPoE Session (0x8864)",
        0x88cc => "LLDP (0x88cc)",
        0x888e => "EAPoL / 802.1X (0x888e)",
        _other => "Custom / Protocol Frame",
    };
    lines.push(Line::from(format!("  ├─ EtherType        : 0x{:04x} [{}]", pkt.ether_type, eth_type_desc)));
    lines.push(Line::from(format!("  └─ Total Frame Size : {} Bytes", pkt.packet_len)));
    lines.push(Line::raw(""));

    // 2. Layer 3: Network (IPv4 / IPv6 / ARP)
    if let Some(ref arp) = pkt.arp_details {
        lines.push(Line::from(Span::styled("▼ [LAYER 3] Address Resolution Protocol (ARP)", Style::default().fg(Color::LightMagenta).add_modifier(Modifier::BOLD))));
        let op_desc = if arp.opcode == 1 { "1 (ARP Request - Who has IP?)" } else if arp.opcode == 2 { "2 (ARP Reply - Is at MAC)" } else { "Unknown" };
        lines.push(Line::from(format!("  ├─ Opcode           : {}", op_desc)));
        lines.push(Line::from(format!("  ├─ Sender Hardware  : IP {}.{}.{}.{} | MAC {}", arp.sender_ip[0], arp.sender_ip[1], arp.sender_ip[2], arp.sender_ip[3], format_mac(&arp.sender_mac))));
        lines.push(Line::from(format!("  └─ Target Hardware  : IP {}.{}.{}.{} | MAC {}", arp.target_ip[0], arp.target_ip[1], arp.target_ip[2], arp.target_ip[3], format_mac(&arp.target_mac))));
    } else if let (Some(src), Some(dst)) = (pkt.src_ip, pkt.dst_ip) {
        let is_v6 = src.is_ipv6();
        let proto_name = if is_v6 { "Internet Protocol Version 6 (IPv6)" } else { "Internet Protocol Version 4 (IPv4)" };
        lines.push(Line::from(Span::styled(format!("▼ [LAYER 3] {}", proto_name), Style::default().fg(Color::Green).add_modifier(Modifier::BOLD))));
        lines.push(Line::from(format!("  ├─ Source IP        : {}", src)));
        lines.push(Line::from(format!("  ├─ Destination IP   : {}", dst)));
        if let Some(ttl) = pkt.ttl {
            lines.push(Line::from(format!("  ├─ Time to Live (TTL): {} hops", ttl)));
        }
        if let Some(ip_id) = pkt.ip_id {
            lines.push(Line::from(format!("  ├─ Identification   : 0x{:04x} ({})", ip_id, ip_id)));
        }
        lines.push(Line::from(format!("  └─ Don't Fragment   : {}", if pkt.ip_flags_df { "Enabled [DF]" } else { "Disabled" })));
    }
    lines.push(Line::raw(""));

    // 3. Layer 4: Transport (TCP / UDP / ICMP)
    match pkt.protocol {
        L4Protocol::Tcp => {
            lines.push(Line::from(Span::styled("▼ [LAYER 4] Transmission Control Protocol (TCP)", Style::default().fg(Color::LightBlue).add_modifier(Modifier::BOLD))));
            if let (Some(sp), Some(dp)) = (pkt.src_port, pkt.dst_port) {
                lines.push(Line::from(format!("  ├─ Source Port      : {}  ->  Destination Port: {}", sp, dp)));
            }
            if let Some(ref flags) = pkt.tcp_flags {
                lines.push(Line::from(vec![
                    Span::raw("  ├─ Control Flags    : "),
                    Span::styled(format!("[{}]", flags), Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
                ]));
            }
            if let Some(seq) = pkt.seq_num {
                lines.push(Line::from(format!("  ├─ Sequence Number  : {}", seq)));
            }
            if let Some(ack) = pkt.ack_num {
                lines.push(Line::from(format!("  ├─ Acknowledgment   : {}", ack)));
            }
            if let Some(win) = pkt.window_size {
                lines.push(Line::from(format!("  ├─ TCP Window Size  : {} Bytes", win)));
            }
            lines.push(Line::from(format!("  └─ TCP Payload Size : {} Bytes", pkt.payload_len)));
        }
        L4Protocol::Udp => {
            lines.push(Line::from(Span::styled("▼ [LAYER 4] User Datagram Protocol (UDP)", Style::default().fg(Color::LightGreen).add_modifier(Modifier::BOLD))));
            if let (Some(sp), Some(dp)) = (pkt.src_port, pkt.dst_port) {
                lines.push(Line::from(format!("  ├─ Source Port      : {}  ->  Destination Port: {}", sp, dp)));
            }
            lines.push(Line::from(format!("  └─ UDP Payload Size : {} Bytes", pkt.payload_len)));
        }
        L4Protocol::Icmp | L4Protocol::Icmpv6 => {
            lines.push(Line::from(Span::styled("▼ [LAYER 4] Internet Control Message Protocol (ICMP)", Style::default().fg(Color::LightRed).add_modifier(Modifier::BOLD))));
            let type_str = match (pkt.icmp_type, pkt.icmp_code) {
                (Some(8), Some(0)) => "Echo Request (Ping)",
                (Some(0), Some(0)) => "Echo Reply (Pong)",
                (Some(3), _) => "Destination Unreachable",
                (Some(11), _) => "Time Exceeded (TTL expired in transit)",
                (Some(_), Some(_)) => "ICMP Message",
                _ => "ICMP",
            };
            lines.push(Line::from(format!("  ├─ Message Type     : {} (Type: {}, Code: {})", type_str, pkt.icmp_type.unwrap_or(0), pkt.icmp_code.unwrap_or(0))));
            lines.push(Line::from(format!("  └─ Payload Size     : {} Bytes", pkt.payload_len)));
        }
        _ => {}
    }
    lines.push(Line::raw(""));

    // 4. Layer 7 / Decoded Payload View
    lines.push(Line::from(Span::styled("▼ [APPLICATION LAYER & DECODED PAYLOAD]", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD))));
    for p_line in pkt.decode_payload_lines() {
        lines.push(Line::from(p_line));
    }

    // Scroll handling inside Decoded Tab
    let total_lines = lines.len();
    let max_visible = area.height.saturating_sub(2) as usize;
    let start_idx = scroll.min(total_lines.saturating_sub(1));

    let visible_lines: Vec<Line> = lines.into_iter().skip(start_idx).take(max_visible).collect();

    let title = format!(" 📜 Decoded Dissector [Line: {}/{} | Scroll: ↑/↓] ", start_idx + 1, total_lines.max(1));
    let block = Paragraph::new(visible_lines).block(
        Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .title(title)
            .title_style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
    );

    frame.render_widget(block, area);
}

/// TAB 2: RAW HEX DUMP + ASCII VIEW
fn render_hex_dump_tab(frame: &mut Frame, data: &[u8], scroll: usize, area: Rect) {
    let mut lines = Vec::new();
    let total_bytes = data.len();
    let total_rows = (total_bytes + 15) / 16;

    // Header row for Hex Dump
    lines.push(Line::from(vec![
        Span::styled("Offset    ", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
        Span::styled("00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F   ", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
        Span::styled("ASCII View", Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)),
    ]));
    lines.push(Line::from(Span::styled("─".repeat(area.width.saturating_sub(4) as usize), Style::default().fg(Color::DarkGray))));

    let max_display_rows = area.height.saturating_sub(4) as usize;
    let start_row = scroll.min(total_rows.saturating_sub(1));

    for row_idx in start_row..total_rows.min(start_row + max_display_rows) {
        let offset = row_idx * 16;
        let chunk_end = (offset + 16).min(total_bytes);
        let chunk = &data[offset..chunk_end];

        let mut spans = Vec::new();

        // 1. Offset
        spans.push(Span::styled(format!("{:06x}    ", offset), Style::default().fg(Color::Yellow)));

        // 2. Hex values (16 bytes, split at byte 8)
        let mut hex_part = String::with_capacity(50);
        for i in 0..16 {
            if i < chunk.len() {
                hex_part.push_str(&format!("{:02x} ", chunk[i]));
            } else {
                hex_part.push_str("   ");
            }
            if i == 7 {
                hex_part.push(' ');
            }
        }
        hex_part.push_str("  ");
        spans.push(Span::styled(hex_part, Style::default().fg(Color::White)));

        // 3. ASCII representation
        let mut ascii_part = String::with_capacity(18);
        ascii_part.push('|');
        for &b in chunk {
            if (32..=126).contains(&b) {
                ascii_part.push(b as char);
            } else {
                ascii_part.push('.');
            }
        }
        ascii_part.push('|');
        spans.push(Span::styled(ascii_part, Style::default().fg(Color::LightGreen)));

        lines.push(Line::from(spans));
    }

    let title = format!(" 🔍 Hex Dump View [Total: {} Bytes | Line: {}/{}] ", total_bytes, start_row + 1, total_rows.max(1));
    let hex_block = Paragraph::new(lines).block(
        Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .title(title)
            .title_style(Style::default().fg(Color::White).add_modifier(Modifier::BOLD)),
    );

    frame.render_widget(hex_block, area);
}

fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(r);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(popup_layout[1])[1]
}

fn format_timestamp(time: std::time::SystemTime) -> String {
    if let Ok(duration) = time.duration_since(std::time::SystemTime::UNIX_EPOCH) {
        let secs = duration.as_secs();
        let millis = duration.subsec_millis();
        let hours = (secs / 3600) % 24;
        let minutes = (secs / 60) % 60;
        let seconds = secs % 60;
        format!("{:02}:{:02}:{:02}.{:03}", hours, minutes, seconds, millis)
    } else {
        "--:--:--".into()
    }
}

fn format_mac(mac: &[u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}
