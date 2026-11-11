use std::net::IpAddr;
use std::time::SystemTime;
use crate::capture::telecom::{self, VlanTag};
use crate::errors::{NetPulseError, Result};
use etherparse::{NetSlice, SlicedPacket, TransportSlice};

/// Định danh các giao thức mạng phổ biến hỗ trợ hiển thị và lọc.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum L4Protocol {
    Tcp,
    Udp,
    Icmp,
    Icmpv6,
    Arp,
    Igmp,
    Pppoe,
    Lldp,
    Eapol,
    Stp,
    Unknown(u8),
}

impl std::fmt::Display for L4Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Tcp => write!(f, "TCP"),
            Self::Udp => write!(f, "UDP"),
            Self::Icmp => write!(f, "ICMP"),
            Self::Icmpv6 => write!(f, "ICMPv6"),
            Self::Arp => write!(f, "ARP"),
            Self::Igmp => write!(f, "IGMP"),
            Self::Pppoe => write!(f, "PPPoE"),
            Self::Lldp => write!(f, "LLDP"),
            Self::Eapol => write!(f, "EAPoL"),
            Self::Stp => write!(f, "STP"),
            Self::Unknown(proto) => write!(f, "PROTO_{}", proto),
        }
    }
}

/// Chi tiết gói tin ARP
#[derive(Debug, Clone)]
pub struct ArpDetails {
    pub opcode: u16, // 1: Request, 2: Reply
    pub sender_mac: [u8; 6],
    pub sender_ip: [u8; 4],
    pub target_mac: [u8; 6],
    pub target_ip: [u8; 4],
}

/// Metadata tóm tắt của một gói tin sau khi bóc tách.
#[derive(Debug, Clone)]
pub struct PacketSummary {
    pub timestamp: SystemTime,
    pub src_mac: [u8; 6],
    pub dst_mac: [u8; 6],
    pub ether_type: u16,
    pub vlan_tags: Vec<VlanTag>,

    pub src_ip: Option<IpAddr>,
    pub dst_ip: Option<IpAddr>,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub protocol: L4Protocol,
    pub packet_len: usize,
    pub payload_len: usize,
    pub payload_offset: usize,
    pub tcp_flags: Option<String>,

    // Thông tin chi tiết phục vụ Packet Inspector & Dissector
    pub ttl: Option<u8>,
    pub ip_id: Option<u16>,
    pub ip_flags_df: bool,
    pub seq_num: Option<u32>,
    pub ack_num: Option<u32>,
    pub window_size: Option<u16>,
    pub icmp_type: Option<u8>,
    pub icmp_code: Option<u8>,
    pub arp_details: Option<ArpDetails>,
    pub app_protocol: String,
    pub raw_data: Vec<u8>,
}

impl PacketSummary {
    /// Phân tích một frame Ethernet thô dạng byte slice `&[u8]`.
    pub fn parse(raw_frame: &[u8]) -> Result<Self> {
        if raw_frame.len() < 14 {
            return Err(NetPulseError::ParseError("Packet size smaller than Ethernet header (14 bytes)".into()));
        }

        // Tách địa chỉ MAC (DST 6B, SRC 6B)
        let mut dst_mac = [0u8; 6];
        let mut src_mac = [0u8; 6];
        dst_mac.copy_from_slice(&raw_frame[0..6]);
        src_mac.copy_from_slice(&raw_frame[6..12]);

        let initial_ethertype = u16::from_be_bytes([raw_frame[12], raw_frame[13]]);

        // Bóc tách VLAN Tags (Hỗ trợ Single Tag 802.1Q và Double Tag 802.1ad QinQ cho OLT/Switch)
        let (vlan_tags, ether_type, vlan_header_len) = if initial_ethertype == 0x8100 || initial_ethertype == 0x88a8 {
            telecom::parse_vlan_tags(&raw_frame[12..])
        } else {
            (Vec::new(), initial_ethertype, 2)
        };

        let l3_offset = 12 + vlan_header_len;
        let l3_slice = if l3_offset < raw_frame.len() {
            &raw_frame[l3_offset..]
        } else {
            &[]
        };

        // 1. Kiểm tra STP BPDU (Dest MAC 01:80:C2:00:00:00)
        if dst_mac == [0x01, 0x80, 0xc2, 0x00, 0x00, 0x00] {
            return Ok(Self {
                timestamp: SystemTime::now(),
                src_mac,
                dst_mac,
                ether_type,
                vlan_tags,
                src_ip: None,
                dst_ip: None,
                src_port: None,
                dst_port: None,
                protocol: L4Protocol::Stp,
                packet_len: raw_frame.len(),
                payload_len: raw_frame.len().saturating_sub(14),
                payload_offset: 14,
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
                app_protocol: "STP / BPDU".to_string(),
                raw_data: raw_frame.to_vec(),
            });
        }

        // 2. Kiểm tra PPPoE (0x8863 Discovery, 0x8864 Session - OLT/Broadband)
        if ether_type == 0x8863 || ether_type == 0x8864 {
            let is_disc = ether_type == 0x8863;
            let code_str = if is_disc {
                match l3_slice.get(1).copied() {
                    Some(0x09) => "PPPoE PADI",
                    Some(0x07) => "PPPoE PADO",
                    Some(0x19) => "PPPoE PADR",
                    Some(0x65) => "PPPoE PADS",
                    Some(0xa7) => "PPPoE PADT",
                    _ => "PPPoE Discovery",
                }
            } else {
                "PPPoE Session"
            };

            return Ok(Self {
                timestamp: SystemTime::now(),
                src_mac,
                dst_mac,
                ether_type,
                vlan_tags,
                src_ip: None,
                dst_ip: None,
                src_port: None,
                dst_port: None,
                protocol: L4Protocol::Pppoe,
                packet_len: raw_frame.len(),
                payload_len: l3_slice.len(),
                payload_offset: l3_offset,
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
                app_protocol: code_str.to_string(),
                raw_data: raw_frame.to_vec(),
            });
        }

        // 3. Kiểm tra LLDP (0x88CC - Switch Discovery)
        if ether_type == 0x88cc {
            return Ok(Self {
                timestamp: SystemTime::now(),
                src_mac,
                dst_mac,
                ether_type,
                vlan_tags,
                src_ip: None,
                dst_ip: None,
                src_port: None,
                dst_port: None,
                protocol: L4Protocol::Lldp,
                packet_len: raw_frame.len(),
                payload_len: l3_slice.len(),
                payload_offset: l3_offset,
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
                app_protocol: "LLDP".to_string(),
                raw_data: raw_frame.to_vec(),
            });
        }

        // 4. Kiểm tra EAPoL (0x888E - 802.1X Port Authentication)
        if ether_type == 0x888e {
            return Ok(Self {
                timestamp: SystemTime::now(),
                src_mac,
                dst_mac,
                ether_type,
                vlan_tags,
                src_ip: None,
                dst_ip: None,
                src_port: None,
                dst_port: None,
                protocol: L4Protocol::Eapol,
                packet_len: raw_frame.len(),
                payload_len: l3_slice.len(),
                payload_offset: l3_offset,
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
                app_protocol: "EAPoL (802.1X)".to_string(),
                raw_data: raw_frame.to_vec(),
            });
        }

        // 5. Kiểm tra ARP (0x0806)
        if ether_type == 0x0806 {
            let arp_details = parse_arp_full(l3_slice);
            let (src_ip, dst_ip) = match &arp_details {
                Some(arp) => (
                    Some(IpAddr::V4(arp.sender_ip.into())),
                    Some(IpAddr::V4(arp.target_ip.into())),
                ),
                None => (None, None),
            };

            let app_proto = match &arp_details {
                Some(arp) if arp.opcode == 1 => "ARP Request",
                Some(arp) if arp.opcode == 2 => "ARP Reply",
                _ => "ARP",
            };

            return Ok(Self {
                timestamp: SystemTime::now(),
                src_mac,
                dst_mac,
                ether_type,
                vlan_tags,
                src_ip,
                dst_ip,
                src_port: None,
                dst_port: None,
                protocol: L4Protocol::Arp,
                packet_len: raw_frame.len(),
                payload_len: l3_slice.len(),
                payload_offset: l3_offset,
                tcp_flags: None,
                ttl: None,
                ip_id: None,
                ip_flags_df: false,
                seq_num: None,
                ack_num: None,
                window_size: None,
                icmp_type: None,
                icmp_code: None,
                arp_details,
                app_protocol: app_proto.to_string(),
                raw_data: raw_frame.to_vec(),
            });
        }

        // 6. Xử lý IP (IPv4 / IPv6) thông qua etherparse::SlicedPacket::from_ip
        match SlicedPacket::from_ip(l3_slice) {
            Ok(sliced) => {
                let mut src_ip = None;
                let mut dst_ip = None;
                let mut src_port = None;
                let mut dst_port = None;
                let mut protocol = L4Protocol::Unknown(0);
                let mut tcp_flags = None;
                let mut ttl = None;
                let mut ip_id = None;
                let mut ip_flags_df = false;
                let mut seq_num = None;
                let mut ack_num = None;
                let mut window_size = None;
                let mut icmp_type = None;
                let mut icmp_code = None;

                // Phân giải IP header
                if let Some(ref net) = sliced.net {
                    match net {
                        NetSlice::Ipv4(ipv4) => {
                            src_ip = Some(IpAddr::V4(ipv4.header().source_addr()));
                            dst_ip = Some(IpAddr::V4(ipv4.header().destination_addr()));
                            let proto_num = ipv4.header().protocol().0;
                            protocol = if proto_num == 2 {
                                L4Protocol::Igmp
                            } else {
                                L4Protocol::Unknown(proto_num)
                            };
                            ttl = Some(ipv4.header().ttl());
                            ip_id = Some(ipv4.header().identification());
                            ip_flags_df = ipv4.header().dont_fragment();
                        }
                        NetSlice::Ipv6(ipv6) => {
                            src_ip = Some(IpAddr::V6(ipv6.header().source_addr()));
                            dst_ip = Some(IpAddr::V6(ipv6.header().destination_addr()));
                            protocol = L4Protocol::Unknown(ipv6.header().next_header().0);
                            ttl = Some(ipv6.header().hop_limit());
                        }
                    }
                }

                let mut payload_len = 0;

                // Phân giải Transport header
                if let Some(transport) = sliced.transport {
                    match transport {
                        TransportSlice::Tcp(tcp) => {
                            protocol = L4Protocol::Tcp;
                            src_port = Some(tcp.source_port());
                            dst_port = Some(tcp.destination_port());
                            payload_len = tcp.payload().len();
                            seq_num = Some(tcp.sequence_number());
                            ack_num = Some(tcp.acknowledgment_number());
                            window_size = Some(tcp.window_size());

                            let mut flags = Vec::with_capacity(6);
                            if tcp.syn() { flags.push("SYN"); }
                            if tcp.ack() { flags.push("ACK"); }
                            if tcp.fin() { flags.push("FIN"); }
                            if tcp.rst() { flags.push("RST"); }
                            if tcp.psh() { flags.push("PSH"); }
                            if tcp.urg() { flags.push("URG"); }
                            tcp_flags = Some(flags.join(","));
                        }
                        TransportSlice::Udp(udp) => {
                            protocol = L4Protocol::Udp;
                            src_port = Some(udp.source_port());
                            dst_port = Some(udp.destination_port());
                            payload_len = udp.payload().len();
                        }
                        TransportSlice::Icmpv4(icmp) => {
                            protocol = L4Protocol::Icmp;
                            payload_len = icmp.payload().len();
                            icmp_type = Some(icmp.type_u8());
                            icmp_code = Some(icmp.code_u8());
                        }
                        TransportSlice::Icmpv6(icmp) => {
                            protocol = L4Protocol::Icmpv6;
                            payload_len = icmp.payload().len();
                            icmp_type = Some(icmp.type_u8());
                            icmp_code = Some(icmp.code_u8());
                        }
                    }
                } else if let Some(net) = sliced.net {
                    match net {
                        NetSlice::Ipv4(ipv4) => payload_len = ipv4.payload().payload.len(),
                        NetSlice::Ipv6(ipv6) => payload_len = ipv6.payload().payload.len(),
                    }
                }

                let payload_offset = raw_frame.len().saturating_sub(payload_len);
                let app_protocol = detect_app_protocol(src_port, dst_port, &raw_frame[payload_offset..], protocol);

                Ok(Self {
                    timestamp: SystemTime::now(),
                    src_mac,
                    dst_mac,
                    ether_type,
                    vlan_tags,
                    src_ip,
                    dst_ip,
                    src_port,
                    dst_port,
                    protocol,
                    packet_len: raw_frame.len(),
                    payload_len,
                    payload_offset,
                    tcp_flags,
                    ttl,
                    ip_id,
                    ip_flags_df,
                    seq_num,
                    ack_num,
                    window_size,
                    icmp_type,
                    icmp_code,
                    arp_details: None,
                    app_protocol,
                    raw_data: raw_frame.to_vec(),
                })
            }
            Err(_) => {
                // Trường hợp raw Ethernet payload không phải IP
                Ok(Self {
                    timestamp: SystemTime::now(),
                    src_mac,
                    dst_mac,
                    ether_type,
                    vlan_tags,
                    src_ip: None,
                    dst_ip: None,
                    src_port: None,
                    dst_port: None,
                    protocol: L4Protocol::Unknown(0),
                    packet_len: raw_frame.len(),
                    payload_len: l3_slice.len(),
                    payload_offset: l3_offset,
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
                    app_protocol: format!("EtherType 0x{:04x}", ether_type),
                    raw_data: raw_frame.to_vec(),
                })
            }
        }
    }

    /// Lấy slice payload thực sự của gói tin
    pub fn payload(&self) -> &[u8] {
        if self.payload_offset < self.raw_data.len() {
            &self.raw_data[self.payload_offset..]
        } else {
            &[]
        }
    }

    /// Giải mã thông minh nội dung payload thành các dòng văn bản rõ ràng (Decoded View)
    pub fn decode_payload_lines(&self) -> Vec<String> {
        let p = self.payload();

        // 1. PPPoE (0x8863 / 0x8864)
        if self.protocol == L4Protocol::Pppoe || self.ether_type == 0x8863 || self.ether_type == 0x8864 {
            let is_disc = self.ether_type == 0x8863;
            return telecom::decode_pppoe(&self.raw_data[self.payload_offset..], is_disc);
        }

        // 2. LLDP (0x88CC)
        if self.protocol == L4Protocol::Lldp || self.ether_type == 0x88cc {
            return telecom::decode_lldp(&self.raw_data[self.payload_offset..]);
        }

        // 3. EAPoL (0x888E)
        if self.protocol == L4Protocol::Eapol || self.ether_type == 0x888e {
            return telecom::decode_eapol(&self.raw_data[self.payload_offset..]);
        }

        // 4. STP BPDU
        if self.protocol == L4Protocol::Stp {
            return telecom::decode_stp_bpdu(&self.raw_data[14..]);
        }

        // 5. IGMP (Multicast IPTV - Protocol 2)
        if self.protocol == L4Protocol::Igmp || self.app_protocol == "IGMP" {
            return telecom::decode_igmp(p);
        }

        // 6. DHCP / BOOTP (UDP Ports 67 & 68 - with Option 82 Relay Agent Info)
        if self.src_port == Some(67) || self.src_port == Some(68) || self.dst_port == Some(67) || self.dst_port == Some(68) {
            return telecom::decode_dhcp(p);
        }

        // 7. DNS (UDP/TCP Port 53)
        if self.src_port == Some(53) || self.dst_port == Some(53) {
            return decode_dns_packet(p);
        }

        // Nếu payload rỗng
        if p.is_empty() {
            return vec!["[No Application Payload (Header-only Frame)]".to_string()];
        }

        let mut lines = Vec::new();

        // 8. HTTP / REST / JSON / Plain Text
        if is_http_payload(p) {
            lines.push(format!("▼ [Application Protocol: HTTP - {} Bytes]", p.len()));
            let text = String::from_utf8_lossy(p);
            for line in text.lines().take(60) {
                lines.push(format!("  {}", line));
            }
            if text.lines().count() > 60 {
                lines.push(format!("  ... ({} more lines)", text.lines().count() - 60));
            }
            return lines;
        }

        // 9. TLS Record (Port 443 or header 0x16 0x03)
        if p.len() >= 5 && p[0] == 0x16 && p[1] == 0x03 {
            let version = match (p[1], p[2]) {
                (3, 1) => "TLS 1.0",
                (3, 2) => "TLS 1.1",
                (3, 3) => "TLS 1.2 / 1.3",
                _ => "TLS Record",
            };
            let handshake_type = match p.get(5) {
                Some(1) => "Client Hello",
                Some(2) => "Server Hello",
                Some(11) => "Certificate",
                Some(16) => "Client Key Exchange",
                _ => "Handshake Record",
            };
            let record_len = u16::from_be_bytes([p[3], p[4]]);
            lines.push("▼ [Security Protocol: Transport Layer Security (TLS)]".to_string());
            lines.push(format!("  ├─ Version      : {}", version));
            lines.push(format!("  ├─ Message Type : {}", handshake_type));
            lines.push(format!("  ├─ Record Length: {} Bytes", record_len));
            lines.push("  └─ Payload is End-to-End Encrypted".to_string());
            return lines;
        }

        // 10. Check if payload is readable ASCII / UTF-8 text
        let printable_count = p.iter().filter(|&&b| (32..=126).contains(&b) || b == b'\n' || b == b'\r' || b == b'\t').count();
        let is_text = p.len() > 0 && (printable_count * 100 / p.len()) >= 70;

        if is_text {
            lines.push(format!("▼ [Text / UTF-8 Data - {} Bytes]", p.len()));
            let text = String::from_utf8_lossy(p);
            for line in text.lines().take(50) {
                lines.push(format!("  {}", line));
            }
            return lines;
        }

        // 11. Generic Binary Payload
        lines.push(format!("▼ [Binary Payload - {} Bytes]", p.len()));
        let strings = extract_printable_strings(p, 4);
        if !strings.is_empty() {
            lines.push("  ├─ Extracted ASCII Strings:".to_string());
            for s in strings.iter().take(15) {
                lines.push(format!("  │   • \"{}\"", s));
            }
        } else {
            lines.push("  ├─ No printable ASCII strings found".to_string());
        }
        lines.push(format!("  └─ First 16 Bytes: {:02x?}", &p[..p.len().min(16)]));

        lines
    }
}

/// Nhận diện giao thức tầng ứng dụng
fn detect_app_protocol(src_port: Option<u16>, dst_port: Option<u16>, payload: &[u8], l4: L4Protocol) -> String {
    let p1 = src_port.unwrap_or(0);
    let p2 = dst_port.unwrap_or(0);

    if p1 == 67 || p2 == 67 || p1 == 68 || p2 == 68 {
        "DHCP".to_string()
    } else if l4 == L4Protocol::Igmp {
        "IGMP".to_string()
    } else if p1 == 80 || p2 == 80 || p1 == 8080 || p2 == 8080 || is_http_payload(payload) {
        "HTTP".to_string()
    } else if p1 == 443 || p2 == 443 || (payload.len() >= 3 && payload[0] == 0x16 && payload[1] == 0x03) {
        "HTTPS/TLS".to_string()
    } else if p1 == 53 || p2 == 53 {
        "DNS".to_string()
    } else if p1 == 22 || p2 == 22 {
        "SSH".to_string()
    } else if p1 == 123 || p2 == 123 {
        "NTP".to_string()
    } else if p1 == 1883 || p2 == 1883 || p1 == 8883 || p2 == 8883 {
        "MQTT".to_string()
    } else if p1 == 5683 || p2 == 5683 {
        "CoAP".to_string()
    } else {
        l4.to_string()
    }
}

fn is_http_payload(p: &[u8]) -> bool {
    let prefixes: [&[u8]; 7] = [b"GET ", b"POST ", b"HTTP/1.", b"PUT ", b"DELETE ", b"HEAD ", b"OPTIONS "];
    prefixes.iter().any(|prefix| p.starts_with(prefix))
}

fn decode_dns_packet(p: &[u8]) -> Vec<String> {
    let mut lines = Vec::new();
    if p.len() < 12 {
        lines.push("[Invalid DNS Packet - length under 12 Bytes]".to_string());
        return lines;
    }

    let tx_id = u16::from_be_bytes([p[0], p[1]]);
    let flags = u16::from_be_bytes([p[2], p[3]]);
    let is_response = (flags & 0x8000) != 0;
    let questions = u16::from_be_bytes([p[4], p[5]]);
    let answers = u16::from_be_bytes([p[6], p[7]]);

    lines.push("▼ [Protocol: Domain Name System (DNS)]".to_string());
    lines.push(format!("  ├─ Transaction ID : 0x{:04x}", tx_id));
    lines.push(format!("  ├─ Message Type   : {}", if is_response { "DNS Response" } else { "DNS Query" }));
    lines.push(format!("  ├─ Questions Count: {}", questions));
    lines.push(format!("  ├─ Answers Count  : {}", answers));

    if let Some((domain, _)) = parse_dns_qname(&p[12..]) {
        lines.push(format!("  └─ Query Domain   : {}", domain));
    } else {
        lines.push("  └─ Unable to parse query domain".to_string());
    }

    lines
}

fn parse_dns_qname(data: &[u8]) -> Option<(String, usize)> {
    let mut parts = Vec::new();
    let mut idx = 0;

    while idx < data.len() {
        let len = data[idx] as usize;
        if len == 0 {
            idx += 1;
            break;
        }
        if len > 63 || idx + 1 + len > data.len() {
            return None;
        }
        idx += 1;
        let part = String::from_utf8_lossy(&data[idx..idx + len]);
        parts.push(part.into_owned());
        idx += len;
    }

    if parts.is_empty() {
        None
    } else {
        Some((parts.join("."), idx))
    }
}

fn extract_printable_strings(data: &[u8], min_len: usize) -> Vec<String> {
    let mut result = Vec::new();
    let mut current = Vec::new();

    for &b in data {
        if (32..=126).contains(&b) {
            current.push(b);
        } else {
            if current.len() >= min_len {
                result.push(String::from_utf8_lossy(&current).to_string());
            }
            current.clear();
        }
    }
    if current.len() >= min_len {
        result.push(String::from_utf8_lossy(&current).to_string());
    }
    result
}

fn parse_arp_full(payload: &[u8]) -> Option<ArpDetails> {
    if payload.len() < 28 {
        return None;
    }
    let opcode = u16::from_be_bytes([payload[6], payload[7]]);
    let mut sender_mac = [0u8; 6];
    let mut sender_ip = [0u8; 4];
    let mut target_mac = [0u8; 6];
    let mut target_ip = [0u8; 4];

    sender_mac.copy_from_slice(&payload[8..14]);
    sender_ip.copy_from_slice(&payload[14..18]);
    target_mac.copy_from_slice(&payload[18..24]);
    target_ip.copy_from_slice(&payload[24..28]);

    Some(ArpDetails {
        opcode,
        sender_mac,
        sender_ip,
        target_mac,
        target_ip,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_truncated_packet() {
        let short_data = [0x00, 0x11, 0x22];
        assert!(PacketSummary::parse(&short_data).is_err());
    }

    #[test]
    fn test_parse_vlan_tagged_packet() {
        // Frame Ethernet có gắn thẻ 802.1Q VLAN 100
        let mut frame = Vec::new();
        frame.extend_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]); // Dst MAC
        frame.extend_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66]); // Src MAC
        frame.extend_from_slice(&[0x81, 0x00]); // 802.1Q TPID
        frame.extend_from_slice(&[0x00, 0x64]); // VID = 100 (0x0064)
        frame.extend_from_slice(&[0x08, 0x06]); // EtherType ARP (0x0806)
        frame.extend_from_slice(&[0x00; 28]);   // ARP dummy data

        let summary = PacketSummary::parse(&frame).expect("Parse VLAN tagged frame thành công");
        assert_eq!(summary.vlan_tags.len(), 1);
        assert_eq!(summary.vlan_tags[0].vid, 100);
        assert_eq!(summary.protocol, L4Protocol::Arp);
    }
}
