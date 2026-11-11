use std::net::Ipv4Addr;

/// Thông tin gắn thẻ VLAN (802.1Q hoặc 802.1ad QinQ)
#[derive(Debug, Clone)]
pub struct VlanTag {
    pub tpid: u16,  // 0x8100 (C-VLAN) hoặc 0x88a8 (S-VLAN / QinQ)
    pub vid: u16,   // VLAN ID (1..4095)
    pub pcp: u8,    // Priority Code Point / CoS (0..7)
    pub dei: bool,  // Drop Eligible Indicator
}

/// Giải mã VLAN tags (hỗ trợ cả Single Tag 802.1Q và Double Tag QinQ)
pub fn parse_vlan_tags(data: &[u8]) -> (Vec<VlanTag>, u16, usize) {
    let mut tags = Vec::new();
    let mut offset = 0;

    while offset + 4 <= data.len() {
        let tpid = u16::from_be_bytes([data[offset], data[offset + 1]]);
        if tpid == 0x8100 || tpid == 0x88a8 {
            let tci = u16::from_be_bytes([data[offset + 2], data[offset + 3]]);
            let pcp = ((tci >> 13) & 0x07) as u8;
            let dei = ((tci >> 12) & 0x01) == 1;
            let vid = tci & 0x0FFF;

            tags.push(VlanTag { tpid, vid, pcp, dei });
            offset += 4;
        } else {
            break;
        }
    }

    let encapsulated_ethertype = if offset + 2 <= data.len() {
        u16::from_be_bytes([data[offset], data[offset + 1]])
    } else {
        0
    };

    (tags, encapsulated_ethertype, offset)
}

/// =========================================================================
/// PPPoE (Point-to-Point Protocol over Ethernet - EtherType 0x8863 & 0x8864)
/// =========================================================================
pub fn decode_pppoe(data: &[u8], is_discovery: bool) -> Vec<String> {
    let mut lines = Vec::new();
    if data.len() < 6 {
        lines.push("[Invalid PPPoE Header - Length under 6 Bytes]".to_string());
        return lines;
    }

    let ver_type = data[0];
    let version = (ver_type >> 4) & 0x0F;
    let p_type = ver_type & 0x0F;
    let code = data[1];
    let session_id = u16::from_be_bytes([data[2], data[3]]);
    let payload_len = u16::from_be_bytes([data[4], data[5]]) as usize;

    let code_desc = match code {
        0x00 => "Session Data (0x00)",
        0x09 => "PADI (Active Discovery Initiation - Client Broadcast)",
        0x07 => "PADO (Active Discovery Offer - AC / BRAS Response)",
        0x19 => "PADR (Active Discovery Request - Client Request)",
        0x65 => "PADS (Active Discovery Session-confirmation)",
        0xa7 => "PADT (Active Discovery Terminate - Session Teardown)",
        _ => "Unknown PPPoE Code",
    };

    lines.push("▼ [PROTOCOL] PPPoE (Point-to-Point Protocol over Ethernet)".to_string());
    lines.push(format!("  ├─ Version/Type : {} / {}", version, p_type));
    lines.push(format!("  ├─ Packet Code  : 0x{:02x} [{}]", code, code_desc));
    lines.push(format!("  ├─ Session ID   : 0x{:04x} ({})", session_id, session_id));
    lines.push(format!("  └─ Length       : {} Bytes", payload_len));

    let ppp_data = if 6 + payload_len <= data.len() {
        &data[6..6 + payload_len]
    } else {
        &data[6..]
    };

    if is_discovery || code != 0x00 {
        // Parse PPPoE Discovery Tags
        lines.extend(parse_pppoe_tags(ppp_data));
    } else if ppp_data.len() >= 2 {
        // Parse Encapsulated PPP Protocol
        let ppp_proto = u16::from_be_bytes([ppp_data[0], ppp_data[1]]);
        let (proto_name, is_control) = match ppp_proto {
            0xc021 => ("LCP (Link Control Protocol)", true),
            0xc023 => ("PAP (Password Authentication Protocol)", true),
            0xc223 => ("CHAP (Challenge Handshake Authentication Protocol)", true),
            0x8021 => ("IPCP (IP Control Protocol - IPv4 Negotiation)", true),
            0x8057 => ("IPv6CP (IPv6 Control Protocol)", true),
            0x0021 => ("Internet Protocol v4 (IPv4 Payload)", false),
            0x0057 => ("Internet Protocol v6 (IPv6 Payload)", false),
            _ => ("Unknown PPP Protocol", false),
        };

        lines.push(format!("▼ [ENCAPSULATED PPP] Protocol: 0x{:04x} [{}]", ppp_proto, proto_name));
        if is_control && ppp_data.len() >= 6 {
            let ppp_code = ppp_data[2];
            let ppp_id = ppp_data[3];
            let ppp_len = u16::from_be_bytes([ppp_data[4], ppp_data[5]]);
            let code_str = match ppp_code {
                1 => "Configure-Request",
                2 => "Configure-Ack",
                3 => "Configure-Nak",
                4 => "Configure-Reject",
                5 => "Terminate-Request",
                6 => "Terminate-Ack",
                7 => "Code-Reject",
                8 => "Protocol-Reject",
                9 => "Echo-Request",
                10 => "Echo-Reply",
                11 => "Discard-Request",
                _ => "Unknown Code",
            };
            lines.push(format!("  ├─ PPP Control Code : {} [{}]", ppp_code, code_str));
            lines.push(format!("  ├─ Identifier       : {}", ppp_id));
            lines.push(format!("  └─ Length           : {} Bytes", ppp_len));
        }
    }

    lines
}

fn parse_pppoe_tags(data: &[u8]) -> Vec<String> {
    let mut lines = Vec::new();
    let mut idx = 0;

    lines.push("  ▼ PPPoE Tags:".to_string());
    while idx + 4 <= data.len() {
        let tag_type = u16::from_be_bytes([data[idx], data[idx + 1]]);
        let tag_len = u16::from_be_bytes([data[idx + 2], data[idx + 3]]) as usize;
        idx += 4;

        if idx + tag_len > data.len() {
            break;
        }
        let tag_val = &data[idx..idx + tag_len];
        idx += tag_len;

        match tag_type {
            0x0101 => lines.push(format!("    ├─ Service-Name : \"{}\"", String::from_utf8_lossy(tag_val))),
            0x0102 => lines.push(format!("    ├─ AC-Name (BRAS): \"{}\"", String::from_utf8_lossy(tag_val))),
            0x0103 => lines.push(format!("    ├─ Host-Uniq    : {:02x?}", tag_val)),
            0x0104 => lines.push(format!("    ├─ AC-Cookie    : {:02x?}", tag_val)),
            0x0105 => lines.push(format!("    ├─ Vendor-Specific: {:02x?}", tag_val)),
            0x0110 => lines.push(format!("    ├─ Relay-Session-Id: {:02x?}", tag_val)),
            0x0201 => lines.push(format!("    ├─ Service-Name-Error: \"{}\"", String::from_utf8_lossy(tag_val))),
            0x0202 => lines.push(format!("    ├─ AC-System-Error   : \"{}\"", String::from_utf8_lossy(tag_val))),
            0x0203 => lines.push(format!("    ├─ Generic-Error     : \"{}\"", String::from_utf8_lossy(tag_val))),
            _ => lines.push(format!("    ├─ Tag 0x{:04x} (Len: {}): {:02x?}", tag_type, tag_len, tag_val)),
        }
    }

    lines
}

/// =========================================================================
/// DHCP / BOOTP (Layer 2 / UDP Port 67 & 68 - Essential for OLT & BRAS)
/// =========================================================================
pub fn decode_dhcp(p: &[u8]) -> Vec<String> {
    let mut lines = Vec::new();
    if p.len() < 240 {
        lines.push("[Invalid DHCP/BOOTP packet - Header under 240 Bytes]".to_string());
        return lines;
    }

    let op = p[0];
    let htype = p[1];
    let hlen = p[2];
    let hops = p[3];
    let xid = u32::from_be_bytes([p[4], p[5], p[6], p[7]]);
    let secs = u16::from_be_bytes([p[8], p[9]]);
    let flags = u16::from_be_bytes([p[10], p[11]]);

    let ciaddr = Ipv4Addr::new(p[12], p[13], p[14], p[15]);
    let yiaddr = Ipv4Addr::new(p[16], p[17], p[18], p[19]);
    let siaddr = Ipv4Addr::new(p[20], p[21], p[22], p[23]);
    let giaddr = Ipv4Addr::new(p[24], p[25], p[26], p[27]);

    let op_str = if op == 1 { "BootRequest (1 - Client to Server)" } else if op == 2 { "BootReply (2 - Server to Client)" } else { "Unknown" };
    let broadcast_flag = if (flags & 0x8000) != 0 { "Broadcast" } else { "Unicast" };

    let mut chaddr_mac = [0u8; 6];
    if hlen == 6 && p.len() >= 34 {
        chaddr_mac.copy_from_slice(&p[28..34]);
    }

    lines.push("▼ [PROTOCOL] Dynamic Host Configuration Protocol (DHCP / BOOTP)".to_string());
    lines.push(format!("  ├─ Message Opcode  : {}", op_str));
    lines.push(format!("  ├─ Hardware Type   : {} (Ethernet) | Hops: {}", htype, hops));
    lines.push(format!("  ├─ Transaction ID  : 0x{:08x}", xid));
    lines.push(format!("  ├─ Elapsed / Flags : {}s | {}", secs, broadcast_flag));
    lines.push(format!("  ├─ Client MAC (chaddr)     : {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        chaddr_mac[0], chaddr_mac[1], chaddr_mac[2], chaddr_mac[3], chaddr_mac[4], chaddr_mac[5]));
    lines.push(format!("  ├─ Client IP (ciaddr)      : {}", ciaddr));
    lines.push(format!("  ├─ Your Assigned IP (yiaddr): {}", yiaddr));
    lines.push(format!("  ├─ Next Server IP (siaddr) : {}", siaddr));
    lines.push(format!("  └─ Relay Agent IP (giaddr) : {}", giaddr));

    // Check DHCP Magic Cookie (0x63 0x82 0x53 0x63 at offset 236..240)
    if p.len() >= 240 && p[236] == 0x63 && p[237] == 0x82 && p[238] == 0x53 && p[239] == 0x63 {
        lines.extend(parse_dhcp_options(&p[240..]));
    }

    lines
}

fn parse_dhcp_options(options: &[u8]) -> Vec<String> {
    let mut lines = Vec::new();
    let mut idx = 0;

    lines.push("  ▼ DHCP Options:".to_string());
    while idx < options.len() {
        let code = options[idx];
        if code == 0 {
            // Pad option
            idx += 1;
            continue;
        }
        if code == 255 {
            // End option
            lines.push("    └─ [End of Options (255)]".to_string());
            break;
        }

        if idx + 1 >= options.len() {
            break;
        }
        let len = options[idx + 1] as usize;
        idx += 2;

        if idx + len > options.len() {
            break;
        }
        let val = &options[idx..idx + len];
        idx += len;

        match code {
            53 if len == 1 => {
                let msg_type = match val[0] {
                    1 => "DHCP Discover",
                    2 => "DHCP Offer",
                    3 => "DHCP Request",
                    4 => "DHCP Decline",
                    5 => "DHCP Ack",
                    6 => "DHCP Nak",
                    7 => "DHCP Release",
                    8 => "DHCP Inform",
                    _ => "Unknown DHCP Type",
                };
                lines.push(format!("    ├─ Option 53 (Message Type) : {} [{}]", val[0], msg_type));
            }
            82 => {
                // Option 82: Relay Agent Information (Crucial for OLT PON port / ONU ID / DSLAM)
                lines.push(format!("    ├─ Option 82 (Relay Agent Information - OLT/DSLAM) [Len: {}B]:", len));
                lines.extend(parse_option_82(val));
            }
            1 if len == 4 => {
                lines.push(format!("    ├─ Option 1  (Subnet Mask)  : {}.{}.{}.{}", val[0], val[1], val[2], val[3]));
            }
            3 if len >= 4 => {
                let ips: Vec<String> = val.chunks(4).map(|c| format!("{}.{}.{}.{}", c[0], c[1], c[2], c[3])).collect();
                lines.push(format!("    ├─ Option 3  (Router/Gateway): {}", ips.join(", ")));
            }
            6 if len >= 4 => {
                let ips: Vec<String> = val.chunks(4).map(|c| format!("{}.{}.{}.{}", c[0], c[1], c[2], c[3])).collect();
                lines.push(format!("    ├─ Option 6  (DNS Servers)   : {}", ips.join(", ")));
            }
            12 => {
                lines.push(format!("    ├─ Option 12 (Host Name)    : \"{}\"", String::from_utf8_lossy(val)));
            }
            50 if len == 4 => {
                lines.push(format!("    ├─ Option 50 (Requested IP) : {}.{}.{}.{}", val[0], val[1], val[2], val[3]));
            }
            51 if len == 4 => {
                let lease = u32::from_be_bytes([val[0], val[1], val[2], val[3]]);
                lines.push(format!("    ├─ Option 51 (Lease Time)   : {} seconds ({} hours)", lease, lease / 3600));
            }
            54 if len == 4 => {
                lines.push(format!("    ├─ Option 54 (Server ID)    : {}.{}.{}.{}", val[0], val[1], val[2], val[3]));
            }
            _ => {
                lines.push(format!("    ├─ Option {:<2} (Len: {:<2}): {:02x?}", code, len, val));
            }
        }
    }

    lines
}

fn parse_option_82(data: &[u8]) -> Vec<String> {
    let mut lines = Vec::new();
    let mut idx = 0;

    while idx + 2 <= data.len() {
        let sub_type = data[idx];
        let sub_len = data[idx + 1] as usize;
        idx += 2;

        if idx + sub_len > data.len() {
            break;
        }
        let sub_val = &data[idx..idx + sub_len];
        idx += sub_len;

        match sub_type {
            1 => {
                // Agent Circuit ID (e.g. PON port / Slot / ONU ID / VLAN)
                let text = String::from_utf8_lossy(sub_val);
                lines.push(format!("    │   ├─ Sub-opt 1 (Agent Circuit ID): \"{}\" | Hex: {:02x?}", text, sub_val));
            }
            2 => {
                // Agent Remote ID (e.g. OLT MAC or Device Serial / Subscriber ID)
                let text = String::from_utf8_lossy(sub_val);
                lines.push(format!("    │   ├─ Sub-opt 2 (Agent Remote ID) : \"{}\" | Hex: {:02x?}", text, sub_val));
            }
            _ => {
                lines.push(format!("    │   ├─ Sub-opt {} (Len: {}): {:02x?}", sub_type, sub_len, sub_val));
            }
        }
    }

    lines
}

/// =========================================================================
/// IGMP (Internet Group Management Protocol - Multicast IPTV in OLT/Switch)
/// =========================================================================
pub fn decode_igmp(p: &[u8]) -> Vec<String> {
    let mut lines = Vec::new();
    if p.len() < 8 {
        lines.push("[Invalid IGMP Packet - Length under 8 Bytes]".to_string());
        return lines;
    }

    let igmp_type = p[0];
    let max_resp_time = p[1];
    let checksum = u16::from_be_bytes([p[2], p[3]]);
    let group_addr = Ipv4Addr::new(p[4], p[5], p[6], p[7]);

    let type_desc = match igmp_type {
        0x11 => "Membership Query (General / Group-Specific)",
        0x12 => "IGMPv1 Membership Report",
        0x16 => "IGMPv2 Membership Report",
        0x17 => "IGMPv2 Leave Group",
        0x22 => "IGMPv3 Membership Report",
        _ => "Unknown IGMP Message",
    };

    lines.push("▼ [PROTOCOL] Internet Group Management Protocol (IGMP - Multicast IPTV)".to_string());
    lines.push(format!("  ├─ Message Type    : 0x{:02x} [{}]", igmp_type, type_desc));
    lines.push(format!("  ├─ Max Resp Time   : {:.1}s (Code: {})", max_resp_time as f64 * 0.1, max_resp_time));
    lines.push(format!("  ├─ Checksum        : 0x{:04x}", checksum));
    lines.push(format!("  └─ Multicast Group : {}", group_addr));

    // Nếu là IGMPv3 Membership Report (Type 0x22)
    if igmp_type == 0x22 && p.len() >= 12 {
        let num_records = u16::from_be_bytes([p[6], p[7]]) as usize;
        lines.push(format!("  ▼ IGMPv3 Group Records Count: {}", num_records));

        let mut offset = 8;
        for r_idx in 0..num_records.min(5) {
            if offset + 8 > p.len() {
                break;
            }
            let record_type = p[offset];
            let aux_len = p[offset + 1] as usize;
            let num_sources = u16::from_be_bytes([p[offset + 2], p[offset + 3]]) as usize;
            let record_group = Ipv4Addr::new(p[offset + 4], p[offset + 5], p[offset + 6], p[offset + 7]);

            let r_type_desc = match record_type {
                1 => "MODE_IS_INCLUDE",
                2 => "MODE_IS_EXCLUDE (Join / SSM)",
                3 => "CHANGE_TO_INCLUDE_MODE",
                4 => "CHANGE_TO_EXCLUDE_MODE",
                5 => "ALLOW_NEW_SOURCES",
                6 => "BLOCK_OLD_SOURCES",
                _ => "Unknown Record Type",
            };

            lines.push(format!("    ├─ Record #{}: Group {} | Type: {} [{}]", r_idx + 1, record_group, record_type, r_type_desc));
            lines.push(format!("    │   └─ Sources Count: {}", num_sources));

            offset += 8 + (num_sources * 4) + (aux_len * 4);
        }
    }

    lines
}

/// =========================================================================
/// LLDP (Link Layer Discovery Protocol - EtherType 0x88CC - Switch topology)
/// =========================================================================
pub fn decode_lldp(p: &[u8]) -> Vec<String> {
    let mut lines = Vec::new();
    lines.push("▼ [PROTOCOL] Link Layer Discovery Protocol (LLDP - 802.1AB)".to_string());

    let mut idx = 0;
    while idx + 2 <= p.len() {
        let tlv_header = u16::from_be_bytes([p[idx], p[idx + 1]]);
        let tlv_type = (tlv_header >> 9) as u8;
        let tlv_len = (tlv_header & 0x01FF) as usize;
        idx += 2;

        if idx + tlv_len > p.len() {
            break;
        }
        let tlv_val = &p[idx..idx + tlv_len];
        idx += tlv_len;

        match tlv_type {
            0 => {
                lines.push("  └─ [End of LLDPDU (TLV 0)]".to_string());
                break;
            }
            1 => {
                // Chassis ID
                let subtype = if !tlv_val.is_empty() { tlv_val[0] } else { 0 };
                let val = if tlv_val.len() > 1 { &tlv_val[1..] } else { &[] };
                lines.push(format!("  ├─ Chassis ID (Subtype {}): {:02x?}", subtype, val));
            }
            2 => {
                // Port ID
                let subtype = if !tlv_val.is_empty() { tlv_val[0] } else { 0 };
                let val_str = if tlv_val.len() > 1 { String::from_utf8_lossy(&tlv_val[1..]) } else { "".into() };
                lines.push(format!("  ├─ Port ID    (Subtype {}): \"{}\"", subtype, val_str));
            }
            3 if tlv_len == 2 => {
                let ttl = u16::from_be_bytes([tlv_val[0], tlv_val[1]]);
                lines.push(format!("  ├─ Time to Live (TTL)    : {} seconds", ttl));
            }
            4 => {
                lines.push(format!("  ├─ Port Description      : \"{}\"", String::from_utf8_lossy(tlv_val)));
            }
            5 => {
                lines.push(format!("  ├─ System Name           : \"{}\"", String::from_utf8_lossy(tlv_val)));
            }
            6 => {
                lines.push(format!("  ├─ System Description    : \"{}\"", String::from_utf8_lossy(tlv_val).replace('\n', " ")));
            }
            _ => {
                lines.push(format!("  ├─ TLV Type {:<2} (Len: {}): {:02x?}", tlv_type, tlv_len, tlv_val));
            }
        }
    }

    lines
}

/// =========================================================================
/// EAPoL (802.1X Port-Based Network Access Control - EtherType 0x888E)
/// =========================================================================
pub fn decode_eapol(p: &[u8]) -> Vec<String> {
    let mut lines = Vec::new();
    if p.len() < 4 {
        lines.push("[Invalid EAPoL Header - Under 4 Bytes]".to_string());
        return lines;
    }

    let version = p[0];
    let p_type = p[1];
    let length = u16::from_be_bytes([p[2], p[3]]) as usize;

    let type_desc = match p_type {
        0 => "EAP-Packet (0)",
        1 => "EAPOL-Start (1)",
        2 => "EAPOL-Logoff (2)",
        3 => "EAPOL-Key (3)",
        4 => "EAPOL-Encapsulated-ASF-Alert (4)",
        _ => "Unknown EAPoL Type",
    };

    lines.push("▼ [PROTOCOL] EAP over LAN (IEEE 802.1X / EAPoL - Switch Access Auth)".to_string());
    lines.push(format!("  ├─ Version : {}", version));
    lines.push(format!("  ├─ Type    : 0x{:02x} [{}]", p_type, type_desc));
    lines.push(format!("  └─ Length  : {} Bytes", length));

    if p_type == 0 && p.len() >= 8 {
        // EAP Packet
        let eap_code = p[4];
        let eap_id = p[5];
        let eap_len = u16::from_be_bytes([p[6], p[7]]);
        let code_desc = match eap_code {
            1 => "Request",
            2 => "Response",
            3 => "Success",
            4 => "Failure",
            _ => "Unknown EAP Code",
        };
        lines.push(format!("  ▼ EAP Payload: Code {} [{}] | ID: {} | Len: {}", eap_code, code_desc, eap_id, eap_len));
        if p.len() >= 9 {
            let eap_type = p[8];
            let eap_type_desc = match eap_type {
                1 => "Identity",
                2 => "Notification",
                3 => "NAK (Response only)",
                4 => "MD5-Challenge",
                13 => "EAP-TLS",
                25 => "PEAP",
                _ => "Other EAP Type",
            };
            lines.push(format!("    └─ EAP Type : {} [{}]", eap_type, eap_type_desc));
            if eap_type == 1 && p.len() > 9 {
                let id_str = String::from_utf8_lossy(&p[9..]);
                lines.push(format!("       └─ Identity String : \"{}\"", id_str));
            }
        }
    }

    lines
}

/// =========================================================================
/// STP / RSTP / MSTP (Spanning Tree BPDU - Dest MAC 01:80:C2:00:00:00)
/// =========================================================================
pub fn decode_stp_bpdu(p: &[u8]) -> Vec<String> {
    let mut lines = Vec::new();
    if p.len() < 35 {
        lines.push("[STP BPDU Frame - Short length]".to_string());
        return lines;
    }

    // Offset in standard LLC/SNAP encapsulated BPDU:
    // 0..3: LLC (0x42 0x42 0x03)
    let protocol_id = u16::from_be_bytes([p[3], p[4]]);
    let version = p[5];
    let bpdu_type = p[6];

    let type_desc = match bpdu_type {
        0x00 => "Configuration BPDU",
        0x02 => "Rapid / Multiple STP (RSTP / MSTP) BPDU",
        0x80 => "Topology Change Notification (TCN) BPDU",
        _ => "Unknown BPDU Type",
    };

    let flags = p[7];
    let root_priority = u16::from_be_bytes([p[8], p[9]]);
    let root_mac = &p[10..16];
    let root_cost = u32::from_be_bytes([p[16], p[17], p[18], p[19]]);
    let bridge_priority = u16::from_be_bytes([p[20], p[21]]);
    let bridge_mac = &p[22..28];
    let port_id = u16::from_be_bytes([p[28], p[29]]);
    let msg_age = u16::from_be_bytes([p[30], p[31]]) / 256;
    let max_age = u16::from_be_bytes([p[32], p[33]]) / 256;
    let hello_time = u16::from_be_bytes([p[34], p[35]]) / 256;
    let forward_delay = u16::from_be_bytes([p[36], p[37]]) / 256;

    lines.push("▼ [PROTOCOL] Spanning Tree Protocol (STP / RSTP BPDU - Switch Loop Prevention)".to_string());
    lines.push(format!("  ├─ Protocol ID    : 0x{:04x} | Version: {}", protocol_id, version));
    lines.push(format!("  ├─ BPDU Type      : 0x{:02x} [{}]", bpdu_type, type_desc));
    lines.push(format!("  ├─ Flags (TCA/TC) : 0x{:02x}", flags));
    lines.push(format!("  ├─ Root Bridge ID : Priority {} | MAC {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        root_priority, root_mac[0], root_mac[1], root_mac[2], root_mac[3], root_mac[4], root_mac[5]));
    lines.push(format!("  ├─ Root Path Cost : {}", root_cost));
    lines.push(format!("  ├─ Bridge ID      : Priority {} | MAC {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        bridge_priority, bridge_mac[0], bridge_mac[1], bridge_mac[2], bridge_mac[3], bridge_mac[4], bridge_mac[5]));
    lines.push(format!("  ├─ Port ID        : 0x{:04x}", port_id));
    lines.push(format!("  └─ Timers         : Message Age: {}s | Max Age: {}s | Hello: {}s | Fwd Delay: {}s",
        msg_age, max_age, hello_time, forward_delay));

    lines
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_qinq_vlan_parsing() {
        // Double Tag: S-VLAN 200 (0x88a8) + C-VLAN 100 (0x8100) + EtherType 0x0800
        let data = [
            0x88, 0xa8, 0x00, 0xc8, // TPID 0x88a8, VID 200
            0x81, 0x00, 0x00, 0x64, // TPID 0x8100, VID 100
            0x08, 0x00,             // EtherType IPv4
        ];
        let (tags, encap, offset) = parse_vlan_tags(&data);
        assert_eq!(tags.len(), 2);
        assert_eq!(tags[0].tpid, 0x88a8);
        assert_eq!(tags[0].vid, 200);
        assert_eq!(tags[1].tpid, 0x8100);
        assert_eq!(tags[1].vid, 100);
        assert_eq!(encap, 0x0800);
        assert_eq!(offset, 8);
    }

    #[test]
    fn test_pppoe_padi_decode() {
        // PPPoE PADI frame: Ver=1, Type=1, Code=0x09 (PADI), Session=0, Len=12
        let pppoe = vec![
            0x11, 0x09, 0x00, 0x00, 0x00, 0x0c,
            // Tag Service-Name (0x0101, len 0)
            0x01, 0x01, 0x00, 0x00,
            // Tag Host-Uniq (0x0103, len 4)
            0x01, 0x03, 0x00, 0x04, 0x12, 0x34, 0x56, 0x78,
        ];
        let lines = decode_pppoe(&pppoe, true);
        assert!(lines.iter().any(|l| l.contains("PADI")));
        assert!(lines.iter().any(|l| l.contains("Host-Uniq")));
    }

    #[test]
    fn test_igmpv2_report_decode() {
        // IGMPv2 Report (0x16), Max Resp=0, Checksum, Group 239.255.255.250 (SSDP)
        let igmp = [
            0x16, 0x00, 0x00, 0x00,
            239, 255, 255, 250,
        ];
        let lines = decode_igmp(&igmp);
        assert!(lines.iter().any(|l| l.contains("IGMPv2 Membership Report")));
        assert!(lines.iter().any(|l| l.contains("239.255.255.250")));
    }
}
