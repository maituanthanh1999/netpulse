# NetPulse 📡

> **Embedded Network Agent:** Real-time network monitoring, protocol analysis, and load-testing agent for Embedded Linux systems.

---

## 1. Key Features

- **Zero-copy Datalink Sniffer:** Captures Layer 2 Ethernet frames directly using `pnet` (`AF_PACKET` raw sockets).
- **Wireshark-compatible PCAP Export:**
  - **On-demand Snapshot:** Press `s` or `p` anytime in the TUI to dump all buffered packets to `netpulse_<interface>_<timestamp>.pcap`.
  - **Continuous Live Streaming:** Use `-d <file.pcap>` to stream all live traffic directly to disk in real-time.
- **Auto-scroll Live Stream Cursor:**
  - The cursor `▶` automatically tracks the newest incoming packet at the bottom of the list.
  - Scrolling up (`↑`/`k`) automatically pauses auto-scroll so you can inspect past packets without screen jitter.
  - Press `G` or `End` to immediately resume auto-scrolling to the latest packet.
- **Dual-Tab Packet Inspector (Press `Enter`):**
  - **Tab 1: Decoded Dissector (Default):** Deep dissection of Layer 2 (Ethernet), Layer 3 (IPv4, IPv6, ARP), Layer 4 (TCP, UDP, ICMP), and **Layer 7 Application protocols** (HTTP, DNS queries/answers, TLS handshakes, plaintext UTF-8, JSON, and extracted ASCII strings from binary payloads).
  - **Tab 2: Raw Hex Dump:** 16-byte hex table with offset and ASCII column view matching `xxd` / Wireshark.
  - Seamlessly switch tabs with `Tab`, `1`, `2`, or arrow keys `←` / `→`.
- **$O(1)$ Ring Buffer:** Efficient bounded memory storage via `VecDeque`, guaranteeing predictable RAM footprint on resource-constrained embedded targets.

---

## 2. Usage Guide

### List Available Network Interfaces:
```bash
cargo run -- --list
```

### Start Monitoring an Interface:
Raw socket datalink capture requires root privileges or Linux Capabilities:

**Option 1: Run with `sudo`**
```bash
sudo ./target/debug/netpulse -i enp1s0
```

**Option 2: Grant Linux Capability (Run without `sudo`)**
```bash
cargo build
sudo setcap cap_net_raw,cap_net_admin=eip ./target/debug/netpulse
./target/debug/netpulse -i enp1s0
```

**Option 3: Monitor and stream live traffic to a PCAP file:**
```bash
sudo ./target/debug/netpulse -i enp1s0 -d capture.pcap
```

---

## 3. Keyboard Shortcuts

### Main Dashboard:
- `Enter`: Open **Packet Inspector** on the selected packet.
- `s` or `p`: **Export current packet buffer to Wireshark `.pcap` file**.
- `↑` / `↓` or `k` / `j`: Move packet selection cursor (pauses auto-scroll).
- `G` or `End`: Jump to the latest packet at the bottom and resume **Auto-scroll**.
- `g` or `Home`: Jump to the first packet in buffer history.
- `a`: Toggle Auto-scroll mode manually.
- `Space`: Pause / Resume live packet capture.
- `Tab` or `f`: Cycle protocol filter (`TCP` -> `UDP` -> `ICMP` -> `ARP` -> All).
- `c`: Clear packet history buffer.
- `q` or `Ctrl + C`: Safe shutdown and exit.

### Packet Inspector Modal:
- `Tab` or `1` / `2` or `←` / `→`: **Switch between Decoded Dissector and Raw Hex Dump**.
- `↑` / `↓` or `k` / `j`: Scroll through decoded fields or hex lines.
- `PgUp` / `PgDn`: Fast scroll 6 lines.
- `Esc`, `Enter`, or `q`: Close modal and return to dashboard.
