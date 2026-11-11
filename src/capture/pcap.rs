use std::fs::{File, OpenOptions};
use std::io::{self, BufWriter, Write};
use std::path::Path;
use std::time::SystemTime;

use crate::capture::PacketSummary;

/// Tiêu chuẩn định dạng file Libpcap (.pcap) kinh điển mở được bởi Wireshark và tcpdump.
///
/// **Cấu trúc PCAP Global Header (24 bytes):**
/// - Magic Number (4B): 0xa1b2c3d4 (microsecond resolution)
/// - Version Major (2B): 2
/// - Version Minor (2B): 4
/// - Timezone (4B): 0 (GMT/UTC)
/// - Sigfigs (4B): 0
/// - Snaplen (4B): 65535 (độ dài tối đa của gói tin)
/// - Network/LinkType (4B): 1 (LINKTYPE_ETHERNET)
const PCAP_MAGIC_NUMBER: u32 = 0xa1b2c3d4;
const PCAP_VERSION_MAJOR: u16 = 2;
const PCAP_VERSION_MINOR: u16 = 4;
const PCAP_THISZONE: i32 = 0;
const PCAP_SIGFIGS: u32 = 0;
const PCAP_SNAPLEN: u32 = 65535;
const PCAP_LINKTYPE_ETHERNET: u32 = 1;

/// Trình ghi file PCAP dạng Stream thời gian thực
pub struct PcapWriter {
    writer: BufWriter<File>,
}

impl PcapWriter {
    /// Khởi tạo file PCAP mới và ghi Global Header 24 bytes
    pub fn create<P: AsRef<Path>>(path: P) -> io::Result<Self> {
        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)?;

        let mut writer = BufWriter::new(file);
        write_global_header(&mut writer)?;
        writer.flush()?;

        Ok(Self { writer })
    }

    /// Ghi một gói tin vào file PCAP
    pub fn write_packet(&mut self, pkt: &PacketSummary) -> io::Result<()> {
        write_packet_record(&mut self.writer, pkt)?;
        Ok(())
    }

    pub fn flush(&mut self) -> io::Result<()> {
        self.writer.flush()
    }
}

/// Xuất toàn bộ danh sách gói tin hiện có trong bộ đệm ra file .pcap
pub fn export_to_pcap<P: AsRef<Path>>(path: P, packets: &[&PacketSummary]) -> io::Result<usize> {
    let mut pcap = PcapWriter::create(path)?;
    let mut count = 0;

    for pkt in packets {
        pcap.write_packet(pkt)?;
        count += 1;
    }

    pcap.flush()?;
    Ok(count)
}

fn write_global_header<W: Write>(writer: &mut W) -> io::Result<()> {
    writer.write_all(&PCAP_MAGIC_NUMBER.to_ne_bytes())?;
    writer.write_all(&PCAP_VERSION_MAJOR.to_ne_bytes())?;
    writer.write_all(&PCAP_VERSION_MINOR.to_ne_bytes())?;
    writer.write_all(&PCAP_THISZONE.to_ne_bytes())?;
    writer.write_all(&PCAP_SIGFIGS.to_ne_bytes())?;
    writer.write_all(&PCAP_SNAPLEN.to_ne_bytes())?;
    writer.write_all(&PCAP_LINKTYPE_ETHERNET.to_ne_bytes())?;
    Ok(())
}

fn write_packet_record<W: Write>(writer: &mut W, pkt: &PacketSummary) -> io::Result<()> {
    let duration = pkt
        .timestamp
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();

    let ts_sec = duration.as_secs() as u32;
    let ts_usec = duration.subsec_micros();
    let incl_len = pkt.raw_data.len() as u32;
    let orig_len = pkt.packet_len as u32;

    // Packet Header (16 bytes)
    writer.write_all(&ts_sec.to_ne_bytes())?;
    writer.write_all(&ts_usec.to_ne_bytes())?;
    writer.write_all(&incl_len.to_ne_bytes())?;
    writer.write_all(&orig_len.to_ne_bytes())?;

    // Packet Payload
    writer.write_all(&pkt.raw_data)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_pcap_export() {
        let test_file = "test_export.pcap";
        let dummy = PacketSummary::parse(&[
            0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x08, 0x00,
            0x45, 0x00, 0x00, 0x14, 0x00, 0x01, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 127, 0, 0,
            1, 127, 0, 0, 1,
        ])
        .unwrap();

        let count = export_to_pcap(test_file, &[&dummy]).expect("Ghi pcap thành công");
        assert_eq!(count, 1);

        let metadata = fs::metadata(test_file).expect("File phải tồn tại");
        // 24 (global header) + 16 (packet header) + 34 (packet len) = 74 bytes
        assert_eq!(metadata.len(), 74);

        let _ = fs::remove_file(test_file);
    }
}

