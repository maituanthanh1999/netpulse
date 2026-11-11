use clap::Parser;

/// NetPulse: Real-time network monitoring & embedded load testing agent
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct CliArgs {
    /// Network interface to monitor (e.g. eth0, wlan0, lo)
    #[arg(short, long)]
    pub interface: Option<String>,

    /// Ring buffer capacity (maximum packets kept in RAM)
    #[arg(short, long, default_value_t = 500)]
    pub buffer_size: usize,

    /// Stream live traffic directly to a .pcap file (Wireshark compatible)
    #[arg(short, long)]
    pub dump: Option<String>,

    /// List all available network interfaces on the system and exit
    #[arg(short, long)]
    pub list: bool,
}

