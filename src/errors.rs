use thiserror::Error;

/// Các lỗi định danh trong NetPulse.
///
/// Trong ngôn ngữ C nhúng, ta thường dùng mã lỗi số âm (`int -errno`) và kiểm tra `if (ret < 0)`.
/// Trong Rust, `enum` đóng vai trò là "Tagged Union" an toàn loại (Type-safe Sum Type).
/// `thiserror` tự động triển khai `std::error::Error` và `Display` tương ứng mà không sinh overhead lúc runtime.
#[derive(Error, Debug)]
pub enum NetPulseError {
    #[error("Insufficient permissions to open raw socket. Please run with sudo or grant CAP_NET_RAW")]
    PermissionDenied,

    #[error("Network interface not found: {0}")]
    InterfaceNotFound(String),

    #[error("Low-level socket I/O error: {0}")]
    SocketError(#[from] std::io::Error),

    #[error("Truncated or malformed packet: {0}")]
    ParseError(String),

    #[allow(dead_code)]
    #[error("Inter-thread channel error: {0}")]
    ChannelError(String),

    #[error("Unsupported or unrecognized protocol: {0}")]
    UnsupportedProtocol(String),
}

/// Type alias tiện ích cho Result trong NetPulse, tương đương idiomatic pattern trong std.
pub type Result<T> = std::result::Result<T, NetPulseError>;

