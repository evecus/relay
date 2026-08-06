//! 规则集模块的结构化错误类型。
//!
//! 用 `thiserror` 派生，让调用方可以 `match` 错误类型做不同处理
//! （例如缓存层判断「文件损坏」vs「文件不存在」vs「格式不支持」）。

use thiserror::Error;

pub type Result<T> = std::result::Result<T, DrsError>;

#[derive(Debug, Error)]
pub enum DrsError {
    /// 解析错误：文本 / JSON / YAML 行解析失败，附带 1-based 行号与描述。
    #[error("parse error at line {line}: {msg}")]
    ParseError { line: usize, msg: String },

    /// CIDR 解析失败：原始字符串 + 原因。
    #[error("invalid CIDR `{raw}`: {reason}")]
    InvalidCidr { raw: String, reason: String },

    /// 端口解析失败：原始字符串。
    #[error("invalid port `{raw}`")]
    InvalidPort { raw: String },

    /// 正则编译失败：pattern + 错误。
    #[error("invalid regex `{pattern}`: {err}")]
    InvalidRegex { pattern: String, err: String },

    /// 域名超长（>253 字节）。
    #[error("domain too long ({len} bytes): `{domain}`")]
    DomainTooLong { domain: String, len: usize },

    /// 二进制魔数错误，附带实际读到的字节方便排错。
    #[error("bad DRS magic bytes: got {got:?}")]
    BadMagic { got: Vec<u8> },

    /// 二进制版本不支持。
    #[error("unsupported DRS version: {0}")]
    UnsupportedVersion(u8),

    /// 二进制中存在未知 section 类型。
    #[error("unknown section type: 0x{0:02x}")]
    UnknownSection(u8),

    /// 二进制截断：期望 / 实际字节数。
    #[error("truncated DRS data: expected {expected} bytes, got {got}")]
    Truncated { expected: usize, got: usize },

    /// UTF-8 解码失败。
    #[error("invalid UTF-8 in DRS data")]
    InvalidUtf8,

    /// FST 加载失败：FST 内部数据不合法。
    #[error("invalid FST data: {0}")]
    InvalidFst(String),

    /// 加载侧正则编译失败（从二进制恢复正则时）。
    #[error("loaded invalid regex: {0}")]
    LoadedInvalidRegex(String),

    /// IO 错误。
    #[error(transparent)]
    Io(#[from] std::io::Error),

    /// 其他通用错误（透传 anyhow）。
    #[error("{0}")]
    Other(String),
}

impl DrsError {
    /// 从任何 Displayable 错误构造一个 `Other`。
    pub fn other<E: std::fmt::Display>(e: E) -> Self {
        DrsError::Other(e.to_string())
    }
}

// 注：不需要手动 impl `From<DrsError> for anyhow::Error`。
// `DrsError` 通过 thiserror 派生 `std::error::Error`，anyhow 已有 blanket impl
// `impl<E: StdError + Send + Sync + 'static> From<E> for anyhow::Error`。
// 手动 impl 会与 blanket impl 冲突（E0119）。
