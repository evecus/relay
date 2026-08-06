//! .drs 规则集模块。
//!
//! 模块结构：
//!   - `error`   : 结构化错误枚举 `DrsError`
//!   - `format`  : v2 二进制格式常量（section-based）
//!   - `drs`     : `DrsFile` 加载 / 写入 / 匹配（零分配热路径）
//!   - `builder` : 从 `RuleEntry` 构建并写入 .drs 文件
//!   - `parser`  : 多种输入格式解析（mihomo / AdGuard / sing-box）

pub mod builder;
pub mod drs;
pub mod error;
pub mod format;
pub mod parser;

pub use drs::{DrsFile, MatchResult};
