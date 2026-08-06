use anyhow::Result;
use clap::Parser;
use bcrypt::hash as bcrypt_hash;

/// 生成 bcrypt 密码哈希，用于 web.auth.password-hash 配置项。
///
/// 用法：relay hash-password
/// 运行后交互式输入密码（不回显），输出哈希字符串。
#[derive(Parser, Debug)]
pub struct HashPasswordArgs {
    /// 直接在命令行提供密码（不推荐，会留在 shell 历史中）。
    /// 不提供则从 stdin 读取。
    #[arg(short, long)]
    pub password: Option<String>,
}

pub fn hash_password(args: HashPasswordArgs) -> Result<()> {
    let password = match args.password {
        Some(p) => p,
        None => {
            use std::io;
            eprint!("Enter password: ");
            let mut buf = String::new();
            io::stdin().read_line(&mut buf)?;
            buf.trim_end().to_string()
        }
    };

    if password.is_empty() {
        anyhow::bail!("Password cannot be empty");
    }

    let hashed = bcrypt_hash(&password, 10)?;
    println!("{}", hashed);
    Ok(())
}
