use anyhow::Result;
use clap::Parser;
use std::path::PathBuf;

#[derive(Parser, Debug)]
pub struct InfoArgs {
    /// Path to the .drs ruleset file
    pub ruleset: PathBuf,
}

pub fn info(args: InfoArgs) -> Result<()> {
    let drs = crate::ruleset::DrsFile::load(&args.ruleset)?;

    let build_time = chrono::DateTime::from_timestamp(drs.build_time as i64, 0)
        .map(|dt| dt.format("%Y-%m-%d %H:%M:%S UTC").to_string())
        .unwrap_or_else(|| "unknown".to_string());

    let hash_hex: String = drs.source_hash.iter().map(|b| format!("{:02x}", b)).collect();

    println!("File:         {}", args.ruleset.display());
    println!("Build time:   {}", build_time);
    println!("Source hash:  {}", &hash_hex[..16]);
    println!("Exact domains:  {}", drs.domain_count);
    println!("Suffix rules:   {}", drs.suffix_count);
    println!("Total rules:    {}", drs.domain_count + drs.suffix_count);

    Ok(())
}
