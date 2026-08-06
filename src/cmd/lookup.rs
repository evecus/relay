use anyhow::Result;
use clap::Parser;
use std::path::PathBuf;

#[derive(Parser, Debug)]
pub struct LookupArgs {
    /// Path to the .drs ruleset file
    pub ruleset: PathBuf,

    /// Domain to look up
    pub domain: String,
}

pub fn lookup(args: LookupArgs) -> Result<()> {
    let drs = crate::ruleset::DrsFile::load(&args.ruleset)?;

    match drs.matches(&args.domain) {
        Some(crate::ruleset::MatchResult::Domain) => {
            println!("MATCH  DOMAIN         {}", args.domain);
        }
        Some(crate::ruleset::MatchResult::DomainSuffix) => {
            println!("MATCH  DOMAIN-SUFFIX  {}", args.domain);
        }
        Some(crate::ruleset::MatchResult::DomainKeyword) => {
            println!("MATCH  DOMAIN-KEYWORD {}", args.domain);
        }
        Some(crate::ruleset::MatchResult::DomainRegex) => {
            println!("MATCH  DOMAIN-REGEX   {}", args.domain);
        }
        // matches() 不会返回 IP/Port 变体，但编译器要求穷尽匹配
        Some(_) => {
            println!("MATCH  (ip/port)      {}", args.domain);
        }
        None => {
            println!("NO MATCH              {}", args.domain);
        }
    }

    Ok(())
}
