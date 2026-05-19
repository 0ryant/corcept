use anyhow::Result;
use clap::Parser;
use corcept_runtime::{init_project, InitOptions};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(
    name = "create-corcept",
    version,
    about = "Initialize Corcept in a repository"
)]
struct Cli {
    #[arg(long, default_value = ".")]
    path: PathBuf,
    #[arg(long)]
    dry_run: bool,
    #[arg(long)]
    force: bool,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let report = init_project(InitOptions {
        path: cli.path,
        dry_run: cli.dry_run,
        force: cli.force,
    })?;
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}
