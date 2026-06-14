mod mcp;

use anyhow::Result;
use clap::{Parser, Subcommand};
use corcept_ledger::{generate_operator_key, show_operator_key, verify_ledger};
use corcept_memory::{new_candidate, promote_candidate, write_candidate};
use corcept_runtime::{
    audit, doctor_with_options, handle_hook, init_project, DoctorOptions, InitOptions,
};
use corcept_sink_cloudevents::export_cloudevents;
use std::io::Read;
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(name = "corcept", version, about = "Corcept Runtime CLI")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    Init {
        #[arg(long, default_value = ".")]
        path: PathBuf,
        #[arg(long)]
        dry_run: bool,
        #[arg(long)]
        force: bool,
    },
    Doctor {
        #[arg(long, default_value = ".")]
        path: PathBuf,
        /// Check owner-only (0700) permissions on ledger and operator data dirs.
        #[arg(long)]
        validate_perms: bool,
        /// Fail on any check failure; validate ledger rows against JSON Schema.
        #[arg(long)]
        strict: bool,
    },
    Audit {
        #[arg(long, default_value = ".")]
        path: PathBuf,
        #[command(subcommand)]
        command: Option<AuditCommands>,
    },
    Key {
        #[command(subcommand)]
        command: KeyCommands,
    },
    Hook {
        event: String,
        /// Hook event JSON payload. When omitted, the payload is read from stdin.
        /// MCP adapters (corcept-mcp) pass the payload here because the McPact
        /// executor runs child processes with a null stdin.
        #[arg(long)]
        input: Option<String>,
    },
    Memory {
        #[command(subcommand)]
        command: MemoryCommands,
    },
    Doctrine {
        #[command(subcommand)]
        command: DoctrineCommands,
    },
    Export {
        #[command(subcommand)]
        command: ExportCommands,
    },
    /// Opt-in bounded MCP stdio server for read-mostly Corcept inspection.
    Serve {
        #[arg(long, default_value = ".")]
        path: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
enum AuditCommands {
    /// Verify hash chain; with --signed require Ed25519 on every row.
    Verify {
        #[arg(long)]
        signed: bool,
    },
}

#[derive(Debug, Subcommand)]
enum KeyCommands {
    /// Generate operator Ed25519 signing key under XDG data home.
    Generate {
        #[arg(long)]
        force: bool,
    },
    /// Show fingerprint and path for the active signing key.
    Show,
}

#[derive(Debug, Subcommand)]
enum MemoryCommands {
    Propose {
        #[arg(long, default_value = ".")]
        path: PathBuf,
        #[arg(long)]
        title: String,
        #[arg(long)]
        claim: String,
        #[arg(long, value_delimiter = ',')]
        evidence: Vec<String>,
    },
    Promote {
        #[arg(long, default_value = ".")]
        path: PathBuf,
        #[arg(long)]
        id: String,
        #[arg(long, default_value = "user")]
        approved_by: String,
    },
}

#[derive(Debug, Subcommand)]
enum DoctrineCommands {
    Validate {
        #[arg(long, default_value = ".")]
        path: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
enum ExportCommands {
    /// Project hash-chained ledger lines to CloudEvents JSONL (derived, non-authority).
    Cloudevents {
        #[arg(long, default_value = ".corcept/ledger/events.jsonl")]
        ledger: PathBuf,
        #[arg(long)]
        out: PathBuf,
    },
    /// Rebuild projection sink files from authority ledger.
    Sinks {
        #[arg(long, default_value = ".corcept/ledger/events.jsonl")]
        ledger: PathBuf,
        #[arg(long, value_enum, default_value = "cloudevents")]
        format: SinkExportFormat,
        #[arg(long)]
        out: PathBuf,
    },
}

#[derive(Debug, Clone, clap::ValueEnum)]
enum SinkExportFormat {
    Cloudevents,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Init {
            path,
            dry_run,
            force,
        } => {
            let report = init_project(InitOptions {
                path,
                dry_run,
                force,
            })?;
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        Commands::Doctor {
            path,
            validate_perms,
            strict,
        } => {
            let report = doctor_with_options(
                path,
                DoctorOptions {
                    validate_perms,
                    strict,
                },
            )?;
            println!("{}", serde_json::to_string_pretty(&report)?);
            // Fail closed: `--strict` is a CI gate, so a failing report must be a
            // non-zero exit, not just printed JSON. Without this the gate is advisory.
            if report.status == "fail" {
                std::process::exit(1);
            }
        }
        Commands::Audit { path, command } => match command {
            Some(AuditCommands::Verify { signed }) => {
                let report = verify_ledger(&path, signed)?;
                println!("{}", serde_json::to_string_pretty(&report)?);
                // Fail closed: ledger verification is an integrity gate, so a
                // tampered chain must be a non-zero exit, not just printed JSON
                // (mirrors `doctor`). Otherwise the gate is advisory and a weak
                // caller can ignore the verdict.
                if report.tamper_detected {
                    std::process::exit(1);
                }
            }
            None => {
                println!("{}", serde_json::to_string_pretty(&audit(path)?)?);
            }
        },
        Commands::Key { command } => match command {
            KeyCommands::Generate { force } => {
                let info = generate_operator_key(force)?;
                println!("{}", serde_json::to_string_pretty(&info)?);
            }
            KeyCommands::Show => {
                println!("{}", serde_json::to_string_pretty(&show_operator_key()?)?);
            }
        },
        Commands::Hook { event, input } => {
            let input = match input {
                Some(input) => input,
                None => {
                    let mut buffer = String::new();
                    std::io::stdin().read_to_string(&mut buffer)?;
                    buffer
                }
            };
            let output = handle_hook(&input, &event)?;
            println!("{}", serde_json::to_string(&output)?);
        }
        Commands::Memory { command } => match command {
            MemoryCommands::Propose {
                path,
                title,
                claim,
                evidence,
            } => {
                let candidate = new_candidate(title, claim, evidence, "corcept-cli");
                let file = write_candidate(path, &candidate)?;
                println!(
                    "{}",
                    serde_json::json!({"status":"created","id":candidate.id,"path":file})
                );
            }
            MemoryCommands::Promote {
                path,
                id,
                approved_by,
            } => {
                let accepted = promote_candidate(path, &id, approved_by)?;
                println!("{}", serde_json::to_string_pretty(&accepted)?);
            }
        },
        Commands::Doctrine { command } => match command {
            DoctrineCommands::Validate { path } => {
                let warnings = corcept_doctrine::validate(path)?;
                println!(
                    "{}",
                    serde_json::json!({"status": if warnings.is_empty() {"pass"} else {"warn"}, "warnings": warnings})
                );
            }
        },
        Commands::Export { command } => match command {
            ExportCommands::Cloudevents { ledger, out } => {
                let count = export_cloudevents(&ledger, &out)?;
                println!(
                    "{}",
                    serde_json::json!({
                        "status": "ok",
                        "events_exported": count,
                        "out": out,
                        "ledger": ledger,
                    })
                );
            }
            ExportCommands::Sinks {
                ledger,
                format,
                out,
            } => match format {
                SinkExportFormat::Cloudevents => {
                    let count = export_cloudevents(&ledger, &out)?;
                    println!(
                        "{}",
                        serde_json::json!({
                            "status": "ok",
                            "format": "cloudevents",
                            "events_exported": count,
                            "out": out,
                            "ledger": ledger,
                        })
                    );
                }
            },
        },
        Commands::Serve { path } => {
            mcp::serve(path)?;
        }
    }
    Ok(())
}
