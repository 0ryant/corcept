mod mcp;

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::Result;
use axiom_audit::ReceiptLink;
use axiom_exit::Exit;
use chrono::{SecondsFormat, Utc};
use clap::{Parser, Subcommand};
use corcept_ledger::{
    append_audit, generate_operator_key, show_operator_key, verify_ledger, Artifact, AuditLink,
    Receipt, ReceiptBody, TrailLock, TRAIL_FILENAME,
};
use corcept_memory::{new_candidate, promote_candidate, write_candidate};
use corcept_runtime::{
    audit, doctor_with_options, handle_hook, init_project, DoctorOptions, InitOptions,
};
use corcept_sink_cloudevents::export_cloudevents;
use std::io::Read;

/// Tool-specific terminal outcome: `doctor` reported a failing check, or a
/// finding/health gate tripped. NOT a verify/chain mismatch (that is exit 1) —
/// pattern-11 reserves exit 1 for `ASSERTION_FAILED`. Distinct *name*, the
/// doctrine `>=64` band.
const FINDINGS_PRESENT: Exit = Exit::ToolSpecific(64);

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
    /// Verify the `axiom.audit.v1` trail (`audit-trail.jsonl`) at the repo root.
    VerifyTrail,
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

fn main() -> ExitCode {
    // clap maps argument/usage errors to exit code 2 (USAGE_ERROR) on its own.
    let cli = Cli::parse();
    match run(cli) {
        Ok(exit) => ExitCode::from(exit),
        // Any IO / parse / startup failure that escapes a verb is a preflight
        // failure (3), NOT a generic exit-1: exit 1 is reserved for an actual
        // verify/chain assertion mismatch (pattern 11).
        Err(err) => {
            eprintln!("corcept: {err:#}");
            ExitCode::from(Exit::Preflight)
        }
    }
}

/// RFC-3339 millis UTC timestamp for audit rows / receipts.
fn now_ts() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true)
}

/// Append one `axiom.audit.v1` row to `<repo>/audit-trail.jsonl` and write a
/// signed `axiom.receipt.v1` receipt linked to it, under a cross-process lock.
///
/// Best-effort: a trail/receipt write failure never changes the verb's own
/// verdict (the authority ledger is the source of truth); it is reported on
/// stderr. Returns the receipt's repo-relative path on success.
fn emit_receipt(
    repo: &Path,
    operation: &str,
    outcome: &str,
    exit: Exit,
    inputs: Vec<Artifact>,
    outputs: Vec<Artifact>,
) -> Option<PathBuf> {
    let ts = now_ts();
    let receipts_dir = repo.join(".corcept").join("receipts");
    let receipt_name = format!("{}-{}.json", operation.replace(' ', "-"), ts.replace(':', ""));
    let receipt_path = receipts_dir.join(&receipt_name);
    let receipt_rel = format!(".corcept/receipts/{receipt_name}");

    let result = (|| -> std::result::Result<(), corcept_ledger::TrailError> {
        let _lock = TrailLock::acquire(repo)?;

        // 1. Append the audit row first so the receipt can link the committed tip.
        let row = append_audit(repo, operation, outcome, exit.as_i32(), &ts, ReceiptLink::None)?;

        // 2. Build + sign the receipt, linking the row we just appended.
        let mut body = ReceiptBody::new(operation, outcome, &ts);
        body.inputs = inputs;
        body.outputs = outputs;
        body.audit_chain = Some(AuditLink {
            trail_path: TRAIL_FILENAME.to_string(),
            seq: row.seq,
            row_hash: row.row_hash,
        });
        let receipt = Receipt::sign(body)?;
        std::fs::create_dir_all(&receipts_dir)
            .map_err(|e| corcept_ledger::TrailError::Audit(axiom_audit::AuditError::Io(e)))?;
        std::fs::write(&receipt_path, receipt.to_json()?)
            .map_err(|e| corcept_ledger::TrailError::Audit(axiom_audit::AuditError::Io(e)))?;
        Ok(())
    })();

    match result {
        Ok(()) => Some(PathBuf::from(receipt_rel)),
        Err(err) => {
            eprintln!("corcept: audit-trail/receipt emission failed (best-effort): {err}");
            None
        }
    }
}

fn run(cli: Cli) -> Result<Exit> {
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
            Ok(Exit::Ok)
        }
        Commands::Doctor {
            path,
            validate_perms,
            strict,
        } => {
            let report = doctor_with_options(
                &path,
                DoctorOptions {
                    validate_perms,
                    strict,
                },
            )?;
            println!("{}", serde_json::to_string_pretty(&report)?);
            // Fail closed: `--strict` is a CI gate, so a failing report must be a
            // non-zero exit. A doctor failure is a tool-specific health verdict,
            // NOT a verify/chain mismatch, so it maps to the >=64 band — exit 1
            // stays reserved for `audit verify` chain assertions.
            if report.status == "fail" {
                Ok(FINDINGS_PRESENT)
            } else {
                Ok(Exit::Ok)
            }
        }
        Commands::Audit { path, command } => match command {
            Some(AuditCommands::Verify { signed }) => {
                let report = verify_ledger(&path, signed)?;
                println!("{}", serde_json::to_string_pretty(&report)?);
                let exit = if report.tamper_detected {
                    Exit::AssertionFailed
                } else {
                    Exit::Ok
                };
                // Record the verification as an axiom.audit.v1 row + signed
                // receipt. The ledger we verified is the receipt's input.
                let ledger = path.join(".corcept/ledger/events.jsonl");
                let inputs = if ledger.is_file() {
                    Artifact::of_file("ledger", ".corcept/ledger/events.jsonl", &ledger)
                        .map(|a| vec![a])
                        .unwrap_or_default()
                } else {
                    Vec::new()
                };
                let outcome = if report.tamper_detected { "failed" } else { "ok" };
                emit_receipt(&path, "audit verify", outcome, exit, inputs, Vec::new());
                Ok(exit)
            }
            Some(AuditCommands::VerifyTrail) => {
                let verdict = corcept_ledger::verify_trail(&path)?;
                let (status, exit) = match &verdict {
                    corcept_ledger::ChainVerdict::Valid { .. } => ("pass", Exit::Ok),
                    corcept_ledger::ChainVerdict::Broken(_) => ("fail", Exit::AssertionFailed),
                };
                let detail = match &verdict {
                    corcept_ledger::ChainVerdict::Valid { rows, head_hash } => serde_json::json!({
                        "status": status, "rows": rows, "head_hash": head_hash,
                    }),
                    corcept_ledger::ChainVerdict::Broken(why) => serde_json::json!({
                        "status": status, "reason": why,
                    }),
                };
                println!("{}", serde_json::to_string_pretty(&detail)?);
                Ok(exit)
            }
            None => {
                println!("{}", serde_json::to_string_pretty(&audit(path)?)?);
                Ok(Exit::Ok)
            }
        },
        Commands::Key { command } => match command {
            KeyCommands::Generate { force } => {
                let info = generate_operator_key(force)?;
                println!("{}", serde_json::to_string_pretty(&info)?);
                Ok(Exit::Ok)
            }
            KeyCommands::Show => {
                println!("{}", serde_json::to_string_pretty(&show_operator_key()?)?);
                Ok(Exit::Ok)
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
            Ok(Exit::Ok)
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
                Ok(Exit::Ok)
            }
            MemoryCommands::Promote {
                path,
                id,
                approved_by,
            } => {
                let accepted = promote_candidate(path, &id, approved_by)?;
                println!("{}", serde_json::to_string_pretty(&accepted)?);
                Ok(Exit::Ok)
            }
        },
        Commands::Doctrine { command } => match command {
            DoctrineCommands::Validate { path } => {
                let warnings = corcept_doctrine::validate(path)?;
                println!(
                    "{}",
                    serde_json::json!({"status": if warnings.is_empty() {"pass"} else {"warn"}, "warnings": warnings})
                );
                Ok(Exit::Ok)
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
                emit_export_receipt(&ledger, &out, count);
                Ok(Exit::Ok)
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
                    emit_export_receipt(&ledger, &out, count);
                    Ok(Exit::Ok)
                }
            },
        },
        Commands::Serve { path } => {
            mcp::serve(path)?;
            Ok(Exit::Ok)
        }
    }
}

/// Emit an `axiom.audit.v1` row + `axiom.receipt.v1` receipt for an export verb,
/// rooting the trail at the ledger's repo (the parent of `.corcept/`).
fn emit_export_receipt(ledger: &Path, out: &Path, count: usize) {
    let repo = repo_root_of(ledger);
    let mut inputs = Vec::new();
    if ledger.is_file() {
        if let Ok(a) = Artifact::of_file("ledger", &ledger.to_string_lossy(), ledger) {
            inputs.push(a);
        }
    }
    let mut outputs = Vec::new();
    if out.is_file() {
        if let Ok(a) = Artifact::of_file("cloudevents", &out.to_string_lossy(), out) {
            outputs.push(a);
        }
    }
    let outcome = if count > 0 || out.is_file() { "ok" } else { "degraded" };
    emit_receipt(&repo, "export", outcome, Exit::Ok, inputs, outputs);
}

/// Resolve the repo root that owns `<repo>/.corcept/ledger/events.jsonl`. Falls
/// back to the current directory when the ledger path has no `.corcept` ancestor.
fn repo_root_of(ledger: &Path) -> PathBuf {
    let mut cur = ledger;
    while let Some(parent) = cur.parent() {
        if parent.file_name().and_then(|n| n.to_str()) == Some(".corcept") {
            if let Some(repo) = parent.parent() {
                return repo.to_path_buf();
            }
        }
        cur = parent;
    }
    PathBuf::from(".")
}
