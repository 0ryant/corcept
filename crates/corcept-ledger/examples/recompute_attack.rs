//! Adversarial-recompute attack tool (corcept level-up 2026-06-15).
//!
//! Simulates a source-reading adversary who edits a committed ledger row AND
//! recomputes the ENTIRE hash chain over the PUBLIC domain prefix
//! (`HASH_DOMAIN = "corcept:ledger:v1:"`). It rebuilds every `prev_hash`/`hash`
//! so the chain is internally consistent again, exactly as `append_event` would
//! have produced it. Signatures are left STALE — the attacker cannot re-sign
//! without the operator's private key.
//!
//! This is a demo/evidence helper, NOT a product surface: it shows that the
//! keyless `corcept audit verify` FALSE-PASSES the result while
//! `corcept audit verify --signed` CATCHES it. The same property is asserted by
//! `tests/recompute_attack.rs`.
//!
//! Usage:
//!   cargo run -p corcept-ledger --example recompute_attack -- \
//!       <events.jsonl> <1-based-line> <field> <new-value>
//!
//! Example (flip a denied dangerous command to allowed):
//!   cargo run -p corcept-ledger --example recompute_attack -- \
//!       ledger/events.jsonl 2 decision allow

use corcept_ledger::hash_event_hardened;
use corcept_types::LedgerEvent;
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 5 {
        eprintln!(
            "usage: {} <events.jsonl> <1-based-line> <field> <new-value>\n\
             field is one of: decision | decision_reason | target | tool",
            args.first()
                .map(String::as_str)
                .unwrap_or("recompute_attack")
        );
        return ExitCode::from(2);
    }
    let path = &args[1];
    let line_no: usize = match args[2].parse() {
        Ok(n) if n >= 1 => n,
        _ => {
            eprintln!("line must be a 1-based positive integer");
            return ExitCode::from(2);
        }
    };
    let field = args[3].as_str();
    let value = args[4].clone();

    let raw = match std::fs::read_to_string(path) {
        Ok(r) => r,
        Err(err) => {
            eprintln!("reading {path}: {err}");
            return ExitCode::from(2);
        }
    };
    let mut events: Vec<LedgerEvent> = match raw
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(serde_json::from_str)
        .collect::<Result<_, _>>()
    {
        Ok(e) => e,
        Err(err) => {
            eprintln!("parsing ledger: {err}");
            return ExitCode::from(2);
        }
    };

    if line_no > events.len() {
        eprintln!(
            "line {line_no} out of range (ledger has {} rows)",
            events.len()
        );
        return ExitCode::from(2);
    }
    let idx = line_no - 1;

    // (1) The edit: tamper one committed row.
    match field {
        "decision" => events[idx].decision = Some(value),
        "decision_reason" => events[idx].decision_reason = Some(value),
        "target" => events[idx].target = Some(value),
        "tool" => events[idx].tool = Some(value),
        other => {
            eprintln!("unknown field '{other}' (decision|decision_reason|target|tool)");
            return ExitCode::from(2);
        }
    }

    // (2) Recompute the WHOLE chain over the PUBLIC prefix. This is the part the
    // naive demo attacker skips; doing it makes the keyless checksum pass again.
    let mut previous: Option<String> = None;
    for event in events.iter_mut() {
        event.prev_hash = previous.clone();
        let hash = match hash_event_hardened(event) {
            Ok(h) => h,
            Err(err) => {
                eprintln!("hashing row: {err}");
                return ExitCode::from(2);
            }
        };
        event.hash = Some(hash);
        previous = event.hash.clone();
        // Signatures are deliberately left untouched -> stale -> caught by
        // `audit verify --signed`.
    }

    let body = events
        .iter()
        .map(|e| serde_json::to_string(e).expect("serialize event"))
        .collect::<Vec<_>>()
        .join("\n");
    if let Err(err) = std::fs::write(path, format!("{body}\n")) {
        eprintln!("writing {path}: {err}");
        return ExitCode::from(2);
    }

    eprintln!(
        "recompute-attack: rewrote line {line_no} field '{field}' and recomputed the \
         public-prefix hash chain over {} rows; signatures left stale.",
        events.len()
    );
    ExitCode::SUCCESS
}
