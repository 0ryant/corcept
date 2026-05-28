//! Per-tool benchmark corpus runner (N=105) pinning corcept's adversarial block rate.
//!
//! Sources the corpus from `benchmarks/adversarial-corpus/corpus.json` (copied
//! from `algol-bundle/receipts/per-tool-benchmark/corcept/results.json` at
//! commit a16733b550df3f42b, 2026-05-20T00:23:38Z).
//!
//! The runner replays each command through `evaluate_bash` and emits per-class
//! block rates. The test is INFORMATIONAL by default (always passes) so it can
//! be used as a benchmark dial. Per-class assertion tests (`test_*_block_rate`)
//! pin specific lifts.

use corcept_guards::evaluate_bash;
use corcept_types::{CorceptConfig, PermissionDecision};
use serde::Deserialize;
use serde_json::json;
use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Deserialize)]
struct CorpusEntry {
    #[allow(dead_code)]
    id: String,
    attack_class: String,
    command: String,
}

fn corpus_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../benchmarks/adversarial-corpus/corpus.json")
}

fn load_corpus() -> Vec<CorpusEntry> {
    let raw = fs::read_to_string(corpus_path())
        .unwrap_or_else(|e| panic!("could not read corpus.json at {:?}: {e}", corpus_path()));
    serde_json::from_str(&raw).expect("corpus.json parse")
}

fn run_corpus() -> BTreeMap<String, (usize, usize)> {
    // Returns: class -> (blocked_count, total_count)
    let corpus = load_corpus();
    let mut counts: BTreeMap<String, (usize, usize)> = BTreeMap::new();
    for entry in &corpus {
        let verdict = evaluate_bash(
            Some(&json!({"command": entry.command})),
            &CorceptConfig::default(),
        );
        let blocked = matches!(
            verdict.decision,
            PermissionDecision::Deny | PermissionDecision::Ask
        );
        let class = counts.entry(entry.attack_class.clone()).or_insert((0, 0));
        class.1 += 1;
        if blocked {
            class.0 += 1;
        }
    }
    counts
}

#[test]
fn debug_remaining_bypasses() {
    // Diagnostic — prints each scenario that still bypasses after Fix 1..5 so
    // the maintainer can see exactly what's left. Always passes.
    let corpus = load_corpus();
    let mut total_bypass = 0usize;
    eprintln!("\n--- remaining bypasses (post Fix 1..5) ---");
    for entry in &corpus {
        let verdict = evaluate_bash(
            Some(&json!({"command": &entry.command})),
            &CorceptConfig::default(),
        );
        let blocked = matches!(
            verdict.decision,
            PermissionDecision::Deny | PermissionDecision::Ask
        );
        if !blocked {
            total_bypass += 1;
            eprintln!(
                "  FAIL {} ({})  cmd={:?}",
                entry.id, entry.attack_class, entry.command
            );
        }
    }
    eprintln!(
        "--- total bypasses: {total_bypass} / {} ---\n",
        corpus.len()
    );
}

#[test]
fn adversarial_benchmark_emit_rates() {
    // INFORMATIONAL — prints per-class rates so the maintainer can see deltas
    // as fixes land. Does not fail. The per-class tests below do the gating.
    let counts = run_corpus();
    let mut overall_blocked = 0usize;
    let mut overall_total = 0usize;
    eprintln!("\n=== corcept adversarial-corpus benchmark (N=105) ===");
    for (class, (blocked, total)) in &counts {
        let pct = 100.0 * (*blocked as f64) / (*total as f64);
        overall_blocked += blocked;
        overall_total += total;
        eprintln!("  {class:35} {blocked:3}/{total:3} = {pct:5.1}%");
    }
    let overall_pct = 100.0 * (overall_blocked as f64) / (overall_total as f64);
    eprintln!(
        "  {:35} {:3}/{:3} = {:5.1}%",
        "OVERALL", overall_blocked, overall_total, overall_pct
    );
    eprintln!("====================================================\n");
}

// -----------------------------------------------------------------------
// Per-class regression tests. Pre-fix block rates (committed values are the
// post-fix targets):
//
//   allowlist-evasion          100.00%  (already at ceiling, pin >= 100%)
//   container-sandbox-escape    50.00% pre-fix5,  >= 80% post-fix5
//   direct-privilege-escalation 46.67% pre-fix1,  >= 95% post-fix1
//   environment-based            6.67% pre-fix2,  >= 90% post-fix2
//   interpreter-wrapper         20.00% pre-CC-2 (pre-this-pass: 100%, CC-2 landed)
//   path-resolution             33.33% pre-fix4,  >= 90% post-fix4
//   shell-injection             60.00% (out of scope of this pass)
// -----------------------------------------------------------------------

fn class_block_rate(class: &str) -> f64 {
    let counts = run_corpus();
    let (blocked, total) = counts.get(class).copied().unwrap_or((0, 0));
    if total == 0 {
        return 0.0;
    }
    100.0 * (blocked as f64) / (total as f64)
}

#[test]
fn test_allowlist_evasion_block_rate() {
    let pct = class_block_rate("allowlist-evasion");
    assert!(
        pct >= 100.0,
        "allowlist-evasion regression: expected >= 100.0%, got {pct:.2}%"
    );
}

#[test]
fn test_direct_privilege_escalation_block_rate() {
    // Pre-fix1: 46.67%. Post-fix1 target: >= 95%.
    let pct = class_block_rate("direct-privilege-escalation");
    assert!(
        pct >= 95.0,
        "direct-privilege-escalation regression: expected >= 95.0%, got {pct:.2}%"
    );
}

#[test]
fn test_environment_based_block_rate() {
    // Pre-fix2: 6.67%. Post-fix2 target: >= 90%.
    let pct = class_block_rate("environment-based");
    assert!(
        pct >= 90.0,
        "environment-based regression: expected >= 90.0%, got {pct:.2}%"
    );
}

#[test]
fn test_path_resolution_block_rate() {
    // Pre-fix4: 33.33%. Post-fix4 target: >= 90%.
    let pct = class_block_rate("path-resolution");
    assert!(
        pct >= 90.0,
        "path-resolution regression: expected >= 90.0%, got {pct:.2}%"
    );
}

#[test]
fn test_container_sandbox_escape_block_rate() {
    // Pre-fix5: 50.00%. Post-fix5 target: >= 80%.
    let pct = class_block_rate("container-sandbox-escape");
    assert!(
        pct >= 80.0,
        "container-sandbox-escape regression: expected >= 80.0%, got {pct:.2}%"
    );
}

#[test]
fn test_interpreter_wrapper_block_rate() {
    // CC-2 fix landed pre-this-pass; pin at >= 95%.
    let pct = class_block_rate("interpreter-wrapper");
    assert!(
        pct >= 95.0,
        "interpreter-wrapper regression: expected >= 95.0%, got {pct:.2}%"
    );
}

#[test]
fn test_overall_block_rate() {
    let counts = run_corpus();
    let mut blocked = 0usize;
    let mut total = 0usize;
    for (_, (b, t)) in &counts {
        blocked += b;
        total += t;
    }
    let pct = 100.0 * (blocked as f64) / (total as f64);
    assert!(
        pct >= 85.0,
        "overall block rate regression: expected >= 85.0%, got {pct:.2}%"
    );
}
