//! Adversarial scenario corpus runner (ST-043).

use corcept_guards::evaluate_pre_tool;
use corcept_types::{CorceptConfig, HookEnvelope, PermissionDecision};
use serde::Deserialize;
use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Deserialize)]
struct Scenario {
    id: String,
    #[allow(dead_code)]
    description: String,
    tool_name: String,
    tool_input: Value,
    expected: PermissionDecision,
    unsafe_if: PermissionDecision,
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap()
}

fn load_scenarios(path: &Path) -> Vec<Scenario> {
    let raw = fs::read_to_string(path).expect("corpus file");
    serde_yaml::Deserializer::from_str(&raw)
        .map(|doc| Scenario::deserialize(doc).expect("scenario yaml"))
        .collect()
}

fn run_scenario(scenario: &Scenario) {
    let input = HookEnvelope {
        hook_event_name: "PreToolUse".to_string(),
        tool_name: Some(scenario.tool_name.clone()),
        cwd: Some(PathBuf::from("/repo")),
        tool_input: Some(scenario.tool_input.clone()),
        ..HookEnvelope::default()
    };
    let verdict = evaluate_pre_tool(&input, &CorceptConfig::default());
    assert_eq!(
        verdict.decision, scenario.expected,
        "scenario {} expected {:?} got {:?}: {}",
        scenario.id, scenario.expected, verdict.decision, verdict.reason
    );
    if verdict.decision == scenario.unsafe_if {
        panic!(
            "unsafe outcome {:?} for scenario {}: {}",
            scenario.unsafe_if, scenario.id, verdict.reason
        );
    }
}

#[test]
fn adversarial_pretool_corpus() {
    let path = repo_root().join("tests/adversarial/scenarios/pretool-corpus.yaml");
    let scenarios = load_scenarios(&path);
    assert!(
        scenarios.len() >= 10,
        "expected >=10 scenarios, got {}",
        scenarios.len()
    );
    for scenario in &scenarios {
        run_scenario(scenario);
    }
}
