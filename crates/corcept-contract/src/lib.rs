//! Contract validation against committed JSON Schemas.

use anyhow::{Context, Result};
use jsonschema::Draft;
use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};

pub fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap_or_else(|_| Path::new(env!("CARGO_MANIFEST_DIR")).join("../.."))
}

pub fn schema_path(name: &str) -> PathBuf {
    repo_root().join("contracts/schemas").join(name)
}

pub fn example_path(name: &str) -> PathBuf {
    repo_root().join("contracts/examples").join(name)
}

pub fn validate_value(schema_file: &str, value: &Value) -> Result<()> {
    let schema_text = fs::read_to_string(schema_path(schema_file))
        .with_context(|| format!("read {schema_file}"))?;
    let schema_val: Value = serde_json::from_str(&schema_text).context("parse schema json")?;
    let validator = jsonschema::options()
        .with_draft(Draft::Draft7)
        .build(&schema_val)
        .context("compile schema")?;
    validator
        .validate(value)
        .map_err(|err| anyhow::anyhow!("schema validation failed: {err}"))
}

pub fn validate_example(schema_file: &str, example_file: &str) -> Result<()> {
    let example_text = fs::read_to_string(example_path(example_file))
        .with_context(|| format!("read example {example_file}"))?;
    let value: Value = serde_json::from_str(&example_text).context("parse example json")?;
    validate_value(schema_file, &value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn validate_path_pair(schema_file: &str, example: PathBuf) {
        let example_text = fs::read_to_string(&example).expect("example");
        let example_val: Value = serde_json::from_str(&example_text).expect("example json");
        validate_value(schema_file, &example_val)
            .unwrap_or_else(|err| panic!("validation failed for {}: {err}", example.display()));
    }

    fn validate_pair(schema_file: &str, example_file: &str) {
        validate_path_pair(schema_file, example_path(example_file));
    }

    #[test]
    fn ledger_example_validates() {
        validate_pair(
            "corcept-ledger-event-v1.schema.json",
            "ledger-tool-deny.json",
        );
    }

    #[test]
    fn hook_example_validates() {
        validate_pair(
            "corcept-hook-input-v1.schema.json",
            "hook-pretool-bash-rm-rf.json",
        );
    }

    #[test]
    fn cloudevent_example_validates() {
        validate_pair(
            "corcept-cloudevent-audit-v1.schema.json",
            "cloudevent-tool-deny.json",
        );
    }

    #[test]
    fn boundary_execution_receipt_validates() {
        validate_pair(
            "corcept-boundary-execution-receipt-v1.schema.json",
            "boundary-execution-receipt-candidate.json",
        );
    }

    #[test]
    fn sink_record_example_validates() {
        validate_pair(
            "corcept-sink-record-v1.schema.json",
            "sink-record-tool-deny.json",
        );
    }

    #[test]
    fn eval_golden_receipts_validate() {
        let root = repo_root();
        validate_path_pair(
            "corcept-case-receipt-v1.schema.json",
            root.join(
                "evals/corcept-eval-suite-v2/fixtures/golden/case-receipt-pretool-allow.json",
            ),
        );
    }

    #[test]
    fn ledger_projects_to_valid_cloudevent() {
        use corcept_sink_cloudevents::project_event;
        use corcept_types::LedgerEvent;

        let ledger_text =
            fs::read_to_string(example_path("ledger-tool-deny.json")).expect("ledger example");
        let event: LedgerEvent = serde_json::from_str(&ledger_text).expect("ledger json");
        let ce = project_event(&event);
        let ce_val = serde_json::to_value(&ce).expect("ce json");
        validate_value("corcept-cloudevent-audit-v1.schema.json", &ce_val)
            .expect("ce validates against schema");
        assert_eq!(ce.id, event.id);
        assert_eq!(
            ce.correlationid.as_str(),
            event.session_id.as_deref().unwrap_or("")
        );
    }
}
