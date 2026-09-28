//! Contract validation against committed JSON Schemas.

use anyhow::{Context, Result};
use jsonschema::{Draft, Resource};
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
    validate_schema(&schema_val, value)
}

fn validate_schema(schema_val: &Value, value: &Value) -> Result<()> {
    // Register the committed delegation contract locally: validation must not
    // depend on a public schema host being reachable or serving the same file.
    let delegation: Value = serde_json::from_str(include_str!(
        "../../../contracts/schemas/corcept-delegation-v1.schema.json"
    ))
    .context("parse delegation schema json")?;
    let validator = jsonschema::options()
        .with_draft(Draft::Draft7)
        .with_resource(
            "https://schemas.corcept.dev/corcept-delegation-v1.schema.json",
            Resource::from_contents(delegation).context("load delegation schema resource")?,
        )
        .build(schema_val)
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

    fn delegation_hook_example() -> Value {
        serde_json::from_str(
            &fs::read_to_string(example_path("delegation-allow.json")).expect("delegation example"),
        )
        .expect("delegation example json")
    }

    fn assert_invalid_delegated_hook(candidate: &Value) {
        for path in [
            schema_path("corcept-hook-input-v1.schema.json"),
            repo_root().join("schemas/hook-input.schema.json"),
        ] {
            let schema: Value =
                serde_json::from_str(&fs::read_to_string(&path).expect("hook schema"))
                    .expect("hook schema json");
            assert!(
                validate_schema(&schema, candidate).is_err(),
                "malformed delegated hook accepted by {}",
                path.display()
            );
        }
    }

    #[test]
    fn delegation_example_validates_as_hook_and_envelope() {
        let example = delegation_hook_example();
        validate_value("corcept-hook-input-v1.schema.json", &example)
            .expect("delegated hook schema");
        validate_value("corcept-delegation-v1.schema.json", &example["delegation"])
            .expect("delegation envelope schema");
        let native_schema: Value = serde_json::from_str(
            &fs::read_to_string(repo_root().join("schemas/hook-input.schema.json"))
                .expect("native hook schema"),
        )
        .expect("native hook schema json");
        validate_schema(&native_schema, &example).expect("native delegated hook schema");
    }

    #[test]
    fn delegation_schema_rejects_missing_required_fields() {
        let envelope = delegation_hook_example()["delegation"].clone();
        for field in [
            "schema",
            "correlation_id",
            "caller_id",
            "agent_id",
            "user_id",
            "organisation_id",
            "target_service",
            "capability",
            "action",
            "resource",
            "grant_id",
        ] {
            let mut candidate = envelope.clone();
            candidate.as_object_mut().expect("envelope").remove(field);
            assert!(
                validate_value("corcept-delegation-v1.schema.json", &candidate).is_err(),
                "missing {field} must be rejected"
            );
        }
    }

    #[test]
    fn delegation_schema_rejects_unknown_version_fields_and_invalid_references() {
        let envelope = delegation_hook_example()["delegation"].clone();
        let mut candidate = envelope.clone();
        candidate["schema"] = serde_json::json!("corcept.delegation.v2");
        assert!(validate_value("corcept-delegation-v1.schema.json", &candidate).is_err());
        candidate = envelope.clone();
        candidate["verified"] = serde_json::json!(true);
        assert!(validate_value("corcept-delegation-v1.schema.json", &candidate).is_err());
        for field in [
            "correlation_id",
            "caller_id",
            "agent_id",
            "user_id",
            "organisation_id",
            "target_service",
            "capability",
            "action",
            "resource",
            "grant_id",
            "approval_id",
        ] {
            for invalid in [
                serde_json::json!(42),
                serde_json::json!([]),
                serde_json::json!({"verified": true}),
                serde_json::json!(""),
                serde_json::json!("has spaces"),
                serde_json::json!("reference\n"),
                serde_json::json!("reference\r\n"),
                serde_json::json!("user@example.test"),
                serde_json::json!("https://service.test/resource"),
                serde_json::json!("é"),
                serde_json::json!("a".repeat(129)),
            ] {
                let mut candidate = envelope.clone();
                candidate[field] = invalid;
                assert!(
                    validate_value("corcept-delegation-v1.schema.json", &candidate).is_err(),
                    "invalid reference in {field} must be rejected"
                );
            }
        }
    }

    #[test]
    fn delegation_approval_reference_can_be_absent_or_null() {
        let mut envelope = delegation_hook_example()["delegation"].clone();
        envelope
            .as_object_mut()
            .expect("envelope")
            .remove("approval_id");
        validate_value("corcept-delegation-v1.schema.json", &envelope).expect("optional approval");
        envelope["approval_id"] = Value::Null;
        validate_value("corcept-delegation-v1.schema.json", &envelope).expect("null approval");
    }

    #[test]
    fn hook_schema_rejects_malformed_delegation_and_missing_invocation_binding() {
        let example = delegation_hook_example();
        for invalid in [
            Value::Null,
            serde_json::json!(true),
            serde_json::json!([]),
            serde_json::json!("grant:1"),
            serde_json::json!({}),
        ] {
            let mut candidate = example.clone();
            candidate["delegation"] = invalid;
            assert_invalid_delegated_hook(&candidate);
        }
        for field in [
            "cwd",
            "session_id",
            "tool_use_id",
            "tool_name",
            "tool_input",
        ] {
            let mut candidate = example.clone();
            candidate.as_object_mut().expect("hook").remove(field);
            assert_invalid_delegated_hook(&candidate);
        }
        for field in ["cwd", "session_id", "tool_use_id", "tool_name", "agent_id"] {
            let mut candidate = example.clone();
            candidate[field] = serde_json::json!("");
            assert_invalid_delegated_hook(&candidate);
        }
        for invalid in [
            Value::Null,
            serde_json::json!([]),
            serde_json::json!("args"),
        ] {
            let mut candidate = example.clone();
            candidate["tool_input"] = invalid;
            assert_invalid_delegated_hook(&candidate);
        }
        let mut candidate = example;
        candidate["hook_event_name"] = serde_json::json!("PostToolUse");
        assert_invalid_delegated_hook(&candidate);
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
