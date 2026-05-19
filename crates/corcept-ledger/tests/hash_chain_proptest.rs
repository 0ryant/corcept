use corcept_ledger::{append_event, verify_hash_chain};
use corcept_types::{AuthorityLevel, LedgerEventKind, LEDGER_EVENT_SCHEMA};
use proptest::prelude::*;

fn arb_kind() -> impl Strategy<Value = LedgerEventKind> {
    prop_oneof![
        Just(LedgerEventKind::SessionStarted),
        Just(LedgerEventKind::PromptSubmitted),
        Just(LedgerEventKind::ToolRequested),
        Just(LedgerEventKind::FileModified),
        Just(LedgerEventKind::TestRun),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(32))]

    #[test]
    fn append_sequence_always_verifies(kinds in prop::collection::vec(arb_kind(), 1..12)) {
        let dir = tempfile::tempdir().unwrap();
        for kind in kinds {
            append_event(
                dir.path(),
                corcept_types::LedgerEvent {
                    schema: LEDGER_EVENT_SCHEMA.to_string(),
                    id: String::new(),
                    ts: String::new(),
                    session_id: Some("s".to_string()),
                    actor: "proptest".to_string(),
                    event_type: kind.wire_str().to_string(),
                    authority_level: AuthorityLevel::L0Observe,
                    tool: None,
                    target: None,
                    decision: None,
                    decision_reason: None,
                    evidence_refs: vec![],
                    prev_hash: None,
                    hash: None,
                    metadata: Default::default(),
                    signature: None,
                },
            ).unwrap();
        }
        prop_assert!(verify_hash_chain(dir.path()).unwrap());
    }
}
