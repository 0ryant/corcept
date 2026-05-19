use corcept_types::LedgerEventKind;
use proptest::prelude::*;

proptest! {
    #[test]
    fn wire_str_roundtrip(kind in prop_oneof![
        Just(LedgerEventKind::SessionStarted),
        Just(LedgerEventKind::PromptSubmitted),
        Just(LedgerEventKind::ToolRequested),
        Just(LedgerEventKind::FileModified),
        Just(LedgerEventKind::TestRun),
        Just(LedgerEventKind::StopBlocked),
    ]) {
        let wire = kind.wire_str();
        prop_assert!(kind.matches_str(wire));
        prop_assert_eq!(LedgerEventKind::parse(wire), kind);
    }
}
