use corcept_types::{compose_pre_tool, compose_stop, PermissionDecision, StopDecision};
use proptest::prelude::*;

fn arb_decision() -> impl Strategy<Value = PermissionDecision> {
    prop_oneof![
        Just(PermissionDecision::Allow),
        Just(PermissionDecision::Ask),
        Just(PermissionDecision::Deny),
    ]
}

proptest! {
    #[test]
    fn compose_pre_tool_deny_dominates(a in arb_decision(), b in arb_decision()) {
        let composed = compose_pre_tool(a, b);
        if a == PermissionDecision::Deny || b == PermissionDecision::Deny {
            prop_assert_eq!(composed, PermissionDecision::Deny);
        } else if a == PermissionDecision::Ask || b == PermissionDecision::Ask {
            prop_assert_eq!(composed, PermissionDecision::Ask);
        } else {
            prop_assert_eq!(composed, PermissionDecision::Allow);
        }
    }

    #[test]
    fn compose_pre_tool_is_commutative(a in arb_decision(), b in arb_decision()) {
        prop_assert_eq!(compose_pre_tool(a, b), compose_pre_tool(b, a));
    }

    #[test]
    fn compose_pre_tool_is_associative(a in arb_decision(), b in arb_decision(), c in arb_decision()) {
        prop_assert_eq!(
            compose_pre_tool(compose_pre_tool(a, b), c),
            compose_pre_tool(a, compose_pre_tool(b, c))
        );
    }

    #[test]
    fn compose_stop_block_dominates(a in prop_oneof![Just(StopDecision::AllowStop), Just(StopDecision::BlockStop)],
                                    b in prop_oneof![Just(StopDecision::AllowStop), Just(StopDecision::BlockStop)]) {
        let composed = compose_stop(a, b);
        if a == StopDecision::BlockStop || b == StopDecision::BlockStop {
            prop_assert_eq!(composed, StopDecision::BlockStop);
        } else {
            prop_assert_eq!(composed, StopDecision::AllowStop);
        }
    }
}
