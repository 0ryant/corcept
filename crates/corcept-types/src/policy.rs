//! Policy composition lattice (ADR-0020).

use crate::PermissionDecision;

/// PreTool total order: Allow < Ask < Deny (strictest wins).
pub fn compose_pre_tool(a: PermissionDecision, b: PermissionDecision) -> PermissionDecision {
    match (a, b) {
        (PermissionDecision::Deny, _) | (_, PermissionDecision::Deny) => PermissionDecision::Deny,
        (PermissionDecision::Ask, _) | (_, PermissionDecision::Ask) => PermissionDecision::Ask,
        _ => PermissionDecision::Allow,
    }
}

/// Stop gate: BlockStop dominates AllowStop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StopDecision {
    AllowStop,
    BlockStop,
}

pub fn compose_stop(a: StopDecision, b: StopDecision) -> StopDecision {
    if a == StopDecision::BlockStop || b == StopDecision::BlockStop {
        StopDecision::BlockStop
    } else {
        StopDecision::AllowStop
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deny_wins_over_ask_and_allow() {
        assert_eq!(
            compose_pre_tool(PermissionDecision::Deny, PermissionDecision::Allow),
            PermissionDecision::Deny
        );
        assert_eq!(
            compose_pre_tool(PermissionDecision::Ask, PermissionDecision::Deny),
            PermissionDecision::Deny
        );
    }

    #[test]
    fn ask_wins_over_allow() {
        assert_eq!(
            compose_pre_tool(PermissionDecision::Allow, PermissionDecision::Ask),
            PermissionDecision::Ask
        );
    }

    #[test]
    fn stop_block_wins() {
        assert_eq!(
            compose_stop(StopDecision::AllowStop, StopDecision::BlockStop),
            StopDecision::BlockStop
        );
    }
}
