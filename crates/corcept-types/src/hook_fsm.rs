//! Hook lifecycle FSM (ADR-0019).

use crate::LedgerEventKind;

/// Session lifecycle states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HookState {
    SessionStart,
    TurnActive,
    PreToolEvaluating,
    ToolExecuting,
    PostToolAuditing,
    StopEvaluating,
    SessionEnd,
}

/// Committed transitions with stable IDs for receipts and benchmarks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HookTransition {
    T010SessionStart,
    T020PromptSubmitted,
    T030PreToolEvaluating,
    T031ToolDecided,
    T040PostToolAuditing,
    T050StopEvaluating,
    T051StopAllowed,
    T052StopBlocked,
}

impl HookTransition {
    pub fn id(self) -> &'static str {
        match self {
            Self::T010SessionStart => "T010_session_start",
            Self::T020PromptSubmitted => "T020_prompt_submitted",
            Self::T030PreToolEvaluating => "T030_pretool_evaluating",
            Self::T031ToolDecided => "T031_tool_decided",
            Self::T040PostToolAuditing => "T040_posttool_auditing",
            Self::T050StopEvaluating => "T050_stop_evaluating",
            Self::T051StopAllowed => "T051_stop_allowed",
            Self::T052StopBlocked => "T052_stop_blocked",
        }
    }

    pub fn ledger_kind(self) -> LedgerEventKind {
        match self {
            Self::T010SessionStart => LedgerEventKind::SessionStarted,
            Self::T020PromptSubmitted => LedgerEventKind::PromptSubmitted,
            Self::T030PreToolEvaluating => LedgerEventKind::ToolRequested,
            Self::T031ToolDecided => LedgerEventKind::ToolRequested,
            Self::T040PostToolAuditing => LedgerEventKind::ToolCompleted,
            Self::T050StopEvaluating => LedgerEventKind::StopAllowed,
            Self::T051StopAllowed => LedgerEventKind::StopAllowed,
            Self::T052StopBlocked => LedgerEventKind::StopBlocked,
        }
    }
}

/// Map hook CLI command + outcome to a committed transition ID.
pub fn transition_for(
    command: &str,
    kind: LedgerEventKind,
    decision: Option<&str>,
) -> HookTransition {
    match command {
        "session-start" => HookTransition::T010SessionStart,
        "user-prompt-submit" => HookTransition::T020PromptSubmitted,
        "pretool-guard" => HookTransition::T030PreToolEvaluating,
        "posttool-audit" => HookTransition::T040PostToolAuditing,
        "stop-check" => match decision {
            Some("block") => HookTransition::T052StopBlocked,
            _ => HookTransition::T051StopAllowed,
        },
        _ => match kind {
            LedgerEventKind::StopBlocked => HookTransition::T052StopBlocked,
            LedgerEventKind::StopAllowed => HookTransition::T051StopAllowed,
            _ => HookTransition::T031ToolDecided,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transition_ids_are_stable() {
        assert_eq!(
            HookTransition::T030PreToolEvaluating.id(),
            "T030_pretool_evaluating"
        );
    }

    #[test]
    fn stop_check_maps_block_decision() {
        assert_eq!(
            transition_for("stop-check", LedgerEventKind::StopBlocked, Some("block")),
            HookTransition::T052StopBlocked
        );
    }
}
