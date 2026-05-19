//! Versioned ledger event wire types (ADR-0018).

use serde::{Deserialize, Serialize};
use std::fmt;

pub const LEDGER_EVENT_SCHEMA: &str = "corcept.ledger_event.v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LedgerEventKind {
    SessionStarted,
    PromptSubmitted,
    ToolRequested,
    ToolDecided,
    FileModified,
    CommandExecuted,
    TestRun,
    ToolCompleted,
    StopAllowed,
    StopBlocked,
}

impl LedgerEventKind {
    pub const ALL: [LedgerEventKind; 10] = [
        Self::SessionStarted,
        Self::PromptSubmitted,
        Self::ToolRequested,
        Self::ToolDecided,
        Self::FileModified,
        Self::CommandExecuted,
        Self::TestRun,
        Self::ToolCompleted,
        Self::StopAllowed,
        Self::StopBlocked,
    ];

    pub fn wire_str(self) -> &'static str {
        match self {
            Self::SessionStarted => "corcept.event.session_started.v1",
            Self::PromptSubmitted => "corcept.event.prompt_submitted.v1",
            Self::ToolRequested => "corcept.event.tool_requested.v1",
            Self::ToolDecided => "corcept.event.tool_decided.v1",
            Self::FileModified => "corcept.event.file_modified.v1",
            Self::CommandExecuted => "corcept.event.command_executed.v1",
            Self::TestRun => "corcept.event.test_run.v1",
            Self::ToolCompleted => "corcept.event.tool_completed.v1",
            Self::StopAllowed => "corcept.event.stop_allowed.v1",
            Self::StopBlocked => "corcept.event.stop_blocked.v1",
        }
    }

    pub fn parse(s: &str) -> Self {
        match s {
            "corcept.event.session_started.v1" | "session_started" => Self::SessionStarted,
            "corcept.event.prompt_submitted.v1" | "prompt_submitted" => Self::PromptSubmitted,
            "corcept.event.tool_requested.v1" | "tool_requested" => Self::ToolRequested,
            "corcept.event.tool_decided.v1" | "tool_decided" => Self::ToolDecided,
            "corcept.event.file_modified.v1" | "file_modified" => Self::FileModified,
            "corcept.event.command_executed.v1" | "command_executed" => Self::CommandExecuted,
            "corcept.event.test_run.v1" | "test_run" => Self::TestRun,
            "corcept.event.tool_completed.v1" | "tool_completed" => Self::ToolCompleted,
            "corcept.event.stop_allowed.v1" | "stop_allowed" => Self::StopAllowed,
            "corcept.event.stop_blocked.v1" | "stop_blocked" => Self::StopBlocked,
            _ => Self::ToolCompleted,
        }
    }

    pub fn matches_str(self, s: &str) -> bool {
        Self::parse(s) == self
    }
}

impl fmt::Display for LedgerEventKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.wire_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_strings_are_stable() {
        let expected = [
            "corcept.event.session_started.v1",
            "corcept.event.prompt_submitted.v1",
            "corcept.event.tool_requested.v1",
            "corcept.event.tool_decided.v1",
            "corcept.event.file_modified.v1",
            "corcept.event.command_executed.v1",
            "corcept.event.test_run.v1",
            "corcept.event.tool_completed.v1",
            "corcept.event.stop_allowed.v1",
            "corcept.event.stop_blocked.v1",
        ];
        for (kind, wire) in LedgerEventKind::ALL.iter().zip(expected) {
            assert_eq!(kind.wire_str(), wire);
        }
    }

    #[test]
    fn legacy_aliases_parse() {
        assert_eq!(
            LedgerEventKind::parse("file_modified"),
            LedgerEventKind::FileModified
        );
        assert_eq!(
            LedgerEventKind::parse("corcept.event.file_modified.v1"),
            LedgerEventKind::FileModified
        );
    }
}
