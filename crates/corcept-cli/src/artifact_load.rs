//! The `corcept artifact-load` verb delegates to the shared verify-before-load
//! classifier in `corcept-guards` — a single source of truth so the explicit
//! verb and the automatic `PreToolUse` hook gate run identical logic.

pub use corcept_guards::verify_before_load::classify;
