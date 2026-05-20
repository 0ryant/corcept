//! BeforeRun hook handlers.
//!
//! Channel 1 of the primer distribution plan. Each hook is a small, typed
//! unit that operates on a shared `BeforeRunContext` and emits an audit
//! event into the existing corcept ledger.

pub mod primer_injection;
pub mod primer_loader;

pub use primer_injection::{
    BeforeRunContext, BeforeRunHook, CellState, HookError, HookOutcome, InjectionDecision,
    ModelCompatibility, PrimerInjectionEvent, PrimerInjectionHook, PrimerRef, PrimerSource,
    RefuseReason, RunContract,
};
pub use primer_loader::{PrimerLoader, PrimerLoaderError, ResolvedPrimer, SourceKind};
