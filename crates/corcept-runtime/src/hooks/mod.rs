//! ADR-0027 Channel 1: stack-enforced primer distribution.
//!
//! This module tree houses the BeforeRun hook surface for the
//! anti-confabulation primer (and any future primers that ride the same
//! lifecycle). The handler is invoked when a cell's run contract declares a
//! `primer` reference. It loads the canonical primer body from the operator's
//! engineering-doctrine checkout (or a vendored fallback), verifies the
//! SHA-256 against the contract-declared expected hash, applies the
//! model-compatibility refusal rule, and prepends the primer to the cell's
//! system prompt before any tool call fires.
//!
//! Why is it scaffolded ahead of ADR-0005 (triggers substrate) and
//! ADR-0006 (13 canonical hook names)? Channel 1 is the only enforcement
//! plane that is structurally guaranteed at the moment the cell starts; the
//! router and validator are auxiliary defences. Shipping the hook first
//! against a typed `BeforeRunContext` shape means the substrate work can
//! wire to a known, tested handler instead of building handler + substrate
//! together.
//!
//! ## TODO(ADR-0005): wire to triggers substrate
//!
//! The handler currently consumes a local `BeforeRunContext` struct defined
//! in `primer_injection.rs`. When the canonical triggers substrate lands,
//! the `try_dispatch_v2("before-run", ...)` path in `hooks_v2.rs` should
//! construct a `BeforeRunContext` from the wire shape (`BeforeRunInput` +
//! cell metadata the host knows but does not currently transport) and call
//! into [`before_run::primer_injection::PrimerInjectionHook::run`]. The
//! local `BeforeRunContext` is the contract; updating it is the only
//! surface change needed at integration time.

pub mod before_run;
