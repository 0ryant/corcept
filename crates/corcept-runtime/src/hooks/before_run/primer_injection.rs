//! BeforeRun primer-injection hook.
//!
//! This is Channel 1 of the primer distribution plan from
//! `engineering-doctrine` branch `claude/anti-confab-priming-pattern-2026-05-19`.
//! The hook fires when a cell's run contract declares a `primer` reference,
//! BEFORE any tool use. It:
//!
//! 1. Reads `ctx.run_contract.primer` (typed `PrimerRef`).
//! 2. Resolves the primer body via [`super::PrimerLoader`].
//! 3. Verifies the model-compatibility table:
//!    - `ConfirmedUplift` / `Neutral` -> inject;
//!    - `InvertedAvoid` -> refuse via [`HookOutcome::AbortStart`].
//! 4. Computes SHA-256 of the loaded body and compares to the
//!    contract-declared `expected_sha256`. Mismatch -> [`HookError::PrimerIntegrity`].
//! 5. Prepends the primer body to `ctx.cell.system_prompt`.
//! 6. Emits a `before_run_primer_injection` audit event with the primer id,
//!    version, fingerprint, model, decision, and source kind.
//!
//! The shape of the audit event is the one
//! `tapprove.claim_audit`'s `priming_active` verifier reads (per
//! `engineering-doctrine/contracts/verifier-pack.v1.schema.json` row 11 / kind
//! enum value `priming_active`).
//!
//! ## TODO(ADR-0005): triggers substrate
//!
//! The current `BeforeRunContext` is a hand-built struct because the
//! canonical triggers substrate is still in flight (agent `a40623dcdf8dc7056`
//! has not returned). When that substrate lands:
//! - The wire-level `BeforeRunInput` (from `hooks_v2.rs`) will gain a `cell`
//!   block carrying model id and current system_prompt.
//! - The `try_dispatch_v2("before-run", ...)` handler in `hooks_v2.rs` will
//!   construct a `BeforeRunContext` from `BeforeRunInput` and invoke this
//!   hook.
//! - At that point the `BeforeRunContext` struct here becomes the integration
//!   contract; nothing else in this file needs to change.

use std::path::PathBuf;

use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

use super::primer_loader::{
    hex_sha256 as compute_hex_sha256, PrimerLoader, PrimerLoaderError, SourceKind,
};

// ---------------------------------------------------------------------------
// Typed contract: PrimerRef, ModelCompatibility, BeforeRunContext, ...
// ---------------------------------------------------------------------------

/// Where the cell is supposed to fetch the primer body from. Mirrors the
/// `primer.source` field of the v3 run-contract schema. The schema is still
/// in flight on the sibling branch; we anchor on the kebab-case identifiers
/// emitted by ADR-0009 v3.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrimerSource {
    /// The cell should consume the primer from the engineering-doctrine
    /// canonical skill file.
    EngineeringDoctrine,
}

/// Empirical model-compatibility verdicts copied verbatim from
/// `anti-confabulation.skill.md` and the v2 canonical scoring file. These
/// drive the structural refusal rule:
///
/// - `ConfirmedUplift` - measured lift on this model class. Inject.
/// - `Neutral` - no significant lift or loss. Inject anyway (the priming
///   cost is small and the structural guarantee is the point).
/// - `InvertedAvoid` - measured regression or unmeasured class with
///   high-risk priors (Stage 2 evidence: Tools-Haiku at 31 with SKILLS).
///   Refuse to start the cell.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModelCompatibility {
    ConfirmedUplift,
    Neutral,
    InvertedAvoid,
}

/// Reference to a primer in a run contract's `primer` field. The shape
/// mirrors what the v3 ADR-0009 run-contract schema will emit; staying
/// faithful to the schema means the hook compiles unchanged once that work
/// lands.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrimerRef {
    /// Primer id (e.g. `anti-confab-200tok`).
    pub id: String,
    /// Semver version of the primer (e.g. `1.0.0`).
    pub version: String,
    /// Where the cell is supposed to fetch the body from.
    pub source: PrimerSource,
    /// Expected SHA-256 of the priming block body (lowercase hex, no
    /// `sha256:` prefix). The hook fails loudly if the loaded body does
    /// not match.
    pub expected_sha256: String,
    /// Per-model-class compatibility verdicts. Keys are the model id or
    /// class prefix the contract author wants to assert. Lookup is by
    /// exact match first, then prefix match (so a contract may declare
    /// `claude-sonnet-4-6` and have a `claude-sonnet-4-6-20250101` cell
    /// match the prefix).
    pub model_compatibility: std::collections::BTreeMap<String, ModelCompatibility>,
}

/// Minimal slice of cell state the hook needs to read and (in the inject
/// case) mutate.
#[derive(Debug, Clone)]
pub struct CellState {
    /// Model id the cell will run on (e.g. `claude-sonnet-4-6`, `haiku-4-5`).
    pub model: String,
    /// The cell's system prompt. The hook prepends the primer body when
    /// it injects.
    pub system_prompt: String,
}

/// Subset of run-contract state the hook reads.
#[derive(Debug, Clone)]
pub struct RunContract {
    /// Contract id (kebab-case).
    pub name: String,
    /// Contract fingerprint (sha256 of the canonicalised body).
    pub fingerprint: String,
    /// The `primer` field. `None` -> no primer declared -> hook is no-op.
    pub primer: Option<PrimerRef>,
}

/// What the hook handler operates on. The substrate produces this from
/// its native wire format.
#[derive(Debug, Clone)]
pub struct BeforeRunContext {
    pub run_contract: RunContract,
    pub cell: CellState,
    /// Session id; flows into the audit event.
    pub session_id: Option<String>,
    /// Free-form bindings the trigger forwarded (currently unused; held
    /// for parity with `hooks_v2::BeforeRunInput`).
    pub bindings: std::collections::BTreeMap<String, Value>,
}

// ---------------------------------------------------------------------------
// Outcome / error / event types
// ---------------------------------------------------------------------------

/// Why a hook refused to start a cell. Stable across versions; the wire
/// shape is `kind`-tagged so the operator-facing audit reason can render.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RefuseReason {
    /// The model-compatibility table marked the cell's model as `InvertedAvoid`.
    /// This is the router-refusal rule from v3 ADR-0009 enforced at the hook
    /// plane.
    ModelCompatibilityRefusal {
        model: String,
        primer_id: String,
        primer_version: String,
        /// Empirical evidence anchor; copied into the operator-facing reason
        /// so the refusal is auditable without external lookup.
        evidence: String,
    },
}

/// What the hook returns to the lifecycle machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HookOutcome {
    /// Continue the run (the cell may start).
    Continue,
    /// Refuse to start the cell. The lifecycle machine MUST surface
    /// `reason` to the operator and write it into the audit log.
    AbortStart { reason: RefuseReason },
}

/// Hook-internal errors (the hook itself failed, distinct from a deliberate
/// `AbortStart`).
#[derive(Debug, Error)]
pub enum HookError {
    /// Loaded primer body's SHA-256 does not match the contract's
    /// `expected_sha256`. Loud-not-silent.
    #[error("primer integrity check failed for {primer_id}@{primer_version}: expected sha256={expected} but loaded body hashes to {actual}")]
    PrimerIntegrity {
        primer_id: String,
        primer_version: String,
        expected: String,
        actual: String,
    },
    /// The loader failed (unknown primer, I/O error, parse error, ...).
    #[error("primer loader failed: {0}")]
    LoaderFailed(#[from] PrimerLoaderError),
    /// The contract's `primer` field is present but its
    /// `model_compatibility` table is silent on the cell's model.
    /// Loud-not-silent: rather than assume `Neutral` we error so the
    /// contract author has to declare a verdict.
    #[error("primer {primer_id}@{primer_version} has no model_compatibility entry for model {model}")]
    UndeclaredModelCompatibility {
        primer_id: String,
        primer_version: String,
        model: String,
    },
}

/// Decision recorded on the audit event. Wire-stable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InjectionDecision {
    Injected,
    RefusedModelCompatibility,
    NoPrimer,
}

/// The audit event the hook emits. Compatible with the `priming_active`
/// verifier kind: the verifier reads `decision`, `primer_id`, `primer_sha256`,
/// and `source_kind` to assert the primer was injected from a known source
/// with the expected hash.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrimerInjectionEvent {
    /// Wire-stable event kind. Always [`PrimerInjectionEvent::KIND`].
    /// Stored as `String` so the event round-trips through `serde_json`
    /// without `'static` lifetime constraints leaking into call sites.
    pub kind: String,
    pub primer_id: Option<String>,
    pub primer_version: Option<String>,
    pub primer_sha256: Option<String>,
    pub model: String,
    pub decision: InjectionDecision,
    pub source_kind: Option<SourceKind>,
    pub source_path: Option<PathBuf>,
    pub run_contract: String,
    pub run_contract_fingerprint: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    pub timestamp_utc: String,
    /// Optional human-readable refusal reason; populated only on `RefusedModelCompatibility`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refuse_reason: Option<String>,
}

impl PrimerInjectionEvent {
    pub const KIND: &'static str = "before_run_primer_injection";
}

// ---------------------------------------------------------------------------
// Trait + implementation
// ---------------------------------------------------------------------------

/// Trait implemented by BeforeRun hook handlers. Defined locally because
/// the canonical 13-hook trait surface (ADR-0006) is still emitting at the
/// `hooks_v2.rs` typed-function layer; once the trait-based surface lands,
/// this trait should converge with it.
pub trait BeforeRunHook {
    /// Run the hook. The handler may mutate `ctx.cell.system_prompt`.
    fn run(&self, ctx: &mut BeforeRunContext) -> Result<HookOutcome, HookError>;
}

/// The primer-injection hook. Stateless; cheap to construct per-run.
#[derive(Debug, Clone, Default)]
pub struct PrimerInjectionHook {
    loader: PrimerLoader,
    /// Last event emitted, available for in-process testing and for the
    /// audit-bridge integration when ADR-0005 lands. The substrate
    /// integration is expected to subscribe via a channel or trait
    /// (TODO(ADR-0005)) and not via this cached field.
    last_event: std::sync::Arc<std::sync::Mutex<Option<PrimerInjectionEvent>>>,
}

impl PrimerInjectionHook {
    /// Construct a hook. `engineering_doctrine_path` is the explicit
    /// override; if `None`, the env var + vendored fallback are still
    /// consulted by the loader.
    pub fn new(engineering_doctrine_path: Option<PathBuf>) -> Self {
        Self {
            loader: PrimerLoader::new(engineering_doctrine_path),
            last_event: std::sync::Arc::new(std::sync::Mutex::new(None)),
        }
    }

    /// Borrow the last emitted event (test helper / introspection hook).
    pub fn last_event(&self) -> Option<PrimerInjectionEvent> {
        self.last_event.lock().ok().and_then(|g| g.clone())
    }

    fn emit(&self, event: PrimerInjectionEvent) {
        // TODO(ADR-0005): forward to the canonical ledger via
        // `corcept_sink::SinkDispatcher`. The substrate carries enough
        // context to build a `SinkRecord` then; doing it here would
        // require the `BeforeRunContext` to carry the corcept project
        // root, which it does not at the moment.
        if let Ok(mut g) = self.last_event.lock() {
            *g = Some(event);
        }
    }
}

impl BeforeRunHook for PrimerInjectionHook {
    fn run(&self, ctx: &mut BeforeRunContext) -> Result<HookOutcome, HookError> {
        // 1. No primer declared -> no-op (still emit a `no_primer` event so
        //    the audit log proves the hook ran and chose to do nothing).
        let primer = match ctx.run_contract.primer.as_ref() {
            None => {
                let event = PrimerInjectionEvent {
                    kind: PrimerInjectionEvent::KIND.to_string(),
                    primer_id: None,
                    primer_version: None,
                    primer_sha256: None,
                    model: ctx.cell.model.clone(),
                    decision: InjectionDecision::NoPrimer,
                    source_kind: None,
                    source_path: None,
                    run_contract: ctx.run_contract.name.clone(),
                    run_contract_fingerprint: ctx.run_contract.fingerprint.clone(),
                    session_id: ctx.session_id.clone(),
                    timestamp_utc: Utc::now().to_rfc3339(),
                    refuse_reason: None,
                };
                self.emit(event);
                return Ok(HookOutcome::Continue);
            }
            Some(p) => p.clone(),
        };

        // 2. Load body.
        let resolved = self.loader.resolve(&primer.id, &primer.version)?;

        // 3. Model-compatibility check. The lookup is exact-match first,
        //    then strict prefix (longest-prefix wins). Loud-not-silent: if
        //    no entry matches we error.
        let compat = lookup_model_compat(&primer.model_compatibility, &ctx.cell.model).ok_or(
            HookError::UndeclaredModelCompatibility {
                primer_id: primer.id.clone(),
                primer_version: primer.version.clone(),
                model: ctx.cell.model.clone(),
            },
        )?;

        if compat == ModelCompatibility::InvertedAvoid {
            let reason = RefuseReason::ModelCompatibilityRefusal {
                model: ctx.cell.model.clone(),
                primer_id: primer.id.clone(),
                primer_version: primer.version.clone(),
                evidence:
                    "v3 ADR-0009: empirical evidence from value-sheet/18-cross-product-test/v2 \
                     shows Tools-Haiku at 31 with SKILLS access. Cells with `inverted_avoid` \
                     model-compatibility MUST NOT start with this primer."
                        .to_string(),
            };
            let event = PrimerInjectionEvent {
                kind: PrimerInjectionEvent::KIND.to_string(),
                primer_id: Some(primer.id.clone()),
                primer_version: Some(primer.version.clone()),
                primer_sha256: Some(resolved.sha256_hex.clone()),
                model: ctx.cell.model.clone(),
                decision: InjectionDecision::RefusedModelCompatibility,
                source_kind: Some(resolved.source_kind),
                source_path: resolved.source_path.clone(),
                run_contract: ctx.run_contract.name.clone(),
                run_contract_fingerprint: ctx.run_contract.fingerprint.clone(),
                session_id: ctx.session_id.clone(),
                timestamp_utc: Utc::now().to_rfc3339(),
                refuse_reason: Some(format!("{reason:?}")),
            };
            self.emit(event);
            return Ok(HookOutcome::AbortStart { reason });
        }

        // 4. Hash integrity. The contract author declares
        //    `expected_sha256`; we verify the loaded body matches BEFORE
        //    injection so a tampered or stale checkout never reaches the
        //    cell.
        let expected = primer.expected_sha256.trim().to_ascii_lowercase();
        let expected = expected
            .strip_prefix("sha256:")
            .unwrap_or(&expected)
            .to_string();
        let actual = compute_hex_sha256(&resolved.body);
        if expected != actual {
            return Err(HookError::PrimerIntegrity {
                primer_id: primer.id.clone(),
                primer_version: primer.version.clone(),
                expected,
                actual,
            });
        }

        // 5. Inject. Prepend the body + a single trailing newline to the
        //    system prompt. The cell sees the primer FIRST.
        let body_str = String::from_utf8(resolved.body.clone())
            .expect("primer body is UTF-8 by canonical contract");
        let mut new_prompt =
            String::with_capacity(body_str.len() + 1 + ctx.cell.system_prompt.len());
        new_prompt.push_str(&body_str);
        if !body_str.ends_with('\n') {
            new_prompt.push('\n');
        }
        new_prompt.push_str(&ctx.cell.system_prompt);
        ctx.cell.system_prompt = new_prompt;

        // 6. Audit event.
        let event = PrimerInjectionEvent {
            kind: PrimerInjectionEvent::KIND.to_string(),
            primer_id: Some(primer.id.clone()),
            primer_version: Some(primer.version.clone()),
            primer_sha256: Some(resolved.sha256_hex.clone()),
            model: ctx.cell.model.clone(),
            decision: InjectionDecision::Injected,
            source_kind: Some(resolved.source_kind),
            source_path: resolved.source_path.clone(),
            run_contract: ctx.run_contract.name.clone(),
            run_contract_fingerprint: ctx.run_contract.fingerprint.clone(),
            session_id: ctx.session_id.clone(),
            timestamp_utc: Utc::now().to_rfc3339(),
            refuse_reason: None,
        };
        self.emit(event);

        Ok(HookOutcome::Continue)
    }
}

/// Look up a model in a model_compatibility map. Returns the verdict for an
/// exact match first; falls back to the LONGEST prefix match. Returns
/// `None` if no entry matches.
fn lookup_model_compat(
    table: &std::collections::BTreeMap<String, ModelCompatibility>,
    model: &str,
) -> Option<ModelCompatibility> {
    if let Some(v) = table.get(model) {
        return Some(*v);
    }
    let mut best: Option<(usize, ModelCompatibility)> = None;
    for (key, verdict) in table {
        if model.starts_with(key) && best.map(|(len, _)| key.len() > len).unwrap_or(true) {
            best = Some((key.len(), *verdict));
        }
    }
    best.map(|(_, v)| v)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    const CANONICAL_HASH: &str =
        "c138dd966c82f7bd792684ab3fef0f50d75aa9342468db8b5d265f24f3fb35a8";
    const PRIMER_BYTES: usize = 1444;

    fn anti_confab_ref(model_compat: BTreeMap<String, ModelCompatibility>) -> PrimerRef {
        PrimerRef {
            id: "anti-confab-200tok".to_string(),
            version: "1.0.0".to_string(),
            source: PrimerSource::EngineeringDoctrine,
            expected_sha256: CANONICAL_HASH.to_string(),
            model_compatibility: model_compat,
        }
    }

    fn base_ctx(primer: Option<PrimerRef>, model: &str, system_prompt: &str) -> BeforeRunContext {
        BeforeRunContext {
            run_contract: RunContract {
                name: "pr-evidence-build".to_string(),
                fingerprint: "sha256:abc".to_string(),
                primer,
            },
            cell: CellState {
                model: model.to_string(),
                system_prompt: system_prompt.to_string(),
            },
            session_id: Some("s1".to_string()),
            bindings: BTreeMap::new(),
        }
    }

    /// Happy path: contract declares primer, model is Sonnet 4.6, primer
    /// is injected, system_prompt grows by exactly the 1444 bytes of the
    /// primer (the canonical body ends in '\n' so no extra newline is
    /// appended).
    #[test]
    fn happy_path_sonnet_injects_primer() {
        let mut compat = BTreeMap::new();
        compat.insert(
            "claude-sonnet-4-6".to_string(),
            ModelCompatibility::ConfirmedUplift,
        );
        let primer = anti_confab_ref(compat);
        let original_prompt = "You are a helpful assistant.\n";
        let mut ctx = base_ctx(Some(primer), "claude-sonnet-4-6", original_prompt);

        let hook = PrimerInjectionHook::new(None);
        let outcome = hook.run(&mut ctx).unwrap();
        assert_eq!(outcome, HookOutcome::Continue);
        assert_eq!(
            ctx.cell.system_prompt.len(),
            original_prompt.len() + PRIMER_BYTES
        );
        assert!(ctx.cell.system_prompt.ends_with(original_prompt));
        // The primer is at the front of the prompt.
        assert!(ctx
            .cell
            .system_prompt
            .starts_with("# Anti-confabulation priming\n"));

        // Audit event shape.
        let event = hook.last_event().expect("event emitted");
        assert_eq!(event.kind, PrimerInjectionEvent::KIND);
        assert_eq!(event.decision, InjectionDecision::Injected);
        assert_eq!(event.primer_id.as_deref(), Some("anti-confab-200tok"));
        assert_eq!(event.primer_version.as_deref(), Some("1.0.0"));
        assert_eq!(event.primer_sha256.as_deref(), Some(CANONICAL_HASH));
        assert_eq!(event.model, "claude-sonnet-4-6");
        assert_eq!(event.source_kind, Some(SourceKind::VendoredFallback));
        assert_eq!(event.run_contract, "pr-evidence-build");
    }

    /// Hash mismatch: contract declares hash X, loader returns body whose
    /// hash is Y, hook returns HookError::PrimerIntegrity.
    #[test]
    fn hash_mismatch_returns_integrity_error() {
        let mut compat = BTreeMap::new();
        compat.insert(
            "claude-sonnet-4-6".to_string(),
            ModelCompatibility::ConfirmedUplift,
        );
        let mut primer = anti_confab_ref(compat);
        primer.expected_sha256 = "0".repeat(64);
        let mut ctx = base_ctx(Some(primer), "claude-sonnet-4-6", "prompt");

        let hook = PrimerInjectionHook::new(None);
        let err = hook.run(&mut ctx).unwrap_err();
        match err {
            HookError::PrimerIntegrity {
                primer_id,
                expected,
                actual,
                ..
            } => {
                assert_eq!(primer_id, "anti-confab-200tok");
                assert_eq!(expected, "0".repeat(64));
                assert_eq!(actual, CANONICAL_HASH);
            }
            other => panic!("unexpected error: {other:?}"),
        }
        // No injection on failure.
        assert_eq!(ctx.cell.system_prompt, "prompt");
    }

    /// Haiku refusal: contract declares primer, model is `haiku-4-5`,
    /// model_compatibility is `inverted_avoid` - hook returns
    /// `AbortStart` with a typed reason.
    #[test]
    fn haiku_with_inverted_avoid_refuses_to_start() {
        let mut compat = BTreeMap::new();
        compat.insert(
            "claude-sonnet-4-6".to_string(),
            ModelCompatibility::ConfirmedUplift,
        );
        compat.insert("haiku-4-5".to_string(), ModelCompatibility::InvertedAvoid);
        let primer = anti_confab_ref(compat);
        let original_prompt = "haiku prompt";
        let mut ctx = base_ctx(Some(primer), "haiku-4-5", original_prompt);

        let hook = PrimerInjectionHook::new(None);
        let outcome = hook.run(&mut ctx).unwrap();
        match outcome {
            HookOutcome::AbortStart {
                reason:
                    RefuseReason::ModelCompatibilityRefusal {
                        model,
                        primer_id,
                        primer_version,
                        evidence,
                    },
            } => {
                assert_eq!(model, "haiku-4-5");
                assert_eq!(primer_id, "anti-confab-200tok");
                assert_eq!(primer_version, "1.0.0");
                assert!(evidence.contains("Tools-Haiku"));
                assert!(evidence.contains("31"));
            }
            other => panic!("expected refusal, got {other:?}"),
        }
        // No injection on refusal.
        assert_eq!(ctx.cell.system_prompt, original_prompt);

        let event = hook.last_event().expect("event emitted");
        assert_eq!(event.decision, InjectionDecision::RefusedModelCompatibility);
        assert_eq!(event.model, "haiku-4-5");
        assert!(event.refuse_reason.is_some());
    }

    /// No primer declared: contract has no primer field, hook is no-op,
    /// system_prompt unchanged, but an audit event is still emitted.
    #[test]
    fn no_primer_declared_is_noop() {
        let original_prompt = "untouched";
        let mut ctx = base_ctx(None, "claude-sonnet-4-6", original_prompt);

        let hook = PrimerInjectionHook::new(None);
        let outcome = hook.run(&mut ctx).unwrap();
        assert_eq!(outcome, HookOutcome::Continue);
        assert_eq!(ctx.cell.system_prompt, original_prompt);

        let event = hook.last_event().expect("event emitted");
        assert_eq!(event.decision, InjectionDecision::NoPrimer);
        assert_eq!(event.model, "claude-sonnet-4-6");
        assert!(event.primer_id.is_none());
        assert!(event.primer_sha256.is_none());
        assert!(event.source_kind.is_none());
    }

    /// Engineering-doctrine path missing or stale -> vendored fallback
    /// kicks in and the audit event records `source_kind: vendored_fallback`.
    #[test]
    fn vendored_fallback_when_live_path_missing() {
        let mut compat = BTreeMap::new();
        compat.insert(
            "claude-sonnet-4-6".to_string(),
            ModelCompatibility::ConfirmedUplift,
        );
        let primer = anti_confab_ref(compat);
        let mut ctx = base_ctx(Some(primer), "claude-sonnet-4-6", "x");

        // Point the loader at a path that exists but has no skills file.
        let dir = tempfile::tempdir().unwrap();
        let hook = PrimerInjectionHook::new(Some(dir.path().to_path_buf()));
        let outcome = hook.run(&mut ctx).unwrap();
        assert_eq!(outcome, HookOutcome::Continue);

        let event = hook.last_event().expect("event emitted");
        assert_eq!(event.decision, InjectionDecision::Injected);
        assert_eq!(event.source_kind, Some(SourceKind::VendoredFallback));
        assert!(event.source_path.is_none());
    }

    /// Cell model has no entry in the compat table -> loud error rather
    /// than implicit `Neutral`.
    #[test]
    fn missing_model_compat_entry_errors() {
        let mut compat = BTreeMap::new();
        compat.insert(
            "claude-sonnet-4-6".to_string(),
            ModelCompatibility::ConfirmedUplift,
        );
        let primer = anti_confab_ref(compat);
        let mut ctx = base_ctx(Some(primer), "some-future-model-x", "prompt");

        let hook = PrimerInjectionHook::new(None);
        let err = hook.run(&mut ctx).unwrap_err();
        assert!(matches!(
            err,
            HookError::UndeclaredModelCompatibility { .. }
        ));
    }

    /// Prefix match: contract declares `claude-sonnet-4-6`, cell runs
    /// `claude-sonnet-4-6-20251201` -> prefix lookup hits.
    #[test]
    fn model_compat_prefix_match() {
        let mut compat = BTreeMap::new();
        compat.insert(
            "claude-sonnet-4-6".to_string(),
            ModelCompatibility::ConfirmedUplift,
        );
        let primer = anti_confab_ref(compat);
        let mut ctx = base_ctx(Some(primer), "claude-sonnet-4-6-20251201", "x");

        let hook = PrimerInjectionHook::new(None);
        let outcome = hook.run(&mut ctx).unwrap();
        assert_eq!(outcome, HookOutcome::Continue);
        let event = hook.last_event().expect("event emitted");
        assert_eq!(event.decision, InjectionDecision::Injected);
    }

    /// Contract declares `sha256:<hex>` prefix on `expected_sha256` -
    /// loader strips it. (Belt-and-braces: schemas in flight have not
    /// settled whether the prefix is included.)
    #[test]
    fn expected_sha256_with_prefix_is_accepted() {
        let mut compat = BTreeMap::new();
        compat.insert(
            "claude-sonnet-4-6".to_string(),
            ModelCompatibility::ConfirmedUplift,
        );
        let mut primer = anti_confab_ref(compat);
        primer.expected_sha256 = format!("sha256:{CANONICAL_HASH}");
        let mut ctx = base_ctx(Some(primer), "claude-sonnet-4-6", "x");

        let hook = PrimerInjectionHook::new(None);
        assert_eq!(hook.run(&mut ctx).unwrap(), HookOutcome::Continue);
    }

    /// Audit event JSON round-trips and matches the shape the
    /// `priming_active` verifier consumes.
    #[test]
    fn audit_event_json_shape_is_priming_active_compatible() {
        let mut compat = BTreeMap::new();
        compat.insert(
            "claude-sonnet-4-6".to_string(),
            ModelCompatibility::ConfirmedUplift,
        );
        let primer = anti_confab_ref(compat);
        let mut ctx = base_ctx(Some(primer), "claude-sonnet-4-6", "x");
        let hook = PrimerInjectionHook::new(None);
        hook.run(&mut ctx).unwrap();
        let event = hook.last_event().expect("event emitted");
        let json = serde_json::to_value(&event).unwrap();
        // The verifier-pack schema row 11 requires these keys.
        assert_eq!(json["kind"], "before_run_primer_injection");
        assert_eq!(json["primer_id"], "anti-confab-200tok");
        assert_eq!(json["primer_version"], "1.0.0");
        assert_eq!(json["primer_sha256"], CANONICAL_HASH);
        assert_eq!(json["model"], "claude-sonnet-4-6");
        assert_eq!(json["decision"], "injected");
        assert_eq!(json["source_kind"], "vendored_fallback");
        assert!(json["timestamp_utc"].is_string());
        assert_eq!(json["run_contract"], "pr-evidence-build");
        // Round-trip back to a typed event.
        let _back: PrimerInjectionEvent = serde_json::from_value(json).unwrap();
    }
}
