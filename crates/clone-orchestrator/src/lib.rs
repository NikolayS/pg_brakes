//! Clone-orchestrator for pg_bumpers — the **dry-run blast-radius engine**
//! (SPEC §4, §10.1, §12).
//!
//! Rehearses a proposed write (on a DBLab clone if present, else in a
//! rolled-back txn — the baseline `clone.provider: none`, §12), measures the
//! blast radius into the §10.1 [`pgb_core::BlastRadius`] record, and guards apply
//! with a PK-set checksum so row-identity drift is caught even when the row
//! *count* is unchanged (SPEC §4, §10.2).
//!
//! # The flow
//!
//! 1. [`propose`] a candidate statement → a [`Proposal`] (stable id + TTL,
//!    measured against the injected [`pgb_core::Clock`], §10.4).
//! 2. [`dry_run`] the proposal against a [`Rehearsal`] backend: it refuses
//!    volatile/non-deterministic predicates and PK-less targets **before
//!    executing**, otherwise runs the statement in a `BEGIN … ROLLBACK` txn,
//!    measures (affected-PK set + cascades + triggers + locks + WAL + duration +
//!    LSN/staleness), and folds the facts into a [`pgb_core::BlastRadius`] — then
//!    rolls back so **nothing is persisted**.
//!
//! # Refusals (fail-closed)
//!
//! - Volatile predicate → REFUSED, never executed (SPEC §4) — the WHERE clause is
//!   AST-walked; non-deterministic special keywords (`now()`/`CURRENT_TIMESTAMP`
//!   /…) are refused by name and every other function is resolved against
//!   `pg_proc.provolatile` (volatile/unknown ⇒ refuse, fail-closed). See
//!   [`predicate`].
//! - No primary key → REFUSED, **no `ctid` fallback** (SPEC §10.2; identity is
//!   keyed on the PK only today — `REPLICA IDENTITY` is orthogonal — see
//!   [`dry_run::DryRunError::PkLess`]).
//! - Non-certified shape (DDL/`TRUNCATE`/`INSERT`/…) → REFUSED (default-deny,
//!   §10.3).
//!
//! # Guarded apply (S3, [`apply`])
//!
//! [`guarded_apply`] is the **reversible half of the moat**: once a proposal has
//! passed the dry-run, it applies the write on the primary under the §4 guards —
//! PITR fence (when enabled; else the typed-inverse is the undo, §1) → `BEGIN` +
//! `statement_timeout ≈ 3× dry-run` → [`pgb_core::ApplyBarrier`] seam → apply with
//! `RETURNING` (capturing the pre-image + the actual written-PK set) →
//! **apply-time PK-set re-check** (0-tolerance drift abort) → **`RETURNING`
//! written-set check** (catches a post-snapshot trigger writing outside the
//! predicate) → `COMMIT`, returning the captured **typed-inverse** for the revert
//! (#37). Anything outside the closed certified action set is refused and never
//! applied. [`guard_decision`] below is the low-level drift-decision primitive the
//! engine's PK-set check builds on.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod apply;
pub mod dry_run;
pub mod predicate;
pub mod proposal;
pub mod provider;

pub use apply::{
    guarded_apply, statement_timeout_ms, AppliedWrite, ApplyConn, ApplyError, CapturedRow,
    ForwardResult, PitrConfig, RecoveryFence, MIN_STATEMENT_TIMEOUT_MS,
    STATEMENT_TIMEOUT_MULTIPLIER,
};
pub use dry_run::{
    classify, dry_run, AffectedTable, DryRunError, Measurement, Rehearsal, WriteKind,
};
pub use predicate::{
    predicate_volatile_reason, FunctionVolatility, NoFunctionVolatility, VolatileReason,
    Volatility, NONDETERMINISTIC_KEYWORDS,
};
pub use proposal::{propose, propose_with_ttl, Proposal, DEFAULT_TTL_MILLIS};
pub use provider::{
    check_parity, reap_orphans, reap_orphans_with_sweep, with_clone, write_owner_marker,
    CloneError, CloneGovernance, CloneHandle, CloneLedger, CloneProvider, ColumnGrant,
    DataClassification, DblabProvider, LedgerEntry, LocalCloneConfig, LocalCloneProvider,
    NoneProvider, OrphanAlarm, OwnerIdentity, ParityReport, PrimaryRef, ProviderKind, ReapOutcome,
    RlsPolicy, OWNER_MARKER,
};

/// The outcome of comparing the dry-run affected-PK set against the apply-time set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DriftDecision {
    /// PK sets match — safe to proceed to commit.
    Proceed,
    /// PK sets diverged — abort before commit (fail-closed).
    Abort,
}

/// Decide whether a guarded apply may proceed given the dry-run and apply-time
/// affected-PK-set checksums.
///
/// Guard is the PK-set checksum, *not* cardinality: identical counts with
/// different rows still drift and must abort.
pub fn guard_decision(dry_run_checksum: u64, apply_checksum: u64) -> DriftDecision {
    if dry_run_checksum == apply_checksum {
        DriftDecision::Proceed
    } else {
        DriftDecision::Abort
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matching_pk_set_proceeds() {
        assert_eq!(guard_decision(0xABCD, 0xABCD), DriftDecision::Proceed);
    }

    #[test]
    fn predicate_flip_same_count_different_rows_aborts() {
        // The count-only blind spot: different checksum => abort even if the
        // cardinality were equal upstream.
        assert_eq!(guard_decision(0xABCD, 0x1234), DriftDecision::Abort);
    }
}
