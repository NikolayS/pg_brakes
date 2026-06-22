//! The guarded-apply engine (SPEC §4, §10.2, §10.3, §10.4, §1 honest recovery).
//!
//! This is the *reversible half of the moat*: once a [`Proposal`] has passed the
//! dry-run ([`crate::dry_run`]) and yielded a [`BlastRadius`], [`guarded_apply`]
//! applies it on the **primary** under a closed set of guards, and returns the
//! typed-inverse ([`pgb_core::InversePlan`]) the revert (#37) will use. Nothing
//! is committed unless every guard passes.
//!
//! # The guarded-apply contract (SPEC §4, in order)
//!
//! 1. **PITR fence** — `pg_create_restore_point(label)` when `pitr.enabled`. When
//!    PITR is *not* enabled we do **not** fabricate a fence; the typed-inverse is
//!    the documented undo (SPEC §1 honest-recovery: the typed-inverse is cheap +
//!    fast; PITR is a last-resort that requires the customer to run continuous WAL
//!    archiving + a tested restore). We never market both as cheap.
//! 2. **`BEGIN`** a single apply txn and `SET LOCAL statement_timeout` ≈ **3× the
//!    dry-run `duration_ms`** (so a slow apply aborts with **no partial commit**,
//!    SPEC §3 deterministic floor) — clamped to a sane floor so a sub-millisecond
//!    dry-run still leaves a usable budget.
//! 3. **[`ApplyBarrier::pause_point`]** between prepare and apply — production is a
//!    no-op; the drift tests inject through this seam (SPEC §10.4).
//! 4. **Apply with `RETURNING`** — capture both the **pre-image** (for the
//!    typed-inverse, §10.3 `{pk, before_image}`) and the **actual affected-PK
//!    set** the forward op wrote.
//! 5. **Apply-time PK-set re-check (0-tolerance destructive)** — recompute the
//!    affected-PK-set checksum *inside the apply txn* on the same predicate and
//!    compare to the dry-run/grant checksum. Any mismatch → **ABORT (ROLLBACK)**.
//!    The guard is the PK-set checksum, **not** the row count, so it catches
//!    row-identity drift (same count, different PKs).
//! 6. **`RETURNING` written-set check (gate carry-forward)** — verify the rows the
//!    forward op *actually wrote* (`RETURNING`) match the predicted set. This
//!    catches a **post-snapshot trigger that writes rows OUTSIDE the predicate** —
//!    a case a pre-op-only guard (step 5, which recomputes on the predicate
//!    *before* the forward op) cannot see. Mismatch → **ABORT**.
//! 7. **`COMMIT`** only if BOTH checks pass; else **`ROLLBACK`**.
//! 8. **Refused-op default-deny** — anything outside the closed certified action
//!    set ([`pgb_core::certify`]) is refused and **never applied**.
//!
//! # The seam
//!
//! Like [`crate::dry_run`] is DB-free and drives a [`crate::Rehearsal`], this
//! engine is DB-free and drives an [`ApplyConn`]: the engine owns the *ordering
//! and the guard decisions*; the connection owns the SQL. Production grows a
//! tokio-backed `ApplyConn`; the env-gated integration tests
//! (`apply_it.rs`, `PG_BUMPERS_IT=1`) implement it against real PostgreSQL 18, and
//! the unit tests here implement an in-memory one that can inject every drift +
//! the `statement_timeout` fire deterministically. The barrier seam
//! ([`ApplyBarrier`]) is crossed at the §10.4 point in both.

use pgb_core::inverse::{certify, InversePlanBuilder, Operation};
use pgb_core::{
    ApplyBarrier, BlastRadius, Clock, InverseKind, InversePlan, InverseRow, PkChecksum,
    PkSetBuilder, PkTuple, RefusedOp,
};

use crate::dry_run::WriteKind;

/// The default floor for the apply txn's `statement_timeout`, in milliseconds.
///
/// `statement_timeout` ≈ 3× the dry-run `duration_ms` (SPEC §4), but a fast
/// dry-run (a few ms, or even 0 on a tiny table) would otherwise produce a
/// timeout so small the apply could not finish even with no drift. We clamp the
/// budget up to this floor so the multiplier only ever *raises* the budget for a
/// genuinely slow apply; it never starves a legitimate fast one.
pub const MIN_STATEMENT_TIMEOUT_MS: u64 = 1_000;

/// The multiplier applied to the dry-run `duration_ms` to size the apply txn's
/// `statement_timeout` (SPEC §4 "`statement_timeout ≈ 3× dry-run`").
pub const STATEMENT_TIMEOUT_MULTIPLIER: u64 = 3;

/// Compute the apply txn's `statement_timeout` from the dry-run `duration_ms`:
/// `max(3 × duration_ms, MIN_STATEMENT_TIMEOUT_MS)` (SPEC §4).
///
/// Saturating so a pathological `duration_ms` cannot overflow the budget.
pub fn statement_timeout_ms(dry_run_duration_ms: u64) -> u64 {
    dry_run_duration_ms
        .saturating_mul(STATEMENT_TIMEOUT_MULTIPLIER)
        .max(MIN_STATEMENT_TIMEOUT_MS)
}

/// Why a guarded apply aborted or was refused. **Every variant means nothing was
/// committed** — the apply path is fail-closed, so on any of these the primary is
/// byte-for-byte unchanged (the txn was rolled back, or never opened).
#[derive(Debug, thiserror::Error)]
pub enum ApplyError {
    /// The proposal's operation is outside the closed certified action set
    /// (default-deny, §10.3) — **refused, never applied**. Carries the typed
    /// [`RefusedOp`] reason for the audit record.
    #[error("REFUSED: {0}")]
    Refused(#[from] RefusedOp),

    /// **Apply-time PK-set drift** (step 5): the affected-PK-set checksum
    /// recomputed inside the apply txn differs from the dry-run/grant checksum.
    /// 0-tolerance → ROLLBACK. This is the guard *firing* — the expected outcome
    /// of every drift test (insert / delete-shrink / predicate-flip /
    /// trigger-amplification).
    #[error("GUARD ABORT (apply-time PK-set drift on `{relation}`): dry_run={dry_run} apply_time={apply_time}")]
    PkSetDrift {
        /// The relation whose affected-PK set drifted.
        relation: String,
        /// The dry-run/grant checksum.
        dry_run: String,
        /// The checksum recomputed inside the apply txn (before the forward op).
        apply_time: String,
    },

    /// **`RETURNING` written-set mismatch** (step 6, the gate carry-forward): the
    /// rows the forward op actually wrote (its `RETURNING` PK set) differ from the
    /// predicted set. Catches a post-snapshot trigger writing rows OUTSIDE the
    /// predicate that the pre-op recompute (step 5) cannot see. → ROLLBACK.
    #[error("GUARD ABORT (RETURNING written-set mismatch on `{relation}`): predicted={predicted} written={written}")]
    WrittenSetMismatch {
        /// The relation whose written set diverged from the prediction.
        relation: String,
        /// The predicted (dry-run) affected-PK-set checksum.
        predicted: String,
        /// The checksum of the rows the forward op actually wrote (`RETURNING`).
        written: String,
    },

    /// The apply txn exceeded its `statement_timeout` (step 2) and was aborted by
    /// the server — **no partial commit**. Surfaced distinctly so the caller can
    /// tell a timeout abort from a drift abort.
    #[error("APPLY TIMEOUT: apply exceeded statement_timeout of {timeout_ms}ms — aborted, nothing committed")]
    Timeout {
        /// The `statement_timeout` budget that was exceeded.
        timeout_ms: u64,
    },

    /// The blast-radius record this apply was handed does not match the proposal
    /// (defensive cross-check) or is missing the target's checksum.
    #[error("INVALID GRANT: {0}")]
    InvalidGrant(String),

    /// The underlying connection failed (DB error etc.). Surfaced as a string so
    /// the engine stays DB-free; the txn is always rolled back before this is
    /// returned.
    #[error("apply backend failed: {0}")]
    Backend(String),
}

/// A pre-image row captured by the forward op's `RETURNING`: its typed PK tuple
/// plus the full ordered `(column, before_value)` pre-image (SPEC §10.3
/// `{pk, before_image}`).
///
/// The connection produces these from `RETURNING` (an `UPDATE` returns the *old*
/// values via `RETURNING <cols>` of the pre-update row image captured at snapshot
/// time; a `DELETE` returns the deleted row). The engine folds them into the
/// [`InversePlan`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapturedRow {
    /// The affected row's typed PK tuple.
    pub pk: PkTuple,
    /// The full ordered pre-image `(column_name, before_value)` pairs.
    pub before_image: Vec<(String, pgb_core::inverse::ImageValue)>,
}

/// What the forward op produced: the rows it actually wrote (from `RETURNING`),
/// each with its captured pre-image. Used to build both the §10.3 typed-inverse
/// and the §10.5(a) written-set checksum.
#[derive(Debug, Clone)]
pub struct ForwardResult {
    /// The rows the forward op actually wrote, in `RETURNING` order.
    pub written: Vec<CapturedRow>,
}

impl ForwardResult {
    /// The checksum of the **written** PK set (the rows the forward op actually
    /// touched, per `RETURNING`). Compared against the prediction in step 6.
    fn written_checksum(&self, relation: &str) -> Result<PkChecksum, ApplyError> {
        let mut b = PkSetBuilder::for_relation(relation);
        for row in &self.written {
            b.push(row.pk.clone())
                .map_err(|e| ApplyError::Backend(e.to_string()))?;
        }
        b.finalize().map_err(|e| ApplyError::Backend(e.to_string()))
    }
}

/// The connection seam the guarded-apply engine drives (the apply analogue of
/// [`crate::Rehearsal`]).
///
/// The engine owns the **ordering and the guard decisions**; the connection owns
/// the SQL. An implementation runs everything against **one** apply transaction:
/// [`begin`](ApplyConn::begin) opens it and sets `statement_timeout`, the
/// recompute / forward / commit / rollback methods run within it. The engine
/// guarantees it calls them in the §4 order and rolls back on any guard failure.
///
/// Production grows a tokio-backed impl; the env-gated integration tests
/// implement it against real PG18; the unit tests use an in-memory one.
pub trait ApplyConn {
    /// **Step 1 — PITR fence.** Create a named restore point
    /// (`pg_create_restore_point(label)`) and return its LSN. Only called when
    /// `pitr.enabled` (SPEC §4 / §1). MUST run **outside** the apply txn (a
    /// restore point is a WAL record that must be durable regardless of the
    /// apply's outcome).
    fn create_restore_point(&mut self, label: &str) -> Result<String, ApplyError>;

    /// **Step 2 — open the apply txn** and `SET LOCAL statement_timeout = timeout_ms`.
    /// All subsequent steps run inside this txn until [`commit`](ApplyConn::commit)
    /// or [`rollback`](ApplyConn::rollback).
    fn begin(&mut self, timeout_ms: u64) -> Result<(), ApplyError>;

    /// **Step 5 — recompute the affected-PK-set checksum** for `relation` on the
    /// same predicate, *inside the apply txn, before the forward op*. This is the
    /// 0-tolerance drift check's apply-time side.
    fn recompute_pk_checksum(&mut self, relation: &str) -> Result<PkChecksum, ApplyError>;

    /// **Step 4 — run the forward op with `RETURNING`**, capturing each written
    /// row's PK + full pre-image. Returns the rows the op actually wrote.
    ///
    /// If the server aborts the statement for exceeding `statement_timeout`, this
    /// MUST return [`ApplyError::Timeout`] (and leave the txn aborted; the engine
    /// rolls back).
    fn apply_forward(
        &mut self,
        kind: WriteKind,
        relation: &str,
    ) -> Result<ForwardResult, ApplyError>;

    /// **Step 7a — commit** the apply txn (only called when both guards pass).
    fn commit(&mut self) -> Result<(), ApplyError>;

    /// **Step 7b — roll back** the apply txn (called on any guard failure or
    /// timeout). MUST be idempotent / safe to call on an already-aborted txn.
    fn rollback(&mut self) -> Result<(), ApplyError>;
}

/// PITR configuration for the apply (SPEC §4 `pitr.enabled` / §1 honest recovery).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PitrConfig {
    /// Whether the customer runs continuous WAL archiving so a restore point is
    /// meaningful. When `false`, the apply does **not** fabricate a fence: the
    /// typed-inverse is the documented undo (SPEC §1).
    pub enabled: bool,
}

impl PitrConfig {
    /// PITR enabled (a restore-point fence is created before the apply txn).
    pub const fn enabled() -> Self {
        PitrConfig { enabled: true }
    }
    /// PITR disabled — the typed-inverse is the undo (SPEC §1 honest recovery).
    pub const fn disabled() -> Self {
        PitrConfig { enabled: false }
    }
}

/// The honest-recovery posture of a committed apply (SPEC §1).
///
/// Names *which* undo mechanism is available so the audit record and the caller
/// never conflate the cheap typed-inverse with the last-resort PITR fence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecoveryFence {
    /// PITR was enabled: a restore point was created before the apply. The
    /// **typed-inverse is still the default, cheap undo**; the restore point is
    /// the last-resort fence (SPEC §1).
    PitrRestorePoint {
        /// The restore point label.
        label: String,
        /// The LSN the restore point was created at.
        lsn: String,
    },
    /// PITR was not enabled: the **typed-inverse is the only undo** (SPEC §1).
    /// Documented explicitly so the caller cannot assume a PITR safety net exists.
    TypedInverseOnly,
}

/// A committed guarded apply (SPEC §4): the rows it actually wrote, the captured
/// **typed-inverse** for the revert (#37), and the honest-recovery posture.
#[derive(Debug, Clone)]
pub struct AppliedWrite {
    /// The proposal id this apply belongs to.
    pub proposal_id: String,
    /// How many rows the forward op actually wrote (per `RETURNING`).
    pub rows_written: u64,
    /// The apply-time affected-PK-set checksum (equal to the dry-run checksum —
    /// the guard passed) for audit.
    pub apply_checksum: PkChecksum,
    /// The captured **typed-inverse** (FK-ordered pre-image) for the revert.
    pub inverse: InversePlan,
    /// The recovery posture (typed-inverse only, or + PITR restore point).
    pub fence: RecoveryFence,
    /// The `statement_timeout` (ms) the apply txn ran under.
    pub statement_timeout_ms: u64,
}

/// The forward operation described to [`certify`] from the dry-run record. Maps
/// the [`WriteKind`] + the §10.1 facts (reversible, PK-bearing) onto the
/// certified-action vocabulary so the default-deny gate (§10.3) is the *single*
/// choke point.
fn operation_from_dry_run(kind: WriteKind, dry_run: &BlastRadius) -> Operation {
    // Reaching guarded_apply means the dry-run assembled a record (it refuses
    // PK-less + volatile up front), so `reversible` reflects a captured pre-image
    // + usable PK. We still route through `certify` so the closed allow-list is
    // re-affirmed at apply time (defense in depth / fail-closed).
    let has_preimage = dry_run.reversible;
    let has_pk = true; // a record with a `pk_set_checksum` had a usable PK.
    match kind {
        WriteKind::Update => Operation::Update {
            has_preimage,
            has_pk,
        },
        WriteKind::Delete => Operation::Delete {
            has_preimage,
            has_pk,
        },
    }
}

/// Apply a dry-run-validated proposal on the primary under the §4 guards.
///
/// `proposal_id` ties the apply to its proposal; `kind` + `relation` name the
/// certified write; `dry_run` is the §10.1 grant the apply re-checks against;
/// `pitr` decides the §1 fence; `conn` is the DB seam; `barrier` is the §10.4
/// drift-injection seam; `clock` stamps the restore-point label.
///
/// On success returns an [`AppliedWrite`] carrying the captured **typed-inverse**
/// (for the revert, #37). On any guard failure / refusal / timeout returns an
/// [`ApplyError`] and **nothing is committed** (the txn is rolled back, or never
/// opened for a refusal).
#[allow(clippy::too_many_arguments)]
pub fn guarded_apply(
    proposal_id: &str,
    kind: WriteKind,
    relation: &str,
    dry_run: &BlastRadius,
    pitr: PitrConfig,
    conn: &mut dyn ApplyConn,
    barrier: &dyn ApplyBarrier,
    clock: &dyn Clock,
) -> Result<AppliedWrite, ApplyError> {
    // (0) Cross-check the grant + extract the dry-run/grant checksum for `relation`.
    if dry_run.proposal_id != proposal_id {
        return Err(ApplyError::InvalidGrant(format!(
            "blast-radius proposal_id `{}` does not match proposal `{}`",
            dry_run.proposal_id, proposal_id
        )));
    }
    let grant_checksum = dry_run
        .affected
        .pk_set_checksum
        .get(relation)
        .cloned()
        .ok_or_else(|| {
            ApplyError::InvalidGrant(format!(
                "blast-radius has no pk_set_checksum for target `{relation}`"
            ))
        })?;

    // (8) Refused-op default-deny — BEFORE touching the DB. Anything outside the
    //     closed certified action set is refused and never applied (§10.3).
    let op = operation_from_dry_run(kind, dry_run);
    certify(&op)?; // Err(RefusedOp) → ApplyError::Refused, no txn opened.

    // (1) PITR fence — only when enabled; else the typed-inverse is the undo (§1).
    let fence = if pitr.enabled {
        let label = restore_point_label(proposal_id, clock);
        let lsn = conn.create_restore_point(&label)?;
        RecoveryFence::PitrRestorePoint { label, lsn }
    } else {
        RecoveryFence::TypedInverseOnly
    };

    // (2) BEGIN + SET LOCAL statement_timeout ≈ 3× dry-run duration.
    let timeout_ms = statement_timeout_ms(dry_run.duration_ms);
    conn.begin(timeout_ms)?;

    // From here on, every early return MUST roll back. We funnel the guarded body
    // through a helper so a single match handles rollback-on-error.
    let outcome = guarded_body(kind, relation, &grant_checksum, conn, barrier);

    match outcome {
        Ok(forward) => {
            // (7a) Both guards passed → COMMIT.
            conn.commit()?;
            let inverse = build_inverse(kind, relation, &forward);
            let apply_checksum = forward.written_checksum(relation)?;
            Ok(AppliedWrite {
                proposal_id: proposal_id.to_string(),
                rows_written: forward.written.len() as u64,
                apply_checksum,
                inverse,
                fence,
                statement_timeout_ms: timeout_ms,
            })
        }
        Err(e) => {
            // (7b) Any guard failure / timeout → ROLLBACK, nothing committed.
            // The rollback's own error must not mask the guard error.
            let _ = conn.rollback();
            Err(e)
        }
    }
}

/// Steps 3–6 inside the open apply txn. Returns the forward result on success;
/// any `Err` here means the caller must roll back.
fn guarded_body(
    kind: WriteKind,
    relation: &str,
    grant_checksum: &str,
    conn: &mut dyn ApplyConn,
    barrier: &dyn ApplyBarrier,
) -> Result<ForwardResult, ApplyError> {
    // (3) The §10.4 seam: cross the barrier between prepare and apply. Production
    //     is a no-op; the drift tests mutate world state here.
    barrier.pause_point("between dry_run and apply");

    // (5) Apply-time PK-set re-check (0-tolerance destructive). Recompute the
    //     affected-PK-set checksum on the predicate INSIDE the txn (before the
    //     forward op) and compare to the grant. The guard is the checksum, not the
    //     count — it catches a predicate-flip (same count, different PKs).
    let apply_time = conn.recompute_pk_checksum(relation)?;
    if apply_time.as_prefixed() != grant_checksum {
        return Err(ApplyError::PkSetDrift {
            relation: relation.to_string(),
            dry_run: grant_checksum.to_string(),
            apply_time: apply_time.as_prefixed(),
        });
    }

    // (4) Forward op with RETURNING — capture pre-image + actual written-PK set.
    //     A statement_timeout overrun surfaces as ApplyError::Timeout here.
    let forward = conn.apply_forward(kind, relation)?;

    // (6) RETURNING written-set check (gate carry-forward). The rows the forward
    //     op ACTUALLY wrote must match the prediction. This catches a
    //     post-snapshot trigger writing rows OUTSIDE the predicate — invisible to
    //     the pre-op recompute in step 5.
    let written = forward.written_checksum(relation)?;
    if written.as_prefixed() != grant_checksum {
        return Err(ApplyError::WrittenSetMismatch {
            relation: relation.to_string(),
            predicted: grant_checksum.to_string(),
            written: written.as_prefixed(),
        });
    }

    Ok(forward)
}

/// Build the typed-inverse (§10.3) from the captured pre-image rows. `UPDATE` →
/// [`InverseKind::PreimageUpsert`]; `DELETE` → [`InverseKind::Insert`]. FK order
/// for the single-relation case is just `[relation]`; the multi-relation
/// (cascade) ordering is layered by the revert (#37) which consumes per-relation
/// inverses.
fn build_inverse(kind: WriteKind, relation: &str, forward: &ForwardResult) -> InversePlan {
    let inverse_kind = match kind {
        WriteKind::Update => InverseKind::for_update(),
        WriteKind::Delete => InverseKind::for_delete(),
    };
    let mut b = InversePlanBuilder::new(relation, inverse_kind);
    for row in &forward.written {
        b = b.push_row(InverseRow::new(row.pk.clone(), row.before_image.clone()));
    }
    b.build()
}

/// A deterministic restore-point label for a proposal, stamped against the
/// injected clock (SPEC §10.4 — no wall-clock read in gating; the stamp is
/// human-facing only). Postgres restore-point names are truncated to 64 bytes, so
/// this stays well under that.
fn restore_point_label(proposal_id: &str, clock: &dyn Clock) -> String {
    format!("pgb_{}_{}", proposal_id, clock.now_unix_millis())
}

#[cfg(test)]
mod tests {
    use super::*;
    use pgb_core::{ClosureBarrier, MockClock, NoopBarrier, PkValue};
    use std::sync::{Arc, Mutex};

    // ---- test fixtures -----------------------------------------------------

    fn checksum_of(rel: &str, ids: &[i64]) -> PkChecksum {
        let mut b = PkSetBuilder::for_relation(rel);
        for &id in ids {
            b.push(PkTuple::single(PkValue::Int(id))).unwrap();
        }
        b.finalize().unwrap()
    }

    /// A blast-radius grant for `rel` over the integer PK set `ids`.
    fn grant_for(proposal_id: &str, rel: &str, ids: &[i64], duration_ms: u64) -> BlastRadius {
        use pgb_core::blast_radius::Affected;
        use pgb_core::LockMode;
        let mut pk_set_checksum = std::collections::BTreeMap::new();
        pk_set_checksum.insert(rel.to_string(), checksum_of(rel, ids).as_prefixed());
        let mut by_table = std::collections::BTreeMap::new();
        by_table.insert(rel.to_string(), ids.len() as u64);
        BlastRadius {
            proposal_id: proposal_id.to_string(),
            clone_lsn: "0/0".into(),
            staleness_lsn_bytes: 0,
            affected: Affected {
                by_table,
                cascade_by_table: std::collections::BTreeMap::new(),
                pk_set_checksum,
                total_rows: ids.len() as u64,
            },
            triggers_fired: vec![],
            locks: vec![],
            max_lock_mode: LockMode::RowExclusiveLock,
            duration_ms,
            wal_bytes: 0,
            constraint_violations: vec![],
            reversible: true,
            inverse_kind: InverseKind::PreimageUpsert,
            predicate_volatile: false,
        }
    }

    fn captured(ids: &[i64]) -> Vec<CapturedRow> {
        ids.iter()
            .map(|&id| CapturedRow {
                pk: PkTuple::single(PkValue::Int(id)),
                before_image: vec![("status".into(), PkValue::Text("open".into()))],
            })
            .collect()
    }

    /// A scripted in-memory `ApplyConn`. The script lets a test set: the PK set
    /// the apply-time recompute sees (drift), the rows the forward op writes
    /// (written-set drift / trigger-outside-predicate), and a forced timeout.
    #[derive(Default)]
    struct MockConnInner {
        /// PK set the apply-time recompute returns (defaults to `target`).
        recompute_ids: Vec<i64>,
        /// PK set the forward op writes via RETURNING (defaults to `target`).
        written_ids: Vec<i64>,
        /// If set, `apply_forward` returns Timeout.
        timeout_at_forward: Option<u64>,
        // observability
        restore_points: Vec<String>,
        began_with_timeout: Option<u64>,
        committed: bool,
        rolled_back: bool,
        forward_ran: bool,
    }

    #[derive(Clone)]
    struct MockConn(Arc<Mutex<MockConnInner>>);

    impl MockConn {
        fn new(_rel: &str, target: &[i64]) -> Self {
            MockConn(Arc::new(Mutex::new(MockConnInner {
                recompute_ids: target.to_vec(),
                written_ids: target.to_vec(),
                ..Default::default()
            })))
        }
        fn inner(&self) -> std::sync::MutexGuard<'_, MockConnInner> {
            self.0.lock().expect("mock conn mutex poisoned")
        }
    }

    impl ApplyConn for MockConn {
        fn create_restore_point(&mut self, label: &str) -> Result<String, ApplyError> {
            self.inner().restore_points.push(label.to_string());
            Ok("0/16B6358".to_string())
        }
        fn begin(&mut self, timeout_ms: u64) -> Result<(), ApplyError> {
            self.inner().began_with_timeout = Some(timeout_ms);
            Ok(())
        }
        fn recompute_pk_checksum(&mut self, relation: &str) -> Result<PkChecksum, ApplyError> {
            let ids = self.inner().recompute_ids.clone();
            Ok(checksum_of(relation, &ids))
        }
        fn apply_forward(
            &mut self,
            _kind: WriteKind,
            _relation: &str,
        ) -> Result<ForwardResult, ApplyError> {
            self.inner().forward_ran = true;
            if let Some(t) = self.inner().timeout_at_forward {
                return Err(ApplyError::Timeout { timeout_ms: t });
            }
            let ids = self.inner().written_ids.clone();
            Ok(ForwardResult {
                written: captured(&ids),
            })
        }
        fn commit(&mut self) -> Result<(), ApplyError> {
            self.inner().committed = true;
            Ok(())
        }
        fn rollback(&mut self) -> Result<(), ApplyError> {
            self.inner().rolled_back = true;
            Ok(())
        }
    }

    const REL: &str = "public.orders";

    // ---- statement_timeout sizing -----------------------------------------

    #[test]
    fn statement_timeout_is_three_x_dry_run_with_a_floor() {
        // 3× a slow dry-run dominates.
        assert_eq!(statement_timeout_ms(5_000), 15_000);
        // A fast dry-run is clamped up to the floor so the apply can finish.
        assert_eq!(statement_timeout_ms(10), MIN_STATEMENT_TIMEOUT_MS);
        assert_eq!(statement_timeout_ms(0), MIN_STATEMENT_TIMEOUT_MS);
        // No overflow on a pathological duration.
        assert_eq!(
            statement_timeout_ms(u64::MAX),
            u64::MAX.saturating_mul(3).max(MIN_STATEMENT_TIMEOUT_MS)
        );
    }

    // ---- happy path: commits + captures the typed-inverse ------------------

    #[test]
    fn no_drift_commits_and_captures_typed_inverse() {
        let mut conn = MockConn::new(REL, &[2, 4, 6, 8, 10]);
        let probe = conn.clone();
        let grant = grant_for("p-1", REL, &[2, 4, 6, 8, 10], 7);
        let applied = guarded_apply(
            "p-1",
            WriteKind::Update,
            REL,
            &grant,
            PitrConfig::disabled(),
            &mut conn,
            &NoopBarrier::new(),
            &MockClock::new(),
        )
        .expect("no-drift apply must commit");

        assert_eq!(applied.rows_written, 5);
        // Typed-inverse captured + matches the changed rows (PreimageUpsert).
        assert_eq!(applied.inverse.kind, InverseKind::PreimageUpsert);
        assert_eq!(applied.inverse.rows.len(), 5);
        assert_eq!(applied.inverse.relation, REL);
        // FK order for a single relation is just [relation].
        assert_eq!(applied.inverse.fk_order, vec![REL.to_string()]);
        // PITR disabled → the typed-inverse is the documented undo (§1).
        assert_eq!(applied.fence, RecoveryFence::TypedInverseOnly);
        // The txn committed (and was NOT rolled back).
        let p = probe.inner();
        assert!(p.committed, "no-drift apply must COMMIT");
        assert!(!p.rolled_back);
        assert!(p.restore_points.is_empty(), "no fence when PITR disabled");
        assert_eq!(p.began_with_timeout, Some(MIN_STATEMENT_TIMEOUT_MS));
    }

    #[test]
    fn pitr_enabled_creates_restore_point_fence_before_apply() {
        let mut conn = MockConn::new(REL, &[1, 2, 3]);
        let probe = conn.clone();
        let grant = grant_for("p-pitr", REL, &[1, 2, 3], 1_000);
        let applied = guarded_apply(
            "p-pitr",
            WriteKind::Delete,
            REL,
            &grant,
            PitrConfig::enabled(),
            &mut conn,
            &NoopBarrier::new(),
            &MockClock::starting_at(42),
        )
        .expect("apply commits");

        // DELETE → INSERT inverse.
        assert_eq!(applied.inverse.kind, InverseKind::Insert);
        match &applied.fence {
            RecoveryFence::PitrRestorePoint { label, lsn } => {
                assert!(label.starts_with("pgb_p-pitr_"));
                assert_eq!(lsn, "0/16B6358");
            }
            other => panic!("expected a PITR fence, got {other:?}"),
        }
        let p = probe.inner();
        assert_eq!(p.restore_points.len(), 1, "exactly one restore point");
        // 3× 1000ms dominates the floor.
        assert_eq!(p.began_with_timeout, Some(3_000));
        assert!(p.committed);
    }

    // ---- drift: apply-time PK-set re-check (0-tolerance) -------------------

    #[test]
    fn drift_insert_over_count_aborts() {
        // Apply-time recompute sees an extra matching row (101) → drift → ABORT.
        let mut conn = MockConn::new(REL, &[2, 4, 6, 8, 10]);
        let probe = conn.clone();
        // Inject the drift through the barrier (as production tests do).
        let conn_for_barrier = conn.clone();
        let barrier = ClosureBarrier::new(move |_| {
            conn_for_barrier.inner().recompute_ids = vec![2, 4, 6, 8, 10, 101];
        });
        let grant = grant_for("p-2", REL, &[2, 4, 6, 8, 10], 5);
        let err = guarded_apply(
            "p-2",
            WriteKind::Update,
            REL,
            &grant,
            PitrConfig::disabled(),
            &mut conn,
            &barrier,
            &MockClock::new(),
        )
        .unwrap_err();
        assert!(matches!(err, ApplyError::PkSetDrift { .. }), "{err:?}");
        let p = probe.inner();
        assert!(p.rolled_back, "drift must ROLLBACK");
        assert!(!p.committed);
        assert!(
            !p.forward_ran,
            "the forward op must NOT run after pre-op drift is caught"
        );
    }

    #[test]
    fn drift_delete_shrink_under_count_aborts() {
        let mut conn = MockConn::new(REL, &[2, 4, 6, 8, 10]);
        let probe = conn.clone();
        let conn_for_barrier = conn.clone();
        let barrier = ClosureBarrier::new(move |_| {
            // one matching row vanished post-snapshot.
            conn_for_barrier.inner().recompute_ids = vec![2, 4, 6, 8];
        });
        let grant = grant_for("p-3", REL, &[2, 4, 6, 8, 10], 5);
        let err = guarded_apply(
            "p-3",
            WriteKind::Update,
            REL,
            &grant,
            PitrConfig::disabled(),
            &mut conn,
            &barrier,
            &MockClock::new(),
        )
        .unwrap_err();
        assert!(matches!(err, ApplyError::PkSetDrift { .. }), "{err:?}");
        assert!(probe.inner().rolled_back);
    }

    #[test]
    fn drift_predicate_flip_same_count_different_pks_aborts() {
        // HEADLINE: same cardinality, different PKs. A row-count guard PASSES
        // here; only the PK-set checksum catches it.
        let mut conn = MockConn::new(REL, &[2, 4, 6, 8, 10]);
        let probe = conn.clone();
        let conn_for_barrier = conn.clone();
        let barrier = ClosureBarrier::new(move |_| {
            // 10 flipped OUT, 1 flipped IN — count is still 5.
            conn_for_barrier.inner().recompute_ids = vec![1, 2, 4, 6, 8];
        });
        let grant = grant_for("p-4", REL, &[2, 4, 6, 8, 10], 5);
        let err = guarded_apply(
            "p-4",
            WriteKind::Update,
            REL,
            &grant,
            PitrConfig::disabled(),
            &mut conn,
            &barrier,
            &MockClock::new(),
        )
        .unwrap_err();
        match err {
            ApplyError::PkSetDrift {
                dry_run,
                apply_time,
                ..
            } => assert_ne!(dry_run, apply_time),
            other => panic!("expected PkSetDrift, got {other:?}"),
        }
        assert!(probe.inner().rolled_back);
    }

    // ---- RETURNING written-set check (the carry-forward) -------------------

    #[test]
    fn returning_written_set_mismatch_aborts() {
        // The pre-op recompute MATCHES the grant (so step 5 passes), but the
        // forward op WRITES a different set — e.g. a post-snapshot trigger wrote
        // a row OUTSIDE the predicate. Step 6 catches it.
        let mut conn = MockConn::new(REL, &[2, 4, 6, 8, 10]);
        // recompute matches grant; written set has an extra (out-of-predicate) row.
        conn.inner().written_ids = vec![2, 4, 6, 8, 10, 999];
        let probe = conn.clone();
        let grant = grant_for("p-5", REL, &[2, 4, 6, 8, 10], 5);
        let err = guarded_apply(
            "p-5",
            WriteKind::Update,
            REL,
            &grant,
            PitrConfig::disabled(),
            &mut conn,
            &NoopBarrier::new(),
            &MockClock::new(),
        )
        .unwrap_err();
        assert!(
            matches!(err, ApplyError::WrittenSetMismatch { .. }),
            "{err:?}"
        );
        let p = probe.inner();
        assert!(
            p.forward_ran,
            "the forward op ran (then we caught the drift)"
        );
        assert!(p.rolled_back, "written-set mismatch must ROLLBACK");
        assert!(!p.committed);
    }

    // ---- statement_timeout fires → no partial commit -----------------------

    #[test]
    fn statement_timeout_aborts_with_no_partial_commit() {
        let mut conn = MockConn::new(REL, &[2, 4, 6, 8, 10]);
        conn.inner().timeout_at_forward = Some(15);
        let probe = conn.clone();
        let grant = grant_for("p-6", REL, &[2, 4, 6, 8, 10], 5);
        let err = guarded_apply(
            "p-6",
            WriteKind::Update,
            REL,
            &grant,
            PitrConfig::disabled(),
            &mut conn,
            &NoopBarrier::new(),
            &MockClock::new(),
        )
        .unwrap_err();
        assert!(matches!(err, ApplyError::Timeout { .. }), "{err:?}");
        let p = probe.inner();
        assert!(p.rolled_back, "a timeout must ROLLBACK (no partial commit)");
        assert!(!p.committed);
    }

    // ---- refused-op default-deny → never applied ---------------------------

    #[test]
    fn refused_op_is_never_applied() {
        // A non-reversible UPDATE (no captured pre-image) is outside the certified
        // set → REFUSED, and the connection is NEVER touched (no begin/forward).
        let mut conn = MockConn::new(REL, &[1]);
        let probe = conn.clone();
        let mut grant = grant_for("p-7", REL, &[1], 5);
        grant.reversible = false; // models "no pre-image captured"
        let err = guarded_apply(
            "p-7",
            WriteKind::Update,
            REL,
            &grant,
            PitrConfig::disabled(),
            &mut conn,
            &NoopBarrier::new(),
            &MockClock::new(),
        )
        .unwrap_err();
        assert!(matches!(err, ApplyError::Refused(_)), "{err:?}");
        let p = probe.inner();
        assert!(
            p.began_with_timeout.is_none(),
            "a refused op must not even open the apply txn"
        );
        assert!(!p.forward_ran && !p.committed && !p.rolled_back);
    }

    #[test]
    fn grant_mismatch_is_rejected_before_any_db_work() {
        let mut conn = MockConn::new(REL, &[1]);
        let probe = conn.clone();
        let grant = grant_for("p-OTHER", REL, &[1], 5);
        let err = guarded_apply(
            "p-8", // does not match grant.proposal_id
            WriteKind::Update,
            REL,
            &grant,
            PitrConfig::disabled(),
            &mut conn,
            &NoopBarrier::new(),
            &MockClock::new(),
        )
        .unwrap_err();
        assert!(matches!(err, ApplyError::InvalidGrant(_)), "{err:?}");
        assert!(probe.inner().began_with_timeout.is_none());
    }

    #[test]
    fn barrier_is_crossed_exactly_once_on_the_apply_path() {
        let mut conn = MockConn::new(REL, &[1, 2, 3]);
        let crossings = Arc::new(Mutex::new(0u32));
        let c2 = Arc::clone(&crossings);
        let barrier = ClosureBarrier::new(move |_| *c2.lock().unwrap() += 1);
        let grant = grant_for("p-9", REL, &[1, 2, 3], 5);
        guarded_apply(
            "p-9",
            WriteKind::Update,
            REL,
            &grant,
            PitrConfig::disabled(),
            &mut conn,
            &barrier,
            &MockClock::new(),
        )
        .unwrap();
        assert_eq!(
            *crossings.lock().unwrap(),
            1,
            "barrier crossed exactly once"
        );
    }
}
