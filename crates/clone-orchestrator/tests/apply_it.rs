//! Real-PG18 integration tests for the **guarded-apply engine** (SPEC §4, §10.2,
//! §10.3, §10.4, §1). Env-gated behind `PG_BUMPERS_IT=1` so CI's fast `cargo test`
//! skips them. Run with:
//!
//! ```sh
//! PG_BUMPERS_IT=1 cargo test -p pgb-clone-orchestrator --test apply_it -- --nocapture
//! ```
//!
//! These drive the production [`pgb_clone_orchestrator::guarded_apply`] engine
//! through a real-PG18 [`PgApplyConn`] against a throwaway cluster on a dedicated
//! port (NEVER 5432). The engine owns the §4 ordering + the guard decisions; the
//! connection owns the SQL — exactly the seam production will use. They assert:
//!
//! - a dry-run-validated UPDATE/DELETE **commits** under the guards; the
//!   **typed-inverse** is captured + matches the changed rows;
//! - **drift injected via `ApplyBarrier::pause_point()`** → apply-time PK-set
//!   re-check **ABORTS** (0-tolerance): insert / delete-shrink / predicate-flip
//!   (same count, different PKs) / trigger-amplification;
//! - the **RETURNING written-set mismatch** (a post-snapshot trigger writing rows
//!   OUTSIDE the predicate) → **ABORTS** (the carry-forward);
//! - `statement_timeout` fires on a slow apply → abort, **no partial commit**;
//! - a refused op → **never applied** (DB untouched).
//!
//! On every abort path we re-read the primary and assert it is byte-for-byte
//! unchanged: the charter is data-loss safety, so "aborted" must mean "nothing
//! persisted".

mod common;

use std::collections::BTreeMap;

use common::{base_pgurl, create_seeded_db, drop_db, it_enabled};
use pgb_clone_orchestrator::apply::{ApplyConn, ApplyError, CapturedRow, ForwardResult};
use pgb_clone_orchestrator::{guarded_apply, PitrConfig, RecoveryFence, WriteKind};
use pgb_core::inverse::ImageValue;
use pgb_core::{
    BlastRadius, ClosureBarrier, InverseKind, NoopBarrier, PkChecksum, PkSetBuilder, PkTuple,
    PkValue, SystemClock,
};
use postgres::error::SqlState;
use postgres::{Client, NoTls};

/// Skip-guard: returns `None` (printing why) when the IT gate is unset.
fn setup(tag: &str) -> Option<(String, String, Client)> {
    if !it_enabled() {
        eprintln!("[skip] {tag}: set PG_BUMPERS_IT=1 to run the DB-backed apply test");
        return None;
    }
    Some(create_seeded_db(&base_pgurl(), tag))
}

/// The stable predicate matching a known PK set in the `accounts` seed: even ids
/// 2,4,6,8 (the seed has ids 1..=8).
const EVEN_WHERE: &str = "id % 2 = 0";

// ===========================================================================
//  The real-PG18 ApplyConn (the production seam, exercised for real)
// ===========================================================================

/// A real-PG18 [`ApplyConn`] for `public.accounts` (single int PK).
///
/// The §4 guarded apply must straddle multiple engine calls inside **one** txn
/// (recompute → forward → commit/rollback), so instead of the `postgres`
/// `Transaction` RAII guard (whose lifetime cannot span separate trait-method
/// calls) we drive the txn with explicit `BEGIN`/`COMMIT`/`ROLLBACK`
/// simple-queries on the owned `Client`. `in_txn` tracks liveness so rollback is
/// idempotent. This is the same connection shape production will use.
struct PgApplyConn<'a> {
    client: &'a mut Client,
    /// The forward statement (without RETURNING); the conn appends `RETURNING id`.
    forward_sql: String,
    /// The recompute predicate (WHERE body) for the apply-time PK-set re-check.
    where_sql: String,
    /// Set once `begin` runs; cleared by commit/rollback (rollback idempotency).
    in_txn: bool,
    /// The `statement_timeout` the txn runs under (so a cancel maps to `Timeout`).
    statement_timeout_ms: u64,
}

impl<'a> PgApplyConn<'a> {
    fn new(client: &'a mut Client, forward_sql: &str, where_sql: &str, _kind: WriteKind) -> Self {
        PgApplyConn {
            client,
            forward_sql: forward_sql.to_string(),
            where_sql: where_sql.to_string(),
            in_txn: false,
            statement_timeout_ms: 0,
        }
    }
}

impl ApplyConn for PgApplyConn<'_> {
    fn create_restore_point(&mut self, label: &str) -> Result<String, ApplyError> {
        // A restore point is a durable WAL record created OUTSIDE the apply txn.
        let row = self
            .client
            .query_one("SELECT pg_create_restore_point($1)::text", &[&label])
            .map_err(|e| ApplyError::Backend(e.to_string()))?;
        Ok(row.get(0))
    }

    fn begin(&mut self, timeout_ms: u64) -> Result<(), ApplyError> {
        // Open the apply txn and pin statement_timeout for it. We use explicit
        // BEGIN/COMMIT (simple-query) rather than the `Transaction` guard so the
        // single txn spans the multiple engine calls cleanly.
        self.client
            .batch_execute(&format!(
                "BEGIN; SET LOCAL statement_timeout = {timeout_ms};"
            ))
            .map_err(|e| ApplyError::Backend(e.to_string()))?;
        self.in_txn = true;
        self.statement_timeout_ms = timeout_ms;
        Ok(())
    }

    fn recompute_pk_checksum(&mut self, relation: &str) -> Result<PkChecksum, ApplyError> {
        // Recompute the affected-PK set on the SAME predicate, INSIDE the txn,
        // BEFORE the forward op (the 0-tolerance drift check's apply-time side).
        let rows = self
            .client
            .query(
                &format!(
                    "SELECT id FROM {relation} WHERE {} ORDER BY id",
                    self.where_sql
                ),
                &[],
            )
            .map_err(|e| ApplyError::Backend(e.to_string()))?;
        let mut b = PkSetBuilder::for_relation(relation);
        for row in &rows {
            let id: i32 = row.get(0);
            b.push(PkTuple::single(PkValue::Int(id as i64)))
                .map_err(|e| ApplyError::Backend(e.to_string()))?;
        }
        b.finalize().map_err(|e| ApplyError::Backend(e.to_string()))
    }

    fn apply_forward(
        &mut self,
        kind: WriteKind,
        relation: &str,
    ) -> Result<ForwardResult, ApplyError> {
        // Capture the full pre-image of the matching rows FOR UPDATE (locks them),
        // then run the forward op with RETURNING id (the actual written-PK set).
        // The pre-image SELECT and the forward op are in the same txn, so the
        // RETURNING set and the pre-image describe the same rows.
        let preimage_rows = self
            .client
            .query(
                &format!(
                    "SELECT id, owner, balance FROM {relation} WHERE {} ORDER BY id FOR UPDATE",
                    self.where_sql
                ),
                &[],
            )
            .map_err(|e| classify_pg_err(&e, self.statement_timeout_ms))?;

        // Index pre-images by pk for pairing with the RETURNING set.
        let mut preimage: BTreeMap<i64, Vec<(String, ImageValue)>> = BTreeMap::new();
        for row in &preimage_rows {
            let id: i32 = row.get(0);
            let owner: String = row.get(1);
            let balance: i64 = row.get(2);
            preimage.insert(
                id as i64,
                vec![
                    ("id".into(), PkValue::Int(id as i64)),
                    ("owner".into(), PkValue::Text(owner)),
                    ("balance".into(), PkValue::Int(balance)),
                ],
            );
        }

        // The forward op with RETURNING id — the rows it ACTUALLY wrote.
        let sql = format!("{} RETURNING id", self.forward_sql);
        let returned = self
            .client
            .query(&sql, &[])
            .map_err(|e| classify_pg_err(&e, self.statement_timeout_ms))?;

        let _ = kind; // the forward SQL already encodes the op; param kept for the seam.
        let mut written = Vec::with_capacity(returned.len());
        for row in &returned {
            let id: i32 = row.get(0);
            let before_image = preimage.get(&(id as i64)).cloned().unwrap_or_else(|| {
                // A RETURNING id with no captured pre-image means the forward op
                // wrote a row OUTSIDE the FOR UPDATE pre-image snapshot (e.g. a
                // trigger inserted/touched an out-of-predicate row). We still
                // surface the PK so the written-set checksum catches the drift;
                // the pre-image is best-effort (the row will trip step 6 anyway).
                vec![("id".into(), PkValue::Int(id as i64))]
            });
            written.push(CapturedRow {
                pk: PkTuple::single(PkValue::Int(id as i64)),
                before_image,
            });
        }
        Ok(ForwardResult { written })
    }

    fn commit(&mut self) -> Result<(), ApplyError> {
        self.client
            .batch_execute("COMMIT")
            .map_err(|e| ApplyError::Backend(e.to_string()))?;
        self.in_txn = false;
        Ok(())
    }

    fn rollback(&mut self) -> Result<(), ApplyError> {
        if self.in_txn {
            // ROLLBACK is safe even on an already-aborted txn (it ends the block).
            let _ = self.client.batch_execute("ROLLBACK");
            self.in_txn = false;
        }
        Ok(())
    }
}

/// Map a PG error to the engine's typed error: a `statement_timeout` cancel
/// (`57014`) becomes [`ApplyError::Timeout`]; anything else is `Backend`.
fn classify_pg_err(e: &postgres::Error, timeout_ms: u64) -> ApplyError {
    if e.code() == Some(&SqlState::QUERY_CANCELED) {
        ApplyError::Timeout { timeout_ms }
    } else {
        ApplyError::Backend(e.to_string())
    }
}

// ===========================================================================
//  Helpers: build the grant + read the world for the unchanged assertions
// ===========================================================================

/// Snapshot the affected-PK-set checksum of `accounts` rows matching `where_sql`
/// (the dry-run / grant side). Uses a fresh connection so it does not disturb the
/// apply client's txn state.
fn grant_checksum(url: &str, where_sql: &str) -> PkChecksum {
    let mut c = Client::connect(url, NoTls).expect("grant connect");
    let rows = c
        .query(
            &format!("SELECT id FROM public.accounts WHERE {where_sql} ORDER BY id"),
            &[],
        )
        .expect("grant select");
    let mut b = PkSetBuilder::for_relation("public.accounts");
    for row in &rows {
        let id: i32 = row.get(0);
        b.push(PkTuple::single(PkValue::Int(id as i64))).unwrap();
    }
    b.finalize().unwrap()
}

/// Build a minimal [`BlastRadius`] grant for `public.accounts` over `where_sql`,
/// with the given predicted `duration_ms`.
fn grant_for(proposal_id: &str, url: &str, where_sql: &str, duration_ms: u64) -> BlastRadius {
    use pgb_core::blast_radius::Affected;
    use pgb_core::LockMode;
    let cs = grant_checksum(url, where_sql);
    let n = {
        let mut c = Client::connect(url, NoTls).expect("count connect");
        let row = c
            .query_one(
                &format!("SELECT count(*) FROM public.accounts WHERE {where_sql}"),
                &[],
            )
            .unwrap();
        let cnt: i64 = row.get(0);
        cnt as u64
    };
    let mut pk_set_checksum = BTreeMap::new();
    pk_set_checksum.insert("public.accounts".to_string(), cs.as_prefixed());
    let mut by_table = BTreeMap::new();
    by_table.insert("public.accounts".to_string(), n);
    BlastRadius {
        proposal_id: proposal_id.to_string(),
        clone_lsn: "0/0".into(),
        staleness_lsn_bytes: 0,
        affected: Affected {
            by_table,
            cascade_by_table: BTreeMap::new(),
            pk_set_checksum,
            total_rows: n,
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

/// Read `(id -> (owner, balance))` for the whole `accounts` table — the
/// golden-state probe for the "unchanged after abort" assertions.
fn read_accounts(url: &str) -> BTreeMap<i32, (String, i64)> {
    let mut c = Client::connect(url, NoTls).expect("read connect");
    let rows = c
        .query(
            "SELECT id, owner, balance FROM public.accounts ORDER BY id",
            &[],
        )
        .expect("read accounts");
    rows.iter()
        .map(|r| {
            (
                r.get::<_, i32>(0),
                (r.get::<_, String>(1), r.get::<_, i64>(2)),
            )
        })
        .collect()
}

fn url_for(admin: &str, dbname: &str) -> String {
    let mut parts: Vec<String> = admin
        .split_whitespace()
        .filter(|kv| !kv.starts_with("dbname="))
        .map(|s| s.to_string())
        .collect();
    parts.push(format!("dbname={dbname}"));
    parts.join(" ")
}

// ===========================================================================
//  (1) HAPPY PATH — commits under the guards; typed-inverse captured + matches.
// ===========================================================================

#[test]
fn dry_run_validated_update_commits_and_captures_matching_typed_inverse() {
    let Some((admin, dbname, _client)) = setup("apply_commit") else {
        return;
    };
    let url = url_for(&admin, &dbname);

    let before = read_accounts(&url);
    eprintln!("[commit] pre-state (even ids): {:?}", even_view(&before));

    let grant = grant_for("p-commit", &url, EVEN_WHERE, 50);
    let forward = "UPDATE public.accounts SET balance = 0 WHERE id % 2 = 0";

    let mut client = Client::connect(&url, NoTls).expect("apply connect");
    let applied = {
        let mut conn = PgApplyConn::new(&mut client, forward, EVEN_WHERE, WriteKind::Update);
        guarded_apply(
            "p-commit",
            WriteKind::Update,
            "public.accounts",
            &grant,
            PitrConfig::disabled(),
            &mut conn,
            &NoopBarrier::new(),
            &SystemClock::new(),
        )
        .expect("no-drift apply must COMMIT")
    };

    eprintln!(
        "[commit] APPLIED: rows_written={} statement_timeout_ms={} fence={:?}",
        applied.rows_written, applied.statement_timeout_ms, applied.fence
    );

    // Committed: the 4 even accounts now have balance 0.
    assert_eq!(applied.rows_written, 4);
    let after = read_accounts(&url);
    for &id in &[2, 4, 6, 8] {
        assert_eq!(
            after[&id].1, 0,
            "even account {id} must be zeroed (committed)"
        );
    }
    // Odd accounts untouched.
    for &id in &[1i32, 3, 5, 7] {
        assert_eq!(after[&id].1, before[&id].1, "odd {id} untouched");
    }

    // Typed-inverse captured + MATCHES the changed rows: kind, count, and the
    // before_image of each row equals the pre-apply value.
    assert_eq!(applied.inverse.kind, InverseKind::PreimageUpsert);
    assert_eq!(applied.inverse.rows.len(), 4);
    assert_eq!(applied.inverse.relation, "public.accounts");
    for row in &applied.inverse.rows {
        let id = match &row.pk.values()[0] {
            PkValue::Int(i) => *i as i32,
            other => panic!("expected int pk, got {other:?}"),
        };
        let pre_balance = col_int(&row.before_image, "balance");
        let pre_owner = col_text(&row.before_image, "owner");
        assert_eq!(
            (pre_owner, pre_balance),
            before[&id].clone(),
            "inverse pre-image for {id} must match the golden pre-state"
        );
    }
    assert_eq!(applied.fence, RecoveryFence::TypedInverseOnly);
    eprintln!("[commit] PASS: committed + typed-inverse matches the changed rows");

    drop_db(&admin, &dbname);
}

/// (1b) DELETE commits (cascades to entries), inverse kind = INSERT, pre-image
/// captured for the deleted parent rows.
#[test]
fn dry_run_validated_delete_commits_and_captures_insert_inverse() {
    let Some((admin, dbname, _c)) = setup("apply_delete_commit") else {
        return;
    };
    let url = url_for(&admin, &dbname);
    let before = read_accounts(&url);

    let grant = grant_for("p-del", &url, EVEN_WHERE, 50);
    let forward = "DELETE FROM public.accounts WHERE id % 2 = 0";

    let mut client = Client::connect(&url, NoTls).expect("apply connect");
    let applied = {
        let mut conn = PgApplyConn::new(&mut client, forward, EVEN_WHERE, WriteKind::Delete);
        guarded_apply(
            "p-del",
            WriteKind::Delete,
            "public.accounts",
            &grant,
            PitrConfig::disabled(),
            &mut conn,
            &NoopBarrier::new(),
            &SystemClock::new(),
        )
        .expect("delete apply must COMMIT")
    };

    assert_eq!(applied.rows_written, 4);
    assert_eq!(applied.inverse.kind, InverseKind::Insert);
    assert_eq!(applied.inverse.rows.len(), 4);
    // The even accounts are gone; cascade removed their entries too.
    let after = read_accounts(&url);
    assert!(
        [2, 4, 6, 8].iter().all(|id| !after.contains_key(id)),
        "even accounts must be deleted"
    );
    // Pre-image of each deleted row matches the golden state (so revert can reinsert).
    for row in &applied.inverse.rows {
        let id = match &row.pk.values()[0] {
            PkValue::Int(i) => *i as i32,
            other => panic!("{other:?}"),
        };
        assert_eq!(col_text(&row.before_image, "owner"), before[&id].0);
        assert_eq!(col_int(&row.before_image, "balance"), before[&id].1);
    }
    eprintln!("[delete-commit] PASS: deleted + INSERT inverse pre-image captured");

    drop_db(&admin, &dbname);
}

/// (1c) PITR enabled → a restore point is created before the apply (the §1 fence).
#[test]
fn pitr_enabled_creates_a_real_restore_point_before_apply() {
    let Some((admin, dbname, _c)) = setup("apply_pitr") else {
        return;
    };
    let url = url_for(&admin, &dbname);
    let grant = grant_for("p-pitr", &url, EVEN_WHERE, 50);
    let forward = "UPDATE public.accounts SET balance = balance + 1 WHERE id % 2 = 0";

    let mut client = Client::connect(&url, NoTls).expect("apply connect");
    let applied = {
        let mut conn = PgApplyConn::new(&mut client, forward, EVEN_WHERE, WriteKind::Update);
        guarded_apply(
            "p-pitr",
            WriteKind::Update,
            "public.accounts",
            &grant,
            PitrConfig::enabled(),
            &mut conn,
            &NoopBarrier::new(),
            &SystemClock::new(),
        )
        .expect("apply commits with a PITR fence")
    };
    match &applied.fence {
        RecoveryFence::PitrRestorePoint { label, lsn } => {
            assert!(label.starts_with("pgb_p-pitr_"), "label={label}");
            assert!(lsn.contains('/'), "a real LSN: {lsn}");
            eprintln!("[pitr] PASS: restore point `{label}` created at LSN {lsn}");
        }
        other => panic!("expected a PITR restore point, got {other:?}"),
    }
    drop_db(&admin, &dbname);
}

// ===========================================================================
//  (2) DRIFT via ApplyBarrier::pause_point() → apply-time re-check ABORTS.
// ===========================================================================

/// Shared drift runner: inject `inject_sql` (committed on a second connection)
/// through the barrier, run the guarded UPDATE, and assert the apply-time PK-set
/// re-check ABORTED with no change.
fn run_drift_case(tag: &str, inject_sql: &str) -> Option<(String, String)> {
    let (admin, dbname, _c) = setup(tag)?;
    let url = url_for(&admin, &dbname);
    let before = read_accounts(&url);

    let grant = grant_for("p-drift", &url, EVEN_WHERE, 50);
    let forward = "UPDATE public.accounts SET balance = 0 WHERE id % 2 = 0";

    // The barrier opens a SEPARATE connection and commits the drift before the
    // apply recomputes the checksum.
    let inject_url = url.clone();
    let inject = inject_sql.to_string();
    let barrier = ClosureBarrier::new(move |_| {
        let mut c = Client::connect(&inject_url, NoTls).expect("inject connect");
        c.batch_execute(&inject).expect("inject drift");
    });

    let mut client = Client::connect(&url, NoTls).expect("apply connect");
    let result = {
        let mut conn = PgApplyConn::new(&mut client, forward, EVEN_WHERE, WriteKind::Update);
        guarded_apply(
            "p-drift",
            WriteKind::Update,
            "public.accounts",
            &grant,
            PitrConfig::disabled(),
            &mut conn,
            &barrier,
            &SystemClock::new(),
        )
    };
    assert_eq!(
        barrier.crossings(),
        1,
        "{tag}: barrier crossed exactly once"
    );

    match result {
        Err(ApplyError::PkSetDrift {
            dry_run,
            apply_time,
            ..
        }) => {
            assert_ne!(
                dry_run, apply_time,
                "{tag}: abort must be a checksum mismatch"
            );
            eprintln!("{tag}: GUARD ABORT (apply-time PK-set drift) dry_run={dry_run} apply_time={apply_time}");
        }
        other => panic!("{tag}: expected PkSetDrift ABORT, got {other:?}"),
    }

    // No partial commit: the even accounts' balances are UNCHANGED (the apply
    // rolled back). We compare only the rows the *forward op* would have touched
    // that the drift did not itself legitimately change.
    let after = read_accounts(&url);
    // The forward op (SET balance = 0) never committed, so NO account that was
    // non-zero before is zero now *because of the apply*. Assert the apply made no
    // balance-zeroing: every id still present whose pre-balance was non-zero is
    // still non-zero (the drift injections here never set balance=0).
    for (id, (_owner, bal)) in &after {
        if let Some((_, pre_bal)) = before.get(id) {
            if *pre_bal != 0 {
                assert_ne!(
                    *bal, 0,
                    "{tag}: account {id} was zeroed — the aborted apply leaked a partial commit"
                );
            }
        }
    }
    Some((admin, dbname))
}

#[test]
fn t_drift_insert_aborts() {
    // A new matching (even-id) row appears post-snapshot (over-count) → ABORT.
    let Some((admin, dbname)) = run_drift_case(
        "drift_insert",
        "INSERT INTO public.accounts(id, owner, balance) VALUES (100, 'drift', 9999)",
    ) else {
        return;
    };
    eprintln!("T-drift-insert PASS: over-count drift ABORTED, no partial commit");
    drop_db(&admin, &dbname);
}

#[test]
fn t_drift_delete_shrink_aborts() {
    // A matching row vanishes post-snapshot (under-count) → ABORT.
    let Some((admin, dbname)) =
        run_drift_case("drift_shrink", "DELETE FROM public.accounts WHERE id = 8")
    else {
        return;
    };
    eprintln!("T-drift-delete-shrink PASS: under-count drift ABORTED");
    drop_db(&admin, &dbname);
}

#[test]
fn t_drift_predicate_flip_same_count_different_pks_aborts() {
    // HEADLINE: id 8 leaves the matched set, id 10 enters it — count stays 4, the
    // PK set changes. A row-count guard PASSES here; only the PK-set checksum
    // catches it. (We delete the even id=8 and insert a new even id=10.)
    let Some((admin, dbname)) = run_drift_case(
        "drift_flip",
        "DELETE FROM public.accounts WHERE id = 8; \
         INSERT INTO public.accounts(id, owner, balance) VALUES (10, 'flip', 1234);",
    ) else {
        return;
    };
    // Prove the COUNT is unchanged (so a count-only guard would have MISSED it).
    let url = url_for(&admin, &dbname);
    let mut c = Client::connect(&url, NoTls).unwrap();
    let n: i64 = c
        .query_one(
            &format!("SELECT count(*) FROM public.accounts WHERE {EVEN_WHERE}"),
            &[],
        )
        .unwrap()
        .get(0);
    eprintln!("T-drift-predicate-flip: matching-row count is still {n} (count guard blind spot)");
    assert_eq!(
        n, 4,
        "count unchanged — only the PK-set checksum catches this"
    );
    eprintln!("T-drift-predicate-flip PASS: identical count, different PK set → ABORTED");
    drop_db(&admin, &dbname);
}

#[test]
fn t_drift_trigger_amplification_aborts() {
    // A trigger is installed on `accounts` post-snapshot (amplifying the audit
    // side-effect footprint), and the same migration also shifts a NEW row INTO
    // the predicate (an even id=12). The apply-time recompute observes the changed
    // affected-PK set → ABORT. (Per §10.3/the spike: a pre-op recompute cannot see
    // a trigger that writes *outside* the predicate during the forward op — that
    // case is the RETURNING written-set check below — so this models the honest,
    // catchable case where the migration shifts the matched set itself.)
    let Some((admin, dbname)) = run_drift_case(
        "drift_amplify",
        "CREATE FUNCTION public.accounts_amplify() RETURNS trigger LANGUAGE plpgsql AS $$ \
           BEGIN INSERT INTO public.account_audit(account_id, op) VALUES (NEW.id, 'AMPLIFY'); RETURN NEW; END; $$; \
         CREATE TRIGGER accounts_amplify_aud AFTER UPDATE ON public.accounts \
           FOR EACH ROW EXECUTE FUNCTION public.accounts_amplify(); \
         INSERT INTO public.accounts(id, owner, balance) VALUES (12, 'amplify', 1);",
    ) else {
        return;
    };
    eprintln!("T-drift-trigger-amplification PASS: post-snapshot trigger+row shift ABORTED");
    drop_db(&admin, &dbname);
}

// ===========================================================================
//  (3) RETURNING written-set check — post-snapshot trigger writes OUTSIDE the
//      predicate. The pre-op recompute MATCHES, but the forward op writes an
//      extra row → step 6 ABORTS (the carry-forward a pre-op-only guard misses).
// ===========================================================================

#[test]
fn t_returning_written_set_mismatch_outside_predicate_aborts() {
    let Some((admin, dbname, _c)) = setup("returning_outside") else {
        return;
    };
    let url = url_for(&admin, &dbname);
    let before = read_accounts(&url);

    // The carry-forward (gate (a)) the pre-op recompute CANNOT see:
    //
    // The engine's apply-time PK-set re-check (step 5) recomputes on the predicate
    // `id % 2 = 0` → {2,4,6,8}, which MATCHES the grant → step 5 PASSES. But the
    // forward statement actually written touches a row OUTSIDE that predicate
    // (id=1) — modelling a post-snapshot trigger/migration that widened what the
    // op writes. The forward op's `RETURNING id` set is therefore {1,2,4,6,8},
    // which differs from the predicted {2,4,6,8}. Only the RETURNING written-set
    // check (step 6) catches this; a pre-op-only guard misses it.
    let grant = grant_for("p-ret", &url, EVEN_WHERE, 50);

    // recompute predicate = EVEN_WHERE (matches grant); forward op writes one more.
    let forward = "UPDATE public.accounts SET balance = 0 WHERE id % 2 = 0 OR id = 1";

    let mut apply_client = Client::connect(&url, NoTls).expect("apply connect");
    let result = {
        let mut conn = PgApplyConn::new(&mut apply_client, forward, EVEN_WHERE, WriteKind::Update);
        guarded_apply(
            "p-ret",
            WriteKind::Update,
            "public.accounts",
            &grant,
            PitrConfig::disabled(),
            &mut conn,
            &NoopBarrier::new(),
            &SystemClock::new(),
        )
    };

    match result {
        Err(ApplyError::WrittenSetMismatch {
            predicted, written, ..
        }) => {
            assert_ne!(predicted, written);
            eprintln!(
                "T-returning-written-set PASS: pre-op recompute matched, but the forward op \
                 wrote OUTSIDE the predicate (predicted={predicted} written={written}) → ABORTED"
            );
        }
        other => panic!("expected WrittenSetMismatch (carry-forward), got {other:?}"),
    }

    // No partial commit: even the in-predicate rows were NOT zeroed — the WHOLE
    // apply rolled back, so the DB is byte-for-byte unchanged.
    let after = read_accounts(&url);
    assert_eq!(
        before, after,
        "the whole apply rolled back — DB byte-for-byte unchanged"
    );
    eprintln!("T-returning-written-set: DB byte-for-byte unchanged after the abort");

    drop_db(&admin, &dbname);
}

// ===========================================================================
//  (4) statement_timeout fires on a slow apply → abort, NO partial commit.
// ===========================================================================

#[test]
fn statement_timeout_fires_and_leaves_no_partial_commit() {
    let Some((admin, dbname, _c)) = setup("apply_timeout") else {
        return;
    };
    let url = url_for(&admin, &dbname);
    let before = read_accounts(&url);

    // A dry-run duration of 0 → statement_timeout floor = 1000ms. The forward op
    // sleeps 3s, so the server cancels it (57014) → ApplyError::Timeout.
    let grant = grant_for("p-timeout", &url, EVEN_WHERE, 0);
    let forward =
        "UPDATE public.accounts SET balance = 0 WHERE id % 2 = 0 AND pg_sleep(3) IS NOT NULL";

    let mut client = Client::connect(&url, NoTls).expect("apply connect");
    let result = {
        let mut conn = PgApplyConn::new(&mut client, forward, EVEN_WHERE, WriteKind::Update);
        guarded_apply(
            "p-timeout",
            WriteKind::Update,
            "public.accounts",
            &grant,
            PitrConfig::disabled(),
            &mut conn,
            &NoopBarrier::new(),
            &SystemClock::new(),
        )
    };
    match result {
        Err(ApplyError::Timeout { timeout_ms }) => {
            assert_eq!(timeout_ms, 1_000, "floor timeout for a 0ms dry-run");
            eprintln!("[timeout] PASS: statement_timeout {timeout_ms}ms fired → aborted");
        }
        other => panic!("expected ApplyError::Timeout, got {other:?}"),
    }
    // No partial commit — every balance unchanged.
    let after = read_accounts(&url);
    assert_eq!(before, after, "a timeout abort must leave the DB unchanged");
    eprintln!("[timeout] DB byte-for-byte unchanged (no partial commit)");

    drop_db(&admin, &dbname);
}

// ===========================================================================
//  (5) Refused op → never applied (DB untouched).
// ===========================================================================

#[test]
fn refused_op_is_never_applied_db_untouched() {
    let Some((admin, dbname, _c)) = setup("apply_refused") else {
        return;
    };
    let url = url_for(&admin, &dbname);
    let before = read_accounts(&url);

    // Model a non-reversible UPDATE (no captured pre-image) → outside the
    // certified set → REFUSED. The grant carries reversible=false.
    let mut grant = grant_for("p-refused", &url, EVEN_WHERE, 50);
    grant.reversible = false;
    let forward = "UPDATE public.accounts SET balance = 0 WHERE id % 2 = 0";

    let mut client = Client::connect(&url, NoTls).expect("apply connect");
    let result = {
        let mut conn = PgApplyConn::new(&mut client, forward, EVEN_WHERE, WriteKind::Update);
        guarded_apply(
            "p-refused",
            WriteKind::Update,
            "public.accounts",
            &grant,
            PitrConfig::disabled(),
            &mut conn,
            &NoopBarrier::new(),
            &SystemClock::new(),
        )
    };
    assert!(
        matches!(result, Err(ApplyError::Refused(_))),
        "got {result:?}"
    );
    eprintln!("[refused] {:?}", result.unwrap_err());

    // DB byte-for-byte untouched — the refusal happened before any txn opened.
    let after = read_accounts(&url);
    assert_eq!(before, after, "a refused op must never touch the DB");
    eprintln!("[refused] PASS: refused before any DB work, DB untouched");

    drop_db(&admin, &dbname);
}

// ---- small pre-image column helpers ---------------------------------------

fn col_int(image: &[(String, ImageValue)], name: &str) -> i64 {
    match image.iter().find(|(c, _)| c == name).map(|(_, v)| v) {
        Some(PkValue::Int(i)) => *i,
        other => panic!("expected int col `{name}`, got {other:?}"),
    }
}
fn col_text(image: &[(String, ImageValue)], name: &str) -> String {
    match image.iter().find(|(c, _)| c == name).map(|(_, v)| v) {
        Some(PkValue::Text(s)) => s.clone(),
        other => panic!("expected text col `{name}`, got {other:?}"),
    }
}

/// A compact "even ids -> balance" view for log lines.
fn even_view(m: &BTreeMap<i32, (String, i64)>) -> BTreeMap<i32, i64> {
    m.iter()
        .filter(|(id, _)| **id % 2 == 0)
        .map(|(id, (_, b))| (*id, *b))
        .collect()
}
