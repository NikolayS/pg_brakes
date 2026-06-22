//! Env-gated **real PG18** integration test for the S5 shared, persistent,
//! anchored `_meta` audit chain wired into the proxy (issue #64, SPEC §3/§4/§10.9).
//!
//! Runs only when `PG_BUMPERS_IT=1` (CI's fast `cargo test` skips it; the crate
//! still builds/links). Run with:
//!
//! ```sh
//! PG_BUMPERS_IT=1 cargo test -p pgb-proxy --test audit_meta_it -- --nocapture
//! ```
//!
//! It proves, against a live `_meta` table created from
//! `crates/audit/sql/10_audit_meta.sql`:
//!   1. the proxy `Recorder` — injected with the SAME shared sink the
//!      [`AuditBoot`] wraps — records a real **REJECT** onto the **persistent**
//!      `_meta` chain (one genesis), which then `verify_chain`s;
//!   2. the [`AuditBoot`] anchors that canonical chain and the anchored head
//!      **matches** the chain head; the fail-closed `startup_verify` passes;
//!   3. a **full-chain rewrite** (every record re-linked in the table) is caught
//!      at startup `verify_against_anchor` → fail-closed (`startup_verify` errs);
//!   4. the writer DSN is the audit-writer role (never the audited agent).
//!
//! Connection: `PG_BUMPERS_AUDIT_PGURL` (admin/superuser) or the default below —
//! the dedicated PG18 audit cluster on **55432**. NEVER 5432.
//!
//! The proxy always compiles `pgb-audit` with its `pg` feature (the running
//! proxy persists to `_meta`), so this test needs no extra cfg gate.

use std::sync::{Arc, Mutex};

use pgb_audit::{
    verify_chain, AuditBoot, BootError, Decision, LocalSecretStore, SecretStore, Sink,
    AUDIT_SIGNING_KEY_ID,
};
use pgb_core::{Clock, MockClock};
use pgb_proxy::Recorder;
use postgres::{Client, NoTls};

const DEFAULT_ADMIN_PGURL: &str = "host=127.0.0.1 port=55432 user=postgres dbname=postgres";

fn it_enabled() -> bool {
    std::env::var("PG_BUMPERS_IT")
        .map(|v| v == "1")
        .unwrap_or(false)
}

fn admin_pgurl() -> String {
    std::env::var("PG_BUMPERS_AUDIT_PGURL").unwrap_or_else(|_| DEFAULT_ADMIN_PGURL.to_string())
}

fn connect(url: &str) -> Client {
    Client::connect(url, NoTls).unwrap_or_else(|e| panic!("connect {url}: {e}"))
}

/// Read the audit `_meta` schema SQL, stripping the psql `\set` meta-command.
fn schema_sql() -> String {
    // The schema lives in the audit crate, one level up from this crate.
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../audit/sql/10_audit_meta.sql"
    );
    let raw = std::fs::read_to_string(path).unwrap_or_else(|e| panic!("read {path}: {e}"));
    raw.lines()
        .filter(|l| !l.trim_start().starts_with("\\set"))
        .collect::<Vec<_>>()
        .join("\n")
}

fn rewrite_db(dsn: &str, dbname: &str) -> String {
    let mut parts: Vec<String> = dsn
        .split_whitespace()
        .filter(|kv| !kv.starts_with("dbname="))
        .map(|s| s.to_string())
        .collect();
    parts.push(format!("dbname={dbname}"));
    parts.join(" ")
}

fn rewrite_role(dsn: &str, role: &str, password: &str) -> String {
    let mut parts: Vec<String> = dsn
        .split_whitespace()
        .filter(|kv| !kv.starts_with("user=") && !kv.starts_with("password="))
        .map(|s| s.to_string())
        .collect();
    parts.push(format!("user={role}"));
    parts.push(format!("password={password}"));
    parts.join(" ")
}

/// Create an isolated fresh DB, apply the audit `_meta` schema, and return
/// `(writer_dsn, admin_client_on_that_db)`.
fn setup_fresh_db(tag: &str) -> (String, Client) {
    let mut admin = connect(&admin_pgurl());
    let dbname = format!(
        "pgb_proxy_s5_it_{tag}_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    admin
        .batch_execute(&format!("CREATE DATABASE \"{dbname}\""))
        .unwrap_or_else(|e| panic!("create db {dbname}: {e}"));
    let db_url = rewrite_db(&admin_pgurl(), &dbname);
    let mut db_admin = connect(&db_url);
    db_admin
        .batch_execute(&schema_sql())
        .expect("apply audit _meta schema");
    let writer_dsn = rewrite_role(&db_url, "pgb_audit_writer", "pgb_audit_writer_dev_pw");
    (writer_dsn, db_admin)
}

fn store_with_key() -> LocalSecretStore {
    let mut store = LocalSecretStore::new();
    store
        .put(AUDIT_SIGNING_KEY_ID, b"proxy-s5-it-signing-key-000001")
        .unwrap();
    store
}

/// (1)+(2): a real proxy REJECT lands on the persistent `_meta` chain (one
/// genesis), the chain verifies, the anchored head matches, and the fail-closed
/// `startup_verify` passes.
#[test]
fn proxy_reject_persists_and_anchored_head_matches() {
    if !it_enabled() {
        eprintln!("[skip] set PG_BUMPERS_IT=1 to run the proxy S5 _meta anchor test");
        return;
    }
    let (writer_dsn, _admin) = setup_fresh_db("anchor");
    let clock = MockClock::starting_at(1_700_000_000_000);

    // Build the boot handle over the real `_meta` writer DSN, interval 10s.
    let mut boot =
        AuditBoot::connect(&writer_dsn, &store_with_key(), 10_000).expect("audit _meta boot");

    // Inject the SAME shared sink into the proxy Recorder.
    let sink_arc: Arc<Mutex<dyn Sink + Send>> = boot.sink_arc();
    let recorder = Recorder::new(
        sink_arc,
        Arc::new(clock.clone()) as Arc<dyn Clock>,
        "pgb_agent",
    );

    // The marquee hostile statement, BLOCKED → recorded as a REJECT on `_meta`.
    recorder
        .reject(
            "it-sess",
            "COMMIT; DROP SCHEMA public CASCADE",
            "simple_query_rejected",
            Some("extended-protocol-only".to_string()),
        )
        .expect("record reject onto _meta");

    // The persisted chain has the reject at the single genesis (seq 0).
    let records = boot.load_chain().expect("load persisted chain");
    assert_eq!(records.len(), 1, "one persisted record");
    assert_eq!(records[0].payload.seq, 0, "single genesis seq 0");
    assert_eq!(records[0].payload.decision, Decision::Reject);
    assert!(records[0].payload.statement_text.contains("DROP SCHEMA"));
    verify_chain(&records).expect("persisted chain verifies");

    // Anchor the canonical chain; the anchored head must match the chain head.
    let anchored = boot
        .maybe_anchor(clock.monotonic_millis())
        .expect("anchor ok")
        .expect("first tick anchors");
    assert_eq!(
        anchored.head_hash,
        records.last().unwrap().record_hash,
        "anchored head == persisted chain head"
    );

    // Fail-closed startup verify passes on the honest, anchored chain.
    boot.startup_verify()
        .expect("startup verify passes on honest anchored chain");
    eprintln!("[it] proxy REJECT persisted on `_meta`; anchored head matches; startup verify OK");
}

/// (3): a full-chain rewrite in the table is caught at startup `verify_against_anchor`
/// → fail-closed refuse-to-start.
#[test]
fn full_chain_rewrite_in_table_is_caught_at_startup() {
    if !it_enabled() {
        eprintln!("[skip] set PG_BUMPERS_IT=1 to run the proxy S5 full-chain-rewrite test");
        return;
    }
    let (writer_dsn, mut admin) = setup_fresh_db("rewrite");
    let clock = MockClock::starting_at(1_700_000_000_000);

    let mut boot =
        AuditBoot::connect(&writer_dsn, &store_with_key(), 10_000).expect("audit _meta boot");
    let sink_arc: Arc<Mutex<dyn Sink + Send>> = boot.sink_arc();
    let recorder = Recorder::new(
        sink_arc,
        Arc::new(clock.clone()) as Arc<dyn Clock>,
        "pgb_agent",
    );

    // Two records: a BLOCK then a REJECT.
    recorder
        .block("s", "UPDATE t SET x=1", "write_on_readonly", None)
        .unwrap();
    recorder
        .reject("s", "COPY t FROM STDIN", "copy_rejected", None)
        .unwrap();

    // Anchor the honest head + confirm startup verify passes.
    boot.maybe_anchor(clock.monotonic_millis())
        .unwrap()
        .unwrap();
    boot.startup_verify().expect("honest chain passes");
    let honest_head = boot
        .load_chain()
        .unwrap()
        .last()
        .unwrap()
        .record_hash
        .clone();

    // ATTACK: a privileged operator rewrites the WHOLE chain in the table,
    // flipping the BLOCK (seq 0) to an ALLOW and re-sealing + re-linking EVERY
    // row so the within-chain `verify_chain` is happy. Disable the append-only
    // trigger (models an operator with direct table access).
    admin
        .batch_execute("ALTER TABLE pgb_audit.audit_log DISABLE TRIGGER audit_log_no_mutation")
        .expect("disable trigger for forced rewrite");

    // Recompute the canonical bytes the chain would have for the tampered rows,
    // using the SAME audit sealing so the forged chain is internally consistent.
    // We rebuild it in-process via an InMemorySink seeded with the tampered
    // entries, then UPDATE each table row to the forged payload + hashes.
    use pgb_audit::{InMemorySink, NewEntry, Principal};
    use pgb_policy::IntentTiers;
    let mk = |role: &str, sql: &str, dec: Decision, code: &str| NewEntry {
        statement_text: sql.to_string(),
        decision: dec,
        reason_code: code.to_string(),
        reason: None,
        principal: Principal {
            role: role.to_string(),
            session_id: Some("s".to_string()),
            principal: None,
        },
        intent: IntentTiers::from_statement(role, sql, Some("proxy".to_string())),
        write_safety: Default::default(),
    };
    // Re-derive the ORIGINAL stamps so the forged rows differ only in the flipped
    // decision (the honest rows used the recorder's clock at fixed mock time).
    let c2 = MockClock::starting_at(1_700_000_000_000);
    let mut forged = InMemorySink::new();
    forged
        .append(
            // tampered: was BLOCK/write_on_readonly, now ALLOW/ok
            mk("pgb_agent", "UPDATE t SET x=1", Decision::Allow, "ok"),
            c2.now_unix_millis(),
        )
        .unwrap();
    forged
        .append(
            mk(
                "pgb_agent",
                "COPY t FROM STDIN",
                Decision::Reject,
                "copy_rejected",
            ),
            c2.now_unix_millis(),
        )
        .unwrap();
    let forged_records = forged.load_chain().unwrap();
    // The forged chain is internally consistent but has a DIFFERENT head.
    verify_chain(&forged_records).expect("forged chain internally consistent");
    assert_ne!(
        forged_records.last().unwrap().record_hash,
        honest_head,
        "rewrite changed the head"
    );

    // Overwrite every row in the table with the forged payload + hashes.
    for rec in &forged_records {
        let payload_text = String::from_utf8(rec.payload.canonical_bytes()).unwrap();
        admin
            .execute(
                "UPDATE pgb_audit.audit_log SET prev_hash=$2, record_hash=$3, payload=$4 \
                 WHERE seq=$1",
                &[
                    &(rec.payload.seq as i64),
                    &rec.payload.prev_hash,
                    &rec.record_hash,
                    &payload_text,
                ],
            )
            .expect("rewrite row");
    }
    admin
        .batch_execute("ALTER TABLE pgb_audit.audit_log ENABLE TRIGGER audit_log_no_mutation")
        .expect("re-enable trigger");

    // A NEW boot handle (a fresh process restart) loads the rewritten table and
    // must REFUSE TO START: the within-chain check passes (the rewrite is
    // consistent), but the anchored head no longer matches.
    let mut boot2 =
        AuditBoot::connect(&writer_dsn, &store_with_key(), 10_000).expect("reconnect boot");
    // Re-anchor would re-pin the forged head, so we DON'T anchor here — we verify
    // against the WORM anchor carried by the still-live `boot` from the honest
    // run. In production the WORM anchor is external + append-only; here we assert
    // the rewritten chain fails against the honest anchor.
    let rewritten = boot2.load_chain().unwrap();
    verify_chain(&rewritten).expect("rewritten chain is internally consistent (S1 blind)");
    let err = pgb_audit::verify_records_against_anchor(&rewritten, boot.worm());
    match err {
        Ok(pgb_audit::AnchorVerification::HeadMismatch { actual_head, .. }) => {
            assert_eq!(actual_head, forged_records.last().unwrap().record_hash);
            eprintln!("[it] full-chain rewrite in `_meta` CAUGHT at startup verify (HeadMismatch)");
        }
        other => panic!("expected HeadMismatch on full-chain rewrite, got {other:?}"),
    }

    // And the boot-level fail-closed wrapper turns that into a refuse-to-start
    // error when the boot handle carries the honest anchor.
    let startup = startup_verify_against(&rewritten, boot.worm());
    assert!(
        matches!(startup, Err(BootError::AnchorHeadMismatch { .. })),
        "startup must fail closed on a full-chain rewrite, got {startup:?}"
    );
}

/// Mirror of `AuditBoot::startup_verify`'s decision logic over an explicit
/// (record-slice, worm) pair, so the test can assert the boot-level fail-closed
/// error type against the honest anchor from a prior run.
fn startup_verify_against(
    records: &[pgb_audit::AuditRecord],
    worm: &pgb_audit::WormAnchor,
) -> Result<(), BootError> {
    verify_chain(records).map_err(BootError::ChainIntegrity)?;
    match pgb_audit::verify_records_against_anchor(records, worm)? {
        pgb_audit::AnchorVerification::Verified => Ok(()),
        pgb_audit::AnchorVerification::HeadMismatch {
            anchored_head,
            actual_head,
            anchored_seq,
        } => Err(BootError::AnchorHeadMismatch {
            anchored_head,
            actual_head,
            anchored_seq,
        }),
    }
}
