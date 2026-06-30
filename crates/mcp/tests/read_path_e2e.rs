//! Env-gated **real PG18** end-to-end test for the EPIC #83 PR2 READ PATH: a REAL
//! MCP client drives `PgBrakesMcp` whose read tools execute THROUGH a live
//! `pgb-proxy` (TLS + SCRAM) in front of PG18 — NOT raw PG. This is the honesty
//! bar the founder set: reads must genuinely traverse the proxy (the real
//! boundary), proven two ways (the WALL denies a non-granted table that a raw
//! superuser path would return; the proxy stamps `application_name='pgb_proxy'` on
//! the backend session it originates).
//!
//! Runs only when `PG_BRAKES_IT=1`, so CI's fast `cargo test` skips it (the crate
//! still builds/links). ⚠️ NEVER touches :5432 — it targets the local-stack
//! primary on a dedicated high port (default 54321).
//!
//! ```sh
//! deploy/local-stack.sh up
//! PG_BRAKES_IT=1 cargo test -p pgb-mcp --test read_path_e2e -- --nocapture
//! deploy/local-stack.sh down
//! ```
//!
//! What it proves end-to-end against a live server, driving the SHIPPED
//! `PgBrakesMcp` handler over the SAME duplex transport the stdio binary uses:
//!   * `query` a GRANTED table → rows, bounded, genuinely through the proxy;
//!   * `query` a NON-granted table → `WALL_DENIED` (the proxy's WALL role denies
//!     it; a raw-PG18 superuser would have returned the row — the load-bearing
//!     proof the read path is behind the proxy/WALL);
//!   * `query`/`explain_plan` a WRITE/stacked statement → `READ_ONLY` blocked by
//!     the canonical-classifier fast-path, and `explain_plan` NEVER executes it
//!     (the TS explain-hole stays CLOSED — the victim row is untouched);
//!   * `discover_schema` → the agent-visible columns (the granted table is there);
//!   * `get_audit` → the `_meta` audit tail (the proxy's verdicts), read-through.

#![cfg(test)]

use std::sync::{Arc, Mutex};

use pgb_core::{Clock, SystemClock};
use pgb_mcp::{AuditConfig, AuditReader, PgBrakesMcp, ProxyConfig, ProxyTransport, TlsMode};
use pgb_policy::{RoleBudget, WindowBudget};
use pgb_proxy::config::{BackendTarget, ProxyConfig as ProxyServerConfig, TlsConfig};
use pgb_proxy::{Recorder, ThreadedSink, serve_connection};
use rmcp::ServiceExt;
use rmcp::model::CallToolRequestParams;
use tokio::net::TcpListener;

const AGENT_USER: &str = "pgb_agent";
const AGENT_PASSWORD: &str = "pgb_agent_dev_pw";
const AUDIT_WRITER_PASSWORD: &str = "pgb_audit_writer_dev_pw";

fn it_enabled() -> bool {
    std::env::var("PG_BRAKES_IT")
        .map(|v| v == "1")
        .unwrap_or(false)
}

fn admin_dsn() -> String {
    std::env::var("PG_BRAKES_PROXY_PGURL")
        .unwrap_or_else(|_| "host=127.0.0.1 port=54321 user=postgres dbname=postgres".to_string())
}

fn backend_host_port_db() -> (String, u16, String) {
    let dsn = admin_dsn();
    let mut host = "127.0.0.1".to_string();
    let mut port = 54321u16;
    let mut db = "postgres".to_string();
    for kv in dsn.split_whitespace() {
        if let Some(v) = kv.strip_prefix("host=") {
            host = v.to_string();
        } else if let Some(v) = kv.strip_prefix("port=") {
            port = v.parse().unwrap_or(54321);
        } else if let Some(v) = kv.strip_prefix("dbname=") {
            db = v.to_string();
        }
    }
    (host, port, db)
}

/// The `_meta` audit WRITER DSN (the `pgb_audit_writer` role on the same primary
/// DB), used to (a) back the proxy's recorder so its verdicts land in `_meta`, and
/// (b) drive `get_audit`'s read-through (the reader has SELECT on the table).
fn meta_dsn() -> String {
    let (host, port, db) = backend_host_port_db();
    format!(
        "host={host} port={port} dbname={db} user=pgb_audit_writer password={AUDIT_WRITER_PASSWORD}"
    )
}

/// Fixtures: the `_meta` audit schema (writer role + append-only chain table), a
/// GRANTED read surface for the WALL role, and a NON-granted secret the WALL must
/// keep from the agent. Mirrors `deploy/up.sh`'s seed so the e2e matches the real
/// deploy.
fn setup_fixtures() {
    use postgres::{Client, NoTls};
    let mut admin = Client::connect(&admin_dsn(), NoTls).expect("admin connect");

    // The canonical `_meta` schema (creates pgb_audit_writer + the append-only
    // audit_log + the "audited cannot write audit" grants). Idempotent.
    let meta_sql = include_str!("../../audit/sql/10_audit_meta.sql");
    // Strip the psql meta-command the file opens with (`\set`), which the
    // simple-protocol batch path does not accept.
    let cleaned: String = meta_sql
        .lines()
        .filter(|l| !l.trim_start().starts_with('\\'))
        .collect::<Vec<_>>()
        .join("\n");
    admin.batch_execute(&cleaned).expect("apply _meta schema");

    admin
        .batch_execute(
            "BEGIN;
             SELECT pg_advisory_xact_lock(7067626669780099);

             -- The WALL role must exist with the dev password (the proxy SCRAM).
             DO $$
             BEGIN
               IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='pgb_agent') THEN
                 CREATE ROLE pgb_agent LOGIN PASSWORD 'pgb_agent_dev_pw' NOSUPERUSER NOINHERIT;
               END IF;
             END $$;
             ALTER ROLE pgb_agent LOGIN PASSWORD 'pgb_agent_dev_pw';

             -- A GRANTED read surface (read THROUGH the proxy as pgb_agent).
             CREATE TABLE IF NOT EXISTS public.mcp_read_demo (
               id int PRIMARY KEY, owner text NOT NULL, balance bigint NOT NULL
             );
             TRUNCATE public.mcp_read_demo;
             INSERT INTO public.mcp_read_demo(id, owner, balance)
               SELECT g, 'owner-'||g, (g*100)::bigint FROM generate_series(1,5) g;
             ANALYZE public.mcp_read_demo;
             GRANT USAGE ON SCHEMA public TO pgb_agent;
             GRANT SELECT ON public.mcp_read_demo TO pgb_agent;

             -- A NON-granted secret the WALL must keep from the agent.
             CREATE TABLE IF NOT EXISTS public.mcp_secret (id int PRIMARY KEY, secret text NOT NULL);
             INSERT INTO public.mcp_secret(id, secret) VALUES (1, 'TOP SECRET')
               ON CONFLICT (id) DO NOTHING;
             REVOKE ALL ON public.mcp_secret FROM pgb_agent;

             -- The explain-hole victim: if explain_plan ever EXECUTED a stacked
             -- write, this row would vanish. We grant SELECT so we can COUNT it
             -- through the proxy and assert it survives.
             CREATE TABLE IF NOT EXISTS public.mcp_explain_victim (id int PRIMARY KEY);
             TRUNCATE public.mcp_explain_victim;
             INSERT INTO public.mcp_explain_victim(id) VALUES (1);
             GRANT SELECT ON public.mcp_explain_victim TO pgb_agent;

             COMMIT;",
        )
        .expect("apply read fixtures");
}

fn make_tls() -> (TlsConfig, Vec<u8>, TempPaths) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
        .expect("self-signed cert");
    let cert_pem = cert.cert.pem();
    let key_pem = cert.key_pair.serialize_pem();
    let der = cert.cert.der().to_vec();

    let dir = std::env::temp_dir().join(format!("pgb-mcp-e2e-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let cert_path = dir.join("server.crt");
    let key_path = dir.join("server.key");
    std::fs::write(&cert_path, cert_pem).unwrap();
    std::fs::write(&key_path, key_pem).unwrap();
    (
        TlsConfig {
            cert_pem: cert_path,
            key_pem: key_path,
        },
        der,
        TempPaths { dir },
    )
}

struct TempPaths {
    dir: std::path::PathBuf,
}
impl Drop for TempPaths {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// A generous budget so the read-only/WALL behavior is what's under test (not the
/// budget gates, which have their own suite).
fn generous_budget() -> RoleBudget {
    RoleBudget {
        max_bytes: 100_000_000,
        max_rows: 1_000_000,
        max_plan_cost: 1_000_000_000.0,
        max_plan_rows: 1_000_000_000,
        per_window: WindowBudget {
            window_secs: 60,
            max_bytes: 1_000_000_000,
            max_rows: 1_000_000_000,
        },
    }
}

/// Spawn the REAL proxy in-process (TLS + SCRAM) against the local-stack primary,
/// with a `_meta`-backed recorder so its verdicts persist to the audit chain.
/// Returns the bound proxy address + the client trust DER.
async fn spawn_proxy() -> (std::net::SocketAddr, Vec<u8>, TempPaths) {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let (tls_cfg, cert_der, paths) = make_tls();
    let (host, port, db) = backend_host_port_db();

    let cfg = Arc::new(ProxyServerConfig {
        listen: "127.0.0.1:0".parse().unwrap(),
        tls: Some(tls_cfg.clone()),
        require_tls: true,
        backend: BackendTarget {
            host,
            port,
            database: db,
            role: AGENT_USER.to_string(),
            password: AGENT_PASSWORD.to_string(),
        },
        agent_user: AGENT_USER.to_string(),
        agent_password: AGENT_PASSWORD.to_string(),
        policy_role: "analytics".to_string(),
        budget: generous_budget(),
        statement_timeout_ms: 30_000,
        search_path: ProxyServerConfig::DEFAULT_SEARCH_PATH.to_string(),
    });

    // A `_meta`-backed recorder (ThreadedSink: the sync PgSink off the runtime), so
    // the proxy's per-statement verdicts land in pgb_audit.audit_log and get_audit
    // can read them back.
    let sink = ThreadedSink::connect(&meta_dsn()).expect("audit recorder sink");
    let sink: Arc<Mutex<dyn pgb_audit::Sink + Send>> = Arc::new(Mutex::new(sink));
    let clock: Arc<dyn Clock> = Arc::new(SystemClock::new());
    let recorder = Recorder::new(sink, clock, AGENT_USER);

    let listener = TcpListener::bind(cfg.listen).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let acceptor = Arc::new(tokio_rustls::TlsAcceptor::from(
        pgb_proxy::tls::server_config(&tls_cfg).unwrap(),
    ));

    let mut id = 0u64;
    tokio::spawn(async move {
        loop {
            let (tcp, _peer) = match listener.accept().await {
                Ok(v) => v,
                Err(_) => break,
            };
            id += 1;
            let cfg = cfg.clone();
            let acceptor = Some(acceptor.clone());
            let recorder = recorder.clone();
            let sid = format!("mcp-e2e-conn-{id}");
            tokio::spawn(async move {
                let _ = serve_connection(tcp, cfg, acceptor, recorder, sid).await;
            });
        }
    });

    (addr, cert_der, paths)
}

/// Build the SHIPPED `PgBrakesMcp` handler pointed at the in-process proxy
/// (TLS-on, verifying the self-signed cert) + the `_meta` audit reader.
fn build_server(addr: std::net::SocketAddr, cert_der: &[u8]) -> PgBrakesMcp {
    let proxy = ProxyTransport::new(ProxyConfig {
        host: "localhost".into(),
        port: addr.port(),
        database: "postgres".into(),
        user: AGENT_USER.into(),
        password: AGENT_PASSWORD.into(),
        application_name: "pgb_mcp".into(),
        tls: TlsMode::Rustls {
            roots_der: vec![cert_der.to_vec()],
        },
        statement_timeout_ms: 30_000,
    });
    let audit = AuditReader::new(AuditConfig { dsn: meta_dsn() });
    PgBrakesMcp::new(AGENT_USER, "mcp-e2e-session")
        .with_proxy(proxy)
        .with_audit(audit)
}

/// Connect a REAL rmcp client to the server over an in-process duplex pipe (the
/// same AsyncRead/AsyncWrite transport the stdio binary uses).
async fn connect_client(
    server: PgBrakesMcp,
) -> rmcp::service::RunningService<rmcp::service::RoleClient, ()> {
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let (s_read, s_write) = tokio::io::split(server_io);
    let (c_read, c_write) = tokio::io::split(client_io);
    tokio::spawn(async move {
        if let Ok(running) = server.serve((s_read, s_write)).await {
            let _ = running.waiting().await;
        }
    });
    ().serve((c_read, c_write)).await.expect("client handshake")
}

/// Helper: call a tool with `{sql}` and return its `structuredContent`.
async fn call_sql(
    client: &rmcp::service::RunningService<rmcp::service::RoleClient, ()>,
    tool: &'static str,
    sql: &str,
) -> serde_json::Value {
    let mut args = serde_json::Map::new();
    args.insert("sql".into(), serde_json::json!(sql));
    let res = client
        .call_tool(CallToolRequestParams::new(tool).with_arguments(args))
        .await
        .expect("tool call transport ok");
    res.structured_content.expect("structuredContent")
}

/// The marquee end-to-end: a REAL MCP client → read tools THROUGH the live proxy.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn mcp_reads_traverse_the_live_proxy_and_the_explain_hole_stays_closed() {
    if !it_enabled() {
        eprintln!(
            "[skip] set PG_BRAKES_IT=1 (+ deploy/local-stack.sh up) for the MCP read-path e2e"
        );
        return;
    }
    tokio::task::spawn_blocking(setup_fixtures)
        .await
        .expect("fixture setup thread");

    let (addr, cert_der, _paths) = spawn_proxy().await;
    let server = build_server(addr, &cert_der);
    let client = connect_client(server).await;

    // ---- 0. tools/list: all nine §4 tools ----
    let tools = client.list_all_tools().await.expect("tools/list");
    assert_eq!(tools.len(), 9, "the §4 catalog is nine tools");
    eprintln!("[ok] tools/list → {} tools", tools.len());

    // ---- 1. query a GRANTED table → rows, bounded, THROUGH the proxy ----
    let granted = call_sql(
        &client,
        "query",
        "SELECT id, owner, balance FROM public.mcp_read_demo ORDER BY id",
    )
    .await;
    assert_eq!(
        granted["status"],
        serde_json::json!("ok"),
        "granted read: {granted}"
    );
    assert_eq!(
        granted["rowCount"],
        serde_json::json!(5),
        "5 rows: {granted}"
    );
    assert_eq!(granted["rows"][0]["owner"], serde_json::json!("owner-1"));
    eprintln!(
        "[ok] query(mcp_read_demo) → {} rows through pgb-proxy",
        granted["rowCount"]
    );

    // ---- 2. PROOF the read is behind the WALL: a NON-granted table is DENIED ----
    // The proxy connects to PG as the WALL role pgb_agent, which has NO SELECT on
    // mcp_secret. A raw-PG18 superuser path would have returned the row; through
    // the proxy it is WALL_DENIED (SQLSTATE 42501). This is the load-bearing proof
    // the read GENUINELY traverses the proxy/WALL, not a raw connection.
    let denied = call_sql(&client, "query", "SELECT secret FROM public.mcp_secret").await;
    assert_eq!(
        denied["status"],
        serde_json::json!("blocked"),
        "secret: {denied}"
    );
    assert_eq!(
        denied["code"],
        serde_json::json!("WALL_DENIED"),
        "the WALL role the proxy connects as must deny the non-granted table: {denied}"
    );
    eprintln!(
        "[ok] query(mcp_secret) → {} (the proxy/WALL denied the non-granted table)",
        denied["code"]
    );

    // ---- 3. A WRITE to the read tool → READ_ONLY (canonical classifier reuse) ----
    let write = call_sql(
        &client,
        "query",
        "DELETE FROM public.mcp_read_demo WHERE id = 1",
    )
    .await;
    assert_eq!(
        write["code"],
        serde_json::json!("READ_ONLY"),
        "write: {write}"
    );
    // The classifier blocked it BEFORE the proxy; the row is untouched.
    let still = call_sql(
        &client,
        "query",
        "SELECT count(*)::int AS n FROM public.mcp_read_demo",
    )
    .await;
    assert_eq!(
        still["rows"][0]["n"],
        serde_json::json!(5),
        "write was NOT executed: {still}"
    );
    eprintln!("[ok] query(DELETE …) → READ_ONLY; the row is untouched (classifier fast-path)");

    // ---- 4. THE EXPLAIN HOLE STAYS CLOSED ----
    // (a) explain_plan of a clean read → a real plan (PLANNED, never executed).
    let plan = call_sql(
        &client,
        "explain_plan",
        "SELECT id FROM public.mcp_read_demo WHERE id = 2",
    )
    .await;
    assert_eq!(
        plan["status"],
        serde_json::json!("ok"),
        "explain ok: {plan}"
    );
    assert!(
        plan["plan"].as_str().unwrap_or_default().contains("Plan"),
        "explain returns a JSON plan: {plan}"
    );
    eprintln!("[ok] explain_plan(read) → a JSON plan (planned, not executed)");

    // (b) explain_plan of a STACKED write — the TS hole: `EXPLAIN ${sql}` would
    //     EXECUTE the second statement. Here the SAME classifier guard blocks it,
    //     so it NEVER reaches the wire and the victim row survives.
    let victim_before = call_sql(
        &client,
        "query",
        "SELECT count(*)::int AS n FROM public.mcp_explain_victim",
    )
    .await;
    assert_eq!(victim_before["rows"][0]["n"], serde_json::json!(1));
    for hole in [
        "SELECT 1; DELETE FROM public.mcp_explain_victim",
        "DELETE FROM public.mcp_explain_victim",
        "DROP TABLE public.mcp_explain_victim",
    ] {
        let blocked = call_sql(&client, "explain_plan", hole).await;
        assert_eq!(
            blocked["code"],
            serde_json::json!("READ_ONLY"),
            "explain_plan(`{hole}`) must be READ_ONLY-blocked (hole closed): {blocked}"
        );
    }
    let victim_after = call_sql(
        &client,
        "query",
        "SELECT count(*)::int AS n FROM public.mcp_explain_victim",
    )
    .await;
    assert_eq!(
        victim_after["rows"][0]["n"],
        serde_json::json!(1),
        "the explain-hole victim row MUST survive — explain_plan never executed a write: {victim_after}"
    );
    eprintln!(
        "[ok] explain-hole CLOSED: stacked/write explain_plan → READ_ONLY; victim row intact"
    );

    // ---- 5. discover_schema → the agent-visible columns (granted table present) ----
    let schema = client
        .call_tool(CallToolRequestParams::new("discover_schema"))
        .await
        .expect("discover_schema")
        .structured_content
        .expect("structuredContent");
    assert_eq!(
        schema["status"],
        serde_json::json!("ok"),
        "schema: {schema}"
    );
    let cols = schema["columns"].as_array().expect("columns array");
    let sees_demo = cols.iter().any(|c| {
        c["table"] == serde_json::json!("mcp_read_demo")
            && c["column"] == serde_json::json!("owner")
    });
    assert!(
        sees_demo,
        "discover_schema must see the granted table's columns: {schema}"
    );
    eprintln!(
        "[ok] discover_schema → {} columns; the granted table is visible",
        cols.len()
    );

    // ---- 6. get_audit → the `_meta` audit tail (the proxy's verdicts) ----
    // The reads above were audited by the proxy's recorder into pgb_audit.audit_log;
    // get_audit reads that tail back (read-through, reusing the audit crate).
    let mut audit_args = serde_json::Map::new();
    audit_args.insert("limit".into(), serde_json::json!(20));
    let audit = client
        .call_tool(CallToolRequestParams::new("get_audit").with_arguments(audit_args))
        .await
        .expect("get_audit")
        .structured_content
        .expect("structuredContent");
    assert_eq!(audit["status"], serde_json::json!("ok"), "audit: {audit}");
    let records = audit["records"].as_array().expect("records array");
    assert!(
        !records.is_empty(),
        "get_audit must return the proxy's audited verdicts: {audit}"
    );
    // The tail must contain at least one block (the WALL denial we triggered).
    let has_block = records.iter().any(|r| {
        r["decision"] == serde_json::json!("BLOCK") || r["decision"] == serde_json::json!("REJECT")
    });
    assert!(
        has_block,
        "the audited tail should include the blocked/rejected read(s): {audit}"
    );
    eprintln!(
        "[ok] get_audit → {} record(s) from the `_meta` chain (incl. a blocked read)",
        records.len()
    );

    client.cancel().await.expect("clean shutdown");
    eprintln!(
        "[PASS] MCP read path: reads traverse the live proxy; explain-hole closed; audit read-through works."
    );
}

/// Terminate the proxy's LIVE backend session (the agent-tagged
/// `application_name='pgb_proxy'`, role `pgb_agent`) from an admin connection — the
/// warden-style `pg_terminate_backend`. Returns how many sessions were terminated
/// (0 if none were live yet). Mirrors how `pgb-warden` reaps an agent-tagged
/// backend, and how the backend dies under us in production (restart / idle reset).
fn terminate_agent_backends() -> u64 {
    use postgres::{Client, NoTls};
    let mut admin = Client::connect(&admin_dsn(), NoTls).expect("admin connect (terminate)");
    let row = admin
        .query_one(
            "SELECT count(*)::bigint AS n FROM (
               SELECT pg_terminate_backend(pid)
               FROM pg_stat_activity
               WHERE application_name = 'pgb_proxy'
                 AND usename = 'pgb_agent'
                 AND pid <> pg_backend_pid()
             ) AS killed",
            &[],
        )
        .expect("pg_terminate_backend the agent-tagged session");
    row.get::<_, i64>("n") as u64
}

/// FIX 2 (samorev round, EPIC #83 PR4): the read path's LIVE connection-loss →
/// re-dial recovery — the symmetric analogue of the write-side
/// `applyd::tests::dropped_socket_transparently_reconnects_on_the_next_call`.
///
/// The prior coverage only proved the **never-dialed / down-from-start** case
/// (`proxy::tests::query_against_a_down_proxy_is_a_recoverable_block_not_a_crash`).
/// This test drives the UNTESTED path the deleted `proxyResilience.test.ts`
/// guarded: a proxy/backend connection lost **mid-session** must be ABSORBED (no
/// crash/throw of the stdio process), and the **next read must re-dial a fresh
/// connection and succeed**.
///
/// What it does, all LIVE (real proxy + real PG18, NEVER 5432):
///   1. a successful read establishes a HELD `tokio-postgres` client to the proxy,
///      which originated a backend session tagged `application_name='pgb_proxy'`;
///   2. an admin `pg_terminate_backend` kills that live backend session (the proxy
///      then closes the agent-facing connection — the held client is now dead);
///   3. the next read finds the held client unusable, ABSORBS the loss (never a
///      panic/throw — it is at worst a RECOVERABLE block), and a follow-up read
///      RE-DIALS a fresh proxy-brokered session and SUCCEEDS, returning correct
///      rows from a genuinely new backend session.
///
/// **Teeth:** if `ProxyTransport::with_client` stops resetting the cached client on
/// `ReadError::ConnectionLost` (e.g. it surfaces a hard error instead of
/// `*guard = None` + re-dial), step 3's recovery read returns `blocked` forever
/// instead of `ok` — and the `recovered["status"] == "ok"` assertion FAILS. (Proven
/// RED in the PR by temporarily breaking that reset.)
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn read_path_absorbs_a_live_connection_loss_and_the_next_read_redials() {
    if !it_enabled() {
        eprintln!(
            "[skip] set PG_BRAKES_IT=1 (+ deploy/local-stack.sh up) for the read-path live-loss e2e"
        );
        return;
    }
    tokio::task::spawn_blocking(setup_fixtures)
        .await
        .expect("fixture setup thread");

    let (addr, cert_der, _paths) = spawn_proxy().await;
    let server = build_server(addr, &cert_der);
    let client = connect_client(server).await;

    // ---- 1. A successful read: dials the proxy + holds a live client. The proxy
    //         originated a backend session tagged application_name='pgb_proxy'. ----
    let first = call_sql(
        &client,
        "query",
        "SELECT id FROM public.mcp_read_demo ORDER BY id",
    )
    .await;
    assert_eq!(
        first["status"],
        serde_json::json!("ok"),
        "the first read must succeed (it establishes the held connection): {first}"
    );
    assert_eq!(first["rowCount"], serde_json::json!(5), "5 rows: {first}");
    eprintln!("[ok] live read #1 → 5 rows; a held proxy connection is now established");

    // ---- 2. Kill the LIVE agent-tagged backend session out-of-band (warden-style).
    //         The proxy's relay loop errors and closes the agent-facing connection,
    //         so the MCP server's held tokio-postgres client is now dead. ----
    let killed = tokio::task::spawn_blocking(terminate_agent_backends)
        .await
        .expect("terminate thread");
    assert!(
        killed >= 1,
        "expected to terminate the live agent-tagged backend session (saw {killed})"
    );
    eprintln!(
        "[ok] terminated {killed} live agent-tagged backend session(s) (pg_terminate_backend)"
    );

    // ---- 3. The loss is ABSORBED (no crash/throw — the call returns a structured
    //         result, recoverable at worst), and the read path RE-DIALS a fresh
    //         session and SUCCEEDS. `with_client` retries once internally, so the
    //         very next read usually recovers transparently; if it instead surfaces
    //         a recoverable PROXY_UNAVAILABLE block, a follow-up read MUST recover.
    //         Either way: never a panic, and recovery is guaranteed. ----
    let after_loss = call_sql(
        &client,
        "query",
        "SELECT id FROM public.mcp_read_demo ORDER BY id",
    )
    .await;
    // The loss must be ABSORBED into a structured outcome — either an immediate
    // transparent recovery (`ok`) or a RECOVERABLE block (never a crash/throw, and
    // never a non-retryable hard failure).
    let status = after_loss["status"].as_str().unwrap_or_default();
    assert!(
        status == "ok" || status == "blocked",
        "a live connection loss must be ABSORBED into ok/blocked, never a crash: {after_loss}"
    );
    if status == "blocked" {
        assert_eq!(
            after_loss["code"],
            serde_json::json!("PROXY_UNAVAILABLE"),
            "a re-dialable live loss surfaces as the recoverable PROXY_UNAVAILABLE block: {after_loss}"
        );
        assert_eq!(
            after_loss["retryable"],
            serde_json::json!(true),
            "the live-loss block must be retryable (re-dial): {after_loss}"
        );
        eprintln!("[ok] live loss → recoverable PROXY_UNAVAILABLE block (absorbed, not a crash)");
    } else {
        eprintln!("[ok] live loss → transparently recovered on the very next read (re-dial)");
    }

    // ---- 3b. A subsequent read MUST re-dial a fresh proxy-brokered session and
    //          SUCCEED with the correct rows — the re-dial-recovery guarantee. ----
    let recovered = call_sql(
        &client,
        "query",
        "SELECT id, owner FROM public.mcp_read_demo ORDER BY id",
    )
    .await;
    assert_eq!(
        recovered["status"],
        serde_json::json!("ok"),
        "after a live loss the next read MUST re-dial a fresh session and SUCCEED: {recovered}"
    );
    assert_eq!(
        recovered["rowCount"],
        serde_json::json!(5),
        "the re-dialed read returns the full result from a fresh backend session: {recovered}"
    );
    assert_eq!(
        recovered["rows"][0]["owner"],
        serde_json::json!("owner-1"),
        "the recovered rows are the real table contents (genuine fresh session): {recovered}"
    );
    eprintln!(
        "[ok] live-loss RECOVERY: the next read re-dialed a fresh proxy session and returned 5 rows"
    );

    client.cancel().await.expect("clean shutdown");
    eprintln!(
        "[PASS] read-path live-loss: a mid-session backend kill is absorbed (no crash); the next read re-dials + succeeds."
    );
}
