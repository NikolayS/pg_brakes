//! Env-gated **real PG18** integration test for the warden (SPEC §3 layer 2,
//! §4, §10.9; issue #52). Runs only when `PG_BUMPERS_IT=1`, so CI's fast
//! `cargo test` skips it (the crate still builds/links).
//!
//! ```sh
//! # stand up a dedicated throwaway PG18 cluster on a high port (NEVER 5432):
//! PG_BUMPERS_IT=1 cargo test -p pgb-warden --test warden_it -- --nocapture
//! ```
//!
//! By default the test **stands up its own throwaway cluster** on port `54362`
//! (initdb + start + teardown, all under a temp dir) so it is hermetic and
//! never touches the developer's 5432. Override with `PG_BUMPERS_WARDEN_PGURL`
//! to point at an already-running local-stack primary.
//!
//! It proves, against a live server:
//!
//!  * the warden's live `ActivitySource` reads `pg_stat_activity` /
//!    `pg_replication_slots` and the pure [`assess`] decision fires;
//!  * an **agent-tagged** runaway (a real backend running `pg_sleep` with the
//!    proxy `application_name`) is **detected and terminated** via
//!    `pg_terminate_backend`, and the backend actually disappears;
//!  * a **non-agent** backend running the same long `pg_sleep` is **left
//!    alone** (no false-positive kill) — it is still present afterwards;
//!  * a **replication slot** created against the cluster is **detected and
//!    alarmed** by the live source.

#![cfg(test)]

use std::process::Command;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use postgres::{Client, NoTls};

use pgb_warden::poller::{ActivitySource, Killer};
use pgb_warden::{assess, Backend, Observation, ReplicationSlot, WardenThresholds};

const AGENT_APP_NAME: &str = "pgb_proxy"; // the warden tag (PROXY_APP_NAME)

fn it_enabled() -> bool {
    std::env::var("PG_BUMPERS_IT")
        .map(|v| v == "1")
        .unwrap_or(false)
}

fn pgbin() -> String {
    std::env::var("PG_BUMPERS_PGBIN")
        .unwrap_or_else(|_| "/opt/homebrew/opt/postgresql@18/bin".to_string())
}

// --------------------------------------------------------------------------
// Live seams: the production `ActivitySource` / `Killer`, backed by a real
// PG18 admin connection. These are what `main` wires at start-up; the test
// exercises them end-to-end.
// --------------------------------------------------------------------------

/// Reads `pg_stat_activity` + `pg_replication_slots` from a live cluster.
struct PgActivitySource {
    admin: Client,
}

impl PgActivitySource {
    fn connect(dsn: &str) -> Self {
        PgActivitySource {
            admin: Client::connect(dsn, NoTls).expect("warden admin connect"),
        }
    }
}

impl ActivitySource for PgActivitySource {
    fn observe(&mut self) -> Observation {
        // Backends: exclude our own admin connection by app_name so the warden
        // never targets itself.
        let backend_rows = self
            .admin
            .query(
                "SELECT pid,
                        coalesce(usename, '') AS usename,
                        coalesce(application_name, '') AS application_name,
                        coalesce(state, '') AS state,
                        coalesce(
                          (extract(epoch FROM (now() - query_start)) * 1000)::bigint, 0
                        ) AS runtime_ms,
                        coalesce(query, '') AS query
                   FROM pg_stat_activity
                  WHERE pid <> pg_backend_pid()
                    AND backend_type = 'client backend'
                    AND application_name <> 'pgb_warden_admin'",
                &[],
            )
            .expect("query pg_stat_activity");
        let backends = backend_rows
            .iter()
            .map(|r| {
                let runtime_ms: i64 = r.get("runtime_ms");
                Backend {
                    pid: r.get("pid"),
                    usename: r.get("usename"),
                    application_name: r.get("application_name"),
                    state: r.get("state"),
                    query_runtime_millis: runtime_ms.max(0) as u64,
                    query: r.get("query"),
                }
            })
            .collect();

        // Replication slots + retained WAL bytes.
        let slot_rows = self
            .admin
            .query(
                "SELECT slot_name,
                        slot_type,
                        coalesce(active, false) AS active,
                        coalesce(
                          pg_wal_lsn_diff(pg_current_wal_lsn(), restart_lsn), 0
                        )::bigint AS retained
                   FROM pg_replication_slots",
                &[],
            )
            .expect("query pg_replication_slots");
        let slots = slot_rows
            .iter()
            .map(|r| {
                let retained: i64 = r.get("retained");
                ReplicationSlot {
                    slot_name: r.get("slot_name"),
                    slot_type: r.get("slot_type"),
                    active: r.get("active"),
                    retained_wal_bytes: retained.max(0) as u64,
                }
            })
            .collect();

        Observation {
            backends,
            slots,
            replication_lag_bytes: 0,
        }
    }
}

/// Terminates a backend via `pg_terminate_backend` on a live cluster.
struct PgKiller {
    admin: Client,
    killed: Vec<i32>,
}

impl PgKiller {
    fn connect(dsn: &str) -> Self {
        PgKiller {
            admin: Client::connect(dsn, NoTls).expect("warden killer connect"),
            killed: Vec::new(),
        }
    }
}

impl Killer for PgKiller {
    fn terminate(&mut self, pid: i32) {
        // pg_terminate_backend returns bool; ignore the (rare) race where the
        // backend already exited.
        let _ = self.admin.query("SELECT pg_terminate_backend($1)", &[&pid]);
        self.killed.push(pid);
    }
}

// --------------------------------------------------------------------------
// Throwaway cluster harness — a dedicated high port; NEVER 5432.
// --------------------------------------------------------------------------

struct ThrowawayCluster {
    datadir: std::path::PathBuf,
    port: u16,
    owns: bool, // true if we initdb'd + started it (so we tear it down)
}

impl ThrowawayCluster {
    /// Stand up (or attach to an override) a throwaway PG18 cluster.
    fn up() -> (Self, String) {
        if let Ok(dsn) = std::env::var("PG_BUMPERS_WARDEN_PGURL") {
            // Attach mode: an external local-stack primary. We don't own it.
            return (
                ThrowawayCluster {
                    datadir: std::path::PathBuf::new(),
                    port: 0,
                    owns: false,
                },
                dsn,
            );
        }
        let port: u16 = 54362; // dedicated warden IT port (never 5432)
        let datadir = std::env::temp_dir().join(format!("pgb-warden-it-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&datadir);
        std::fs::create_dir_all(&datadir).unwrap();

        let bin = pgbin();
        // initdb (trust auth on loopback so the test connects without a
        // password). The datadir must be empty for initdb, so write nothing
        // into it beforehand.
        let status = Command::new(format!("{bin}/initdb"))
            .args([
                "-D",
                datadir.to_str().unwrap(),
                "-U",
                "postgres",
                "--auth=trust",
                "--no-sync",
            ])
            .status()
            .expect("run initdb");
        assert!(status.success(), "initdb failed");

        // Start the postmaster on the dedicated port, loopback only, with
        // logical replication enabled (so we can create a logical slot).
        let status = Command::new(format!("{bin}/pg_ctl"))
            .args([
                "-D",
                datadir.to_str().unwrap(),
                "-o",
                &format!(
                    "-p {port} -c listen_addresses=127.0.0.1 -c wal_level=logical \
                     -c max_replication_slots=8 -c max_wal_senders=8 -c unix_socket_directories=''"
                ),
                "-w",
                "-l",
                datadir.join("server.log").to_str().unwrap(),
                "start",
            ])
            .status()
            .expect("run pg_ctl start");
        assert!(status.success(), "pg_ctl start failed");

        let dsn = format!("host=127.0.0.1 port={port} user=postgres dbname=postgres");
        (
            ThrowawayCluster {
                datadir,
                port,
                owns: true,
            },
            dsn,
        )
    }
}

impl Drop for ThrowawayCluster {
    fn drop(&mut self) {
        if !self.owns {
            return;
        }
        let bin = pgbin();
        let _ = Command::new(format!("{bin}/pg_ctl"))
            .args([
                "-D",
                self.datadir.to_str().unwrap(),
                "-m",
                "immediate",
                "-w",
                "stop",
            ])
            .status();
        let _ = std::fs::remove_dir_all(&self.datadir);
        eprintln!(
            "[warden-it] torn down throwaway cluster on port {} (NEVER touched 5432)",
            self.port
        );
    }
}

/// Spawn a backend that runs a long `pg_sleep` with a given role + app_name,
/// returning its pid (read from a side channel) so the test can assert on it.
fn spawn_sleeper(dsn: &str, app_name: &str, label: &str) -> (thread::JoinHandle<()>, i32) {
    let pid = Arc::new(Mutex::new(0i32));
    let pid_w = Arc::clone(&pid);
    let dsn_app = format!("{dsn} application_name={app_name}");
    let handle = thread::spawn(move || {
        let mut c = match Client::connect(&dsn_app, NoTls) {
            Ok(c) => c,
            Err(_) => return,
        };
        let row = c.query_one("SELECT pg_backend_pid()", &[]).unwrap();
        *pid_w.lock().unwrap() = row.get::<_, i32>(0);
        // Long sleep; the warden should terminate the agent-tagged one. The
        // terminate aborts this query (it returns an error) — that's expected.
        let _ = c.batch_execute("SELECT pg_sleep(60)");
    });
    // Wait for the backend to register its pid.
    let start = Instant::now();
    loop {
        {
            let p = *pid.lock().unwrap();
            if p != 0 {
                eprintln!("[warden-it] spawned {label} backend pid={p} app={app_name}");
                return (handle, p);
            }
        }
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "{label} sleeper never registered a pid"
        );
        thread::sleep(Duration::from_millis(20));
    }
}

/// Wait until the backend's running query has accrued at least `min_ms`
/// runtime, so the warden's runtime ceiling can be set below it deterministically.
fn wait_for_runtime(admin: &mut Client, pid: i32, min_ms: u64) {
    let start = Instant::now();
    loop {
        let rows = admin
            .query(
                "SELECT coalesce(
                          (extract(epoch FROM (now() - query_start)) * 1000)::bigint, 0)
                   FROM pg_stat_activity WHERE pid = $1 AND state = 'active'",
                &[&pid],
            )
            .unwrap();
        if let Some(r) = rows.first() {
            let ms: i64 = r.get(0);
            if ms as u64 >= min_ms {
                return;
            }
        }
        assert!(
            start.elapsed() < Duration::from_secs(15),
            "backend {pid} never reached {min_ms}ms runtime"
        );
        thread::sleep(Duration::from_millis(50));
    }
}

fn backend_present(admin: &mut Client, pid: i32) -> bool {
    let rows = admin
        .query("SELECT 1 FROM pg_stat_activity WHERE pid = $1", &[&pid])
        .unwrap();
    !rows.is_empty()
}

#[test]
fn warden_kills_agent_tagged_runaway_and_spares_shared_and_alarms_slot() {
    if !it_enabled() {
        eprintln!("[skip] warden_it: set PG_BUMPERS_IT=1 to run against live PG18");
        return;
    }

    let (cluster, dsn) = ThrowawayCluster::up();

    // Admin connections: one for the warden's source/killer, one for the test's
    // own assertions (tagged so the source excludes it).
    let admin_app_dsn = format!("{dsn} application_name=pgb_warden_admin");
    let mut test_admin = Client::connect(&admin_app_dsn, NoTls).expect("test admin connect");

    // --- Fixture: a logical replication slot (the slot-exfil / WAL-DoS watch).
    test_admin
        .batch_execute(
            "SELECT pg_create_logical_replication_slot('agent_exfil_slot', 'test_decoding')",
        )
        .expect("create logical slot");

    // --- Spawn two real runaways: one AGENT-TAGGED, one SHARED (non-agent).
    // Both connect as `postgres` here (the throwaway cluster has no WALL role);
    // the warden's targeting keys on the proxy `application_name` tag, which the
    // agent-tagged one carries and the shared one does not. (In the live system
    // the un-strippable anchor is additionally the `pgb_agent` role; the
    // application_name tag is the portable half exercised here.)
    let (agent_handle, agent_pid) = spawn_sleeper(&dsn, AGENT_APP_NAME, "agent-tagged");
    let (shared_handle, shared_pid) = spawn_sleeper(&dsn, "some_shared_app", "shared");

    // Let both queries accrue runtime so a low ceiling classifies them runaway.
    wait_for_runtime(&mut test_admin, agent_pid, 500);
    wait_for_runtime(&mut test_admin, shared_pid, 500);

    // --- Build the live source + killer and assess one observation.
    let mut source = PgActivitySource::connect(&admin_app_dsn);
    let mut killer = PgKiller::connect(&admin_app_dsn);

    // Ceiling 200ms: both runaways exceed it; only the agent-tagged is killed.
    let thresholds = WardenThresholds {
        poll_interval_millis: 1_000,
        max_query_runtime_millis: 200,
        // Set the slot alarm to 0-ish so ANY retained WAL alarms (a fresh slot
        // retains a small but non-zero amount; we just want the detection).
        slot_retained_wal_alarm_bytes: 1,
        breaker_lag_trip_bytes: 1,
        breaker_runaway_trip_count: 99, // don't trip on volume in this test
        breaker_cooldown_millis: 5_000,
    };

    let obs = source.observe();
    eprintln!(
        "[warden-it] observed {} backends, {} slots",
        obs.backends.len(),
        obs.slots.len()
    );
    let decision = assess(&obs, &thresholds);
    eprintln!(
        "[warden-it] assess -> terminate={:?} spared_non_agent={:?} slot_alarms={:?}",
        decision.to_terminate, decision.spared_non_agent, decision.slot_alarms
    );

    // The agent-tagged pid is targeted; the shared pid is spared.
    assert!(
        decision.to_terminate.contains(&agent_pid),
        "agent-tagged runaway {agent_pid} must be targeted; got {:?}",
        decision.to_terminate
    );
    assert!(
        !decision.to_terminate.contains(&shared_pid),
        "shared runaway {shared_pid} must NOT be targeted (no false-positive kill)"
    );
    assert!(
        decision.spared_non_agent.contains(&shared_pid),
        "shared runaway {shared_pid} must be recorded as spared"
    );

    // The slot is detected + alarmed.
    assert!(
        decision
            .slot_alarms
            .iter()
            .any(|(name, _)| name == "agent_exfil_slot"),
        "replication slot must be detected + alarmed; got {:?}",
        decision.slot_alarms
    );

    // --- Apply the kill decision via the live killer, then prove the agent
    // backend is gone and the shared backend survives.
    for pid in &decision.to_terminate {
        killer.terminate(*pid);
    }
    assert_eq!(
        killer.killed,
        vec![agent_pid],
        "killer only saw the agent pid"
    );

    // Poll until the agent backend disappears (terminate is async-ish).
    let start = Instant::now();
    while backend_present(&mut test_admin, agent_pid) {
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "agent backend {agent_pid} was not terminated"
        );
        thread::sleep(Duration::from_millis(50));
    }
    eprintln!("[warden-it] agent backend {agent_pid} terminated ✓");
    assert!(
        backend_present(&mut test_admin, shared_pid),
        "shared backend {shared_pid} must STILL be present (left alone) ✓"
    );
    eprintln!("[warden-it] shared backend {shared_pid} left alone ✓");

    // --- Teardown: terminate the shared sleeper, drop the slot, join threads.
    let _ = test_admin.query("SELECT pg_terminate_backend($1)", &[&shared_pid]);
    let _ = test_admin.batch_execute("SELECT pg_drop_replication_slot('agent_exfil_slot')");
    let _ = agent_handle.join();
    let _ = shared_handle.join();
    drop(cluster); // explicit teardown of the throwaway cluster

    eprintln!(
        "[warden-it] PASS — agent-tagged killed, shared spared, slot alarmed, 5432 untouched"
    );
}
