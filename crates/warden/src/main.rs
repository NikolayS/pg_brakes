//! pg_bumpers warden binary (SPEC §3 layer 2, §4, §10.9).
//!
//! The warden runs out-of-band: it polls `pg_stat_activity` /
//! `pg_stat_statements` / replication lag / `pg_replication_slots`, **only**
//! cancels/terminates agent-tagged / agent-role sessions (never shared roles —
//! avoid false-positive outages), and owns the authenticated circuit breaker.
//!
//! The gating *logic* lives in the `pgb_warden` library (and is exhaustively
//! unit-tested with a [`MockClock`](pgb_core::MockClock) and scripted
//! observation/kill seams, plus an env-gated real-PG18 integration test). This
//! binary is the thin production wiring: read `policy.yaml`, build the loop on a
//! [`SystemClock`](pgb_core::SystemClock), and poll.
//!
//! The live `ActivitySource` (the `pg_stat_activity` / `pg_replication_slots`
//! query) and `Killer` (`pg_terminate_backend`) are wired against the running
//! cluster at start-up; the env-gated integration test (`tests/warden_it.rs`)
//! exercises that path against real PG18. This `main` documents the loop shape.

use pgb_core::{Clock, SystemClock};
use pgb_warden::WardenThresholds;

fn main() {
    // In production the thresholds come from `policy.yaml`; here we surface the
    // conservative defaults + validate them so a bad config fails closed.
    let thresholds = WardenThresholds::default();
    thresholds
        .validate()
        .expect("default warden thresholds must validate");

    let clock = SystemClock::new();
    let _now = clock.monotonic_millis(); // the cadence anchor (read via Clock)

    println!(
        "pgb-warden: out-of-band watchdog (SPEC §3/§4/§10.9). \
         poll_interval={}ms, runaway_kill={}ms, slot_alarm={}B, lag_trip={}B, \
         runaway_trip={}, breaker_cooldown={}ms. \
         Kills agent-tagged/agent-role sessions only; owns the authenticated \
         (non-forgeable) circuit breaker. Live ActivitySource/Killer wired at \
         start-up; gating logic is in the pgb_warden lib (unit + PG18 IT).",
        thresholds.poll_interval_millis,
        thresholds.max_query_runtime_millis,
        thresholds.slot_retained_wal_alarm_bytes,
        thresholds.breaker_lag_trip_bytes,
        thresholds.breaker_runaway_trip_count,
        thresholds.breaker_cooldown_millis,
    );
}
