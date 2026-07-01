//! pg_brakes **proxy** — the inline, agent-only enforcement point (SPEC §3
//! layer 2, §4, §7 S1). This is the project's core IP.
//!
//! The proxy terminates an agent's PostgreSQL connection (SCRAM-SHA-256 over
//! TLS), opens a **separate** backend connection to PG18 as the hardened WALL
//! role `pgb_agent` (the only network path to the DB — SPEC §3 layer 0), and
//! drives the FE/BE message loop through [`crate::pgwire`]-level framing with
//! the deterministic-floor enforcement hooks wired in:
//!
//! 1. **extended-protocol-only** — reject the simple `Query` ('Q') path and all
//!    `COPY` traffic, which kills `COMMIT; DROP SCHEMA …` statement-stacking;
//! 2. **read-only** — classify each `Parse` SQL; non-`Read` is blocked. This is
//!    the **real gate** for the function-call write class (M2a #114): a `SELECT`
//!    is a read only if every function it references is on a curated read-safe
//!    allowlist, so `SELECT lo_create(…)`/`setval(…)`/`public.writing_fn()` are
//!    Blocked here, never forwarded. The WALL role remains the un-foolable
//!    backstop for the rest;
//! 3. **EXPLAIN-cost gate** ([`explain`]) — before a read executes, run
//!    `EXPLAIN` (no `ANALYZE`) and block pre-flight if the planner's estimated
//!    cost/rows exceed the per-role ceiling (advisory + fail-closed);
//! 4. **byte/row mid-stream cutoff** — count `DataRow` bytes/rows from the
//!    backend and cut the stream off at the per-role budget from `policy.yaml`;
//! 5. **cumulative per-window volume budget** ([`window`]) — accumulate
//!    bytes/rows streamed across statements and kill the session when the
//!    rolling-window budget is exceeded (anti slow-drip, deterministic clock);
//! 6. **timeout injection** — `SET statement_timeout` on the backend session;
//! 7. **fail-closed** — any parse/enforcement uncertainty denies;
//! 8. **audit** — every statement (allow/block/reject) is recorded on a
//!    hash-chained [`pgb_audit`] chain.
//!
//! ## Threat-model note (from the pgwire review; updated for M2a #114)
//! The read-only classifier now **fail-closes on non-allowlisted function calls**:
//! a `SELECT` is a `Read` only if EVERY function it references (anywhere in the
//! statement AST — projection, `WHERE`/`HAVING`/`GROUP BY`/`ORDER BY`, JOIN `ON`,
//! aggregate `FILTER`/`ORDER BY`, subqueries, CTEs, function arguments, and
//! table-valued functions in `FROM`/`JOIN`) is on a curated read-safe allowlist.
//! So the previously "foolable" side-effecting functions —
//! `nextval`/`setval`/`pg_sleep`/`lo_export`/`lo_create`/`pg_read_file`/`dblink`
//! and EVERY user/unknown/qualified `schema.fn()` (including a SECURITY DEFINER
//! write fn) — now classify `NotRead` and are **Blocked at this gate**, no longer
//! forwarded to the backend. This is what lets the DB-level `REVOKE … FROM PUBLIC`
//! backstop be dropped from a BYO-prod default (M2) without reopening the
//! catastrophic-FN path. The other un-foolable guarantees — the **WALL hardened
//! role**, **`statement_timeout`**, and the **byte/row cutoff** — remain in place,
//! all fail-closed, so the classifier is still defense-in-depth, not the sole gate.
//!
//! ## Clean-room note
//! Built from the SPEC and the public PostgreSQL v3 protocol / RFC 5802+7677
//! only. No pgDog (AGPL) code was consulted or copied.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod auth;
pub mod budget;
pub mod config;
pub mod enforce;
pub mod explain;
pub mod recorder;
pub mod session;
pub mod threaded_sink;
pub mod tls;
pub mod window;

pub use budget::{Budget, BudgetOutcome};
pub use config::ProxyConfig;
pub use enforce::{Enforcement, GateDecision, RejectKind};
pub use explain::{
    EstimateDecision, EstimateDim, ExplainCeiling, ExplainGate, PlanEstimate, explain_wrap,
};
pub use recorder::Recorder;
pub use session::{SessionError, serve_connection};
pub use threaded_sink::ThreadedSink;
pub use window::{WindowCap, WindowMeter, WindowOutcome};
