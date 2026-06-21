//! pg_bumpers **proxy** — the inline, agent-only enforcement point (SPEC §3
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
//! 2. **read-only** — classify each `Parse` SQL; non-`Read` is blocked
//!    (advisory — the WALL role is the un-foolable backstop);
//! 3. **byte/row mid-stream cutoff** — count `DataRow` bytes/rows from the
//!    backend and cut the stream off at the per-role budget from `policy.yaml`;
//! 4. **timeout injection** — `SET statement_timeout` on the backend session;
//! 5. **fail-closed** — any parse/enforcement uncertainty denies;
//! 6. **audit** — every statement (allow/block/reject) is recorded on a
//!    hash-chained [`pgb_audit`] chain.
//!
//! ## Threat-model note (from the pgwire review)
//! The read-only classifier is **advisory and foolable** (side-effecting
//! functions like `nextval`/`pg_sleep`/`lo_export` classify as `Read`). The
//! un-foolable guarantees the proxy *relies* on are the **WALL hardened role**,
//! **`statement_timeout`**, and the **byte/row cutoff** — all fail-closed. The
//! classifier is defense-in-depth, never the sole gate.
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
pub mod recorder;
pub mod session;
pub mod tls;

pub use budget::{Budget, BudgetOutcome};
pub use config::ProxyConfig;
pub use enforce::{Enforcement, GateDecision, RejectKind};
pub use recorder::Recorder;
pub use session::{serve_connection, SessionError};
