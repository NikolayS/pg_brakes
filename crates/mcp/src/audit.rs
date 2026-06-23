//! `get_audit` — a READ-THROUGH to the hash-chained `_meta` audit tail (SPEC §4).
//!
//! The TS `get_audit` reads the audit tail through the write daemon; this Rust
//! read-path analogue reads the SAME canonical `_meta` chain directly, REUSING the
//! audit crate ([`pgb_audit::PgSink`] + the record types) — it does NOT
//! re-implement the chain. The records come back oldest-first; we return the last
//! `limit` of them (the tail), each projected to the compact wire shape the TS
//! `get_audit` returns (`seq` / `decision` / `statement_class`).
//!
//! The `_meta` reader connects as a genuinely SELECT-only audit role —
//! `pgb_audit_reader`, which has `SELECT` on the chain but NO `INSERT`/`UPDATE`/
//! `DELETE` (see `crates/audit/sql/10_audit_meta.sql`). So the credential the
//! agent-facing `pgb-mcp` process holds for `get_audit` can read the audit tail but
//! can NEVER write/forge it — never the audit *writer*, and never the audited agent
//! (which is `REVOKE`d from the audit table entirely). The `postgres` crate is
//! synchronous (it drives its own internal runtime), so every read runs on a
//! `spawn_blocking` thread, off the MCP server's tokio runtime.

use pgb_audit::{PgSink, Sink};

use crate::contract::BlockContract;

/// Connection details for the SELECT-only `_meta` audit reader. Mirrors the
/// `PGB_META_DSN` the deploy stack forwards to the agent process — which is the
/// `pgb_audit_reader` reader DSN (a role that can `SELECT` the audit table but holds
/// no write privilege, and is never the audited agent or the audit writer).
#[derive(Debug, Clone)]
pub struct AuditConfig {
    /// The `_meta` reader DSN (keyword/value, e.g.
    /// `host=… port=… user=pgb_audit_reader password=… dbname=postgres`).
    pub dsn: String,
}

/// One projected audit record on the `get_audit` wire (mirrors the TS shape).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct AuditRecordView {
    /// The chain sequence number.
    pub seq: u64,
    /// The decision (`ALLOW` / `BLOCK` / `REJECT`).
    pub decision: String,
    /// The statement-class / reason code recorded for the decision.
    pub statement_class: String,
}

/// The audit-tail reader. Holds only the reader DSN; it opens a short-lived sync
/// connection per read on a blocking thread (the chain is small and reads are
/// infrequent — no need for a resident connection, and it avoids holding a sync
/// `postgres` client across the async boundary).
#[derive(Debug, Clone)]
pub struct AuditReader {
    config: AuditConfig,
}

impl AuditReader {
    /// Build a reader for the given `_meta` reader DSN.
    pub fn new(config: AuditConfig) -> Self {
        AuditReader { config }
    }

    /// Read the audit tail: up to `limit` most-recent records, oldest-first within
    /// the returned window. Returns a recoverable block on a connect/read failure
    /// (the `_meta` DB being unreachable is recoverable, not a crash).
    pub async fn tail(&self, limit: usize) -> Result<Vec<AuditRecordView>, BlockContract> {
        let dsn = self.config.dsn.clone();
        let limit = clamp_limit(limit);
        // The sync `postgres` client must run off the tokio runtime.
        let result =
            tokio::task::spawn_blocking(move || -> Result<Vec<AuditRecordView>, String> {
                let mut sink = PgSink::connect(&dsn).map_err(|e| e.to_string())?;
                // REUSE the audit crate's chain read — no re-implementation.
                let chain = sink.load_chain_mut().map_err(|e| e.to_string())?;
                let total = chain.len();
                let start = total.saturating_sub(limit);
                let view = chain[start..]
                    .iter()
                    .map(|rec| AuditRecordView {
                        seq: rec.payload.seq,
                        decision: format!("{:?}", rec.payload.decision).to_uppercase(),
                        statement_class: rec.payload.reason_code.clone(),
                    })
                    .collect();
                Ok(view)
            })
            .await;

        match result {
            Ok(Ok(records)) => Ok(records),
            Ok(Err(detail)) => Err(BlockContract::new(
                "AUDIT_UNAVAILABLE",
                format!("the `_meta` audit tail could not be read: {detail}"),
                "the audit `_meta` DB may be unreachable or unconfigured; retry, \
                 or check PGB_META_DSN / the reader role's SELECT grant",
                true,
            )),
            Err(join_err) => Err(BlockContract::new(
                "AUDIT_UNAVAILABLE",
                format!("the audit read task failed: {join_err}"),
                "retry the get_audit call",
                true,
            )),
        }
    }
}

/// Clamp `get_audit`'s limit to a sane window (fail-closed default), matching the
/// TS `clampLimit`: 0/garbage ⇒ 50; otherwise capped at 1000.
fn clamp_limit(limit: usize) -> usize {
    if limit == 0 {
        return 50;
    }
    limit.min(1000)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clamp_limit_matches_the_ts_window() {
        assert_eq!(clamp_limit(0), 50, "0 ⇒ the default 50");
        assert_eq!(clamp_limit(10), 10);
        assert_eq!(clamp_limit(100_000), 1000, "capped at 1000");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn tail_against_an_unreachable_meta_is_a_recoverable_block() {
        // Nothing listens on port 1 — the read must come back as a RECOVERABLE
        // block, never a crash.
        let reader = AuditReader::new(AuditConfig {
            dsn: "host=127.0.0.1 port=1 user=pgb_audit_writer password=x dbname=postgres \
                  connect_timeout=1"
                .into(),
        });
        let block = reader.tail(10).await.unwrap_err();
        assert_eq!(block.code, "AUDIT_UNAVAILABLE");
        assert!(block.retryable, "an unreachable _meta DB is retryable");
    }
}
