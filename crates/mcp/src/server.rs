//! The rmcp [`ServerHandler`] implementation: the §4 nine-tool MCP server.
//!
//! EPIC #83 PR2 wires the **read path** through the live `pgb-proxy`:
//!   - `whoami` — the §3 posture (`security_boundary: false`, role/session, tools).
//!   - `query` — a read THROUGH the proxy. Before sending, the cooperative
//!     read-only/anti-stacking fast-path REUSES the canonical Rust classifier
//!     (`pgb_pgwire::classify`); a write/DDL/stacked statement → a recoverable
//!     `READ_ONLY` block (the proxy enforces independently — the MCP classifier is
//!     a cooperative fast-path, not the boundary).
//!   - `explain_plan` — `EXPLAIN (FORMAT JSON)` (never ANALYZE) of a read, through
//!     the proxy, gated by the SAME read-only guard as `query`. The TS explain-hole
//!     (raw SQL into `EXPLAIN`) is NOT reproduced: a non-read inner statement is
//!     blocked before it can reach the wire.
//!   - `discover_schema` — the agent-visible `information_schema`, through the proxy.
//!   - `get_audit` — a read-through to the hash-chained `_meta` audit tail.
//!   - the four write tools (`propose_write`/`dry_run`/`apply_write`/
//!     `request_elevation`) stay UNIMPLEMENTED blocks (PR3).
//!
//! Honesty (SPEC §3): this server is COOPERATIVE, NOT a security boundary. It adds
//! no privilege; reads go through the proxy/WALL (the real boundary). Result data
//! is opaque — never interpreted as instruction or hoisted into a control field,
//! so injection-via-data can never widen capability (SPEC §4, §11.4#5).

use std::sync::Arc;

use rmcp::{
    ErrorData as McpError, ServerHandler,
    model::{
        CallToolRequestParams, CallToolResult, Implementation, InitializeResult, ListToolsResult,
        PaginatedRequestParams, ProtocolVersion, ServerCapabilities, ServerInfo, Tool,
    },
    service::{RequestContext, RoleServer},
};

use crate::audit::AuditReader;
use crate::catalog::{ToolSpec, catalog};
use crate::contract::{BlockContract, WhoamiResult};
use crate::proxy::{PlanJson, ProxyTransport, ReadOutcome, SchemaColumn};

/// The MCP server name advertised in `initialize` (the `serverInfo.name`).
pub const SERVER_NAME: &str = "pg-bumpers-mcp";

/// The protocol version this server speaks. `2024-11-05` is the widely-supported
/// MCP revision the TS server advertised; we keep it for client compatibility.
const PROTOCOL_VERSION: ProtocolVersion = ProtocolVersion::V_2024_11_05;

/// The §4 nine-tool MCP server.
///
/// Stateless by construction (SPEC §4): it holds only the session identity
/// (`role` / `session_id`) used by `whoami`, the **live proxy transport** the read
/// tools execute through, and the read-only `_meta` audit reader. Proposal /
/// ticket / write state lives behind the floor (applyd), never in this process.
#[derive(Clone)]
pub struct PgBumpersMcp {
    /// The authenticated role (T0), from `PGB_ROLE`. `whoami` reports it; the
    /// server never elevates beyond it.
    role: String,
    /// The session/principal id, from `PGB_SESSION_ID`.
    session_id: String,
    /// The live wire to `pgb-proxy` the read tools execute through. `None` when no
    /// proxy is configured (e.g. the bare skeleton / a unit test without a proxy),
    /// in which case the read tools return a recoverable `PROXY_UNAVAILABLE` block
    /// — honest, never a panic.
    proxy: Option<ProxyTransport>,
    /// The read-only `_meta` audit-tail reader `get_audit` uses. `None` when no
    /// `_meta` reader is configured (then `get_audit` returns a recoverable block).
    audit: Option<AuditReader>,
}

impl std::fmt::Debug for PgBumpersMcp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PgBumpersMcp")
            .field("role", &self.role)
            .field("session_id", &self.session_id)
            .field("proxy", &self.proxy.is_some())
            .field("audit", &self.audit.is_some())
            .finish()
    }
}

impl PgBumpersMcp {
    /// Construct a server bound to a `role` + `session_id`, with NO proxy/audit
    /// wired (the read tools then return a recoverable `PROXY_UNAVAILABLE` block).
    /// Used by unit tests and the bare skeleton.
    pub fn new(role: impl Into<String>, session_id: impl Into<String>) -> Self {
        PgBumpersMcp {
            role: role.into(),
            session_id: session_id.into(),
            proxy: None,
            audit: None,
        }
    }

    /// Attach the live proxy transport the read tools (`query` / `explain_plan` /
    /// `discover_schema`) execute through.
    pub fn with_proxy(mut self, proxy: ProxyTransport) -> Self {
        self.proxy = Some(proxy);
        self
    }

    /// Attach the read-only `_meta` audit-tail reader `get_audit` uses.
    pub fn with_audit(mut self, audit: AuditReader) -> Self {
        self.audit = Some(audit);
        self
    }

    /// Build the `whoami` posture result (SPEC §3 honesty contract).
    fn whoami(&self) -> WhoamiResult {
        WhoamiResult::new(&self.role, &self.session_id, &crate::catalog::TOOL_NAMES)
    }

    /// The recoverable block returned when a read tool is asked to run but no proxy
    /// is wired (config-less skeleton / unit test) — honest, retryable.
    fn no_proxy_block() -> BlockContract {
        BlockContract::proxy_unavailable(
            "no proxy endpoint is configured (set PGB_PROXY_HOST/PORT/DB/USER/PASSWORD)",
        )
    }

    /// `query`: a read THROUGH the proxy, gated by the canonical classifier.
    async fn tool_query(&self, sql: &str) -> CallToolResult {
        // Cooperative fast-path: REUSE `pgb_pgwire::classify` (the canonical Rust
        // classifier — fail-closed, statement-stacking-proof). A write/DDL/stacked
        // statement gets a friendly recoverable READ_ONLY block instead of a
        // pointless round-trip. The proxy would reject it too (the real guarantee).
        if !pgb_pgwire::classify(sql).is_read() {
            return structured_block(&BlockContract::read_only("write/DDL or stacked statement"));
        }
        let Some(proxy) = &self.proxy else {
            return structured_block(&Self::no_proxy_block());
        };
        match proxy.query(sql).await {
            ReadOutcome::Rows { rows, row_count } => {
                // Result data lives ONLY under `rows` — never hoisted into the
                // envelope (the structural half of the injection-via-data defense).
                structured_ok(&serde_json::json!({
                    "status": "ok",
                    "rows": rows,
                    "rowCount": row_count,
                }))
            }
            ReadOutcome::Blocked(block) => structured_block(&block),
        }
    }

    /// `explain_plan`: `EXPLAIN (FORMAT JSON)` (never ANALYZE) of a read, through
    /// the proxy, gated EXACTLY like `query`. The TS explain-hole — forwarding raw
    /// SQL into `EXPLAIN ${sql}` so a stacked/write second statement would EXECUTE
    /// — is closed: a non-read inner statement is blocked before reaching the wire.
    async fn tool_explain(&self, sql: &str) -> CallToolResult {
        if !pgb_pgwire::classify(sql).is_read() {
            return structured_block(&BlockContract::read_only(
                "write/DDL or stacked statement (explain_plan plans read-only statements)",
            ));
        }
        let Some(proxy) = &self.proxy else {
            return structured_block(&Self::no_proxy_block());
        };
        match proxy.explain(sql).await {
            Ok(PlanJson { plan, cost }) => structured_ok(&serde_json::json!({
                "status": "ok",
                "plan": plan,
                "cost": cost,
            })),
            Err(block) => structured_block(&block),
        }
    }

    /// `discover_schema`: the agent-visible `information_schema`, through the proxy.
    async fn tool_discover_schema(&self) -> CallToolResult {
        let Some(proxy) = &self.proxy else {
            return structured_block(&Self::no_proxy_block());
        };
        match proxy.discover_schema().await {
            Ok(columns) => {
                let columns: Vec<SchemaColumn> = columns;
                structured_ok(&serde_json::json!({
                    "status": "ok",
                    "columns": columns,
                }))
            }
            Err(block) => structured_block(&block),
        }
    }

    /// `get_audit`: a read-through to the hash-chained `_meta` audit tail.
    async fn tool_get_audit(&self, limit: usize) -> CallToolResult {
        let Some(audit) = &self.audit else {
            return structured_block(&BlockContract::new(
                "AUDIT_UNAVAILABLE",
                "no `_meta` audit reader is configured (set PGB_META_DSN)",
                "configure the `_meta` reader DSN to read the audit tail",
                true,
            ));
        };
        match audit.tail(limit).await {
            Ok(records) => structured_ok(&serde_json::json!({
                "status": "ok",
                "records": records,
            })),
            Err(block) => structured_block(&block),
        }
    }

    /// Dispatch one `tools/call` to a structured JSON result.
    ///
    /// Fail-closed: an unknown tool name is an error. `whoami` returns its posture;
    /// the read tools execute through the proxy / `_meta` reader; the four write
    /// tools return the `UNIMPLEMENTED` block naming PR3 — never a panic.
    async fn dispatch(
        &self,
        name: &str,
        args: &serde_json::Map<String, serde_json::Value>,
    ) -> Result<CallToolResult, McpError> {
        match name {
            "whoami" => Ok(structured_ok(&self.whoami())),
            "query" => {
                let sql = arg_str(args, "sql");
                Ok(self.tool_query(&sql).await)
            }
            "explain_plan" => {
                let sql = arg_str(args, "sql");
                Ok(self.tool_explain(&sql).await)
            }
            "discover_schema" => Ok(self.tool_discover_schema().await),
            "get_audit" => {
                let limit = args
                    .get("limit")
                    .and_then(|v| v.as_u64())
                    .map(|n| n as usize)
                    .unwrap_or(0);
                Ok(self.tool_get_audit(limit).await)
            }
            // The write paths (PR3) are not wired yet; each returns the recoverable
            // UNIMPLEMENTED block, honestly tracked.
            "propose_write" | "dry_run" | "apply_write" | "request_elevation" => Ok(
                structured_block(&BlockContract::unimplemented(name, "#83 PR3")),
            ),
            other => Err(McpError::invalid_params(
                format!("no such tool: {other}"),
                None,
            )),
        }
    }
}

/// Extract a string argument by key, defaulting to empty (the classifier then
/// fail-closes an empty/garbage statement to NotRead → READ_ONLY block).
fn arg_str(args: &serde_json::Map<String, serde_json::Value>, key: &str) -> String {
    args.get(key)
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string()
}

impl ServerHandler for PgBumpersMcp {
    fn get_info(&self) -> ServerInfo {
        InitializeResult::new(ServerCapabilities::builder().enable_tools().build())
            .with_protocol_version(PROTOCOL_VERSION)
            .with_server_info(Implementation::new(SERVER_NAME, env!("CARGO_PKG_VERSION")))
            .with_instructions(
                "pg_bumpers MCP server (SPEC §3/§4). COOPERATIVE, not a security boundary: \
                 the deterministic floor (proxy + WALL + applyd + warden) is the real boundary. \
                 Call whoami to see the posture. Reads (query/explain_plan/discover_schema/\
                 get_audit) go THROUGH the proxy/_meta; writes (propose_write→dry_run→\
                 apply_write) are being wired (EPIC #83 PR3).",
            )
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, McpError> {
        Ok(ListToolsResult::with_all_items(
            catalog().into_iter().map(tool_from_spec).collect(),
        ))
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let args = request.arguments.unwrap_or_default();
        self.dispatch(request.name.as_ref(), &args).await
    }
}

/// Convert a catalog [`ToolSpec`] into an rmcp [`Tool`] for `tools/list`.
fn tool_from_spec(spec: ToolSpec) -> Tool {
    // The schema is a JSON object by construction (see `catalog`), so the
    // `as_object` cannot be `None` in practice; fall back to an empty object to
    // stay panic-free (fail-closed).
    let schema = spec.input_schema.as_object().cloned().unwrap_or_default();
    Tool::new(spec.name, spec.description, Arc::new(schema))
}

/// Wrap a serializable success payload as a success `CallToolResult`.
///
/// `CallToolResult::structured` carries the value as BOTH a JSON text block (for
/// clients that read `content`) and `structuredContent` — the result data lives
/// ONLY under those fields, never hoisted into a control position.
fn structured_ok<T: serde::Serialize>(value: &T) -> CallToolResult {
    let json = serde_json::to_value(value).unwrap_or(serde_json::Value::Null);
    CallToolResult::structured(json)
}

/// Wrap a [`BlockContract`] as an ERROR `CallToolResult` (a recoverable denial):
/// `isError: true`, the block carried as both a JSON text block and
/// `structuredContent`.
fn structured_block(block: &BlockContract) -> CallToolResult {
    let json = serde_json::to_value(block).unwrap_or(serde_json::Value::Null);
    CallToolResult::structured_error(json)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn no_args() -> serde_json::Map<String, serde_json::Value> {
        serde_json::Map::new()
    }

    fn args(pairs: &[(&str, serde_json::Value)]) -> serde_json::Map<String, serde_json::Value> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.clone()))
            .collect()
    }

    #[tokio::test]
    async fn dispatch_whoami_returns_posture_not_a_boundary() {
        let s = PgBumpersMcp::new("pgb_agent", "sess-1");
        let r = s.dispatch("whoami", &no_args()).await.unwrap();
        assert_eq!(r.is_error, Some(false));
        let sc = r.structured_content.unwrap();
        assert_eq!(sc["security_boundary"], serde_json::json!(false));
        assert_eq!(sc["role"], serde_json::json!("pgb_agent"));
        assert_eq!(sc["tools"].as_array().unwrap().len(), 9);
    }

    #[tokio::test]
    async fn query_with_a_write_is_blocked_read_only_via_the_canonical_classifier() {
        // No proxy wired: a WRITE must still be blocked by the cooperative
        // fast-path BEFORE any transport call (the classifier reuse), so it never
        // even reaches the (absent) proxy. This is the canonical-classifier reuse:
        // a DROP/DELETE/stacked statement → READ_ONLY.
        let s = PgBumpersMcp::new("pgb_agent", "sess-1");
        for sql in [
            "DROP TABLE orders",
            "DELETE FROM orders WHERE id = 1",
            "UPDATE orders SET x = 1",
            "SELECT 1; DROP TABLE orders", // statement-stacking
            "WITH x AS (DELETE FROM orders RETURNING id) SELECT * FROM x", // data-modifying CTE
            "TRUNCATE orders",
        ] {
            let r = s
                .dispatch("query", &args(&[("sql", serde_json::json!(sql))]))
                .await
                .unwrap();
            assert_eq!(r.is_error, Some(true), "`{sql}` must be blocked");
            let sc = r.structured_content.unwrap();
            assert_eq!(
                sc["code"],
                serde_json::json!("READ_ONLY"),
                "`{sql}` → READ_ONLY"
            );
            assert_eq!(sc["status"], serde_json::json!("blocked"));
            assert_eq!(sc["retryable"], serde_json::json!(false));
        }
    }

    #[tokio::test]
    async fn explain_plan_gates_writes_exactly_like_query_the_hole_is_closed() {
        // The TS explain-hole: a write/stacked statement forwarded into
        // `EXPLAIN ${sql}` would EXECUTE the second statement. Here a non-read
        // inner statement is blocked by the SAME classifier guard before it can
        // reach the wire — proving the explain path can NEVER execute a write.
        let s = PgBumpersMcp::new("pgb_agent", "sess-1");
        for sql in [
            "DROP TABLE orders",
            "SELECT 1; DROP TABLE orders",
            "DELETE FROM orders",
            "INSERT INTO orders VALUES (1)",
            // REV bug-hunter (HIGH): the British synonym `ANALYSE` EXECUTES the
            // inner statement on PG18 (proven live: it mutates/deletes/side-
            // effects), so the MCP fast-path must refuse it BEFORE it reaches the
            // wire — exactly like `ANALYZE`. SERIALIZE also executes; any unknown
            // option fails closed.
            "EXPLAIN (ANALYSE) SELECT 1",
            "EXPLAIN (ANALYSE) UPDATE orders SET id = id",
            "EXPLAIN (ANALYSE) DELETE FROM orders",
            "EXPLAIN (FORMAT JSON, ANALYSE) SELECT 1",
            "EXPLAIN (SERIALIZE) SELECT 1",
            "EXPLAIN (FROBNICATE) SELECT 1",
        ] {
            let r = s
                .dispatch("explain_plan", &args(&[("sql", serde_json::json!(sql))]))
                .await
                .unwrap();
            assert_eq!(
                r.is_error,
                Some(true),
                "explain_plan(`{sql}`) must be blocked"
            );
            let sc = r.structured_content.unwrap();
            assert_eq!(
                sc["code"],
                serde_json::json!("READ_ONLY"),
                "explain_plan(`{sql}`) → READ_ONLY (the hole is closed)"
            );
        }
    }

    #[tokio::test]
    async fn query_fast_path_refuses_explain_analyse_executes() {
        // The `query` fast-path shares the SAME `pgb_pgwire::classify` chokepoint,
        // so it too must refuse `EXPLAIN (ANALYSE) …` (which EXECUTES on PG18)
        // before it can reach the proxy. Proves both fast-path entry points
        // (`query` + `explain_plan`) are covered by the single fix.
        let s = PgBumpersMcp::new("pgb_agent", "sess-1");
        for sql in [
            "EXPLAIN (ANALYSE) SELECT 1",
            "EXPLAIN (ANALYSE) UPDATE orders SET id = id",
            "EXPLAIN (SERIALIZE) SELECT 1",
            "EXPLAIN (FROBNICATE) SELECT 1",
        ] {
            let r = s
                .dispatch("query", &args(&[("sql", serde_json::json!(sql))]))
                .await
                .unwrap();
            assert_eq!(r.is_error, Some(true), "query(`{sql}`) must be blocked");
            let sc = r.structured_content.unwrap();
            assert_eq!(
                sc["code"],
                serde_json::json!("READ_ONLY"),
                "query(`{sql}`) → READ_ONLY (fast-path refuses the executing EXPLAIN)"
            );
        }
    }

    #[tokio::test]
    async fn a_clean_read_passes_the_classifier_then_hits_the_proxy() {
        // With no proxy wired, a CLEAN read passes the classifier (it is NOT
        // blocked READ_ONLY) and then surfaces the recoverable PROXY_UNAVAILABLE —
        // proving the read was allowed by the fast-path and routed to the proxy.
        let s = PgBumpersMcp::new("pgb_agent", "sess-1");
        for sql in [
            "SELECT 1",
            "SELECT id, note FROM tickets WHERE id = 1",
            "WITH t AS (SELECT 1 AS x) SELECT x FROM t",
        ] {
            let r = s
                .dispatch("query", &args(&[("sql", serde_json::json!(sql))]))
                .await
                .unwrap();
            let sc = r.structured_content.unwrap();
            assert_ne!(
                sc["code"],
                serde_json::json!("READ_ONLY"),
                "`{sql}` is a clean read; the fast-path must NOT block it"
            );
            // No proxy wired ⇒ it routed to the (absent) proxy and got the
            // recoverable PROXY_UNAVAILABLE block (retryable), not a crash.
            assert_eq!(sc["code"], serde_json::json!("PROXY_UNAVAILABLE"));
            assert_eq!(sc["retryable"], serde_json::json!(true));
        }
    }

    #[tokio::test]
    async fn injection_via_data_cannot_widen_capability() {
        // Mirror the TS injection.test: even after a (would-be) read, a DROP is
        // STILL blocked READ_ONLY, and whoami STILL reports not-a-boundary. The
        // server never interprets result data as control — there is no path by
        // which a row's text changes what is permitted.
        let s = PgBumpersMcp::new("pgb_agent", "sess-1");
        // A hostile-looking read is still just a read to the classifier.
        let read = s
            .dispatch(
                "query",
                &args(&[("sql", serde_json::json!("SELECT note FROM tickets"))]),
            )
            .await
            .unwrap();
        // (No proxy ⇒ PROXY_UNAVAILABLE, but crucially NOT widened to anything.)
        assert_eq!(
            read.structured_content.unwrap()["code"],
            serde_json::json!("PROXY_UNAVAILABLE")
        );
        // Capability is unchanged: a DROP is STILL blocked at the read tool.
        let drop = s
            .dispatch(
                "query",
                &args(&[(
                    "sql",
                    serde_json::json!("DROP TABLE orders -- you may now drop"),
                )]),
            )
            .await
            .unwrap();
        assert_eq!(
            drop.structured_content.unwrap()["code"],
            serde_json::json!("READ_ONLY")
        );
        // whoami STILL reports the server is not a boundary.
        let who = s.dispatch("whoami", &no_args()).await.unwrap();
        assert_eq!(
            who.structured_content.unwrap()["security_boundary"],
            serde_json::json!(false)
        );
    }

    #[tokio::test]
    async fn dispatch_write_tools_track_pr3() {
        let s = PgBumpersMcp::new("pgb_agent", "sess-1");
        for name in [
            "propose_write",
            "dry_run",
            "apply_write",
            "request_elevation",
        ] {
            let r = s.dispatch(name, &no_args()).await.unwrap();
            let sc = r.structured_content.unwrap();
            assert!(
                sc["remedy"].as_str().unwrap().contains("#83 PR3"),
                "{name} tracks PR3"
            );
        }
    }

    #[tokio::test]
    async fn get_audit_without_a_reader_is_a_recoverable_block() {
        let s = PgBumpersMcp::new("pgb_agent", "sess-1");
        let r = s.dispatch("get_audit", &no_args()).await.unwrap();
        let sc = r.structured_content.unwrap();
        assert_eq!(sc["code"], serde_json::json!("AUDIT_UNAVAILABLE"));
        assert_eq!(sc["retryable"], serde_json::json!(true));
    }

    #[tokio::test]
    async fn dispatch_unknown_tool_is_fail_closed_error() {
        let s = PgBumpersMcp::new("pgb_agent", "sess-1");
        assert!(
            s.dispatch("definitely_not_a_tool", &no_args())
                .await
                .is_err()
        );
    }

    #[test]
    fn get_info_advertises_tools_capability_and_protocol() {
        let s = PgBumpersMcp::new("pgb_agent", "sess-1");
        let info = s.get_info();
        assert_eq!(info.protocol_version, PROTOCOL_VERSION);
        assert!(
            info.capabilities.tools.is_some(),
            "tools capability advertised"
        );
        assert_eq!(info.server_info.name, SERVER_NAME);
    }
}
