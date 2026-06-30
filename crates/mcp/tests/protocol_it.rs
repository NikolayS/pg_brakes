//! End-to-end protocol test: a REAL MCP client drives the `pgb-mcp` server over
//! an in-process duplex pipe (the same `AsyncRead`/`AsyncWrite` transport the
//! stdio binary uses), exercising the full handshake + catalog + a tool call.
//!
//! This is the protocol-level RED→GREEN test for EPIC #83 (PR1 handshake/catalog +
//! PR2 read path). It asserts:
//!   1. `initialize` — the handshake completes; the server reports the expected
//!      protocolVersion, server name, and the `tools` capability.
//!   2. `tools/list` — ALL nine §4 tools are advertised with correct names +
//!      object input schemas (with the right required fields).
//!   3. `tools/call whoami` — returns the posture incl. `security_boundary: false`
//!      and the nine tool names.
//!   4. `tools/call query` (PR2 read path): a WRITE is blocked `READ_ONLY` by the
//!      cooperative classifier fast-path; a CLEAN read passes the fast-path and is
//!      routed to the proxy (here unwired ⇒ a recoverable `PROXY_UNAVAILABLE`
//!      block, never `UNIMPLEMENTED`). No panic; the server stays up.
//!
//! The driver is rmcp's real client (`().serve(...)`) — not a hand-rolled
//! JSON-RPC stub — so the assertions exercise the genuine protocol path.

use std::collections::BTreeSet;

use pgb_mcp::{PgBrakesMcp, SERVER_NAME, TOOL_NAMES};
use rmcp::ServiceExt;
use rmcp::model::{CallToolRequestParams, ProtocolVersion};

/// Spin up the server + a real client over an in-process duplex pipe, returning
/// the running client (whose `peer_info` is the server's `initialize` result).
async fn connect() -> rmcp::service::RunningService<rmcp::service::RoleClient, ()> {
    // Two ends of an in-memory bidirectional pipe. The server reads `s_read` /
    // writes `s_write`; the client gets the mirror image. This is exactly the
    // (AsyncRead, AsyncWrite) tuple transport the stdio binary uses.
    let (client_io, server_io) = tokio::io::duplex(8 * 1024);
    let (s_read, s_write) = tokio::io::split(server_io);
    let (c_read, c_write) = tokio::io::split(client_io);

    // Serve the server in the background; it performs the handshake then serves.
    let server = PgBrakesMcp::new("pgb_agent", "sess-it");
    tokio::spawn(async move {
        let running = server
            .serve((s_read, s_write))
            .await
            .expect("server handshake");
        let _ = running.waiting().await;
    });

    // The client drives `initialize` as part of `serve`; `peer_info` then holds
    // the server's InitializeResult.
    ().serve((c_read, c_write)).await.expect("client handshake")
}

#[tokio::test]
async fn initialize_lists_nine_tools_and_whoami_is_not_a_boundary() {
    let client = connect().await;

    // ---- 1. initialize: the handshake result ----
    let info = client.peer_info().expect("server sent InitializeResult");
    assert_eq!(
        info.protocol_version,
        ProtocolVersion::V_2024_11_05,
        "server advertises the 2024-11-05 protocol revision"
    );
    assert_eq!(info.server_info.name, SERVER_NAME, "server name");
    assert!(
        info.capabilities.tools.is_some(),
        "server advertises the tools capability"
    );

    // ---- 2. tools/list: all nine §4 tools, with schemas ----
    let tools = client.list_all_tools().await.expect("tools/list");
    let got: BTreeSet<String> = tools.iter().map(|t| t.name.to_string()).collect();
    let want: BTreeSet<String> = TOOL_NAMES.iter().map(|s| s.to_string()).collect();
    assert_eq!(got, want, "exactly the nine §4 tool names are advertised");

    for t in &tools {
        let schema = &*t.input_schema;
        assert_eq!(
            schema.get("type").and_then(|v| v.as_str()),
            Some("object"),
            "{} input schema is an object",
            t.name
        );
    }
    // `query` requires `sql`; `apply_write` requires `proposal_id`.
    let query = tools.iter().find(|t| t.name == "query").unwrap();
    let required: Vec<&str> = query.input_schema["required"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|v| v.as_str())
        .collect();
    assert_eq!(required, vec!["sql"], "query requires sql");

    // ---- 3. tools/call whoami: the §3 posture ----
    let whoami = client
        .call_tool(CallToolRequestParams::new("whoami"))
        .await
        .expect("tools/call whoami");
    assert_eq!(whoami.is_error, Some(false), "whoami is a success result");
    let sc = whoami
        .structured_content
        .as_ref()
        .expect("whoami structuredContent");
    assert_eq!(
        sc["security_boundary"],
        serde_json::json!(false),
        "MCP is NOT a security boundary (SPEC §3)"
    );
    assert_eq!(sc["role"], serde_json::json!("pgb_agent"));
    assert_eq!(
        sc["tools"].as_array().unwrap().len(),
        9,
        "whoami reports the nine tools"
    );

    // ---- 4. tools/call query: PR2 read path through the (here-unwired) proxy ----
    // (a) A WRITE to the read tool is blocked by the cooperative read-only
    //     fast-path (the canonical `pgb_pgwire::classify` reuse) — a recoverable
    //     READ_ONLY block, BEFORE it can reach the proxy. No panic; the server
    //     stays up.
    let write_args = {
        let mut m = serde_json::Map::new();
        m.insert("sql".into(), serde_json::json!("DROP TABLE orders"));
        m
    };
    let write_res = client
        .call_tool(CallToolRequestParams::new("query").with_arguments(write_args))
        .await
        .expect("tools/call query(write) does not error the transport");
    assert_eq!(
        write_res.is_error,
        Some(true),
        "a write is a blocked result"
    );
    let wsc = write_res
        .structured_content
        .as_ref()
        .expect("query structuredContent");
    assert_eq!(wsc["status"], serde_json::json!("blocked"));
    assert_eq!(
        wsc["code"],
        serde_json::json!("READ_ONLY"),
        "a write to the read tool → READ_ONLY (canonical classifier reuse)"
    );
    assert_eq!(wsc["retryable"], serde_json::json!(false));

    // (b) A CLEAN read passes the fast-path and is routed to the proxy. This test
    //     server has NO proxy wired, so the read surfaces the recoverable
    //     PROXY_UNAVAILABLE block (retryable) — proving the read was ALLOWED by the
    //     fast-path and dispatched to the proxy transport, never UNIMPLEMENTED.
    let read_args = {
        let mut m = serde_json::Map::new();
        m.insert("sql".into(), serde_json::json!("SELECT 1"));
        m
    };
    let read_res = client
        .call_tool(CallToolRequestParams::new("query").with_arguments(read_args))
        .await
        .expect("tools/call query(read) does not error the transport");
    let rsc = read_res
        .structured_content
        .as_ref()
        .expect("query structuredContent");
    assert_ne!(
        rsc["code"],
        serde_json::json!("READ_ONLY"),
        "a clean read is NOT blocked by the fast-path"
    );
    assert_ne!(
        rsc["code"],
        serde_json::json!("UNIMPLEMENTED"),
        "query is wired in PR2 — never UNIMPLEMENTED"
    );
    assert_eq!(
        rsc["code"],
        serde_json::json!("PROXY_UNAVAILABLE"),
        "no proxy wired ⇒ the read routed to the proxy and got a recoverable block"
    );
    assert_eq!(rsc["retryable"], serde_json::json!(true));

    // The server survived the blocks and still serves: whoami again succeeds.
    let again = client
        .call_tool(CallToolRequestParams::new("whoami"))
        .await
        .expect("server still serving after a block");
    assert_eq!(again.is_error, Some(false));

    client.cancel().await.expect("clean shutdown");
}
