//! The per-connection FE/BE loop — where the enforcement hooks meet the wire
//! (SPEC §3 layer 2, §4, §7 S1).
//!
//! One [`serve_connection`] call drives a single agent connection end to end:
//!
//! 1. **startup + TLS negotiation** — answer the PostgreSQL `SSLRequest`, then
//!    read the `StartupMessage`;
//! 2. **client-side SCRAM-SHA-256 auth** — prove the agent before any backend
//!    work ([`crate::auth`]);
//! 3. **originate the backend** — open a fresh PG18 session as the WALL role and
//!    inject `statement_timeout` (terminate-and-originate);
//! 4. **the query loop** — read each frontend frame, run the [`Enforcement`]
//!    gate, forward allowed frames, and relay backend responses while the
//!    [`Budget`] meters the `DataRow` stream and cuts it off at the cap.
//!
//! Everything fails closed: a malformed frame, a failed audit append, a budget
//! overrun, or a rejected statement all stop the offending statement (or the
//! connection) rather than letting bytes through ungated.

use std::sync::Arc;

use bytes::Bytes;
use pgb_pgwire::backend::{BackendMessage, TransactionStatus};
use pgb_pgwire::frontend::PROTOCOL_VERSION_3;
use pgb_pgwire::scram::{
    AuthenticationSasl, AuthenticationSaslContinue, AuthenticationSaslFinal, SaslInitialResponse,
    SaslResponse,
};
use pgb_pgwire::{
    read_startup_body, read_tagged_frame, write_frame, FrontendMessage, RawFrame, SslRequest,
    StartupMessage,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::auth::{ScramServer, ScramVerifier};
use crate::budget::{Budget, BudgetOutcome};
use crate::config::{BackendTarget, ProxyConfig};
use crate::enforce::{Enforcement, GateDecision};
use crate::recorder::Recorder;

/// Errors the session loop can end with. Most are terminal for the connection.
#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    /// A wire/IO error on the agent or backend socket.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    /// A protocol decode/encode error from [`pgb_pgwire`].
    #[error("protocol error: {0}")]
    Protocol(#[from] pgb_pgwire::ProtocolError),
    /// SCRAM authentication of the agent failed (fail-closed).
    #[error("auth error: {0}")]
    Auth(#[from] crate::auth::ScramError),
    /// The agent sent something out of sequence during startup/auth.
    #[error("handshake error: {0}")]
    Handshake(&'static str),
    /// Appending to the audit chain failed — audit is evidence, so this is fatal.
    #[error("audit error: {0}")]
    Audit(String),
    /// The backend refused our connection / behaved unexpectedly.
    #[error("backend error: {0}")]
    Backend(String),
}

/// The agent-facing stream after optional TLS upgrade: either plaintext TCP or a
/// rustls-wrapped TCP stream. Boxed as a trait object so the query loop is
/// monomorphic over one type.
pub type AgentStream = Box<dyn AsyncReadWrite + Unpin + Send>;

/// Marker trait combining the async read+write bounds the loop needs.
pub trait AsyncReadWrite: AsyncRead + AsyncWrite {}
impl<T: AsyncRead + AsyncWrite> AsyncReadWrite for T {}

/// Serve one agent connection to completion.
///
/// `tls` is an optional rustls acceptor; when present the proxy answers the
/// `SSLRequest` with `S` and upgrades. `recorder` records every gate verdict on
/// the shared audit chain. The function returns when the agent disconnects or a
/// terminal error occurs; per-statement blocks/rejects do **not** end it.
pub async fn serve_connection(
    tcp: TcpStream,
    cfg: Arc<ProxyConfig>,
    tls: Option<Arc<tokio_rustls::TlsAcceptor>>,
    recorder: Recorder,
    session_id: String,
) -> Result<(), SessionError> {
    tcp.set_nodelay(true).ok();
    let mut stream = startup_and_tls(tcp, &tls).await?;

    // Read the real StartupMessage (post-TLS).
    let body = read_startup_body(&mut stream).await?;
    let startup = StartupMessage::decode_body(body)?;
    if startup.protocol_version != PROTOCOL_VERSION_3 {
        send_fatal(&mut stream, "0A000", "unsupported protocol version").await?;
        return Err(SessionError::Handshake("unsupported protocol version"));
    }

    // (2) Authenticate the agent over SCRAM-SHA-256.
    authenticate_agent(&mut stream, &cfg).await?;

    // Auth ok → send the post-auth startup sequence to the agent.
    finish_agent_startup(&mut stream).await?;

    // (3) Originate the backend session as the WALL role.
    let mut backend = connect_backend(&cfg.backend, cfg.statement_timeout_ms).await?;

    // (4) The enforced query loop.
    query_loop(&mut stream, &mut backend, &cfg, &recorder, &session_id).await
}

/// Handle the `SSLRequest` negotiation and optionally upgrade to TLS, returning
/// the (possibly wrapped) agent stream. A client that opens with a plain
/// `StartupMessage` (no `SSLRequest`) is supported too: we peek the magic code.
async fn startup_and_tls(
    tcp: TcpStream,
    tls: &Option<Arc<tokio_rustls::TlsAcceptor>>,
) -> Result<AgentStream, SessionError> {
    let mut tcp = tcp;
    // Peek the first 8 bytes: an SSLRequest is exactly `00 00 00 08 <magic>`.
    let mut head = [0u8; 8];
    peek_exact(&mut tcp, &mut head).await?;
    let is_ssl_request = SslRequest::decode_body(Bytes::copy_from_slice(&head[4..8])).is_ok()
        && i32::from_be_bytes([head[0], head[1], head[2], head[3]]) == 8;

    if is_ssl_request {
        // Consume the 8-byte SSLRequest we peeked.
        tcp.read_exact(&mut head).await?;
        match tls {
            Some(acceptor) => {
                tcp.write_all(b"S").await?;
                tcp.flush().await?;
                let tls_stream = acceptor.accept(tcp).await?;
                Ok(Box::new(tls_stream))
            }
            None => {
                // No TLS configured → tell the client plaintext, continue.
                tcp.write_all(b"N").await?;
                tcp.flush().await?;
                Ok(Box::new(tcp))
            }
        }
    } else {
        // Direct StartupMessage (no SSLRequest) — plaintext.
        Ok(Box::new(tcp))
    }
}

/// Peek `buf.len()` bytes without consuming them.
async fn peek_exact(tcp: &mut TcpStream, buf: &mut [u8]) -> Result<(), SessionError> {
    loop {
        let n = tcp.peek(buf).await?;
        if n >= buf.len() {
            return Ok(());
        }
        if n == 0 {
            return Err(SessionError::Handshake("connection closed during startup"));
        }
        // Brief yield so the kernel buffers more; bounded by the OS — the peer
        // either sends the rest of the 8-byte header or we error out.
        tokio::task::yield_now().await;
    }
}

/// Run the SCRAM-SHA-256 server handshake against the agent (SPEC §7 S1).
async fn authenticate_agent<S>(stream: &mut S, cfg: &ProxyConfig) -> Result<(), SessionError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // Offer SCRAM-SHA-256.
    let offer = BackendMessage::AuthenticationSasl(AuthenticationSasl {
        mechanisms: vec!["SCRAM-SHA-256".to_string()],
    });
    write_frame(stream, &offer.encode()).await?;

    // client-first: a 'p' SASLInitialResponse.
    let frame = read_tagged_frame(stream)
        .await?
        .ok_or(SessionError::Handshake("eof before SASLInitialResponse"))?;
    if frame.tag != b'p' {
        return Err(SessionError::Handshake("expected SASLInitialResponse 'p'"));
    }
    let mut body = frame.body;
    let initial = SaslInitialResponse::decode_body_from(&mut body)?;
    if initial.mechanism != "SCRAM-SHA-256" {
        send_fatal(stream, "28000", "unsupported SASL mechanism").await?;
        return Err(SessionError::Auth(
            crate::auth::ScramError::UnsupportedMechanism,
        ));
    }
    let client_first = initial
        .initial_response
        .ok_or(SessionError::Handshake("empty SASL initial response"))?;
    let client_first = std::str::from_utf8(&client_first)
        .map_err(|_| SessionError::Handshake("non-utf8 client-first"))?;

    // Derive a verifier from the configured agent password and challenge.
    let verifier = ScramVerifier::from_password(&cfg.agent_password);
    let mut server = ScramServer::new(verifier);
    let server_first = server.handle_client_first(client_first)?;
    let cont = BackendMessage::AuthenticationSaslContinue(AuthenticationSaslContinue {
        data: Bytes::from(server_first.message.into_bytes()),
    });
    write_frame(stream, &cont.encode()).await?;

    // client-final: a 'p' SASLResponse.
    let frame = read_tagged_frame(stream)
        .await?
        .ok_or(SessionError::Handshake("eof before SASLResponse"))?;
    if frame.tag != b'p' {
        return Err(SessionError::Handshake("expected SASLResponse 'p'"));
    }
    let mut body = frame.body;
    let response = SaslResponse::decode_body_from(&mut body)?;
    let client_final = std::str::from_utf8(&response.data)
        .map_err(|_| SessionError::Handshake("non-utf8 client-final"))?;

    // Verify the proof — fail-closed on a bad password.
    let server_final = match server.handle_client_final(client_final) {
        Ok(f) => f,
        Err(e) => {
            send_fatal(stream, "28P01", "password authentication failed").await?;
            return Err(SessionError::Auth(e));
        }
    };
    let final_msg = BackendMessage::AuthenticationSaslFinal(AuthenticationSaslFinal {
        data: Bytes::from(server_final.message.into_bytes()),
    });
    write_frame(stream, &final_msg.encode()).await?;
    Ok(())
}

/// Send the post-auth startup tail to the agent: `AuthenticationOk`, a couple of
/// `ParameterStatus` messages, a `BackendKeyData`, and `ReadyForQuery`.
async fn finish_agent_startup<S>(stream: &mut S) -> Result<(), SessionError>
where
    S: AsyncWrite + Unpin,
{
    write_frame(stream, &BackendMessage::AuthenticationOk.encode()).await?;
    for (name, value) in [
        ("server_version", "18.0 (pg_bumpers proxy)"),
        ("client_encoding", "UTF8"),
        ("DateStyle", "ISO, MDY"),
        ("standard_conforming_strings", "on"),
    ] {
        let ps = BackendMessage::ParameterStatus {
            name: name.to_string(),
            value: value.to_string(),
        };
        write_frame(stream, &ps.encode()).await?;
    }
    write_frame(
        stream,
        &BackendMessage::BackendKeyData {
            process_id: 0,
            secret_key: 0,
        }
        .encode(),
    )
    .await?;
    write_frame(
        stream,
        &BackendMessage::ReadyForQuery {
            status: TransactionStatus::Idle,
        }
        .encode(),
    )
    .await?;
    Ok(())
}

/// A backend (proxy→PG18) connection as the WALL role.
struct Backend {
    stream: TcpStream,
}

/// Open the backend session as the WALL role and inject `statement_timeout`.
///
/// The local-stack primary trusts local connections (auth is `trust` for the
/// boundary's loopback), so the proxy sends a `StartupMessage` and expects
/// `AuthenticationOk`. (Terminate-and-originate: the agent's SCRAM proof gates
/// reaching this point; the backend trusts the network boundary — SPEC §3
/// layer 0. TLS to the backend is out of MVP scope and noted in the PR.)
async fn connect_backend(
    target: &BackendTarget,
    statement_timeout_ms: u64,
) -> Result<Backend, SessionError> {
    let mut stream = TcpStream::connect((target.host.as_str(), target.port)).await?;
    stream.set_nodelay(true).ok();

    let startup = StartupMessage {
        protocol_version: PROTOCOL_VERSION_3,
        parameters: vec![
            ("user".to_string(), target.role.clone()),
            ("database".to_string(), target.database.clone()),
            ("application_name".to_string(), "pgb_proxy".to_string()),
        ],
    };
    write_frame(&mut stream, &startup.encode()).await?;

    // Drive auth to AuthenticationOk, then to the first ReadyForQuery.
    wait_for_ready(&mut stream, target).await?;

    // (4) Timeout injection — set statement_timeout on the backend session.
    if statement_timeout_ms > 0 {
        inject_statement_timeout(&mut stream, statement_timeout_ms).await?;
    }
    Ok(Backend { stream })
}

/// Consume backend startup messages until the first `ReadyForQuery`. Handles the
/// trust/cleartext/MD5 auth replies the local-stack might send; SCRAM to the
/// backend is not required on the loopback boundary.
async fn wait_for_ready(
    stream: &mut TcpStream,
    target: &BackendTarget,
) -> Result<(), SessionError> {
    loop {
        let frame = read_tagged_frame(stream)
            .await?
            .ok_or_else(|| SessionError::Backend("backend closed during startup".into()))?;
        let msg = BackendMessage::decode(frame.tag, frame.body)?;
        match msg {
            BackendMessage::AuthenticationOk => {}
            BackendMessage::AuthenticationCleartextPassword => {
                let pw = FrontendMessage::PasswordMessage {
                    password: target.password.clone(),
                };
                write_frame(stream, &pw.encode()).await?;
            }
            BackendMessage::AuthenticationMd5Password { .. }
            | BackendMessage::AuthenticationSasl(_) => {
                return Err(SessionError::Backend(
                    "backend requires md5/scram auth; the local-stack boundary uses \
                     trust on loopback (MVP). Configure trust or extend backend auth."
                        .into(),
                ));
            }
            BackendMessage::ErrorResponse { fields } => {
                return Err(SessionError::Backend(format!(
                    "backend rejected startup: {}",
                    diag(&fields)
                )));
            }
            BackendMessage::ReadyForQuery { .. } => return Ok(()),
            // ParameterStatus / BackendKeyData / NoticeResponse: ignore.
            _ => {}
        }
    }
}

/// Inject `statement_timeout` via an extended-protocol round-trip on the backend
/// (Parse/Bind/Execute/Sync), draining to `ReadyForQuery`.
async fn inject_statement_timeout(
    stream: &mut TcpStream,
    timeout_ms: u64,
) -> Result<(), SessionError> {
    // A parameterless SET via the extended protocol (we force extended for
    // ourselves too — no simple query path anywhere).
    let sql = format!("SET statement_timeout = {timeout_ms}");
    send_extended_unit(stream, &sql).await?;
    drain_to_ready(stream).await
}

/// Send a single statement through the backend via Parse/Bind/Describe-less/
/// Execute/Sync (unnamed statement + portal).
async fn send_extended_unit(stream: &mut TcpStream, sql: &str) -> Result<(), SessionError> {
    let parse = FrontendMessage::Parse {
        statement: String::new(),
        sql: sql.to_string(),
        param_types: vec![],
    };
    // Bind body: 0 param-format-codes, 0 params, 0 result-format-codes.
    let bind = FrontendMessage::Bind {
        portal: String::new(),
        statement: String::new(),
        rest: Bytes::from_static(&[0, 0, 0, 0, 0, 0]),
    };
    let execute = FrontendMessage::Execute {
        portal: String::new(),
        max_rows: 0,
    };
    write_frame(stream, &parse.encode()).await?;
    write_frame(stream, &bind.encode()).await?;
    write_frame(stream, &execute.encode()).await?;
    write_frame(stream, &FrontendMessage::Sync.encode()).await?;
    Ok(())
}

/// Drain backend frames until `ReadyForQuery`, returning an error if the backend
/// reported one.
async fn drain_to_ready(stream: &mut TcpStream) -> Result<(), SessionError> {
    loop {
        let frame = read_tagged_frame(stream)
            .await?
            .ok_or_else(|| SessionError::Backend("backend closed mid-command".into()))?;
        let msg = BackendMessage::decode(frame.tag, frame.body)?;
        if let BackendMessage::ErrorResponse { fields } = &msg {
            return Err(SessionError::Backend(format!(
                "backend error: {}",
                diag(fields)
            )));
        }
        if matches!(msg, BackendMessage::ReadyForQuery { .. }) {
            return Ok(());
        }
    }
}

/// A deferred error for extended-protocol error recovery: when the proxy blocks
/// or rejects a frame mid-pipeline, it must (like PostgreSQL) **discard every
/// following frontend message until the next `Sync`**, then report the error and
/// a single `ReadyForQuery`. This carries the error to emit at that `Sync`.
struct PendingError {
    code: &'static str,
    message: String,
}

/// The enforced FE/BE query loop.
///
/// Implements PostgreSQL's extended-protocol error semantics: a blocked/rejected
/// `Parse` (or a malformed/`Copy*`/`Query` frame) puts the loop into a
/// **skip-until-Sync** state so the client's already-pipelined `Bind`/`Describe`/
/// `Execute` frames for that statement are discarded — never forwarded to the
/// backend out of context — and exactly one `ErrorResponse` + `ReadyForQuery`
/// is returned at the `Sync`. This keeps the FE/BE streams in lock-step so the
/// session survives every recoverable block.
async fn query_loop<S>(
    agent: &mut S,
    backend: &mut Backend,
    cfg: &ProxyConfig,
    recorder: &Recorder,
    session_id: &str,
) -> Result<(), SessionError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let gate = Enforcement::new();
    // When `Some`, we are skipping frames until the next Sync, then will emit it.
    let mut pending: Option<PendingError> = None;

    loop {
        let frame = match read_tagged_frame(agent).await? {
            Some(f) => f,
            None => return Ok(()), // clean disconnect between messages
        };

        // Decode for the gate. A malformed frame fails closed: skip-until-Sync.
        let msg = match FrontendMessage::decode(frame.tag, frame.body.clone()) {
            Ok(m) => m,
            Err(e) => {
                if pending.is_none() {
                    recorder
                        .reject(
                            session_id,
                            "<undecodable frame>",
                            "malformed_frame",
                            Some(e.to_string()),
                        )
                        .map_err(SessionError::Audit)?;
                    pending = Some(PendingError {
                        code: "08P01",
                        message: "malformed protocol frame".to_string(),
                    });
                }
                continue;
            }
        };

        if matches!(msg, FrontendMessage::Terminate) {
            return Ok(());
        }

        // In skip mode, swallow everything until a Sync flushes the deferred error.
        if let Some(err) = &pending {
            if matches!(msg, FrontendMessage::Sync) {
                send_error_then_ready(agent, err.code, &err.message).await?;
                pending = None;
            }
            // (Flush during skip is ignored; nothing is produced until Sync.)
            continue;
        }

        match gate.gate(&msg) {
            GateDecision::Allow { sql } => {
                if let Some(sql) = sql {
                    recorder
                        .allow(session_id, &sql)
                        .map_err(SessionError::Audit)?;
                }
                // Forward the original frame bytes verbatim to the backend.
                forward_frame(&mut backend.stream, &frame).await?;
                // A Sync flushes the pipeline: relay the backend response(s) to
                // the agent under the byte/row budget.
                if matches!(msg, FrontendMessage::Sync) {
                    relay_until_ready(agent, &mut backend.stream, cfg, recorder, session_id)
                        .await?;
                }
            }
            GateDecision::Block { sql, code, message } => {
                recorder
                    .block(session_id, &sql, code, Some(message.clone()))
                    .map_err(SessionError::Audit)?;
                // Defer the error to the next Sync (extended-protocol recovery).
                pending = Some(PendingError {
                    code: "42501",
                    message,
                });
            }
            GateDecision::Reject { code, message, .. } => {
                let stmt = match &msg {
                    FrontendMessage::Query { sql } => sql.clone(),
                    _ => format!("<{} frame>", frame.tag as char),
                };
                recorder
                    .reject(session_id, &stmt, code, Some(message.clone()))
                    .map_err(SessionError::Audit)?;
                match &msg {
                    // A simple `Query` ('Q') is a complete message: respond with
                    // the error + ReadyForQuery immediately (no Sync follows it).
                    FrontendMessage::Query { .. } => {
                        send_error_then_ready(agent, "0A000", &message).await?;
                    }
                    // A `Copy*` frame inside the extended flow: skip-until-Sync.
                    _ => {
                        pending = Some(PendingError {
                            code: "0A000",
                            message,
                        });
                    }
                }
            }
        }
    }
}

/// Relay backend frames to the agent until `ReadyForQuery`, applying the
/// per-statement byte/row cutoff to `DataRow` frames. On a cutoff we stop
/// forwarding rows, emit an `ErrorResponse` to the agent, record the block, and
/// cancel/drain the backend.
async fn relay_until_ready<S>(
    agent: &mut S,
    backend: &mut TcpStream,
    cfg: &ProxyConfig,
    recorder: &Recorder,
    session_id: &str,
) -> Result<(), SessionError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut budget = Budget::for_role(&cfg.budget);
    let mut cut_off = false;

    loop {
        let frame = read_tagged_frame(backend)
            .await?
            .ok_or_else(|| SessionError::Backend("backend closed mid-result".into()))?;

        match frame.tag {
            // ReadyForQuery — the terminator. After a cutoff we already sent an
            // ErrorResponse, so forward Z to re-sync the agent and finish.
            b'Z' => {
                forward_frame(agent, &frame).await?;
                return Ok(());
            }
            // DataRow — the only metered frame. Before a cutoff, charge it; once
            // cut off, the remaining rows are suppressed (not forwarded).
            b'D' if !cut_off => match budget.charge_row(frame.body.len() as u64) {
                BudgetOutcome::Within { .. } => forward_frame(agent, &frame).await?,
                BudgetOutcome::Exceeded { cap, bytes, rows } => {
                    cut_off = true;
                    let message = format!(
                        "result cut off at the {} budget after {} rows / {} bytes \
                         (single-shot cap exceeded)",
                        match cap {
                            crate::budget::Cap::Bytes => "byte",
                            crate::budget::Cap::Rows => "row",
                        },
                        rows,
                        bytes
                    );
                    recorder
                        .block(
                            session_id,
                            "<result stream>",
                            cap.code(),
                            Some(message.clone()),
                        )
                        .map_err(SessionError::Audit)?;
                    // Tell the agent the stream was cut; keep draining the
                    // backend so the connection ends in a clean (Z) state.
                    write_frame(agent, &error_response("53400", &message).encode()).await?;
                }
            },
            // Suppressed after a cutoff: remaining DataRows + the now-redundant
            // CommandComplete (we already emitted our ErrorResponse).
            b'D' | b'C' if cut_off => {}
            // Everything else (RowDescription, ParseComplete, BindComplete,
            // CommandComplete pre-cutoff, NoticeResponse, ErrorResponse, …)
            // passes through verbatim.
            _ => forward_frame(agent, &frame).await?,
        }
    }
}

/// Forward a raw frame verbatim by re-encoding tag + length + body.
async fn forward_frame<W>(out: &mut W, frame: &RawFrame) -> Result<(), SessionError>
where
    W: AsyncWrite + Unpin,
{
    let mut buf = bytes::BytesMut::with_capacity(5 + frame.body.len());
    use bytes::BufMut;
    buf.put_u8(frame.tag);
    buf.put_i32((4 + frame.body.len()) as i32);
    buf.put_slice(&frame.body);
    write_frame(out, &buf).await?;
    Ok(())
}

/// Build an `ErrorResponse` with severity/code/message fields.
fn error_response(code: &str, message: &str) -> BackendMessage {
    BackendMessage::ErrorResponse {
        fields: vec![
            (b'S', "ERROR".to_string()),
            (b'V', "ERROR".to_string()),
            (b'C', code.to_string()),
            (b'M', message.to_string()),
        ],
    }
}

/// Send an `ErrorResponse` followed by a `ReadyForQuery(Idle)` so the agent can
/// continue issuing statements after a recoverable block/reject.
async fn send_error_then_ready<S>(
    stream: &mut S,
    code: &str,
    message: &str,
) -> Result<(), SessionError>
where
    S: AsyncWrite + Unpin,
{
    write_frame(stream, &error_response(code, message).encode()).await?;
    write_frame(
        stream,
        &BackendMessage::ReadyForQuery {
            status: TransactionStatus::Idle,
        }
        .encode(),
    )
    .await?;
    Ok(())
}

/// Send a fatal `ErrorResponse` (no `ReadyForQuery`) — used during startup/auth.
async fn send_fatal<S>(stream: &mut S, code: &str, message: &str) -> Result<(), SessionError>
where
    S: AsyncWrite + Unpin,
{
    let err = BackendMessage::ErrorResponse {
        fields: vec![
            (b'S', "FATAL".to_string()),
            (b'V', "FATAL".to_string()),
            (b'C', code.to_string()),
            (b'M', message.to_string()),
        ],
    };
    write_frame(stream, &err.encode()).await?;
    Ok(())
}

/// Render diagnostic fields into a `message (code)` string for logs/errors.
fn diag(fields: &[(u8, String)]) -> String {
    let msg = fields
        .iter()
        .find(|(c, _)| *c == b'M')
        .map(|(_, v)| v.as_str())
        .unwrap_or("?");
    let code = fields
        .iter()
        .find(|(c, _)| *c == b'C')
        .map(|(_, v)| v.as_str())
        .unwrap_or("?");
    format!("{msg} ({code})")
}
