//! pg_bumpers proxy binary — the inline, agent-only enforcement endpoint
//! (SPEC §3 layer 2, §7 S1).
//!
//! Reads its wiring from the environment (so it stays 12-factor and secret-store
//! friendly), loads per-role budgets from `policy.yaml`, optionally terminates
//! TLS on the agent endpoint, and serves each connection through the enforced
//! FE/BE loop in [`pgb_proxy::serve_connection`].
//!
//! Environment:
//! - `PGB_PROXY_LISTEN`      — agent listen addr (default `127.0.0.1:6432`).
//! - `PGB_PROXY_TLS_CERT` / `PGB_PROXY_TLS_KEY` — PEM paths; both ⇒ TLS on.
//! - `PGB_BACKEND_HOST` / `PGB_BACKEND_PORT` / `PGB_BACKEND_DB` — PG18 target
//!   (defaults `127.0.0.1` / `54321` / `postgres`; **never 5432**).
//! - `PGB_BACKEND_ROLE` / `PGB_BACKEND_PASSWORD` — the WALL role + password
//!   (defaults `pgb_agent` / `pgb_agent_dev_pw`).
//! - `PGB_AGENT_USER` / `PGB_AGENT_PASSWORD` — the SCRAM credential the proxy
//!   verifies for agents.
//! - `PGB_POLICY_PATH` — path to `policy.yaml`.
//! - `PGB_POLICY_ROLE` — which role's budgets apply (default `analytics`).
//! - `PGB_STATEMENT_TIMEOUT_MS` — injected `statement_timeout` (default 30000).

use std::sync::{Arc, Mutex};

use pgb_audit::InMemorySink;
use pgb_core::{Clock, SystemClock};
use pgb_policy::PolicyConfig;
use pgb_proxy::config::{BackendTarget, TlsConfig};
use pgb_proxy::{serve_connection, ProxyConfig, Recorder};
use tokio::net::TcpListener;

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Install the ring crypto provider for rustls (process-wide, once).
    let _ = rustls::crypto::ring::default_provider().install_default();

    let listen = env_or("PGB_PROXY_LISTEN", "127.0.0.1:6432").parse()?;

    let tls = match (
        std::env::var("PGB_PROXY_TLS_CERT"),
        std::env::var("PGB_PROXY_TLS_KEY"),
    ) {
        (Ok(cert), Ok(key)) => Some(TlsConfig {
            cert_pem: cert.into(),
            key_pem: key.into(),
        }),
        _ => None,
    };

    let policy_path = env_or("PGB_POLICY_PATH", "crates/policy/policy.example.yaml");
    let policy_role = env_or("PGB_POLICY_ROLE", "analytics");
    let policy = PolicyConfig::load_from_yaml(&std::fs::read_to_string(&policy_path)?)?;
    let budget = ProxyConfig::budget_for(&policy, &policy_role)?;

    let cfg = Arc::new(ProxyConfig {
        listen,
        tls,
        backend: BackendTarget {
            host: env_or("PGB_BACKEND_HOST", "127.0.0.1"),
            port: env_or("PGB_BACKEND_PORT", "54321").parse()?,
            database: env_or("PGB_BACKEND_DB", "postgres"),
            role: env_or("PGB_BACKEND_ROLE", "pgb_agent"),
            password: env_or("PGB_BACKEND_PASSWORD", "pgb_agent_dev_pw"),
        },
        agent_user: env_or("PGB_AGENT_USER", "pgb_agent"),
        agent_password: env_or("PGB_AGENT_PASSWORD", "pgb_agent_dev_pw"),
        policy_role: policy_role.clone(),
        budget,
        statement_timeout_ms: env_or("PGB_STATEMENT_TIMEOUT_MS", "30000").parse()?,
    });

    // Audit sink: the in-memory hash chain (the Postgres `_meta` sink is wired in
    // a follow-up; this binary keeps the chain in-process). The chain is the
    // tamper-evident evidence that hostile statements were stopped.
    let sink: Arc<Mutex<dyn pgb_audit::Sink + Send>> = Arc::new(Mutex::new(InMemorySink::new()));
    let clock: Arc<dyn Clock> = Arc::new(SystemClock::new());
    let recorder = Recorder::new(sink, clock, cfg.backend.role.clone());

    let tls_acceptor = match &cfg.tls {
        Some(t) => Some(Arc::new(tokio_rustls::TlsAcceptor::from(
            pgb_proxy::tls::server_config(t)?,
        ))),
        None => None,
    };

    let listener = TcpListener::bind(cfg.listen).await?;
    eprintln!(
        "pgb-proxy: listening on {} → backend {}:{} as {} (policy role `{}`, \
         statement_timeout={}ms, tls={})",
        cfg.listen,
        cfg.backend.host,
        cfg.backend.port,
        cfg.backend.role,
        cfg.policy_role,
        cfg.statement_timeout_ms,
        cfg.tls.is_some(),
    );

    let mut conn_id: u64 = 0;
    loop {
        let (tcp, peer) = listener.accept().await?;
        conn_id += 1;
        let session_id = format!("conn-{conn_id}");
        let cfg = cfg.clone();
        let tls_acceptor = tls_acceptor.clone();
        let recorder = recorder.clone();
        tokio::spawn(async move {
            if let Err(e) =
                serve_connection(tcp, cfg, tls_acceptor, recorder, session_id.clone()).await
            {
                eprintln!("pgb-proxy: session {session_id} ({peer}) ended: {e}");
            }
        });
    }
}
