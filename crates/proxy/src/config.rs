//! Proxy runtime configuration (SPEC §3 layer 2, §7 S1).
//!
//! Two sources, kept separate on purpose:
//! - the **per-role budgets** come from `policy.yaml` ([`pgb_policy::PolicyConfig`]),
//!   the single source of truth for byte/row caps;
//! - the **deployment wiring** (listen address, TLS material, the backend DSN,
//!   the agent credential the proxy authenticates, the injected
//!   `statement_timeout`) comes from this struct, which a binary builds from
//!   env/flags.
//!
//! The proxy is the *only* network path to the DB (SPEC §3 layer 0), so the
//! backend DSN here points at PG18 as the hardened WALL role `pgb_agent`.

use std::net::SocketAddr;
use std::path::PathBuf;

use pgb_policy::RoleBudget;

/// The backend connection target: where the proxy originates the PG18 session as
/// the hardened WALL role.
#[derive(Debug, Clone)]
pub struct BackendTarget {
    /// Backend host (e.g. `127.0.0.1`).
    pub host: String,
    /// Backend port (the local-stack primary is 54321; **never** 5432).
    pub port: u16,
    /// Database name to connect to.
    pub database: String,
    /// The WALL role the proxy connects as (`pgb_agent`).
    pub role: String,
    /// The WALL role's password (dev: `pgb_agent_dev_pw`; prod: secret store).
    pub password: String,
}

/// TLS material for the agent-facing listener (PEM-encoded files).
#[derive(Debug, Clone)]
pub struct TlsConfig {
    /// Path to the server certificate chain (PEM).
    pub cert_pem: PathBuf,
    /// Path to the server private key (PEM, PKCS#8 or PKCS#1).
    pub key_pem: PathBuf,
}

/// The full proxy configuration.
#[derive(Debug, Clone)]
pub struct ProxyConfig {
    /// The agent-facing listen address.
    pub listen: SocketAddr,
    /// Optional TLS on the listener. `None` ⇒ plaintext (dev/test only).
    pub tls: Option<TlsConfig>,
    /// The backend PG18 target (the WALL role connection).
    pub backend: BackendTarget,
    /// The username an agent must present to the proxy (terminate side). The
    /// proxy authenticates this via SCRAM-SHA-256.
    pub agent_user: String,
    /// The password the proxy expects for `agent_user` (used to verify the
    /// agent's SCRAM proof and as the SCRAM verifier secret). Dev material;
    /// production resolves this from the secret store.
    pub agent_password: String,
    /// The role this connection's budgets are looked up under in `policy.yaml`.
    pub policy_role: String,
    /// The single-shot byte/row budget for `policy_role` (resolved from
    /// `policy.yaml`).
    pub budget: RoleBudget,
    /// The `statement_timeout` (milliseconds) injected on every backend session.
    /// `0` disables the injection (not recommended).
    pub statement_timeout_ms: u64,
}

impl ProxyConfig {
    /// Resolve a `policy_role`'s single-shot budget from a loaded policy.
    pub fn budget_for(
        policy: &pgb_policy::PolicyConfig,
        role: &str,
    ) -> Result<RoleBudget, ConfigError> {
        policy
            .roles
            .get(role)
            .map(|r| r.budget.clone())
            .ok_or_else(|| ConfigError::UnknownRole(role.to_string()))
    }
}

/// Configuration errors.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// The requested policy role is not present in `policy.yaml`.
    #[error("role `{0}` is not defined in policy.yaml")]
    UnknownRole(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn budget_lookup_resolves_and_fails_closed() {
        let policy = pgb_policy::PolicyConfig::load_from_yaml(include_str!(
            "../../policy/policy.example.yaml"
        ))
        .unwrap();
        let b = ProxyConfig::budget_for(&policy, "analytics").unwrap();
        assert!(b.max_bytes > 0 && b.max_rows > 0);
        // An undefined role is a hard error (fail-closed), never a default.
        assert!(matches!(
            ProxyConfig::budget_for(&policy, "does_not_exist"),
            Err(ConfigError::UnknownRole(_))
        ));
    }
}
