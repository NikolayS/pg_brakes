//! Observation types the warden reads from a (mockable) activity source
//! (SPEC §3 layer 2, §4). DB-free on purpose: the poll loop and the targeting /
//! breaker logic are pure functions of these structs, so every gating decision
//! is unit-testable with **no live database and no wall-clock** — the real
//! `pg_stat_activity` / `pg_replication_slots` query lives behind the
//! [`ActivitySource`](crate::poller::ActivitySource) seam.

/// The `application_name` the proxy stamps on every backend session it brokers
/// (`crates/proxy/src/session.rs`). It is the warden's primary *tag*: a backend
/// carrying it was opened by the proxy on the agent's behalf.
///
/// The tag alone is **not** the security anchor — an agent could try to
/// `SET application_name` to shed it. The un-strippable anchor is the **role
/// identity** ([`AGENT_ROLE`]); see [`Backend::is_agent_tagged`].
pub const PROXY_APP_NAME: &str = "pgb_proxy";

/// The hardened WALL role the proxy connects as (`deploy/sql/10_hardened_role.sql`).
/// A backend running as this role is agent-originated **regardless of its
/// `application_name`** — the role is set at connect time and a non-superuser
/// cannot `SET ROLE` away from its login identity in a way that changes
/// `pg_stat_activity.usename`. This is why the warden tag cannot be stripped.
pub const AGENT_ROLE: &str = "pgb_agent";

/// One backend as seen in `pg_stat_activity` (the fields the warden gates on).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Backend {
    /// `pg_stat_activity.pid` — the backend to cancel/terminate.
    pub pid: i32,
    /// `pg_stat_activity.usename` — the login role. The **un-strippable**
    /// half of the tag: a backend whose role is [`AGENT_ROLE`] is always
    /// agent-originated.
    pub usename: String,
    /// `pg_stat_activity.application_name` — the proxy stamps [`PROXY_APP_NAME`].
    /// An agent may try to mutate this; the role identity still pins the tag.
    pub application_name: String,
    /// `pg_stat_activity.state` (`active` / `idle` / `idle in transaction` …).
    pub state: String,
    /// Whole milliseconds the current query has been running
    /// (`now() - query_start`). `0` for an idle backend.
    pub query_runtime_millis: u64,
    /// The current/last query text (for the runbook / alarm; never gated on).
    pub query: String,
}

impl Backend {
    /// Is this backend **agent-tagged**, i.e. a legitimate warden target?
    ///
    /// True when **either** the role is the hardened agent role (the
    /// un-strippable anchor) **or** the proxy `application_name` tag is present.
    /// The role check is what survives an agent that tries to shed the
    /// `application_name` tag — see [`tag_is_strippable_for`].
    pub fn is_agent_tagged(&self) -> bool {
        self.usename == AGENT_ROLE || self.application_name == PROXY_APP_NAME
    }
}

/// One replication slot as seen in `pg_replication_slots` (the slot-exfil /
/// WAL-DoS watch — SPEC §3, §4). A slot created by the agent role is the
/// headline alarm: it pins WAL on the primary (DoS) and can stream changes out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplicationSlot {
    /// `pg_replication_slots.slot_name`.
    pub slot_name: String,
    /// `pg_replication_slots.slot_type` (`physical` / `logical`).
    pub slot_type: String,
    /// Whether the slot is currently held by a walsender
    /// (`pg_replication_slots.active`).
    pub active: bool,
    /// Bytes of WAL the slot is retaining on the primary
    /// (`pg_current_wal_lsn() - restart_lsn`). The WAL-DoS magnitude.
    pub retained_wal_bytes: u64,
}

/// A single warden poll: everything observed in one tick (SPEC §4 poll 1–5s).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Observation {
    /// Backends seen in `pg_stat_activity` this tick.
    pub backends: Vec<Backend>,
    /// Replication slots seen in `pg_replication_slots` this tick.
    pub slots: Vec<ReplicationSlot>,
    /// Replication lag in bytes (max over replicas; `0` if no replica / caught
    /// up). Feeds the lag breaker condition.
    pub replication_lag_bytes: u64,
}

/// Whether the warden tag can be stripped off a backend by the agent.
///
/// The MVP claim (SPEC §10: "agent can't strip its warden tag") is that an
/// agent **cannot** make a warden tag itself untargetable. It may `SET
/// application_name` to anything (PostgreSQL allows it), but it cannot change
/// its **login role** (`pg_stat_activity.usename`) — a non-superuser cannot
/// become another role's `usename`. So as long as the proxy connects as the
/// hardened [`AGENT_ROLE`], the tag survives any `application_name` change.
///
/// Returns `true` only if the tag would be strippable — which is exactly when
/// the backend is **not** running as the agent role (i.e. it was only
/// `application_name`-tagged). This function exists to make the invariant
/// testable: for an agent-role backend it must always return `false`.
pub fn tag_is_strippable_for(role: &str) -> bool {
    role != AGENT_ROLE
}

#[cfg(test)]
mod tests {
    use super::*;

    fn agent_backend() -> Backend {
        Backend {
            pid: 42,
            usename: AGENT_ROLE.to_string(),
            application_name: PROXY_APP_NAME.to_string(),
            state: "active".to_string(),
            query_runtime_millis: 0,
            query: "SELECT 1".to_string(),
        }
    }

    #[test]
    fn agent_role_backend_is_tagged() {
        assert!(agent_backend().is_agent_tagged());
    }

    #[test]
    fn proxy_app_name_alone_is_tagged() {
        // A backend with the proxy app_name but some other role is still a
        // target (it came through the proxy).
        let mut b = agent_backend();
        b.usename = "someone_else".to_string();
        assert!(b.is_agent_tagged());
    }

    #[test]
    fn shared_role_without_tag_is_not_targeted() {
        // A plain shared-application backend: never a warden target.
        let b = Backend {
            pid: 7,
            usename: "app_shared".to_string(),
            application_name: "psql".to_string(),
            state: "active".to_string(),
            query_runtime_millis: 999_999,
            query: "SELECT pg_sleep(9999)".to_string(),
        };
        assert!(!b.is_agent_tagged());
    }

    #[test]
    fn agent_cannot_strip_its_tag_via_application_name() {
        // The crux of the §10 invariant: the agent resets application_name to
        // shed the tag, but its login role still pins it.
        let mut b = agent_backend();
        b.application_name = String::new(); // agent ran `RESET application_name`
        assert!(
            b.is_agent_tagged(),
            "stripping application_name must NOT untarget an agent-role backend"
        );
        assert!(
            !tag_is_strippable_for(&b.usename),
            "the agent role's tag is structurally un-strippable"
        );
    }

    #[test]
    fn non_agent_role_tag_is_strippable() {
        // Documents the boundary: only the role anchor is un-strippable.
        assert!(tag_is_strippable_for("app_shared"));
        assert!(!tag_is_strippable_for(AGENT_ROLE));
    }
}
