//! Boot wiring for the **one shared, persistent, anchored** `_meta` audit chain
//! (SPEC §3/§4/§10.9; issue #64, S5).
//!
//! S4 shipped the chain, the `_meta` [`PgSink`](crate::pg::PgSink), the external
//! WORM anchor, and the KMS key-separation as *libraries*, but the proxy and the
//! CLI each built their own ephemeral in-memory chain with an independent
//! genesis, and nothing anchored the running chain. This module is the seam that
//! S5's consumers (proxy + CLI) call to:
//!
//! 1. construct **one** [`SharedSink`] over the Postgres `_meta`
//!    [`PgSink`](crate::pg::PgSink) — the single canonical chain both consumers
//!    hash-chain into ([`AuditBoot::connect`]);
//! 2. run an [`Anchorer`] over that canonical chain on a `core::Clock` interval
//!    ([`AuditBoot::maybe_anchor`]); and
//! 3. perform the **fail-closed startup verification** ([`AuditBoot::startup_verify`]):
//!    load the persisted chain, check it verifies within-chain, and check its
//!    head matches the validly-signed WORM-anchored head — refusing to proceed
//!    on any mismatch (a full-chain rewrite) or a missing anchor.
//!
//! The KMS signer is loaded from a [`SecretStore`](crate::secret::SecretStore)
//! the audited DB operator cannot reach (SPEC §10.9). Time is always read from a
//! `core::Clock` passed in by the caller, so anchoring cadence is mockable and no
//! wall clock is touched.
//!
//! This module is behind the `pg` feature (it needs the Postgres client).

use std::sync::{Arc, Mutex};

use postgres::{Client, NoTls};

use crate::anchor::{verify_records_against_anchor, AnchorError, AnchorVerification, Anchorer};
use crate::kms::LocalKms;
use crate::pg::PgSink;
use crate::secret::{SecretStore, AUDIT_SIGNING_KEY_ID};
use crate::sink::{SharedSink, Sink, SinkError};
use crate::WormAnchor;

/// Why the audit boot wiring failed. Every variant is **fail-closed** — a boot
/// error means the consumer must refuse to start (the audit chain is the
/// tamper-evidence root of trust; if it cannot be established or verified, the
/// system has no business running).
#[derive(Debug, thiserror::Error)]
pub enum BootError {
    /// Could not connect to the `_meta` database as the audit writer.
    #[error("audit _meta connect failed: {0}")]
    Connect(String),
    /// Could not load the audit chain-head signing key from the secret store.
    #[error("audit signing key load failed: {0}")]
    Kms(#[from] crate::kms::KmsError),
    /// A sink read/append failed.
    #[error(transparent)]
    Sink(#[from] SinkError),
    /// Publishing the anchor to the WORM sink failed (e.g. the file backing).
    #[error("audit anchor publish failed: {0}")]
    Worm(#[from] crate::anchor::WormAnchorError),
    /// The persisted chain failed within-chain integrity (a mid-chain edit/delete).
    #[error("persisted _meta chain integrity broken: {0:?}")]
    ChainIntegrity(crate::chain::ChainBreak),
    /// The chain's head does **not** match the WORM-anchored head — a full-chain
    /// rewrite was detected at startup. **Refuse to start.**
    #[error(
        "FAIL-CLOSED: _meta chain head does not match the anchored head \
         (full-chain rewrite detected): anchored seq {anchored_seq}, anchored_head {anchored_head}, \
         actual_head {actual_head}"
    )]
    AnchorHeadMismatch {
        /// The head the WORM anchor pins (the honest, signed one).
        anchored_head: String,
        /// The head the persisted chain actually has now.
        actual_head: String,
        /// The `seq` the anchor pinned.
        anchored_seq: u64,
    },
    /// The anchor verification itself errored (no anchor published / bad
    /// signature / no verifier). Fail closed.
    #[error("FAIL-CLOSED: anchor verification error at startup: {0}")]
    Anchor(#[from] AnchorError),
}

/// The boot handle for the canonical, anchored `_meta` chain.
///
/// Holds the [`SharedSink`] both consumers append to, the WORM anchor, and the
/// interval [`Anchorer`]. Construct it with [`connect`](AuditBoot::connect) (real
/// `_meta`) or [`with_sink`](AuditBoot::with_sink) (any [`Sink`], for tests),
/// then [`startup_verify`](AuditBoot::startup_verify) before serving traffic and
/// [`maybe_anchor`](AuditBoot::maybe_anchor) on the clock cadence.
pub struct AuditBoot {
    sink: SharedSink,
    worm: WormAnchor,
    anchorer: Anchorer,
}

impl AuditBoot {
    /// Build a boot handle over a `_meta` writer DSN, loading the signing key
    /// from `store`. The DSN must authenticate as the **audit writer** role
    /// (never the audited agent — see `crates/audit/sql/10_audit_meta.sql`).
    ///
    /// `interval_millis` is the anchoring cadence (monotonic millis, measured by
    /// the caller's `core::Clock`).
    pub fn connect(
        writer_dsn: &str,
        store: &impl SecretStore,
        interval_millis: u64,
    ) -> Result<Self, BootError> {
        let client =
            Client::connect(writer_dsn, NoTls).map_err(|e| BootError::Connect(e.to_string()))?;
        let signer = LocalKms::from_secret_store(store, AUDIT_SIGNING_KEY_ID)?;
        Ok(Self::with_sink(
            PgSink::new(client),
            signer,
            interval_millis,
        ))
    }

    /// Build a boot handle over an arbitrary backing [`Sink`] (e.g. an
    /// [`InMemorySink`](crate::sink::InMemorySink) in unit tests), given an
    /// already-loaded signer and the anchoring interval. The sink is wrapped in a
    /// [`SharedSink`] so every consumer clone shares the one chain.
    pub fn with_sink(
        sink: impl Sink + Send + 'static,
        signer: LocalKms,
        interval_millis: u64,
    ) -> Self {
        AuditBoot {
            sink: SharedSink::new(sink),
            worm: WormAnchor::new(),
            anchorer: Anchorer::new(signer, interval_millis),
        }
    }

    /// A cloneable handle to the **one** shared sink, to inject into a consumer
    /// (the proxy `Recorder`, the CLI flow). Every clone appends to and reads
    /// from the same canonical chain.
    pub fn shared_sink(&self) -> SharedSink {
        self.sink.clone()
    }

    /// The shared sink as the exact `Arc<Mutex<dyn Sink + Send>>` the proxy
    /// `Recorder` is constructed from — so the recorder and the anchorer/verify
    /// share the identical backing sink.
    pub fn sink_arc(&self) -> Arc<Mutex<dyn Sink + Send>> {
        self.sink.arc()
    }

    /// Read the canonical persisted chain back (oldest first).
    pub fn load_chain(&mut self) -> Result<Vec<crate::record::AuditRecord>, BootError> {
        Ok(self.sink.load_chain_mut()?)
    }

    /// Run one interval tick: anchor the **current persisted head** to the WORM
    /// sink iff an interval has elapsed (or this is the first tick). `now_monotonic_millis`
    /// comes from the caller's `core::Clock::monotonic_millis`.
    ///
    /// Returns the anchored head (and seq) if it published, or `None` if the
    /// interval has not elapsed.
    pub fn maybe_anchor(
        &mut self,
        now_monotonic_millis: u64,
    ) -> Result<Option<crate::anchor::Anchored>, BootError> {
        let records = self.sink.load_chain_mut()?;
        Ok(self
            .anchorer
            .maybe_anchor_records(&records, now_monotonic_millis, &mut self.worm)?)
    }

    /// **Fail-closed startup verification** (SPEC §3/§10.9). Loads the persisted
    /// `_meta` chain and asserts:
    ///
    /// 1. it verifies within-chain (no mid-chain edit/delete), and
    /// 2. its head matches the validly-signed WORM-anchored head.
    ///
    /// A full-chain rewrite (every record re-linked so step 1 passes) is caught
    /// at step 2 as [`BootError::AnchorHeadMismatch`]; a missing/forged anchor is
    /// a [`BootError::Anchor`]. Any error here means **refuse to start**.
    ///
    /// This must be called **after** at least one [`maybe_anchor`](AuditBoot::maybe_anchor)
    /// has established a baseline anchor (the first tick always anchors), or it
    /// fails closed with no anchor.
    pub fn startup_verify(&mut self) -> Result<(), BootError> {
        let records = self.sink.load_chain_mut()?;
        // (1) Within-chain integrity.
        crate::chain::verify_chain(&records).map_err(BootError::ChainIntegrity)?;
        // (2) Anchored-head match (catches a full-chain rewrite).
        match verify_records_against_anchor(&records, &self.worm)? {
            AnchorVerification::Verified => Ok(()),
            AnchorVerification::HeadMismatch {
                anchored_head,
                actual_head,
                anchored_seq,
            } => Err(BootError::AnchorHeadMismatch {
                anchored_head,
                actual_head,
                anchored_seq,
            }),
        }
    }

    /// Borrow the WORM anchor (e.g. to inspect published entries in tests).
    pub fn worm(&self) -> &WormAnchor {
        &self.worm
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::Decision;
    use crate::sink::InMemorySink;
    use crate::{LocalSecretStore, NewEntry, Principal};
    use pgb_core::{Clock, MockClock};
    use pgb_policy::IntentTiers;

    fn signer() -> LocalKms {
        let mut store = LocalSecretStore::new();
        store
            .put(AUDIT_SIGNING_KEY_ID, b"boot-test-key-000001")
            .unwrap();
        LocalKms::from_secret_store(&store, AUDIT_SIGNING_KEY_ID).unwrap()
    }

    fn entry(role: &str, sql: &str, decision: Decision, code: &str) -> NewEntry {
        NewEntry {
            statement_text: sql.to_string(),
            decision,
            reason_code: code.to_string(),
            reason: None,
            principal: Principal {
                role: role.to_string(),
                session_id: Some("s".to_string()),
                principal: None,
            },
            intent: IntentTiers::default(),
            write_safety: Default::default(),
        }
    }

    #[test]
    fn boot_anchors_and_startup_verify_passes_on_honest_chain() {
        let clock = MockClock::starting_at(1_000);
        let mut boot = AuditBoot::with_sink(InMemorySink::new(), signer(), 1_000);

        // Two consumers share the one sink.
        let mut a = boot.shared_sink();
        let mut b = boot.shared_sink();
        a.append(
            entry("pgb_agent", "X", Decision::Reject, "rej"),
            clock.now_unix_millis(),
        )
        .unwrap();
        b.append(
            entry("human", "Y", Decision::Allow, "grant"),
            clock.now_unix_millis(),
        )
        .unwrap();

        // First tick anchors; startup verify then passes.
        boot.maybe_anchor(clock.monotonic_millis())
            .unwrap()
            .unwrap();
        boot.startup_verify().expect("honest chain passes startup");
    }

    #[test]
    fn startup_verify_is_fail_closed_without_an_anchor() {
        let mut boot = AuditBoot::with_sink(InMemorySink::new(), signer(), 1_000);
        let mut a = boot.shared_sink();
        a.append(entry("pgb_agent", "X", Decision::Allow, "ok"), 1)
            .unwrap();
        // No maybe_anchor() call => no anchor published => refuse to start.
        let err = boot
            .startup_verify()
            .expect_err("no anchor must fail closed");
        assert!(matches!(err, BootError::Anchor(_)), "got {err:?}");
    }

    #[test]
    fn anchor_respects_the_injected_clock_interval() {
        let clock = MockClock::starting_at(0);
        let mut boot = AuditBoot::with_sink(InMemorySink::new(), signer(), 1_000);
        let mut a = boot.shared_sink();
        a.append(entry("pgb_agent", "X", Decision::Allow, "ok"), 1)
            .unwrap();

        // t=0 first tick anchors.
        assert!(boot
            .maybe_anchor(clock.monotonic_millis())
            .unwrap()
            .is_some());
        // t=500 not due.
        clock.advance(500);
        assert!(boot
            .maybe_anchor(clock.monotonic_millis())
            .unwrap()
            .is_none());
        // t=1000 due again.
        clock.advance(500);
        assert!(boot
            .maybe_anchor(clock.monotonic_millis())
            .unwrap()
            .is_some());
    }
}
