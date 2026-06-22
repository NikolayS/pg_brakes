//! Audit sinks: the append-only write target for sealed records (SPEC §4).
//!
//! A [`Sink`] is *append-only* — there is intentionally no update or delete in
//! the trait, because the audit log must be immutable evidence. The two MVP
//! implementations are:
//!
//! - [`InMemorySink`] — wraps an [`AuditChain`]; used by unit tests and as the
//!   reference for the chain semantics.
//! - the Postgres `_meta` sink ([`crate::pg`]) — appends to an append-only
//!   table whose grants `REVOKE` write from the audited principal.
//!
//! Both stamp time from `core::Clock` (passed in by the caller), so no sink
//! reads a wall clock itself and tests are fully deterministic.

use crate::chain::{AuditChain, ChainBreak, NewEntry};
use crate::record::AuditRecord;

/// Errors a sink can surface while appending or reading back the chain.
#[derive(Debug, thiserror::Error)]
pub enum SinkError {
    /// A backend (e.g. Postgres) returned an error.
    #[error("audit sink backend error: {0}")]
    Backend(String),
    /// The chain read back from the sink failed verification.
    #[error("audit chain integrity broken: {0:?}")]
    Integrity(ChainBreak),
}

/// An append-only audit sink.
///
/// The contract is deliberately minimal: append a sealed record, read the chain
/// back, and verify it. There is **no** mutation or deletion method — the audit
/// log is write-once, and tamper-evidence assumes the only legitimate operation
/// is append.
pub trait Sink {
    /// Append a new entry, stamping it at `timestamp_ms` (from `core::Clock`),
    /// and return the sealed record that was stored.
    fn append(&mut self, entry: NewEntry, timestamp_ms: u64) -> Result<AuditRecord, SinkError>;

    /// Read the full chain back, oldest first, for verification / export.
    ///
    /// Some backends (the synchronous Postgres `_meta` sink) cannot satisfy a
    /// `&self` read because the DB client needs `&mut`; they return a
    /// [`SinkError::Backend`] here and implement [`load_chain_mut`](Sink::load_chain_mut)
    /// instead. Callers that may hold such a sink should prefer `load_chain_mut`.
    fn load_chain(&self) -> Result<Vec<AuditRecord>, SinkError>;

    /// Read the full chain back, oldest first, with a **mutable** borrow.
    ///
    /// This is the universal read path: the in-memory sink delegates to the
    /// `&self` [`load_chain`](Sink::load_chain), and the Postgres `_meta` sink
    /// overrides it to drive its `&mut` client. The proxy/CLI anchoring + the
    /// fail-closed startup verify both read through this method so they work
    /// against **either** sink unchanged.
    fn load_chain_mut(&mut self) -> Result<Vec<AuditRecord>, SinkError> {
        self.load_chain()
    }

    /// Verify the persisted chain's integrity, returning the first broken link.
    fn verify(&self) -> Result<(), SinkError> {
        crate::chain::verify_chain(&self.load_chain()?).map_err(SinkError::Integrity)
    }

    /// Verify the persisted chain's integrity via the `&mut` read path (the one
    /// that works against the Postgres `_meta` sink too).
    fn verify_mut(&mut self) -> Result<(), SinkError> {
        crate::chain::verify_chain(&self.load_chain_mut()?).map_err(SinkError::Integrity)
    }
}

/// An in-memory append-only sink backed by an [`AuditChain`].
///
/// Used by unit tests and as the semantic reference for the persistent sink:
/// the bytes it stores are identical to what the Postgres sink stores, so a
/// chain appended here verifies the same way as one read from `_meta`.
#[derive(Debug, Clone, Default)]
pub struct InMemorySink {
    chain: AuditChain,
}

impl InMemorySink {
    /// A fresh, empty in-memory sink.
    pub fn new() -> Self {
        InMemorySink {
            chain: AuditChain::new(),
        }
    }

    /// Borrow the underlying chain (for `head_hash`/`len`/etc.).
    pub fn chain(&self) -> &AuditChain {
        &self.chain
    }
}

impl Sink for InMemorySink {
    fn append(&mut self, entry: NewEntry, timestamp_ms: u64) -> Result<AuditRecord, SinkError> {
        Ok(self.chain.append(entry, timestamp_ms))
    }

    fn load_chain(&self) -> Result<Vec<AuditRecord>, SinkError> {
        Ok(self.chain.records().to_vec())
    }
}

/// A **shared, cloneable** handle to one append-only [`Sink`] (SPEC §3/§4 — one
/// canonical `_meta` chain).
///
/// This is the seam that collapses the per-component, in-memory, ephemeral
/// chains into **one** chain: the proxy `Recorder` and the CLI approval flow each
/// hold a clone of the same `SharedSink`, so a proxy reject and a CLI approve
/// hash-chain into the **same** underlying sink (one genesis, one head). Wrap a
/// single backing sink — the Postgres `_meta` [`crate::pg::PgSink`] in
/// production, an [`InMemorySink`] in unit tests — once, then clone the handle to
/// every consumer.
///
/// The inner `Mutex` serializes appends, which a hash chain requires anyway (it
/// is inherently sequential). `load_chain_mut` (and `verify_mut`) read the same
/// underlying chain, so the interval anchorer and the fail-closed startup verify
/// see exactly the records both consumers appended.
#[derive(Clone)]
pub struct SharedSink {
    inner: std::sync::Arc<std::sync::Mutex<dyn Sink + Send>>,
}

impl SharedSink {
    /// Wrap a backing sink in a shared, cloneable handle. Every clone appends to
    /// and reads from the **same** underlying chain.
    pub fn new(sink: impl Sink + Send + 'static) -> Self {
        SharedSink {
            inner: std::sync::Arc::new(std::sync::Mutex::new(sink)),
        }
    }

    /// Wrap an already-shared `Arc<Mutex<dyn Sink + Send>>` (e.g. the exact
    /// trait-object handle the proxy `Recorder` is constructed from), so the
    /// anchorer/verify path and the recorder share the identical backing sink.
    pub fn from_arc(inner: std::sync::Arc<std::sync::Mutex<dyn Sink + Send>>) -> Self {
        SharedSink { inner }
    }

    /// The underlying shared handle, e.g. to hand the proxy `Recorder` the same
    /// `Arc<Mutex<dyn Sink + Send>>` this `SharedSink` wraps.
    pub fn arc(&self) -> std::sync::Arc<std::sync::Mutex<dyn Sink + Send>> {
        self.inner.clone()
    }
}

impl Sink for SharedSink {
    fn append(&mut self, entry: NewEntry, timestamp_ms: u64) -> Result<AuditRecord, SinkError> {
        let mut guard = self
            .inner
            .lock()
            .map_err(|_| SinkError::Backend("shared audit sink mutex poisoned".to_string()))?;
        guard.append(entry, timestamp_ms)
    }

    fn load_chain(&self) -> Result<Vec<AuditRecord>, SinkError> {
        let guard = self
            .inner
            .lock()
            .map_err(|_| SinkError::Backend("shared audit sink mutex poisoned".to_string()))?;
        guard.load_chain()
    }

    fn load_chain_mut(&mut self) -> Result<Vec<AuditRecord>, SinkError> {
        let mut guard = self
            .inner
            .lock()
            .map_err(|_| SinkError::Backend("shared audit sink mutex poisoned".to_string()))?;
        guard.load_chain_mut()
    }
}
