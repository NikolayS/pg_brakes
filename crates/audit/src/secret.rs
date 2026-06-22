//! The secret store for DSNs + the audit signing key (SPEC §3, §4 "Secrets",
//! §10.9; issue #54, S4).
//!
//! The proxy/warden/core DSNs and the **audit signing key** must not live in
//! source, config files, or on the DB host — they live behind a [`SecretStore`]
//! seam so the dev impl can be swapped for a production secret manager (Vault /
//! AWS Secrets Manager / cloud KMS-wrapped material) without touching callers.
//!
//! # The seam
//! - [`SecretStore`] — fetch a named secret, **put** a new one, and **rotate**
//!   an existing one. Rotation is a first-class operation (SPEC §4 "rotation
//!   documented"): a new value atomically replaces the old, and any capability
//!   re-derived from the store afterwards uses the new material.
//! - [`LocalSecretStore`] — an in-memory dev impl. It holds the bytes in a
//!   `BTreeMap` and **never** logs or `Debug`-prints the material (the `Debug`
//!   impl redacts every value), so a secret cannot leak through a log line.
//!
//! # Key separation
//! The store is the *only* place the audit signing-key bytes exist in the dev
//! build, and the [`crate::kms`] capability is the *only* way to use them to
//! sign — there is no API that returns the raw key bytes to a caller. That keeps
//! the "audited principal cannot sign / the key is not on the DB host" property
//! enforceable at the type level (see [`crate::kms`]).
//!
//! ## Production target (documented, not built here)
//! - **DSNs:** a cloud secret manager (Vault / AWS Secrets Manager / GCP Secret
//!   Manager) referenced by id; the proxy reads them at boot and zeroizes the
//!   in-memory copy after connecting (SPEC §4 "proxy memory-handling noted").
//! - **Audit signing key:** never materialized as raw bytes — held in a KMS that
//!   performs the signature itself (the [`crate::kms::Kms`] trait models exactly
//!   this seam). Rotation is a KMS key-version bump; the anchor records the key
//!   id/version it used so old anchors stay verifiable. See `deploy/README.md`
//!   → *"Audit anchor, KMS key separation & secret store"*.

use std::collections::BTreeMap;

/// The canonical secret id of the audit chain-head **signing key**. The KMS dev
/// signer ([`crate::kms::LocalKms`]) loads its material from the store under
/// this id; production uses the same id to address a KMS key version.
pub const AUDIT_SIGNING_KEY_ID: &str = "audit/signing-key";

/// Errors a secret store can surface. Never carries the secret *value* — only
/// the id — so an error string is safe to log.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SecretError {
    /// No secret is stored under the requested id.
    #[error("secret not found: {id}")]
    NotFound {
        /// The id that was requested (never the value).
        id: String,
    },
    /// A `put` was issued for an id that already exists (use [`SecretStore::rotate`]
    /// to replace an existing secret — `put` is create-only, so an accidental
    /// overwrite is a typed error rather than a silent clobber).
    #[error("secret already exists (use rotate to replace): {id}")]
    AlreadyExists {
        /// The id that already had a value.
        id: String,
    },
    /// A `rotate` was issued for an id that does not exist yet (rotation replaces
    /// existing material; create it with [`SecretStore::put`] first).
    #[error("cannot rotate a secret that does not exist: {id}")]
    RotateMissing {
        /// The id that had no prior value to rotate.
        id: String,
    },
    /// The supplied secret material was empty — never a valid key/DSN.
    #[error("refusing to store an empty secret: {id}")]
    Empty {
        /// The id of the empty put/rotate attempt.
        id: String,
    },
}

/// A store of named secrets (DSNs, the audit signing key).
///
/// The contract is deliberately small: read a secret, create one, and rotate
/// one. There is **no** method that bulk-dumps every secret, and the trait is
/// the only way callers reach secret material — keeping the blast radius of a
/// leak minimal and rotation a first-class, explicit operation.
pub trait SecretStore {
    /// Fetch the secret bytes stored under `id`, or [`SecretError::NotFound`].
    fn get(&self, id: &str) -> Result<Vec<u8>, SecretError>;

    /// Create a new secret under `id`. Errors with [`SecretError::AlreadyExists`]
    /// if one is already present (use [`rotate`](SecretStore::rotate) to replace),
    /// or [`SecretError::Empty`] for empty material.
    fn put(&mut self, id: &str, value: &[u8]) -> Result<(), SecretError>;

    /// Replace the material of an existing secret (rotation). Errors with
    /// [`SecretError::RotateMissing`] if nothing exists under `id`, or
    /// [`SecretError::Empty`] for empty material. After this returns, any
    /// capability re-derived from the store uses the new material.
    fn rotate(&mut self, id: &str, value: &[u8]) -> Result<(), SecretError>;

    /// Whether a secret exists under `id` (without revealing its value).
    fn contains(&self, id: &str) -> bool {
        self.get(id).is_ok()
    }
}

/// In-memory dev secret store. **Not for production** — material lives in
/// process memory in the clear. It exists so the anchor/KMS seams are testable
/// and the local stack runs without a cloud secret manager.
///
/// The `Debug` impl **redacts** every value so a secret never lands in a log or
/// a panic message.
#[derive(Default, Clone)]
pub struct LocalSecretStore {
    secrets: BTreeMap<String, Vec<u8>>,
}

impl LocalSecretStore {
    /// A fresh, empty store.
    pub fn new() -> Self {
        LocalSecretStore {
            secrets: BTreeMap::new(),
        }
    }

    /// Number of secrets held (for tests/diagnostics — never the values).
    pub fn len(&self) -> usize {
        self.secrets.len()
    }

    /// Whether the store holds no secrets.
    pub fn is_empty(&self) -> bool {
        self.secrets.is_empty()
    }
}

impl std::fmt::Debug for LocalSecretStore {
    /// Redacting `Debug`: prints the ids but never the bytes, so a `{:?}` of the
    /// store (e.g. in a panic or a log line) cannot leak key material.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LocalSecretStore")
            .field("ids", &self.secrets.keys().collect::<Vec<_>>())
            .field("values", &"<redacted>")
            .finish()
    }
}

impl SecretStore for LocalSecretStore {
    fn get(&self, id: &str) -> Result<Vec<u8>, SecretError> {
        self.secrets
            .get(id)
            .cloned()
            .ok_or_else(|| SecretError::NotFound { id: id.to_string() })
    }

    fn put(&mut self, id: &str, value: &[u8]) -> Result<(), SecretError> {
        if value.is_empty() {
            return Err(SecretError::Empty { id: id.to_string() });
        }
        if self.secrets.contains_key(id) {
            return Err(SecretError::AlreadyExists { id: id.to_string() });
        }
        self.secrets.insert(id.to_string(), value.to_vec());
        Ok(())
    }

    fn rotate(&mut self, id: &str, value: &[u8]) -> Result<(), SecretError> {
        if value.is_empty() {
            return Err(SecretError::Empty { id: id.to_string() });
        }
        if !self.secrets.contains_key(id) {
            return Err(SecretError::RotateMissing { id: id.to_string() });
        }
        self.secrets.insert(id.to_string(), value.to_vec());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn put_get_roundtrips() {
        let mut s = LocalSecretStore::new();
        assert!(s.is_empty());
        s.put("dsn/proxy", b"host=127.0.0.1").unwrap();
        assert_eq!(s.get("dsn/proxy").unwrap(), b"host=127.0.0.1");
        assert_eq!(s.len(), 1);
        assert!(s.contains("dsn/proxy"));
        assert!(!s.contains("dsn/warden"));
    }

    #[test]
    fn put_is_create_only() {
        let mut s = LocalSecretStore::new();
        s.put("k", b"v1").unwrap();
        let err = s.put("k", b"v2").unwrap_err();
        assert_eq!(err, SecretError::AlreadyExists { id: "k".into() });
        // The original value is untouched.
        assert_eq!(s.get("k").unwrap(), b"v1");
    }

    #[test]
    fn rotate_replaces_existing_only() {
        let mut s = LocalSecretStore::new();
        let missing = s.rotate("k", b"v1").unwrap_err();
        assert_eq!(missing, SecretError::RotateMissing { id: "k".into() });
        s.put("k", b"v1").unwrap();
        s.rotate("k", b"v2").unwrap();
        assert_eq!(s.get("k").unwrap(), b"v2");
    }

    #[test]
    fn empty_material_is_rejected() {
        let mut s = LocalSecretStore::new();
        assert_eq!(
            s.put("k", b"").unwrap_err(),
            SecretError::Empty { id: "k".into() }
        );
        s.put("k", b"v").unwrap();
        assert_eq!(
            s.rotate("k", b"").unwrap_err(),
            SecretError::Empty { id: "k".into() }
        );
    }

    #[test]
    fn get_missing_is_typed_not_panic() {
        let s = LocalSecretStore::new();
        assert_eq!(
            s.get("nope").unwrap_err(),
            SecretError::NotFound { id: "nope".into() }
        );
    }

    #[test]
    fn debug_redacts_the_value() {
        let mut s = LocalSecretStore::new();
        s.put("audit/signing-key", b"super-secret-bytes").unwrap();
        let dbg = format!("{s:?}");
        assert!(dbg.contains("audit/signing-key"), "ids are visible: {dbg}");
        assert!(
            !dbg.contains("super-secret-bytes"),
            "the secret value must NOT appear in Debug: {dbg}"
        );
        assert!(dbg.contains("redacted"));
    }
}
