//! Client-side **SCRAM-SHA-256** authentication of the agent (SPEC §7 S1).
//!
//! The proxy *terminates* the agent connection and *originates* a fresh backend
//! connection (terminate-and-originate, the MVP choice documented in the PR):
//! the agent proves it knows the proxy's agent password via SCRAM-SHA-256, and
//! only then does the proxy open the PG18 session as the WALL role. SCRAM means
//! the agent's password never crosses the wire in the clear and the proxy
//! verifies the proof without a plaintext compare.
//!
//! This is a **clean-room** implementation of the server side of SCRAM-SHA-256
//! (RFC 5802 + RFC 7677, channel-binding `n` / no `-PLUS`) built from the RFCs
//! and PostgreSQL's `AuthenticationSASL*` framing in [`pgb_pgwire::scram`]. No
//! pgDog code was consulted.
//!
//! ## Scope / honesty
//! The proxy stores the agent password as configured material and derives the
//! SCRAM keys per-handshake. A production deployment would store only the
//! `StoredKey`/`ServerKey` + salt (a SCRAM verifier), never the password; that
//! refinement is noted as MVP-minimal. Channel binding is not negotiated
//! (`gs2-cbind-flag = n`), which is acceptable since the listener TLS is
//! terminated at the proxy.

use base64::Engine as _;
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

type HmacSha256 = Hmac<Sha256>;

/// SCRAM iteration count for newly-derived salted keys. PostgreSQL defaults to
/// 4096; we match it.
const ITERATIONS: u32 = 4096;
/// Salt length in bytes for a freshly-derived verifier.
const SALT_LEN: usize = 16;
/// Server nonce length (random bytes, base64-encoded into the nonce string).
const SERVER_NONCE_LEN: usize = 18;

/// Errors raised while authenticating an agent over SCRAM.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ScramError {
    /// The client-first / client-final message was malformed.
    #[error("malformed SCRAM message: {0}")]
    Malformed(&'static str),
    /// The selected mechanism is not SCRAM-SHA-256.
    #[error("unsupported SASL mechanism")]
    UnsupportedMechanism,
    /// The client nonce in the final message did not extend the server nonce.
    #[error("SCRAM nonce mismatch")]
    NonceMismatch,
    /// The client's `ClientProof` did not verify — wrong password. **Auth fails
    /// closed.**
    #[error("SCRAM authentication failed (bad proof)")]
    BadProof,
    /// A base64 field did not decode.
    #[error("SCRAM base64 decode error")]
    Base64,
}

fn b64() -> base64::engine::GeneralPurpose {
    base64::engine::general_purpose::STANDARD
}

/// The server-side SCRAM verifier secret for one principal: salted, iterated
/// keys derived from the password. In production these are stored; here they are
/// derived from the configured agent password per server start.
#[derive(Debug, Clone)]
pub struct ScramVerifier {
    salt: Vec<u8>,
    iterations: u32,
    stored_key: [u8; 32],
    server_key: [u8; 32],
}

impl ScramVerifier {
    /// Derive a verifier from a cleartext password with a fresh random salt.
    pub fn from_password(password: &str) -> Self {
        let mut salt = vec![0u8; SALT_LEN];
        rand::thread_rng().fill_bytes(&mut salt);
        Self::from_password_with_salt(password, salt, ITERATIONS)
    }

    /// Derive a verifier from a password, salt, and iteration count
    /// (deterministic — used by tests).
    pub fn from_password_with_salt(password: &str, salt: Vec<u8>, iterations: u32) -> Self {
        let salted = hi(password.as_bytes(), &salt, iterations);
        let client_key = hmac(&salted, b"Client Key");
        let stored_key: [u8; 32] = Sha256::digest(client_key).into();
        let server_key = hmac(&salted, b"Server Key");
        ScramVerifier {
            salt,
            iterations,
            stored_key,
            server_key,
        }
    }
}

/// The server-side handshake state machine. Drives the two SCRAM round-trips:
/// `client-first → server-first` then `client-final → server-final`.
#[derive(Debug)]
pub struct ScramServer {
    verifier: ScramVerifier,
    server_nonce: String,
    client_first_bare: Option<String>,
    server_first: Option<String>,
    full_nonce: Option<String>,
}

/// The server's reply to a client-first message: the `server-first-message`
/// challenge to send back inside `AuthenticationSASLContinue`.
#[derive(Debug, Clone)]
pub struct ServerFirst {
    /// The `r=…,s=…,i=…` server-first-message bytes.
    pub message: String,
}

/// The server's reply to a client-final message: the `server-final-message`
/// (`v=…`) to send inside `AuthenticationSASLFinal`, sent only after the proof
/// verified.
#[derive(Debug, Clone)]
pub struct ServerFinal {
    /// The `v=ServerSignature` server-final-message bytes.
    pub message: String,
}

impl ScramServer {
    /// Start a handshake for a principal with the given verifier.
    pub fn new(verifier: ScramVerifier) -> Self {
        let mut nonce_bytes = [0u8; SERVER_NONCE_LEN];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        ScramServer {
            verifier,
            server_nonce: b64().encode(nonce_bytes),
            client_first_bare: None,
            server_first: None,
            full_nonce: None,
        }
    }

    /// Construct with a fixed server nonce (deterministic — used by tests).
    pub fn with_server_nonce(verifier: ScramVerifier, server_nonce: String) -> Self {
        ScramServer {
            verifier,
            server_nonce,
            client_first_bare: None,
            server_first: None,
            full_nonce: None,
        }
    }

    /// Process the SCRAM `client-first-message` (the bytes from a
    /// `SASLInitialResponse` initial-response) and produce the server-first
    /// challenge.
    ///
    /// `client_first` looks like `n,,n=user,r=<client-nonce>`. We tolerate any
    /// gs2 header (channel binding `n`/`y`/authzid) and extract the bare part.
    pub fn handle_client_first(&mut self, client_first: &str) -> Result<ServerFirst, ScramError> {
        // gs2 header is everything up to and including the second comma.
        let bare = strip_gs2_header(client_first)?;
        let client_nonce = field(bare, 'r').ok_or(ScramError::Malformed("missing r="))?;

        let full_nonce = format!("{client_nonce}{}", self.server_nonce);
        let server_first = format!(
            "r={full_nonce},s={},i={}",
            b64().encode(&self.verifier.salt),
            self.verifier.iterations
        );

        self.client_first_bare = Some(bare.to_string());
        self.server_first = Some(server_first.clone());
        self.full_nonce = Some(full_nonce);
        Ok(ServerFirst {
            message: server_first,
        })
    }

    /// Process the SCRAM `client-final-message` and verify the `ClientProof`.
    ///
    /// Returns the `server-final-message` (`v=…`) on success; fails closed with
    /// [`ScramError::BadProof`] on a bad password.
    pub fn handle_client_final(&self, client_final: &str) -> Result<ServerFinal, ScramError> {
        let client_first_bare = self
            .client_first_bare
            .as_deref()
            .ok_or(ScramError::Malformed("client-final before client-first"))?;
        let server_first = self
            .server_first
            .as_deref()
            .ok_or(ScramError::Malformed("no server-first"))?;
        let expected_nonce = self
            .full_nonce
            .as_deref()
            .ok_or(ScramError::Malformed("no nonce"))?;

        let channel_binding =
            field(client_final, 'c').ok_or(ScramError::Malformed("missing c="))?;
        let final_nonce = field(client_final, 'r').ok_or(ScramError::Malformed("missing r="))?;
        let proof_b64 = field(client_final, 'p').ok_or(ScramError::Malformed("missing p="))?;

        if final_nonce != expected_nonce {
            return Err(ScramError::NonceMismatch);
        }

        // client-final-without-proof = "c=<cb>,r=<nonce>".
        let client_final_without_proof = format!("c={channel_binding},r={final_nonce}");
        let auth_message =
            format!("{client_first_bare},{server_first},{client_final_without_proof}");

        // ClientSignature = HMAC(StoredKey, AuthMessage)
        let client_signature = hmac(&self.verifier.stored_key, auth_message.as_bytes());
        let proof = b64().decode(proof_b64).map_err(|_| ScramError::Base64)?;
        if proof.len() != 32 {
            return Err(ScramError::BadProof);
        }
        // ClientKey = ClientProof XOR ClientSignature
        let mut client_key = [0u8; 32];
        for i in 0..32 {
            client_key[i] = proof[i] ^ client_signature[i];
        }
        // Verify: SHA256(ClientKey) must equal StoredKey (constant-time).
        let recomputed_stored: [u8; 32] = Sha256::digest(client_key).into();
        if recomputed_stored
            .ct_eq(&self.verifier.stored_key)
            .unwrap_u8()
            != 1
        {
            return Err(ScramError::BadProof);
        }

        // ServerSignature = HMAC(ServerKey, AuthMessage)
        let server_signature = hmac(&self.verifier.server_key, auth_message.as_bytes());
        Ok(ServerFinal {
            message: format!("v={}", b64().encode(server_signature)),
        })
    }
}

/// Strip the gs2 header (`<cbind-flag>,<authzid>,`) and return the
/// client-first-bare portion.
fn strip_gs2_header(client_first: &str) -> Result<&str, ScramError> {
    // The header is the part before the second comma: `n,,` or `y,,` or
    // `p=tls-server-end-point,,` or `n,a=authzid,`.
    let mut commas = 0;
    for (i, b) in client_first.bytes().enumerate() {
        if b == b',' {
            commas += 1;
            if commas == 2 {
                return Ok(&client_first[i + 1..]);
            }
        }
    }
    Err(ScramError::Malformed("missing gs2 header"))
}

/// Extract the value of a single-letter SCRAM attribute (`r`, `s`, `i`, `c`,
/// `p`, `n`) from a comma-separated message.
fn field(msg: &str, key: char) -> Option<&str> {
    let prefix = format!("{key}=");
    msg.split(',')
        .find(|part| part.starts_with(&prefix))
        .map(|part| &part[prefix.len()..])
}

/// HMAC-SHA-256.
fn hmac(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

/// PBKDF2-HMAC-SHA-256 (`Hi` in RFC 5802).
fn hi(password: &[u8], salt: &[u8], iterations: u32) -> [u8; 32] {
    let mut out = [0u8; 32];
    pbkdf2::pbkdf2::<HmacSha256>(password, salt, iterations, &mut out)
        .expect("pbkdf2 output length is valid");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal SCRAM **client** so we can drive the server end-to-end in a
    /// unit test (mirrors what a real libpq/tokio-postgres client does).
    fn client_proof(
        password: &str,
        client_nonce: &str,
        server_first: &str,
        client_first_bare: &str,
    ) -> (String, String) {
        let salt = b64().decode(field(server_first, 's').unwrap()).unwrap();
        let iters: u32 = field(server_first, 'i').unwrap().parse().unwrap();
        let full_nonce = field(server_first, 'r').unwrap();

        let salted = hi(password.as_bytes(), &salt, iters);
        let client_key = hmac(&salted, b"Client Key");
        let stored_key: [u8; 32] = Sha256::digest(client_key).into();

        let channel_binding = b64().encode(b"n,,");
        let client_final_without_proof = format!("c={channel_binding},r={full_nonce}");
        let auth_message =
            format!("{client_first_bare},{server_first},{client_final_without_proof}");
        let client_signature = hmac(&stored_key, auth_message.as_bytes());
        let mut proof = [0u8; 32];
        for i in 0..32 {
            proof[i] = client_key[i] ^ client_signature[i];
        }
        let _ = client_nonce;
        (
            format!("{client_final_without_proof},p={}", b64().encode(proof)),
            auth_message,
        )
    }

    #[test]
    fn full_handshake_with_correct_password_succeeds() {
        let password = "pgb_agent_dev_pw";
        let verifier = ScramVerifier::from_password_with_salt(password, vec![1u8; 16], 4096);
        let mut server = ScramServer::with_server_nonce(verifier, "SERVERNONCE".to_string());

        let client_nonce = "clientnonce123";
        let client_first = format!("n,,n=pgb_agent,r={client_nonce}");
        let client_first_bare = &client_first[3..];
        let sf = server.handle_client_first(&client_first).unwrap();

        let (client_final, _) =
            client_proof(password, client_nonce, &sf.message, client_first_bare);
        let server_final = server.handle_client_final(&client_final).unwrap();
        assert!(server_final.message.starts_with("v="));
    }

    #[test]
    fn wrong_password_fails_closed() {
        let verifier =
            ScramVerifier::from_password_with_salt("right_password", vec![2u8; 16], 4096);
        let mut server = ScramServer::with_server_nonce(verifier, "NONCE".to_string());
        let client_first = "n,,n=pgb_agent,r=abc";
        let sf = server.handle_client_first(client_first).unwrap();
        // The client computes its proof from the WRONG password.
        let (client_final, _) =
            client_proof("wrong_password", "abc", &sf.message, "n=pgb_agent,r=abc");
        assert!(matches!(
            server.handle_client_final(&client_final),
            Err(ScramError::BadProof)
        ));
    }

    #[test]
    fn tampered_nonce_is_rejected() {
        let verifier = ScramVerifier::from_password_with_salt("pw", vec![3u8; 16], 4096);
        let mut server = ScramServer::with_server_nonce(verifier, "NONCE".to_string());
        server.handle_client_first("n,,n=u,r=abc").unwrap();
        // A client-final whose r= does not match the agreed full nonce.
        let cb = b64().encode(b"n,,");
        let bad = format!("c={cb},r=DIFFERENT,p={}", b64().encode([0u8; 32]));
        assert!(matches!(
            server.handle_client_final(&bad),
            Err(ScramError::NonceMismatch)
        ));
    }

    #[test]
    fn strips_various_gs2_headers() {
        assert_eq!(strip_gs2_header("n,,n=u,r=x").unwrap(), "n=u,r=x");
        assert_eq!(strip_gs2_header("y,,n=u,r=x").unwrap(), "n=u,r=x");
        assert_eq!(strip_gs2_header("n,a=other,n=u,r=x").unwrap(), "n=u,r=x");
    }
}
