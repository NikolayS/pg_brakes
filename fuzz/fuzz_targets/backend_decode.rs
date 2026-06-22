//! Fuzz the **backend (server→client) frame decoder** (SPEC §4 — hostile FE/BE
//! parse-loop fuzzing).
//!
//! Invariant under test: `BackendMessage::decode(tag, body)` must **never
//! panic** on arbitrary bytes. A compromised or buggy backend can send anything;
//! the proxy decodes backend frames to drive auth and surface results, so a
//! malformed backend frame must be a clean `ProtocolError`, never a crash or an
//! unbounded allocation driven by an attacker-declared count.
//!
//! As with the frontend target, the first byte selects the tag and the rest is
//! the body, so every `match tag { … }` arm (incl. the count-prefixed
//! RowDescription / DataRow paths) gets exercised.

#![no_main]

use libfuzzer_sys::fuzz_target;
use pgb_pgwire::BackendMessage;

fuzz_target!(|data: &[u8]| {
    let (tag, body) = match data.split_first() {
        Some((t, rest)) => (*t, bytes::Bytes::copy_from_slice(rest)),
        None => (0u8, bytes::Bytes::new()),
    };

    // Must not panic; malformed → Err, fail-closed.
    let _ = BackendMessage::decode(tag, body);
});
