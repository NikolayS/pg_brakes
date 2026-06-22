//! Fuzz the **frontend (client→server) frame decoder** (SPEC §4 — hostile
//! FE/BE parse-loop fuzzing).
//!
//! Invariant under test: `FrontendMessage::decode(tag, body)` must **never
//! panic** on arbitrary bytes. It is the proxy's seam onto an untrusted client;
//! a malformed frame must produce a `ProtocolError` (fail-closed), never a
//! crash, unbounded allocation, or out-of-bounds read.
//!
//! We split the raw fuzz input into a 1-byte tag plus the remaining body so the
//! fuzzer exercises every `match tag { … }` arm, including the unknown-tag and
//! truncated-body paths.

#![no_main]

use libfuzzer_sys::fuzz_target;
use pgb_pgwire::FrontendMessage;

fuzz_target!(|data: &[u8]| {
    // First byte selects the message tag; the rest is the body. An empty input
    // still exercises the "empty body" decode paths via tag 0.
    let (tag, body) = match data.split_first() {
        Some((t, rest)) => (*t, bytes::Bytes::copy_from_slice(rest)),
        None => (0u8, bytes::Bytes::new()),
    };

    // The ONLY requirement: this must not panic. Ok or Err are both fine; a
    // malformed frame must be a clean `Err`, never a crash.
    let _ = FrontendMessage::decode(tag, body);
});
