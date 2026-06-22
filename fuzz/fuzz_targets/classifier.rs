//! Fuzz the **read-only SQL classifier** (SPEC §4 — the advisory, fail-closed
//! read-only gate).
//!
//! Two invariants under test:
//!
//! 1. **Never panics.** `classify`/`classify_with_reason` over arbitrary UTF-8
//!    must always return, never crash (it parses hostile SQL via sqlparser).
//!
//! 2. **The safety invariant has teeth.** The classifier is a *tighten-only*
//!    safety control: a write / DDL / multi-statement input must **never** be
//!    classified as a safe single `Read`. We assert this two ways:
//!      a. If the classifier ever says `Read`, the reason is `None` and a
//!         re-classification is stable (`Read` is deterministic).
//!      b. We synthesize inputs we KNOW are unsafe — by appending a stacked
//!         write statement (`; DROP TABLE …` / `; UPDATE …` etc.) to the fuzzer
//!         text — and assert the classifier NEVER returns `Read` for them.
//!         This is the property a deliberately-broken classifier (one that
//!         classifies a `DROP` as a read) would fail, proving the target's
//!         teeth.
//!
//! The fuzzer drives both: it controls the base SQL text AND which unsafe
//! suffix to append.

#![no_main]

use libfuzzer_sys::fuzz_target;
use pgb_pgwire::{classify, classify_with_reason, Classification};

/// Statements that are unambiguously NOT a safe single read. Appending any of
/// these (statement-stacked) to ANY base text yields input that the classifier
/// must reject — either as a write, a multi-statement, or a parse error. Never
/// as `Read`.
const UNSAFE_TAILS: &[&str] = &[
    "DROP TABLE users",
    "DELETE FROM accounts",
    "UPDATE accounts SET balance = 0",
    "INSERT INTO logs VALUES (1)",
    "TRUNCATE audit",
    "CREATE TABLE t (id int)",
    "ALTER TABLE t ADD COLUMN c int",
    "GRANT ALL ON t TO public",
    "COPY t FROM PROGRAM 'sh'",
];

fuzz_target!(|data: &[u8]| {
    // Need valid UTF-8 to feed &str; non-UTF-8 inputs are simply skipped (the
    // classifier only ever sees decoded protocol strings, which are UTF-8).
    let Ok(base) = std::str::from_utf8(data) else {
        return;
    };

    // --- Invariant 1: never panic on arbitrary SQL. ---
    let (cls, reason) = classify_with_reason(base);

    // --- Invariant 2a: `Read` is reason-free and stable. ---
    if cls == Classification::Read {
        assert!(
            reason.is_none(),
            "Read classification must carry no NotReadReason; got {reason:?} for {base:?}"
        );
        assert_eq!(
            classify(base),
            Classification::Read,
            "classification must be deterministic for {base:?}"
        );
    }

    // --- Invariant 2b: fail-closed teeth. Stacking a known write onto ANY base
    // must NEVER classify as a safe single read. The fuzzer picks the tail. ---
    let tail = UNSAFE_TAILS[(data.first().copied().unwrap_or(0) as usize) % UNSAFE_TAILS.len()];

    // `base ; <write>` — statement-stacked, the classic `SELECT 1; DROP …`
    // bypass. Must be NotRead (MultipleStatements / ParseError / NotARead).
    let stacked = format!("{base} ; {tail}");
    assert_ne!(
        classify(&stacked),
        Classification::Read,
        "SAFETY VIOLATION: stacked write classified as a safe read: {stacked:?}"
    );

    // The bare write alone must also never be a read.
    assert_ne!(
        classify(tail),
        Classification::Read,
        "SAFETY VIOLATION: bare write classified as a safe read: {tail:?}"
    );
});
