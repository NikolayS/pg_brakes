//! pg_bumpers CLI binary (`pgb-cli`) — the MVP approval surface (SPEC §14).
//!
//! Subcommands:
//! - `pgb-cli approve <request-id>` — a human approver signs the §14.3
//!   proposal-bound grant for a pending request. In a real deployment the
//!   request store, the approver's audit-key-grade signing key (§10.9), and the
//!   webhook target are resolved from `policy.yaml` / KMS; this binary wires the
//!   library flow and documents the contract.
//! - `pgb-cli demo` — runs the full request → approve → verify-at-apply flow
//!   in-process against an in-memory store + audit chain, printing each step.
//!   This is a runnable smoke of the §14 mechanism (no DB, no network).
//!
//! The cryptography is entirely `pgb_policy`'s grant token (reused, not
//! reimplemented); this binary is glue + UX.

use std::process::ExitCode;

use ed25519_dalek::SigningKey;
use rand_core::OsRng;

use pgb_audit::{AuditBoot, LocalSecretStore, SecretStore, Sink, AUDIT_SIGNING_KEY_ID};
use pgb_cli::{
    ApprovalFlow, InMemoryNonceStore, Principal, Proposal, RecordingWebhookSender, RequestId,
};
use pgb_core::{inverse::Operation, Clock, SystemClock};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("approve") => match args.get(2) {
            Some(id) => {
                // In the MVP binary the request store is per-process; a real
                // deployment resolves it (and the signing key) from policy/KMS.
                // We document the contract and exit non-zero because there is no
                // standing request in this stub invocation.
                eprintln!(
                    "pgb-cli approve: would sign a single-use, proposal-bound grant for \
                     request `{id}` using the approver's audit-key-grade signing key (SPEC \
                     §10.9). The agent can never self-approve. Wire the request store + KMS \
                     key from policy.yaml to use this against a live request; run `pgb-cli \
                     demo` for an in-process end-to-end run."
                );
                ExitCode::from(2)
            }
            None => {
                eprintln!("usage: pgb-cli approve <request-id>");
                ExitCode::from(2)
            }
        },
        Some("demo") => match run_demo() {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("pgb-cli demo failed: {e}");
                ExitCode::from(1)
            }
        },
        _ => {
            println!(
                "pgb-cli — pg_bumpers approval CLI (SPEC §14 MVP).\n\
                 usage:\n  \
                 pgb-cli approve <request-id>   sign a proposal-bound grant (human approver)\n  \
                 pgb-cli demo                   run request -> approve -> verify-at-apply\n\
                 \n\
                 Set PGB_META_DSN (audit-writer DSN) + PGB_AUDIT_SIGNING_KEY to run the demo\n\
                 against the SHARED, persistent, anchored `_meta` chain (the one the proxy\n\
                 also writes); otherwise the demo runs in-process on an in-memory chain."
            );
            ExitCode::SUCCESS
        }
    }
}

/// Run the full §14 flow + print each step. When `PGB_META_DSN` +
/// `PGB_AUDIT_SIGNING_KEY` are set, the flow hash-chains into the **shared,
/// persistent, anchored `_meta` chain** (issue #64 — the same chain the proxy
/// writes), and the run anchors + fail-closed-verifies it on exit. Otherwise it
/// runs in-process on an in-memory chain (the DB-free smoke).
fn run_demo() -> Result<(), String> {
    let clock = SystemClock::new();

    // The approver's audit-key-grade signing key (§10.9). In production this is
    // KMS-held and separated from the DB operator; here it is generated for the
    // demo and its public half seeds the flow's verifier.
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();

    match (
        std::env::var("PGB_META_DSN").ok(),
        std::env::var("PGB_AUDIT_SIGNING_KEY").ok(),
    ) {
        (Some(dsn), Some(key)) if !dsn.is_empty() && !key.is_empty() => {
            // SHARED `_meta` path: build the boot handle, run the flow against a
            // clone of its shared sink, then anchor + fail-closed verify.
            let interval_ms: u64 = std::env::var("PGB_ANCHOR_INTERVAL_MS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(60_000);
            let mut store = LocalSecretStore::new();
            store
                .put(AUDIT_SIGNING_KEY_ID, key.as_bytes())
                .map_err(|e| e.to_string())?;
            let mut boot = AuditBoot::connect(&dsn, &store, interval_ms)
                .map_err(|e| format!("audit _meta boot failed (fail-closed): {e}"))?;
            let audit = boot.shared_sink();

            run_flow(audit, &signing_key, verifying_key, &clock)?;

            // Anchor the head we just extended, then fail-closed verify the
            // canonical chain against the anchored head.
            boot.maybe_anchor(clock.monotonic_millis())
                .map_err(|e| format!("audit anchor failed: {e}"))?;
            boot.startup_verify()
                .map_err(|e| format!("audit `_meta` chain verification failed: {e}"))?;
            let n = boot.load_chain().map(|c| c.len()).unwrap_or(0);
            println!(
                "audit: {n} records on the SHARED, anchored `_meta` chain; \
                 chain verified against its anchored head"
            );
            Ok(())
        }
        _ => {
            // DB-free smoke on an in-memory chain, wrapped in a SharedSink so we
            // can read the same chain back after the flow consumes its handle.
            let audit = pgb_audit::SharedSink::new(pgb_audit::InMemorySink::new());
            let readback = audit.clone();
            run_flow(audit, &signing_key, verifying_key, &clock)?;
            let chain_ok = readback.verify().is_ok();
            println!(
                "audit: {} records (in-memory), chain intact={}",
                readback.load_chain().map(|c| c.len()).unwrap_or(0),
                chain_ok
            );
            Ok(())
        }
    }
}

/// Drive request → approve → verify-at-apply over an arbitrary audit [`Sink`],
/// printing each step. The audit sink is whatever the caller injected — an
/// in-memory chain or a clone of the shared, persistent `_meta` chain.
fn run_flow<S: Sink>(
    audit: S,
    signing_key: &SigningKey,
    verifying_key: ed25519_dalek::VerifyingKey,
    clock: &dyn Clock,
) -> Result<(), String> {
    let mut flow = ApprovalFlow::new(
        audit,
        RecordingWebhookSender::new(),
        verifying_key,
        InMemoryNonceStore::new(),
    );

    let proposal = Proposal {
        proposal_id: "p-demo-1".to_string(),
        statement_text: "UPDATE public.orders SET status='fixed' WHERE id = $1".to_string(),
        normalized_params: vec!["42".to_string()],
        role: "app_writer".to_string(),
        session_id: "sess-demo".to_string(),
        dry_run_lsn: "3A/7F00C8".to_string(),
        blast_radius_checksum: "sha256:demo".to_string(),
    };
    // A bounded, reversible UPDATE — eligible for elevation (not structural).
    let op = Operation::Update {
        has_preimage: true,
        has_pk: true,
    };
    let id = RequestId("req-demo-1".to_string());

    // 1. The blocked write opens an APPROVAL_REQUIRED ticket + fires the webhook.
    let outcome = flow
        .request_elevation(id.clone(), proposal, "agent-demo", &op, 60_000, clock)
        .map_err(|e| format!("request_elevation: {e}"))?;
    println!(
        "1) request_elevation -> {} (request {}, webhook delivered={})",
        outcome.contract.code,
        outcome.contract.request_id,
        outcome.webhook.is_ok()
    );

    // 2. A human approver (NOT the agent) signs the grant.
    let approver = Principal::approver("human-alice");
    let approval = flow
        .approve(&id, &approver, signing_key, "nonce-demo-1", 30_000, clock)
        .map_err(|e| format!("approve: {e}"))?;
    println!("2) approve -> grant signed by `{}`", approver.id);

    // 3. At apply, re-derive the live binding and re-verify the grant.
    let live = flow
        .store()
        .get(&id)
        .expect("request exists")
        .proposal
        .to_binding("nonce-demo-1", approval.grant.binding.expiry_unix_millis);
    match flow.verify_at_apply(&approval.grant, &live, clock) {
        Ok(()) => println!("3) verify_at_apply -> VERIFIED (grant binds to the approved proposal)"),
        Err(e) => println!("3) verify_at_apply -> REJECTED: {e}"),
    }
    Ok(())
}
