# pg_brakes — Decisions (SamoSpec)

Accepted / rejected / deferred decisions with rationale. Paired with SPEC.md **v0.7** — **CONVERGED**
across 4 review rounds (security/ops · QA/testability · buildability; round-3 BLOCKING resolved, round-4
MINORs closed). MVP build-ready pending founder review + 1 DECISION (LLM posture sequencing §15.4).

## ACCEPTED (v0.6 — round-3 resolutions)
- **FN claim split by damage class:** writes = 0 catastrophic FN by construction; **reads/exfil = bounded
  disclosure ≤ budget B + best-effort detection, NOT 0**. (Central honesty fix.) (§1/§13.2)
- **LLM anti-DoS/trust hardening:** trust tighten-only (no ramp-and-strike); attacker-controllable-only
  signals escalate-not-hard-block (+ rate-limit); per-class fail behavior. (§11.1)
- **§14 grant binding** expanded ({statement, params, role, session, proposal_id, dry_run_lsn,
  blast_radius_checksum, nonce, expiry} + re-verify); phishing-resistant approver auth; distinct-identity
  dual-control; unavailable-approver fails toward restriction. **MVP approval = CLI + signed grant + one
  webhook** (defer UI/dual-control/connectors). (§14)
- **§13 FP/FN rigor:** labeling oracle (labels from seeds via known-semantics transforms); metamorphic
  relations R1–R4; N≥30 + worst-case/majority aggregation + detection-plane regression gate; held-out
  mechanically enforced + corpus-refresh owner. (§13)
- **MVP scope triage (§15):** MVP = v0.4 core + T0–T2 capture (logged) + `RiskEngine` stub + CLI approval;
  LLM gating engine / §13 harness / T4 / §14-full = **fast-follow** (~separate 8–12w). T0–T2 schema +
  RiskEngine trait + grant token = spec-now/defer-impl (one-way doors).
- **§2:** stories 5/8/10 reworded to floor-level MVP accept; added day-2 **operator** story.

## CONFIRMED (founder)
- **LLM posture sequencing (§15.4) — AGREED 2026-06-20:** floor-only (MVP) → advisory non-gating
  (fast-follow v1) → gating (later, post-§13). End state = gating. Last open decision → spec
  BUILD-FROZEN for MVP.

## ACCEPTED
- **Working name = `pg_brakes`** (title only; brand TBD — name-brainstorm memo). Decided by Nik.
- **Scope = MVP** (Nik's calls): write-safety thin-clone moat IN · own Apache Rust proxy IN ·
  **focused frozen benchmark first** (full ~120-scenario set + public multi-competitor leaderboard
  DEFERRED post-MVP).
- **Benchmark trimmed to a focused frozen set first** (Nik: "smaller makes sense" — accepting Reviewer
  A). MVP = ~30–40 high-signal frozen scenarios, self-scoring, deterministic, golden expected-outcome,
  KNOWN_BYPASSES, third-party-runnable, + the marquee official-MCP-bypass repro. Defers the full set +
  the multi-competitor leaderboard. Frees ~1.5–2 weeks; keeps the trust artifact honest.
- **Apache-2.0 core; own proxy, not pgDog** (pgDog is AGPL → contaminates + enterprise-AGPL-allergy).
  `cargo-deny` gates CI to Apache/MIT/BSD/ISC.
- **Native roles = the security wall**, hardened (member-of-nothing; revoke `pg_read_all_data` + `pg_*`
  predefined roles + REPLICATION + PUBLIC EXECUTE; deny dblink/fdw/COPY-PROGRAM/lo_*/pg_read_file; pin
  search_path). *Accepted from Reviewer A — "not superuser" is insufficient.*
- **Mandatory network boundary** — agent role reaches Postgres ONLY via the proxy host (pg_hba +
  network). *Accepted from Reviewer A — direct-to-DB bypass otherwise defeats all enforcement + audit.*
  This is now a BLOCKING prerequisite, tested.
- **Clone treated as prod-classified data** — encryption-at-rest, RLS/column-grant parity, access
  logging, mandatory teardown, documented owner. *Accepted from Reviewer A — else the moat is an exfil
  channel; biggest CISO veto.*
- **Tamper-resistant audit** — hash-chain + external anchor (WORM/transparency log) + signing-key
  separation; audited principal cannot write audit. *Accepted from Reviewer A.*
- **Honest recovery model** — typed-inverse (cheap default) vs PITR restore-point (last resort,
  requires WAL archiving + tested restore, big RTO). Stop marketing both as cheap "nine lives".
  Sequences/trigger-side-effects/NOTIFY NOT restored (documented). *Accepted from Reviewer A.*
- **EXPLAIN-cost gate is advisory** (planner misestimation); real DoS backstop = statement_timeout +
  warden. *Accepted from Reviewer A.*
- **Guard = affected-PK-set checksum (not just cardinality) + apply-time drift re-check; refuse
  volatile/nondeterministic predicates; enumerated refused-op default-deny.** *Accepted from Reviewer B
  — row-identity drift (same count, different rows) was an undetected data-loss path.*
- **Benchmark must be deterministic + CI-gateable** — scripted frozen payloads (LLM out of the gating
  loop; live-agent suite non-gating), golden expected-outcome ("0 regressions" gate), clock-injection
  for time-to-auto-stop, KNOWN_BYPASSES deflates the headline, direct-to-DB bypass attempts in the
  suite, adversarially-curated legit corpus, reverts independently diffed. *Accepted from Reviewer B+A.*
- **TDD reorder** — clone↔prod fidelity + typed-inverse restore are red-tested in an S0 spike BEFORE
  building the proxy (riskiest assumptions first). *Accepted from Reviewer B.*
- **Warden kills only proxy-tagged/agent-role sessions; monitors replication slots + retained WAL;
  authenticated breaker.** *Accepted from Reviewer A (false-positive outages + slot-exfil/WAL-DoS).*
- **Cumulative per-role volume budget over a window** (anti slow-drip). *Accepted from Reviewer A.*

## ACCEPTED (v0.5 — founder-directed)
- **LLM IS used for risk evaluation** (Nik: "can be very helpful") — but **advisory & tighten-only**:
  it sets friction (auto / human-approve / hold), can never remove the deterministic floor. Auto-apply
  needs BOTH within-floor AND LLM-risk-low → a fooled LLM is *survivable* (worst case still bounded +
  reversible). Generic model first, **specialized/fine-tuned later**. (§11)
- **Intent capture is tiered & inferred at the wire** (Nik: don't expect rich input from agents; we sit
  at SQL/libpq): **T0 role · T1 SQL+comments+GUCs · T2 observed context · T3 MCP asserts (bonus)**.
  Baseline T0–T2; T3 enrichment, never required. ⇒ **universal coverage of any Postgres client** (elevate
  to positioning). (§11)
- **DBLab is OPTIONAL** (Nik: not installed initially) — and replica + PITR too. The bounded+reversible
  **guarantee is invariant**; baseline = **guarded apply** (txn on primary, no clone, no drift), DBLab
  upgrade = **clone rehearsal** (the moat, pre-flight preview). Graceful degradation; moat = upgrade,
  not gate. Baseline may build before the DBLab path. (§12)

- **LLM evaluates READS too** (Nik), multi-axis: performance/cost, security/exfiltration (bulk +
  slow-drip, PII-targeting, recon, injection, privilege-probing), compliance/policy, behavioral
  anomaly (+ extensible). Floor handles gross volume inline & fast (EXPLAIN/budget/cutoff blocks the
  "1M rows" case before it streams); LLM adds the semantic/intent layer + context-aware tuning. Latency
  architecture: **async-by-default** (query + session-pattern → warden/breaker/trust; catches slow-drip)
  + **inline-on-suspicion** + opt-in inline-always. Tighten-only; fail-safe to floor. (§11.6)

- **LLM may GATE (block), not just advise** (Nik) — autonomous BLOCK/HOLD on high-confidence suspicion.
  Consistent with tighten-only (blocking = tightening); never grants/loosens, so the worst LLM error is a
  **false-positive, never a breach**. Calibrated: block high / escalate medium / allow+log low (tunable).
  **Prod-gating ≠ CI-gating** (benchmark stays deterministic; LLM has its own non-gating FP/recall eval).
  Gate **fails open to floor** by default; fail-closed opt-in. (§11.1)
- **T4 origin/provenance context (OPTIONAL)** (Nik) — risk engine may see the upstream discussion / agent
  reasoning that generated the SQL → true intent-vs-action analysis. Attacker-controllable → tighten-only
  / detection unless **attested** (signed by trusted channel) to reduce friction; correlation ids
  attested to prevent spoofing. Privacy: opt-in, data-minimized, self-hosted-model option. Post-MVP;
  also a reason to adopt our MCP/SDK. (§11.7)

- **FP/FN targets + testing methodology** (Nik): **0 false negatives** (catastrophic FN = 0 *by
  construction* via the deterministic floor; detection FN measured & minimized), **minimal false
  positives**. Achieved by **calibration + large-scale testing** ("100k runs showed: …") — labeled
  corpora (dangerous / adversarial-legit / boundary), mutation + metamorphic + adversarial generation,
  two planes (deterministic floor = CI-gating with 0 catastrophic FN; LLM detection = statistical
  non-gating with confusion matrix/ROC/CIs), held-out set. Honest framing: 0-FN claim is empirical over
  the test distribution; the floor is the actual guarantee. (§13)
- **Authorization / unblock flow** (Nik): every block has a route to be unblocked by an **authorized
  human**. Routes by cause — routine approval (LLM hold / L1) · raise-the-bound (parameter floor block,
  stays reversible) · **break-glass + dual-control** (structural/irreversible). **Agent can't
  self-authorize**; grant is **signed, single-use, time-boxed, bound to the exact proposal** (TOCTOU-
  safe); fully audited; approvals feed calibration (§13.6). (§14)
- **§2 = the 10 main user stories** (Nik: ≤10).

## PROPOSED (v0.5 — pending Nik's confirmation; then a focused review round)
- LLM **fail-safe** (LLM down → floor + human for writes / floor-bounded for reads, never auto-allow on
  timeout) · **privacy** (hosted generic first, self-hosted/local for CISOs, send SQL+schema+stats not
  row data) · LLM layer **evaluated separately & non-gating** (floor stays the CI gate).

## REJECTED (for now)
- *pgDog as the proxy* — AGPL (see above).
- *Read-only-only MVP* — rejected by Nik (write-safety is the moat / differentiator).
- *MCP-only enforcement (no proxy)* — rejected by Nik (proxy in MVP for hostile-agent enforcement +
  benchmark credibility).
- *Literal absolute claims* ("physically cannot") in marketing/spec — rejected by Reviewer B; reworded
  to assertions over the frozen suite + KNOWN_BYPASSES.

## DEFERRED
- **Full ~120-scenario benchmark + multi-competitor public leaderboard** (raw conn / Crystal-via-
  Temporal / read-only gateway adapters) — post-MVP. *(Now ACCEPTED to defer; see above — Nik agreed
  smaller makes sense.)*
- DDL, multi-statement interactive txns, L2/L3 narrow-full-auto beyond the closed certified action set,
  multi-DB, cloud/multi-tenant, web console — post-MVP.
- Company brand selection (Pronea/Custra/Felis/… — separate from the `pg_brakes` working title).

## OPEN (resolve during S0)
- `policy.yaml` schema + the closed certified-action-set format for L2.
- Secret-store choice + key-rotation specifics; external-anchor target for the audit chain.
- Concierge-pilot design partner(s) confirmed (GitLab + 1 AI-builder customer) for S0–S2.
