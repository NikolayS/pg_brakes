<!-- SamoSpec-format spec (emulated). Tool: https://github.com/NikolayS/samospec -->
# pg_bumpers — SPEC

## 9. Version header
- **Project:** `pg_bumpers` (working title; brand TBD — see name-brainstorm memo)
- **Spec version:** v0.8.1 (BUILD-FROZEN MVP + founder build-corrections: BYO Postgres FUX, PG 14–18,
  Rust-only/no-Node — §0.5; converged across 4 review rounds)
- **Date:** 2026-06-20
- **License:** Apache-2.0 · **Repo home:** PostgresAI org, standalone-branded
- **Status:** **CONVERGED — BUILD-FROZEN for the MVP.** Last open decision (LLM posture sequencing,
  §15.4) CONFIRMED by founder (floor-only → advisory → gating). Architecture: deterministic floor +
  tighten-only LLM risk-gate §11; tiered intent T0–T4; optional DBLab/replica with invariant
  bounded+reversible guarantee §12; FN split by damage class §13; authorization/unblock §14; MVP scope
  triage §15. Fast-follow items explicitly carved out (§15.2). Awaiting founder's final read; no code
  until the go.
- **Method:** SamoSpec-format (Lead draft → Reviewer A security/ops + Reviewer B QA/testability +
  Reviewer C buildability → revise; 4 rounds).

---

## 1. Goal & why
**Goal:** Let AI agents read and write **production Postgres** safely. The honest claim, **split by
damage class** (per review round 3):
- **Writes (reversible damage):** 0 catastrophic false-negatives **by construction** — every applied
  write is bounded + reversible (data-loss is prevented or undoable).
- **Reads (disclosure):** *not* zero by construction — disclosure can't be un-happened. The structural
  guarantee is **bounded disclosure** (≤ a per-role byte/row budget before cutoff/kill) + **best-effort
  detection** of exfiltration patterns. We say "prevented" for data-loss, "bounded + detected" for
  exfiltration — never "impossible."

**Why now:** agents now touch prod DBs, often in `--dangerously-skip-permissions` / YOLO modes. The
Replit agent deleted SaaStr's production database; the official Anthropic Postgres MCP read-only mode
was bypassed by statement-stacking (`COMMIT; DROP SCHEMA…`) — Datadog: *app-layer protection is
insufficient; you need native Postgres RBAC.*

**The moat:** every risky **write** is rehearsed on an instant thin clone of prod (DBLab), blast radius
**measured**, then applied reversibly under guards. Tagline: *"your database has nine lives."*
**DBLab is OPTIONAL** (not installed initially). The bounded+reversible *guarantee* holds without it via
**guarded apply** (baseline); DBLab is the upgrade that adds pre-flight rehearsal/preview = the moat.
See §12 (graceful degradation).

**Honest recovery model (per review):** two distinct mechanisms — (a) **typed-inverse** = cheap, fast,
the default undo (UPDATE/DELETE pre-image); (b) **PITR restore-point** = last-resort, **requires the
customer to run continuous WAL archiving + a tested restore**, with large RTO on big DBs. Do NOT market
both as cheap "nine lives." Sequences, trigger side-effects, and NOTIFY are NOT restored by the inverse
(documented, tested).

**Non-goals (v0):** multi-tenant SaaS, non-Postgres engines, cloud/hosted plane, DDL full-auto,
multi-statement interactive txns, masking beyond RLS, polished web console.

## 0.5 Supported environment & first-user experience (BYO Postgres)
- **The user brings their own production Postgres.** The first-run path is "**point pg_bumpers at your
  existing database**" (DSNs in `policy.yaml`: target primary, optional read replica, audit/`_meta`
  location). We **never require** the user to spin up a database. Quickstart/README leads with BYO.
- **The docker-compose demo cluster is CI/dev/test ONLY** (a deterministic fixture for our own tests and
  the benchmark) — it is **not** the onboarding flow. Clearly labeled as such; no "throwaway PG instance"
  in the user quickstart.
- **Supported PostgreSQL: 14, 15, 16, 17, 18** (target the user's existing version; **do NOT pin to 18**;
  most prod is 14–16). Version-specific features must degrade/gate gracefully; the wire proxy + role wall
  are version-agnostic. CI matrix tests against this range.
- **Implementation is Rust-only — NO Node/TypeScript.** The MCP server is a Rust crate (`rmcp`). No
  pnpm/node in the toolchain or CI.

## 2. User stories (the 10 main)
1. **Bound every write (DBA / buyer):** As a DBA, I want every agent write bounded and reversible, so a
   mistake or attack can't cause an irreversible incident. *Accept:* no-WHERE `UPDATE` blocked/reverted
   from compose.
2. **Low-friction eval (SRE):** As an SRE, I want to deploy audit-only against a replica (or even a bare
   primary, no DBLab) in an afternoon, so I can evaluate without infra changes. *Accept:* docker-compose;
   graceful degradation (§12).
3. **Productive agent (AI-app / coding-agent dev):** As a developer, I want my agent — via MCP *or* plain
   libpq — to do RCA and fixes, so I get speed without fearing a `DROP`. *Accept:* any libpq client; reads
   cost-gated; writes propose→dry_run→apply.
4. **Self-correcting agent (the agent):** As an agent, I want every block to return a structured,
   recoverable next step + the dry-run blast radius, so I can fix my action without a human. *Accept:*
   block contract; `confirm_rows`.
5. **Bound disclosure (security eng):** As a security engineer, I want any read capped at a per-role
   budget (cutoff + per-window cumulative), so a compromised/jailbroken agent can leak **at most a bounded
   amount** before kill. *Accept (MVP):* single-shot byte cutoff + cumulative budget → kill at ≤ B.
   *Fast-follow:* semantic/slow-drip exfil detection + escalation (§11.6).
6. **Confident mass change (data engineer):** As a data engineer, I want to rehearse a large backfill on
   a clone, see exactly what it touches, then apply under a guard, so I can run mass changes safely.
   *Accept:* dry-run blast radius; guarded apply; reversible.
7. **Safe RCA under pressure (on-call):** As on-call, I want the agent's read-only RCA on a replica to
   never melt the DB, so diagnosis doesn't cause a second outage. *Accept:* statement_timeout +
   byte-cutoff (S1 floor); EXPLAIN-cost gate + cumulative volume budget land S4.
8. **Approve & unblock (authorized approver):** As an approver, I want blocked/held actions routed to me
   with the SQL, blast radius, intent and reason — to approve (with scope/expiry), deny, or break-glass —
   so legitimate work proceeds safely and exceptions are controlled. *Accept (MVP):* CLI approval emitting
   a signed, single-use, proposal-bound grant + one generic webhook; fully audited. *Fast-follow:*
   approval UI, dual-control, tiered approvers (§14).
9. **Operate day-2 (operator/installer):** As the operator, I want to run pg_bumpers safely over time —
   key rotation, clone-reaper/orphan alarms, breaker recovery, degraded-mode transitions, and set the
   `policy.yaml` (roles, budgets, autonomy L0–L2) — so it stays healthy and correctly configured.
   *Accept:* `policy.yaml`; reaper + breaker + anchor runbooks; graceful-degradation transitions visible.
10. **Explainable, provable audit (CISO / auditor):** As a CISO/auditor, I want every
    allow/block/revert/approve decision recorded tamper-evidently with its reason, intent signals and
    optional origin context — and a published safety benchmark — so I can approve agent access and explain
    incidents. *Accept (MVP):* hash-chained audit + external anchor; decision rationale; deterministic
    benchmark + KNOWN_BYPASSES. *Fast-follow:* the 100k-run FP/FN report (§13).

## 3. Architecture
**Four layers + a mandatory network boundary.**
0. **NETWORK BOUNDARY (new, blocking):** the agent role's `pg_hba.conf` + network policy permit
   connections **only from the proxy host**. Without this, an agent connects direct-to-DB, bypassing
   all enforcement and leaving audit holes. This is what makes the proxy meaningful.
1. **WALL — native Postgres roles/RLS (hardened):** agent role `NOINHERIT`, **member of nothing**, no
   superuser, no write grant, SELECT-whitelist, **REVOKE `pg_read_all_data` + all `pg_*` predefined
   roles + REPLICATION + PUBLIC EXECUTE**, `search_path` pinned, `dblink`/`postgres_fdw`/`COPY …
   PROGRAM`/`lo_*`/`pg_read_file` denied. "Not superuser" is insufficient — see role-hardening matrix.
2. **ENFORCEMENT — own Apache Rust proxy (inline, agent-only endpoint) + out-of-band warden.** Proxy:
   replica routing, read-only, EXPLAIN-cost gate **(advisory — defeated by planner misestimation; the
   real DoS backstop is `statement_timeout` + warden)**, row/byte mid-stream cutoff, **cumulative
   per-role volume budget over a window** (anti slow-drip), timeout injection, hash-chained audit; force
   extended protocol (kills statement-stacking), reject COPY/simple-query-fallback. Warden: kills only
   **proxy-tagged / agent-role** sessions (avoid false-positive outages on shared roles); watches
   `pg_stat_activity`/`pg_stat_statements`/lag **+ replication-slot creation/retained-WAL**; owns the
   circuit breaker (authenticated warden→proxy).
3. **INTENT/UX — MCP server (cooperative):** intent-typed tools; executes *through* the proxy; not a
   security boundary by itself.
4. **WRITE-SAFETY (two impls, one guarantee = bounded + reversible):** *baseline* **guarded apply** (no
   deps) — apply in a txn on the primary with PITR fence + PK-set/row-count guard (abort before commit
   on overrun) + typed-inverse; no clone-drift (same txn). *upgrade* **DBLab thin-clone dry-run**
   (OPTIONAL, the moat) — propose → rehearse on isolated clone → measured blast-radius *preview* (zero
   prod impact) → guarded apply. **Clone is prod-classified data** (governance below). DBLab optional /
   runtime-detected (`clone.provider: none|dblab`); see §12.

```
<!-- architecture:begin -->
   AI agent (MCP)         hostile/raw client
        |                        |
   (MCP tools)              (raw libpq)
        v                        v
  +-----------+   exec-thru  +==================+   pg_hba: ONLY from proxy host
  | MCP server|------------->|  Apache PROXY    |  read-only, replica-route,
  | propose/  |              |  EXPLAIN(advisory)|  byte+cumulative cutoff,
  | dry_run/  |              |  timeout, audit  |  extended-proto only, NO COPY
  | apply/... |              +========+=========+
  +-----+-----+                       | reads
        | dry_run/apply               v
        v                      +---------------+      +----------------+
  +-------------------+ clone  | DBLab CLONE   |      | Postgres REPLICA|
  | clone-orchestr.   |------> | (prod-PII!    |      +-------+--------+
  | PK-set guard,     |        |  governed:    |              |
  | PITR fence,       |        |  enc, RLS-par,|              |
  | typed-inverse,    |        |  teardown)    |     guarded apply
  | drift re-check    |        +---------------+        |  (fence+guard)
  +---------+---------+                                 v
            ^                                    Postgres PRIMARY
   WALL (hardened roles, member-of-nothing) ----------^  ^
            ^         +--------------+  watch+slots     |
            +---------|  WARDEN (oob)|--kill agent-tagged backends only
                      |  breaker(authn)|
                      +------+-------+
                             v
              hash-chained AUDIT + EXTERNAL ANCHOR (WORM/transparency log;
              signing key separated from operator; audited cannot write audit)
<!-- architecture:end -->
```

**Repo (single Cargo workspace — Rust-only, NO Node/TS):** `crates/{proxy,warden,core,policy,
clone-orchestrator,pgwire,audit,mcp,cli}` — the **MCP server is a Rust crate** using the official Rust
MCP SDK (`rmcp`, Apache-2.0/MIT). `deploy/` holds the docker-compose stack which is **CI/dev/test ONLY**
(not the first-user experience — see §0.5). Separate: `dbsafe-bench`. (Approval UI deferred; CLI approval
in MVP — §15.5.)

## 4. Implementation details
- **Network/roles (do FIRST):** role-hardening matrix as code + tests — enumerate every revoke/deny
  above; assert agent role is member of nothing and `pg_hba` permits proxy-host only. Enumerate
  installed extensions; deny `dblink`/fdw or block egress at network layer.
- **Proxy (Rust/tokio, `pgwire` MIT/Apache):** enforcement hooks in the FE/BE loop; `sqlparser-rs`
  (Apache) classify; `libpg_query`/`pg_query.rs` (BSD/PostgreSQL-license, feature-flagged) for
  write-path parse. Parse advisory only; un-foolable guarantees = network-boundary + hardened role +
  read-only replica + `statement_timeout` + byte-cutoff (all fail-closed). Volatile/SECURITY-DEFINER
  functions that can write server-side: flagged/denied for the agent role.
- **Warden (Rust, oob):** poll 1–5s (**interval mockable for tests**); cancel/terminate only
  agent-tagged sessions; monitor replication slots + retained WAL; breaker state authenticated.
- **MCP (Rust, `rmcp`):** `whoami`, `discover_schema`, `query`, `explain_plan`, `propose_write`, `dry_run`,
  `apply_write`, `request_elevation`, `get_audit`. Block contract `{status,code,reason,remedy,
  retryable}`. `confirm_rows` forcing function. Stateless; proposal/ticket state in core (TTL).
  Result data can NEVER widen capability (prompt-injection-via-data defense).
- **Clone-orchestrator (Rust):** warm DBLab clone pool; dry-run exact statement in a rolled-back txn;
  measure blast radius (rows incl. cascades/triggers via `pg_stat_xact_*` deltas, locks + max-lock-mode,
  duration, WAL bytes, constraint violations, sample diff, **affected-PK set/checksum**, reversible?,
  clone LSN + staleness). **Guard = PK-set checksum, not just cardinality** (catches row-identity drift:
  same count, different rows). **Refuse volatile/nondeterministic predicates** (`now()`, `random()`).
  Guarded apply: `pg_create_restore_point` fence → txn `statement_timeout≈3×dry-run` → **re-check
  affected-PK set vs dry-run at apply time** (abort on any drift; 0-tolerance destructive) → commit;
  typed-inverse from captured pre-image; **enumerated refused-op list** (TRUNCATE/DROP/ALTER/volatile
  -default-INSERT/no-pre-image-DELETE) default-deny outside the closed certified action set.
- **Clone governance (blocking):** clone = prod-classified; encryption-at-rest, **RLS/column-grant
  parity with prod**, access-logged, **mandatory teardown after dry-run**, documented location/owner.
- **Policy (Rust lib, compiled into proxy+core):** one `policy.yaml`.
- **Audit (Rust):** append-only hash-chained rows in `_meta` DB **+ external anchor** of the chain head
  (object-lock/WORM or transparency log) on an interval; **signing key separated** from the DB
  operator; `REVOKE` so the audited principal cannot write/rewrite audit. Records every statement incl.
  rejects.
- **Secrets:** proxy/warden/core DSNs + audit signing key in a secret store; rotation documented; proxy
  memory-handling noted.
- **License hygiene:** `cargo-deny` → Apache/MIT/BSD/ISC only (ban GPL/AGPL). (Rust-only; no JS deps.)
- **Benchmark (`dbsafe-bench`, FOCUSED first):** deterministic seeded OLTP Postgres (FKs/triggers/
  partitions/PII), **scripted frozen YAML payloads** (~30–40 high-signal attacks across exfil/DoS/
  data-loss incl. statement-stacking + **direct-to-DB bypass attempts**), **adversarially-curated**
  legit corpus (designed to surface FPs), reproducible (pinned PG/DBLab versions, seeded RNG, frozen
  `now()`), **golden expected-outcome file** (CI gate = "0 regressions vs golden", not a recomputed
  ≥99%), KNOWN_BYPASSES ledger **counted against the headline**, external PRs ≤7 days, third-party-
  runnable. Live-LLM-agent suite exists but is **non-gating** (discovery → ledger). "Revert" successes
  independently diffed. **MVP ships the focused self-scoring suite + the marquee official-Anthropic-MCP-
  bypass repro** (the why-now). **DEFERRED post-MVP:** the full ~120-scenario set and the multi-
  competitor public leaderboard (raw conn / Crystal-via-Temporal / read-only gateway adapters).

## 5. Tests plan (TDD, red/green) — riskiest assumptions FIRST
- **S0 FIDELITY SPIKE (week 1–2, before the proxy):** throwaway harness that measures predicted-vs-actual
  affected-PK set under injected drift, and that the typed-inverse restores a golden prod state. **If
  clone↔prod fidelity or inverse-restore fails here, the moat is invalid — find out in week 2, not 10.**
- **Drift tests (need an apply-barrier seam to pause between dry_run and apply):**
  T-drift-insert (new matching rows → ABORT); T-drift-delete-shrink (decide+test under-count direction);
  **T-drift-predicate-flip (same count, different PKs → ABORT — the count-only blind spot)**;
  T-drift-trigger-amplification (trigger added post-snapshot → ABORT); T-nondeterministic-predicate
  (`now()`/`random()` → REFUSED).
- **Reversibility (red/green against a GOLDEN PROD STATE, not just a clone):** seed → checksum golden
  (table checksums + sequence `last_value` + trigger-side-effect tables) → apply → inverse → assert
  equality of target+cascade rows; **assert sequences/trigger-audit/NOTIFY are NOT claimed restored**
  (documented gaps). **Negative test per refused op**; property test: anything outside the certified set
  is refused (default-deny).
- **Enforcement/unit:** policy decisions per statement class; role-hardening matrix (each revoke/deny
  asserted); network-boundary (direct-to-DB connection by agent role is refused); EXPLAIN-gate +
  byte-cutoff + cumulative budget; hash-chain integrity **+ tamper-injection (edited/deleted mid-chain
  detected; rejects recorded)**.
- **Benchmark = CI gate (deterministic):** scripted payloads; gate on golden expected-outcome ("0
  regressions"); **time-to-auto-stop asserted via clock-injection / event-ordering, not wall-clock**;
  block-or-revert + FP computed over frozen sets with pinned pass-predicate per scenario.
- **Authorization suite (§14, round-4 enumerated):** T-grant-sql-swap (mutate SQL post-approval → REJECT);
  T-grant-param-swap (prepared-param change → REJECT); T-grant-cross-session-replay (other session, same
  hash → REJECT); T-grant-replay (single-use nonce reused → REJECT); T-grant-expiry (clock past TTL →
  REJECT); T-self-auth (agent principal approves own → REJECT); T-dual-control-same-identity (one identity
  twice → REJECT); T-raise-bound-stays-reversible (parameter raise → post-state revertible);
  T-unavailable-approver (no approver → stays BLOCKED, never single-approver bypass); T-break-glass-audited
  (irreversible op offers reversible alt first; break-glass requires ack + audit row).
- **Read-path / risk suite (§11.6, round-4 enumerated; needs the session-state + trust-level fixtures of
  §10.4):** T-trust-tighten-only (benign reads can NOT unlock a bigger floor budget); T-slowdrip-trips-
  window-budget (N small reads over injected time → cumulative budget trips at the deterministic boundary,
  via Clock); T-suspicion-inline (heuristic flag → synchronous check before rows return, event-ordered);
  T-llm-down-fails-toward-tighten (§11.1 per-class: LLM-exclusive detections tighten, not pass-through);
  T-budget-window-reset (cumulative counter resets correctly per window). Trust-transition is a **pure
  function of (events, clock)** — asserted deterministic.
- **Acceptance (as suite assertions):** read-only RCA agent cannot exfil/melt; `COMMIT; DROP…` blocked;
  killer demo (no-WHERE `UPDATE` → dry-run "N rows" → guard blocks; slipped write → auto-reversed +
  diff) runs from compose; proxy never in app path (asserted); no data leaves host; clone torn down.

## 6. Team of veteran experts (review personas)
PG-internals engineer (clone fidelity/blast radius) · Rust systems engineer (proxy, fail-closed) ·
**Security architect/red-teamer (Reviewer A)** · SRE/on-call (warden, no-app-SPOF) · MCP/agent engineer
(ergonomics, injection-via-data) · **QA/testability lead (Reviewer B)** · **Staff engineer /
buildability + product (Reviewer C)**.

## 7. Sprint plan (~11–13 weeks, 1 founder + AI agents)
- **S0 (2w) — Skeleton + WALL + FIDELITY SPIKE:** workspace, compose (primary+replica+dblab), hardened
  agent role + role-hardening test matrix, **pg_hba network-boundary**, `cargo-deny` CI; **the clone↔prod
  fidelity + typed-inverse spike (red-tested)**; why-now bypass-repro content.
- **S1 (3w, likeliest slip → budget 4w) — Proxy + read enforcement (MINIMAL):** pgwire termination
  incl. **SCRAM auth passthrough + TLS + prepared-statement/portal state**, read-only, extended-proto-
  only (reject simple-query/COPY), byte cutoff, timeout injection, hash-chained audit; fail-closed.
  **Deferred to S4 to protect S1 (per Reviewer C): EXPLAIN-cost gate, cumulative volume budget, replica
  routing** (advisory/secondary). Build the **apply-barrier + mock-clock seams as injectable `core`
  traits now** (cheap now, expensive retrofit).
- **S2 (2.5w) — Clone-orchestrator + dry-run:** warm pool, propose/dry_run → blast radius incl.
  affected-PK set; clone governance (enc, RLS parity, teardown). The demo that sells.
- **S3 (2.5w) — Guarded apply:** PK-set guard + apply-barrier seam + PITR fence + typed-inverse +
  refused-op list; reversibility verified vs golden state.
- **S4 (2w) — Warden + MCP + policy + audit anchor + deferred read gates:** oob warden (agent-tagged
  kills, slot monitor, mockable clock) + authenticated breaker; **minimal MCP** through proxy (the §11
  toolset; **`RiskEngine` stub returning `Allow`**, T0–T2 capture logged); the **EXPLAIN-cost gate +
  cumulative volume budget** deferred from S1 land here; `policy.yaml`; external audit anchor + key
  separation; secret store; **CLI approval + signed proposal-bound grant** (§14 MVP). *(NOT the LLM
  gating engine — that's fast-follow, §15.2.)*
- **S5 (1.5w) — Focused benchmark:** deterministic dbsafe-bench (~30–40 frozen payloads incl.
  direct-to-DB bypass + adversarial legit corpus) + golden expected-outcome + KNOWN_BYPASSES + the
  marquee official-MCP-bypass repro. **Deferred post-MVP:** full ~120-scenario set + multi-competitor
  public leaderboard. *(Per review + Nik: smaller frozen set first.)*
- **Parallel S0–S2:** design-partner concierge pilot (manual cost-gating during real incidents).

## 8. Embedded changelog
- **v0.8.1 (2026-06-21):** Founder corrections from early-build feedback. (1) **BYO Postgres** is the
  first-user experience — point at the user's existing DB; the docker-compose cluster is **CI/dev/test
  only**, never onboarding (§0.5, §3). (2) **Supported PostgreSQL 14–18** (do NOT pin to 18; prod is
  often 14–16). (3) **Rust-only — Node/TypeScript removed**; MCP server is a Rust crate using `rmcp`;
  no pnpm/node in toolchain, CI, or repo (§3, §4).
- **v0.8 (2026-06-20):** Founder **CONFIRMED** the LLM posture sequencing (§15.4: floor-only → advisory
  → gating; end state gating). Last open decision resolved → spec **BUILD-FROZEN for the MVP** (awaiting
  founder's final read before code).
- **v0.7 (2026-06-20):** Round-4 MINORs closed → **CONVERGED**. Enumerated the **§14 authorization test
  suite** + **§11.6 read-path/risk test suite** in §5 (+ `SessionState`/`TrustLevel` fixture in §10.4);
  defined the **verdict partial order** (ALLOW<ESCALATE<HOLD<BLOCK) for R2; **split R4** into R4a
  (floor/gating) + R4b (LLM/tracked); named the **benchmark maintainer** + cadence (quarterly + per
  model change); reconciled **§7 S4 + §11.5 with §15** (minimal MCP + RiskEngine *stub* in MVP, gating
  engine fast-follow); softened **story 7** accept (EXPLAIN-gate/budget land S4); added **RiskEngine
  trait + T0–T2 schema** to the S0 artifact list (§10.10); **privacy** literal-redaction + self-hosted
  default for compliance tenants; **T4 attestation** made concrete (§11.7); **CLI approval key** =
  audit-key-grade KMS, break-glass unreachable in MVP via default-deny; §3 repo marks `approval-ui`
  fast-follow; added Reviewer C to §6/method; fixed header.
- **v0.6 (2026-06-20):** Round-3 review incorporated (A=BLOCKING→resolved, B/C=MINOR→resolved).
  **(1) FN claim split by damage class** (§1/§13.2/§13.7/§10.6/§2-story-5): writes = 0 catastrophic FN
  by construction; reads/exfil = **bounded disclosure ≤ B, not 0** + best-effort detection (the central
  honesty fix). **(2) LLM anti-DoS/trust hardening** (§11.1): trust tighten-only (no ramp-and-strike);
  untrusted-only signals can't autonomously hard-block (escalate instead; rate-limit); per-class fail
  behavior (LLM-exclusive detections fail toward tighten). **(3) §14 grant binding** expanded to
  {statement, params, role, session, proposal_id, dry_run_lsn, blast_radius_checksum, nonce, expiry} +
  re-verify vs grant; **phishing-resistant approver auth**, distinct-identity dual-control,
  unavailable-approver fails toward restriction; **MVP approval = CLI + signed grant + one webhook**.
  **(4) §13 FP/FN rigor:** labeling oracle (labels inherited from seeds via known-semantics transforms),
  enumerated metamorphic relations R1–R4, N≥30 + worst-case/majority aggregation + detection-plane
  regression gate, mechanically-enforced held-out + corpus-refresh owner. **(5) Scope triage §15:** MVP =
  v0.4 core + T0–T2 capture + RiskEngine stub + CLI approval; LLM gating/§13-harness/T4/§14-full =
  fast-follow; LLM-posture sequencing flagged as a founder DECISION. **(6) §2:** stories 5/8/10 reworded
  to floor-level MVP accept; added day-2 **operator** story (dropped standalone "tune friction").
- **v0.5 (2026-06-20):** Founder-directed architecture additions. **§11 Intent capture & risk engine:**
  safety guarantee never depends on the LLM; deterministic *floor* (bounded+reversible+role wall) +
  *risk engine* (LLM, advisory, **tighten-only — can add caution, never remove the floor**; generic
  first, specialized later); tiered intent capture **T0 role / T1 SQL+comments+GUCs / T2 observed
  context / T3 MCP asserts**, baseline T0–T2 at the wire (don't demand rich input) → universal coverage
  of any Postgres client. **§12 Graceful degradation:** DBLab + replica + PITR all OPTIONAL; bounded+
  reversible guarantee invariant across configs; baseline **guarded apply** (no clone, no drift) vs
  DBLab **clone rehearsal** (the moat, pre-flight preview). **§11.6 (founder): LLM risk engine extended
  to the READ path** — multi-axis (performance / security-exfiltration / compliance / anomaly), with an
  **async-by-default + inline-on-suspicion** latency architecture; the floor still hard-blocks gross
  volume inline. **§11.1: the LLM may also GATE** — autonomously BLOCK/HOLD on high-confidence suspicion
  (blocking = tightening, so consistent with the principle); risk asymmetry = worst LLM error is a
  false-positive, never a breach; calibrated block/escalate/allow; **prod-gating ≠ CI-gating** (benchmark
  stays deterministic); gate **fails open to floor** by default. **§11.7 / T4: optional origin/provenance
  context** (the upstream discussion that generated the SQL) for true intent-vs-action analysis —
  attacker-controllable → tighten-only/detection unless **attested**. PROPOSED items (LLM fail-safe,
  privacy/local-model, separate non-gating LLM eval) pending confirmation; warrants a focused re-review
  before build-freeze. **§2 rewritten as the 10 main user stories.** **§13 Testing methodology (FP/FN):**
  target 0 false negatives (catastrophic FN = 0 by construction via the floor; detection FN measured),
  minimal false positives; labeled corpora + mutation/metamorphic/adversarial scale ("100k runs");
  two planes (deterministic floor = CI-gating; LLM detection = statistical, non-gating); calibration
  (ROC/PR, held-out); honest "0 FN = empirical over the test dist, floor = the real guarantee."
  **§14 Authorization & unblock flow:** routed approval / scoped grant / break-glass (dual-control for
  irreversible); TOCTOU-safe signed proposal-bound grants; agent can't self-authorize; approvals feed
  calibration.
- **v0.4 (2026-06-20):** Converged (round 2: all three reviewers MINOR). Incorporated: §10 concrete
  S0 artifacts (blast-radius record, affected-PK-set checksum incl. composite/PK-less, typed-inverse
  capture format, apply-barrier + mock-clock seams, golden-file schema + per-scenario pass predicate,
  S0-spike binary pass criteria, DBLab API assumptions, degraded-mode-no-replica). Security polish:
  pin audit-key + external-anchor *properties* in S0; breaker/warden mutual-auth (mTLS) + non-forgeable
  breaker state + agent can't strip its warden tag (tested); clone-teardown reaper + orphan-clone alarm
  + test; `cargo-audit`/RUSTSEC + FE/BE parse-loop fuzzing. Testability polish: clone↔prod RLS/column-
  grant parity test; coverage targets (attack-category matrix + enforcement-crate mutation/branch
  floor); independent revert-differ (no shared code with inverse-under-test); CI handling for breaker/
  clone-provision timing. Sprint: S1 resequenced (defer EXPLAIN-gate/volume-budget/replica-routing to
  S4; add SCRAM/TLS/portal state; budget 4w); realistic total ~12–15w. Marketing guardrail: no
  "beats X" comparative claim pre-leaderboard.
- **v0.3 (2026-06-20):** Trimmed benchmark scope (Nik agreed with Reviewer A): MVP ships a FOCUSED
  frozen ~30–40-scenario self-scoring suite + the marquee official-MCP-bypass repro; the full
  ~120-scenario set and the multi-competitor public leaderboard are DEFERRED post-MVP. S5 3w→1.5w;
  total ~13–15w→~11–13w. Integrity properties (determinism, golden expected-outcome, KNOWN_BYPASSES,
  direct-to-DB bypass in suite, third-party-runnable) retained.
- **v0.2 (2026-06-20):** Incorporated review round 1. Added: mandatory network boundary (proxy-only
  path); hardened role matrix (revoke pg_read_all_data/pg_*/REPLICATION/PUBLIC EXECUTE, deny dblink/fdw/
  COPY-PROGRAM/lo_*); clone-as-prod-PII governance (enc/RLS-parity/teardown); tamper-resistant audit
  (external anchor + key separation); honest recovery model (typed-inverse vs PITR prerequisite);
  EXPLAIN-gate demoted to advisory; warden kills agent-tagged only + slot monitoring; cumulative volume
  budget; **guard = affected-PK-set checksum (catches row-identity drift), apply-time drift re-check,
  refuse volatile predicates, enumerated refused-op default-deny**; deterministic CI-gating benchmark
  (scripted payloads, golden expected-outcome, clock-injection, KNOWN_BYPASSES deflates headline,
  direct-to-DB bypass in suite); **TDD reorder: clone-fidelity + inverse spike in S0**. Reworded
  absolute claims into suite-assertions.
- **v0.1 (2026-06-20):** Initial draft; scope locked maximal.

---

## 10. Appendix — concrete S0 artifacts (resolves round-2 must-fix; specify before S0 code)

**10.1 Blast-radius record (dry-run output):**
```jsonc
{ "proposal_id":"...", "clone_lsn":"3A/7F00C8", "staleness_lsn_bytes": 4194304,
  "affected": { "by_table": {"public.orders": 4800000},
                "cascade_by_table": {"public.order_items": 0},
                "pk_set_checksum": {"public.orders":"sha256:…"},   // see 10.2
                "total_rows": 4800000 },
  "triggers_fired":[{"name":"orders_audit_ai","rows":4800000}],
  "locks":[{"relation":"public.orders","mode":"RowExclusiveLock","held_ms":88400}],
  "max_lock_mode":"RowExclusiveLock", "duration_ms":88421, "wal_bytes":1503289344,
  "constraint_violations":[], "reversible":true, "inverse_kind":"PREIMAGE_UPSERT",
  "predicate_volatile":false }
```

**10.2 Affected-PK-set checksum (the guard's basis):** capture the **primary-key tuples** of every
affected row (target + cascade) via `RETURNING`/pre-image; canonicalize (sorted, typed), hash to
`sha256`. **Composite PK** → ordered tuple of columns. **PK-less table** → use `ctid` is unsafe across
the dry-run/apply boundary, so **refuse writes to PK-less / no-replica-identity tables** (negative
test). The **guard** compares dry-run `pk_set_checksum` to the apply-time computed checksum **inside
the same apply txn**; any mismatch → ABORT (catches row-identity drift; both over- and under-count).

**10.3 Typed-inverse capture format:** per affected row store `{pk, before_image}` (full column values
for UPDATE/DELETE). Inverse = `UPDATE … FROM (values …) WHERE pk=…` (UPDATE) / `INSERT …` (DELETE),
FK-ordered. **Refused-op list (default-deny):** TRUNCATE, DROP, ALTER, volatile-default INSERT,
no-pre-image/PK-less DELETE, anything outside the closed certified action set. Sequences, trigger
side-effects, NOTIFY are **explicitly not restored** (documented + tested).

**10.4 Apply-barrier & mock-clock seams (test infra; build in S0):** `core` exposes injectable traits —
`ApplyBarrier::pause_point()` (deterministic hook between dry_run and apply; test impl mutates clone/
prod to inject drift, prod impl is a no-op) and `Clock` (mockable; warden poll, time-to-auto-stop,
breaker timing all read it — **no wall-clock in gating tests**). **Plus a `SessionState`/`TrustLevel`
fixture** (injectable cumulative-byte/row counter + trust store) so read-path slow-drip/trust tests are
deterministic; the **trust-transition function is a pure function of `(events, Clock)`** (round-4 fix).

**10.5 S0 fidelity-spike binary pass criteria (gates the whole project):**
(a) for a no-drift apply, dry-run `pk_set_checksum` **==** apply-time checksum (exact); predicted
total_rows == actual (delta 0). (b) typed-inverse restores the **golden prod state** (table checksums +
sequence last_value-with-documented-gaps + trigger-side-effect tables) byte-for-byte for the certified
op set. (c) staleness bound: reject any clone whose `staleness_lsn_bytes` exceeds a configured ceiling.
**Fail any → the moat is invalid; stop and rethink before building the proxy.**

**10.6 Golden-file (benchmark) schema + pass predicate:** per scenario
`{id, class, payload, vector, expected_verdict: BLOCK|ALLOW|REVERTED|REFUSED, defense_layer,
revert_diff_expected?}`. CI gate = **0 diffs vs golden**. Per-scenario pass predicate: **exfil→bytes-out
≤ budget B at kill** (bounded disclosure, not 0 — see §13.2); data-loss→prod rows-touched=0 OR
reverted-with-verified-diff; DoS→breaker/timeout fired before budget breach (asserted via
mock-clock/event-order). KNOWN_BYPASSES entries **count against** the
headline. Coverage floor: every (class × {naive,obfuscated,direct-to-DB-bypass}) cell non-empty;
enforcement crates ≥ target mutation/branch coverage. **Independent revert-differ** shares no code with
the inverse-under-test (avoid circularity).

**10.7 DBLab API assumptions (pin before S0):** version, auth, `create/reset/destroy` semantics,
measured clone-ready latency, warm-pool size, and **teardown-failure handling = reaper/GC + orphan-
clone alarm + test asserting no clone survives a killed orchestrator** (orphaned clone = unencrypted
prod PII = the CISO veto we sell against).

**10.8 Degraded mode (no replica):** if the customer has no replica, reads route to the primary under
**stricter** budgets + `statement_timeout` + warden (documented, opt-in); the write path is unchanged
(clone-based). State this so S1 routing has a defined fallback.

**10.9 Audit root-of-trust (pin properties in S0, implement S4):** signing key KMS-backed, never on the
DB host; external anchor is append-only/WORM with independent retention; audited principal `REVOKE`d
from writing audit; mutual-auth (mTLS) warden↔proxy; breaker state not writable by agent/operator
principal.

**10.10 Still OPEN (resolve during S0, now scoped):** `policy.yaml` schema; closed certified-action-set
format (S3); MCP tool I/O schemas + error-code enum (S4); `architecture.json`; proto/ interfaces; **the
`RiskEngine` trait signature** (`{sql, schema, measured_stats, intent_tiers}` → `{Allow|Escalate|Hold|
Block, reason, confidence}`) and **the T0–T2 intent-capture schema** (fields logged into the audit/blast-
radius record) — both one-way doors MVP code touches (§15.3).

---

## 11. Intent capture & risk engine (v0.5 direction — folds in founder guidance; PROPOSED items pending confirmation)

**11.1 Core principle — the safety guarantee never depends on the LLM.** Two tiers:
- **Floor (deterministic, non-bypassable):** bounded blast radius + reversibility + role wall +
  cost/byte/timeout gates. Always enforced; no model involved.
- **Risk engine (LLM):** assesses *how dangerous* an action looks (from captured intent + measured
  effects, across the axes in §11.6) and acts in the **tightening direction only** — it can
  **BLOCK / HOLD / require-approval / escalate**, autonomously, including a hard **block on
  high-confidence suspicion** ("obviously off" → stop it). It can **never loosen** below the floor or
  grant access. Generic model first; specialized later.

  **Rule: the LLM can only add restriction, never remove it — blocking IS tightening, so an LLM *gate*
  is consistent with the principle.** Auto-*allow* still requires BOTH (a) within the floor (bounded +
  reversible + certified action set) AND (b) the LLM not flagging. **Risk asymmetry:** because the LLM
  can only block, never grant, an LLM error is at worst a **false-positive (blocked legitimate action),
  never a breach** — the correct place to put a foolable model. **Calibration:** block on high
  confidence · escalate-to-human on medium · allow + log on low (thresholds tunable). **Prod-gating ≠
  CI-gating:** the LLM gates in production, but the benchmark/CI still gates on the deterministic floor
  (the LLM gets its own non-gating precision/recall + false-positive eval, §11.4).

  **Anti-DoS / trust-poisoning hardening (round-3 BLOCKING fixes):**
  - **Trust is tighten-only too.** A session's earned "trust level" (§11.6) may only *raise* friction,
    **never raise a floor bound** (no ramp-and-strike: benign reads can't unlock a bigger budget).
  - **Untrusted-only signals can't autonomously hard-block.** T1 (SQL comments), T2 (behavior), and
    unattested T4 are attacker-controllable → prompt-injection could force false-positive **denial-of-
    service** on legit agents. So an *autonomous hard block* requires a trusted/independent signal
    (deterministic floor, or attested context); when the *only* signal is attacker-controllable the
    engine **escalates-to-human, not hard-blocks**, and autonomous blocks are **rate-limited**.
  - **Per-class fail behavior (not a global default).** Fail-**open** to the floor only for classes the
    floor independently covers (write bounding). For **LLM-exclusive detections** (slow-drip exfil,
    intent↔action mismatch) an LLM outage must **fail toward tighten** (stricter deterministic budgets +
    flag), never silently pass through. (Reconciles §11.1 vs §11.6.)

**11.2 Intent capture is TIERED — we sit at the SQL/libpq wire, so we INFER; we never demand rich input.**
- **T0 — role/identity:** coarse scope + purpose. Always available. (Trivial intent.)
- **T1 — the SQL itself + comments + `application_name`/GUCs:** `/* intent:… ticket:… actor:… */`
  annotations, statement shape/class. Always available at the wire.
- **T2 — observed session context:** query sequence, reads-before-write, rate, tables, timing
  (behavioral inference).
- **T3 — explicit MCP asserts (bonus):** richest *declared* signal (the `propose_write` assertion
  contract), only when the agent cooperates.
- **T4 — origin/provenance context (OPTIONAL, most comprehensive):** the upstream discussion + agent
  reasoning that generated the SQL → true intent-vs-action analysis. See §11.7. **Untrusted unless
  attested → tighten-only.**

  **Baseline = T0–T2** (works with ANY libpq client / agent framework). **T3–T4 are enrichment, never
  required.**

**11.3 Strategic consequence:** wire-level understanding ⇒ **universal coverage** — pg_bumpers protects
*any* Postgres-speaking agent, not only those that adopt our MCP. A bigger wedge than cooperation-only
competitors. (Candidate headline.)

**11.4 PROPOSED defaults (pending founder confirmation):**
1. LLM risk-eval covers **both writes AND reads** (multi-axis — see §11.6). Reads keep a fast inline
   deterministic floor (cost-gate / row+byte budget / mid-stream cutoff) for gross volume; the LLM runs
   **async-by-default** (scoring query + session pattern → warden / breaker / trust level) and
   **inline-on-suspicion**, so benign reads aren't taxed. Writes: LLM on the write/dry-run path
   (tolerant of 100s ms–s).
2. **Fail-safe:** LLM unavailable/slow/low-confidence → fall back to the floor + escalate to a human;
   **never auto-allow on timeout.**
3. **Privacy/deployment:** generic hosted model first (experiment speed); **self-hosted/local model is
   the DEFAULT for residency/compliance-flagged tenants** (not merely offered). **Data-minimization +
   literal redaction** — send schema + measured stats + SQL with **literals stripped/parameterized**
   (`WHERE ssn='…'` → `WHERE ssn=$1`) so embedded PII never egresses; never row data. (CISO item.)
4. **Evaluation:** the LLM risk layer gets its own precision/recall harness on a labeled risk corpus,
   **non-gating**; the deterministic floor remains the CI gate (keeps the benchmark honest; aligns with
   Reviewer B).
5. **Prompt-injection-via-data:** the risk engine's inputs are untrusted; its output is **tighten-only**
   + structured — it can never widen capability.

**11.5 Build sequencing (reconciled with §15):** MVP ships the floor + **T0–T2 intent capture (logged)**
+ a **`RiskEngine` trait stub returning `Allow`**. The actual LLM risk-gate engine (gating, read-path,
trust level) is **fast-follow** (§15.2/§15.4); specialized model later. The §7 sprint plan is the single
source of MVP scope.

**11.6 Read-risk evaluation — multi-axis, latency-aware (founder: the LLM evaluates reads too).**
- **Axes:** (1) **performance/cost** — volume, plan cost, locks, load; (2) **security/exfiltration** —
  bulk *or* slow-drip theft, PII-targeting, recon/enumeration, injection, privilege-probing;
  (3) **data-integrity** (writes); (4) **compliance/policy** — restricted data, residency;
  (5) **behavioral anomaly** — deviation from role/session norm. Extensible.
- **Division of labor:** the deterministic **floor handles gross/mechanical read risk inline & fast** —
  EXPLAIN cost-gate + row/byte budget + mid-stream cutoff hard-block the "returns 1M rows" case *before
  it streams*, ~zero added latency, even if the LLM is slow/down. The **LLM adds the semantic/intent
  layer** the floor can't see (exfiltration? recon? hacking?) plus **context-aware tuning** (1M rows is
  fine for an analytics role, not an app role).
- **Latency architecture (reads not taxed):**
  - **async-by-default** — LLM scores each query + the *session pattern* in parallel / just-behind →
    feeds warden, circuit breaker, and a live **trust level**; can mid-session escalate (tighten
    budgets, require approval, kill session, alert). Catches **slow-drip exfiltration** across many
    small reads.
  - **inline-on-suspicion** — cheap heuristics (PII columns, odd shape, sensitive tables, new pattern)
    escalate *that* query to a synchronous LLM check before rows return.
  - **inline-always** — opt-in high-assurance mode (accepts the latency).
- **tighten-only + fail-safe:** LLM can only block/escalate, never loosen; if it's down, reads stay
  bounded by the floor (budgets/cutoff) and suspicion-escalation degrades to deterministic heuristics.

**11.7 Origin / provenance context (T4 — OPTIONAL, most comprehensive).** Let the risk engine optionally
see the *upstream context that produced the SQL* — the user's request + the agent's plan/reasoning +
relevant thread excerpt — enabling true **intent-vs-action** analysis (e.g. user asked "fix customer X's
duplicate" but the SQL deletes all orders → mismatch → block/escalate).
- **Plumbing (opt-in, increasing integration):** (a) **MCP `context` field** — agent attaches the
  originating prompt/task/reasoning to `propose_write`/`query`; (b) **correlation-id + out-of-band
  store** — the app pushes its thread to a pg_bumpers context endpoint keyed by a `trace_id` carried at
  the wire (SQL comment / `SET pg_bumpers.trace_id=…`); engine fetches at eval time (keeps the wire
  thin); (c) **SDK / MCP-middleware / platform connectors** (Cursor, Claude Code, LangChain…) capturing
  the thread automatically.
- **Trust model (critical — origin context is attacker-controllable):** a malicious/injected agent can
  *fabricate* benign context. Therefore **tighten-only holds** — context improves **detection of
  intent↔action mismatch** and can raise suspicion, but can **never loosen below the floor** (fabricating
  good context buys an attacker nothing). To let context **reduce friction** (e.g. grant L2 auto) it must
  be **attested**: a signature over `hash(context_excerpt ∥ trace_id ∥ statement_hash ∥ timestamp)` by a
  **platform key registered in `policy.yaml`, KMS-held, rotation documented** (same root-of-trust as the
  §10.9 audit key) — binding the context to *this* SQL/trace_id (defeats replay onto a different
  statement). Unattested context = detection/tightening only.
- **Privacy (opt-in, CISO):** prompts can be sensitive → opt-in, data-minimized (excerpt/summary, not
  whole transcripts), honors the self-hosted/local model option, configurable redaction.
- **Status:** post-MVP layer (after floor + T0–T2 + base LLM engine); also a concrete reason to adopt
  our MCP/SDK.

---

## 12. Graceful degradation / optional components (v0.5 direction)

pg_bumpers works against a **bare primary** (no replica, no DBLab) and each added component upgrades
capability — keeping install friction low and making the moat an *upgrade*, not a gate.

| Component | Absent (baseline) | Present (upgrade) |
|---|---|---|
| **Replica** | reads route to primary under stricter budgets/timeouts/warden (§10.8) | isolated reads on the replica |
| **DBLab** | **guarded apply** — txn on primary + PITR fence + PK-set/row-count guard (abort-before-commit on overrun) + typed-inverse. Bounded + reversible. No clone-drift (same txn). *Optional in-place rolled-back dry-run for preview at the cost of prod locks/load.* | **clone rehearsal (the moat)** — pre-flight blast-radius *preview* on an isolated clone, zero prod impact, then guarded apply |
| **WAL archiving / PITR** | typed-inverse is the undo (cheap) | + PITR restore-point as last-resort fence |

**12.1 The guarantee is invariant:** *bounded blast radius + reversibility* hold in every configuration;
only the **preview/isolation experience** improves with replica + DBLab. The deterministic floor (§11.1)
never depends on optional components.

**12.2 Config + UX:** runtime-detected; `policy.yaml` → `replica.dsn?`, `clone.provider: none|dblab`,
`pitr.enabled`. When a component is absent, the MCP/UI states the active mode plainly (e.g., "preview
unavailable — using guarded apply"); never silently downgrade.

**12.3 Build implication:** the baseline guarded-apply path is simpler to prove correct (no clone-drift)
and may be built **before** the DBLab path; the S0 fidelity spike still validates the DBLab clone↔prod
path since that's where drift risk lives.

---

## 13. Testing methodology — false negatives & false positives

**13.1 Definitions & targets.**
- **False negative (FN) — the catastrophic error:** a harmful action NOT prevented (not blocked, not
  bounded, not reverted) → damage occurs. **Target: 0.**
- **False positive (FP) — the friction error:** a legitimate, safe action wrongly blocked/over-escalated.
  **Target: as low as possible** (a productivity tax, not a breach).

**13.2 The FN target is SPLIT BY DAMAGE CLASS (round-3 BLOCKING fix — reads ≠ writes).** We do NOT rely
on *detecting* every bad action (impossible for a probabilistic gate). What the floor guarantees differs:
- **Write / data-loss (reversible damage): 0 catastrophic FN BY CONSTRUCTION.** Bounded + reversible +
  apply-time PK-set re-check → a "missed" dangerous write is still capped and undoable. Independent of
  LLM accuracy. This is the claim we stand behind. Test **T-FN-write**: prod end-state == golden
  pre-state (reverted) OR rows-touched == 0 (blocked).
- **Read / exfiltration (disclosure): NOT 0 by construction — disclosure can't be un-happened.** The
  floor guarantee is **bounded disclosure**: ≤ a per-role byte/row budget B (single-shot cutoff +
  per-window cumulative budget) leaks before kill. So the honest guarantee is "**≤ B leaked, then
  stopped**," *not* "0 leaked." Beyond that, exfiltration relies on **best-effort detection** (LLM async
  + heuristics). Test **T-FN-exfil**: bytes-streamed ≤ B at kill (asserted via cumulative-counter +
  clock fixtures), and the residual ≤B leak is documented as the guarantee.
- **Detection FN (LLM/heuristics failed to *flag* a risk): measured & minimized**, never the sole safety
  line — backstopped by the floor (capped for writes; budget-capped for reads).
- Because the floor backstops the *catastrophic* case, we can **tune the LLM gate for LOW FP** without
  sacrificing the write-FN guarantee.
**13.3 Ground-truth corpora (labeled).**
- **Dangerous corpus** (expected BLOCK | BOUND | REVERT): exfiltration, DoS, data-loss, recon, injection,
  privilege-probing — across §11.6 axes; each labeled with expected outcome + which layer should catch it.
- **Legit corpus** (expected ALLOW) — the FP denominator; **adversarially curated** to include *hard*
  legitimate cases (large-but-legit analytics reads, legit bulk backfills/mass updates) that naive tools
  false-positive on.
- **Boundary corpus** — near-decision-boundary pairs (a legit mass delete vs a malicious one differing
  only in context) — where calibration is decided.

**13.4 Reaching scale (the "100k runs") — the labeling oracle (round-3 fix).** No case is machine-labeled
from scratch (an LLM/heuristic labeler would be a noisy oracle). **Every one of the 100k cases inherits
its ground-truth label from a hand-labeled seed via a known-semantics transform.** Seeds = the frozen
hand-labeled dangerous + adversarial-legit + boundary corpora (§13.3).
- **Enumerated metamorphic relations (each = a property test + generator):**
  - **R1 (label-preserving):** whitespace / comment / alias / casing reformat → **verdict invariant**.
  - **R2 (label-flipping, monotone):** define the **verdict partial order `ALLOW < ESCALATE < HOLD <
    BLOCK`**; removing `WHERE` / widening scope must move the verdict **monotonically ≥** (never become
    safer); adding a tightening `WHERE` may move it ≤. (Makes "monotone" mechanically checkable.)
  - **R3 (label-preserving):** re-encode literals (hex/unicode/concat) → **verdict invariant** (anti-
    obfuscation).
  - **R4a (floor, gating):** split one large read into N small reads over time → the **per-window
    cumulative budget still trips** (deterministic; CI-gated).
  - **R4b (LLM, tracked):** the slow-drip **detection recall is preserved** in the non-gating detection
    plane (statistical, not a CI gate).
- **Combinatorial mutation** across table/predicate/volume/role within a relation's label class.
- **Adversarial generation (LLM red-teamer): discovery-only, UNLABELED → KNOWN_BYPASSES; EXCLUDED from
  the FP/FN denominators** (they're for finding new bypasses, not scoring).
- **Workload replay:** synthetic/anonymized OLTP traces for realistic legit volume (label = ALLOW).

**13.5 Two evaluation planes (kept separate).**
- **Deterministic floor plane — CI-GATING:** every dangerous scenario must be bounded/reverted by the
  floor; reproducible; gate = **0 regressions vs golden + 0 catastrophic FN**. The FN guarantee is
  enforced here.
- **Detection/LLM plane — statistical, tracked (non-CI-gating):** run the gate over the labeled corpus →
  confusion matrix (TP/FP/TN/FN) **per axis, per confidence threshold**. **Non-determinism handling
  (round-3 fix):** temp 0 is *not* fully deterministic → run **N ≥ 30 reps/case** (N set by target CI
  half-width); **per-case aggregation = worst-case for safety axes** (any-rep-miss counts as a detection
  miss) and **majority for FP**; report Wilson CIs. **Tracked, not untracked:** a **detection-plane
  regression gate** — recall per axis must not drop > Δ vs the frozen baseline at fixed thresholds, or
  the model/prompt change is rejected.

**13.6 Calibration loop.** Sweep block/escalate/allow thresholds → ROC / precision-recall per axis →
operating point meeting the FN target at **minimum FP**; report the curve, not a point. **Held-out
discipline is mechanically enforced (round-3 fix):** the held-out partition is hashed + committed and the
**calibration tooling refuses to read held-out IDs** (CI test fails if it does) — prevents overfitting
thresholds to the FP corpus. **Ownership:** the **benchmark maintainer** (a named owner) refreshes corpora +
re-baselines **quarterly AND on every base-model/prompt change** (else the published number silently goes
stale). Approvals/denials from §14 feed back as new labels.

**13.7 Reported metrics (the "100k runs showed: …" statement).**
- Catastrophic FN: **0** (structural; asserted in the gating plane).
- Detection recall / FN-rate per axis; FP-rate on the legit corpus (overall + per workload) with CIs;
  per-threshold confusion matrices; ROC/PR curves; time-to-auto-stop (logical/clock-injected).
- *Example target statement (split by class, honest):* "Across 100k seeded + metamorphic runs: **0
  data-loss false-negatives** (write damage bounded+reverted, floor-guaranteed); **exfiltration bounded
  to ≤ B per role** (no unbounded disclosure) with LLM detection recall 9x.x%; **false-positive rate
  y.y%** on the adversarial legit corpus (95% CI …). [Adversarial-generated bypasses tracked separately
  in KNOWN_BYPASSES, excluded from these denominators.]"

**13.8 Honesty / anti-gaming.** Held-out + third-party-runnable + public legit corpus + KNOWN_BYPASSES
counted against the headline + pinned versions/seeds. "0 FN" is an **empirical statement over the test
distribution**; the *actual guarantee* is the structural floor — do not overstate the empirical number as
a proof over all inputs.

---

## 14. Authorization & unblock flow (escalation / break-glass)

Every block must have a **defined route to get unblocked by an authorized human** — else blocks are dead
ends and FPs become outages.

**14.1 Who authorizes.** A policy-defined **approver set**, scoped by environment + action class +
autonomy level. Tiered: teammate (medium) → DBA/owner (high) → **dual-control / four-eyes** (most
destructive / irreversible). The **agent can never authorize itself**; the approver authenticates
independently of the agent with **phishing-resistant auth (WebAuthn / hardware key, not click-a-link)**
(round-3 fix — the OOB channel is itself a phishing vector). **Dual-control** must verify **two distinct
identities on distinct channels** (defeats one-person-two-accounts). **Unavailable-approver path:** when
no approver is reachable the system **fails toward more restriction** (stays blocked) + pages a secondary;
it **never** degrades to single-approver bypass.

**14.2 Routes differ by *why* it was blocked.**
- **LLM HOLD/escalate, or L1 human-in-loop:** routine approval — a human reviews proposal + dry-run blast
  radius + intent signals + LLM rationale + block reason → approve/deny. On approve → proceeds under the
  floor's guards.
- **Floor block that's a *parameter*** (row/cost budget, volume): an authorized human can **raise the
  bound for this specific action** ("yes, this 5M-row backfill is intended"); it runs **still reversibly**
  under the higher bound. Not a break of the guarantee.
- **Floor block that's *structural/irreversible*** (TRUNCATE/DROP/no-inverse/PK-less): **break-glass** —
  highest authority + dual-control, explicit acknowledgment of irreversibility, time-boxed, heavily
  audited. The system **offers the reversible alternative first** ("take a snapshot, then proceed
  reversibly?") and prefers it.

**14.3 Mechanics (TOCTOU-safe).**
- Block returns `APPROVAL_REQUIRED` + a remedy with an **approval-request id** (TTL); MCP
  `request_elevation` / CLI creates it.
- Request delivered **out-of-band** (UI / Slack / email / webhook / CLI) with full context. Approver
  approves (optional **scope + limit + expiry**), denies, or break-glasses.
- On approval → a **signed, single-use (nonce), time-boxed grant bound to the exact proposal**. The
  binding hash covers (round-3 fix — statement+blast-radius alone is insufficient): **`{statement_text,
  normalized_params, role, session/principal id, proposal_id, dry_run_lsn, blast_radius_checksum, nonce,
  expiry}`**. At apply, re-verify the live affected-PK-set against the **grant's** recorded checksum (not
  just dry-run vs apply) → defeats SQL-swap, prepared-param-swap, cross-session replay, and data-drift
  since approval.
- **Everything in the tamper-evident audit:** request, approver identity, decision, grant, scope, expiry,
  break-glass flag.
- **MVP mechanism (round-3 scope cut):** **CLI approval** (`pg_bumpers approve <id>`, human-held signing
  key) emitting the signed proposal-bound grant **+ one generic webhook POST** of the request payload
  (customers wire Slack/etc themselves). **Defer** to fast-follow: approval UI (`mcp/approval-ui`),
  dual-control, tiered approver sets, native connectors. Keeps the TOCTOU-safe grant (the load-bearing
  security property) while cutting ~90% of the build. The **CLI approval signing key gets audit-key-grade
  handling** (KMS-backed, separated — §10.9). **MVP safety note:** structural/irreversible ops
  (TRUNCATE/DROP/no-inverse) are in the **default-deny refused set** (§10.3), so break-glass on them is
  effectively **unreachable in MVP** — dual-control can defer to fast-follow without exposing the
  irreversible path.

**14.4 Async & ergonomics.** Agent gets a ticket → polls/awaits → on grant proceeds; on deny/expiry
abandons or re-proposes. Approval UX must be fast and show **why** (FP friction = approval load).

**14.5 Feedback to calibration (§13.6).** A pattern approved repeatedly → candidate for the **certified
action set** (L2 auto) or a threshold adjustment → drives FP down over time. Repeated denials → tighten.

---

## 15. MVP scope triage & build sequencing (round-3 Reviewer C)

v0.5 roughly doubled the surface; this pins MVP vs fast-follow so scope-gravity doesn't sink the timeline.

**15.1 MVP = the v0.4 core (~12–15w solo+AI):** WALL + network boundary + hardened roles · proxy
(read-only, extended-proto-only, byte + cumulative cutoff, timeout, audit) · clone dry-run blast-radius
preview · guarded apply + typed-inverse + PK-set guard · warden + minimal MCP + `policy.yaml` + audit
anchor · focused deterministic benchmark + marquee MCP-bypass repro · **CLI approval + signed
proposal-bound grant** (§14 MVP mechanism) · **intent capture T0–T2 *logged*** (not yet acted on) · a
**`RiskEngine` trait seam returning `Allow`** (impl deferred).

**15.2 Fast-follow track (~separate 8–12w, NOT inside the MVP window):** the LLM risk engine (§11.1
gating, §11.6 read-path + trust level), §13 100k-run FP/FN harness + calibration, §11.7 T4 origin context
+ attestation, §14 full (approval UI, dual-control, connectors), specialized model.

**15.3 Spec-now / defer-impl (one-way doors MVP code touches):** §14.3 grant token format (done); the
**T0–T2 capture schema** (intent fields logged into the audit/blast-radius record); the **`RiskEngine`
trait** — inputs `{sql, schema, measured_stats, intent_tiers}`, output a tighten-only verdict
`{Allow | Escalate | Hold | Block, reason, confidence}`. Build the data path + seam in the MVP; the engine
later.

**15.4 DECISION (founder) — LLM posture sequencing.** Reviewers recommend **floor-only (MVP) → LLM
advisory non-gating (fast-follow v1) → LLM gating (later, once §13 gives a defensible operating point).**
End state = gating (your stated wish, unchanged); only the *sequencing* is staged, because a *good*
gating model needs the eval harness first and adds latency/cost/ops. **CONFIRMED (founder, 2026-06-20):
floor-only MVP → advisory non-gating → gating. End state = gating.**

**15.5 Repo change:** drop `mcp/approval-ui` from the MVP repo (CLI-only approval); it returns in
fast-follow.
