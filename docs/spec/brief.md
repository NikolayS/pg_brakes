# pg_bumpers — brief

![license](https://img.shields.io/badge/license-Apache--2.0-3ddc97)
![spec](https://img.shields.io/badge/SPEC-v0.8%20·%20build--frozen-5b8cff)
![review](https://img.shields.io/badge/4%20review%20rounds-converged-3ddc97)
![status](https://img.shields.io/badge/status-MVP%20build--ready%20·%20awaiting%20founder%20review-ffb454)

> **Working title** (brand TBD; nine-lives / *Felis* leads).
> *(Styled version: `brief.html` — open locally.)*

**Let AI agents read & write _production Postgres_ — safely.** Run them with `--dangerously-skip-permissions` and they can't cause disaster. **Your database has nine lives.**

---

## The problem · why now
AI agents now touch production databases — coding agents, text-to-SQL, internal copilots — often in YOLO / `--dangerously-skip-permissions` modes. Nobody has a safe way to let them.

> The Replit agent **deleted SaaStr's production database**. The official Anthropic Postgres MCP read-only mode was bypassed by statement-stacking (`COMMIT; DROP SCHEMA…`). Datadog's lesson: **app-layer protection isn't enough — you need native Postgres RBAC.**

Everyone else decides *whether* an action runs (allow/deny, masking, JIT). **Nobody predicts _what a write will do_.**

## What it is
A self-hostable control plane between an AI agent and production Postgres. Reads are cost-gated, bounded & audited. Writes are **rehearsed on an instant clone of prod**, blast radius **measured**, then applied reversibly under guards.

**The honest guarantee, split by damage class:**
- **Writes (reversible):** data-loss is **prevented or undoable** — every applied write is bounded + reversible. *0 catastrophic false-negatives by construction.*
- **Reads (disclosure):** disclosure can't be un-happened, so we promise **bounded disclosure** (≤ a per-role budget, then cutoff/kill) **+ best-effort detection** of exfiltration — never "impossible."

## How it decides: a deterministic floor + an LLM risk-gate
- **Floor (deterministic, non-bypassable):** native-role wall + cost/byte budgets + timeouts + bounded-&-reversible writes. This *is* the guarantee — no model involved.
- **LLM risk-gate (tighten-only):** scores how dangerous an action looks (performance, exfiltration, recon, anomaly…) and can **block / hold / escalate** — autonomously on high-confidence suspicion — but can **never loosen** below the floor.
- **Why that's safe:** because the LLM can only *block, never grant*, its worst mistake is a false-positive (blocked legit action), **never a breach**. That's the right place to put a (foolable) model.

## Architecture · four layers + a boundary
| # | Layer | What it does |
|---|---|---|
| **0** | **Network boundary** *(mandatory)* | Agent reaches Postgres **only via the proxy** — no bypass, no audit holes. |
| **1** | **The Wall — native Postgres roles** *(unbypassable)* | Hardened least-priv role; a hostile raw client *physically* can't write or read denied data. |
| **2** | **Enforcement — Apache Rust proxy + warden** *(our IP)* | Read-only, budgets, cutoff, timeouts, audit; warden kills runaways + owns the breaker. |
| **3** | **Intent / UX — MCP server** *(agent-facing)* | What the agent talks to; executes *through* the proxy; recoverable blocks. |
| **4** | **Write-safety — guarded apply (+ optional clone rehearsal)** *(the moat)* | Bounded + reversible writes; with DBLab, a zero-impact pre-flight preview. |

## Intent: inferred at the wire (works with *any* Postgres agent)
We don't demand rich input — we infer intent in tiers: **T0** role · **T1** SQL + comments + `application_name` · **T2** observed session behavior · **T3** explicit MCP asserts (bonus) · **T4** origin/provenance context (optional, richest). **Baseline T0–T2 works with any libpq client** → universal coverage, not just agents that adopt our MCP.

## How a write works
1. **propose** — SQL + expected rows. Nothing touches prod.
2. **dry-run** — rehearse (on a clone if DBLab present; else measure in-txn); report rows, cascades, locks, the affected-PK set, reversibility.
3. **apply** — restore-point fence → PK-set/row-count guard (abort on drift) → commit → typed-inverse captured. `confirm_rows` forces the agent to own the blast radius.

> **Killer demo:** `UPDATE accounts SET balance=0` (no `WHERE`) → "4,823,901 rows" → blocked before prod. Slipped write → **auto-reversed**, with a verifiable diff.

## Autonomy & unblocking
- **Levels:** L0 observe · L1 human-in-loop · L2 narrow auto (certified set) · ~~L3 full auto~~ (earned later).
- **Unblock route:** every block has a path out — an **authorized human** approves (with scope/expiry), denies, or **break-glass** (dual-control for irreversible). Grants are **signed, single-use, bound to the exact proposal** (the agent can't swap the SQL after approval); the agent can never authorize itself. Fully audited.

## Graceful degradation
Works against a **bare primary** (no replica, no DBLab); a replica unlocks isolated reads, DBLab unlocks pre-flight preview. **The bounded+reversible guarantee is invariant** — the moat is an *upgrade*, not a gate.

## Scope
| ✅ MVP (~12–15 wks) | ◻︎ Fast-follow |
|---|---|
| Native-role wall + proxy-only network path | LLM **gating** risk-engine (write+read) |
| Proxy: read-only, budgets, cutoff, timeouts, audit | The 100k-run FP/FN benchmark + calibration |
| Clone dry-run preview + guarded apply + typed-inverse | T4 origin-context + attestation |
| Warden + MCP + `policy.yaml` + tamper-evident audit | Approval UI, dual-control, connectors |
| Autonomy L0–L2 · **intent capture T0–T2 (logged)** | DDL, multi-stmt txns, multi-DB, cloud |
| **CLI approval** + signed proposal-bound grant | Specialized (fine-tuned) risk model |
| Focused deterministic benchmark + bypass repro | |

> LLM posture is **staged** (founder decision): floor-only → advisory → gating. End state = gating; only the sequencing is phased, because a *good* gating model needs the eval harness first.

## Testing: 0 false negatives, minimal false positives
- **Writes:** 0 catastrophic FN **by construction** (the floor bounds + reverts). Reads: **bounded disclosure ≤ budget**, not zero.
- **At scale ("100k runs"):** labeled seed corpora → known-semantics **metamorphic** transforms (every case keeps a ground-truth label) + mutation; two planes — the **deterministic floor gates CI**, the **LLM detection plane** is tracked statistically (confusion matrix, ROC, Wilson CIs).
- **Calibration** tunes thresholds to the FN target at minimum FP; held-out set prevents overfitting.
- *Target statement:* "0 data-loss false-negatives; exfiltration bounded ≤ B; false-positive rate y.y% (95% CI …)."

## What we deliberately do **not** claim
- Not "physically impossible to break" — claims are assertions over the frozen suite + a public KNOWN_BYPASSES ledger.
- Reads can't be un-disclosed — exfiltration is **bounded + detected**, not prevented.
- Full-auto write is **narrow** (a certified, reversible action set), not open-ended.
- The LLM **reduces friction & catches more**, but is never the safety guarantee — the floor is.

## What success looks like (90-day experiment)
- **Resonance:** benchmark cited · ≥1 HN front page · ~1k stars · **≥500 owned-audience signups** (today: zero).
- **Pull to the moat:** a concierge-pilot customer asks **"can it fix the data too?"** → 3–5 design partners → **≥1 non-GitLab logo at human-in-loop _write_ autonomy** (the investor trigger).

---

**Status:** SPEC v0.8 — **BUILD-FROZEN for the MVP** (converged across 4 review rounds; LLM-posture decision confirmed). Awaiting your final read; no code until the go.
Full spec: [`SPEC.md`](./SPEC.md) · decisions: [`decisions.md`](./decisions.md) · styled: [`brief.html`](./brief.html)
