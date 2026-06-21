# pg_bumpers — SPEC amendments

Intentional, recorded deviations from `docs/spec/SPEC.md` (v0.8, build-frozen), per
`CLAUDE.md` §8 ("Intentional deviations: record in `docs/spec/SPEC.amendments.md` with
rationale") and the process spec (#1, sprint-review step). The SPEC is **not** edited in
feature PRs; deviations are logged here instead.

---

## S0 integration substrate — docker-compose retained as shipped artifact; live tests run on local Postgres 18

**SPEC sections touched:** §7 (S0: "compose — primary + replica + dblab") and §12
(graceful degradation: replica/DBLab/PITR all OPTIONAL; the bounded + reversible
guarantee is invariant). Also relevant: §4 (`_meta` audit DB), §10.8 (degraded mode, no
replica).

**Issue:** #4 (S0 dev/test stack).

### Deviation

The SPEC's S0 plan (§7) calls for a `docker-compose` stack as the substrate that every
integration test and the fidelity gate (#8) run against. We **keep
`deploy/docker-compose.yml` as the shipped artifact** for real users — and **bump its
image from the SPEC's example `postgres:16` to `postgres:18`** — but the **live**
integration tests in this build environment run against **local Postgres 18** clusters
(`postgresql@18` via Homebrew: `initdb` / `pg_basebackup` / `pg_ctl`), driven by
`deploy/local-stack.sh` + `deploy/smoke.sh`, **not** against docker containers.

### Rationale

Docker image pulls are **non-functional** in the pg_bumpers build environment. The
Docker Desktop VM (4.23.0) **and** a freshly-installed Colima VM (engine 27.4.0) both
hang `docker pull` at **zero blob bytes**, even though `curl https://registry-1.docker.io/v2/`
succeeds (HTTP 401) from inside the same VM. Ruled out: HTTP proxy (none), Tailscale
(not an exit node; Docker Hub routes via `en0`, and bringing Tailscale fully down did
not help), MTU (lowering the VM `eth0` to 1280 did not help), and dockerd
proxy/mirror config (clean). It is a **host-level Docker daemon networking fault**, not
fixable from the build session.

Founder-approved decision: rather than block S0, keep the compose as the user-facing
artifact and run S0's live tests on local Postgres 18. This keeps **every test real** —
real streaming replication (`pg_basebackup -R` → `standby.signal` + `primary_conninfo`,
verified via `pg_stat_replication` and a replicated row round-trip), real apply/inverse
— and unblocks S0 immediately. The fidelity GATE (#8) likewise runs for real against
local PG 18.

The deviation is **scoped to the test/dev substrate only**. It does not touch the
deterministic floor (§11.1), the bounded + reversible guarantee (§12.1), or any
product behavior. The graceful-degradation baseline (§12) is still proven: the default
path runs a **bare primary** (no replica), with the replica added only when requested —
exactly as `docker compose` (no profiles) vs. `--profile replica` would behave.

### What was built (issue #4, re-scoped)

- **`deploy/docker-compose.yml`** — shipped artifact. `postgres:18`; `primary` + `meta`
  always on; `replica` under profile `replica` (off by default → bare-primary baseline);
  `dblab` placeholder under profile `dblab`; healthchecks; `depends_on` ordering;
  `wal_level=replica` + replication-ready knobs. Statically validated with
  `docker compose -f deploy/docker-compose.yml config -q`.
- **`deploy/local-stack.sh`** (`up` / `down` / `status`) — isolated throwaway PG 18
  clusters under a git-ignored `./.localstack/` on **dedicated high ports**
  (primary 54321, replica 54322, meta 54323) so they never touch any cluster already on
  5432. Primary configured for streaming replication; replica built via `pg_basebackup
  -R`; `meta` a separate cluster hosting the append-only `_meta` audit DB. A
  clearly-marked include point reserves where the issue-#5 hardened-role WALL SQL
  attaches (no duplication of that work here).
- **`deploy/smoke.sh`** — env-gated on `PG_BUMPERS_IT=1`: asserts primary + meta
  reachable, replica in recovery and streaming (`pg_stat_replication`), and a replicated
  row round-trip within a bound. Non-zero exit on any failure; skips (exit 0) when the
  gate is unset.

### How to re-validate the compose live (on a docker-healthy machine)

On any machine with a working Docker daemon (can `docker pull postgres:18`):

```sh
# 1. Static parse (no pulls) — already enforced here:
docker compose -f deploy/docker-compose.yml config -q && echo COMPOSE_OK

# 2. Baseline — primary + meta healthy, replica absent (bare-primary baseline):
docker compose -f deploy/docker-compose.yml up -d
docker compose -f deploy/docker-compose.yml ps          # primary + meta healthy

# 3. Streaming replica — write on primary visible on replica; standby in pg_stat_replication:
docker compose -f deploy/docker-compose.yml --profile replica up -d
docker compose -f deploy/docker-compose.yml exec primary \
  psql -U postgres -c "SELECT application_name, state FROM pg_stat_replication;"

# 4. Tear down:
docker compose -f deploy/docker-compose.yml --profile replica --profile dblab down -v
```

When the compose is confirmed live, this amendment can be narrowed to "image bumped to
`postgres:18`; both substrates supported" — the local-PG substrate remains useful as the
fast, Docker-free dev/CI path.

---

## S1 proxy — SCRAM terminate-and-originate; TLS to the backend deferred (MVP-minimal)

**SPEC sections touched:** §3 (layer 2 proxy + layer 0 network boundary), §4 (proxy
enforcement hooks; "un-foolable guarantees = network-boundary + hardened role + read-only
+ statement_timeout + byte-cutoff"), §7 S1 ("pgwire termination incl. SCRAM auth
passthrough + TLS").

**Issue:** #22 (S1 proxy).

### Deviation

1. **SCRAM is terminated-and-originated, not passed through.** The SPEC's S1 line says
   "SCRAM auth **passthrough**." The proxy instead **terminates** the agent's
   SCRAM-SHA-256 handshake (authenticating the agent against the proxy's configured agent
   credential) and then **originates a separate backend connection** as the WALL role
   `pgb_agent`. True passthrough (relaying the agent's SCRAM proof to the backend so the
   backend authenticates the original principal) is not done in the MVP.

2. **TLS terminates at the proxy; the proxy→backend hop is not TLS in the MVP.** The agent
   endpoint is TLS-terminated with `rustls` (ring). The backend connection is plaintext
   over loopback, relying on the §3 layer-0 network boundary (pg_hba: only-from-proxy) for
   confidentiality/integrity on that hop.

3. **Audit sink is the in-memory hash chain in the binary.** The proxy records every
   statement (allow/block/reject) on a `pgb_audit` hash chain, but the shipped binary keeps
   that chain **in-process** (`InMemorySink`). Wiring the Postgres `_meta` sink
   (`pgb_audit::PgSink`, already built in #21) into the running proxy is a follow-up.

### Rationale

- **Terminate-and-originate is the natural shape of an enforcing proxy** and is what makes
  the enforcement hooks possible at all: to gate the extended protocol, classify SQL,
  meter the result stream, and inject `statement_timeout`, the proxy must own both wire
  sides. Passthrough would hand the backend a connection the proxy cannot fully mediate.
  The security guarantee does **not** weaken: the agent still proves a SCRAM credential to
  reach the proxy, and the backend session is the **hardened WALL role** reachable **only**
  via the proxy (the un-foolable backstops — WALL role + `statement_timeout` + byte/row
  cutoff — all hold). The agent→backend principal mapping is fixed (agent ⇒ `pgb_agent`),
  which is exactly the least-privilege intent.

- **Backend TLS is redundant with the network boundary on the loopback/private-link hop**
  the SPEC already mandates (layer 0). It is a config addition (point `rustls` at the
  backend) with no enforcement-logic impact, so it is deferred without weakening the model.

- **The in-memory chain proves the audit contract end-to-end** (allow + blocks/rejects
  recorded, the marquee `COMMIT; DROP SCHEMA` captured verbatim, `verify_chain()` holds —
  see the issue-#22 integration evidence). Persisting to `_meta` reuses the already-merged,
  already-tested `PgSink` and changes no proxy logic.

### Un-foolable enforcement actually proven (issue #22, against live PG18)

The classifier is **advisory and foolable** (e.g. `pg_sleep` classifies as a read). The
proxy therefore relies on the un-foolable backstops, all exercised in the env-gated
`crates/proxy/tests/proxy_it.rs` against the local-stack WALL role: extended-protocol-only
(the marquee `COMMIT; DROP SCHEMA public CASCADE` simple-query **BLOCKED**, schema intact),
read-only gate (UPDATE/DELETE/DDL/COPY blocked), byte/row **mid-stream cutoff** (large
SELECT cut at the per-role budget), `statement_timeout` (fires on `pg_sleep`), fail-closed
(parse failure blocked), and the hash-chained audit recording all of it.
