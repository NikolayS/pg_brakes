#!/usr/bin/env bash
# pg_bumpers — integration smoke harness for the S0 dev substrate.
#
# Env-gated: only runs its assertions when PG_BUMPERS_IT=1, so plain test runs
# (and the cargo CI job) stay fast and don't depend on a live database. This is
# the documented integration-test gate convention for the whole project.
#
# Asserts (against deploy/local-stack.sh clusters):
#   1. primary reachable           (pg_isready, port 54321)
#   2. meta reachable + _meta DB    (pg_isready + SELECT in _meta, port 54323)
#   3. replica reachable + IN RECOVERY (pg_is_in_recovery() = t, port 54322)
#   4. streaming works             (pg_stat_replication row on primary)
#   5. round-trip                  (row written on primary visible on replica
#                                   within a bounded wait)
#
# Exit non-zero on ANY failure. With PG_BUMPERS_IT unset/!=1 it SKIPS (exit 0).
#
# SPEC refs: §7 (S0 substrate), §12 (replica OPTIONAL; streaming when present),
# §4 (_meta audit DB). See docs/spec/SPEC.amendments.md "S0 integration substrate".

set -euo pipefail

PGBIN="${PGBIN:-/opt/homebrew/opt/postgresql@18/bin}"
LISTEN="localhost"
PRIMARY_PORT="${PG_BUMPERS_PRIMARY_PORT:-54321}"
REPLICA_PORT="${PG_BUMPERS_REPLICA_PORT:-54322}"
META_PORT="${PG_BUMPERS_META_PORT:-54323}"

# Bound for replication visibility (seconds).
REPL_WAIT_SECS="${PG_BUMPERS_REPL_WAIT_SECS:-15}"

pass()  { printf '  ok   — %s\n' "$*"; }
fail()  { printf '  FAIL — %s\n' "$*" >&2; FAILED=1; }
info()  { printf '[smoke] %s\n' "$*"; }

# --------------------------------------------------------------------------------------
# Gate
# --------------------------------------------------------------------------------------
if [ "${PG_BUMPERS_IT:-0}" != "1" ]; then
  info "PG_BUMPERS_IT != 1 — skipping integration smoke (set PG_BUMPERS_IT=1 to run)."
  exit 0
fi

[ -x "$PGBIN/psql" ] || { echo "[smoke] FAIL: missing $PGBIN/psql" >&2; exit 1; }

FAILED=0

psql_q() { # host-port db sql
  # -X ignores any user ~/.psqlrc (which can inject banners/timing into output).
  "$PGBIN/psql" -X -h "$LISTEN" -p "$1" -U postgres -d "$2" -tAqc "$3"
}

# --------------------------------------------------------------------------------------
# 1. primary reachable
# --------------------------------------------------------------------------------------
info "1/5 primary reachable (port $PRIMARY_PORT)"
if "$PGBIN/pg_isready" -h "$LISTEN" -p "$PRIMARY_PORT" -q; then
  pass "primary accepting connections"
else
  fail "primary NOT reachable on port $PRIMARY_PORT"
fi

# --------------------------------------------------------------------------------------
# 2. meta reachable + _meta DB present
# --------------------------------------------------------------------------------------
info "2/5 meta reachable + _meta DB (port $META_PORT)"
if "$PGBIN/pg_isready" -h "$LISTEN" -p "$META_PORT" -q; then
  if [ "$(psql_q "$META_PORT" _meta 'SELECT 1' 2>/dev/null || true)" = "1" ]; then
    pass "meta reachable and _meta DB queryable"
  else
    fail "meta reachable but _meta DB not queryable"
  fi
else
  fail "meta NOT reachable on port $META_PORT"
fi

# --------------------------------------------------------------------------------------
# 3. replica reachable + in recovery (is a standby)
# --------------------------------------------------------------------------------------
info "3/5 replica reachable + in recovery (port $REPLICA_PORT)"
if "$PGBIN/pg_isready" -h "$LISTEN" -p "$REPLICA_PORT" -q; then
  in_rec="$(psql_q "$REPLICA_PORT" postgres 'SELECT pg_is_in_recovery()' 2>/dev/null || true)"
  if [ "$in_rec" = "t" ]; then
    pass "replica is in recovery (pg_is_in_recovery() = t)"
  else
    fail "replica reachable but NOT in recovery (got '$in_rec')"
  fi
else
  fail "replica NOT reachable on port $REPLICA_PORT"
fi

# --------------------------------------------------------------------------------------
# 4. streaming — primary sees the standby in pg_stat_replication
# --------------------------------------------------------------------------------------
info "4/5 streaming (pg_stat_replication on primary)"
n_standbys="$(psql_q "$PRIMARY_PORT" postgres \
  "SELECT count(*) FROM pg_stat_replication WHERE state = 'streaming'" 2>/dev/null || echo 0)"
if [ "${n_standbys:-0}" -ge 1 ]; then
  pass "primary reports $n_standbys streaming standby(s)"
else
  fail "no streaming standby in pg_stat_replication"
fi

# --------------------------------------------------------------------------------------
# 5. round-trip — write on primary, read on replica within a bound
# --------------------------------------------------------------------------------------
info "5/5 replicated round-trip (bound ${REPL_WAIT_SECS}s)"
TOKEN="smoke-$(date +%s)-$$"
psql_q "$PRIMARY_PORT" postgres "
  CREATE TABLE IF NOT EXISTS public.pgb_smoke (id bigserial PRIMARY KEY, token text NOT NULL);
  INSERT INTO public.pgb_smoke (token) VALUES ('$TOKEN');" >/dev/null 2>&1 \
  || fail "could not write probe row on primary"

seen=""
deadline=$(( $(date +%s) + REPL_WAIT_SECS ))
while [ "$(date +%s)" -le "$deadline" ]; do
  seen="$(psql_q "$REPLICA_PORT" postgres \
    "SELECT 1 FROM public.pgb_smoke WHERE token = '$TOKEN' LIMIT 1" 2>/dev/null || true)"
  [ "$seen" = "1" ] && break
  sleep 0.5
done
if [ "$seen" = "1" ]; then
  pass "probe row '$TOKEN' replicated to standby within bound"
else
  fail "probe row did NOT appear on replica within ${REPL_WAIT_SECS}s"
fi

# --------------------------------------------------------------------------------------
# Verdict
# --------------------------------------------------------------------------------------
if [ "$FAILED" -ne 0 ]; then
  echo "[smoke] RESULT: FAIL" >&2
  exit 1
fi
echo "[smoke] RESULT: PASS"
