#!/usr/bin/env bash
# pg_bumpers — CI helper: start a THROWAWAY plain PG18 admin cluster on a
# dedicated high port (issue #44 — the CI integration job).
#
# Several env-gated Rust ITs do NOT self-provision; they connect to an
# already-running admin server on a fixed default port (each test then creates
# its OWN uniquely-named database, so one admin server per port is enough):
#
#   54341  clone-orchestrator dry_run/apply/revert/apply_grant  (PG_BUMPERS_PGURL)
#   54355  applyd_it                                            (PG_BUMPERS_PGURL)
#   55431  fidelity spike                                       (PG_BUMPERS_PGURL)
#   55432  audit + cli (_meta) ITs                              (PG_BUMPERS_AUDIT_PGURL)
#
# (The proxy/read-path ITs instead use deploy/local-stack.sh, which also applies
# the native-role WALL — they are NOT covered here.)
#
# This brings up a minimal trust-on-loopback cluster (NEVER :5432) under a
# git-ignored scratch dir, waits for readiness, and is paired with stop-pg.sh
# for teardown. Idempotent-ish: a stale datadir for the port is removed first.
#
# Usage:  deploy/ci/start-pg.sh <port> [datadir-root]
#         deploy/ci/stop-pg.sh  <port> [datadir-root]
#
# PG bin dir precedence (unified — issues #44, #102):
#   PG_BUMPERS_PG_BIN → PGBIN → the version-neutral Homebrew keg path (macOS dev
#   fallback). Version-agnostic across the supported PG 14-18 range.

set -Eeuo pipefail
IFS=$'\n\t'

PGBIN="${PG_BUMPERS_PG_BIN:-${PGBIN:-/opt/homebrew/opt/postgresql/bin}}"

PORT="${1:?usage: start-pg.sh <port> [datadir-root]}"
ROOT="${2:-${PG_BUMPERS_CI_PGROOT:-${TMPDIR:-/tmp}/pgb-ci-pg}}"

[ "$PORT" != "5432" ] || { echo "[start-pg] REFUSING to start on :5432 (the founder's cluster)" >&2; exit 1; }

DATADIR="$ROOT/pg-$PORT"
SOCKDIR="$ROOT/sock-$PORT"
LOGFILE="$ROOT/pg-$PORT.log"

for b in initdb pg_ctl psql pg_isready; do
  [ -x "$PGBIN/$b" ] || { echo "[start-pg] missing $PGBIN/$b — set PG_BUMPERS_PG_BIN" >&2; exit 1; }
done

echo "[start-pg] port=$PORT datadir=$DATADIR bin=$PGBIN"

# Fresh datadir each time (a re-run must not reuse a half-initialised cluster).
rm -rf "$DATADIR" "$SOCKDIR"
mkdir -p "$DATADIR" "$SOCKDIR"

"$PGBIN/initdb" -D "$DATADIR" -U postgres -A trust --no-sync >/dev/null

# Loopback-only, dedicated port, fsync off (throwaway → speed). The sockets live
# in a short path so the Unix-socket directory is well under any length cap.
cat >> "$DATADIR/postgresql.auto.conf" <<EOF

# --- pg_bumpers CI throwaway admin cluster (issue #44) ---
listen_addresses = '127.0.0.1'
port = $PORT
unix_socket_directories = '$SOCKDIR'
fsync = off
synchronous_commit = off
full_page_writes = off
EOF

"$PGBIN/pg_ctl" -D "$DATADIR" -l "$LOGFILE" -w -t 60 start >/dev/null

# Prove readiness on the dedicated port before returning.
for _ in $(seq 1 60); do
  if "$PGBIN/pg_isready" -h 127.0.0.1 -p "$PORT" -q; then
    echo "[start-pg] ready on :$PORT"
    exit 0
  fi
  sleep 0.5
done

echo "[start-pg] PG18 did not become ready on :$PORT — log tail:" >&2
tail -n 40 "$LOGFILE" >&2 || true
exit 1
