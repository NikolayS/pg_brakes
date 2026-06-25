#!/usr/bin/env bash
# pg_bumpers — CI helper: stop + remove a throwaway PG18 admin cluster started by
# deploy/ci/start-pg.sh (issue #44). NEVER touches :5432. Best-effort: a missing
# cluster is not an error (teardown must be idempotent).
#
# Usage:  deploy/ci/stop-pg.sh <port> [datadir-root]

set -Eeuo pipefail
IFS=$'\n\t'

# PG bin dir (unified — issues #44, #102): PG_BUMPERS_PG_BIN → PGBIN → the
# version-neutral Homebrew keg. Version-agnostic across the supported PG 14-18 range.
PGBIN="${PG_BUMPERS_PG_BIN:-${PGBIN:-/opt/homebrew/opt/postgresql/bin}}"

PORT="${1:?usage: stop-pg.sh <port> [datadir-root]}"
ROOT="${2:-${PG_BUMPERS_CI_PGROOT:-${TMPDIR:-/tmp}/pgb-ci-pg}}"

[ "$PORT" != "5432" ] || { echo "[stop-pg] REFUSING to act on :5432" >&2; exit 1; }

DATADIR="$ROOT/pg-$PORT"
SOCKDIR="$ROOT/sock-$PORT"

if [ -d "$DATADIR" ] && [ -f "$DATADIR/postmaster.pid" ]; then
  "$PGBIN/pg_ctl" -D "$DATADIR" -m immediate -w -t 30 stop >/dev/null 2>&1 || true
fi
rm -rf "$DATADIR" "$SOCKDIR"
echo "[stop-pg] stopped + removed cluster on :$PORT"
