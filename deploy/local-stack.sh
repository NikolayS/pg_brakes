#!/usr/bin/env bash
# pg_bumpers — local dev/test substrate (live S0 substrate for THIS environment)
#
# Brings up isolated, throwaway Postgres 18 clusters under ./.localstack/ using the
# Homebrew keg-only postgresql@18 binaries (initdb / pg_basebackup / pg_ctl). No Docker.
#
# Why local PG instead of docker-compose here: `docker pull` is non-functional in the
# pg_bumpers build environment (host-level daemon networking fault). docker-compose.yml
# remains the shipped artifact; this script is the live substrate every integration test
# and the fidelity gate (#8) run against. See docs/spec/SPEC.amendments.md "S0 integration
# substrate". SPEC refs: §7 (S0 compose), §12 (graceful degradation), §10.8 (degraded
# mode, no replica), §4 (append-only _meta audit DB).
#
# Topology (dedicated high ports; never touches the cluster on 5432):
#   primary  port 54321  — wal_level=replica, replication-ready, PITR-ready.
#   replica  port 54322  — streaming standby of primary via pg_basebackup -R.
#   meta     port 54323  — separate cluster hosting the append-only _meta audit DB (§4).
#
# Usage:
#   deploy/local-stack.sh up      # initdb + start primary + meta, base-backup + stream replica
#   deploy/local-stack.sh down    # stop all clusters and remove ./.localstack/ (clean teardown)
#   deploy/local-stack.sh status  # pg_isready + recovery/replication snapshot
#
# Idempotent: `up` on an already-up stack is a no-op-ish refresh; `down` is always safe.

set -euo pipefail

# --------------------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------------------
PGBIN="${PGBIN:-/opt/homebrew/opt/postgresql@18/bin}"

# Repo root = parent of this script's dir, so paths work from any cwd.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

ROOT="${PG_BUMPERS_LOCALSTACK_DIR:-$REPO_ROOT/.localstack}"
PRIMARY_DIR="$ROOT/primary"
REPLICA_DIR="$ROOT/replica"
META_DIR="$ROOT/meta"
LOG_DIR="$ROOT/logs"

PRIMARY_PORT="${PG_BUMPERS_PRIMARY_PORT:-54321}"
REPLICA_PORT="${PG_BUMPERS_REPLICA_PORT:-54322}"
META_PORT="${PG_BUMPERS_META_PORT:-54323}"

REPL_USER="replicator"
REPL_PASS="replicator"
REPL_SLOT="local_replica_slot"

# Bind to loopback only — these are throwaway dev clusters.
LISTEN="localhost"

# --------------------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------------------
log()  { printf '[local-stack] %s\n' "$*" >&2; }
die()  { printf '[local-stack] ERROR: %s\n' "$*" >&2; exit 1; }

require_bins() {
  for b in initdb pg_ctl pg_basebackup psql pg_isready; do
    [ -x "$PGBIN/$b" ] || die "missing $PGBIN/$b — set PGBIN to your postgresql@18 bin dir"
  done
}

# Wait until a cluster accepts connections (bounded).
wait_ready() {
  local port="$1" label="$2" tries="${3:-60}"
  for _ in $(seq 1 "$tries"); do
    if "$PGBIN/pg_isready" -h "$LISTEN" -p "$port" -q; then
      log "$label ready on port $port"
      return 0
    fi
    sleep 0.5
  done
  die "$label did not become ready on port $port"
}

# --------------------------------------------------------------------------------------
# init + configure each cluster
# --------------------------------------------------------------------------------------
init_primary() {
  log "initdb primary -> $PRIMARY_DIR"
  "$PGBIN/initdb" -D "$PRIMARY_DIR" -U postgres -A trust --no-sync >/dev/null

  # postgresql.conf: replication-ready + PITR-ready knobs.
  cat >> "$PRIMARY_DIR/postgresql.conf" <<EOF

# --- pg_bumpers local-stack: primary (SPEC §7/§12) ---
listen_addresses = '$LISTEN'
port = $PRIMARY_PORT
wal_level = replica
max_wal_senders = 10
max_replication_slots = 10
wal_keep_size = '128MB'
hot_standby = on
# archive_mode is OFF by default (PITR is OPTIONAL per §12). To make this
# PITR-ready: archive_mode = on; archive_command = 'test ! -f .../%f && cp %p .../%f'
EOF

  # pg_hba.conf: local access + a replication entry for the standby over TCP.
  cat >> "$PRIMARY_DIR/pg_hba.conf" <<EOF

# --- pg_bumpers local-stack: local access + streaming replication ---
local   all             all                                     trust
host    all             all             127.0.0.1/32            trust
host    all             all             ::1/128                 trust
host    replication     $REPL_USER      127.0.0.1/32            trust
host    replication     $REPL_USER      ::1/128                 trust
EOF
}

start_primary() {
  log "starting primary on port $PRIMARY_PORT"
  "$PGBIN/pg_ctl" -D "$PRIMARY_DIR" -l "$LOG_DIR/primary.log" \
    -o "-p $PRIMARY_PORT" -w -t 60 start >/dev/null
  wait_ready "$PRIMARY_PORT" "primary"

  # Replication role for the standby.
  "$PGBIN/psql" -X -h "$LISTEN" -p "$PRIMARY_PORT" -U postgres -d postgres -v ON_ERROR_STOP=1 -q <<EOF
DO \$\$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '$REPL_USER') THEN
    CREATE ROLE $REPL_USER WITH REPLICATION LOGIN PASSWORD '$REPL_PASS';
  END IF;
END
\$\$;
EOF

  # =====================================================================
  # >>> HARDENED-ROLE INCLUDE POINT — issue #5 (do NOT duplicate here) <<<
  # The native-role WALL (hardened agent role, least-privilege GRANTs,
  # role-hardening matrix, pg_hba network boundary; SPEC §3 layer 0-1)
  # lands in #5. When it does, source its SQL here against the primary,
  # e.g.:  "$PGBIN/psql" ... -f "$SCRIPT_DIR/init/10_hardened_role.sql"
  # This script intentionally does the WAL/replication wiring only.
  # =====================================================================

  # Minimal baseline marker table so the stack is queryable end-to-end and the
  # smoke harness has a deterministic row to replicate.
  "$PGBIN/psql" -X -h "$LISTEN" -p "$PRIMARY_PORT" -U postgres -d postgres -v ON_ERROR_STOP=1 -q <<'EOF'
CREATE TABLE IF NOT EXISTS public.pgb_devstack_marker (
    id         integer PRIMARY KEY,
    note       text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);
INSERT INTO public.pgb_devstack_marker (id, note)
VALUES (1, 'pg_bumpers local-stack primary initialized')
ON CONFLICT (id) DO NOTHING;
EOF
}

init_and_start_replica() {
  log "pg_basebackup replica <- primary($PRIMARY_PORT) -> $REPLICA_DIR"
  # -R writes standby.signal + primary_conninfo; -C -S creates a physical slot.
  PGPASSWORD="$REPL_PASS" "$PGBIN/pg_basebackup" \
    -h "$LISTEN" -p "$PRIMARY_PORT" -U "$REPL_USER" \
    -D "$REPLICA_DIR" -Fp -Xs -P -R -C -S "$REPL_SLOT" --no-sync

  # Standby-specific knobs (appended so they win).
  cat >> "$REPLICA_DIR/postgresql.conf" <<EOF

# --- pg_bumpers local-stack: replica (standby) ---
listen_addresses = '$LISTEN'
port = $REPLICA_PORT
hot_standby = on
EOF

  log "starting replica on port $REPLICA_PORT"
  "$PGBIN/pg_ctl" -D "$REPLICA_DIR" -l "$LOG_DIR/replica.log" \
    -o "-p $REPLICA_PORT" -w -t 60 start >/dev/null
  wait_ready "$REPLICA_PORT" "replica"
}

init_and_start_meta() {
  log "initdb meta -> $META_DIR"
  "$PGBIN/initdb" -D "$META_DIR" -U postgres -A trust --no-sync >/dev/null
  cat >> "$META_DIR/postgresql.conf" <<EOF

# --- pg_bumpers local-stack: meta (append-only _meta audit DB, SPEC §4) ---
listen_addresses = '$LISTEN'
port = $META_PORT
EOF
  cat >> "$META_DIR/pg_hba.conf" <<EOF

# --- pg_bumpers local-stack: local access ---
local   all   all                  trust
host    all   all   127.0.0.1/32   trust
host    all   all   ::1/128        trust
EOF

  log "starting meta on port $META_PORT"
  "$PGBIN/pg_ctl" -D "$META_DIR" -l "$LOG_DIR/meta.log" \
    -o "-p $META_PORT" -w -t 60 start >/dev/null
  wait_ready "$META_PORT" "meta"

  # Create the append-only _meta audit DB (the audit schema itself lands later).
  if ! "$PGBIN/psql" -X -h "$LISTEN" -p "$META_PORT" -U postgres -d postgres -tAqc \
       "SELECT 1 FROM pg_database WHERE datname = '_meta'" | grep -q 1; then
    "$PGBIN/psql" -X -h "$LISTEN" -p "$META_PORT" -U postgres -d postgres -v ON_ERROR_STOP=1 -qc \
      'CREATE DATABASE "_meta";'
    log "created _meta audit database"
  fi
}

# --------------------------------------------------------------------------------------
# stop a single cluster if its data dir exists and a postmaster is running
# --------------------------------------------------------------------------------------
stop_cluster() {
  local dir="$1" label="$2"
  if [ -d "$dir" ] && [ -f "$dir/postmaster.pid" ]; then
    log "stopping $label"
    "$PGBIN/pg_ctl" -D "$dir" -m fast -w -t 30 stop >/dev/null 2>&1 || \
      "$PGBIN/pg_ctl" -D "$dir" -m immediate -w -t 30 stop >/dev/null 2>&1 || true
  fi
}

# --------------------------------------------------------------------------------------
# Subcommands
# --------------------------------------------------------------------------------------
cmd_up() {
  require_bins
  mkdir -p "$ROOT" "$LOG_DIR"

  # Fresh clusters each up: tear down anything stale first so `up` is deterministic.
  cmd_down_quiet

  mkdir -p "$ROOT" "$LOG_DIR"

  init_primary
  start_primary
  init_and_start_meta
  init_and_start_replica

  log "stack up: primary=$PRIMARY_PORT meta=$META_PORT replica=$REPLICA_PORT"
}

cmd_down_quiet() {
  stop_cluster "$REPLICA_DIR" "replica"
  stop_cluster "$META_DIR" "meta"
  stop_cluster "$PRIMARY_DIR" "primary"
  if [ -d "$ROOT" ]; then
    rm -rf "$ROOT"
  fi
}

cmd_down() {
  require_bins
  cmd_down_quiet
  log "stack down: clusters stopped, $ROOT removed"
}

cmd_status() {
  require_bins
  for spec in "primary:$PRIMARY_PORT" "meta:$META_PORT" "replica:$REPLICA_PORT"; do
    local label="${spec%%:*}" port="${spec##*:}"
    if "$PGBIN/pg_isready" -h "$LISTEN" -p "$port" -q; then
      printf '[local-stack] %-8s port %-6s UP\n' "$label" "$port" >&2
    else
      printf '[local-stack] %-8s port %-6s DOWN\n' "$label" "$port" >&2
    fi
  done
}

main() {
  local sub="${1:-}"
  case "$sub" in
    up)     cmd_up ;;
    down)   cmd_down ;;
    status) cmd_status ;;
    *) die "usage: $(basename "$0") {up|down|status}" ;;
  esac
}

main "$@"
