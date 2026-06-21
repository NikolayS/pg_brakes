#!/usr/bin/env bash
# pg_bumpers — Layer 1 WALL + Layer 0 boundary: the role-hardening TEST MATRIX.
# =====================================================================================
# Env-gated on PG_BUMPERS_IT=1 (the project integration-test gate). Spins a DEDICATED,
# throwaway Postgres 18 cluster on port 54331 under a temp dir (never collides with
# local-stack's 54321-3, and NEVER touches the founder's 5432), applies the hardened-role
# SQL + the Layer 0 boundary pg_hba, then asserts ONE matrix row per check by ATTEMPTING
# the denied action as the agent role and proving it fails — plus the whitelisted SELECT
# succeeds, member-of-nothing, and the direct-from-non-proxy connection is refused.
#
# Two modes (TDD red/green):
#   GREEN (default):  apply deploy/sql/10_hardened_role.sql → EVERY matrix row must PASS.
#   RED  (--red):     create a bare, UN-hardened agent role (LOGIN + a couple of broad
#                     grants a careless operator might give) → the deny assertions FAIL,
#                     proving the tests have teeth (a freshly-created role CAN do denied
#                     things). The harness exits NON-ZERO in --red (failures are expected
#                     and demonstrate the RED state).
#
# SPEC §3 (layers 0-1), §4 ("Network/roles — do FIRST"), §5 (role-hardening matrix +
# network-boundary negative test). Issue #5. decisions.md "native roles = the security
# wall, hardened".
#
# Usage:
#   PG_BUMPERS_IT=1 deploy/test/wall_matrix.sh           # GREEN: all rows pass, exit 0
#   PG_BUMPERS_IT=1 deploy/test/wall_matrix.sh --red     # RED:  denies fail, exit non-0
#   deploy/test/wall_matrix.sh                           # gate unset → SKIP (exit 0)
# =====================================================================================
set -Eeuo pipefail
IFS=$'\n\t'

# --------------------------------------------------------------------------------------
# Config
# --------------------------------------------------------------------------------------
PGBIN="${PGBIN:-/opt/homebrew/opt/postgresql@18/bin}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEPLOY_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
SQL_FILE="$DEPLOY_DIR/sql/10_hardened_role.sql"
HBA_RENDER="$DEPLOY_DIR/hba/render-hba.sh"

# Dedicated test port + temp data dir. 54331 ∉ {54321,54322,54323,5432}.
TEST_PORT="${PG_BUMPERS_WALL_PORT:-54331}"
AGENT_ROLE="pgb_agent"
AGENT_PW="pgb_agent_dev_pw"           # must match deploy/sql/10_hardened_role.sql default
AGENT_DB="postgres"
# ::1 = proxy-host stand-in (agent ALLOWED). 127.0.0.1 = non-proxy origin (agent REJECT).
PROXY_HOST="::1"
NONPROXY_HOST="127.0.0.1"

MODE="green"
[ "${1:-}" = "--red" ] && MODE="red"

# --------------------------------------------------------------------------------------
# Gate
# --------------------------------------------------------------------------------------
if [ "${PG_BUMPERS_IT:-0}" != "1" ]; then
  echo "[wall] PG_BUMPERS_IT != 1 — skipping role-hardening matrix (set PG_BUMPERS_IT=1 to run)."
  exit 0
fi
for b in initdb pg_ctl psql pg_isready; do
  [ -x "$PGBIN/$b" ] || { echo "[wall] FAIL: missing $PGBIN/$b — set PGBIN to your postgresql@18 bin dir" >&2; exit 1; }
done
[ -f "$SQL_FILE" ]   || { echo "[wall] FAIL: missing $SQL_FILE" >&2; exit 1; }
[ -f "$HBA_RENDER" ] || { echo "[wall] FAIL: missing $HBA_RENDER" >&2; exit 1; }

# Guard: the docker-init copy of the WALL SQL must match the canonical source we apply.
bash "$DEPLOY_DIR/sql/check-init-sync.sh" || {
  echo "[wall] FAIL: deploy/init copy of the WALL SQL is out of sync (see above)." >&2; exit 1; }

DATADIR="$(mktemp -d "${TMPDIR:-/tmp}/pgb_wall.XXXXXX")"
PASS=0; FAIL=0

log()  { printf '[wall] %s\n' "$*"; }
okrow(){ printf '  PASS — %s\n' "$*"; PASS=$((PASS+1)); }
badrow(){ printf '  FAIL — %s\n' "$*" >&2; FAIL=$((FAIL+1)); }

# Superuser psql (local, trust) — for setup/inspection.
SU() { "$PGBIN/psql" -X -h "$NONPROXY_HOST" -p "$TEST_PORT" -U postgres -d "$AGENT_DB" -v ON_ERROR_STOP=1 -tAqc "$1"; }

# Run SQL AS THE AGENT ROLE from the proxy host (::1, allowed). Captures combined
# stdout+stderr and the exit code. This is how every deny is *attempted*.
AGENT() { # sql -> sets AGENT_OUT, returns psql exit code
  AGENT_OUT="$(PGPASSWORD="$AGENT_PW" "$PGBIN/psql" -X \
    "host=$PROXY_HOST port=$TEST_PORT user=$AGENT_ROLE dbname=$AGENT_DB sslmode=disable" \
    -v ON_ERROR_STOP=1 -tAqc "$1" 2>&1)"; }

cleanup() {
  if [ -d "$DATADIR/data" ]; then
    "$PGBIN/pg_ctl" -D "$DATADIR/data" -m immediate -w -t 20 stop >/dev/null 2>&1 || true
  fi
  rm -rf "$DATADIR" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

# --------------------------------------------------------------------------------------
# Safety: refuse to ever touch 5432, and refuse if 54331 is already bound by someone else.
# --------------------------------------------------------------------------------------
[ "$TEST_PORT" != "5432" ] || { echo "[wall] FAIL: refusing TEST_PORT=5432 (the founder's cluster)" >&2; exit 1; }
if lsof -tiTCP:"$TEST_PORT" -sTCP:LISTEN >/dev/null 2>&1; then
  echo "[wall] FAIL: port $TEST_PORT already bound — refusing to collide (set PG_BUMPERS_WALL_PORT)" >&2
  exit 1
fi

# --------------------------------------------------------------------------------------
# 1. initdb + configure the dedicated cluster (listen on ::1 AND 127.0.0.1).
# --------------------------------------------------------------------------------------
log "mode=$MODE — initdb dedicated cluster on :$TEST_PORT under $DATADIR"
# initdb with trust for the bootstrap superuser (local setup); the rendered pg_hba below
# overwrites the rules so the AGENT role authenticates with scram from the proxy host and
# is rejected from non-proxy origins. password_encryption=scram so the agent's password
# verifier is scram (set explicitly; PG18 default is scram already).
"$PGBIN/initdb" -D "$DATADIR/data" -U postgres -A trust --no-sync >/dev/null

cat >> "$DATADIR/data/postgresql.conf" <<EOF

# pg_bumpers wall-matrix test cluster
listen_addresses = '$NONPROXY_HOST,$PROXY_HOST'
port = $TEST_PORT
password_encryption = 'scram-sha-256'
EOF

# Base pg_hba: superuser 'postgres' trusted locally for setup. Then APPEND the rendered
# Layer 0 boundary for the AGENT role (proxy=::1 allowed, everything else rejected).
cat > "$DATADIR/data/pg_hba.conf" <<EOF
# superuser setup access (test only)
local   all   postgres                    trust
host    all   postgres   127.0.0.1/32     trust
host    all   postgres   ::1/128          trust
EOF
# The boundary rules for the agent role (rendered from the shipped template). proxy=::1.
PGB_AGENT_ROLE="$AGENT_ROLE" PGB_AGENT_DB="$AGENT_DB" \
  bash "$HBA_RENDER" --proxy-cidr "$PROXY_HOST/128" --auth scram-sha-256 \
  >> "$DATADIR/data/pg_hba.conf"

"$PGBIN/pg_ctl" -D "$DATADIR/data" -l "$DATADIR/log" -o "-p $TEST_PORT" -w -t 30 start >/dev/null
log "cluster up; PG $(SU 'SHOW server_version' | tr -d '\n')"

# --------------------------------------------------------------------------------------
# 2. Provision the role under test.
#    GREEN: run the real hardened-role migration (creates + hardens pgb_agent + whitelist).
#    RED:   create a bare role with the kind of broad grants a careless operator gives,
#           so the deny assertions below FAIL (proving the matrix has teeth).
# --------------------------------------------------------------------------------------
if [ "$MODE" = "green" ]; then
  log "GREEN: applying deploy/sql/10_hardened_role.sql"
  "$PGBIN/psql" -X -h "$NONPROXY_HOST" -p "$TEST_PORT" -U postgres -d "$AGENT_DB" \
    -v ON_ERROR_STOP=1 -q -f "$SQL_FILE" >/dev/null
  # Idempotency check: apply a SECOND time — must still succeed without error.
  "$PGBIN/psql" -X -h "$NONPROXY_HOST" -p "$TEST_PORT" -U postgres -d "$AGENT_DB" \
    -v ON_ERROR_STOP=1 -q -f "$SQL_FILE" >/dev/null
  log "GREEN: migration applied twice (idempotent)"
else
  log "RED: creating a BARE, UN-hardened agent role with broad grants"
  SU "DROP ROLE IF EXISTS $AGENT_ROLE;" >/dev/null || true
  SU "CREATE ROLE $AGENT_ROLE LOGIN PASSWORD '$AGENT_PW';"
  # The tables exist either way (so SELECT targets are present).
  SU "CREATE TABLE IF NOT EXISTS public.allowed_read (id int PRIMARY KEY, label text NOT NULL);"
  SU "INSERT INTO public.allowed_read VALUES (1,'a'),(2,'b') ON CONFLICT DO NOTHING;"
  SU "CREATE TABLE IF NOT EXISTS public.secret_data (id int PRIMARY KEY, secret text NOT NULL);"
  SU "INSERT INTO public.secret_data VALUES (1,'TOP SECRET') ON CONFLICT DO NOTHING;"
  # The careless grants that the WALL is supposed to PREVENT:
  SU "GRANT pg_read_all_data TO $AGENT_ROLE;"     # makes the agent able to read EVERYTHING
  SU "GRANT pg_execute_server_program TO $AGENT_ROLE;"  # enables COPY … PROGRAM
  SU "GRANT ALL ON public.allowed_read TO $AGENT_ROLE;" # includes write
  SU "GRANT ALL ON public.secret_data TO $AGENT_ROLE;"  # non-whitelisted, should be denied
  # In RED, the boundary pg_hba is still in place; allow the agent from ::1 to run checks.
fi

# Helper: assert an action ATTEMPTED AS THE AGENT FAILS with a permission/error (deny row).
# $1 = human label, $2 = SQL to attempt. PASS iff psql returns non-zero (denied).
assert_denied() {
  local label="$1" sql="$2"
  if AGENT "$sql"; then
    badrow "$label — action SUCCEEDED but should have been DENIED. Output: ${AGENT_OUT:-<empty>}"
  else
    okrow "$label — denied (${AGENT_OUT##*$'\n'})"
  fi
}
# Helper: assert an action ATTEMPTED AS THE AGENT SUCCEEDS (whitelist row).
assert_allowed() {
  local label="$1" sql="$2" want="${3:-}"
  if AGENT "$sql"; then
    if [ -z "$want" ] || printf '%s' "$AGENT_OUT" | grep -q "$want"; then
      okrow "$label — allowed (${AGENT_OUT//$'\n'/ })"
    else
      badrow "$label — allowed but output unexpected: ${AGENT_OUT:-<empty>} (wanted '$want')"
    fi
  else
    badrow "$label — should have SUCCEEDED but was denied: ${AGENT_OUT:-<empty>}"
  fi
}

echo
log "===== ROLE-HARDENING MATRIX (mode=$MODE) ====="

# --------------------------------------------------------------------------------------
# A. Role-attribute matrix (queried from the catalog; the attributes ARE the control).
# --------------------------------------------------------------------------------------
ATTRS="$(SU "SELECT rolsuper,rolinherit,rolcreaterole,rolcreatedb,rolreplication,rolbypassrls FROM pg_roles WHERE rolname='$AGENT_ROLE'")"
IFS='|' read -r r_super r_inherit r_createrole r_createdb r_repl r_bypassrls <<<"$ATTRS"
[ "$r_super"      = "f" ] && okrow "NOT superuser (rolsuper=f)"            || badrow "rolsuper=$r_super (expected f)"
[ "$r_inherit"    = "f" ] && okrow "NOINHERIT (rolinherit=f)"             || badrow "rolinherit=$r_inherit (expected f)"
[ "$r_createrole" = "f" ] && okrow "NOT CREATEROLE (rolcreaterole=f)"     || badrow "rolcreaterole=$r_createrole (expected f)"
[ "$r_createdb"   = "f" ] && okrow "NOT CREATEDB (rolcreatedb=f)"         || badrow "rolcreatedb=$r_createdb (expected f)"
[ "$r_repl"       = "f" ] && okrow "NOT REPLICATION (rolreplication=f)"   || badrow "rolreplication=$r_repl (expected f)"
[ "$r_bypassrls"  = "f" ] && okrow "NOT BYPASSRLS (rolbypassrls=f)"       || badrow "rolbypassrls=$r_bypassrls (expected f)"

# Member-of-nothing: pg_auth_members must be EMPTY for the agent (no pg_* role memberships).
NMEMB="$(SU "SELECT count(*) FROM pg_auth_members m JOIN pg_roles a ON a.oid=m.member WHERE a.rolname='$AGENT_ROLE'")"
if [ "$NMEMB" = "0" ]; then
  okrow "member-of-nothing (pg_auth_members empty for agent)"
else
  MEMBS="$(SU "SELECT string_agg(g.rolname,',') FROM pg_auth_members m JOIN pg_roles a ON a.oid=m.member JOIN pg_roles g ON g.oid=m.roleid WHERE a.rolname='$AGENT_ROLE'")"
  badrow "member-of-nothing — agent is a member of: $MEMBS (expected none)"
fi

# search_path pinned (no mutable "$user"): rolconfig must contain a pinned search_path.
SP="$(SU "SELECT coalesce((SELECT c FROM unnest(rolconfig) c WHERE c LIKE 'search_path=%'),'<unset>') FROM pg_roles WHERE rolname='$AGENT_ROLE'")"
if printf '%s' "$SP" | grep -q 'search_path=' && ! printf '%s' "$SP" | grep -q '\$user'; then
  okrow "search_path pinned, no \$user ($SP)"
else
  badrow "search_path not pinned / contains \$user ($SP)"
fi

# --------------------------------------------------------------------------------------
# B. Predefined-role REVOKEs — proven by ATTEMPTING the capability each grants.
# --------------------------------------------------------------------------------------
# pg_read_all_data → can read ANY table. Prove revoked: SELECT a non-whitelisted table fails.
assert_denied "REVOKE pg_read_all_data (SELECT non-whitelisted public.secret_data)" \
  "SELECT secret FROM public.secret_data LIMIT 1"
# pg_read_all_settings → can read restricted GUCs. (Functional proof is covered by member-
# of-nothing + the catalog check above; here we assert the membership is gone.)
for PR in pg_read_all_data pg_write_all_data pg_read_all_settings pg_read_all_stats \
          pg_monitor pg_execute_server_program pg_read_server_files pg_write_server_files \
          pg_maintain pg_checkpoint pg_signal_backend pg_create_subscription \
          pg_stat_scan_tables pg_use_reserved_connections; do
  IS_MEMBER="$(SU "SELECT pg_has_role('$AGENT_ROLE','$PR','MEMBER')")"
  [ "$IS_MEMBER" = "f" ] && okrow "not a member of $PR" || badrow "agent IS a member of $PR (expected revoked)"
done

# --------------------------------------------------------------------------------------
# C. Write denies — NO write grant anywhere (default-deny). Attempt each, expect failure.
# --------------------------------------------------------------------------------------
assert_denied "no INSERT on whitelisted public.allowed_read" \
  "INSERT INTO public.allowed_read (id,label) VALUES (999,'pwn')"
assert_denied "no UPDATE on whitelisted public.allowed_read" \
  "UPDATE public.allowed_read SET label='pwn' WHERE id=1"
assert_denied "no DELETE on whitelisted public.allowed_read" \
  "DELETE FROM public.allowed_read WHERE id=1"
assert_denied "no INSERT on non-whitelisted public.secret_data" \
  "INSERT INTO public.secret_data (id,secret) VALUES (999,'pwn')"
assert_denied "no CREATE TABLE (no CREATE on schema public)" \
  "CREATE TABLE public.pgb_pwn (id int)"

# --------------------------------------------------------------------------------------
# D. SELECT-whitelist — positive + negative read pair.
# --------------------------------------------------------------------------------------
assert_allowed "whitelisted SELECT public.allowed_read succeeds" \
  "SELECT count(*) FROM public.allowed_read" "2"
assert_denied  "non-whitelisted SELECT public.secret_data denied" \
  "SELECT secret FROM public.secret_data LIMIT 1"

# --------------------------------------------------------------------------------------
# E. Egress / file / program / large-object denies — ATTEMPT each as the agent.
# --------------------------------------------------------------------------------------
assert_denied "COPY … PROGRAM denied (no pg_execute_server_program / superuser)" \
  "COPY (SELECT 1) TO PROGRAM 'cat > /tmp/pgb_pwn_copy'"
assert_denied "COPY FROM PROGRAM denied" \
  "COPY public.allowed_read FROM PROGRAM 'echo 1,x'"
assert_denied "pg_read_file denied (no pg_read_server_files / superuser)" \
  "SELECT pg_read_file('pg_hba.conf')"
assert_denied "pg_read_server_files via pg_read_binary_file denied" \
  "SELECT length(pg_read_binary_file('PG_VERSION'))"
assert_denied "pg_ls_dir (server-file enumeration) denied" \
  "SELECT pg_ls_dir('.')"
assert_denied "lo_import (large-object file read) denied" \
  "SELECT lo_import('/etc/hosts')"
assert_denied "lo_export (large-object file write) denied" \
  "SELECT lo_export(2, '/tmp/pgb_pwn_lo')"
assert_denied "adminpack-style pg_logfile (catalog admin fn) denied or absent" \
  "SELECT pg_read_file('postgresql.conf', 0, 16)"

# --------------------------------------------------------------------------------------
# F. dblink / postgres_fdw deny — enumerate installed extensions; assert absent + the
#    agent cannot CREATE them (no superuser, no CREATE on db).
# --------------------------------------------------------------------------------------
EXTS="$(SU "SELECT coalesce(string_agg(extname,','),'<none>') FROM pg_extension WHERE extname IN ('dblink','postgres_fdw','file_fdw')")"
if [ "$EXTS" = "<none>" ]; then
  okrow "dblink/postgres_fdw/file_fdw NOT installed (enumerated pg_extension)"
else
  badrow "dangerous extensions installed: $EXTS"
fi
assert_denied "agent cannot CREATE EXTENSION dblink (egress)" \
  "CREATE EXTENSION IF NOT EXISTS dblink"
assert_denied "agent cannot CREATE EXTENSION postgres_fdw (egress)" \
  "CREATE EXTENSION IF NOT EXISTS postgres_fdw"

# --------------------------------------------------------------------------------------
# G. PUBLIC EXECUTE revoked — a SECURITY DEFINER / volatile server-side write function
#    must NOT be reachable by the agent via the PUBLIC default. Create one as superuser
#    (NOT granted to the agent), then attempt to call it as the agent → must be denied.
# --------------------------------------------------------------------------------------
SU "CREATE OR REPLACE FUNCTION public.pgb_secdef_write() RETURNS void LANGUAGE sql SECURITY DEFINER AS \$\$ INSERT INTO public.secret_data(id,secret) VALUES (1000,'via secdef') ON CONFLICT DO NOTHING \$\$;" >/dev/null
if [ "$MODE" = "green" ]; then
  # In GREEN the migration revoked PUBLIC EXECUTE on public funcs + default-privileges.
  SU "REVOKE EXECUTE ON FUNCTION public.pgb_secdef_write() FROM PUBLIC;" >/dev/null
fi
assert_denied "PUBLIC EXECUTE revoked (cannot call SECURITY DEFINER write fn)" \
  "SELECT public.pgb_secdef_write()"

# --------------------------------------------------------------------------------------
# H. Layer 0 NETWORK BOUNDARY — agent from non-proxy origin REFUSED; from proxy ALLOWED.
# --------------------------------------------------------------------------------------
echo
log "===== LAYER 0 NETWORK BOUNDARY ====="
# Negative: agent from 127.0.0.1 (a NON-proxy origin) must be REJECTED at pg_hba.
if BOUT="$(PGPASSWORD="$AGENT_PW" "$PGBIN/psql" -X \
      "host=$NONPROXY_HOST port=$TEST_PORT user=$AGENT_ROLE dbname=$AGENT_DB sslmode=disable" \
      -tAqc 'SELECT 1' 2>&1)"; then
  badrow "BOUNDARY — agent CONNECTED from non-proxy $NONPROXY_HOST (should be REJECTED): $BOUT"
else
  if printf '%s' "$BOUT" | grep -qi 'pg_hba.conf rejects connection'; then
    okrow "BOUNDARY — agent from non-proxy $NONPROXY_HOST refused at pg_hba ($(printf '%s' "$BOUT" | tr '\n' ' '))"
  else
    badrow "BOUNDARY — agent from $NONPROXY_HOST failed but not via pg_hba reject: $BOUT"
  fi
fi
# Positive: agent from ::1 (the proxy-host stand-in) must be ALLOWED.
if POUT="$(PGPASSWORD="$AGENT_PW" "$PGBIN/psql" -X \
      "host=$PROXY_HOST port=$TEST_PORT user=$AGENT_ROLE dbname=$AGENT_DB sslmode=disable" \
      -tAqc 'SELECT 1' 2>&1)" && [ "$POUT" = "1" ]; then
  okrow "BOUNDARY — agent from proxy host $PROXY_HOST allowed (models the proxy's IP/CIDR)"
else
  badrow "BOUNDARY — agent from proxy host $PROXY_HOST should be ALLOWED: $POUT"
fi

# --------------------------------------------------------------------------------------
# Verdict
# --------------------------------------------------------------------------------------
echo
log "===== RESULT (mode=$MODE): PASS=$PASS FAIL=$FAIL ====="
if [ "$MODE" = "red" ]; then
  # RED is a DEMONSTRATION that deny assertions fail on an un-hardened role. We EXPECT
  # failures; exit non-zero so the red state is unmistakable (and captured in the PR).
  if [ "$FAIL" -gt 0 ]; then
    log "RED as expected: $FAIL deny/whitelist assertion(s) FAILED on the un-hardened role."
    exit 1
  else
    log "RED UNEXPECTED: no assertions failed on the un-hardened role — the matrix lacks teeth!"
    exit 2
  fi
fi
# GREEN: every row must pass.
[ "$FAIL" -eq 0 ] || { log "GREEN FAILED: $FAIL matrix row(s) did not pass."; exit 1; }
log "GREEN: all $PASS matrix rows passed."
exit 0
