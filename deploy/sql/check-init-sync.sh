#!/usr/bin/env bash
# pg_bumpers — guard: the docker-init copies of the WALL SQL must stay byte-for-byte in
# sync with the canonical sources. The docker entrypoint mounts only deploy/init/, so the
# SQL is duplicated there (a symlink would dangle inside the container). This guard fails
# loudly on drift so the two never diverge silently. Run it in review/CI and the matrix
# harness runs it on startup.
#
# TWO synced files (issue #103 split the role hardening from the demo seed):
#   * 10_hardened_role.sql — the canonical, version-agnostic, BYO-applicable role hardening
#     (a real deployment applies this + grants its own relations);
#   * 20_demo_seed.sql     — the FIXTURE-ONLY demo schema + grants (dev/test/CI only;
#     a real deployment does NOT apply this).
# Both must stay byte-synced sql/ <-> init/.
#
#   deploy/sql/check-init-sync.sh   # exit 0 if in sync, non-zero + diff if not
set -Eeuo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEPLOY_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# Every canonical SQL file that is duplicated into deploy/init/ (byte-synced).
SYNCED_FILES=(10_hardened_role.sql 20_demo_seed.sql)

drift=0
for name in "${SYNCED_FILES[@]}"; do
  CANON="$DEPLOY_DIR/sql/$name"
  INIT="$DEPLOY_DIR/init/$name"
  for f in "$CANON" "$INIT"; do
    [ -f "$f" ] || { echo "check-init-sync: missing $f" >&2; exit 1; }
  done
  if diff -u "$CANON" "$INIT" >/tmp/pgb_init_sync_diff.$$ 2>&1; then
    echo "check-init-sync: deploy/init/$name is IN SYNC with deploy/sql/."
  else
    echo "check-init-sync: DRIFT — deploy/init/$name differs from the canonical" >&2
    echo "  deploy/sql/$name. Re-sync with:" >&2
    echo "    cp deploy/sql/$name deploy/init/$name" >&2
    echo "--- diff (canonical -> init) ---" >&2
    cat /tmp/pgb_init_sync_diff.$$ >&2
    drift=1
  fi
  rm -f /tmp/pgb_init_sync_diff.$$
done

exit "$drift"
