#!/usr/bin/env bash
# pg_brakes — local-stack.sh PATH/PID guard tests (issue #16).
# =====================================================================================
# Pure path/PID-logic unit tests for the defense-in-depth hardenings flagged in the
# PR #14 review. NO real PostgreSQL is required (and none is started); NOTHING real is
# ever killed. The test sources local-stack.sh with PG_BRAKES_LOCALSTACK_TEST=1 so the
# script defines its functions but does NOT run `main`, then drives the real
# `canonicalize_path`, `validate_root`, and `pid_is_ours` functions DIRECTLY with
# controlled inputs (all confined to a private `mktemp` scratch tree + one tracked
# `sleep` we spawn ourselves).
#
# It asserts the hardenings, with teeth (a RED self-check proves the assertions would
# have failed against the pre-fix logic / against a symlink-blind canonicalizer — see
# the inline RED notes):
#
#   UNIT — canonicalize_path's contract, driven DIRECTLY: empty/relative inputs refuse,
#     trailing-slash collapses, root-only is handled, a not-yet-existing multi-segment
#     tail re-attaches under its nearest existing ancestor (incl. the ancestor == '/'
#     case). This is the most intricate new code, so it gets dedicated unit coverage.
#
#   GUARD 1 — validate_root rejects a hostile PG_BRAKES_LOCALSTACK_DIR that escapes the
#     repo — both via a `..` segment AND via a SYMLINK whose canonical target is outside
#     confinement (the symlink case is what `pwd -P` defends; a string-normalize would
#     wrongly accept it). It ACCEPTS the safe default + a legitimate *localstack* dir.
#
#   GUARD 2 — pid_is_ours returns FALSE for a process whose args merely CONTAIN our
#     datadir as a substring / a prefix-collision, and TRUE only for an EXACT CANONICAL
#     data-dir match — including a datadir reached via a SYMLINK that canonicalizes to
#     our real cluster dir (proving the compare is canonical, not literal-string). Driven
#     against a real `sleep` with a crafted argv — never a real cluster, never a kill.
#
# Always-runnable (no env gate): it is pure logic, so it runs in the FAST path and in
# CI without a live PG. SPEC §12 (graceful degradation). Issue #16.
#
# Usage:
#   deploy/test/local_stack_guards.sh        # run all guard assertions, exit 0 on PASS
# =====================================================================================
set -Eeuo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEPLOY_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
STACK="$DEPLOY_DIR/local-stack.sh"

PASS=0
FAIL=0
log()   { printf '[guards] %s\n' "$*"; }
okrow() { printf '  PASS — %s\n' "$*"; PASS=$((PASS + 1)); }
badrow(){ printf '  FAIL — %s\n' "$*" >&2; FAIL=$((FAIL + 1)); }

[ -f "$STACK" ] || { echo "[guards] FAIL: missing $STACK" >&2; exit 1; }

# A dedicated scratch repo-root + localstack tree so we exercise the confinement logic
# against real directories without touching the actual repo or its .localstack.
SCRATCH="$(mktemp -d "${TMPDIR:-/tmp}/pgb_guards.XXXXXX")"
# shellcheck disable=SC2329  # invoked indirectly via `trap cleanup EXIT INT TERM` below.
cleanup() {
  # Kill any test-only sleep we spawned (NEVER a real cluster).
  [ -n "${SLEEP_PID:-}" ] && kill "$SLEEP_PID" 2>/dev/null || true
  rm -rf "$SCRATCH" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

FAKE_REPO="$SCRATCH/repo"
mkdir -p "$FAKE_REPO/.localstack"

# -------------------------------------------------------------------------------------
# Source local-stack.sh in TEST mode: it must define functions but NOT run main. We feed
# it controlled env so REPO_ROOT/ROOT/PRIMARY_DIR/etc. resolve into our scratch tree.
# A subshell isolates each scenario so per-scenario env (and a die() that exits) never
# pollutes the next assertion.
# -------------------------------------------------------------------------------------

# run_canon <input> -> prints "<rc>|<stdout>". Drives canonicalize_path DIRECTLY (it is a
# pure path-logic function — no PG, no kill) and reports BOTH its exit status and its
# printed result so the caller can assert the full contract (refuse vs canonical output).
run_canon() {
  local in="$1" out rc=0
  out="$(
    export PG_BRAKES_LOCALSTACK_TEST=1
    # shellcheck source=/dev/null
    source "$STACK"
    canonicalize_path "$in"
  )" && rc=0 || rc=$?
  printf '%s|%s\n' "$rc" "$out"
}

# run_validate_root <ROOT> <REPO_ROOT> -> prints OK / REJECT. validate_root uses die()
# (which `exit 1`s), so we run it in a child process and key off that child's exit
# status: exit 0 == accepted (OK), non-zero == rejected (REJECT). The `|| true` keeps our
# own `set -e` from aborting on the (expected) reject. NEVER runs any rm.
run_validate_root() {
  local root="$1" repo="$2" rc=0
  (
    export PG_BRAKES_LOCALSTACK_TEST=1
    export PG_BRAKES_LOCALSTACK_DIR="$root"
    # We can't change BASH_SOURCE, so override REPO_ROOT/ROOT after sourcing. These are
    # consumed by the sourced validate_root (cross-source data flow shellcheck can't see).
    # shellcheck source=/dev/null
    source "$STACK"
    # shellcheck disable=SC2034
    REPO_ROOT="$repo"
    # shellcheck disable=SC2034
    ROOT="$root"
    validate_root
  ) >/dev/null 2>&1 && rc=0 || rc=$?
  if [ "$rc" -eq 0 ]; then echo OK; else echo REJECT; fi
}

# run_pid_is_ours <pid> <PRIMARY_DIR> <REPLICA_DIR> <META_DIR> <ROOT> -> OURS / NOT
run_pid_is_ours() {
  local pid="$1" primary="$2" replica="$3" meta="$4" root="$5"
  (
    export PG_BRAKES_LOCALSTACK_TEST=1
    # shellcheck source=/dev/null
    source "$STACK"
    # These override the script's globals and are read by the sourced pid_is_ours
    # (cross-source data flow shellcheck can't see).
    # shellcheck disable=SC2034
    PRIMARY_DIR="$primary"
    # shellcheck disable=SC2034
    REPLICA_DIR="$replica"
    # shellcheck disable=SC2034
    META_DIR="$meta"
    # shellcheck disable=SC2034
    ROOT="$root"
    if pid_is_ours "$pid" 2>/dev/null; then echo OURS; else echo NOT; fi
  )
}

# =====================================================================================
# UNIT — canonicalize_path contract (driven DIRECTLY). The intricate new code: empty /
# relative inputs must refuse; trailing slash collapses; root-only handled; a not-yet-
# existing multi-segment tail re-attaches under its nearest existing ancestor (incl. the
# ancestor == '/' first-`up` case). No PG, no kill — pure path logic.
# =====================================================================================
log "UNIT — canonicalize_path contract"

UNIT_BASE="$SCRATCH/unit"     # an existing ancestor we hang not-yet-existing tails off of
mkdir -p "$UNIT_BASE"

# (u1) empty input -> refuses (non-zero, no output).
got="$(run_canon "")"
if [ "${got%%|*}" != "0" ]; then
  okrow "empty input refused (rc=${got%%|*}, no canonical path)"
else
  badrow "empty input was canonicalized ($got) — must refuse"
fi

# (u2) relative input -> refuses (must be absolute).
got="$(run_canon "relative/x")"
if [ "${got%%|*}" != "0" ]; then
  okrow "relative input 'relative/x' refused (must be absolute)"
else
  badrow "relative input was canonicalized ($got) — must refuse"
fi

# (u3) root-only "/" -> rc 0, prints "/".
got="$(run_canon "/")"
if [ "$got" = "0|/" ]; then
  okrow "root-only '/' canonicalizes to '/' (rc 0)"
else
  badrow "root-only '/' mishandled (got '$got', want '0|/')"
fi

# (u4) trailing slash collapses to the SAME canonical as without it.
canon_with="$(run_canon "$UNIT_BASE/notyet/")"
canon_without="$(run_canon "$UNIT_BASE/notyet")"
if [ "$canon_with" = "$canon_without" ] && [ "${canon_with%%|*}" = "0" ]; then
  okrow "trailing-slash input collapses to same canonical as without ('${canon_with#*|}')"
else
  badrow "trailing-slash mismatch: with='$canon_with' without='$canon_without'"
fi

# (u5) a multi-segment NOT-YET-EXISTING tail under an existing ancestor re-attaches: the
# canonical must be <canon(ancestor)>/a/b/c (exercises the first-`up` peel-and-reattach).
ancestor_canon="$(run_canon "$UNIT_BASE")"; ancestor_canon="${ancestor_canon#*|}"
got="$(run_canon "$UNIT_BASE/a/b/c")"
if [ "$got" = "0|$ancestor_canon/a/b/c" ]; then
  okrow "not-yet-existing tail 'a/b/c' re-attaches under existing ancestor ('${got#*|}')"
else
  badrow "not-yet-existing tail mis-reattached (got '$got', want '0|$ancestor_canon/a/b/c')"
fi

# (u6) an input whose nearest EXISTING ancestor is '/' itself (no symlink on the way), so
# the whole non-existing tail re-attaches directly under root. Use a top-level name that
# cannot exist (PID-stamped) so '/' is genuinely the nearest existing ancestor.
NOEXIST_TOP="/pgb_guards_noexist_$$"
got="$(run_canon "$NOEXIST_TOP/deep/tail")"
if [ "$got" = "0|$NOEXIST_TOP/deep/tail" ]; then
  okrow "tail whose nearest existing ancestor is '/' re-attaches under root ('${got#*|}')"
else
  badrow "ancestor=='/' case mis-handled (got '$got', want '0|$NOEXIST_TOP/deep/tail')"
fi

# =====================================================================================
# GUARD 1 — validate_root: path confinement (`..` AND symlink escapes) + safe-default /
# *localstack* acceptance.
# =====================================================================================
log "GUARD 1 — validate_root path confinement"

# (1a) Safe DEFAULT must still pass: $REPO_ROOT/.localstack under the repo.
got="$(run_validate_root "$FAKE_REPO/.localstack" "$FAKE_REPO")"
if [ "$got" = "OK" ]; then
  okrow "safe default \$REPO_ROOT/.localstack ACCEPTED"
else
  badrow "safe default \$REPO_ROOT/.localstack was REJECTED ($got) — guard too strict"
fi

# (1b) A legitimate *localstack* dir OUTSIDE the repo must still pass (basename allowance).
mkdir -p "$SCRATCH/elsewhere/my-localstack-scratch"
got="$(run_validate_root "$SCRATCH/elsewhere/my-localstack-scratch" "$FAKE_REPO")"
if [ "$got" = "OK" ]; then
  okrow "legitimate *localstack* dir outside repo ACCEPTED"
else
  badrow "legitimate *localstack* dir was REJECTED ($got)"
fi

# (1c) HOSTILE: a `..` that string-prefixes the repo but RESOLVES outside it. This is the
# core string-prefix attack. Pre-fix (unanchored string-prefix "$REPO_ROOT/*") this PASSED
# because the literal string starts with "$REPO_ROOT/" — yet it canonicalizes to
# $SCRATCH/escaped, OUTSIDE the repo and outside any *localstack* dir, where the later
# `rm -rf "$ROOT"` would run. The fix must REJECT it (via the up-front `..` refusal).
mkdir -p "$SCRATCH/escaped"
HOSTILE="$FAKE_REPO/.localstack/../../escaped"
got="$(run_validate_root "$HOSTILE" "$FAKE_REPO")"
if [ "$got" = "REJECT" ]; then
  okrow "hostile '..' escape ('$HOSTILE' -> $SCRATCH/escaped) REJECTED"
else
  badrow "hostile '..' escape was ACCEPTED ($got) — confinement bypassed! (RED: pre-fix string-prefix lets this through)"
fi

# (1d) HOSTILE SYMLINK escape — the headline vector `canonicalize_path`'s `pwd -P` defends.
# With `..` segments already refused outright (1c), a SYMLINK is the ONLY remaining escape
# vector canonicalization defends. We create a real symlink INSIDE a scratch "repo" whose
# target is OUTSIDE the repo; the literal ROOT path has NO `..` (so the `..` guard is NOT
# what stops it) AND its literal basename (`escape-link`) is not *localstack*. The defense
# is purely symlink-resolution: canon -> $SCRATCH/sym-outside (outside repo, non-localstack
# basename) -> REJECT.  >>> RED-TEETH: a regression swapping `pwd -P` for a string-normalize
# would leave the path literally under "$REPO_ROOT/.localstack/..." and ACCEPT it, letting
# `rm -rf "$ROOT"` run on the symlink's real (outside) target. <<<
mkdir -p "$SCRATCH/sym-outside"
ln -s "$SCRATCH/sym-outside" "$FAKE_REPO/.localstack/escape-link"
SYM_ESCAPE="$FAKE_REPO/.localstack/escape-link"
got="$(run_validate_root "$SYM_ESCAPE" "$FAKE_REPO")"
if [ "$got" = "REJECT" ]; then
  okrow "hostile SYMLINK escape ('$SYM_ESCAPE' -> $SCRATCH/sym-outside, no '..' literal) REJECTED (symlink resolved)"
else
  badrow "hostile SYMLINK escape was ACCEPTED ($got) — \`pwd -P\` not resolving the symlink (RED: a string-normalize accepts this)"
fi

# (1e) HOSTILE SYMLINK whose NAME matches *localstack* but whose CANONICAL TARGET is outside
# the repo. This is the real teeth behind the "*localstack* basename allowance": a string-
# normalize would keep the basename `evil-localstack` and ACCEPT via the *localstack* case,
# but canonicalization resolves the link so the basename becomes the target's (`out-target`,
# non-localstack) and the path is outside the repo -> REJECT.  (Replaces the old tautological
# 1d, whose literal basename `outside` was already rejected pre-fix because it isn't
# *localstack* — not because of the `..`.)  >>> RED-TEETH against a symlink-blind canonicalize.
mkdir -p "$SCRATCH/out-target"
ln -s "$SCRATCH/out-target" "$FAKE_REPO/evil-localstack"
SYM_LOCALSTACK="$FAKE_REPO/evil-localstack"   # basename *localstack*, but resolves OUTSIDE
got="$(run_validate_root "$SYM_LOCALSTACK" "$FAKE_REPO")"
if [ "$got" = "REJECT" ]; then
  okrow "*localstack*-NAMED symlink resolving OUTSIDE the repo ('$SYM_LOCALSTACK' -> $SCRATCH/out-target) REJECTED (canonical basename wins)"
else
  badrow "*localstack*-named symlink escape was ACCEPTED ($got) — basename allowance defeated by symlink (RED: a string-normalize accepts this)"
fi

# (1f) NO rm -rf ever happens in validate_root itself — assert the scratch trees the hostile
# ROOTs pointed at are still intact (validate_root must never delete; it only gate-keeps).
# This proves the reject path didn't take a destructive branch.
if [ -d "$SCRATCH/escaped" ] && [ -d "$SCRATCH/sym-outside" ] && [ -d "$SCRATCH/out-target" ]; then
  okrow "no destructive side effect: validate_root left target dirs intact (gate-only)"
else
  badrow "a target dir vanished — validate_root must NEVER rm anything"
fi

# =====================================================================================
# GUARD 2 — pid_is_ours: exact canonical data-dir equality, not substring.
# =====================================================================================
log "GUARD 2 — pid_is_ours exact canonical data-dir match"

# Our canonical cluster dirs live under the fake stack root.
G_ROOT="$FAKE_REPO/.localstack"
G_PRIMARY="$G_ROOT/primary"
G_REPLICA="$G_ROOT/replica"
G_META="$G_ROOT/meta"
mkdir -p "$G_PRIMARY" "$G_REPLICA" "$G_META"

# A prefix-collision dir: its path string CONTAINS our primary dir as a prefix, but it is
# a DIFFERENT directory. Pre-fix the unanchored `*"-D $PRIMARY_DIR"*` substring matched
# any args containing the prefix -> false OURS. The fix's exact-equality must say NOT.
COLLIDE="${G_PRIMARY}-evil"   # ".../primary-evil" — has ".../primary" as a string prefix
mkdir -p "$COLLIDE"

# A symlinked path to our stack root, so a datadir reached VIA the symlink canonicalizes to
# exactly our real $G_PRIMARY. Used by (2a-sym) to prove the compare is canonical.
ln -s "$G_ROOT" "$SCRATCH/symlinked-stack"
SYM_PRIMARY="$SCRATCH/symlinked-stack/primary"   # canon == $G_PRIMARY (via the symlink)

# Spawn a `sleep` whose argv mimics `<comm> -D <dir>` IN THIS shell (NOT a command
# substitution — that would put the job in a short-lived subshell that reaps it before we
# can inspect it). Sets SLEEP_PID. This harmless sleep is the ONLY process we ever touch;
# never a real cluster, never a kill of anything but our own sleep.
#   $1 = leading comm token (e.g. "postgres" or "not_a_db")
#   $2 = the -D data-dir value
spawn_fake_pg() {
  local comm="$1" datadir="$2"
  # exec -a sets argv[0] to the whole "comm -D datadir" string; `ps -o command=` then
  # renders it as our crafted command line.
  bash -c 'exec -a "'"$comm"' -D '"$datadir"'" sleep 30' &
  SLEEP_PID="$!"
  # POLL (don't fixed-sleep) until `ps` shows the renamed argv: `exec -a` runs a beat after
  # fork, and a loaded CI runner can lag — a fixed sleep would either flake or waste time.
  # Bounded so a genuine failure still surfaces (fail-loud) instead of hanging.
  local want="$comm -D $datadir"
  for _ in $(seq 1 100); do   # ~5s ceiling at 0.05s/iter
    case "$(ps -o command= -p "$SLEEP_PID" 2>/dev/null || true)" in
      *"$want"*) return 0 ;;
    esac
    sleep 0.05
  done
  return 0   # fall through: the assertion itself will fail loudly if argv never appeared
}
reap_sleep() { [ -n "${SLEEP_PID:-}" ] && kill "$SLEEP_PID" 2>/dev/null; wait "$SLEEP_PID" 2>/dev/null || true; SLEEP_PID=""; }

# (2a) EXACT match on our primary dir -> OURS.
spawn_fake_pg "postgres" "$G_PRIMARY"
got="$(run_pid_is_ours "$SLEEP_PID" "$G_PRIMARY" "$G_REPLICA" "$G_META" "$G_ROOT")"
if [ "$got" = "OURS" ]; then
  okrow "exact match: 'postgres -D $G_PRIMARY' recognized as OURS"
else
  badrow "exact match on our primary dir was NOT recognized ($got) — fail-closed too aggressive"
fi
reap_sleep

# (2a-sym) CANONICAL match ACROSS A SYMLINK -> OURS. The -D arg is the symlinked path, which
# canonicalizes to exactly our real $G_PRIMARY. Proves the compare is canonical, not literal
# string.  >>> RED-TEETH: a string-normalize canonicalize would leave the candidate as the
# symlinked path ('.../symlinked-stack/primary') which is != '.../.localstack/primary', so it
# would (wrongly) read NOT ours — the assertion here would fail. <<<  No kill of any cluster;
# the crafted `sleep` is the only process touched.
spawn_fake_pg "postgres" "$SYM_PRIMARY"
got="$(run_pid_is_ours "$SLEEP_PID" "$G_PRIMARY" "$G_REPLICA" "$G_META" "$G_ROOT")"
if [ "$got" = "OURS" ]; then
  okrow "canonical match across a symlink: 'postgres -D $SYM_PRIMARY' (canon == $G_PRIMARY) is OURS"
else
  badrow "symlinked datadir canonicalizing to our primary was NOT recognized ($got) — compare is literal-string, not canonical (RED: a string-normalize fails this)"
fi
reap_sleep

# (2b) PREFIX-COLLISION: a DIFFERENT dir whose string has our primary dir as a prefix
# must be NOT ours. RED: pre-fix `*"-D $PRIMARY_DIR"*` substring match returns OURS here
# (the killer could then target a non-ours postmaster). The fix must return NOT.
spawn_fake_pg "postgres" "$COLLIDE"
got="$(run_pid_is_ours "$SLEEP_PID" "$G_PRIMARY" "$G_REPLICA" "$G_META" "$G_ROOT")"
if [ "$got" = "NOT" ]; then
  okrow "prefix-collision: 'postgres -D ${COLLIDE}' correctly NOT ours (exact-equality, not substring)"
else
  badrow "prefix-collision dir matched as OURS ($got) — UNANCHORED SUBSTRING BUG (RED: pre-fix substring matches)"
fi
reap_sleep

# (2c) A process whose args CONTAIN our datadir merely as an embedded substring (not the
# real -D value) must be NOT ours. RED: pre-fix `*"-D $ROOT/"*` substring matches this.
spawn_fake_pg "postgres" "$G_ROOT/primary/pgdata --opt"
got="$(run_pid_is_ours "$SLEEP_PID" "$G_PRIMARY" "$G_REPLICA" "$G_META" "$G_ROOT")"
if [ "$got" = "NOT" ]; then
  okrow "embedded-substring arg under \$ROOT but not an exact datadir correctly NOT ours"
else
  badrow "embedded-substring arg matched as OURS ($got) — \$ROOT/ substring bug (RED)"
fi
reap_sleep

# (2d) FAIL-CLOSED regression guard (NOT a pre-fix-RED case): a non-postgres process (no
# `postgres` token) is never ours, even if its args contain the exact datadir. NOTE: the
# pre-fix `*postgres*` gate already rejected this, so it does not differ pre/post-fix — it
# is an honest regression guard against someone weakening that gate, not a RED-teeth case.
spawn_fake_pg "not_a_db" "$G_PRIMARY"
got="$(run_pid_is_ours "$SLEEP_PID" "$G_PRIMARY" "$G_REPLICA" "$G_META" "$G_ROOT")"
if [ "$got" = "NOT" ]; then
  okrow "non-postgres process with exact datadir arg correctly NOT ours (fail-closed; regression guard)"
else
  badrow "non-postgres process matched as OURS ($got)"
fi
reap_sleep

# (2e) FAIL-CLOSED: a dead/never-existed PID is never ours.
got="$(run_pid_is_ours "999999" "$G_PRIMARY" "$G_REPLICA" "$G_META" "$G_ROOT")"
if [ "$got" = "NOT" ]; then
  okrow "non-existent PID correctly NOT ours (fail-closed)"
else
  badrow "non-existent PID matched as OURS ($got)"
fi

# =====================================================================================
# Verdict
# =====================================================================================
echo
log "===== RESULT: PASS=$PASS FAIL=$FAIL ====="
[ "$FAIL" -eq 0 ] || { log "GUARD TESTS FAILED: $FAIL assertion(s) did not pass."; exit 1; }
log "GREEN: all $PASS guard assertions passed."
exit 0
