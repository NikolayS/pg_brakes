#!/usr/bin/env bash
# pg_bumpers — Rust-only grep-acceptance gate (issue #101, spec v0.8.1 §0.5).
# =====================================================================================
# The implementation is **Rust-only**: NO Node.js / TypeScript / pnpm technology in
# tracked source, docs, CI, or the toolchain. The deployable MCP server is the native
# Rust `pgb-mcp` (crates/mcp, rmcp); the original non-Rust MCP server is gone.
#
# This gate asserts that the `node`/`pnpm`/`typescript` *technology* tokens are absent
# from tracked files, and SURFACES (for the reviewer) any remaining literal `node` word
# so each can be confirmed as a legitimate non-Node.js use (e.g. a plan/AST "node",
# `set_nodelay`). It needs NO PostgreSQL and is wired into the fast `rust` CI job.
#
# Exclusions (by design, see the issue Decisions):
#   - build artifacts (not tracked anyway) + the resolved `Cargo.lock` (a lockfile of
#     crate names, not a technology choice).
#   - this script itself (it must NAME the banned technology tokens to scan for them).
#   - the FROZEN docs/spec/SPEC.md, which STATES the Rust-only prohibition itself
#     ("NO Node/TypeScript … no pnpm/node in the toolchain or CI") — it must name the
#     banned technologies to forbid them, and is build-frozen (never edited in features).
# The EPIC #83 historical record in docs/spec/SPEC.amendments.md is NOT excluded: it was
# reworded (issue #101) to drop the literal technology tokens while preserving the fact.
#
# Exit 0 (GREEN) when the technology tokens are absent; exit 1 (RED) listing the
# residual files otherwise.

set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$REPO_ROOT"

# Technology tokens that must NOT appear in tracked files. `node_modules`, `nodejs`,
# `node.js`, `npm ` (with the trailing space to avoid e.g. unrelated "npm"-substrings),
# plus the TypeScript/pnpm toolchain markers.
TOKENS='pnpm|typescript|vitest|tsconfig|node_modules|nodejs|node\.js|npm '

# Files excluded from the technology-token scan (documented above). The scan runs over
# tracked files only (`git grep`), so build artifacts are already out of scope.
EXCLUDES=(
  ':(exclude)Cargo.lock'
  ':(exclude)deploy/test/no_node_residuals.sh'
  ':(exclude)docs/spec/SPEC.md'
)

echo "== no_node_residuals: scanning tracked files for Node.js/pnpm/TypeScript technology =="

# `git grep -lI` lists matching tracked files; `|| true` because grep exits 1 on no-match.
residual_files="$(git grep -lIiE "$TOKENS" -- . "${EXCLUDES[@]}" || true)"

if [ -n "$residual_files" ]; then
  echo "RED: Node.js/pnpm/TypeScript technology tokens found in tracked files:" >&2
  echo "$residual_files" | sed 's/^/  /' >&2
  echo >&2
  echo "matching lines:" >&2
  git grep -nIiE "$TOKENS" -- . "${EXCLUDES[@]}" | sed 's/^/  /' >&2 || true
  exit 1
fi

echo "GREEN: no Node.js/pnpm/TypeScript technology tokens in tracked files."

# --- Reviewer aid: surface every remaining literal `node` word for confirmation -------
# These are the legitimate non-Node.js uses (plan/AST "node", `set_nodelay`, "exit node",
# a network "node"). Listed, never failed on — the reviewer confirms each is benign.
# NB: `git grep -E` uses POSIX ERE (no `\b` word boundary), so we match the plain
# substring `node` case-insensitively to be sure NOTHING is hidden from the reviewer.
echo
echo "== remaining literal 'node' substrings (expected: legitimate non-Node.js uses only) =="
git grep -nIi 'node' -- . ':(exclude)Cargo.lock' || echo "  (none)"

exit 0
