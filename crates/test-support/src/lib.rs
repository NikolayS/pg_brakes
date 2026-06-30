//! Shared test-support for pg_brakes' env-gated PostgreSQL integration tests
//! (issues #44, #102).
//!
//! The integration tests live in **separate test binaries across several crates**
//! (`dbsafe-bench` gate_it, `clone-orchestrator` cluster, `warden_it`, `mcp`
//! write_path_e2e). Each needs the SAME rule for finding the PG client/server
//! binaries (`initdb`, `pg_ctl`, `psql`, …). Before this crate that rule was
//! copy-pasted four times and had **drifted**: only one copy treated a
//! *set-but-empty* `PG_BRAKES_PG_BIN` as fall-through; the others did
//! `env::var(NEW).or_else(|_| env::var(LEGACY))`, which only falls through when
//! `NEW` is **unset** — so with `PG_BRAKES_PG_BIN=""` they selected `""` and
//! broke cluster bootstrap (a fail-OPEN footgun: an empty bin dir silently
//! resolves tools to `/initdb` etc.).
//!
//! [`resolve_pg_bin`] is now the ONE implementation. Every IT resolver calls
//! it, and the precedence is unit-tested against the **exact** function the
//! callers use (see the `tests` module) — including the empty-string
//! fall-through that the old per-resolver `or_else` form got wrong.
//!
//! VERSION-AGNOSTIC (C1 #102, spec v0.8.1 §0.5): the substrate supports the full
//! PG 14-18 range. The bin-dir variable is `PG_BRAKES_PG_BIN` (hard-renamed from
//! the old PG18-pinned `PG_BRAKES_PG18_BIN`, no back-compat alias — pre-1.0, all
//! callers are in-tree). The CI matrix sets it to
//! `/usr/lib/postgresql/${matrix.pg}/bin`; the cluster config the resolver feeds
//! is itself version-agnostic, so the SAME resolver serves every supported major.

use std::path::PathBuf;

/// The version-neutral macOS Homebrew keg path — the dev fallback shared by every
/// IT resolver. Uses the generic `postgresql` formula (not a `postgresql@NN`
/// pin), so a local dev box gets whatever stable major Homebrew has linked; to
/// test a specific major locally, set `PG_BRAKES_PG_BIN` (e.g. to a
/// `…/postgresql@15/bin` keg). The substrate is version-agnostic across PG 14-18.
pub const HOMEBREW_PG_BIN: &str = "/opt/homebrew/opt/postgresql/bin";

/// Resolve the PG bin dir for an integration test, unified across every IT
/// (issues #44, #102). Precedence, matching the shell `${VAR:-…}` semantics
/// (a *set-but-empty* var falls through, it does NOT win):
///
/// 1. `PG_BRAKES_PG_BIN` — the ONE cross-IT/CI variable (set on the runner,
///    per-major in the CI matrix), when **non-empty**.
/// 2. `legacy_var` — the calling crate's legacy var (back-compat for local dev),
///    when **non-empty**. This differs per crate, so it is passed in:
///    `PG_BRAKES_PGBIN` (gate_it / cluster / warden_it) or `PG_BRAKES_PG_BINDIR`
///    (mcp write_path_e2e).
/// 3. [`HOMEBREW_PG_BIN`] — the version-neutral macOS dev fallback.
///
/// This is the public entry point the four IT resolvers call; it reads the
/// process env and delegates the ordering to [`resolve_pg_bin_from`] so the
/// precedence is unit-testable without mutating process-global env.
pub fn resolve_pg_bin(legacy_var: &str) -> PathBuf {
    PathBuf::from(resolve_pg_bin_from(
        std::env::var("PG_BRAKES_PG_BIN").ok().as_deref(),
        std::env::var(legacy_var).ok().as_deref(),
    ))
}

/// Pure precedence for [`resolve_pg_bin`], factored out so the ordering — and
/// the *set-but-empty* fall-through in particular — is unit-tested without
/// touching process-global env. `primary` is `PG_BRAKES_PG_BIN`, `legacy` is the
/// caller's legacy var; `None` = unset, `Some("")` = set-but-empty (must fall
/// through, never win).
fn resolve_pg_bin_from(primary: Option<&str>, legacy: Option<&str>) -> String {
    primary
        .filter(|s| !s.is_empty())
        .or(legacy.filter(|s| !s.is_empty()))
        .unwrap_or(HOMEBREW_PG_BIN)
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// DB-FREE unit test (issues #44, #102): the unified PG bin-dir precedence —
    /// `PG_BRAKES_PG_BIN` (the ONE cross-IT/CI var) wins over the legacy var,
    /// which wins over the Homebrew fallback; **empty strings are ignored**
    /// (the bug FIX 1 closes: the old `or_else` form let `PG_BRAKES_PG_BIN=""`
    /// shadow the legacy var and break bootstrap). Runs in the fast (DB-free)
    /// job, so a regression in the resolver ordering is caught even without a
    /// live PG, and it exercises the EXACT precedence logic all four callers
    /// reach through [`resolve_pg_bin`].
    #[test]
    fn pg_bin_precedence_is_unified() {
        // 1. The cross-IT/CI var wins over the legacy var.
        assert_eq!(
            resolve_pg_bin_from(Some("/ci/pg"), Some("/legacy")),
            "/ci/pg",
            "PG_BRAKES_PG_BIN must take precedence over the legacy var"
        );
        // 2. The legacy var is honored when the cross-IT/CI var is absent (local dev).
        assert_eq!(
            resolve_pg_bin_from(None, Some("/legacy")),
            "/legacy",
            "the legacy var is the local-dev back-compat fallback"
        );
        // 3. The Homebrew keg path is the final fallback when neither is set.
        assert_eq!(
            resolve_pg_bin_from(None, None),
            HOMEBREW_PG_BIN,
            "the version-neutral Homebrew keg path is the macOS dev fallback"
        );
        // 4. An empty cross-IT/CI var falls through to the legacy var (not "").
        //    This is the case the old per-resolver `or_else` form got WRONG.
        assert_eq!(
            resolve_pg_bin_from(Some(""), Some("/legacy")),
            "/legacy",
            "an empty PG_BRAKES_PG_BIN must not shadow the legacy var"
        );
        // 5. An empty legacy var also falls through (to Homebrew here).
        assert_eq!(
            resolve_pg_bin_from(Some(""), Some("")),
            HOMEBREW_PG_BIN,
            "an empty legacy var must not be selected either"
        );
        // 6. A set legacy var with an UNSET cross-IT/CI var is honored even if
        //    the cross-IT/CI var would have been empty — covers None vs Some("").
        assert_eq!(
            resolve_pg_bin_from(None, Some("")),
            HOMEBREW_PG_BIN,
            "empty legacy + unset cross-IT/CI var → Homebrew, never an empty bin dir"
        );
    }
}
