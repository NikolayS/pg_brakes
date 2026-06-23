//! Advisory, fail-closed read-only statement classifier (`sqlparser-rs`).
//!
//! Given the SQL text from a `Parse`/`Query`, decide whether it is a **single
//! read** (the only thing an agent's read path may run) or **not** (writes,
//! DDL, utility, `COPY`, statement-stacking, or anything we cannot prove safe).
//!
//! This is **advisory** per SPEC §4: the un-foolable guarantees are the
//! network boundary + hardened role + read-only replica + `statement_timeout` +
//! byte cutoff. The classifier is a defense-in-depth layer, so it is
//! **fail-closed**: a parse error, multiple statements, or any construct we do
//! not positively recognize as read-only is classified [`Classification::NotRead`].
//!
//! ## Clean-room note
//! This is implemented from the SPEC and the public `sqlparser` AST only; no
//! pgDog code was consulted or copied.

use sqlparser::ast::{Query, SetExpr, Statement, TableFactor};
use sqlparser::dialect::PostgreSqlDialect;
use sqlparser::parser::Parser;

/// The outcome of classifying a chunk of SQL text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Classification {
    /// A single, provably read-only statement (SELECT / read-only CTE).
    Read,
    /// Anything else: writes, DDL, utility, COPY, volatile, multi-statement,
    /// or unparseable. Fail-closed default.
    NotRead,
}

impl Classification {
    /// Whether this classification permits the read path.
    pub fn is_read(self) -> bool {
        matches!(self, Classification::Read)
    }
}

/// Why a statement was classified [`Classification::NotRead`]. Advisory detail
/// for audit/log; the gate decision is the [`Classification`] alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotReadReason {
    /// The SQL text did not parse under the PostgreSQL dialect.
    ParseError,
    /// Zero statements (e.g. empty or comment-only input).
    Empty,
    /// More than one statement (statement-stacking, e.g. `SELECT 1; DROP …`).
    MultipleStatements,
    /// A single statement that is not a read (write/DDL/utility/COPY/etc.).
    NotAReadStatement,
}

/// Classify SQL text as a single read or not-read, with an advisory reason.
///
/// Fail-closed at every branch:
/// - parse error → [`NotReadReason::ParseError`];
/// - `0` statements → [`NotReadReason::Empty`];
/// - `>1` statements → [`NotReadReason::MultipleStatements`] (stacking);
/// - one non-read statement → [`NotReadReason::NotAReadStatement`].
pub fn classify_with_reason(sql: &str) -> (Classification, Option<NotReadReason>) {
    let dialect = PostgreSqlDialect {};
    let statements = match Parser::parse_sql(&dialect, sql) {
        Ok(s) => s,
        // Fail-closed: anything we cannot parse is treated as a write.
        Err(_) => return (Classification::NotRead, Some(NotReadReason::ParseError)),
    };

    match statements.len() {
        0 => (Classification::NotRead, Some(NotReadReason::Empty)),
        1 => {
            if is_read_statement(&statements[0]) {
                (Classification::Read, None)
            } else {
                (
                    Classification::NotRead,
                    Some(NotReadReason::NotAReadStatement),
                )
            }
        }
        // Statement-stacking is never a single read (the `SELECT 1; DROP …`
        // bypass) — flagged even if every statement were individually a SELECT.
        _ => (
            Classification::NotRead,
            Some(NotReadReason::MultipleStatements),
        ),
    }
}

/// Convenience wrapper returning only the [`Classification`].
pub fn classify(sql: &str) -> Classification {
    classify_with_reason(sql).0
}

/// Whether `sql` is a SINGLE `EXPLAIN` statement (any form) — used by the proxy to
/// SKIP the EXPLAIN-cost pre-flight on a statement that is *itself* an EXPLAIN
/// (wrapping it in another `EXPLAIN` would be invalid — "Explain must be root").
///
/// This is purely structural: it says nothing about read/write-ness (that is the
/// classifier's job — a non-`ANALYZE` EXPLAIN of a read is already a
/// [`Classification::Read`]). Fail-closed: a parse error or a multi-statement
/// input is **not** a single EXPLAIN (returns `false`).
pub fn is_explain(sql: &str) -> bool {
    let dialect = PostgreSqlDialect {};
    match Parser::parse_sql(&dialect, sql) {
        Ok(stmts) if stmts.len() == 1 => {
            matches!(
                stmts[0],
                Statement::Explain { .. } | Statement::ExplainTable { .. }
            )
        }
        _ => false,
    }
}

/// Whether a single parsed statement is provably read-only.
///
/// Only `SELECT` (incl. a read-only WITH/CTE) and an **`EXPLAIN` of a read whose
/// every option is plan-only** qualify. An `EXPLAIN` with `ANALYZE`/`ANALYSE`,
/// `SERIALIZE`, or any non-allowlisted option is not-read (it would execute).
/// `INSERT`/`UPDATE`/`DELETE`/`MERGE`/DDL/`COPY`/`TRUNCATE`/utility and everything
/// else are not-read. A data-modifying CTE (`WITH x AS (DELETE …) SELECT …`) is
/// rejected because the WITH body contains a write.
fn is_read_statement(stmt: &Statement) -> bool {
    match stmt {
        Statement::Query(query) => query_is_read_only(query),
        // A plain `EXPLAIN` (no ANALYZE) only PLANS — it never executes the inner
        // statement — so `EXPLAIN [(FORMAT …)] <read>` is a read. It is read-only
        // iff:
        //   (a) it is not bare `EXPLAIN ANALYZE …` (the `analyze` flag — which
        //       WOULD execute), AND
        //   (b) EVERY parenthesized `EXPLAIN (…)` option is in the proven
        //       **plan-only allowlist** ([`explain_options_plan_only`]) — so
        //       `ANALYZE`/`ANALYSE` (the British synonym), `SERIALIZE`, or ANY
        //       option we cannot prove is plan-only makes it NOT a read
        //       (fail-closed), AND
        //   (c) the inner statement is itself a read (so `EXPLAIN DELETE …` /
        //       `EXPLAIN SELECT 1; DROP …` are NOT reads).
        // This lets the agent read path serve `explain_plan` THROUGH the proxy
        // without ever planning *or executing* a write — the explain-hole stays
        // closed by construction. Live-verified on PostgreSQL 18.4 that
        // `EXPLAIN (ANALYSE) …` executes (it mutates/deletes/side-effects) while
        // every allowlisted option below only plans.
        Statement::Explain {
            analyze,
            statement,
            options,
            ..
        } => !*analyze && explain_options_plan_only(options) && is_read_statement(statement),
        // `COPY … TO/FROM` is a not-read path regardless of direction.
        Statement::Copy { .. } => false,
        // Explicitly enumerate the common writes/DDL/utility for clarity even
        // though the catch-all already denies them (fail-closed).
        Statement::Insert(_)
        | Statement::Update { .. }
        | Statement::Delete(_)
        | Statement::Truncate { .. }
        | Statement::Merge { .. }
        | Statement::CreateTable(_)
        | Statement::CreateView { .. }
        | Statement::CreateSchema { .. }
        | Statement::CreateIndex(_)
        | Statement::AlterTable { .. }
        | Statement::Drop { .. } => false,
        // Default-deny: any statement kind we have not positively proven to be
        // read-only is treated as a write.
        _ => false,
    }
}

/// The `EXPLAIN (…)` options that we have **proven** (live, on PostgreSQL 18.4)
/// only PLAN the statement — they never execute it, so they have no side effects
/// and are safe on the read path. The list is intentionally an **allowlist**, not
/// a denylist: anything not on it is fail-closed to not-read.
///
/// Proven plan-only on PG18.4 (verified against a side-effecting `SELECT bump()`
/// that mutates a sentinel — the sentinel stayed `0`, i.e. no execution):
/// `FORMAT`, `VERBOSE`, `COSTS`, `SETTINGS`, `GENERIC_PLAN`, `SUMMARY`, `MEMORY`,
/// and standalone `BUFFERS` (PG18 reports planning buffers without running).
///
/// **Deliberately excluded** (each EXECUTES the statement — proven live, or by PG
/// rule cannot stand alone without `ANALYZE`, which executes):
/// - `ANALYZE` / `ANALYSE` — the British synonym is a *full* PostgreSQL synonym;
///   both EXECUTE (the headline bug: `EXPLAIN (ANALYSE) UPDATE …` mutated,
///   `… DELETE …` deleted, `… SELECT bump()` fired the side effect).
/// - `SERIALIZE` — EXECUTES (it serializes the *result*, which requires running
///   the plan); PG additionally rejects it without `ANALYZE`.
/// - `WAL`, `TIMING` — meaningful only with `ANALYZE` (PG errors "requires
///   ANALYZE" standalone), and with ANALYZE they execute → never plan-only.
///
/// Matching is **case-insensitive** on the option *name* only; the option's `arg`
/// (e.g. `COSTS false`, `BUFFERS true`, `FORMAT json`) does not change whether the
/// name is plan-only, so it is not consulted — an allowlisted name with any arg
/// stays plan-only, and a non-allowlisted name is not-read regardless of arg.
const EXPLAIN_PLAN_ONLY_OPTIONS: &[&str] = &[
    "FORMAT",
    "VERBOSE",
    "COSTS",
    "SETTINGS",
    "GENERIC_PLAN",
    "SUMMARY",
    "MEMORY",
    "BUFFERS",
];

/// Whether **every** parenthesized `EXPLAIN (…)` option is in the proven
/// plan-only allowlist ([`EXPLAIN_PLAN_ONLY_OPTIONS`]).
///
/// Fail-closed: `ANALYZE`/`ANALYSE`, `SERIALIZE`, or **any** unrecognized/unknown
/// option (a typo, a future PG option, an injected token) makes this return
/// `false` → the `EXPLAIN` is not-read. `None` (the bare, non-parenthesized form)
/// has no utility options and is vacuously plan-only here — the bare `ANALYZE`
/// case is caught separately by the `analyze` flag at the call site.
fn explain_options_plan_only(options: &Option<Vec<sqlparser::ast::UtilityOption>>) -> bool {
    match options {
        None => true,
        Some(opts) => opts.iter().all(|o| {
            EXPLAIN_PLAN_ONLY_OPTIONS
                .iter()
                .any(|allowed| o.name.value.eq_ignore_ascii_case(allowed))
        }),
    }
}

/// Whether a `Query` (a SELECT, possibly with a WITH clause) is read-only.
///
/// Rejects data-modifying CTEs by recursively requiring every CTE body to be a
/// read-only query, and requires the top-level set expression to be a
/// SELECT/VALUES (not an `INSERT … RETURNING`-style body).
fn query_is_read_only(query: &Query) -> bool {
    // Any CTE that itself contains a write makes the whole query not-read.
    if let Some(with) = &query.with {
        for cte in &with.cte_tables {
            if !query_is_read_only(&cte.query) {
                return false;
            }
        }
    }
    set_expr_is_read_only(&query.body)
}

/// Whether a set-expression (the body of a query) is read-only.
fn set_expr_is_read_only(body: &SetExpr) -> bool {
    match body {
        SetExpr::Select(select) => {
            // A SELECT … INTO writes a new table — not a read.
            if select.into.is_some() {
                return false;
            }
            // Guard against `SELECT … FROM` over a data-modifying sub-target
            // (defensive; sqlparser models writes elsewhere, but fail-closed).
            for twj in &select.from {
                if !table_factor_is_read_only(&twj.relation) {
                    return false;
                }
                for join in &twj.joins {
                    if !table_factor_is_read_only(&join.relation) {
                        return false;
                    }
                }
            }
            true
        }
        SetExpr::Query(q) => query_is_read_only(q),
        SetExpr::SetOperation { left, right, .. } => {
            set_expr_is_read_only(left) && set_expr_is_read_only(right)
        }
        SetExpr::Values(_) | SetExpr::Table(_) => true,
        // INSERT/UPDATE/DELETE/MERGE as a set-expr body are writes.
        SetExpr::Insert(_) | SetExpr::Update(_) | SetExpr::Delete(_) | SetExpr::Merge(_) => false,
    }
}

/// Whether a table factor (a FROM target) is read-only. Derived subqueries are
/// checked recursively; plain tables/functions are reads.
fn table_factor_is_read_only(factor: &TableFactor) -> bool {
    match factor {
        TableFactor::Derived { subquery, .. } => query_is_read_only(subquery),
        TableFactor::NestedJoin {
            table_with_joins, ..
        } => {
            if !table_factor_is_read_only(&table_with_joins.relation) {
                return false;
            }
            table_with_joins
                .joins
                .iter()
                .all(|j| table_factor_is_read_only(&j.relation))
        }
        // Plain table names, table functions, UNNEST, JSON_TABLE, pivots etc.
        // are read targets in a SELECT context.
        _ => true,
    }
}
