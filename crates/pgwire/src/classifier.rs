//! Fail-closed read-only statement classifier (`sqlparser-rs`).
//!
//! Given the SQL text from a `Parse`/`Query`, decide whether it is a **single
//! read** (the only thing an agent's read path may run) or **not** (writes,
//! DDL, utility, `COPY`, statement-stacking, or anything we cannot prove safe).
//!
//! The classifier is **fail-closed**: a parse error, multiple statements, or any
//! construct we do not positively recognize as read-only is classified
//! [`Classification::NotRead`]. This is defense-in-depth (SPEC §4) — the network
//! boundary + hardened role + `statement_timeout` + byte cutoff remain the
//! un-foolable backstops — but for the **function-call write** class the
//! classifier is now the **real gate**, not advisory (M2a, issue #114).
//!
//! ## Function-call fail-closed gate (M2a, #114)
//! The classifier used to be **projection-blind**: it inspected only the
//! statement KIND + the FROM/CTE table factors, never the projection / `WHERE` /
//! `HAVING` / … **expressions**, so a `SELECT lo_create(0)`, `SELECT setval(…)`,
//! or `SELECT public.some_security_definer_write_fn()` classified as `Read` →
//! `Allow` and the proxy forwarded the **write** to the backend. That is the
//! catastrophic-FN path once the DB-level `REVOKE … FROM PUBLIC` backstop is gone.
//!
//! A `SELECT` is now `Read` **only if EVERY function it references is on the
//! curated read-safe allowlist** ([`READ_SAFE_FUNCTIONS`]); ANY non-allowlisted
//! function (an `lo_*` writer, `setval`/`nextval`, `pg_read_file`, a `dblink`, a
//! `pg_sleep`, or **any** user/unknown/qualified `schema.fn()` — including a
//! SECURITY DEFINER write fn that could be mislabeled `STABLE`) makes the whole
//! statement `NotRead` → the proxy floor Blocks it. Volatility (`provolatile`) is
//! deliberately **not** the gate (it is spoofable); the allowlist is the mechanism.
//!
//! The scan walks the **full statement AST** via sqlparser's derived `Visit`
//! ([`sqlparser::ast::visit_expressions`]) — projection items, `WHERE`/`HAVING`/
//! `GROUP BY`/`ORDER BY`, JOIN `ON` conditions, aggregate `FILTER`/`ORDER BY`,
//! subqueries + CTEs, and function ARGUMENTS (nested calls like
//! `lo_put(lo_create(0), …)`) — so no `Expr::Function` node can be missed. Table-
//! valued function calls in `FROM`/`JOIN` (which are table factors, not
//! `Expr::Function` nodes) are checked separately against the same allowlist.
//!
//! ## Clean-room note
//! This is implemented from the SPEC and the public `sqlparser` AST only; no
//! pgDog code was consulted or copied.

use std::ops::ControlFlow;

use sqlparser::ast::{Expr, ObjectName, Query, SetExpr, Statement, TableFactor, visit_expressions};
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
    // Fail-closed function-call gate (M2a #114): a SELECT/EXPLAIN-of-a-read is a
    // read ONLY IF every function it references — in ANY position of the statement
    // AST — is on the curated read-safe allowlist. This is checked ONCE here at the
    // statement root (the derived `Visit` walk descends into every nested
    // expression, subquery, CTE, and function argument on its own), independent of
    // the structural recursion below. A single non-allowlisted function anywhere
    // makes the statement NotRead. Applied to `Query` and `Explain` (whose inner
    // read is scanned too); write/DDL/utility kinds are already NotRead structurally.
    if matches!(stmt, Statement::Query(_) | Statement::Explain { .. })
        && !statement_functions_all_read_safe(stmt)
    {
        return false;
    }
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
        // closed by construction. Live-verified that `EXPLAIN (ANALYSE) …`
        // executes (it mutates/deletes/side-effects) while every allowlisted
        // option below only plans — behaviour shared across the supported PG
        // 14-18 range (now exercised across the 14-18 CI matrix).
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

/// The `EXPLAIN (…)` options that we have **proven** (live) only PLAN the
/// statement — they never execute it, so they have no side effects and are safe
/// on the read path. The list is intentionally an **allowlist**, not a denylist:
/// anything not on it is fail-closed to not-read.
///
/// Proven plan-only (verified against a side-effecting `SELECT bump()` that
/// mutates a sentinel — the sentinel stayed `0`, i.e. no execution):
/// `FORMAT`, `VERBOSE`, `COSTS`, `SETTINGS`, `GENERIC_PLAN`, `SUMMARY`, `MEMORY`,
/// and standalone `BUFFERS` (Postgres reports planning buffers without running);
/// the option semantics are stable across the supported PG 14-18 range and are
/// now exercised across the 14-18 CI matrix.
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
///
/// VERSION DEGRADE — FAIL-CLOSED ACROSS PG 14-18 (C1 #102, spec v0.8.1 §0.5):
/// some allowlisted option names were INTRODUCED in a specific major —
/// `GENERIC_PLAN` is **16+** and `MEMORY` is **17+** (`SERIALIZE` is 17+ too, and
/// is deliberately EXCLUDED here regardless). This classifier is purely about
/// *plan-only-ness*; it never gates on PG version, so an agent's
/// `EXPLAIN (GENERIC_PLAN) …` is classified read on any major. The version
/// degrade is handled **downstream and fail-closed**: the EXPLAIN-cost gate
/// (`pgb-proxy`'s `explain.rs`) runs the `EXPLAIN (…)` on the *real backend*, so a
/// PG 14/15 backend that doesn't know `GENERIC_PLAN` (or a PG ≤16 that doesn't
/// know `MEMORY`) returns an ERROR and the gate **blocks the statement** (it
/// refuses anything whose EXPLAIN it cannot prove is under the ceiling). So a
/// version-specific option on an older backend degrades to a *deny*, never a
/// silent execute — the supported-range posture stays least-privilege with no
/// per-version branching here.
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

/// The curated **read-safe function allowlist** (M2a #114) — the KNOWN
/// side-effect-free built-ins an agent legitimately needs on a read path. A
/// `SELECT` is a read only if EVERY function it references is on this list; ANY
/// name not here (an `lo_*` writer, `setval`/`nextval`, `pg_read_file`, a
/// `dblink`, `pg_sleep`, or any user/unknown/**qualified** `schema.fn()`) makes
/// the statement NotRead → the proxy floor Blocks it.
///
/// The list is an **allowlist, not a denylist** (fail-closed): the danger is an
/// unbounded universe of write/side-effecting functions (user SECURITY DEFINER
/// fns, extension fns, future built-ins) we can never fully enumerate, so we
/// enumerate only the small, well-understood read surface and reject everything
/// else. When unsure about a name, it is **left off** (excluded) — a false
/// exclusion only costs a legitimate read a re-phrase; a false inclusion is a
/// silent write bypass.
///
/// Names are matched **case-insensitively** and only in their **bare
/// (schema-less) built-in form**: a schema-qualified call (`public.count(…)`,
/// `pg_catalog.lower(…)`) is treated as NotRead even if the final component
/// collides with an allowlisted built-in — a qualified name is no longer the
/// trusted unqualified built-in (it could resolve to a same-named user function),
/// so we fail closed. (See [`function_name_is_read_safe`].)
///
/// Deliberately EXCLUDED (⇒ NotRead), for the record: every `lo_*`
/// (`lo_create`/`lo_creat`/`lowrite`/`lo_from_bytea`/`lo_put`/`lo_get`/
/// `lo_truncate`/`lo_truncate64`/`lo_unlink`/`lo_import`/`lo_export`),
/// `setval`/`nextval`/`currval`/`lastval`, `pg_read_file`/`pg_read_binary_file`/
/// `pg_stat_file`/`pg_ls_dir`, `dblink*`, `pg_sleep*`, `pg_terminate_backend`/
/// `pg_cancel_backend`, `pg_logical_emit_message`, `set_config`, and EVERY
/// user/unknown/qualified function.
const READ_SAFE_FUNCTIONS: &[&str] = &[
    // ---- aggregates (side-effect-free reductions) ----
    "count",
    "sum",
    "avg",
    "min",
    "max",
    "array_agg",
    "string_agg",
    "jsonb_agg",
    "json_agg",
    "jsonb_object_agg",
    "json_object_agg",
    "bool_and",
    "bool_or",
    "every",
    "bit_and",
    "bit_or",
    "stddev",
    "stddev_pop",
    "stddev_samp",
    "variance",
    "var_pop",
    "var_samp",
    "corr",
    "covar_pop",
    "covar_samp",
    "mode",
    "percentile_cont",
    "percentile_disc",
    // ---- window functions (read-only ordering/ranking) ----
    "row_number",
    "rank",
    "dense_rank",
    "percent_rank",
    "cume_dist",
    "ntile",
    "lag",
    "lead",
    "first_value",
    "last_value",
    "nth_value",
    // ---- math ----
    "abs",
    "ceil",
    "ceiling",
    "floor",
    "round",
    "trunc",
    "sign",
    "sqrt",
    "cbrt",
    "power",
    "pow",
    "exp",
    "ln",
    "log",
    "log10",
    "mod",
    "div",
    "gcd",
    "lcm",
    "pi",
    "degrees",
    "radians",
    "sin",
    "cos",
    "tan",
    "asin",
    "acos",
    "atan",
    "atan2",
    "sinh",
    "cosh",
    "tanh",
    "width_bucket",
    // ---- string ----
    "lower",
    "upper",
    "initcap",
    "length",
    "char_length",
    "character_length",
    "bit_length",
    "octet_length",
    "substr",
    "substring",
    "left",
    "right",
    "trim",
    "btrim",
    "ltrim",
    "rtrim",
    "lpad",
    "rpad",
    "concat",
    "concat_ws",
    "replace",
    "translate",
    "reverse",
    "repeat",
    "split_part",
    "strpos",
    "position",
    "starts_with",
    "format",
    "to_hex",
    "ascii",
    "chr",
    "md5",
    "encode",
    "decode",
    // ---- regex (read-only matching/extraction) ----
    "regexp_replace",
    "regexp_match",
    "regexp_matches",
    "regexp_split_to_array",
    "regexp_split_to_table",
    "regexp_count",
    "regexp_instr",
    "regexp_substr",
    "like",
    "similar_to",
    // ---- coalesce / conditional / comparison ----
    "coalesce",
    "nullif",
    "greatest",
    "least",
    "num_nonnulls",
    "num_nulls",
    // ---- casting / type helpers (side-effect-free) ----
    "cast",
    "to_char",
    "to_number",
    "to_date",
    "to_timestamp",
    // ---- date/time READS ----
    "now",
    "statement_timestamp",
    "transaction_timestamp",
    "clock_timestamp",
    "timeofday",
    "current_timestamp",
    "current_date",
    "current_time",
    "localtime",
    "localtimestamp",
    "date_trunc",
    "date_part",
    "date_bin",
    "extract",
    "age",
    "make_date",
    "make_time",
    "make_timestamp",
    "make_timestamptz",
    "make_interval",
    "justify_days",
    "justify_hours",
    "justify_interval",
    "isfinite",
    // ---- json / jsonb builders + read accessors ----
    "to_json",
    "to_jsonb",
    "json_build_object",
    "jsonb_build_object",
    "json_build_array",
    "jsonb_build_array",
    "json_object",
    "jsonb_object",
    "json_array_length",
    "jsonb_array_length",
    "json_extract_path",
    "jsonb_extract_path",
    "json_extract_path_text",
    "jsonb_extract_path_text",
    "json_typeof",
    "jsonb_typeof",
    "json_strip_nulls",
    "jsonb_strip_nulls",
    "jsonb_pretty",
    "json_array_elements",
    "jsonb_array_elements",
    "json_array_elements_text",
    "jsonb_array_elements_text",
    "json_each",
    "jsonb_each",
    "json_each_text",
    "jsonb_each_text",
    "json_object_keys",
    "jsonb_object_keys",
    "jsonb_path_query",
    "jsonb_path_query_array",
    "jsonb_path_query_first",
    "jsonb_path_exists",
    "jsonb_path_match",
    "row_to_json",
    "json_populate_record",
    "jsonb_populate_record",
    "json_to_record",
    "jsonb_to_record",
    "json_to_recordset",
    "jsonb_to_recordset",
    // ---- array read helpers ----
    "array_length",
    "array_dims",
    "array_ndims",
    "array_upper",
    "array_lower",
    "cardinality",
    "array_position",
    "array_positions",
    "array_to_string",
    "string_to_array",
    "array_append",
    "array_prepend",
    "array_cat",
    "array_remove",
    "array_replace",
    "unnest",
    "generate_series",
    "generate_subscripts",
    // ---- type / value introspection reads (no side effects) ----
    "current_setting",
    "pg_typeof",
    "format_type",
    "current_database",
    "current_schema",
    "current_catalog",
    "current_user",
    "session_user",
    "user",
    "version",
    "pg_backend_pid",
    "row",
];

/// Whether a function name resolved from an `Expr::Function` / table-valued
/// function is on the read-safe allowlist ([`READ_SAFE_FUNCTIONS`]).
///
/// Fail-closed rules:
/// - a **schema-qualified** name (more than one identifier part, e.g.
///   `public.writing_fn`, `pg_catalog.lower`) is NEVER read-safe — a qualified
///   call is not the trusted unqualified built-in and could resolve to a
///   same-named user function, so we deny it;
/// - a bare name is read-safe iff it matches an allowlist entry
///   case-insensitively;
/// - anything else (empty/odd name) is not read-safe.
fn function_name_is_read_safe(name: &ObjectName) -> bool {
    // A qualified name (schema.fn, catalog.schema.fn) is fail-closed NotRead.
    if name.0.len() != 1 {
        return false;
    }
    let ident = match name.0[0].as_ident() {
        Some(i) => i.value.as_str(),
        // A non-identifier name part (e.g. an expression) is not a known built-in.
        None => return false,
    };
    READ_SAFE_FUNCTIONS
        .iter()
        .any(|allowed| ident.eq_ignore_ascii_case(allowed))
}

/// Whether EVERY function referenced anywhere in `stmt`'s AST is read-safe.
///
/// Two independent sweeps, both fail-closed:
/// 1. **Expression sweep** — [`visit_expressions`] runs the derived `Visit` walk
///    over the whole statement, invoking the closure on every [`Expr`]. For each
///    `Expr::Function` we check the name against the allowlist. Because the walk
///    descends into nested expressions, subqueries, CTEs, JOIN `ON`, aggregate
///    `FILTER`/`ORDER BY`, and function ARGUMENTS, a write hidden as an argument
///    (`lo_put(lo_create(0), …)`) or inside a CTE/subquery is caught. We short-
///    circuit (`ControlFlow::Break`) on the first offender.
/// 2. **Table-valued-function sweep** — table-valued function calls in
///    `FROM`/`JOIN` are table factors, NOT `Expr::Function` nodes, so the
///    expression sweep does not see the OUTER name (it does see their argument
///    expressions). [`statement_table_functions_all_read_safe`] walks the query
///    tree and checks each table-function name against the same allowlist.
///
/// Returns `true` only if BOTH sweeps find no non-allowlisted function.
fn statement_functions_all_read_safe(stmt: &Statement) -> bool {
    // Sweep 1: every `Expr::Function` name (projection/WHERE/HAVING/args/…).
    let expr_ok = visit_expressions(stmt, |expr: &Expr| {
        if let Expr::Function(func) = expr
            && !function_name_is_read_safe(&func.name)
        {
            return ControlFlow::Break(());
        }
        ControlFlow::Continue(())
    })
    .is_continue();
    if !expr_ok {
        return false;
    }
    // Sweep 2: table-valued function names in FROM/JOIN.
    statement_table_functions_all_read_safe(stmt)
}

/// Walk `stmt` for table-valued function calls (`FROM generate_series(…)`,
/// `JOIN lo_import(…)`, …) and require each name to be read-safe. Descends into
/// the inner statement of an `EXPLAIN` and into nested/derived subqueries.
fn statement_table_functions_all_read_safe(stmt: &Statement) -> bool {
    match stmt {
        Statement::Query(query) => query_table_functions_all_read_safe(query),
        Statement::Explain { statement, .. } => statement_table_functions_all_read_safe(statement),
        // Non-read kinds are already NotRead structurally; nothing to scan.
        _ => true,
    }
}

/// Recursively require every table-valued function name in a `Query` (its CTEs
/// and body) to be read-safe.
fn query_table_functions_all_read_safe(query: &Query) -> bool {
    if let Some(with) = &query.with {
        for cte in &with.cte_tables {
            if !query_table_functions_all_read_safe(&cte.query) {
                return false;
            }
        }
    }
    set_expr_table_functions_all_read_safe(&query.body)
}

/// Table-valued-function sweep over a set-expression body.
fn set_expr_table_functions_all_read_safe(body: &SetExpr) -> bool {
    match body {
        SetExpr::Select(select) => {
            for twj in &select.from {
                if !table_factor_functions_all_read_safe(&twj.relation) {
                    return false;
                }
                for join in &twj.joins {
                    if !table_factor_functions_all_read_safe(&join.relation) {
                        return false;
                    }
                }
            }
            true
        }
        SetExpr::Query(q) => query_table_functions_all_read_safe(q),
        SetExpr::SetOperation { left, right, .. } => {
            set_expr_table_functions_all_read_safe(left)
                && set_expr_table_functions_all_read_safe(right)
        }
        // VALUES / TABLE have no FROM table factors; write bodies are already
        // rejected structurally (fail-closed) elsewhere.
        _ => true,
    }
}

/// Whether a single table factor introduces no non-allowlisted table function.
///
/// - `TableFactor::Table` with `args: Some(_)` is a table-valued FUNCTION call
///   (`generate_series(…)`, `lo_import(…)`) — its name must be read-safe. A plain
///   table (`args: None`) is a data read and is fine.
/// - `TableFactor::TableFunction` / `TableFactor::Function` are function-form
///   table factors — fail-closed unless the name is read-safe (the ClickHouse-ish
///   `TableFunction` carries an expression, not a name, so it is always NotRead).
/// - Derived subqueries / nested joins recurse.
fn table_factor_functions_all_read_safe(factor: &TableFactor) -> bool {
    match factor {
        // A table factor with parenthesized args is a table-valued function — its
        // name must be read-safe. A plain table (`args: None`) is a data read.
        TableFactor::Table {
            name,
            args: Some(_),
            ..
        } => function_name_is_read_safe(name),
        TableFactor::Table { args: None, .. } => true,
        TableFactor::Function { name, .. } => function_name_is_read_safe(name),
        // A `TableFunction` carries a bare `Expr` (no resolvable name) — we cannot
        // prove it read-safe, so fail closed.
        TableFactor::TableFunction { .. } => false,
        TableFactor::Derived { subquery, .. } => query_table_functions_all_read_safe(subquery),
        TableFactor::NestedJoin {
            table_with_joins, ..
        } => {
            if !table_factor_functions_all_read_safe(&table_with_joins.relation) {
                return false;
            }
            table_with_joins
                .joins
                .iter()
                .all(|j| table_factor_functions_all_read_safe(&j.relation))
        }
        // UNNEST/JSON_TABLE/pivots etc. carry their argument expressions, which the
        // expression sweep already checked; they introduce no table-fn NAME.
        _ => true,
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
