//! Tiered intent capture, T0–T2 (SPEC §11.2, §15.3 one-way door).
//!
//! pg_brakes sits at the SQL/libpq wire, so it **infers** intent rather than
//! demanding rich input. The tiers, weakest signal to richest, that the MVP
//! captures:
//!
//! - **T0 — role/identity:** coarse scope + purpose; always available.
//! - **T1 — the SQL itself + comments + `application_name`/GUCs:** including the
//!   `/* intent: … ticket: … actor: … */` annotation and the statement class.
//! - **T2 — observed session context:** query sequence, reads-before-write,
//!   rate, tables, timing (behavioral inference).
//!
//! T3 (explicit MCP asserts) and T4 (attested origin/provenance) are
//! enrichment, **out of MVP scope**, and not modeled here.
//!
//! **MVP posture (§11.5):** these tiers are **captured and logged only** — they
//! are serialized into the audit / blast-radius record but **not acted on**.
//! The serde shape is the one-way door; the parser is best-effort and never
//! fails closed-or-open on a malformed annotation (it just leaves fields empty,
//! since absence of intent signal must not loosen anything).

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// T0 — coarse role / identity (SPEC §11.2). Always available at the wire.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TierT0 {
    /// The database role / principal the session authenticated as.
    pub role: String,
    /// Optional coarse purpose/scope label attached to the role (e.g.
    /// `"app"`, `"analytics"`, `"migration"`). Drives context-aware tuning in
    /// the real engine (§11.6); informational in MVP.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub purpose: Option<String>,
}

/// A parsed `/* intent: … ticket: … actor: … */` annotation (SPEC §11.2 T1).
///
/// Every field is optional because the annotation is attacker-controllable and
/// frequently absent — it is a *logged* signal, never a gate in MVP.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct IntentAnnotation {
    /// The declared `intent:` free text.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub intent: Option<String>,
    /// The declared `ticket:` reference.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ticket: Option<String>,
    /// The declared `actor:` (who/what is acting).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor: Option<String>,
}

impl IntentAnnotation {
    /// Whether the annotation carried no recognized fields.
    pub fn is_empty(&self) -> bool {
        self.intent.is_none() && self.ticket.is_none() && self.actor.is_none()
    }
}

/// T1 — the SQL itself + comments + `application_name`/GUCs (SPEC §11.2).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TierT1 {
    /// The raw statement text as seen at the wire.
    pub statement_text: String,
    /// A coarse statement class (e.g. `"SELECT"`, `"UPDATE"`, `"DELETE"`),
    /// derived from the statement's leading keyword.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub statement_class: Option<String>,
    /// The libpq `application_name`, if set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub application_name: Option<String>,
    /// Selected session GUCs captured for context (e.g. a `pg_brakes.trace_id`).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub gucs: BTreeMap<String, String>,
    /// The parsed `/* intent: … */` annotation, if any was present.
    #[serde(default)]
    pub annotation: IntentAnnotation,
}

/// One observed step in the session's query sequence (SPEC §11.2 T2).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservedStep {
    /// Statement class for this step (`"SELECT"`, `"UPDATE"`, …).
    pub class: String,
    /// The relations the step referenced (`schema.table`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tables: Vec<String>,
    /// The clock reading (monotonic millis) at which the step was observed, for
    /// rate/timing inference. Sourced from `core::Clock` upstream.
    pub at_monotonic_millis: u64,
}

/// T2 — observed session context / behavioral inference (SPEC §11.2).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct TierT2 {
    /// The ordered sequence of statements observed in the session so far.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub query_sequence: Vec<ObservedStep>,
    /// Whether at least one read preceded this write in the session
    /// (reads-before-write — a recon-then-act signal).
    #[serde(default)]
    pub reads_before_write: bool,
    /// Observed statements-per-minute over the recent window (rate signal).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rate_per_min: Option<f64>,
    /// The distinct relations touched in the session window.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tables: Vec<String>,
}

/// The full T0–T2 intent-capture record logged with each action
/// (SPEC §11.2, §15.3).
///
/// This is the serde one-way door: it is embedded in the audit / blast-radius
/// record. In MVP it is **captured/logged only**, not consulted by any gate.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct IntentTiers {
    /// T0 — role / identity.
    #[serde(default)]
    pub t0: TierT0,
    /// T1 — SQL + comments + application_name / GUCs.
    #[serde(default)]
    pub t1: TierT1,
    /// T2 — observed session context.
    #[serde(default)]
    pub t2: TierT2,
}

impl IntentTiers {
    /// Capture T0 + T1 from a single annotated statement.
    ///
    /// Parses the `/* intent: … ticket: … actor: … */` annotation out of the
    /// SQL, derives the statement class, and records the role and (optional)
    /// `application_name`. T2 is left empty — it is built up across the session
    /// by the proxy and is not derivable from one statement.
    pub fn from_statement(
        role: impl Into<String>,
        statement_text: impl Into<String>,
        application_name: Option<String>,
    ) -> Self {
        let statement_text = statement_text.into();
        let annotation = parse_intent_annotation(&statement_text);
        let statement_class = statement_class(&statement_text);
        IntentTiers {
            t0: TierT0 {
                role: role.into(),
                purpose: None,
            },
            t1: TierT1 {
                statement_text,
                statement_class,
                application_name,
                gucs: BTreeMap::new(),
                annotation,
            },
            t2: TierT2::default(),
        }
    }
}

/// Derive a coarse statement class from the leading SQL keyword.
///
/// Skips a leading `/* … */` block comment and leading whitespace, then reads
/// the first word. Returns `None` if no keyword can be found.
pub fn statement_class(sql: &str) -> Option<String> {
    let trimmed = strip_leading_comments(sql).trim_start();
    let word: String = trimmed
        .chars()
        .take_while(|c| c.is_ascii_alphabetic())
        .collect();
    if word.is_empty() {
        None
    } else {
        Some(word.to_ascii_uppercase())
    }
}

/// Remove leading `/* … */` block comments (and surrounding whitespace) so the
/// statement keyword can be read. Best-effort; only strips from the front.
fn strip_leading_comments(sql: &str) -> &str {
    let mut rest = sql.trim_start();
    while let Some(after_open) = rest.strip_prefix("/*") {
        match after_open.find("*/") {
            Some(end) => rest = after_open[end + 2..].trim_start(),
            // Unterminated comment — nothing useful follows.
            None => return "",
        }
    }
    rest
}

/// Parse the **first** `/* intent: … ticket: … actor: … */` annotation in `sql`.
///
/// The annotation is a single block comment whose body contains `key: value`
/// fields. Field values run to the next recognized key or the end of the
/// comment. Recognized keys: `intent`, `ticket`, `actor` (case-insensitive).
/// Unrecognized comments / fields are ignored (best-effort; never errors).
pub fn parse_intent_annotation(sql: &str) -> IntentAnnotation {
    let mut out = IntentAnnotation::default();

    // Scan every block comment; use the first one that carries an `intent:`,
    // `ticket:`, or `actor:` field. (Other comments are ignored.)
    let mut haystack = sql;
    while let Some(open) = haystack.find("/*") {
        let after_open = &haystack[open + 2..];
        let Some(close) = after_open.find("*/") else {
            break;
        };
        let body = &after_open[..close];
        let parsed = parse_annotation_body(body);
        if !parsed.is_empty() {
            return parsed;
        }
        haystack = &after_open[close + 2..];
    }
    // No annotated comment found.
    out.intent = None;
    out
}

/// Recognized annotation keys, in the order we scan for them.
const ANNOTATION_KEYS: [&str; 3] = ["intent", "ticket", "actor"];

/// Parse the body of a single block comment into an [`IntentAnnotation`].
///
/// Splits the body into `key: value` spans. A value extends from after its
/// `key:` to the start of the next recognized `key:` (or end of body), then is
/// trimmed of whitespace and a trailing separator.
fn parse_annotation_body(body: &str) -> IntentAnnotation {
    // Collect (key, byte-offset-of-value-start) for each recognized key found.
    let lower = body.to_ascii_lowercase();
    let mut hits: Vec<(usize, &'static str, usize)> = Vec::new();
    for key in ANNOTATION_KEYS {
        let mut search_from = 0;
        let pat = format!("{key}:");
        while let Some(rel) = lower[search_from..].find(&pat) {
            let key_pos = search_from + rel;
            let value_start = key_pos + pat.len();
            hits.push((key_pos, key, value_start));
            search_from = value_start;
        }
    }
    // Order by position so each value runs to the next key's position.
    hits.sort_by_key(|(pos, _, _)| *pos);

    let mut out = IntentAnnotation::default();
    for (i, (_pos, key, value_start)) in hits.iter().enumerate() {
        let value_end = hits
            .get(i + 1)
            .map(|(next_pos, _, _)| *next_pos)
            .unwrap_or(body.len());
        if *value_start > value_end {
            continue;
        }
        let value = body[*value_start..value_end]
            .trim()
            .trim_end_matches([',', ';'])
            .trim()
            .to_string();
        if value.is_empty() {
            continue;
        }
        match *key {
            "intent" if out.intent.is_none() => out.intent = Some(value),
            "ticket" if out.ticket.is_none() => out.ticket = Some(value),
            "actor" if out.actor.is_none() => out.actor = Some(value),
            _ => {}
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_sample_annotated_statement_into_tiers() {
        let sql = "/* intent: fix duplicate order ticket: JIRA-4821 actor: claude-code */ \
                   UPDATE public.orders SET status='fixed' WHERE id=42";
        let tiers =
            IntentTiers::from_statement("app_writer", sql, Some("anthropic-mcp".to_string()));

        // T0
        assert_eq!(tiers.t0.role, "app_writer");
        // T1 — annotation parsed, class derived, application_name captured.
        assert_eq!(
            tiers.t1.annotation.intent.as_deref(),
            Some("fix duplicate order")
        );
        assert_eq!(tiers.t1.annotation.ticket.as_deref(), Some("JIRA-4821"));
        assert_eq!(tiers.t1.annotation.actor.as_deref(), Some("claude-code"));
        assert_eq!(tiers.t1.statement_class.as_deref(), Some("UPDATE"));
        assert_eq!(tiers.t1.application_name.as_deref(), Some("anthropic-mcp"));
        assert_eq!(tiers.t1.statement_text, sql);
        // T2 is not derivable from a single statement.
        assert!(tiers.t2.query_sequence.is_empty());
    }

    #[test]
    fn statement_class_skips_leading_comment() {
        assert_eq!(
            statement_class("/* intent: x */ delete from t").as_deref(),
            Some("DELETE")
        );
        assert_eq!(statement_class("  select 1").as_deref(), Some("SELECT"));
        assert_eq!(statement_class("/* unterminated").as_deref(), None);
    }

    #[test]
    fn annotation_fields_can_appear_in_any_order() {
        let a = parse_intent_annotation("/* actor: bot ticket: T-1 intent: backfill */ SELECT 1");
        assert_eq!(a.intent.as_deref(), Some("backfill"));
        assert_eq!(a.ticket.as_deref(), Some("T-1"));
        assert_eq!(a.actor.as_deref(), Some("bot"));
    }

    #[test]
    fn missing_or_malformed_annotation_yields_empty_not_error() {
        // No annotation at all.
        assert!(parse_intent_annotation("SELECT 1").is_empty());
        // A comment with no recognized fields.
        assert!(parse_intent_annotation("/* just a note */ SELECT 1").is_empty());
        // Unterminated comment — best-effort, no panic, empty.
        assert!(parse_intent_annotation("/* intent: x").is_empty());
    }

    #[test]
    fn case_insensitive_keys() {
        let a = parse_intent_annotation("/* INTENT: hello TICKET: ABC */ select 1");
        assert_eq!(a.intent.as_deref(), Some("hello"));
        assert_eq!(a.ticket.as_deref(), Some("ABC"));
    }

    #[test]
    fn intent_tiers_round_trip_through_serde() {
        let sql = "/* intent: backfill ticket: OPS-9 actor: migrator */ \
                   UPDATE t SET x=1";
        let mut tiers = IntentTiers::from_statement("migration", sql, Some("psql".to_string()));
        // Populate T2 so the round-trip exercises every tier.
        tiers
            .t1
            .gucs
            .insert("pg_brakes.trace_id".to_string(), "trace-123".to_string());
        tiers.t2 = TierT2 {
            query_sequence: vec![
                ObservedStep {
                    class: "SELECT".to_string(),
                    tables: vec!["public.t".to_string()],
                    at_monotonic_millis: 1_000,
                },
                ObservedStep {
                    class: "UPDATE".to_string(),
                    tables: vec!["public.t".to_string()],
                    at_monotonic_millis: 1_500,
                },
            ],
            reads_before_write: true,
            rate_per_min: Some(12.0),
            tables: vec!["public.t".to_string()],
        };

        let json = serde_json::to_string_pretty(&tiers).unwrap();
        let back: IntentTiers = serde_json::from_str(&json).unwrap();
        assert_eq!(tiers, back, "intent tiers must round-trip exactly");
        // The trace_id GUC survived.
        assert_eq!(back.t1.gucs["pg_brakes.trace_id"], "trace-123");
        assert!(back.t2.reads_before_write);
    }

    #[test]
    fn empty_tiers_serialize_minimally() {
        // A default record should not emit a wall of nulls/empties; skip_*
        // keeps the logged JSON small.
        let tiers = IntentTiers::default();
        let json = serde_json::to_string(&tiers).unwrap();
        // No optional fields present.
        assert!(!json.contains("query_sequence"), "{json}");
        assert!(!json.contains("application_name"), "{json}");
    }
}
