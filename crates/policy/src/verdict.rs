//! The risk-plane verdict and its **total order** (SPEC §13/§7, §13.4 R2).
//!
//! A risk evaluation can only push an action in the *tightening* direction.
//! The vocabulary is a four-point ladder with the partial order defined in the
//! spec's R2 metamorphic relation (§13.4):
//!
//! ```text
//! ALLOW < ESCALATE < HOLD < BLOCK
//! ```
//!
//! "More restrictive" is "greater". This ordering is **load-bearing**: the R2
//! monotonicity property test (fast-follow) asserts that widening a statement's
//! scope (e.g. dropping a `WHERE`) may only move the verdict `>=`, never make it
//! safer, and the *tighten-only* contract (§11.1) is expressed as "the engine may
//! only return a verdict `>=` the deterministic floor". A real [`Ord`] makes both
//! mechanically checkable with `max`/comparison operators.

use serde::{Deserialize, Serialize};

/// A risk-plane verdict, ordered from least to most restrictive.
///
/// The discriminant order **is** the safety order — do not reorder the variants.
/// `ALLOW < ESCALATE < HOLD < BLOCK`, so `Verdict::max(a, b)` yields the more
/// restrictive of two verdicts (used to combine the floor with the engine, and
/// later to combine multiple signals).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Verdict {
    /// Permitted by the risk plane (still subject to the deterministic floor).
    /// The least restrictive verdict.
    Allow,
    /// Send to a human to decide before proceeding (medium confidence / only
    /// attacker-controllable signal present — §11.1 anti-DoS rule).
    Escalate,
    /// Hold pending approval; stronger than escalate, weaker than an outright
    /// block.
    Hold,
    /// Block outright. The most restrictive verdict.
    Block,
}

impl Verdict {
    /// The least restrictive verdict — the deterministic floor's default before
    /// any tightening is applied.
    pub const FLOOR_DEFAULT: Verdict = Verdict::Allow;

    /// The more restrictive (tighter) of two verdicts.
    ///
    /// Because the ordering is `ALLOW < ESCALATE < HOLD < BLOCK`, this is just
    /// `Ord::max`, surfaced as a named method so call sites read as intent
    /// ("combine signals, keep the tightest").
    pub fn tighter(self, other: Verdict) -> Verdict {
        core::cmp::max(self, other)
    }

    /// Whether `self` is at least as restrictive as `floor`.
    ///
    /// The *tighten-only* contract (§11.1) requires every engine verdict to
    /// satisfy `verdict >= floor`; this predicate makes that check explicit.
    pub fn is_at_least_as_tight_as(self, floor: Verdict) -> bool {
        self >= floor
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordering_is_allow_lt_escalate_lt_hold_lt_block() {
        // The exact §13.4 R2 partial order.
        assert!(Verdict::Allow < Verdict::Escalate);
        assert!(Verdict::Escalate < Verdict::Hold);
        assert!(Verdict::Hold < Verdict::Block);
        // …and transitively the extremes.
        assert!(Verdict::Allow < Verdict::Block);
    }

    #[test]
    fn sorting_yields_the_spec_ladder() {
        let mut v = vec![
            Verdict::Block,
            Verdict::Allow,
            Verdict::Hold,
            Verdict::Escalate,
        ];
        v.sort();
        assert_eq!(
            v,
            vec![
                Verdict::Allow,
                Verdict::Escalate,
                Verdict::Hold,
                Verdict::Block
            ]
        );
    }

    #[test]
    fn tighter_keeps_the_more_restrictive_verdict() {
        assert_eq!(Verdict::Allow.tighter(Verdict::Hold), Verdict::Hold);
        assert_eq!(Verdict::Block.tighter(Verdict::Escalate), Verdict::Block);
        // Commutative.
        assert_eq!(
            Verdict::Hold.tighter(Verdict::Escalate),
            Verdict::Escalate.tighter(Verdict::Hold)
        );
    }

    #[test]
    fn tighten_only_floor_check() {
        // A verdict at or above the floor is acceptable; below it is a loosen
        // (a contract violation the caller must reject).
        assert!(Verdict::Block.is_at_least_as_tight_as(Verdict::Hold));
        assert!(Verdict::Hold.is_at_least_as_tight_as(Verdict::Hold));
        assert!(!Verdict::Allow.is_at_least_as_tight_as(Verdict::Hold));
    }

    #[test]
    fn serde_round_trips_uppercase() {
        for (v, s) in [
            (Verdict::Allow, "\"ALLOW\""),
            (Verdict::Escalate, "\"ESCALATE\""),
            (Verdict::Hold, "\"HOLD\""),
            (Verdict::Block, "\"BLOCK\""),
        ] {
            assert_eq!(serde_json::to_string(&v).unwrap(), s);
            let back: Verdict = serde_json::from_str(s).unwrap();
            assert_eq!(back, v);
        }
    }
}
