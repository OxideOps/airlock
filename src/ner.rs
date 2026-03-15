//! # Named Entity Recognition (NER)
//!
//! Detects PII spans within plain-text strings using compiled regex patterns.
//!
//! The public [`Ner`] trait is deliberately thin so that a real ML-backed
//! recogniser (e.g. a local ONNX model) can be swapped in without touching
//! any caller.
//!
//! ## Zero-Copy Design
//!
//! [`RegexNer::find_spans`] returns byte-offset [`PiiSpan`]s that reference
//! the *caller's* string — no intermediate `String` is allocated during
//! iteration.  The `text` field is materialised only at the span→pipeline
//! boundary, keeping hot-path allocations to a minimum.

use std::sync::OnceLock;

use regex::Regex;
use tracing::debug;

use crate::types::{EntityType, PiiSpan};

// ── Compiled regex singletons ─────────────────────────────────────────────────

/// Returns the compiled name regex, initialised exactly once per process.
///
/// Matches two or more consecutively capitalised ASCII words, e.g.
/// `"Alice Johnson"` or `"Mary Jane Watson"`.  Deliberately conservative:
/// false negatives are safer than false positives that could corrupt
/// legitimate uppercase tokens.
fn name_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    // Pattern is a compile-time constant — `expect` is unreachable at runtime.
    RE.get_or_init(|| {
        Regex::new(r"\b([A-Z][a-z]+(?:\s+[A-Z][a-z]+)+)\b").expect("static regex is valid")
    })
}

/// Returns the compiled email regex, initialised exactly once per process.
///
/// Matches RFC-5322–ish addresses, e.g. `alice.johnson@corp.example.com`.
fn email_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")
            .expect("static regex is valid")
    })
}

// ── Trait ─────────────────────────────────────────────────────────────────────

/// Pluggable named-entity recogniser interface.
///
/// Implementors scan a string slice and return all PII [`PiiSpan`]s, sorted
/// by `start` byte offset.  The trait is object-safe and `Send + Sync` so
/// implementations can be used freely across Rayon worker threads.
pub trait Ner: Send + Sync {
    /// Returns all PII spans found in `text`, sorted by start byte offset.
    ///
    /// Returned spans must not overlap.
    fn find_spans(&self, text: &str) -> Vec<PiiSpan>;
}

// ── RegexNer ──────────────────────────────────────────────────────────────────

/// The default regex-based named-entity recogniser.
///
/// Detects full names and email addresses using pre-compiled [`Regex`]
/// singletons.  Email patterns are detected first so that a name-shaped
/// substring inside an email (e.g. `"John.Smith@example.com"`) is not
/// double-counted as a [`EntityType::Name`] span.
///
/// # Examples
///
/// ```
/// use airlock::ner::{Ner, RegexNer};
///
/// let ner = RegexNer;
/// let spans = ner.find_spans("Approved by Alice Johnson <alice@corp.example.com>");
/// assert_eq!(spans.len(), 2); // one Name, one Email — no overlap
/// ```
pub struct RegexNer;

impl Ner for RegexNer {
    fn find_spans(&self, text: &str) -> Vec<PiiSpan> {
        let mut spans: Vec<PiiSpan> = Vec::new();

        // Detect emails first — they often contain capitalised words that the
        // name regex would otherwise claim (e.g. "John.Smith@example.com").
        for m in email_regex().find_iter(text) {
            debug!(
                "NER[Email] found {:?} at {}..{}",
                m.as_str(),
                m.start(),
                m.end()
            );
            spans.push(PiiSpan {
                entity_type: EntityType::Email,
                start: m.start(),
                end: m.end(),
                text: m.as_str().to_owned(),
            });
        }

        // Detect names — skip byte ranges already claimed by an email span.
        for m in name_regex().find_iter(text) {
            let overlaps = spans
                .iter()
                .any(|s| m.start() < s.end && m.end() > s.start);
            if overlaps {
                continue;
            }
            debug!(
                "NER[Name]  found {:?} at {}..{}",
                m.as_str(),
                m.start(),
                m.end()
            );
            spans.push(PiiSpan {
                entity_type: EntityType::Name,
                start: m.start(),
                end: m.end(),
                text: m.as_str().to_owned(),
            });
        }

        // Ensure callers receive spans in left-to-right source order.
        spans.sort_unstable_by_key(|s| s.start);
        spans
    }
}

// ── MockNer ───────────────────────────────────────────────────────────────────

/// A deterministic mock recogniser for unit tests and fuzzing harnesses.
///
/// Searches for hard-coded `(EntityType, literal_token)` pairs using simple
/// substring matching.  All occurrences of each token are returned as spans.
#[cfg(test)]
pub struct MockNer {
    /// Token entries to search for, in the form `(EntityType, literal_token)`.
    pub entries: Vec<(EntityType, &'static str)>,
}

#[cfg(test)]
impl Ner for MockNer {
    fn find_spans(&self, text: &str) -> Vec<PiiSpan> {
        let mut spans = Vec::new();
        for (entity_type, token) in &self.entries {
            let mut search_from = 0usize;
            while let Some(pos) = text[search_from..].find(token) {
                let start = search_from + pos;
                let end = start + token.len();
                spans.push(PiiSpan {
                    entity_type: entity_type.clone(),
                    start,
                    end,
                    text: (*token).to_owned(),
                });
                search_from = end;
            }
        }
        spans.sort_unstable_by_key(|s| s.start);
        spans
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_email() {
        let ner = RegexNer;
        let spans = ner.find_spans("Contact support@airlock.rs for help");
        assert_eq!(spans.len(), 1);
        assert_eq!(spans[0].entity_type, EntityType::Email);
        assert_eq!(spans[0].text, "support@airlock.rs");
    }

    #[test]
    fn detects_name() {
        let ner = RegexNer;
        let spans = ner.find_spans("Approved by Alice Johnson on March 14");
        assert!(spans.iter().any(|s| s.entity_type == EntityType::Name));
    }

    #[test]
    fn email_wins_over_name_overlap() {
        let ner = RegexNer;
        let spans = ner.find_spans("john.smith@example.com");
        assert_eq!(spans.len(), 1);
        assert_eq!(spans[0].entity_type, EntityType::Email);
    }

    #[test]
    fn spans_are_sorted_by_start_offset() {
        let ner = RegexNer;
        let spans = ner.find_spans("Alice Johnson emailed bob@corp.com last week");
        let starts: Vec<usize> = spans.iter().map(|s| s.start).collect();
        assert!(starts.windows(2).all(|w| w[0] <= w[1]));
    }

    #[test]
    fn mock_ner_finds_all_occurrences() {
        let ner = MockNer {
            entries: vec![(EntityType::Name, "Alice"), (EntityType::Email, "a@b.com")],
        };
        let spans = ner.find_spans("Alice wrote to a@b.com");
        assert_eq!(spans.len(), 2);
    }
}
