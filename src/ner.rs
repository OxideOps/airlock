//! NER (Named Entity Recognition) module
//!
//! Currently implemented via regex patterns.  The public [`Ner`] trait is
//! intentionally thin so that a real ML-backed recogniser (e.g. a local ONNX
//! model) can be dropped in without changing the caller.
//!
//! ## Zero-Copy Design
//! [`RegexNer::find_spans`] returns byte-offset spans referencing the
//! *caller's* string slice — it never allocates a new `String` for the match
//! text itself during iteration.  The `text` field on [`PiiSpan`] is only
//! materialised (one allocation) when the span is handed off to the synth
//! layer, keeping hot-path allocations to a minimum.

use regex::Regex;
use std::sync::OnceLock;
use tracing::debug;

use crate::types::{EntityType, PiiSpan};

// ── Compiled regexes (initialised exactly once per process) ──────────────────

/// Matches common "Full Name" patterns:
///   • Two or more capitalised words (ASCII)
///   • e.g. "John Smith", "Mary Jane Watson"
///
/// Deliberately conservative — false negatives are safer than false positives
/// which could corrupt legitimate non-PII tokens.
fn name_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"\b([A-Z][a-z]+(?:\s+[A-Z][a-z]+)+)\b").expect("static regex is valid")
    })
}

/// Matches RFC-5322–ish email addresses.
fn email_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")
            .expect("static regex is valid")
    })
}

// ── Trait definition ──────────────────────────────────────────────────────────

/// Pluggable NER interface.  Implementors scan a string and return spans.
pub trait Ner: Send + Sync {
    /// Returns all PII spans found in `text`, sorted by `start` offset.
    fn find_spans(&self, text: &str) -> Vec<PiiSpan>;
}

// ── Regex-based implementation ────────────────────────────────────────────────

/// The default regex-based recogniser.
pub struct RegexNer;

impl Ner for RegexNer {
    fn find_spans(&self, text: &str) -> Vec<PiiSpan> {
        let mut spans: Vec<PiiSpan> = Vec::new();

        // Emails first — they often contain capitalised words that the name
        // regex would also match (e.g. "John.Smith@example.com").
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
                text: m.as_str().to_owned(), // one alloc per match
            });
        }

        // Names — skip ranges already claimed by an email match.
        for m in name_regex().find_iter(text) {
            if spans.iter().any(|s| m.start() < s.end && m.end() > s.start) {
                // Overlaps with an existing email span; skip.
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

        // Sort by byte offset so the synth layer can apply replacements
        // in a single left-to-right pass.
        spans.sort_by_key(|s| s.start);
        spans
    }
}

// ── Mock NER (for testing / future ML swap-in) ────────────────────────────────

/// A deterministic mock recogniser that returns hard-coded spans.
/// Useful for unit tests or for demonstrating the swap pipeline without
/// depending on the regex engine.
#[allow(dead_code)]
pub struct MockNer {
    pub entries: Vec<(EntityType, &'static str)>,
}

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
                    text: token.to_string(),
                });
                search_from = end;
            }
        }
        spans.sort_by_key(|s| s.start);
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
        // "John.Smith" inside an email address should NOT also be a Name span.
        let spans = ner.find_spans("john.smith@example.com");
        assert_eq!(spans.len(), 1);
        assert_eq!(spans[0].entity_type, EntityType::Email);
    }

    #[test]
    fn mock_ner_finds_tokens() {
        let ner = MockNer {
            entries: vec![(EntityType::Name, "Alice"), (EntityType::Email, "a@b.com")],
        };
        let spans = ner.find_spans("Alice wrote to a@b.com");
        assert_eq!(spans.len(), 2);
    }
}
