//! # Named Entity Recognition (NER)
//!
//! Detects PII spans within plain-text strings using compiled regex patterns.
//!
//! The public [`Ner`] trait is deliberately thin so that a real ML-backed
//! recogniser (e.g. a local ONNX model) can be swapped in without touching
//! any caller.
//!
//! ## Detection Priority
//!
//! To avoid overlapping spans, patterns are applied in this order (highest
//! to lowest priority):
//!
//! 1. Email — prevents name false-positives inside email addresses
//! 2. CreditCard — before SSN to avoid partial 9-digit matches
//! 3. SSN — specific dash-separated format
//! 4. Phone — flexible US format
//! 5. IpAddress — dotted-quad notation
//! 6. Custom rules — user-defined patterns from `.airlock.toml`
//! 7. Name — last, as it is most prone to false positives

use std::sync::OnceLock;

use regex::Regex;
use tracing::debug;

use crate::types::{EntityType, PiiSpan};

// ── Static regex singletons ───────────────────────────────────────────────────

fn email_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")
            .expect("static regex is valid")
    })
}

fn credit_card_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    // Visa (4xxx), Mastercard (5[1-5]xx), Amex (3[47]xx), Discover (6011/65xx)
    RE.get_or_init(|| {
        Regex::new(
            r"\b(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2}|6(?:011|5\d{2}))[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}(?:[- ]?\d{1,3})?\b",
        )
        .expect("static regex is valid")
    })
}

fn ssn_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    // NNN-NN-NNNN format. The regex crate does not support lookahead, so we
    // match the common format and accept rare false positives (e.g. phone ext).
    RE.get_or_init(|| Regex::new(r"\b\d{3}-\d{2}-\d{4}\b").expect("static regex is valid"))
}

fn phone_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    // Common US formats: (555) 867-5309, 555-867-5309, +1 555.867.5309
    // Area code starts 2-9 to reduce false positives in version numbers etc.
    RE.get_or_init(|| {
        Regex::new(r"\b(?:\+?1[\s.\-]?)?\(?[2-9]\d{2}\)?[\s.\-]\d{3}[\s.\-]\d{4}\b")
            .expect("static regex is valid")
    })
}

fn ipv4_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    // Matches valid dotted-quad IPv4 addresses (each octet 0-255)
    RE.get_or_init(|| {
        Regex::new(
            r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b",
        )
        .expect("static regex is valid")
    })
}

fn name_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    // Two or more consecutively capitalised ASCII words (e.g. "Alice Johnson")
    RE.get_or_init(|| {
        Regex::new(r"\b([A-Z][a-z]+(?:\s+[A-Z][a-z]+)+)\b").expect("static regex is valid")
    })
}

// ── Trait ─────────────────────────────────────────────────────────────────────

/// Pluggable named-entity recogniser interface.
///
/// Implementors scan a string slice and return all PII [`PiiSpan`]s, sorted
/// by `start` byte offset with no overlapping spans.
pub trait Ner: Send + Sync {
    fn find_spans(&self, text: &str) -> Vec<PiiSpan>;
}

// ── Custom rule ───────────────────────────────────────────────────────────────

/// A compiled custom PII rule loaded from `.airlock.toml`.
pub struct CompiledCustomRule {
    pub name: String,
    pub alias_prefix: String,
    pub pattern: Regex,
}

// ── RegexNer ──────────────────────────────────────────────────────────────────

/// The default regex-based named-entity recogniser.
///
/// # Examples
///
/// ```
/// use airlock::ner::{Ner, RegexNer};
///
/// let ner = RegexNer::default();
/// let spans = ner.find_spans("Contact alice@corp.com or call 555-867-5309");
/// assert_eq!(spans.len(), 2);
/// ```
#[derive(Default)]
pub struct RegexNer {
    /// User-defined patterns added via `.airlock.toml` `[[rules]]`.
    pub custom_rules: Vec<CompiledCustomRule>,
}

impl Ner for RegexNer {
    fn find_spans(&self, text: &str) -> Vec<PiiSpan> {
        let mut spans: Vec<PiiSpan> = Vec::new();

        macro_rules! push_spans {
            ($regex:expr, $etype:expr) => {
                for m in $regex().find_iter(text) {
                    if !overlaps_existing(&spans, m.start(), m.end()) {
                        debug!(
                            "NER[{}] {:?} {}..{}",
                            $etype,
                            m.as_str(),
                            m.start(),
                            m.end()
                        );
                        spans.push(PiiSpan {
                            entity_type: $etype,
                            start: m.start(),
                            end: m.end(),
                            text: m.as_str().to_owned(),
                        });
                    }
                }
            };
        }

        // Priority order — each step skips ranges claimed by earlier passes.
        push_spans!(email_regex, EntityType::Email);
        push_spans!(credit_card_regex, EntityType::CreditCard);
        push_spans!(ssn_regex, EntityType::Ssn);
        push_spans!(phone_regex, EntityType::Phone);
        push_spans!(ipv4_regex, EntityType::IpAddress);

        // Custom rules (lower priority than built-ins)
        for rule in &self.custom_rules {
            for m in rule.pattern.find_iter(text) {
                if !overlaps_existing(&spans, m.start(), m.end()) {
                    let et = EntityType::Custom {
                        name: rule.name.clone(),
                        alias_prefix: rule.alias_prefix.clone(),
                    };
                    debug!(
                        "NER[{}] {:?} {}..{}",
                        rule.name,
                        m.as_str(),
                        m.start(),
                        m.end()
                    );
                    spans.push(PiiSpan {
                        entity_type: et,
                        start: m.start(),
                        end: m.end(),
                        text: m.as_str().to_owned(),
                    });
                }
            }
        }

        // Names last — most likely to false-positive inside other token types
        push_spans!(name_regex, EntityType::Name);

        spans.sort_unstable_by_key(|s| s.start);
        spans
    }
}

fn overlaps_existing(spans: &[PiiSpan], start: usize, end: usize) -> bool {
    spans.iter().any(|s| start < s.end && end > s.start)
}

// ── MockNer (test only) ───────────────────────────────────────────────────────

#[cfg(test)]
pub struct MockNer {
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
        let ner = RegexNer::default();
        let spans = ner.find_spans("Contact support@airlock.rs for help");
        assert_eq!(spans.len(), 1);
        assert_eq!(spans[0].entity_type, EntityType::Email);
    }

    #[test]
    fn detects_name() {
        let ner = RegexNer::default();
        let spans = ner.find_spans("Approved by Alice Johnson on March 14");
        assert!(spans.iter().any(|s| s.entity_type == EntityType::Name));
    }

    #[test]
    fn email_wins_over_name_overlap() {
        let ner = RegexNer::default();
        let spans = ner.find_spans("john.smith@example.com");
        assert_eq!(spans.len(), 1);
        assert_eq!(spans[0].entity_type, EntityType::Email);
    }

    #[test]
    fn spans_are_sorted_by_start_offset() {
        let ner = RegexNer::default();
        let spans = ner.find_spans("Alice Johnson emailed bob@corp.com last week");
        let starts: Vec<usize> = spans.iter().map(|s| s.start).collect();
        assert!(starts.windows(2).all(|w| w[0] <= w[1]));
    }

    #[test]
    fn detects_phone_us_dashes() {
        let ner = RegexNer::default();
        let spans = ner.find_spans("Call me at 555-867-5309 anytime");
        assert!(spans.iter().any(|s| s.entity_type == EntityType::Phone));
    }

    #[test]
    fn detects_ssn() {
        let ner = RegexNer::default();
        let spans = ner.find_spans("SSN: 123-45-6789");
        assert!(spans.iter().any(|s| s.entity_type == EntityType::Ssn));
    }

    #[test]
    fn detects_credit_card_visa() {
        let ner = RegexNer::default();
        let spans = ner.find_spans("Card: 4111 1111 1111 1111");
        assert!(spans
            .iter()
            .any(|s| s.entity_type == EntityType::CreditCard));
    }

    #[test]
    fn detects_ipv4() {
        let ner = RegexNer::default();
        let spans = ner.find_spans("Connected from 192.168.0.1");
        assert!(spans.iter().any(|s| s.entity_type == EntityType::IpAddress));
    }

    #[test]
    fn no_overlap_between_types() {
        let ner = RegexNer::default();
        // An email address must not also be detected as a name
        let spans = ner.find_spans("john.smith@example.com");
        assert_eq!(spans.len(), 1);
        assert_eq!(spans[0].entity_type, EntityType::Email);
    }

    #[test]
    fn custom_rule_fires() {
        let rule = CompiledCustomRule {
            name: "EmployeeId".to_string(),
            alias_prefix: "Emp".to_string(),
            pattern: Regex::new(r"\bEMP-\d{5}\b").unwrap(),
        };
        let ner = RegexNer {
            custom_rules: vec![rule],
        };
        let spans = ner.find_spans("Employee EMP-00042 logged in");
        assert_eq!(spans.len(), 1);
        match &spans[0].entity_type {
            EntityType::Custom { name, .. } => assert_eq!(name, "EmployeeId"),
            _ => panic!("expected Custom entity type"),
        }
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
