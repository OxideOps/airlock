//! # Named Entity Recognition (NER)
//!
//! Detects PII spans within plain-text strings using compiled regex patterns
//! with post-match validation where standards apply.
//!
//! The public [`Ner`] trait is deliberately thin so that a real ML-backed
//! recogniser (e.g. a local ONNX model) can be swapped in without touching
//! any caller.
//!
//! ## Standards Compliance
//!
//! | Type       | Standard          | Notes                                          |
//! |------------|-------------------|------------------------------------------------|
//! | Email      | RFC 5322 (subset) | Handles 99%+ of real addresses; skips quoted locals |
//! | CreditCard | ISO/IEC 7812      | Luhn checksum validated after regex match      |
//! | SSN        | SSA format        | Filters invalid area numbers (000, 666, 900+)  |
//! | Phone      | NANP + E.164      | US/CA formats and international compact/formatted |
//! | IPv4       | RFC 791           | Octet range 0–255 validated in regex           |
//!
//! ## Detection Priority
//!
//! To avoid overlapping spans, patterns are applied in this order (highest
//! to lowest priority):
//!
//! 1. Email — prevents name false-positives inside email addresses
//! 2. CreditCard — before SSN to avoid partial 9-digit matches
//! 3. SSN — specific dash-separated format
//! 4. Phone (NANP) — US/Canada formats
//! 5. Phone (international) — E.164 compact and formatted
//! 6. IpAddress — dotted-quad notation
//! 7. Custom rules — user-defined patterns from `.airlock.toml`
//! 8. Name — last, as it is most prone to false positives

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
    // Visa (4xxx), Mastercard (5[1-5]xx), Discover (6011/65xx): 16-digit 4-4-4-4
    // Amex (3[47]xx): 15-digit 4-6-5
    RE.get_or_init(|| {
        Regex::new(
            r"\b(?:(?:4\d{3}|5[1-5]\d{2}|6(?:011|5\d{2}))[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}|3[47]\d{2}[- ]?\d{6}[- ]?\d{5})\b",
        )
        .expect("static regex is valid")
    })
}

fn ssn_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    // NNN-NN-NNNN format. Invalid area numbers (000, 666, 900-999) are filtered
    // by ssn_valid() after the match since the regex crate lacks lookahead.
    RE.get_or_init(|| Regex::new(r"\b\d{3}-\d{2}-\d{4}\b").expect("static regex is valid"))
}

fn phone_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    // NANP: (555) 867-5309, 555-867-5309, +1 555.867.5309
    // Area code starts 2-9 to reduce false positives in version numbers etc.
    RE.get_or_init(|| {
        Regex::new(r"\b(?:\+?1[\s.\-]?)?\(?[2-9]\d{2}\)?[\s.\-]\d{3}[\s.\-]\d{4}\b")
            .expect("static regex is valid")
    })
}

fn international_phone_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    // E.164 compact:    +447911123456, +14155551234
    // E.164 formatted:  +44 7911 123456, +49 30 12345678, +1 415 555 1234
    // Country code 1–4 digits; total 10–15 digits per E.164 standard.
    RE.get_or_init(|| {
        Regex::new(r"\+[1-9]\d{9,13}\b|\+[1-9]\d{0,3}[\s.\-]\d{2,9}(?:[\s.\-]\d{2,9}){0,4}\b")
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

fn jwt_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    // Three base64url segments separated by dots: header.payload.signature
    // Header and payload both decode to JSON, so they start with `eyJ` (base64 of `{"`).
    RE.get_or_init(|| {
        Regex::new(r"\beyJ[A-Za-z0-9_\-]{2,}\.eyJ[A-Za-z0-9_\-]{2,}\.[A-Za-z0-9_\-]{2,}\b")
            .expect("static regex is valid")
    })
}

fn aws_key_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    // AWS access key IDs begin with AKIA followed by 16 uppercase alphanumerics.
    RE.get_or_init(|| Regex::new(r"\bAKIA[0-9A-Z]{16}\b").expect("static regex is valid"))
}

fn env_secret_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    // Matches `KEY=value` or `key: value` where the key name strongly implies a secret.
    // The value must be at least 6 non-whitespace characters to filter out placeholders.
    RE.get_or_init(|| {
        Regex::new(
            r#"(?i)\b(?:api[_-]?key|secret(?:[_-]?key)?|private[_-]?key|password|passwd|db[_-]?pass(?:word)?|auth[_-]?token|access[_-]?token|refresh[_-]?token)\s*[=:]\s*['"]?[^\s'"]{6,}['"]?"#,
        )
        .expect("static regex is valid")
    })
}

// ── Post-match validators ─────────────────────────────────────────────────────

/// Validate a credit card number using the Luhn algorithm (ISO/IEC 7812).
///
/// Delegates to the [`luhn`] crate, which strips spaces and dashes automatically.
fn luhn_valid(s: &str) -> bool {
    luhn::valid(s)
}

/// Validate an SSN area number — rejects 000, 666, and 900-999.
///
/// The regex crate lacks lookahead, so this runs as a post-match filter.
fn ssn_valid(s: &str) -> bool {
    let area: u32 = s[..3].parse().unwrap_or(0);
    area != 0 && area != 666 && area < 900
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
/// All built-in entity types are enabled by default. Set a flag to `false` to
/// skip that detection pass entirely — useful when combined with the
/// `[redact]` section of `.airlock.toml`.
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
pub struct RegexNer {
    /// User-defined patterns added via `.airlock.toml` `[[rules]]`.
    pub custom_rules: Vec<CompiledCustomRule>,
    /// Detect full names (e.g. `Alice Johnson`). Default: `true`.
    pub names: bool,
    /// Detect email addresses. Default: `true`.
    pub emails: bool,
    /// Detect US phone numbers. Default: `true`.
    pub phones: bool,
    /// Detect Social Security Numbers. Default: `true`.
    pub ssns: bool,
    /// Detect credit card numbers. Default: `true`.
    pub credit_cards: bool,
    /// Detect IPv4 addresses. Default: `true`.
    pub ip_addresses: bool,
    /// Detect JWT tokens (three-part base64url). Default: `true`.
    pub jwt_tokens: bool,
    /// Detect AWS access key IDs (`AKIA…`). Default: `true`.
    pub aws_keys: bool,
    /// Detect secret values in `KEY=value` / `key: value` assignments. Default: `true`.
    pub env_secrets: bool,
}

impl Default for RegexNer {
    fn default() -> Self {
        Self {
            custom_rules: Vec::new(),
            names: true,
            emails: true,
            phones: true,
            ssns: true,
            credit_cards: true,
            ip_addresses: true,
            jwt_tokens: true,
            aws_keys: true,
            env_secrets: true,
        }
    }
}

impl Ner for RegexNer {
    fn find_spans(&self, text: &str) -> Vec<PiiSpan> {
        let mut spans: Vec<PiiSpan> = Vec::new();

        macro_rules! push_spans {
            ($regex:expr, $etype:expr) => {
                push_spans!($regex, $etype, |_: &str| true)
            };
            ($regex:expr, $etype:expr, $validate:expr) => {
                for m in $regex().find_iter(text) {
                    if !overlaps_existing(&spans, m.start(), m.end()) && $validate(m.as_str()) {
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
        if self.emails {
            push_spans!(email_regex, EntityType::Email);
        }
        if self.credit_cards {
            push_spans!(credit_card_regex, EntityType::CreditCard, luhn_valid);
        }
        if self.ssns {
            push_spans!(ssn_regex, EntityType::Ssn, ssn_valid);
        }
        if self.phones {
            push_spans!(phone_regex, EntityType::Phone);
            push_spans!(international_phone_regex, EntityType::Phone);
        }
        if self.ip_addresses {
            push_spans!(ipv4_regex, EntityType::IpAddress);
        }
        if self.jwt_tokens {
            push_spans!(jwt_regex, EntityType::JwtToken);
        }
        if self.aws_keys {
            push_spans!(aws_key_regex, EntityType::AwsKey);
        }
        if self.env_secrets {
            push_spans!(env_secret_regex, EntityType::EnvSecret);
        }

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
        if self.names {
            push_spans!(name_regex, EntityType::Name);
        }

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
            ..RegexNer::default()
        };
        let spans = ner.find_spans("Employee EMP-00042 logged in");
        assert_eq!(spans.len(), 1);
        match &spans[0].entity_type {
            EntityType::Custom { name, .. } => assert_eq!(name, "EmployeeId"),
            _ => panic!("expected Custom entity type"),
        }
    }

    #[test]
    fn detects_credit_card_with_dashes() {
        let ner = RegexNer::default();
        let spans = ner.find_spans("Card: 4111-1111-1111-1111");
        assert!(spans
            .iter()
            .any(|s| s.entity_type == EntityType::CreditCard));
    }

    #[test]
    fn detects_mastercard() {
        let ner = RegexNer::default();
        let spans = ner.find_spans("Paid with 5111 1111 1111 1118");
        assert!(spans
            .iter()
            .any(|s| s.entity_type == EntityType::CreditCard));
    }

    #[test]
    fn detects_amex() {
        let ner = RegexNer::default();
        let spans = ner.find_spans("Amex: 3714 496353 98431");
        assert!(spans
            .iter()
            .any(|s| s.entity_type == EntityType::CreditCard));
    }

    #[test]
    fn detects_phone_with_parens() {
        let ner = RegexNer::default();
        let spans = ner.find_spans("Call (555) 867-5309 now");
        assert!(spans.iter().any(|s| s.entity_type == EntityType::Phone));
    }

    #[test]
    fn detects_phone_with_country_code() {
        let ner = RegexNer::default();
        let spans = ner.find_spans("Reach me at +1 555-867-5309");
        assert!(spans.iter().any(|s| s.entity_type == EntityType::Phone));
    }

    #[test]
    fn each_redact_toggle_suppresses_only_its_type() {
        let text =
            "Alice Johnson alice@corp.com 555-867-5309 123-45-6789 4111 1111 1111 1111 192.168.1.1";
        let types = [
            (
                EntityType::Name,
                RegexNer {
                    names: false,
                    ..RegexNer::default()
                },
            ),
            (
                EntityType::Email,
                RegexNer {
                    emails: false,
                    ..RegexNer::default()
                },
            ),
            (
                EntityType::Phone,
                RegexNer {
                    phones: false,
                    ..RegexNer::default()
                },
            ),
            (
                EntityType::Ssn,
                RegexNer {
                    ssns: false,
                    ..RegexNer::default()
                },
            ),
            (
                EntityType::CreditCard,
                RegexNer {
                    credit_cards: false,
                    ..RegexNer::default()
                },
            ),
            (
                EntityType::IpAddress,
                RegexNer {
                    ip_addresses: false,
                    ..RegexNer::default()
                },
            ),
        ];
        for (suppressed, ner) in &types {
            let spans = ner.find_spans(text);
            assert!(
                spans.iter().all(|s| &s.entity_type != suppressed),
                "{suppressed:?} should be suppressed but was detected"
            );
        }
    }

    #[test]
    fn redact_toggles_suppress_detection() {
        let ner = RegexNer {
            ip_addresses: false,
            emails: false,
            ..RegexNer::default()
        };
        // Neither email nor IP should be detected
        let spans = ner.find_spans("Alice Johnson logged in from 192.168.1.1 via alice@corp.com");
        assert!(spans.iter().all(|s| s.entity_type != EntityType::Email));
        assert!(spans.iter().all(|s| s.entity_type != EntityType::IpAddress));
        // Names should still be detected
        assert!(spans.iter().any(|s| s.entity_type == EntityType::Name));
    }

    #[test]
    fn luhn_rejects_invalid_card_number() {
        // 4111 1111 1111 1112 — last digit changed, Luhn fails
        assert!(!luhn_valid("4111111111111112"));
        assert!(!luhn_valid("1234567890123456"));
    }

    #[test]
    fn luhn_accepts_valid_card_numbers() {
        assert!(luhn_valid("4111111111111111")); // Visa test card
        assert!(luhn_valid("5500005555555559")); // Mastercard test card
        assert!(luhn_valid("371449635398431")); // Amex test card
    }

    #[test]
    fn invalid_card_shape_not_detected() {
        let ner = RegexNer::default();
        // Matches card pattern but fails Luhn
        let spans = ner.find_spans("4111 1111 1111 1112");
        assert!(spans
            .iter()
            .all(|s| s.entity_type != EntityType::CreditCard));
    }

    #[test]
    fn ssn_rejects_invalid_area_numbers() {
        assert!(!ssn_valid("000-12-3456")); // area 000
        assert!(!ssn_valid("666-12-3456")); // area 666
        assert!(!ssn_valid("900-12-3456")); // area 900+
        assert!(!ssn_valid("999-12-3456")); // area 999
    }

    #[test]
    fn ssn_accepts_valid_area_numbers() {
        assert!(ssn_valid("123-45-6789"));
        assert!(ssn_valid("001-01-0001")); // area 001 is valid
    }

    #[test]
    fn invalid_ssn_area_not_detected() {
        let ner = RegexNer::default();
        let spans = ner.find_spans("SSN: 000-12-3456");
        assert!(spans.iter().all(|s| s.entity_type != EntityType::Ssn));
        let spans = ner.find_spans("SSN: 666-12-3456");
        assert!(spans.iter().all(|s| s.entity_type != EntityType::Ssn));
    }

    #[test]
    fn detects_international_phone_compact_e164() {
        let ner = RegexNer::default();
        assert!(ner
            .find_spans("Call +447911123456 now")
            .iter()
            .any(|s| s.entity_type == EntityType::Phone));
        assert!(ner
            .find_spans("Reach +14155551234 here")
            .iter()
            .any(|s| s.entity_type == EntityType::Phone));
    }

    #[test]
    fn detects_international_phone_formatted() {
        let ner = RegexNer::default();
        assert!(ner
            .find_spans("+44 7911 123456")
            .iter()
            .any(|s| s.entity_type == EntityType::Phone));
        assert!(ner
            .find_spans("+49 30 12345678")
            .iter()
            .any(|s| s.entity_type == EntityType::Phone));
    }

    #[test]
    fn detects_jwt_token() {
        let ner = RegexNer::default();
        let jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        let spans = ner.find_spans(&format!("Authorization: Bearer {jwt}"));
        assert!(spans.iter().any(|s| s.entity_type == EntityType::JwtToken));
    }

    #[test]
    fn detects_aws_access_key() {
        let ner = RegexNer::default();
        let spans = ner.find_spans("Using key AKIAIOSFODNN7EXAMPLE for request");
        assert!(spans.iter().any(|s| s.entity_type == EntityType::AwsKey));
    }

    #[test]
    fn detects_env_secret_equals() {
        let ner = RegexNer::default();
        let spans = ner.find_spans("API_KEY=sk-abc123def456");
        assert!(spans.iter().any(|s| s.entity_type == EntityType::EnvSecret));
    }

    #[test]
    fn detects_env_secret_colon() {
        let ner = RegexNer::default();
        let spans = ner.find_spans("password: supersecretvalue");
        assert!(spans.iter().any(|s| s.entity_type == EntityType::EnvSecret));
    }

    #[test]
    fn env_secret_ignores_short_values() {
        let ner = RegexNer::default();
        // Value "abc" is only 3 chars — below the 6-char minimum
        let spans = ner.find_spans("password=abc");
        assert!(spans.iter().all(|s| s.entity_type != EntityType::EnvSecret));
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
