//! Shared data types used across all Airlock modules.

/// Canonical PII entity categories that Airlock can detect and replace.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum EntityType {
    /// A person's full name — two or more consecutively capitalised words.
    Name,
    /// An RFC-5322-style email address.
    Email,
}

impl std::fmt::Display for EntityType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EntityType::Name => write!(f, "Name"),
            EntityType::Email => write!(f, "Email"),
        }
    }
}

/// A single detected PII span within a string value.
///
/// Byte offsets reference the *original* string, enabling a zero-copy
/// replacement pass without intermediate allocations.
#[derive(Debug, Clone)]
pub struct PiiSpan {
    /// The kind of PII entity detected.
    pub entity_type: EntityType,
    /// Inclusive start byte offset in the source string.
    pub start: usize,
    /// Exclusive end byte offset in the source string.
    pub end: usize,
    /// The matched text (one allocation per match; offsets avoid repeated
    /// substring allocations in the hot path).
    pub text: String,
}

/// Records one synthetic swap that was applied during a scrub session.
#[derive(Debug, Clone)]
pub struct SwapRecord {
    /// Human-readable entity category (e.g. `"Name"`, `"Email"`).
    pub entity_type: String,
    /// The original PII token as it appeared in the source data.
    pub original: String,
    /// The synthetic alias that replaced it.
    pub synthetic: String,
}

/// A single row written to the SQLite Risk Ledger for each `airlock scrub` run.
#[derive(Debug, Clone)]
pub struct LedgerEntry {
    /// UTC ISO-8601 timestamp of the scrub run.
    pub timestamp: String,
    /// Path to the input file that was processed.
    pub source_path: String,
    /// Number of log entries (JSON objects) in the input array.
    pub entry_count: usize,
    /// Total PII instances detected, including duplicate occurrences.
    pub pii_count: usize,
    /// Risk score in the range 0–100 derived from PII density.
    pub risk_score: f64,
    /// Approximate LLM token count before compression.
    pub tokens_before: usize,
    /// Approximate LLM token count after compression.
    pub tokens_after: usize,
    /// Percentage of tokens saved by compression.
    pub reduction_pct: f64,
}
