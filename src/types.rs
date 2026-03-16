//! Shared data types used across all Airlock modules.

/// Canonical PII entity categories that Airlock can detect and replace.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum EntityType {
    /// A person's full name — two or more consecutively capitalised words.
    Name,
    /// An RFC-5322-style email address.
    Email,
    /// A US phone number in any common format.
    Phone,
    /// A US Social Security Number (NNN-NN-NNNN).
    Ssn,
    /// A credit/debit card number (Visa, MC, Amex, Discover).
    CreditCard,
    /// An IPv4 address in dotted-quad notation.
    IpAddress,
    /// A user-defined entity from `.airlock.toml` custom rules.
    Custom { name: String, alias_prefix: String },
}

impl EntityType {
    /// The alias prefix used when building synthetic labels.
    ///
    /// `Email` is special-cased in the alias engine to produce the
    /// `alias_x@redacted.dev` format; all other types use `{prefix}_{label}`.
    pub fn alias_prefix(&self) -> &str {
        match self {
            EntityType::Name => "User",
            EntityType::Email => "alias",
            EntityType::Phone => "Phone",
            EntityType::Ssn => "SSN",
            EntityType::CreditCard => "Card",
            EntityType::IpAddress => "IP",
            EntityType::Custom { alias_prefix, .. } => alias_prefix.as_str(),
        }
    }
}

impl std::fmt::Display for EntityType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EntityType::Name => write!(f, "Name"),
            EntityType::Email => write!(f, "Email"),
            EntityType::Phone => write!(f, "Phone"),
            EntityType::Ssn => write!(f, "SSN"),
            EntityType::CreditCard => write!(f, "CreditCard"),
            EntityType::IpAddress => write!(f, "IpAddress"),
            EntityType::Custom { name, .. } => write!(f, "{name}"),
        }
    }
}

/// A single detected PII span within a string value.
#[derive(Debug, Clone)]
pub struct PiiSpan {
    /// The category of PII detected at this span.
    pub entity_type: EntityType,
    /// Inclusive start byte offset in the source string.
    pub start: usize,
    /// Exclusive end byte offset in the source string.
    pub end: usize,
    /// The matched text (materialised once per span).
    pub text: String,
}

/// Records one synthetic swap applied during a scrub session.
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
    /// RFC-3339 timestamp of when the scrub ran.
    pub timestamp: String,
    /// The file path (or `"<python>"`) passed as the data source.
    pub source_path: String,
    /// Number of JSON/NDJSON records processed.
    pub entry_count: usize,
    /// Total PII instances detected across all entries.
    pub pii_count: usize,
    /// 0–100 risk density score: `(pii / entries × 25).min(100)`.
    pub risk_score: f64,
    /// Approximate LLM token count before compression.
    pub tokens_before: usize,
    /// Approximate LLM token count after compression.
    pub tokens_after: usize,
    /// Percentage of tokens saved: `(before − after) / before × 100`.
    pub reduction_pct: f64,
}
