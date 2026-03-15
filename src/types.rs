/// Canonical entity types that Airlock can detect and swap.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum EntityType {
    Name,
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
#[derive(Debug, Clone)]
pub struct PiiSpan {
    pub entity_type: EntityType,
    /// Byte offsets into the original string (zero-copy friendly).
    pub start: usize,
    pub end: usize,
    /// The matched text (borrowed from the source for zero-copy paths,
    /// owned here for ergonomics across the pipeline boundary).
    pub text: String,
}

/// One synthetic swap that was performed during processing.
#[derive(Debug, Clone)]
pub struct SwapRecord {
    pub entity_type: String,
    pub original: String,
    pub synthetic: String,
}

/// One row written to the SQLite Risk Ledger per `scrub` invocation.
#[derive(Debug, Clone)]
pub struct LedgerEntry {
    pub timestamp: String,
    pub source_path: String,
    pub entry_count: usize,
    /// Total PII instances detected (including duplicates).
    pub pii_count: usize,
    /// 0–100 risk score derived from PII density.
    pub risk_score: f64,
    pub tokens_before: usize,
    pub tokens_after: usize,
    pub reduction_pct: f64,
}
