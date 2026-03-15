//! # Scrub Pipeline
//!
//! Wires together the three Airlock features in a single end-to-end pass:
//!
//! 1. **Parallel NER scan** (Rayon) — collect all PII tokens from every entry
//! 2. **Sequential alias assignment** — deterministic mapping with optional
//!    cross-run stability via [`AliasMode::Seeded`]
//! 3. **Parallel alias application** (Rayon) — rewrite each entry concurrently
//! 4. **Token-Tax compression** — extract schema header, compact rows
//! 5. **Risk Ledger** — persist stats to the local SQLite audit database

use std::collections::HashMap;
use std::path::PathBuf;

use anyhow::Result;
use chrono::Utc;
use rayon::prelude::*;
use serde_json::Value;
use tracing::{debug, info};

use crate::{
    compress::{self, CompressResult},
    ledger::Ledger,
    ner::{Ner, RegexNer},
    types::{EntityType, LedgerEntry, SwapRecord},
};

// ── Alias Mode ────────────────────────────────────────────────────────────────

/// Controls whether [`AliasEngine`] assigns aliases sequentially or from a seed.
#[derive(Debug, Clone)]
pub enum AliasMode {
    /// Assigns aliases in first-encounter order: `User_A`, `User_B`, …
    Sequential,

    /// Derives each alias deterministically from `SHA-256(salt ‖ entity_prefix ‖ token)`.
    ///
    /// The same real identity maps to the same alias in every run, regardless
    /// of file order — provided the same `salt` is supplied.  Keep it secret.
    Seeded { salt: String },
}

// ── Alias Engine ──────────────────────────────────────────────────────────────

/// Maps real PII tokens to consistent synthetic aliases within a processing session.
pub struct AliasEngine {
    map: HashMap<String, String>,
    counters: HashMap<EntityType, usize>,
    mode: AliasMode,
}

impl AliasEngine {
    pub fn new(mode: AliasMode) -> Self {
        Self { map: HashMap::new(), counters: HashMap::new(), mode }
    }

    /// Register `token` (if not already seen) and assign it the next alias.
    pub fn register(&mut self, entity: &EntityType, token: &str) {
        if self.map.contains_key(token) {
            return;
        }
        let alias = match &self.mode {
            AliasMode::Sequential => self.next_sequential_alias(entity),
            AliasMode::Seeded { salt } => seeded_alias(salt, entity, token),
        };
        self.map.insert(token.to_owned(), alias);
    }

    /// Return the alias for `token`, or `None` if it was never registered.
    pub fn get(&self, token: &str) -> Option<&str> {
        self.map.get(token).map(String::as_str)
    }

    /// Return a snapshot of unique alias counts per entity type.
    ///
    /// In [`AliasMode::Sequential`] this reflects every alias assigned.
    /// In [`AliasMode::Seeded`] counters are not incremented, so the map is empty.
    pub fn alias_counts(&self) -> HashMap<EntityType, usize> {
        self.counters.clone()
    }

    /// Apply the alias map to a JSON value tree in-place.
    pub fn apply_to_value(&self, value: &mut Value, ner: &dyn Ner) -> Vec<SwapRecord> {
        let mut records = Vec::new();
        apply_recursive(value, self, ner, &mut records);
        records
    }

    fn next_sequential_alias(&mut self, entity: &EntityType) -> String {
        let count = self.counters.entry(entity.clone()).or_insert(0);
        let label = counter_to_label(*count);
        *count += 1;
        match entity {
            EntityType::Email => format!("alias_{}@redacted.dev", label.to_lowercase()),
            _ => format!("{}_{label}", entity.alias_prefix()),
        }
    }
}

// ── Stable-Seed Alias Derivation ──────────────────────────────────────────────

/// Derive a stable, cross-run alias from `SHA-256(salt NUL entity_prefix NUL token)`.
fn seeded_alias(salt: &str, entity: &EntityType, token: &str) -> String {
    use rand::Rng;
    use rand::SeedableRng;
    use rand_chacha::ChaCha8Rng;
    use sha2::{Digest, Sha256};

    // Use stable string keys for Name/Email to preserve backward compatibility
    // with aliases generated before v0.3.0.
    let prefix_key = match entity {
        EntityType::Name  => "name".to_string(),
        EntityType::Email => "email".to_string(),
        _                 => entity.alias_prefix().to_lowercase(),
    };

    let mut hasher = Sha256::new();
    hasher.update(salt.as_bytes());
    hasher.update(b"\x00");
    hasher.update(prefix_key.as_bytes());
    hasher.update(b"\x00");
    hasher.update(token.as_bytes());
    let seed: [u8; 32] = hasher.finalize().into();

    let mut rng = ChaCha8Rng::from_seed(seed);
    let label: String = (0..4).map(|_| (b'A' + rng.gen_range(0u8..26)) as char).collect();

    match entity {
        EntityType::Email => format!("alias_{}@redacted.dev", label.to_lowercase()),
        _ => format!("{}_{label}", entity.alias_prefix()),
    }
}

// ── Recursive alias application ───────────────────────────────────────────────

fn apply_recursive(
    value: &mut Value,
    engine: &AliasEngine,
    ner: &dyn Ner,
    records: &mut Vec<SwapRecord>,
) {
    match value {
        Value::String(s) => {
            let spans = ner.find_spans(s.as_str());
            if spans.is_empty() {
                return;
            }
            let mut out = String::with_capacity(s.len());
            let mut cursor = 0usize;
            for span in &spans {
                out.push_str(&s[cursor..span.start]);
                if let Some(alias) = engine.get(&span.text) {
                    records.push(SwapRecord {
                        entity_type: span.entity_type.to_string(),
                        original: span.text.clone(),
                        synthetic: alias.to_owned(),
                    });
                    out.push_str(alias);
                } else {
                    out.push_str(&s[span.start..span.end]);
                }
                cursor = span.end;
            }
            out.push_str(&s[cursor..]);
            *s = out;
        }
        Value::Array(arr) => {
            for item in arr.iter_mut() {
                apply_recursive(item, engine, ner, records);
            }
        }
        Value::Object(map) => {
            for val in map.values_mut() {
                apply_recursive(val, engine, ner, records);
            }
        }
        _ => {}
    }
}

// ── PII collection ────────────────────────────────────────────────────────────

/// Recursively collect all PII spans from a JSON value tree.
pub fn collect_pii(value: &Value, ner: &dyn Ner) -> Vec<(EntityType, String)> {
    let mut out = Vec::new();
    collect_pii_rec(value, ner, &mut out);
    out
}

fn collect_pii_rec(value: &Value, ner: &dyn Ner, out: &mut Vec<(EntityType, String)>) {
    match value {
        Value::String(s) => {
            for span in ner.find_spans(s.as_str()) {
                out.push((span.entity_type, span.text));
            }
        }
        Value::Array(arr) => arr.iter().for_each(|v| collect_pii_rec(v, ner, out)),
        Value::Object(map) => map.values().for_each(|v| collect_pii_rec(v, ner, out)),
        _ => {}
    }
}

// ── Public types ──────────────────────────────────────────────────────────────

/// Configuration for a single [`scrub`] invocation.
pub struct ScrubConfig {
    /// Path to the SQLite Risk Ledger. `None` skips ledger persistence entirely.
    pub db_path: Option<PathBuf>,
    /// Human-readable source label stored in the ledger.
    pub source_path: String,
    /// Alias assignment strategy.
    pub alias_mode: AliasMode,
    /// Custom NER implementation. `None` uses [`RegexNer::default()`].
    pub ner: Option<Box<dyn Ner>>,
}

/// The complete output of a successful [`scrub`] run.
pub struct ScrubResult {
    pub compressed: CompressResult,
    /// `None` when `ScrubConfig::db_path` was `None`.
    pub ledger_id: Option<i64>,
    pub total_pii: usize,
    /// Unique aliases assigned per entity type (empty in seeded mode).
    pub alias_counts: HashMap<EntityType, usize>,
    pub all_records: Vec<SwapRecord>,
}

// ── Pipeline ──────────────────────────────────────────────────────────────────

/// Run the complete Airlock scrub pipeline on `raw_json`.
pub fn scrub(raw_json: &str, config: ScrubConfig) -> Result<ScrubResult> {
    let entries: Vec<Value> =
        serde_json::from_str(raw_json).map_err(|e| anyhow::anyhow!("Invalid JSON: {e}"))?;

    info!("Scrubbing {} log entries", entries.len());

    let ner: Box<dyn Ner> =
        config.ner.unwrap_or_else(|| Box::new(RegexNer::default()));

    // Phase 1: Parallel NER scan.
    let per_entry_tokens: Vec<Vec<(EntityType, String)>> =
        entries.par_iter().map(|entry| collect_pii(entry, ner.as_ref())).collect();

    // Phase 2: Sequential alias assignment.
    let mut alias_engine = AliasEngine::new(config.alias_mode);
    let mut total_pii = 0usize;
    for tokens in &per_entry_tokens {
        for (entity, token) in tokens {
            alias_engine.register(entity, token);
            total_pii += 1;
        }
    }
    let alias_counts = alias_engine.alias_counts();
    debug!("{} total PII instances, alias counts: {:?}", total_pii, alias_counts);

    // Phase 3: Parallel alias application.
    let results: Vec<(Value, Vec<SwapRecord>)> = entries
        .into_par_iter()
        .map(|mut entry| {
            let records = alias_engine.apply_to_value(&mut entry, ner.as_ref());
            (entry, records)
        })
        .collect();

    let (redacted, swap_vecs): (Vec<Value>, Vec<Vec<SwapRecord>>) = results.into_iter().unzip();
    let all_records: Vec<SwapRecord> = swap_vecs.into_iter().flatten().collect();

    // Phase 4: Token-Tax compression.
    let compressed = compress::compress(&redacted)?;
    info!(
        "Compression: {:.1}% reduction ({} → {} tokens)",
        compressed.reduction_pct, compressed.tokens_before, compressed.tokens_after
    );

    // Phase 5: Risk score + optional ledger persistence.
    let risk_score = compute_risk(total_pii, compressed.entry_count);
    let ledger_id = if let Some(db_path) = &config.db_path {
        let entry = LedgerEntry {
            timestamp: Utc::now().to_rfc3339(),
            source_path: config.source_path,
            entry_count: compressed.entry_count,
            pii_count: total_pii,
            risk_score,
            tokens_before: compressed.tokens_before,
            tokens_after: compressed.tokens_after,
            reduction_pct: compressed.reduction_pct,
        };
        let mut ledger = Ledger::open(db_path)?;
        Some(ledger.record(&entry)?)
    } else {
        None
    };

    Ok(ScrubResult { compressed, ledger_id, total_pii, alias_counts, all_records })
}

// ── Risk score ────────────────────────────────────────────────────────────────

/// Compute a 0–100 risk score based on PII density (`pii / entries × 25`).
fn compute_risk(pii_count: usize, entry_count: usize) -> f64 {
    if entry_count == 0 {
        return 0.0;
    }
    (pii_count as f64 / entry_count as f64 * 25.0).min(100.0)
}

// ── Label helpers ─────────────────────────────────────────────────────────────

/// Convert a zero-based counter to an Excel-style label: A, B, …, Z, AA, AB, …
fn counter_to_label(n: usize) -> String {
    let mut n = n;
    let mut label = String::new();
    loop {
        label.insert(0, (b'A' + (n % 26) as u8) as char);
        if n < 26 {
            break;
        }
        n = n / 26 - 1;
    }
    label
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counter_to_label_basic() {
        assert_eq!(counter_to_label(0), "A");
        assert_eq!(counter_to_label(25), "Z");
        assert_eq!(counter_to_label(26), "AA");
        assert_eq!(counter_to_label(27), "AB");
    }

    #[test]
    fn sequential_aliases_are_consistent() {
        let mut engine = AliasEngine::new(AliasMode::Sequential);
        engine.register(&EntityType::Name, "Alice Johnson");
        engine.register(&EntityType::Name, "Bob Smith");
        engine.register(&EntityType::Name, "Alice Johnson"); // duplicate — ignored
        let counts = engine.alias_counts();
        assert_eq!(counts.get(&EntityType::Name).copied().unwrap_or(0), 2);
        assert_eq!(counts.get(&EntityType::Email).copied().unwrap_or(0), 0);
        assert_eq!(engine.get("Alice Johnson"), Some("User_A"));
        assert_eq!(engine.get("Bob Smith"), Some("User_B"));
    }

    #[test]
    fn sequential_email_aliases() {
        let mut engine = AliasEngine::new(AliasMode::Sequential);
        engine.register(&EntityType::Email, "alice@corp.com");
        engine.register(&EntityType::Email, "bob@corp.com");
        assert_eq!(engine.get("alice@corp.com"), Some("alias_a@redacted.dev"));
        assert_eq!(engine.get("bob@corp.com"), Some("alias_b@redacted.dev"));
    }

    #[test]
    fn sequential_phone_aliases() {
        let mut engine = AliasEngine::new(AliasMode::Sequential);
        engine.register(&EntityType::Phone, "555-867-5309");
        assert_eq!(engine.get("555-867-5309"), Some("Phone_A"));
        assert_eq!(engine.alias_counts().get(&EntityType::Phone).copied().unwrap_or(0), 1);
    }

    #[test]
    fn sequential_ssn_and_card_aliases() {
        let mut engine = AliasEngine::new(AliasMode::Sequential);
        engine.register(&EntityType::Ssn, "123-45-6789");
        engine.register(&EntityType::CreditCard, "4111111111111111");
        assert_eq!(engine.get("123-45-6789"), Some("SSN_A"));
        assert_eq!(engine.get("4111111111111111"), Some("Card_A"));
    }

    #[test]
    fn seeded_aliases_are_stable_across_calls() {
        let a1 = seeded_alias("mysalt", &EntityType::Name, "Alice Johnson");
        let a2 = seeded_alias("mysalt", &EntityType::Name, "Alice Johnson");
        assert_eq!(a1, a2);
        assert!(a1.starts_with("User_"), "got: {a1}");
    }

    #[test]
    fn seeded_aliases_differ_with_different_salts() {
        let a1 = seeded_alias("salt1", &EntityType::Name, "Alice Johnson");
        let a2 = seeded_alias("salt2", &EntityType::Name, "Alice Johnson");
        assert_ne!(a1, a2);
    }

    #[test]
    fn compute_risk_capped_at_100() {
        assert_eq!(compute_risk(0, 10), 0.0);
        assert_eq!(compute_risk(4, 1), 100.0);
        assert!(compute_risk(2, 10) < 100.0);
    }

    #[test]
    fn scrub_without_db_returns_none_ledger_id() {
        let config = ScrubConfig {
            db_path: None,
            source_path: "test".to_string(),
            alias_mode: AliasMode::Sequential,
            ner: None,
        };
        let result = scrub(r#"[{"msg": "hello"}]"#, config).unwrap();
        assert!(result.ledger_id.is_none());
    }
}
