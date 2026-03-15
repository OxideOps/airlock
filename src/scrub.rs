//! `scrub` pipeline — the three Money-Maker features wired together.
//!
//! Processing phases (designed for performance):
//!  1. Parse JSON array
//!  2. **Parallel NER scan** (rayon) — collect all PII tokens from every entry
//!  3. Sequential alias assignment — deterministic `User_A / alias_a` mapping
//!  4. **Parallel alias application** (rayon) — rewrite each entry concurrently
//!  5. Token-Tax compression — extract schema header, compact rows
//!  6. Risk Ledger — persist stats to local SQLite

use std::collections::HashMap;
use std::path::Path;

use anyhow::{Context, Result};
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

// ── Alias Engine ──────────────────────────────────────────────────────────────

/// Maps real PII tokens to human-readable sequential aliases.
///
/// * Names  → `User_A`, `User_B`, … `User_Z`, `User_AA`, …
/// * Emails → `alias_a@redacted.dev`, `alias_b@redacted.dev`, …
///
/// The mapping is stable within a session: the same token always gets the
/// same alias.  Registration is sequential; application is read-only and
/// safe to call from multiple rayon threads simultaneously.
pub struct AliasEngine {
    map: HashMap<String, String>,
    name_counter: usize,
    email_counter: usize,
}

impl AliasEngine {
    pub fn new() -> Self {
        Self {
            map: HashMap::new(),
            name_counter: 0,
            email_counter: 0,
        }
    }

    /// Register `token` if not already seen; assign the next alias.
    pub fn register(&mut self, entity: &EntityType, token: &str) {
        if self.map.contains_key(token) {
            return;
        }
        let alias = match entity {
            EntityType::Name => {
                let label = counter_to_label(self.name_counter);
                self.name_counter += 1;
                format!("User_{label}")
            }
            EntityType::Email => {
                let label = counter_to_label(self.email_counter).to_lowercase();
                self.email_counter += 1;
                format!("alias_{label}@redacted.dev")
            }
        };
        self.map.insert(token.to_owned(), alias);
    }

    pub fn get(&self, token: &str) -> Option<&str> {
        self.map.get(token).map(String::as_str)
    }

    /// (unique name aliases, unique email aliases)
    pub fn alias_counts(&self) -> (usize, usize) {
        (self.name_counter, self.email_counter)
    }

    /// Apply aliases to an already-parsed JSON value tree (in-place).
    /// Thread-safe: only reads from `self.map`.
    pub fn apply_to_value(&self, value: &mut Value, ner: &dyn Ner) -> Vec<SwapRecord> {
        let mut records = Vec::new();
        apply_recursive(value, self, ner, &mut records);
        records
    }
}

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
                    // Span detected but not in alias map — pass through unchanged.
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

/// Convert a zero-based counter to A, B, …, Z, AA, AB, … (Excel-style).
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

// ── Token collection ──────────────────────────────────────────────────────────

/// Recursively collect all PII spans from a JSON value tree.
/// Returns `(EntityType, token_text)` pairs (duplicates included).
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

// ── Scrub pipeline ────────────────────────────────────────────────────────────

pub struct ScrubConfig<'a> {
    pub db_path: &'a Path,
    pub source_path: String,
}

pub struct ScrubResult {
    pub compressed: CompressResult,
    pub ledger_id: i64,
    pub total_pii: usize,
    pub name_aliases: usize,
    pub email_aliases: usize,
    pub all_records: Vec<SwapRecord>,
}

pub fn scrub(raw_json: &str, config: ScrubConfig) -> Result<ScrubResult> {
    let entries: Vec<Value> =
        serde_json::from_str(raw_json).context("Input must be a JSON array of log objects")?;

    info!("Scrubbing {} log entries", entries.len());

    let ner = RegexNer;

    // ── Phase 1: Parallel NER scan ────────────────────────────────────────────
    let per_entry_tokens: Vec<Vec<(EntityType, String)>> = entries
        .par_iter()
        .map(|entry| collect_pii(entry, &ner))
        .collect();

    // ── Phase 2: Sequential alias assignment ──────────────────────────────────
    let mut alias_engine = AliasEngine::new();
    let mut total_pii = 0usize;
    for tokens in &per_entry_tokens {
        for (entity, token) in tokens {
            alias_engine.register(entity, token);
            total_pii += 1;
        }
    }
    let (name_aliases, email_aliases) = alias_engine.alias_counts();
    debug!(
        "Assigned {} name aliases, {} email aliases ({} total PII instances)",
        name_aliases, email_aliases, total_pii
    );

    // ── Phase 3: Parallel alias application ───────────────────────────────────
    // alias_engine is now read-only; AliasEngine: Sync via HashMap<String,String>
    let results: Vec<(Value, Vec<SwapRecord>)> = entries
        .into_par_iter()
        .map(|mut entry| {
            let records = alias_engine.apply_to_value(&mut entry, &ner);
            (entry, records)
        })
        .collect();

    let (redacted, swap_vecs): (Vec<Value>, Vec<Vec<SwapRecord>>) = results.into_iter().unzip();
    let all_records: Vec<SwapRecord> = swap_vecs.into_iter().flatten().collect();

    // ── Phase 4: Token-Tax compression ────────────────────────────────────────
    let compressed = compress::compress(&redacted);
    info!(
        "Compression: {:.1}% reduction ({} → {} tokens)",
        compressed.reduction_pct, compressed.tokens_before, compressed.tokens_after
    );

    // ── Phase 5: Risk score + Ledger ──────────────────────────────────────────
    let risk_score = compute_risk(total_pii, compressed.entry_count);
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
    let mut ledger = Ledger::open(config.db_path)?;
    let ledger_id = ledger.record(&entry)?;

    Ok(ScrubResult {
        compressed,
        ledger_id,
        total_pii,
        name_aliases,
        email_aliases,
        all_records,
    })
}

/// Risk score: 25 points per PII instance per entry, capped at 100.
fn compute_risk(pii_count: usize, entry_count: usize) -> f64 {
    if entry_count == 0 {
        return 0.0;
    }
    let density = pii_count as f64 / entry_count as f64;
    (density * 25.0).min(100.0)
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counter_to_label_works() {
        assert_eq!(counter_to_label(0), "A");
        assert_eq!(counter_to_label(25), "Z");
        assert_eq!(counter_to_label(26), "AA");
        assert_eq!(counter_to_label(27), "AB");
    }

    #[test]
    fn alias_engine_consistent() {
        let mut engine = AliasEngine::new();
        engine.register(&EntityType::Name, "Alice Johnson");
        engine.register(&EntityType::Name, "Bob Smith");
        engine.register(&EntityType::Name, "Alice Johnson"); // duplicate
        assert_eq!(engine.alias_counts().0, 2); // only 2 unique names
        assert_eq!(engine.get("Alice Johnson"), Some("User_A"));
        assert_eq!(engine.get("Bob Smith"), Some("User_B"));
        // same token always → same alias
        assert_eq!(engine.get("Alice Johnson"), Some("User_A"));
    }

    #[test]
    fn alias_engine_emails() {
        let mut engine = AliasEngine::new();
        engine.register(&EntityType::Email, "alice@corp.com");
        engine.register(&EntityType::Email, "bob@corp.com");
        assert_eq!(engine.get("alice@corp.com"), Some("alias_a@redacted.dev"));
        assert_eq!(engine.get("bob@corp.com"), Some("alias_b@redacted.dev"));
    }

    #[test]
    fn compute_risk_capped() {
        assert_eq!(compute_risk(0, 10), 0.0);
        assert_eq!(compute_risk(4, 1), 100.0); // 4 PII / 1 entry * 25 = 100
        assert!(compute_risk(2, 10) < 100.0);
    }
}
