//! # Scrub Pipeline
//!
//! Wires together the three Airlock Money-Maker features in a single
//! end-to-end pass:
//!
//! 1. **Parallel NER scan** (Rayon) — collect all PII tokens from every entry
//! 2. **Sequential alias assignment** — deterministic mapping with optional
//!    cross-run stability via [`AliasMode::Seeded`]
//! 3. **Parallel alias application** (Rayon) — rewrite each entry concurrently
//! 4. **Token-Tax compression** — extract schema header, compact rows
//! 5. **Risk Ledger** — persist stats to the local SQLite audit database

use std::collections::HashMap;
use std::path::Path;

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

/// Controls whether the [`AliasEngine`] assigns aliases sequentially or
/// deterministically from a cryptographic seed.
#[derive(Debug, Clone)]
pub enum AliasMode {
    /// Assigns aliases in first-encounter order: `User_A`, `User_B`, …
    ///
    /// Within a single run the same token always gets the same alias, but the
    /// assignment may differ between runs if entities appear in different order.
    Sequential,

    /// Derives each alias from `SHA-256(salt ‖ entity_prefix ‖ token)`,
    /// seeding a `ChaCha8Rng` for uniform label generation.
    ///
    /// This guarantees that the **same real identity maps to the same alias in
    /// every run**, regardless of file order or which subset of records is
    /// processed — provided the same `salt` is supplied each time.
    ///
    /// Keep the salt secret; it is the only thing preventing alias reversal.
    Seeded {
        /// A private string used as the HMAC-style key for alias derivation.
        salt: String,
    },
}

// ── Alias Engine ──────────────────────────────────────────────────────────────

/// Maps real PII tokens to consistent synthetic aliases within a processing session.
///
/// * **Names** → `User_A`, `User_B`, … (sequential) or `User_WXYZ` (seeded)
/// * **Emails** → `alias_a@redacted.dev` or `alias_wxyz@redacted.dev`
///
/// After all tokens have been [`register`]ed, the engine is read-only and safe
/// to call from multiple Rayon threads simultaneously via [`apply_to_value`].
///
/// # Examples
///
/// ```
/// use airlock::scrub::{AliasEngine, AliasMode};
/// use airlock::types::EntityType;
///
/// let mut engine = AliasEngine::new(AliasMode::Sequential);
/// engine.register(&EntityType::Name, "Alice Johnson");
/// engine.register(&EntityType::Name, "Bob Smith");
/// engine.register(&EntityType::Name, "Alice Johnson"); // duplicate — ignored
///
/// assert_eq!(engine.alias_counts(), (2, 0));
/// assert_eq!(engine.get("Alice Johnson"), Some("User_A"));
/// assert_eq!(engine.get("Bob Smith"),     Some("User_B"));
/// ```
pub struct AliasEngine {
    map: HashMap<String, String>,
    /// Counter for sequential name alias assignment.
    name_counter: usize,
    /// Counter for sequential email alias assignment.
    email_counter: usize,
    mode: AliasMode,
}

impl AliasEngine {
    /// Create a new, empty engine using the given [`AliasMode`].
    pub fn new(mode: AliasMode) -> Self {
        Self {
            map: HashMap::new(),
            name_counter: 0,
            email_counter: 0,
            mode,
        }
    }

    /// Register `token` (if not already seen) and assign it the next alias.
    ///
    /// Duplicate registrations are silently ignored — the first-seen alias wins.
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

    /// Return the `(name_aliases, email_aliases)` counts assigned so far.
    ///
    /// Only meaningful in [`AliasMode::Sequential`]; seeded mode returns `(0, 0)`.
    pub fn alias_counts(&self) -> (usize, usize) {
        (self.name_counter, self.email_counter)
    }

    /// Apply the alias map to a JSON value tree in-place.
    ///
    /// Thread-safe after the registration phase (read-only access to `self.map`).
    /// Returns every [`SwapRecord`] produced, in source order.
    pub fn apply_to_value(&self, value: &mut Value, ner: &dyn Ner) -> Vec<SwapRecord> {
        let mut records = Vec::new();
        apply_recursive(value, self, ner, &mut records);
        records
    }

    /// Assign and return the next sequential alias for `entity`.
    fn next_sequential_alias(&mut self, entity: &EntityType) -> String {
        match entity {
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
        }
    }
}

// ── Stable-Seed Alias Derivation ──────────────────────────────────────────────

/// Derive a **stable, cross-run alias** for `token` by seeding a ChaCha8 RNG
/// from `SHA-256(salt NUL entity_prefix NUL token)`.
///
/// The resulting 4-character base-26 label (`User_WXYZ` / `alias_wxyz@…`)
/// gives ~456 976 unique values, making accidental collision extremely unlikely
/// for typical enterprise datasets.
fn seeded_alias(salt: &str, entity: &EntityType, token: &str) -> String {
    use rand::Rng;
    use rand::SeedableRng;
    use rand_chacha::ChaCha8Rng;
    use sha2::{Digest, Sha256};

    let prefix = match entity {
        EntityType::Name => "name",
        EntityType::Email => "email",
    };

    // Derive a 32-byte deterministic seed: SHA-256(salt NUL prefix NUL token).
    // NUL bytes are used as separators to prevent prefix-extension collisions.
    let mut hasher = Sha256::new();
    hasher.update(salt.as_bytes());
    hasher.update(b"\x00");
    hasher.update(prefix.as_bytes());
    hasher.update(b"\x00");
    hasher.update(token.as_bytes());
    let seed: [u8; 32] = hasher.finalize().into();

    // Seed a ChaCha8 CSPRNG for uniformly distributed label characters.
    let mut rng = ChaCha8Rng::from_seed(seed);
    let label: String = (0..4)
        .map(|_| (b'A' + rng.gen_range(0u8..26)) as char)
        .collect();

    match entity {
        EntityType::Name => format!("User_{label}"),
        EntityType::Email => format!("alias_{}@redacted.dev", label.to_lowercase()),
    }
}

// ── Recursive alias application ───────────────────────────────────────────────

/// Walk a JSON value tree and replace every string containing known PII.
///
/// Replacements are made in a single left-to-right pass over each string value,
/// keeping allocations bounded to one output buffer per string node.
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
                    // Detected but not in alias map — pass through unchanged.
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
///
/// Returns `(EntityType, token_text)` pairs, including duplicate occurrences.
/// Duplicates are intentional — they are counted toward the PII density score.
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
pub struct ScrubConfig<'a> {
    /// Path to the SQLite Risk Ledger database file.
    pub db_path: &'a Path,
    /// Human-readable source label stored in the ledger (typically the input file path).
    pub source_path: String,
    /// Alias assignment strategy.  Use [`AliasMode::Seeded`] for stable cross-run aliases.
    pub alias_mode: AliasMode,
}

/// The complete output of a successful [`scrub`] run.
pub struct ScrubResult {
    /// The compressed JSON output, ready to be written to stdout.
    pub compressed: CompressResult,
    /// The auto-incremented ledger row ID assigned to this run.
    pub ledger_id: i64,
    /// Total PII instances detected (including duplicates).
    pub total_pii: usize,
    /// Number of unique name aliases assigned.
    pub name_aliases: usize,
    /// Number of unique email aliases assigned.
    pub email_aliases: usize,
    /// Flat list of every swap performed, in source order.
    pub all_records: Vec<SwapRecord>,
}

// ── Pipeline ──────────────────────────────────────────────────────────────────

/// Run the complete Airlock scrub pipeline on `raw_json`.
///
/// # Processing Phases
///
/// 1. Parse the JSON array
/// 2. **Parallel NER scan** — collect PII from all entries concurrently (Rayon)
/// 3. Sequential alias assignment — stable, deterministic encounter ordering
/// 4. **Parallel alias application** — rewrite each entry concurrently (Rayon)
/// 5. Token-Tax compression — schema extraction + row compaction
/// 6. Risk score computation + ledger persistence
///
/// # Errors
///
/// Returns an error if `raw_json` is not a JSON array,
/// or propagates ledger / compression errors.
pub fn scrub(raw_json: &str, config: ScrubConfig<'_>) -> Result<ScrubResult> {
    let entries: Vec<Value> = serde_json::from_str(raw_json).map_err(|e| {
        anyhow::anyhow!("Invalid JSON: {e}")
    })?;

    info!("Scrubbing {} log entries", entries.len());

    let ner = RegexNer;

    // Phase 1: Parallel NER scan.
    let per_entry_tokens: Vec<Vec<(EntityType, String)>> = entries
        .par_iter()
        .map(|entry| collect_pii(entry, &ner))
        .collect();

    // Phase 2: Sequential alias assignment (preserves deterministic ordering).
    let mut alias_engine = AliasEngine::new(config.alias_mode);
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

    // Phase 3: Parallel alias application (engine is now read-only).
    let results: Vec<(Value, Vec<SwapRecord>)> = entries
        .into_par_iter()
        .map(|mut entry| {
            let records = alias_engine.apply_to_value(&mut entry, &ner);
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

    // Phase 5: Risk score + ledger persistence.
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

// ── Risk score ────────────────────────────────────────────────────────────────

/// Compute a 0–100 risk score based on PII density (`pii_count / entry_count × 25`).
///
/// Four or more PII instances per entry saturates the score at 100 (CRITICAL).
fn compute_risk(pii_count: usize, entry_count: usize) -> f64 {
    if entry_count == 0 {
        return 0.0;
    }
    (pii_count as f64 / entry_count as f64 * 25.0).min(100.0)
}

// ── Alias label helpers ───────────────────────────────────────────────────────

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
        engine.register(&EntityType::Name, "Alice Johnson"); // duplicate
        assert_eq!(engine.alias_counts(), (2, 0));
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
    fn seeded_aliases_are_stable_across_calls() {
        // The same (salt, token) pair must always produce the same alias.
        let a1 = seeded_alias("mysalt", &EntityType::Name, "Alice Johnson");
        let a2 = seeded_alias("mysalt", &EntityType::Name, "Alice Johnson");
        assert_eq!(a1, a2);
        assert!(a1.starts_with("User_"), "got: {a1}");
        assert_eq!(a1.len(), "User_".len() + 4);
    }

    #[test]
    fn seeded_aliases_differ_with_different_salts() {
        let a1 = seeded_alias("salt1", &EntityType::Name, "Alice Johnson");
        let a2 = seeded_alias("salt2", &EntityType::Name, "Alice Johnson");
        // With overwhelming probability different salts yield different aliases.
        assert_ne!(a1, a2);
    }

    #[test]
    fn compute_risk_capped_at_100() {
        assert_eq!(compute_risk(0, 10), 0.0);
        assert_eq!(compute_risk(4, 1), 100.0); // 4 / 1 * 25 = 100
        assert!(compute_risk(2, 10) < 100.0);
    }
}
