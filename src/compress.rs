//! # Token-Tax Compression
//!
//! Converts a homogeneous JSON array of log objects into a compact
//! `schema + rows` envelope, eliminating repeated key names and achieving
//! 20–60 % LLM token reductions.
//!
//! ## Output Format
//!
//! ```json
//! {
//!   "__airlock_schema": ["timestamp", "user", "action"],
//!   "__airlock_rows": [
//!     ["2024-01-01T10:00:00Z", "User_A", "login"],
//!     ["2024-01-01T10:01:00Z", "User_B", "logout"]
//!   ],
//!   "__airlock_meta": {
//!     "tokens_before": 120,
//!     "tokens_after":  68,
//!     "reduction_pct": "43.3"
//!   }
//! }
//! ```
//!
//! Keys absent from a given row are represented as JSON `null`.

use std::collections::HashSet;

use serde_json::{json, Value};

use anyhow::Result;

// ── Output type ───────────────────────────────────────────────────────────────

/// The output produced by a successful [`compress`] call.
pub struct CompressResult {
    /// The compressed JSON document — write this to stdout.
    pub output: Value,
    /// Ordered list of field names extracted into the schema header.
    pub schema: Vec<String>,
    /// Number of input log entries processed.
    pub entry_count: usize,
    /// Approximate LLM token count of the *uncompressed* input (chars / 4).
    pub tokens_before: usize,
    /// Approximate LLM token count of the *compressed* output (chars / 4).
    pub tokens_after: usize,
    /// Percentage of tokens saved: `(before − after) / before × 100`.
    pub reduction_pct: f64,
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Compress `entries` (a slice of JSON objects) into the Airlock schema+rows format.
///
/// All unique top-level keys are collected into a single `__airlock_schema`
/// header in first-encounter order.  Each entry is then reduced to a
/// positional value array aligned to that schema, with `null` for any key
/// that is absent in that row.
///
/// # Examples
///
/// ```
/// use serde_json::json;
/// use airlock::compress::compress;
///
/// let entries: Vec<serde_json::Value> = (0..10)
///     .map(|i| json!({"user": format!("User_{i}"), "action": "login"}))
///     .collect();
/// let result = compress(&entries).unwrap();
/// assert!(result.reduction_pct > 0.0);
/// assert!(result.schema.contains(&"user".to_string()));
/// ```
///
/// # Errors
///
/// Returns an error if the input values cannot be serialised.
/// In practice this is infallible for well-formed [`serde_json::Value`]s.
pub fn compress(entries: &[Value]) -> Result<CompressResult> {
    let before_str = serde_json::to_string(entries)?;
    let tokens_before = approx_tokens(before_str.len());

    let schema = extract_schema(entries);

    let rows: Vec<Value> = entries
        .iter()
        .map(|e| Value::Array(entry_to_row(e, &schema)))
        .collect();

    let mut output = json!({
        "__airlock_schema": &schema,
        "__airlock_rows":   rows,
        "__airlock_meta":   { "tokens_before": tokens_before },
    });

    let after_str = serde_json::to_string(&output)?;
    let tokens_after = approx_tokens(after_str.len());

    let reduction_pct = if tokens_before > 0 {
        tokens_before.saturating_sub(tokens_after) as f64 / tokens_before as f64 * 100.0
    } else {
        0.0
    };

    // Patch in the real numbers now that we have the final token count.
    output["__airlock_meta"] = json!({
        "tokens_before": tokens_before,
        "tokens_after":  tokens_after,
        "reduction_pct": format!("{:.1}", reduction_pct),
    });

    Ok(CompressResult {
        output,
        schema,
        entry_count: entries.len(),
        tokens_before,
        tokens_after,
        reduction_pct,
    })
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Collect all unique top-level keys from `entries` in first-encounter order.
fn extract_schema(entries: &[Value]) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut schema = Vec::new();
    for entry in entries {
        if let Value::Object(map) = entry {
            for key in map.keys() {
                if seen.insert(key.clone()) {
                    schema.push(key.clone());
                }
            }
        }
    }
    schema
}

/// Convert one entry to a positional row aligned to `schema`.
///
/// Keys absent from the entry become `null`; extra keys outside the schema
/// are silently dropped (they cannot exist after [`extract_schema`] has
/// processed all entries).
fn entry_to_row(entry: &Value, schema: &[String]) -> Vec<Value> {
    schema
        .iter()
        .map(|key| match entry {
            Value::Object(map) => map.get(key).cloned().unwrap_or(Value::Null),
            _ => Value::Null,
        })
        .collect()
}

/// Approximate LLM token count using the common `1 token ≈ 4 characters` heuristic.
#[inline]
fn approx_tokens(char_count: usize) -> usize {
    char_count.div_ceil(4)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn reduces_tokens_by_at_least_35_pct() {
        let entries: Vec<Value> = (0..20)
            .map(|i| {
                json!({
                    "timestamp":  "2024-01-14T10:00:00Z",
                    "user":       format!("User_{i}"),
                    "action":     "login",
                    "ip":         "192.168.1.1",
                    "status":     "success",
                    "session_id": format!("sess-{:04}", i),
                })
            })
            .collect();
        let result = compress(&entries).unwrap();
        assert!(
            result.reduction_pct >= 35.0,
            "Expected ≥35% reduction, got {:.1}%",
            result.reduction_pct
        );
    }

    #[test]
    fn schema_contains_all_keys() {
        let entries = vec![json!({"a": 1, "b": 2}), json!({"b": 3, "c": 4})];
        let r = compress(&entries).unwrap();
        assert!(r.schema.contains(&"a".to_string()));
        assert!(r.schema.contains(&"b".to_string()));
        assert!(r.schema.contains(&"c".to_string()));
    }

    #[test]
    fn missing_keys_become_null() {
        let entries = vec![json!({"a": 1}), json!({"b": 2})];
        let r = compress(&entries).unwrap();
        let rows = r.output["__airlock_rows"].as_array().unwrap();
        assert_eq!(rows[0][1], Value::Null); // row 0 has "a" but not "b"
        assert_eq!(rows[1][0], Value::Null); // row 1 has "b" but not "a"
    }

    #[test]
    fn empty_input_returns_zero_reduction() {
        let r = compress(&[]).unwrap();
        assert_eq!(r.entry_count, 0);
        assert_eq!(r.reduction_pct, 0.0);
    }
}
