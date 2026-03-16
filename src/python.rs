//! Python bindings for Airlock — compiled only with `--features python`.
//!
//! Exposes two functions to Python:
//!
//! - `airlock.scrub(json_input, salt=None, db_path=None)` → `ScrubOutput`
//! - `airlock.compress(json_input)` → `CompressOutput`
//!
//! Both functions accept a JSON string. Use `json.dumps(records)` in Python
//! to convert a list of dicts before passing it in.

use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};

use crate::{compress as compress_mod, scrub as scrub_mod};

// ── Python return types ───────────────────────────────────────────────────────

#[pyclass]
pub struct ScrubOutput {
    #[pyo3(get)]
    pub json_str: String,
    #[pyo3(get)]
    pub pii_count: usize,
    #[pyo3(get)]
    pub risk_score: f64,
    #[pyo3(get)]
    pub reduction_pct: f64,
    #[pyo3(get)]
    pub ledger_id: Option<i64>,
    // Stored internally; exposed via the `swaps` property below
    swaps_data: Vec<(String, String, String)>,
}

#[pymethods]
impl ScrubOutput {
    /// List of swap dicts: `[{"original": ..., "synthetic": ..., "entity_type": ...}]`
    #[getter]
    fn swaps<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyList>> {
        let list = PyList::empty_bound(py);
        for (original, synthetic, entity_type) in &self.swaps_data {
            let d = PyDict::new_bound(py);
            d.set_item("original", original)?;
            d.set_item("synthetic", synthetic)?;
            d.set_item("entity_type", entity_type)?;
            list.append(d)?;
        }
        Ok(list)
    }

    fn __repr__(&self) -> String {
        format!(
            "ScrubOutput(pii_count={}, risk_score={:.1}, reduction_pct={:.1}%)",
            self.pii_count, self.risk_score, self.reduction_pct
        )
    }
}

#[pyclass]
pub struct CompressOutput {
    #[pyo3(get)]
    pub json_str: String,
    #[pyo3(get)]
    pub tokens_before: usize,
    #[pyo3(get)]
    pub tokens_after: usize,
    #[pyo3(get)]
    pub reduction_pct: f64,
    #[pyo3(get)]
    pub entry_count: usize,
}

#[pymethods]
impl CompressOutput {
    fn __repr__(&self) -> String {
        format!(
            "CompressOutput(entry_count={}, tokens_before={}, tokens_after={}, reduction_pct={:.1}%)",
            self.entry_count, self.tokens_before, self.tokens_after, self.reduction_pct
        )
    }
}

// ── Python functions ──────────────────────────────────────────────────────────

/// Redact PII and compress a JSON array of log objects.
///
/// Args:
///     json_input: A JSON string (use `json.dumps(records)` to convert a list).
///     salt:       Optional secret string for stable cross-run aliases.
///     db_path:    Optional path to write an audit entry to the SQLite ledger.
///
/// Returns:
///     ScrubOutput with `.json_str`, `.pii_count`, `.risk_score`,
///     `.reduction_pct`, `.swaps`, and `.ledger_id`.
#[pyfunction]
#[pyo3(signature = (json_input, salt=None, db_path=None))]
fn scrub(json_input: &str, salt: Option<&str>, db_path: Option<&str>) -> PyResult<ScrubOutput> {
    use scrub_mod::{AliasMode, ScrubConfig};
    use std::path::PathBuf;

    let alias_mode = match salt {
        Some(s) => AliasMode::Seeded {
            salt: s.to_string(),
        },
        None => AliasMode::Sequential,
    };

    let config = ScrubConfig {
        db_path: db_path.map(PathBuf::from),
        source_path: "<python>".to_string(),
        alias_mode,
        ner: None,
    };

    let result = scrub_mod::scrub(json_input, config)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;

    let json_str = serde_json::to_string(&result.compressed.output)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;

    let entries = result.compressed.entry_count.max(1);
    let risk_score = (result.total_pii as f64 / entries as f64 * 25.0).min(100.0);

    let swaps_data: Vec<(String, String, String)> = result
        .all_records
        .into_iter()
        .map(|r| (r.original, r.synthetic, r.entity_type))
        .collect();

    Ok(ScrubOutput {
        json_str,
        pii_count: result.total_pii,
        risk_score,
        reduction_pct: result.compressed.reduction_pct,
        ledger_id: result.ledger_id,
        swaps_data,
    })
}

/// Compress a JSON array or NDJSON log objects without PII redaction.
///
/// Args:
///     json_input: A JSON string (use `json.dumps(records)` to convert a list)
///                 or an NDJSON string (one JSON object per line).
///
/// Returns:
///     CompressOutput with `.json_str`, `.tokens_before`, `.tokens_after`,
///     `.reduction_pct`, and `.entry_count`.
#[pyfunction]
fn compress(json_input: &str) -> PyResult<CompressOutput> {
    let entries = scrub_mod::parse_entries(json_input)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;

    let result = compress_mod::compress(&entries)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;

    let json_str = serde_json::to_string(&result.output)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;

    Ok(CompressOutput {
        json_str,
        tokens_before: result.tokens_before,
        tokens_after: result.tokens_after,
        reduction_pct: result.reduction_pct,
        entry_count: result.entry_count,
    })
}

// ── Module registration ───────────────────────────────────────────────────────

#[pymodule]
fn airlock(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    m.add_function(wrap_pyfunction!(scrub, m)?)?;
    m.add_function(wrap_pyfunction!(compress, m)?)?;
    m.add_class::<ScrubOutput>()?;
    m.add_class::<CompressOutput>()?;
    Ok(())
}
