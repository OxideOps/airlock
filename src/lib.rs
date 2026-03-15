//! # Airlock
//!
//! **Local-first AI security gateway** — PII redaction, token compression,
//! and audit ledger in a single Rust library.
//!
//! Airlock sits between your raw data and any AI model, ensuring sensitive
//! information never leaves your infrastructure.  All processing happens
//! in-process; no network calls are made.
//!
//! ## Feature Overview
//!
//! | Module | What it does |
//! |--------|-------------|
//! | [`scrub`] | Full pipeline: NER → alias swap → compress → ledger |
//! | [`compress`] | Token-Tax compression (schema+rows, 20–60 % savings) |
//! | [`ner`] | Named Entity Recognition (pluggable [`ner::Ner`] trait) |
//! | [`ledger`] | Local SQLite audit log of every scrub session |
//! | [`error`] | Library-level error types |
//! | [`types`] | Shared data types |
//!
//! ## Quick Example
//!
//! ```no_run
//! use airlock::scrub::{scrub, AliasMode, ScrubConfig};
//!
//! let raw = std::fs::read_to_string("logs.json").unwrap();
//! let config = ScrubConfig {
//!     db_path:    std::path::Path::new("airlock_ledger.db"),
//!     source_path: "logs.json".to_string(),
//!     alias_mode: AliasMode::Sequential,
//! };
//! let result = scrub(&raw, config).unwrap();
//! println!("Removed {} PII instances", result.total_pii);
//! println!("Token reduction: {:.1}%", result.compressed.reduction_pct);
//! ```
//!
//! ### Stable Cross-Run Aliases
//!
//! ```no_run
//! use airlock::scrub::{scrub, AliasMode, ScrubConfig};
//!
//! // "Alice Johnson" → "User_GKQT" on every run with this salt.
//! let config = ScrubConfig {
//!     db_path:    std::path::Path::new("airlock_ledger.db"),
//!     source_path: "logs.json".to_string(),
//!     alias_mode: AliasMode::Seeded { salt: "my-secret-salt".to_string() },
//! };
//! ```

pub mod compress;
pub mod error;
pub mod ledger;
pub mod ner;
pub mod scrub;
pub mod types;

// ── Convenience re-exports ────────────────────────────────────────────────────

/// The top-level error type — re-exported for ergonomic `use airlock::AirlockError`.
pub use error::AirlockError;

/// Compress a JSON log array into schema+rows format — re-exported from [`compress`].
pub use compress::compress;

/// The output of a [`compress`] call — re-exported from [`compress`].
pub use compress::CompressResult;

/// Run the full scrub pipeline — re-exported from [`scrub`].
pub use scrub::scrub;

/// Alias assignment strategy — re-exported from [`scrub`].
pub use scrub::AliasMode;

/// Full-pipeline configuration — re-exported from [`scrub`].
pub use scrub::ScrubConfig;

/// Full-pipeline output — re-exported from [`scrub`].
pub use scrub::ScrubResult;
