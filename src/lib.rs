//! Airlock — Local-first AI Security Gateway
//!
//! This crate can be used as a Rust library, a CLI binary, or a Python extension.
//!
//! ## Rust library
//!
//! ```rust,no_run
//! use airlock::scrub::{scrub, AliasMode, ScrubConfig};
//!
//! let config = ScrubConfig {
//!     db_path: None,
//!     source_path: "my_logs".to_string(),
//!     alias_mode: AliasMode::Sequential,
//!     ner: None,
//! };
//! let result = scrub(r#"[{"user": "Alice Johnson"}]"#, config).unwrap();
//! println!("Scrubbed {} PII instances", result.total_pii);
//! ```
//!
//! ## Python (via `pip install airlock`)
//!
//! ```python
//! import airlock, json
//!
//! records = [{"user": "Alice Johnson", "email": "alice@corp.com"}]
//! result = airlock.scrub(json.dumps(records))
//! print(result.pii_count)   # 2
//! print(result.risk_score)  # 50.0
//! ```

pub mod compress;
pub mod config;
pub mod ledger;
pub mod ner;
pub mod scrub;
pub mod server;
pub mod types;

// Python extension module — only compiled with `--features python`
#[cfg(feature = "python")]
mod python;
