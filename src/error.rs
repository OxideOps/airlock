//! Library-level error types for Airlock.
//!
//! All fallible library functions return `Result<T, AirlockError>`.
//! CLI entry-points wrap these with [`anyhow`] for richer context chains.

use thiserror::Error;

/// The canonical error type for all Airlock library operations.
///
/// Consumers of the library should match on [`AirlockError`] variants to
/// provide user-friendly messages.  The CLI layer wraps these with [`anyhow`]
/// to add file-path context without losing the original cause.
#[derive(Debug, Error)]
pub enum AirlockError {
    /// The input file does not exist at the given path.
    #[error("File not found: '{path}'")]
    FileNotFound { path: String },

    /// The process lacks read permission on the input file.
    #[error("Permission denied reading '{path}'. Try: chmod +r \"{path}\"")]
    PermissionDenied { path: String },

    /// The input file exists but is not a valid JSON array of objects.
    #[error("Input is not a valid JSON array: {detail}")]
    InvalidJson { detail: String },

    /// The Risk Ledger SQLite database could not be opened or written.
    #[error("Risk Ledger error: {detail}")]
    #[allow(dead_code)]
    LedgerError { detail: String },

    /// A JSON serialisation or deserialisation error.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// A SQLite database error from rusqlite.
    #[error("Database error: {0}")]
    Sqlite(#[from] rusqlite::Error),

    /// A lower-level I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}
