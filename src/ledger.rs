//! # Risk Ledger
//!
//! Maintains a local SQLite audit log of every `airlock scrub` run.
//!
//! Each row in the `sessions` table represents one invocation and captures
//! the source file, the number of PII entities found, the computed risk
//! score, and the token compression savings.  The database is created
//! automatically on first use; no migration tooling is required.

use std::path::Path;

use anyhow::{Context, Result};
use rusqlite::{params, Connection};

use crate::types::LedgerEntry;

// ── Ledger ────────────────────────────────────────────────────────────────────

/// A handle to the local SQLite Risk Ledger database.
///
/// Open the database with [`Ledger::open`], then use [`Ledger::record`] to
/// insert a new session entry and [`Ledger::recent`] to query history.
pub struct Ledger {
    conn: Connection,
}

impl Ledger {
    /// Open (or create) the ledger database at `path`.
    ///
    /// If the database does not yet exist it is created and the schema
    /// is initialised.  The call is idempotent — running it on an existing
    /// database is safe.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be created or the schema
    /// initialisation fails (e.g. the directory is not writable).
    pub fn open(path: &Path) -> Result<Self> {
        let conn = Connection::open(path)
            .with_context(|| format!("Cannot open ledger at '{}'", path.display()))?;

        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS sessions (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp     TEXT    NOT NULL,
                source_path   TEXT    NOT NULL,
                entry_count   INTEGER NOT NULL,
                pii_count     INTEGER NOT NULL,
                risk_score    REAL    NOT NULL,
                tokens_before INTEGER NOT NULL,
                tokens_after  INTEGER NOT NULL,
                reduction_pct REAL    NOT NULL
            );",
        )
        .context("Failed to initialise ledger schema")?;

        Ok(Self { conn })
    }

    /// Insert a new session record and return its auto-incremented row ID.
    ///
    /// # Errors
    ///
    /// Returns an error if the INSERT statement fails (e.g. the database
    /// file is read-only or the disk is full).
    pub fn record(&mut self, entry: &LedgerEntry) -> Result<i64> {
        self.conn
            .execute(
                "INSERT INTO sessions
                    (timestamp, source_path, entry_count, pii_count,
                     risk_score, tokens_before, tokens_after, reduction_pct)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
                params![
                    entry.timestamp,
                    entry.source_path,
                    entry.entry_count as i64,
                    entry.pii_count as i64,
                    entry.risk_score,
                    entry.tokens_before as i64,
                    entry.tokens_after as i64,
                    entry.reduction_pct,
                ],
            )
            .context("Failed to insert ledger record")?;

        Ok(self.conn.last_insert_rowid())
    }

    /// Read the `n` most recent session records, newest first.
    ///
    /// # Errors
    ///
    /// Returns an error if the SELECT statement fails.
    pub fn recent(&self, n: usize) -> Result<Vec<(i64, LedgerEntry)>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, timestamp, source_path, entry_count, pii_count,
                    risk_score, tokens_before, tokens_after, reduction_pct
             FROM sessions ORDER BY id DESC LIMIT ?1",
        )?;

        let rows = stmt
            .query_map(params![n as i64], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    LedgerEntry {
                        timestamp: row.get(1)?,
                        source_path: row.get(2)?,
                        entry_count: row.get::<_, i64>(3)? as usize,
                        pii_count: row.get::<_, i64>(4)? as usize,
                        risk_score: row.get(5)?,
                        tokens_before: row.get::<_, i64>(6)? as usize,
                        tokens_after: row.get::<_, i64>(7)? as usize,
                        reduction_pct: row.get(8)?,
                    },
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()
            .context("Failed to read ledger")?;

        Ok(rows)
    }
}
