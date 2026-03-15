//! Risk Ledger — local SQLite audit log for every `airlock scrub` run.

use anyhow::{Context, Result};
use rusqlite::{params, Connection};
use std::path::Path;

use crate::types::LedgerEntry;

pub struct Ledger {
    conn: Connection,
}

impl Ledger {
    /// Open (or create) the ledger database at `path`.
    pub fn open(path: &Path) -> Result<Self> {
        let conn = Connection::open(path)
            .with_context(|| format!("Cannot open ledger at {}", path.display()))?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS sessions (
                id               INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp        TEXT    NOT NULL,
                source_path      TEXT    NOT NULL,
                entry_count      INTEGER NOT NULL,
                pii_count        INTEGER NOT NULL,
                risk_score       REAL    NOT NULL,
                tokens_before    INTEGER NOT NULL,
                tokens_after     INTEGER NOT NULL,
                reduction_pct    REAL    NOT NULL
            );",
        )
        .context("Failed to initialise ledger schema")?;
        Ok(Self { conn })
    }

    /// Insert a new session record and return its auto-incremented id.
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

    /// Read the `n` most recent session records for display.
    pub fn recent(&self, n: usize) -> Result<Vec<(i64, LedgerEntry)>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, timestamp, source_path, entry_count, pii_count,
                    risk_score, tokens_before, tokens_after, reduction_pct
             FROM sessions ORDER BY id DESC LIMIT ?1",
        )?;
        let rows = stmt.query_map(params![n as i64], |row| {
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
        })?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .context("Failed to read ledger")
    }
}
