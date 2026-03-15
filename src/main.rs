use std::path::{Path, PathBuf};
use std::process;

use anyhow::Result;
use clap::{Parser, Subcommand};
use tracing::debug;

use airlock::{compress, ledger, scrub};
use airlock::error::AirlockError;
use airlock::scrub::AliasMode;

// ── ANSI helpers ──────────────────────────────────────────────────────────────

const RED_BOLD: &str = "\x1b[1;31m";
const RESET: &str = "\x1b[0m";

fn fatal(msg: &str) -> ! {
    eprintln!("{RED_BOLD}Error:{RESET} {msg}");
    process::exit(1);
}

/// Read a file to a `String`, emitting user-friendly errors for common failures.
fn require_file(path: &Path) -> Result<String> {
    match std::fs::read_to_string(path) {
        Ok(s) => Ok(s),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            Err(AirlockError::FileNotFound {
                path: path.display().to_string(),
            }
            .into())
        }
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            Err(AirlockError::PermissionDenied {
                path: path.display().to_string(),
            }
            .into())
        }
        Err(e) => Err(e.into()),
    }
}

// ── CLI ───────────────────────────────────────────────────────────────────────

/// Airlock — Local-first AI Security Gateway
///
/// Airlock protects your data before it ever reaches an AI model.
/// It intercepts JSON log files, redacts PII with consistent synthetic
/// aliases, compresses token overhead, and maintains a local audit ledger
/// — all without sending a single byte to the cloud.
///
/// QUICK START
///   airlock scrub logs.json --diff
///   airlock compress logs.json
///   airlock ledger
#[derive(Parser, Debug)]
#[command(
    name = "airlock",
    version,
    author,
    about = "Local-first AI security gateway: PII redaction, token compression, and audit ledger",
    long_about = "Airlock is a local-first AI security gateway written in Rust.\n\
                  \n\
                  It solves three enterprise problems:\n\
                  \n\
                  1. SYNTHETIC DATA SWAPPING — replaces real names and emails with consistent\n\
                     session-scoped aliases (e.g. 'Dillon Roller' → 'User_A') so AI models\n\
                     can follow conversational logic without ever seeing real identities.\n\
                  \n\
                  2. TOKEN-TAX COMPRESSION — extracts repeated JSON keys into a single schema\n\
                     header, reducing LLM token count by 20–60% and cutting API costs.\n\
                  \n\
                  3. RISK LEDGER — persists an auditable SQLite record of every scrub session:\n\
                     timestamp, PII count, risk score, and compression savings.",
    propagate_version = true,
    subcommand_required = true,
    arg_required_else_help = true
)]
struct Cli {
    /// Verbosity level: -v info, -vv debug, -vvv trace
    #[arg(short, long, action = clap::ArgAction::Count, global = true)]
    verbose: u8,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Redact PII, compress tokens, and write an audit entry to the Risk Ledger.
    ///
    /// Reads a JSON array of log objects from PATH.  Every name and email address
    /// found is replaced with a stable session alias (User_A, alias_a@redacted.dev).
    /// The same identity always maps to the same alias within the run, so AI models
    /// can still reason about behaviour patterns without seeing real data.
    ///
    /// Passing --salt enables cross-run stability: the same real identity will map
    /// to the same alias every time, across any number of files, as long as the
    /// same salt is supplied.
    ///
    /// OUTPUT
    ///   Compressed JSON → stdout  (pipeable to a file or another process)
    ///   Report + swaps  → stderr
    ///
    /// EXAMPLES
    ///   airlock scrub logs.json --diff
    ///   airlock scrub logs.json --salt mysecret --diff > clean.json
    Scrub {
        /// Path to a JSON file containing an array of log objects
        path: PathBuf,

        /// Path to the SQLite Risk Ledger database [default: airlock_ledger.db]
        #[arg(long, default_value = "airlock_ledger.db", value_name = "FILE")]
        db: PathBuf,

        /// Print a detailed swap table to stderr (original → alias for every hit)
        #[arg(short, long)]
        diff: bool,

        /// Output format for the compressed JSON: pretty or compact
        #[arg(short, long, default_value = "pretty", value_name = "FORMAT")]
        output: String,

        /// Enable stable cross-run aliases by seeding alias derivation with SALT.
        ///
        /// When set, the same real identity always maps to the same synthetic alias
        /// regardless of file order or which records are present.  Keep this value
        /// secret — it is the only thing preventing alias reversal.
        #[arg(long, value_name = "SALT")]
        salt: Option<String>,
    },

    /// Compress a JSON log file without PII redaction.
    ///
    /// Extracts all repeated top-level JSON keys into a single '__airlock_schema'
    /// header and converts each log object into a compact value array.  No PII
    /// detection is performed — use 'scrub' if you need redaction too.
    ///
    /// EXAMPLES
    ///   airlock compress logs.json
    ///   airlock compress logs.json --output compact > compressed.json
    Compress {
        /// Path to a JSON file containing an array of log objects
        path: PathBuf,

        /// Output format: pretty or compact
        #[arg(short, long, default_value = "pretty", value_name = "FORMAT")]
        output: String,
    },

    /// Display recent entries from the local Risk Ledger.
    ///
    /// Each row represents one 'airlock scrub' session and shows the source file,
    /// number of PII entities found, the computed risk score (0–100), and the
    /// token compression savings achieved.
    ///
    /// EXAMPLES
    ///   airlock ledger
    ///   airlock ledger --last 20
    ///   airlock ledger --db /path/to/custom.db
    Ledger {
        /// Path to the SQLite Risk Ledger database [default: airlock_ledger.db]
        #[arg(long, default_value = "airlock_ledger.db", value_name = "FILE")]
        db: PathBuf,

        /// Number of most-recent entries to display
        #[arg(short, long, default_value = "10", value_name = "N")]
        last: usize,
    },
}

// ── Entry point ───────────────────────────────────────────────────────────────

fn main() {
    let cli = Cli::parse();
    init_tracing(cli.verbose);

    if let Err(e) = run(cli) {
        fatal(&e.to_string());
    }
}

fn run(cli: Cli) -> Result<()> {
    match cli.command {
        Commands::Scrub {
            path,
            db,
            diff,
            output,
            salt,
        } => cmd_scrub(&path, &db, diff, &output, salt),
        Commands::Compress { path, output } => cmd_compress(&path, &output),
        Commands::Ledger { db, last } => cmd_ledger(&db, last),
    }
}

// ── Command handlers ──────────────────────────────────────────────────────────

fn cmd_scrub(
    path: &Path,
    db: &Path,
    diff: bool,
    output: &str,
    salt: Option<String>,
) -> Result<()> {
    let raw = require_file(path)?;
    debug!("Loaded {} bytes from '{}'", raw.len(), path.display());

    let alias_mode = match salt {
        Some(s) => {
            eprintln!("  ℹ  Stable-seed mode enabled — aliases are cross-run deterministic.");
            AliasMode::Seeded { salt: s }
        }
        None => AliasMode::Sequential,
    };

    let config = scrub::ScrubConfig {
        db_path: db,
        source_path: path.display().to_string(),
        alias_mode,
    };

    let result = scrub::scrub(&raw, config)?;

    print_scrub_report(&result, &path.display().to_string(), &db.display().to_string());

    if diff && !result.all_records.is_empty() {
        eprintln!("  Swap Detail:");
        for r in &result.all_records {
            eprintln!(
                "    [{:>10}]  {:35} → {}",
                r.entity_type, r.original, r.synthetic
            );
        }
        eprintln!();
    }

    let json_out = match output {
        "compact" => serde_json::to_string(&result.compressed.output)?,
        _ => serde_json::to_string_pretty(&result.compressed.output)?,
    };
    println!("{json_out}");
    Ok(())
}

fn cmd_compress(path: &Path, output: &str) -> Result<()> {
    let raw = require_file(path)?;
    debug!("Loaded {} bytes from '{}'", raw.len(), path.display());

    let entries: Vec<serde_json::Value> = serde_json::from_str(&raw).map_err(|e| {
        AirlockError::InvalidJson {
            detail: format!("'{}' is not a valid JSON array: {e}", path.display()),
        }
    })?;

    let result = compress::compress(&entries)?;

    eprintln!();
    eprintln!("  ╔══════════════════════════════════════════════════════════╗");
    eprintln!("  ║          📦  AIRLOCK — COMPRESS                         ║");
    eprintln!("  ╠══════════════════════════════════════════════════════════╣");
    eprintln!(
        "  ║  Source      {:<44} ║",
        format!(
            "{} ({} entries)",
            trunc(&path.display().to_string(), 30),
            result.entry_count
        )
    );
    eprintln!(
        "  ║  Schema      {:<44} ║",
        format!("{} fields extracted", result.schema.len())
    );
    eprintln!(
        "  ║  Tokens      {:<44} ║",
        format!(
            "{} → {}  ({:.1}% reduction)",
            result.tokens_before, result.tokens_after, result.reduction_pct
        )
    );
    eprintln!("  ╚══════════════════════════════════════════════════════════╝");
    eprintln!();

    let json_out = match output {
        "compact" => serde_json::to_string(&result.output)?,
        _ => serde_json::to_string_pretty(&result.output)?,
    };
    println!("{json_out}");
    Ok(())
}

fn cmd_ledger(db: &Path, last: usize) -> Result<()> {
    if !db.exists() {
        eprintln!(
            "No ledger found at '{}'. Run 'airlock scrub <file>' first.",
            db.display()
        );
        return Ok(());
    }

    let ledger = ledger::Ledger::open(db)?;
    let rows = ledger.recent(last)?;

    if rows.is_empty() {
        eprintln!("Ledger is empty — run 'airlock scrub <file>' first.");
        return Ok(());
    }

    eprintln!();
    eprintln!("  ╔══════╦════════════════════╦══════════╦═════════╦══════════╦══════════════════╗");
    eprintln!(
        "  ║  AIRLOCK — RISK LEDGER ({})                                              ║",
        db.display()
    );
    eprintln!("  ╠══════╬════════════════════╬══════════╬═════════╬══════════╬══════════════════╣");
    eprintln!("  ║  ID  ║  Timestamp         ║ Entries  ║  PII    ║  Risk    ║  Compression     ║");
    eprintln!("  ╠══════╬════════════════════╬══════════╬═════════╬══════════╬══════════════════╣");
    for (id, e) in &rows {
        eprintln!(
            "  ║ {:>4} ║ {:18} ║ {:>8} ║ {:>7} ║ {:>6.0}/100 ║ {:>13.1}%  ║",
            id,
            &e.timestamp[..18.min(e.timestamp.len())],
            e.entry_count,
            e.pii_count,
            e.risk_score,
            e.reduction_pct
        );
    }
    eprintln!("  ╚══════╩════════════════════╩══════════╩═════════╩══════════╩══════════════════╝");
    eprintln!();
    Ok(())
}

// ── Scrub report banner ───────────────────────────────────────────────────────

fn print_scrub_report(result: &scrub::ScrubResult, source: &str, db_path: &str) {
    let c = &result.compressed;
    let risk_score = compute_risk_display(result.total_pii, c.entry_count);
    let risk_label = match risk_score as u32 {
        0..=24 => "LOW",
        25..=49 => "MEDIUM",
        50..=74 => "HIGH",
        _ => "CRITICAL",
    };

    eprintln!();
    eprintln!("  ╔══════════════════════════════════════════════════════════╗");
    eprintln!("  ║          ✈  AIRLOCK — SCRUB COMPLETE                    ║");
    eprintln!("  ╠══════════════════════════════════════════════════════════╣");
    eprintln!(
        "  ║  Source      {:<44} ║",
        format!("{} ({} entries)", trunc(source, 30), c.entry_count)
    );
    eprintln!(
        "  ║  PII Found   {:<44} ║",
        format!(
            "{} entities  ({} names · {} emails)",
            result.total_pii, result.name_aliases, result.email_aliases
        )
    );
    eprintln!(
        "  ║  Aliases     {:<44} ║",
        format!(
            "User_A..{}  ·  alias_a..{}",
            nth_label(result.name_aliases),
            nth_label(result.email_aliases).to_lowercase()
        )
    );
    eprintln!(
        "  ║  Compression {:<44} ║",
        format!(
            "{:.1}%  {}  {} → {} tokens",
            c.reduction_pct,
            bar(c.reduction_pct, 10),
            c.tokens_before,
            c.tokens_after,
        )
    );
    eprintln!(
        "  ║  Risk Score  {:<44} ║",
        format!(
            "{:.0}/100  {}  {risk_label}",
            risk_score,
            bar(risk_score, 10)
        )
    );
    eprintln!(
        "  ║  Ledger      {:<44} ║",
        format!("Entry #{} → {}", result.ledger_id, db_path)
    );
    eprintln!("  ╚══════════════════════════════════════════════════════════╝");
    eprintln!();
}

// ── Display helpers ───────────────────────────────────────────────────────────

/// Render a filled/empty progress bar of `width` cells.
fn bar(pct: f64, width: usize) -> String {
    let filled = ((pct / 100.0) * width as f64).round() as usize;
    format!(
        "{}{}",
        "█".repeat(filled),
        "░".repeat(width.saturating_sub(filled))
    )
}

/// Return the last alias label for `n` unique aliases (e.g. `n=3` → `"C"`).
fn nth_label(n: usize) -> String {
    if n == 0 {
        return "—".to_string();
    }
    label_for(n.saturating_sub(1))
}

/// Excel-style label for zero-based index `n`.
fn label_for(mut n: usize) -> String {
    let mut s = String::new();
    loop {
        s.insert(0, (b'A' + (n % 26) as u8) as char);
        if n < 26 {
            break;
        }
        n = n / 26 - 1;
    }
    s
}

/// Truncate `s` to at most `max` characters, prepending `…` if truncated.
fn trunc(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_owned()
    } else {
        format!("…{}", &s[s.len().saturating_sub(max - 1)..])
    }
}

/// Risk score for display (mirrors the library calculation).
fn compute_risk_display(pii: usize, entries: usize) -> f64 {
    if entries == 0 {
        return 0.0;
    }
    (pii as f64 / entries as f64 * 25.0).min(100.0)
}

/// Initialise the `tracing` subscriber based on the `-v` verbosity flag.
fn init_tracing(verbose: u8) {
    let level = match verbose {
        0 => "warn",
        1 => "info",
        2 => "debug",
        _ => "trace",
    };
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(level)),
        )
        .with_writer(std::io::stderr)
        .init();
}
