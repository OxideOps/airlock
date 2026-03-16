use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use tracing::debug;

use airlock::config::{self, AirlockConfig};
use airlock::ner::{CompiledCustomRule, RegexNer};
use airlock::scrub::AliasMode;
use airlock::types::EntityType;
use airlock::{compress, ledger, scrub};

// ── ANSI helpers ──────────────────────────────────────────────────────────────

const RED_BOLD: &str = "\x1b[1;31m";
const RESET: &str = "\x1b[0m";

fn fatal(msg: &str) -> ! {
    eprintln!("{RED_BOLD}Error:{RESET} {msg}");
    process::exit(1);
}

fn require_file(path: &Path) -> Result<String> {
    match std::fs::read_to_string(path) {
        Ok(s) => Ok(s),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            anyhow::bail!("File not found: '{}'", path.display())
        }
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            anyhow::bail!("Permission denied reading '{}'", path.display())
        }
        Err(e) => Err(e.into()),
    }
}

/// Build a [`RegexNer`] from the active config's custom rules and redact toggles.
fn build_ner(cfg: &AirlockConfig) -> Result<RegexNer> {
    let mut custom_rules = Vec::new();
    for rule in &cfg.rules {
        let pattern = regex::Regex::new(&rule.pattern)
            .with_context(|| format!("Invalid regex in rule '{}': {}", rule.name, rule.pattern))?;
        custom_rules.push(CompiledCustomRule {
            name: rule.name.clone(),
            alias_prefix: rule.alias_prefix.clone(),
            pattern,
        });
    }
    Ok(RegexNer {
        custom_rules,
        names: cfg.redact.names,
        emails: cfg.redact.emails,
        phones: cfg.redact.phones,
        ssns: cfg.redact.ssns,
        credit_cards: cfg.redact.credit_cards,
        ip_addresses: cfg.redact.ip_addresses,
        jwt_tokens: cfg.redact.jwt_tokens,
        aws_keys: cfg.redact.aws_keys,
        env_secrets: cfg.redact.env_secrets,
    })
}

// ── CLI ───────────────────────────────────────────────────────────────────────

/// Airlock — Local-first AI Security Gateway
///
/// Airlock protects your data before it reaches an AI model.
/// It intercepts JSON (or NDJSON) log files, redacts PII with consistent
/// synthetic aliases, compresses token overhead, and maintains a local audit
/// ledger — all without sending a single byte to the cloud.
///
/// QUICK START
///   airlock scrub logs.json --diff
///   airlock compress logs.json
///   airlock ledger
///
/// CONFIG FILE
///   Drop a .airlock.toml in the current directory to set defaults:
///
///     [scrub]
///     salt = "my-org-secret"
///
///     [[rules]]
///     name         = "EmployeeId"
///     pattern      = "EMP-\\d{5}"
///     alias_prefix = "Emp"
#[derive(Parser, Debug)]
#[command(
    name = "airlock",
    version,
    author,
    about = "Local-first AI security gateway: PII redaction, token compression, and audit ledger",
    propagate_version = true,
    subcommand_required = true,
    arg_required_else_help = true
)]
struct Cli {
    /// Verbosity: -v info, -vv debug, -vvv trace
    #[arg(short, long, action = clap::ArgAction::Count, global = true)]
    verbose: u8,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Redact PII, compress tokens, and write an audit entry to the Risk Ledger.
    ///
    /// Reads a JSON array or NDJSON file from PATH. Every name, email, phone,
    /// SSN, credit card, and IP address found is replaced with a stable alias.
    /// The same identity always maps to the same alias within the run.
    ///
    /// Use --salt for cross-run stability: the same real identity maps to the
    /// same alias across any number of files, as long as the same salt is used.
    ///
    /// EXAMPLES
    ///   airlock scrub logs.json --diff
    ///   airlock scrub logs.ndjson --salt mysecret --diff > clean.json
    Scrub {
        /// Path to a JSON array or NDJSON file
        path: PathBuf,

        /// Path to the SQLite Risk Ledger [default: airlock_ledger.db]
        #[arg(long, value_name = "FILE")]
        db: Option<PathBuf>,

        /// Print a detailed swap table to stderr
        #[arg(short, long)]
        diff: bool,

        /// Output format: pretty (default) or compact
        #[arg(short, long, default_value = "pretty", value_name = "FORMAT")]
        output: String,

        /// Enable stable cross-run aliases by seeding with SALT
        #[arg(long, value_name = "SALT")]
        salt: Option<String>,
    },

    /// Compress a JSON log file without PII redaction.
    ///
    /// Extracts repeated top-level keys into a single schema header,
    /// reducing LLM token count by 20-60%. Accepts JSON arrays or NDJSON.
    ///
    /// EXAMPLES
    ///   airlock compress logs.json
    ///   airlock compress logs.ndjson --output compact > compressed.json
    Compress {
        /// Path to a JSON array or NDJSON file
        path: PathBuf,

        /// Output format: pretty (default) or compact
        #[arg(short, long, default_value = "pretty", value_name = "FORMAT")]
        output: String,
    },

    /// Display recent entries from the local Risk Ledger.
    ///
    /// EXAMPLES
    ///   airlock ledger
    ///   airlock ledger --last 20 --db /path/to/custom.db
    Ledger {
        /// Path to the SQLite Risk Ledger [default: airlock_ledger.db]
        #[arg(long, value_name = "FILE")]
        db: Option<PathBuf>,

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
    let cfg = config::load().unwrap_or_default();

    match cli.command {
        Commands::Scrub {
            path,
            db,
            diff,
            output,
            salt,
        } => cmd_scrub(&path, db, diff, &output, salt, cfg),
        Commands::Compress { path, output } => cmd_compress(&path, &output),
        Commands::Ledger { db, last } => cmd_ledger(db, last, &cfg),
    }
}

// ── Command handlers ──────────────────────────────────────────────────────────

fn cmd_scrub(
    path: &Path,
    db: Option<PathBuf>,
    diff: bool,
    output: &str,
    salt: Option<String>,
    cfg: AirlockConfig,
) -> Result<()> {
    let raw = require_file(path)?;
    debug!("Loaded {} bytes from '{}'", raw.len(), path.display());

    // CLI flags take precedence over config file
    let effective_salt = salt.or_else(|| cfg.scrub.salt.clone());
    let effective_db: Option<PathBuf> = db
        .or_else(|| cfg.scrub.db.clone())
        .or_else(|| Some(PathBuf::from("airlock_ledger.db")));

    let alias_mode = match &effective_salt {
        Some(s) => {
            eprintln!("  ℹ  Stable-seed mode enabled — aliases are cross-run deterministic.");
            AliasMode::Seeded { salt: s.clone() }
        }
        None => AliasMode::Sequential,
    };

    let ner = build_ner(&cfg)?;

    let scrub_config = scrub::ScrubConfig {
        db_path: effective_db.clone(),
        source_path: path.display().to_string(),
        alias_mode,
        ner: Some(Box::new(ner)),
    };

    let result = scrub::scrub(&raw, scrub_config)?;
    let db_display = effective_db
        .as_ref()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| "none".to_string());

    print_scrub_report(&result, &path.display().to_string(), &db_display);

    if diff && !result.all_records.is_empty() {
        eprintln!("  Swap Detail:");
        for r in &result.all_records {
            eprintln!(
                "    [{:>12}]  {:35} → {}",
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

    let entries = scrub::parse_entries(&raw)
        .with_context(|| format!("Failed to parse '{}'", path.display()))?;
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

fn cmd_ledger(db: Option<PathBuf>, last: usize, cfg: &AirlockConfig) -> Result<()> {
    let db_path = db
        .or_else(|| cfg.scrub.db.clone())
        .unwrap_or_else(|| PathBuf::from("airlock_ledger.db"));

    if !db_path.exists() {
        eprintln!(
            "No ledger found at '{}'. Run 'airlock scrub <file>' first.",
            db_path.display()
        );
        return Ok(());
    }

    let ledger = ledger::Ledger::open(&db_path)?;
    let rows = ledger.recent(last)?;

    if rows.is_empty() {
        eprintln!("Ledger is empty — run 'airlock scrub <file>' first.");
        return Ok(());
    }

    eprintln!();
    eprintln!("  ╔══════╦════════════════════╦══════════╦═════════╦══════════╦══════════════════╗");
    eprintln!(
        "  ║  AIRLOCK — RISK LEDGER ({}){}║",
        db_path.display(),
        " ".repeat(44_usize.saturating_sub(db_path.display().to_string().len()))
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
    let risk_score = scrub::compute_risk(result.total_pii, c.entry_count);
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
            "{} entities  ({})",
            result.total_pii,
            format_pii_breakdown(&result.alias_counts)
        )
    );
    eprintln!(
        "  ║  Aliases     {:<44} ║",
        format_alias_ranges(&result.alias_counts)
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
        match result.ledger_id {
            Some(id) => format!("Entry #{id} → {db_path}"),
            None => "skipped (no db configured)".to_string(),
        }
    );
    eprintln!("  ╚══════════════════════════════════════════════════════════╝");
    eprintln!();
}

// ── Display helpers ───────────────────────────────────────────────────────────

fn format_pii_breakdown(counts: &HashMap<EntityType, usize>) -> String {
    // Fixed display order for built-in types
    let ordered = [
        EntityType::Name,
        EntityType::Email,
        EntityType::Phone,
        EntityType::Ssn,
        EntityType::CreditCard,
        EntityType::IpAddress,
        EntityType::JwtToken,
        EntityType::AwsKey,
        EntityType::EnvSecret,
    ];
    let mut parts: Vec<String> = ordered
        .iter()
        .filter_map(|et| {
            let n = counts.get(et).copied().unwrap_or(0);
            if n > 0 {
                Some(format!("{n} {et}"))
            } else {
                None
            }
        })
        .collect();
    // Custom entities
    for (et, &n) in counts {
        if matches!(et, EntityType::Custom { .. }) && n > 0 {
            parts.push(format!("{n} {et}"));
        }
    }
    if parts.is_empty() {
        "none detected".to_string()
    } else {
        parts.join(" · ")
    }
}

fn format_alias_ranges(counts: &HashMap<EntityType, usize>) -> String {
    let names = counts.get(&EntityType::Name).copied().unwrap_or(0);
    let emails = counts.get(&EntityType::Email).copied().unwrap_or(0);
    let mut parts = Vec::new();
    if names > 0 {
        parts.push(format!("User_A..{}", nth_label(names)));
    }
    if emails > 0 {
        parts.push(format!("alias_a..{}", nth_label(emails).to_lowercase()));
    }
    for (et, &n) in counts {
        if !matches!(et, EntityType::Name | EntityType::Email) && n > 0 {
            parts.push(format!(
                "{}_A..{}_{}",
                et.alias_prefix(),
                et.alias_prefix(),
                nth_label(n)
            ));
        }
    }
    if parts.is_empty() {
        "—".to_string()
    } else {
        parts.join("  ·  ")
    }
}

fn bar(pct: f64, width: usize) -> String {
    let filled = ((pct / 100.0) * width as f64).round() as usize;
    format!(
        "{}{}",
        "█".repeat(filled),
        "░".repeat(width.saturating_sub(filled))
    )
}

fn nth_label(n: usize) -> String {
    if n == 0 {
        return "—".to_string();
    }
    scrub::counter_to_label(n.saturating_sub(1))
}

fn trunc(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_owned()
    } else {
        format!("…{}", &s[s.len().saturating_sub(max - 1)..])
    }
}

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
