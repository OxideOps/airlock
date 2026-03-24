//! # Airlock MCP Server
//!
//! Exposes Airlock's PII redaction and audit ledger as
//! [Model Context Protocol](https://modelcontextprotocol.io) tools, enabling
//! Claude Desktop (and any MCP-compatible AI agent) to scrub sensitive data
//! in-flight before it leaves your machine.
//!
//! ## Tools
//!
//! | Tool | Description |
//! |------|-------------|
//! | `redact_data` | Run the full scrub pipeline on a JSON or NDJSON payload |
//! | `audit_log`   | Return the most recent audit-ledger entries |
//!
//! ## Transport
//!
//! The server communicates over **stdio** — the standard transport for Claude
//! Desktop integration.  All tracing output is directed to stderr so it never
//! corrupts the MCP message stream on stdout.

use std::path::PathBuf;

use anyhow::Result;
use rmcp::{
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::{CallToolResult, Content, ServerCapabilities, ServerInfo},
    schemars, tool, tool_handler, tool_router,
    transport::stdio,
    ErrorData as McpError, ServerHandler, ServiceExt,
};
use serde::{Deserialize, Serialize};
use tracing_subscriber::EnvFilter;

use airlock::{
    ledger::Ledger,
    ner::RegexNer,
    scrub::{self, AliasMode, ScrubConfig},
};

// ── Tool input schemas ─────────────────────────────────────────────────────────

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct RedactInput {
    /// A JSON array of objects (or NDJSON — one object per line) containing
    /// the data you want to redact. Each object is an independent record.
    pub data: String,

    /// Optional secret for cross-run stable aliases.  When set, the same real
    /// identity always maps to the same synthetic alias regardless of
    /// processing order.  Keep this value secret — it is the only thing
    /// preventing alias reversal.
    #[serde(default)]
    pub salt: Option<String>,

    /// Detect and redact person names (default: true)
    #[serde(default)]
    pub names: Option<bool>,
    /// Detect and redact email addresses (default: true)
    #[serde(default)]
    pub emails: Option<bool>,
    /// Detect and redact phone numbers — NANP and E.164 (default: true)
    #[serde(default)]
    pub phones: Option<bool>,
    /// Detect and redact Social Security Numbers (default: true)
    #[serde(default)]
    pub ssns: Option<bool>,
    /// Detect and redact credit card numbers with Luhn validation (default: true)
    #[serde(default)]
    pub credit_cards: Option<bool>,
    /// Detect and redact IPv4 addresses (default: true)
    #[serde(default)]
    pub ip_addresses: Option<bool>,
    /// Detect and redact JWT tokens (default: true)
    #[serde(default)]
    pub jwt_tokens: Option<bool>,
    /// Detect and redact AWS access keys (default: true)
    #[serde(default)]
    pub aws_keys: Option<bool>,
    /// Detect and redact environment variable secrets (default: true)
    #[serde(default)]
    pub env_secrets: Option<bool>,

    /// Path to the SQLite audit ledger (default: `airlock_ledger.db` in the
    /// current working directory).  Set to an empty string to skip ledger
    /// writes entirely.
    #[serde(default)]
    pub db_path: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct AuditInput {
    /// Number of recent entries to return — newest first (default: 20, max: 100)
    #[serde(default)]
    pub limit: Option<usize>,

    /// Path to the SQLite audit ledger (default: `airlock_ledger.db`)
    #[serde(default)]
    pub db_path: Option<String>,
}

// ── Response types ─────────────────────────────────────────────────────────────

#[derive(Serialize)]
struct RedactOutput {
    /// Redacted, compressed JSON — pipe this directly to your LLM
    output: serde_json::Value,
    /// Total number of PII instances replaced
    total_pii: usize,
    /// Risk score 0–100 (PII density relative to record count)
    risk_score: f64,
    /// Number of JSON records processed
    entry_count: usize,
    /// Approximate LLM token count before compression
    tokens_before: usize,
    /// Approximate LLM token count after compression
    tokens_after: usize,
    /// Token reduction percentage
    reduction_pct: f64,
    /// Audit ledger row ID (`null` when `db_path` is empty or skipped)
    ledger_id: Option<i64>,
}

#[derive(Serialize)]
struct AuditRow {
    id: i64,
    timestamp: String,
    source: String,
    entry_count: usize,
    pii_count: usize,
    risk_score: f64,
    tokens_before: usize,
    tokens_after: usize,
    reduction_pct: f64,
}

// ── MCP handler ────────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct AirlockMcp {
    tool_router: ToolRouter<Self>,
}

#[tool_router]
impl AirlockMcp {
    pub fn new() -> Self {
        Self {
            tool_router: Self::tool_router(),
        }
    }

    /// Redact PII from a JSON or NDJSON payload.
    ///
    /// Runs the full Airlock scrub pipeline: parallel NER scan → sequential
    /// alias assignment → parallel alias substitution → Token-Tax compression
    /// → audit ledger write.  Returns the compressed, redacted output ready
    /// to pass to an LLM, along with statistics about what was found.
    #[tool(
        description = "Redact PII (names, emails, phones, SSNs, credit cards, IPs, JWTs, AWS keys, env secrets) from a JSON array or NDJSON string. Returns compressed, redacted JSON that is safe to send to an LLM, along with redaction statistics and an audit ledger entry."
    )]
    async fn redact_data(
        &self,
        Parameters(input): Parameters<RedactInput>,
    ) -> Result<CallToolResult, McpError> {
        let ner = RegexNer {
            names: input.names.unwrap_or(true),
            emails: input.emails.unwrap_or(true),
            phones: input.phones.unwrap_or(true),
            ssns: input.ssns.unwrap_or(true),
            credit_cards: input.credit_cards.unwrap_or(true),
            ip_addresses: input.ip_addresses.unwrap_or(true),
            jwt_tokens: input.jwt_tokens.unwrap_or(true),
            aws_keys: input.aws_keys.unwrap_or(true),
            env_secrets: input.env_secrets.unwrap_or(true),
            custom_rules: vec![],
        };

        let alias_mode = match input.salt {
            Some(s) => AliasMode::Seeded { salt: s },
            None => AliasMode::Sequential,
        };

        // An empty string means "skip ledger write".
        let db_path = input
            .db_path
            .as_deref()
            .map(|p| {
                if p.is_empty() {
                    None
                } else {
                    Some(PathBuf::from(p))
                }
            })
            .unwrap_or_else(|| Some(PathBuf::from("airlock_ledger.db")));

        let raw = input.data;
        let cfg = ScrubConfig {
            db_path,
            source_path: "<mcp:redact_data>".to_string(),
            alias_mode,
            ner: Some(Box::new(ner)),
        };

        let result = tokio::task::spawn_blocking(move || scrub::scrub(&raw, cfg))
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        let risk_score = scrub::compute_risk(result.total_pii, result.compressed.entry_count);

        let out = RedactOutput {
            output: result.compressed.output,
            total_pii: result.total_pii,
            risk_score,
            entry_count: result.compressed.entry_count,
            tokens_before: result.compressed.tokens_before,
            tokens_after: result.compressed.tokens_after,
            reduction_pct: result.compressed.reduction_pct,
            ledger_id: result.ledger_id,
        };

        let json_str = serde_json::to_string_pretty(&out)
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        Ok(CallToolResult::success(vec![Content::text(json_str)]))
    }

    /// Return recent entries from the Airlock audit ledger.
    ///
    /// Each row records metadata from a past `redact_data` call: timestamp,
    /// entry count, PII count, risk score, and token compression savings.
    /// No original PII values are ever written to the ledger.
    #[tool(
        description = "Return recent entries from the Airlock audit ledger — newest first. Each row records metadata about a past redaction run: timestamp, entry count, PII count, risk score, and token savings. No original PII values are ever stored."
    )]
    async fn audit_log(
        &self,
        Parameters(input): Parameters<AuditInput>,
    ) -> Result<CallToolResult, McpError> {
        let limit = input.limit.unwrap_or(20).min(100);
        let db_path = PathBuf::from(input.db_path.as_deref().unwrap_or("airlock_ledger.db"));

        let rows = tokio::task::spawn_blocking(move || -> anyhow::Result<Vec<AuditRow>> {
            if !db_path.exists() {
                return Ok(vec![]);
            }
            let ledger = Ledger::open(&db_path)?;
            let entries = ledger.recent(limit)?;
            Ok(entries
                .into_iter()
                .map(|(id, e)| AuditRow {
                    id,
                    timestamp: e.timestamp,
                    source: e.source_path,
                    entry_count: e.entry_count,
                    pii_count: e.pii_count,
                    risk_score: e.risk_score,
                    tokens_before: e.tokens_before,
                    tokens_after: e.tokens_after,
                    reduction_pct: e.reduction_pct,
                })
                .collect())
        })
        .await
        .map_err(|e| McpError::internal_error(e.to_string(), None))?
        .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        let json_str = serde_json::to_string_pretty(&rows)
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        Ok(CallToolResult::success(vec![Content::text(json_str)]))
    }
}

#[tool_handler]
impl ServerHandler for AirlockMcp {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build()).with_instructions(
            "Airlock is a local-first PII security gateway. \
             Use `redact_data` to strip sensitive information (names, emails, \
             phones, SSNs, credit cards, IPs, JWTs, AWS keys) from JSON data \
             before sending it to an LLM. Use `audit_log` to review the history \
             of past redaction runs. All processing happens locally — no data \
             ever leaves your machine."
                .to_string(),
        )
    }
}

// ── Entry point ────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    // Tracing must write to stderr — stdout is the MCP message channel.
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive(tracing::Level::WARN.into()))
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .init();

    tracing::info!("airlock-mcp starting");

    let service = AirlockMcp::new()
        .serve(stdio())
        .await
        .inspect_err(|e| tracing::error!("MCP serve error: {e:?}"))?;

    service.waiting().await?;
    Ok(())
}
