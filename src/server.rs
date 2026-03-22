//! HTTP server for the `airlock serve` subcommand.
//!
//! Exposes three endpoints over a local HTTP interface:
//!
//!   POST /redact    — run the full scrub pipeline on a JSON payload
//!   POST /restore   — look up a ledger entry by ID and return its metadata
//!   GET  /audit     — return the most recent N ledger entries
//!
//! Start the server with [`serve`]. All three handlers share an [`AppState`]
//! that holds the active config and the resolved ledger database path.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Result;
use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tower_http::trace::TraceLayer;
use tracing::info;

use crate::{
    config::AirlockConfig,
    ledger::Ledger,
    ner::{CompiledCustomRule, RegexNer},
    scrub::{self, AliasMode, ScrubConfig},
    types::LedgerEntry,
};

// ── App state ─────────────────────────────────────────────────────────────────

/// Shared state injected into every handler via axum's [`State`] extractor.
#[derive(Clone)]
pub struct AppState {
    pub cfg: Arc<AirlockConfig>,
    pub db_path: PathBuf,
}

// ── Error type ────────────────────────────────────────────────────────────────

/// Converts any `anyhow`-compatible error into a `500 { "error": "…" }` response.
pub struct AppError(anyhow::Error);

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": self.0.to_string() })),
        )
            .into_response()
    }
}

impl<E: Into<anyhow::Error>> From<E> for AppError {
    fn from(e: E) -> Self {
        AppError(e.into())
    }
}

// ── Shared DTO ────────────────────────────────────────────────────────────────

/// Serialisable view of a [`LedgerEntry`] for HTTP responses.
#[derive(Serialize)]
pub struct LedgerEntryDto {
    pub timestamp: String,
    pub source_path: String,
    pub entry_count: usize,
    pub pii_count: usize,
    pub risk_score: f64,
    pub tokens_before: usize,
    pub tokens_after: usize,
    pub reduction_pct: f64,
}

impl From<LedgerEntry> for LedgerEntryDto {
    fn from(e: LedgerEntry) -> Self {
        Self {
            timestamp: e.timestamp,
            source_path: e.source_path,
            entry_count: e.entry_count,
            pii_count: e.pii_count,
            risk_score: e.risk_score,
            tokens_before: e.tokens_before,
            tokens_after: e.tokens_after,
            reduction_pct: e.reduction_pct,
        }
    }
}

// ── POST /redact ──────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct RedactRequest {
    /// A JSON array of objects, or a single object. NDJSON is not accepted
    /// over HTTP — convert to a JSON array before sending.
    pub data: Value,
    /// Optional secret for stable cross-run aliases. Falls back to
    /// `[scrub] salt` in `.airlock.toml` when omitted.
    pub salt: Option<String>,
    /// Per-request PII detector toggles. Each field defaults to the
    /// corresponding `[redact]` flag in `.airlock.toml` when omitted.
    pub options: Option<RedactOptions>,
}

#[derive(Deserialize, Default)]
pub struct RedactOptions {
    pub names: Option<bool>,
    pub emails: Option<bool>,
    pub phones: Option<bool>,
    pub ssns: Option<bool>,
    pub credit_cards: Option<bool>,
    pub ip_addresses: Option<bool>,
    pub jwt_tokens: Option<bool>,
    pub aws_keys: Option<bool>,
    pub env_secrets: Option<bool>,
}

#[derive(Serialize)]
pub struct RedactResponse {
    /// The compressed schema+rows output — pipe this to your LLM.
    pub output: Value,
    pub ledger_id: Option<i64>,
    pub total_pii: usize,
    /// Unique alias count per entity type (string keys: `"Name"`, `"Email"`, …).
    pub alias_counts: HashMap<String, usize>,
    pub entry_count: usize,
    pub tokens_before: usize,
    pub tokens_after: usize,
    pub reduction_pct: f64,
    pub risk_score: f64,
}

async fn handle_redact(
    State(state): State<AppState>,
    Json(req): Json<RedactRequest>,
) -> Result<Json<RedactResponse>, AppError> {
    // Normalise: wrap a bare object in an array so parse_entries is happy.
    let entries_value = match req.data {
        Value::Array(_) => req.data,
        other => Value::Array(vec![other]),
    };
    let raw_json = serde_json::to_string(&entries_value)?;

    let opts = req.options.unwrap_or_default();
    let cfg = &state.cfg;

    // Compile custom rules from config (not overrideable per-request).
    let mut custom_rules = Vec::new();
    for rule in &cfg.rules {
        let pattern = regex::Regex::new(&rule.pattern)
            .map_err(|e| anyhow::anyhow!("Invalid regex in rule '{}': {e}", rule.name))?;
        custom_rules.push(CompiledCustomRule {
            name: rule.name.clone(),
            alias_prefix: rule.alias_prefix.clone(),
            pattern,
        });
    }

    // Per-request options override the config redact flags.
    let ner = RegexNer {
        custom_rules,
        names: opts.names.unwrap_or(cfg.redact.names),
        emails: opts.emails.unwrap_or(cfg.redact.emails),
        phones: opts.phones.unwrap_or(cfg.redact.phones),
        ssns: opts.ssns.unwrap_or(cfg.redact.ssns),
        credit_cards: opts.credit_cards.unwrap_or(cfg.redact.credit_cards),
        ip_addresses: opts.ip_addresses.unwrap_or(cfg.redact.ip_addresses),
        jwt_tokens: opts.jwt_tokens.unwrap_or(cfg.redact.jwt_tokens),
        aws_keys: opts.aws_keys.unwrap_or(cfg.redact.aws_keys),
        env_secrets: opts.env_secrets.unwrap_or(cfg.redact.env_secrets),
    };

    // Request salt takes precedence; fall back to config salt.
    let effective_salt = req.salt.or_else(|| cfg.scrub.salt.clone());
    let alias_mode = match effective_salt {
        Some(s) => AliasMode::Seeded { salt: s },
        None => AliasMode::Sequential,
    };

    let db_path = state.db_path.clone();
    let scrub_cfg = ScrubConfig {
        db_path: Some(db_path),
        source_path: "<http:/redact>".to_string(),
        alias_mode,
        ner: Some(Box::new(ner)),
    };

    let result = tokio::task::spawn_blocking(move || scrub::scrub(&raw_json, scrub_cfg))
        .await
        .map_err(|e| anyhow::anyhow!("Task join error: {e}"))??;

    let alias_counts: HashMap<String, usize> = result
        .alias_counts
        .into_iter()
        .map(|(k, v)| (k.to_string(), v))
        .collect();

    let risk_score = scrub::compute_risk(result.total_pii, result.compressed.entry_count);

    Ok(Json(RedactResponse {
        output: result.compressed.output,
        ledger_id: result.ledger_id,
        total_pii: result.total_pii,
        alias_counts,
        entry_count: result.compressed.entry_count,
        tokens_before: result.compressed.tokens_before,
        tokens_after: result.compressed.tokens_after,
        reduction_pct: result.compressed.reduction_pct,
        risk_score,
    }))
}

// ── POST /restore ─────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct RestoreRequest {
    /// The redacted JSON payload (accepted for future validation; unused now).
    pub data: Value,
    /// The ledger row ID returned by a prior `/redact` call.
    pub ledger_id: i64,
}

#[derive(Serialize)]
pub struct RestoreResponse {
    pub ledger_id: i64,
    /// `None` when the ledger database does not exist or the ID is unknown.
    pub entry: Option<LedgerEntryDto>,
}

async fn handle_restore(
    State(state): State<AppState>,
    Json(req): Json<RestoreRequest>,
) -> Result<Json<RestoreResponse>, AppError> {
    let db_path = state.db_path.clone();
    let id = req.ledger_id;

    let entry = tokio::task::spawn_blocking(move || -> Result<Option<(i64, LedgerEntry)>> {
        if !db_path.exists() {
            return Ok(None);
        }
        Ledger::open(&db_path)?.get_by_id(id)
    })
    .await
    .map_err(|e| anyhow::anyhow!("Task join error: {e}"))??;

    Ok(Json(RestoreResponse {
        ledger_id: id,
        entry: entry.map(|(_, e)| LedgerEntryDto::from(e)),
    }))
}

// ── GET /audit ────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct AuditParams {
    #[serde(default = "default_audit_limit")]
    pub limit: usize,
}

fn default_audit_limit() -> usize {
    20
}

#[derive(Serialize)]
pub struct AuditEntry {
    pub id: i64,
    pub entry: LedgerEntryDto,
}

async fn handle_audit(
    State(state): State<AppState>,
    Query(params): Query<AuditParams>,
) -> Result<Json<Vec<AuditEntry>>, AppError> {
    let db_path = state.db_path.clone();
    let limit = params.limit;

    let rows = tokio::task::spawn_blocking(move || -> Result<Vec<(i64, LedgerEntry)>> {
        if !db_path.exists() {
            return Ok(vec![]);
        }
        Ledger::open(&db_path)?.recent(limit)
    })
    .await
    .map_err(|e| anyhow::anyhow!("Task join error: {e}"))??;

    let entries = rows
        .into_iter()
        .map(|(id, e)| AuditEntry {
            id,
            entry: LedgerEntryDto::from(e),
        })
        .collect();

    Ok(Json(entries))
}

// ── Router ────────────────────────────────────────────────────────────────────

/// Build the axum [`Router`] from shared application state.
pub fn build_router(state: AppState) -> Router {
    Router::new()
        .route("/redact", post(handle_redact))
        .route("/restore", post(handle_restore))
        .route("/audit", get(handle_audit))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

// ── Entry point ───────────────────────────────────────────────────────────────

/// Start the HTTP server. Called from `main()` inside a tokio runtime.
///
/// Host and port are resolved in priority order:
///   1. `host` / `port` arguments (from `--host` / `--port` CLI flags)
///   2. `[server]` section in `.airlock.toml`
///   3. Built-in defaults: `127.0.0.1:7777`
pub async fn serve(cfg: AirlockConfig, host: Option<String>, port: Option<u16>) -> Result<()> {
    let effective_host = host.unwrap_or_else(|| cfg.server.host.clone());
    let effective_port = port.unwrap_or(cfg.server.port);
    let db_path = cfg
        .scrub
        .db
        .clone()
        .unwrap_or_else(|| PathBuf::from("airlock_ledger.db"));

    let addr = format!("{effective_host}:{effective_port}");

    let state = AppState {
        cfg: Arc::new(cfg),
        db_path: db_path.clone(),
    };

    let listener = tokio::net::TcpListener::bind(&addr).await?;

    eprintln!();
    eprintln!("  ╔══════════════════════════════════════════════════════════╗");
    eprintln!("  ║          ✈  AIRLOCK — SERVER                            ║");
    eprintln!("  ╠══════════════════════════════════════════════════════════╣");
    eprintln!("  ║  Listening   {:<44} ║", format!("http://{addr}"));
    eprintln!("  ║  Ledger      {:<44} ║", db_path.display());
    eprintln!("  ╠══════════════════════════════════════════════════════════╣");
    eprintln!("  ║  POST /redact     run scrub pipeline                    ║");
    eprintln!("  ║  POST /restore    look up a ledger entry by ID          ║");
    eprintln!("  ║  GET  /audit      query recent audit ledger entries      ║");
    eprintln!("  ╚══════════════════════════════════════════════════════════╝");
    eprintln!();

    info!("airlock server listening on {addr}");
    axum::serve(listener, build_router(state)).await?;
    Ok(())
}
