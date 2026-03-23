# Airlock — Developer Guide

## What Airlock Does

Airlock is a **local-first AI security gateway** written in Rust. It sits between
your data and an LLM, performing three operations in a single pass before any
bytes leave your machine:

1. **PII redaction** — detects names, emails, phones, SSNs, credit cards, IPs,
   JWTs, AWS keys, and env secrets via regex NER with Luhn/SSN post-validation;
   replaces each with a consistent synthetic alias (e.g. `User_A`, `alias_a@redacted.dev`).
2. **Token-Tax compression** — hoists repeated JSON keys into a
   `__airlock_schema` header, converting each object into a positional value
   array; achieves 20–60% LLM token reduction with no data loss.
3. **Risk Ledger** — appends a row to a local SQLite database (`airlock_ledger.db`)
   after every scrub, recording PII density, risk score (0–100), and compression
   savings for compliance audit trails.

Airlock ships as a CLI binary, a Rust library (`crate-type = ["cdylib", "rlib"]`),
and a Python extension module (`pip install airlock`, built with maturin/PyO3).

---

## src/ Architecture

| File | Role |
|------|------|
| `src/lib.rs` | Crate root — declares public modules and conditionally compiles the Python extension. |
| `src/types.rs` | Shared data types: `EntityType`, `PiiSpan`, `SwapRecord`, `LedgerEntry`. |
| `src/ner.rs` | `Ner` trait + `RegexNer` implementation — detects PII spans using static regexes, curated name dictionaries, and context heuristics (honorifics, field labels, attribution verbs). |
| `src/scrub.rs` | End-to-end pipeline: parallel NER scan (Rayon) → sequential alias assignment (`AliasEngine`) → parallel alias application → compression → ledger write. Also owns `AliasMode`, `ScrubConfig`, `ScrubResult`, `compute_risk`, and `parse_entries`. |
| `src/compress.rs` | Token-Tax compression — extracts a union schema from a JSON object slice and rewrites each entry as a positional value row. |
| `src/ledger.rs` | SQLite Risk Ledger wrapper — auto-creates schema on first open, exposes `record` (INSERT), `recent` (SELECT … LIMIT n), and `get_by_id`. |
| `src/config.rs` | `.airlock.toml` loader — `AirlockConfig` with `[scrub]`, `[redact]`, `[server]`, and `[[rules]]` sections; missing file silently returns defaults. |
| `src/server.rs` | Axum REST API — `POST /redact`, `POST /restore`, `GET /audit`; wired to `airlock serve` CLI subcommand. Shares state via `AppState` (config + db path). |
| `src/python.rs` | PyO3 bindings (feature-gated) — exposes `airlock.scrub()` and `airlock.compress()` to Python with `ScrubOutput` / `CompressOutput` return types. |
| `src/main.rs` | CLI entry point — Clap subcommands (`scrub`, `compress`, `ledger`, `serve`), config loading, NER construction, and terminal report banners. |
| `src/bin/airlock_mcp.rs` | MCP server binary (`airlock-mcp`) — stdio transport, two tools: `redact_data` and `audit_log`; calls into `scrub::scrub` and `ledger::Ledger` via `spawn_blocking`. |

### Scrub pipeline phases (src/scrub.rs)

```
parse_entries (JSON array | NDJSON)
  └─ Phase 1: par_iter → scan_entry per record (NER, deduped string cache)
  └─ Phase 2: sequential AliasEngine::register (deterministic ordering)
  └─ Phase 3: par_iter → apply_to_value (span cache, no re-scan)
  └─ Phase 4: compress::compress (schema+rows envelope)
  └─ Phase 5: compute_risk + optional Ledger::record
```

### Alias modes

| Mode | Behaviour |
|------|-----------|
| `Sequential` | First-encounter order: `User_A`, `User_B`, … |
| `Seeded { salt }` | `SHA-256(salt ‖ prefix ‖ token)` → 4-char label via ChaCha8; same identity maps to same alias across runs |

---

## Dependencies

| Crate | Why |
|-------|-----|
| `clap` (derive) | CLI argument parsing with rich help text |
| `serde` + `serde_json` | JSON (de)serialisation throughout |
| `regex` | Compiled regex patterns for NER |
| `rand` + `rand_chacha` | ChaCha8Rng for seeded alias derivation |
| `sha2` | SHA-256 for the stable-seed alias hash |
| `rayon` | Data-parallel NER scan and alias application |
| `rusqlite` (bundled) | SQLite Risk Ledger — `bundled` avoids a system libsqlite3 dep |
| `chrono` | RFC-3339 timestamps for ledger rows |
| `tracing` + `tracing-subscriber` | Structured logging; level controlled via `-v/-vv/-vvv` |
| `anyhow` | Ergonomic error propagation with `.context()` chains |
| `toml` | `.airlock.toml` config parsing |
| `luhn` | ISO/IEC 7812 Luhn validation for credit card post-filtering |
| `rmcp` | Official Rust MCP SDK — `#[tool_router]` / `#[tool_handler]` macros + stdio transport for `airlock-mcp`. |
| `pyo3` (optional) | Python extension module — only compiled with `--features python` |

### Release profile

`opt-level=3`, `lto=true`, `codegen-units=1`, `strip=true`.
`panic="abort"` is deliberately omitted — PyO3 requires unwinding to propagate Python exceptions.

---

## Coding Conventions

- **Module-level doc comments** (`//!`) describe purpose and include a standards
  table or example where relevant.
- **Section comments** (`// ── Label ─────`) divide files into logical blocks.
- Static regexes are lazy-initialised with `OnceLock<Regex>` — one singleton
  per pattern, compiled once and reused for the lifetime of the process.
- All public types carry doc comments; `pub(crate)` is used for internals that
  cross module boundaries within the crate.
- Tests live in `#[cfg(test)] mod tests` at the bottom of each file; integration
  concerns (e.g. SQLite) use `:memory:` databases so tests are hermetic.
- CLI flags always take precedence over `.airlock.toml` config values; the
  config is loaded once in `run()` and threaded down to command handlers.
- `anyhow::Result` is used everywhere; `fatal()` in `main.rs` is the single
  exit point for top-level errors.
- The `Ner` trait (`Send + Sync`) is intentionally thin so an ML-backed
  recogniser can be substituted without touching call sites.

---

## Completed Features

### Axum REST API (`src/server.rs`)

Exposes the scrub pipeline over HTTP via `airlock serve`.

| Method | Path | Body | Response |
|--------|------|------|----------|
| `POST` | `/redact` | `{ "data": [...], "salt"?: "...", "options"?: {...} }` | `RedactResponse` JSON |
| `POST` | `/restore` | `{ "data": ..., "ledger_id": N }` | ledger entry metadata |
| `GET`  | `/audit` | `?limit=N` | recent ledger entries |

Default address: `127.0.0.1:7777` — configurable via `--host`/`--port` flags
or `[server]` in `.airlock.toml`.

### MCP Server (`src/bin/airlock_mcp.rs`)

Exposes Airlock as a [Model Context Protocol](https://modelcontextprotocol.io)
server so Claude Desktop (and any MCP agent) can redact PII in-flight during
inference — before data reaches the upstream LLM API.

| Tool | Description |
|------|-------------|
| `redact_data` | Full scrub pipeline: NER → alias → compress → ledger |
| `audit_log` | Query the N most recent audit-ledger entries |

Transport: **stdio** (standard for Claude Desktop).
Install: `cargo install airlock-rs --bin airlock-mcp`.
Register in `~/Library/Application Support/Claude/claude_desktop_config.json`.
