# 🔒 Airlock

> **Local-first AI Security Gateway** — PII redaction, token compression, and audit ledger in a single Rust binary.

[![MIT License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-2021-orange.svg)](https://www.rust-lang.org)

Airlock sits **between your raw data and any AI model**, ensuring sensitive information is never sent to the cloud. It intercepts JSON log files, replaces real identities with consistent synthetic aliases, compresses token overhead by 20–60 %, and writes an auditable SQLite record of every run.

---

## Quick Start

```bash
# Build (release binary — ~3 MB, no runtime dependencies)
cargo build --release

# Redact PII, compress tokens, write to ledger, print result to stdout
./target/release/airlock scrub logs.json --diff

# Cross-run stable aliases (same real name → same alias on every file)
./target/release/airlock scrub logs.json --salt mysecret --diff > clean.json

# Compress only (no PII redaction)
./target/release/airlock compress logs.json

# View the audit ledger
./target/release/airlock ledger --last 20
```

---

## How It Works

```
┌─────────────────────────────────────────────────────────────────────┐
│                         airlock scrub                               │
│                                                                     │
│  JSON Array            NER Scan (rayon)       Alias Engine          │
│  ─────────────►  ─────────────────────────►  ────────────────────► │
│  logs.json       [parallel per-entry scan]    User_A, alias_b@…    │
│                                                                     │
│  Alias Apply (rayon)   Token-Tax Compress     Risk Ledger           │
│  ──────────────────►  ────────────────────►  ────────────────────► │
│  [parallel rewrite]    40–60% token saving    SQLite audit row      │
│                                                                     │
│                              ▼                                      │
│                     Clean JSON → stdout                             │
│                     Report     → stderr                             │
└─────────────────────────────────────────────────────────────────────┘
```

### The Three Money-Maker Features

| # | Feature | What It Does |
|---|---------|-------------|
| 1 | **Synthetic Data Swapping** | Replaces real names and emails with stable session aliases (`User_A`, `alias_b@redacted.dev`). The same identity always maps to the same alias — AI models can reason about patterns without seeing real PII. |
| 2 | **Token-Tax Compression** | Extracts repeated JSON key names into a single `__airlock_schema` header, converting rows to compact value arrays. Reduces LLM token spend by 20–60 %. |
| 3 | **Risk Ledger** | Persists an auditable SQLite row per run: timestamp, PII count, risk score (0–100), compression savings. View it any time with `airlock ledger`. |

---

## CLI Reference

```
airlock scrub <FILE> [OPTIONS]
  --diff              Print a detailed swap table to stderr
  --salt <SALT>       Enable stable cross-run aliases (same name → same alias always)
  --output <FORMAT>   pretty (default) | compact
  --db <FILE>         SQLite ledger path [default: airlock_ledger.db]

airlock compress <FILE> [OPTIONS]
  --output <FORMAT>   pretty | compact

airlock ledger [OPTIONS]
  --last <N>          Show N most recent entries [default: 10]
  --db <FILE>         SQLite ledger path

Global:
  -v / -vv / -vvv     Verbosity (info / debug / trace)
```

---

## Stable-Seed Aliases (`--salt`)

By default, aliases are assigned in **encounter order** — the first name seen becomes `User_A`, the second `User_B`, etc.  This is consistent within a single run but may differ between runs.

Pass `--salt <secret>` to enable **cross-run stability**: aliases are derived from `SHA-256(salt ‖ entity_type ‖ token)` fed into a `ChaCha8Rng`.  The same real name will always produce the same 4-character alias (e.g. `User_GKQT`) regardless of encounter order or which file is processed.

```bash
# File A and File B processed on different days with the same salt:
airlock scrub fileA.json --salt prod-2026 > cleanA.json
airlock scrub fileB.json --salt prod-2026 > cleanB.json
# "Alice Johnson" → "User_GKQT" in both outputs
```

> **Keep your salt secret.** It is the only thing that prevents alias reversal.

---

## Compression Format

Input (keys repeated on every row — expensive for LLMs):
```json
[
  {"timestamp": "2026-01-01T10:00:00Z", "user": "User_A", "action": "login"},
  {"timestamp": "2026-01-01T10:01:00Z", "user": "User_B", "action": "logout"}
]
```

Output (keys extracted once into a schema header):
```json
{
  "__airlock_schema": ["timestamp", "user", "action"],
  "__airlock_rows": [
    ["2026-01-01T10:00:00Z", "User_A", "login"],
    ["2026-01-01T10:01:00Z", "User_B", "logout"]
  ],
  "__airlock_meta": { "tokens_before": 120, "tokens_after": 68, "reduction_pct": "43.3" }
}
```

---

## Security & Privacy Guarantee

| Guarantee | Detail |
|-----------|--------|
| **Zero network calls** | Airlock never opens a socket. All processing happens in-process on your machine. |
| **No data written to disk** (except the ledger) | The ledger stores *counts and statistics only* — never the original PII values or the aliases. |
| **Alias irreversibility** | In seeded mode, aliases require knowledge of the salt to reverse. Without the salt, `User_GKQT` reveals nothing about the underlying identity. |
| **Deterministic, auditable** | Every run writes a timestamped row to the local SQLite ledger, giving you a complete history of what was processed and what the risk level was. |
| **No third-party AI calls** | The NER engine runs locally via regex patterns (or a future local ONNX model). Your data never touches an external API. |

---

## Architecture

```
src/
├── main.rs      — CLI (clap), command dispatch, user-facing error messages
├── error.rs     — Library-level error types (thiserror)
├── types.rs     — Shared data types (EntityType, PiiSpan, SwapRecord, LedgerEntry)
├── ner.rs       — Named Entity Recognition (pluggable Ner trait + RegexNer)
├── scrub.rs     — Full pipeline: NER → alias → redact → compress → ledger
├── compress.rs  — Token-Tax compression (schema extraction + row compaction)
└── ledger.rs    — SQLite Risk Ledger (rusqlite, bundled)
```

### Performance Notes

- **Parallel NER**: all entries scanned concurrently via [Rayon](https://docs.rs/rayon)
- **Parallel rewrite**: alias application runs concurrently after sequential alias registration
- **Zero-copy NER**: spans carry byte offsets; no intermediate `String` allocations during scan
- **Static regexes**: compiled once per process via `OnceLock`
- **Release binary**: LTO + single codegen unit + panic=abort + symbol stripping

---

## Building & Testing

```bash
# Run all tests
cargo test

# Build optimised release binary
cargo build --release

# Check with Clippy
cargo clippy -- -D warnings

# Generate docs
cargo doc --open
```

---

## License

MIT — see [LICENSE](LICENSE).
