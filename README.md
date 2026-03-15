# Airlock

[![CI](https://github.com/OxideOps/airlock/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/OxideOps/airlock/actions/workflows/ci.yml)
[![Crates.io](https://img.shields.io/crates/v/airlock.svg)](https://crates.io/crates/airlock)
[![PyPI](https://img.shields.io/pypi/v/airlock.svg)](https://pypi.org/project/airlock/)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.75%2B-orange.svg)](https://www.rust-lang.org)

**Local-first AI security gateway.** Redact PII, cut LLM token costs, and maintain a full audit trail — without sending a single byte to the cloud.

```bash
pip install airlock          # Python SDK
cargo install airlock        # CLI
```

---

## The Problem

You have logs, support tickets, or user data you want to send to an AI model. But that data contains names, emails, phone numbers, and credit card numbers. Sending it to OpenAI or Claude as-is creates GDPR, HIPAA, and SOC2 exposure.

Airlock sits between your data and the model. It scrubs PII, compresses the JSON to cut token costs, and writes an auditable record of what was processed — all locally, zero network calls.

---

## Python SDK

```python
import airlock, json

records = [
    {"user": "Alice Johnson", "email": "alice@corp.com", "action": "login",  "ip": "192.168.1.1"},
    {"user": "Bob Smith",     "email": "bob@corp.com",   "action": "logout", "ip": "10.0.0.2"},
]

result = airlock.scrub(json.dumps(records), salt="my-org-secret")

print(result.pii_count)      # 6
print(result.risk_score)     # 75.0
print(result.reduction_pct)  # 38.4

for swap in result.swaps:
    print(f"{swap['original']} → {swap['synthetic']}")
# alice@corp.com    → alias_a@redacted.dev
# Alice Johnson     → User_A
# 192.168.1.1       → IP_A
# bob@corp.com      → alias_b@redacted.dev
# Bob Smith         → User_B
# 10.0.0.2          → IP_B

# Feed the clean JSON directly to your LLM
response = openai_client.chat(messages=[{"role": "user", "content": result.json_str}])
```

### API

```python
# Scrub PII + compress
result = airlock.scrub(json_str, salt=None, db_path=None)
result.json_str       # str   — scrubbed, compressed JSON
result.pii_count      # int   — total PII instances found
result.risk_score     # float — 0–100 density score
result.reduction_pct  # float — token reduction percentage
result.swaps          # list[dict] — [{original, synthetic, entity_type}]
result.ledger_id      # int | None — SQLite row ID if db_path was set

# Compress only (no PII detection)
result = airlock.compress(json_str)
result.json_str
result.tokens_before
result.tokens_after
result.reduction_pct
result.entry_count
```

---

## CLI

```bash
# Scrub PII from a JSON or NDJSON file
airlock scrub logs.json --diff

# Stable cross-run aliases (same person → same alias across files)
airlock scrub logs.json --salt my-secret --diff > clean.json

# Compress only
airlock compress logs.json

# View audit history
airlock ledger --last 20
```

### All flags

```
airlock scrub <FILE>
  --salt <SALT>       Cross-run stable aliases via SHA-256(salt ‖ entity ‖ token)
  --diff              Print every original → alias swap to stderr
  --db <FILE>         SQLite ledger path [default: airlock_ledger.db]
  --output <FORMAT>   pretty (default) | compact
  -v / -vv / -vvv     Verbosity (info / debug / trace)

airlock compress <FILE>
  --output <FORMAT>   pretty | compact

airlock ledger
  --last <N>          Show N most recent entries [default: 10]
  --db <FILE>         SQLite ledger path
```

---

## What Gets Redacted

| PII Type | Example Input | Alias |
|---|---|---|
| Full name | `Alice Johnson` | `User_A` |
| Email | `alice@corp.com` | `alias_a@redacted.dev` |
| Phone | `555-867-5309` | `Phone_A` |
| SSN | `123-45-6789` | `SSN_A` |
| Credit card | `4111 1111 1111 1111` | `Card_A` |
| IPv4 address | `192.168.1.100` | `IP_A` |

Aliases are consistent within a run — `User_A` always refers to the same person, so AI models can still reason about behavior patterns without seeing real identities.

---

## Config File

Drop a `.airlock.toml` in your project directory to set defaults:

```toml
[scrub]
salt = "my-org-secret"          # stable cross-run aliases
db   = "~/.airlock/ledger.db"   # shared ledger location

[redact]
ip_addresses = false            # keep IPs as-is

[[rules]]
name         = "EmployeeId"
pattern      = "EMP-\\d{5}"
alias_prefix = "Emp"            # EMP-00042 → Emp_A
```

CLI flags always take precedence over the config file.

---

## Token Compression

Repeated JSON keys are expensive for LLMs. Airlock extracts them into a single schema header:

**Before** (keys repeated on every row):
```json
[
  {"timestamp": "2026-01-01T10:00:00Z", "user": "User_A", "action": "login"},
  {"timestamp": "2026-01-01T10:01:00Z", "user": "User_B", "action": "logout"}
]
```

**After** (keys extracted once, 43% fewer tokens):
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

Typical savings: **20–60%** on structured log data.

---

## Cross-Run Stable Aliases (`--salt`)

By default, aliases are assigned in encounter order: the first name seen becomes `User_A`, the second `User_B`. This is consistent within a run but may differ between runs.

Pass `--salt <secret>` to enable **cross-run stability**: every alias is derived from `SHA-256(salt ‖ entity_type ‖ token)` fed into a `ChaCha8Rng`. The same real identity always produces the same alias, regardless of which file is processed or what order records appear in.

```bash
airlock scrub january.json --salt prod-2026 > jan_clean.json
airlock scrub february.json --salt prod-2026 > feb_clean.json
# "Alice Johnson" → "User_GKQT" in both files
```

> **Keep your salt secret.** It is the only thing preventing alias reversal.

---

## Audit Ledger

Every `airlock scrub` run writes a row to a local SQLite database:

```
  ╔══════╦════════════════════╦══════════╦═════════╦══════════╦══════════════════╗
  ║  ID  ║  Timestamp         ║ Entries  ║  PII    ║  Risk    ║  Compression     ║
  ╠══════╬════════════════════╬══════════╬═════════╬══════════╬══════════════════╣
  ║    1 ║ 2026-01-15T10:00   ║      500 ║      84 ║  42/100  ║          38.4%   ║
  ║    2 ║ 2026-01-15T14:22   ║     1200 ║     203 ║  71/100  ║          51.2%   ║
  ╚══════╩════════════════════╩══════════╩═════════╩══════════╩══════════════════╝
```

The ledger stores counts and statistics only — never the original PII values.

---

## Security Guarantees

| | |
|---|---|
| **Zero network calls** | Airlock never opens a socket. All processing is in-process on your machine. |
| **No PII on disk** | The ledger stores counts and risk scores only — never names, emails, or the aliases themselves. |
| **Alias irreversibility** | In seeded mode, reversing an alias requires knowledge of your salt. |
| **Deterministic** | The same input + same salt always produces the same output. Fully auditable. |
| **No third-party AI** | The NER engine runs locally via compiled regex patterns. Your data never touches an external API. |

---

## Installation

### Python (recommended)

```bash
pip install airlock
```

Requires Python 3.8+. Pre-built wheels for Linux, macOS, and Windows.

### CLI — Homebrew

```bash
brew install OxideOps/homebrew-tap/airlock   # coming soon
```

### CLI — Cargo

```bash
cargo install airlock
```

### CLI — pre-built binary

Download from [GitHub Releases](https://github.com/OxideOps/airlock/releases). Single static binary, no runtime dependencies.

---

## Building from Source

```bash
git clone https://github.com/OxideOps/airlock
cd airlock

# Run tests
cargo test

# Build release binary
cargo build --release

# Build Python wheel (requires maturin: pip install maturin)
maturin develop --features python

# Lint
cargo clippy -- -D warnings
```

---

## Architecture

```
src/
├── lib.rs       — Library entry point; Python module registration
├── main.rs      — CLI (clap): scrub / compress / ledger commands
├── types.rs     — EntityType, PiiSpan, SwapRecord, LedgerEntry
├── ner.rs       — Ner trait + RegexNer (6 built-in patterns + custom rules)
├── scrub.rs     — Pipeline: NER → alias → redact → compress → ledger
├── compress.rs  — Token-Tax compression (schema extraction + row compaction)
├── ledger.rs    — SQLite Risk Ledger (rusqlite, bundled)
└── config.rs    — .airlock.toml loader
```

### Performance

- Parallel NER scan and alias application via [Rayon](https://docs.rs/rayon)
- Static regexes compiled once per process via `OnceLock`
- Zero-copy span detection using byte offsets
- ~3.5 MB statically-linked binary with no runtime dependencies

---

## License

Apache 2.0 — see [LICENSE](LICENSE).
