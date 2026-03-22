//! `.airlock.toml` configuration loader.
//!
//! Airlock looks for `.airlock.toml` in the current working directory.
//! All fields are optional — a missing file returns [`AirlockConfig::default()`].
//!
//! ```toml
//! [scrub]
//! salt = "my-org-secret"
//! db   = "~/.airlock/ledger.db"
//!
//! [redact]
//! ip_addresses = false   # keep IPs unchanged
//!
//! [[rules]]
//! name         = "EmployeeId"
//! pattern      = "EMP-\\d{5}"
//! alias_prefix = "Emp"
//! ```

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::Deserialize;

/// Top-level configuration loaded from `.airlock.toml`.
#[derive(Debug, Deserialize, Default)]
pub struct AirlockConfig {
    #[serde(default)]
    pub scrub: ScrubSection,

    #[serde(default)]
    pub redact: RedactSection,

    #[serde(default)]
    pub rules: Vec<CustomRuleConfig>,

    #[serde(default)]
    pub server: ServerSection,
}

/// `[server]` section — HTTP server settings for `airlock serve`.
#[derive(Debug, Deserialize)]
pub struct ServerSection {
    /// Interface to bind on.
    #[serde(default = "default_host")]
    pub host: String,
    /// TCP port to listen on.
    #[serde(default = "default_port")]
    pub port: u16,
}

impl Default for ServerSection {
    fn default() -> Self {
        Self {
            host: default_host(),
            port: default_port(),
        }
    }
}

fn default_host() -> String {
    "127.0.0.1".to_string()
}

fn default_port() -> u16 {
    7777
}

/// `[scrub]` section — default session settings.
#[derive(Debug, Deserialize, Default)]
pub struct ScrubSection {
    /// Default salt for stable cross-run aliases.
    pub salt: Option<String>,
    /// Default path to the SQLite ledger database.
    pub db: Option<PathBuf>,
}

/// `[redact]` section — toggle which PII types are detected.
#[derive(Debug, Deserialize)]
pub struct RedactSection {
    #[serde(default = "default_true")]
    pub names: bool,
    #[serde(default = "default_true")]
    pub emails: bool,
    #[serde(default = "default_true")]
    pub phones: bool,
    #[serde(default = "default_true")]
    pub ssns: bool,
    #[serde(default = "default_true")]
    pub credit_cards: bool,
    #[serde(default = "default_true")]
    pub ip_addresses: bool,
    #[serde(default = "default_true")]
    pub jwt_tokens: bool,
    #[serde(default = "default_true")]
    pub aws_keys: bool,
    #[serde(default = "default_true")]
    pub env_secrets: bool,
}

impl Default for RedactSection {
    fn default() -> Self {
        Self {
            names: true,
            emails: true,
            phones: true,
            ssns: true,
            credit_cards: true,
            ip_addresses: true,
            jwt_tokens: true,
            aws_keys: true,
            env_secrets: true,
        }
    }
}

fn default_true() -> bool {
    true
}

/// One entry in the `[[rules]]` array — a custom regex-based PII pattern.
#[derive(Debug, Deserialize)]
pub struct CustomRuleConfig {
    /// Human-readable label (shown in reports and used as the `Custom` entity name).
    pub name: String,
    /// A Rust-compatible regex pattern. Backslashes must be escaped: `\\d`.
    pub pattern: String,
    /// Prefix for synthetic aliases, e.g. `"Emp"` → `"Emp_A"`.
    pub alias_prefix: String,
}

/// Load `.airlock.toml` from the current working directory.
///
/// Returns `AirlockConfig::default()` if the file does not exist, so callers
/// never need to special-case a missing config file.
pub fn load() -> Result<AirlockConfig> {
    load_from(Path::new(".airlock.toml"))
}

/// Load config from an explicit path (useful for tests).
pub fn load_from(path: &Path) -> Result<AirlockConfig> {
    if !path.exists() {
        return Ok(AirlockConfig::default());
    }
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("Cannot read config '{}'", path.display()))?;
    toml::from_str(&text).with_context(|| format!("Invalid TOML in '{}'", path.display()))
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_file_returns_defaults() {
        let cfg = load_from(Path::new("/nonexistent/.airlock.toml")).unwrap();
        assert!(cfg.scrub.salt.is_none());
        assert!(cfg.redact.names);
        assert!(cfg.redact.ip_addresses);
        assert!(cfg.rules.is_empty());
    }

    #[test]
    fn all_redact_flags_false() {
        let src = r#"
            [redact]
            names        = false
            emails       = false
            phones       = false
            ssns         = false
            credit_cards = false
            ip_addresses = false
        "#;
        let cfg: AirlockConfig = toml::from_str(src).unwrap();
        assert!(!cfg.redact.names);
        assert!(!cfg.redact.emails);
        assert!(!cfg.redact.phones);
        assert!(!cfg.redact.ssns);
        assert!(!cfg.redact.credit_cards);
        assert!(!cfg.redact.ip_addresses);
    }

    #[test]
    fn invalid_toml_returns_error() {
        let result = toml::from_str::<AirlockConfig>("not valid toml ][");
        assert!(result.is_err());
    }

    #[test]
    fn parses_full_config() {
        let src = r#"
            [scrub]
            salt = "mysecret"

            [redact]
            ip_addresses = false

            [[rules]]
            name         = "EmployeeId"
            pattern      = "EMP-\\d{5}"
            alias_prefix = "Emp"
        "#;
        let cfg: AirlockConfig = toml::from_str(src).unwrap();
        assert_eq!(cfg.scrub.salt.as_deref(), Some("mysecret"));
        assert!(!cfg.redact.ip_addresses);
        assert_eq!(cfg.rules.len(), 1);
        assert_eq!(cfg.rules[0].name, "EmployeeId");
        assert_eq!(cfg.rules[0].alias_prefix, "Emp");
    }
}
