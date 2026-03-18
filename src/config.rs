//! Runtime configuration for the Cosmian EKM provider.
//!
//! Configuration is read from `%PROGRAMDATA%\Cosmian\EKM\config.toml`
//! (typically `C:\ProgramData\Cosmian\EKM\config.toml`) at the time the
//! first session is opened.  All keys are optional; missing keys fall back
//! to the compiled-in defaults listed below.
//!
//! ## Example `config.toml`
//!
//! ```toml
//! # Maximum number of seconds a session can be idle before it is considered
//! # stale.  Every access resets the TTL clock.
//! # Default: 1800 (30 minutes)
//! max_age_seconds = 1800
//!
//! # How often (in seconds) the background stale-session collector thread
//! # wakes to bulk-evict expired sessions.
//! # Default: 120 (2 minutes)
//! stale_collector_period_seconds = 120
//!
//! [kms]
//! server_url = "https://kms.example.com:9998"
//! accept_invalid_certs = false
//!
//! [[kms.certificates]]
//! username = "admin"
//! client_cert = "C:\\ProgramData\\Cosmian\\EKM\\certificates\\admin.cert.pem"
//! client_key  = "C:\\ProgramData\\Cosmian\\EKM\\certificates\\admin.key.pem"
//! ```

use serde::Deserialize;
use tracing::{info, warn};

// ---------------------------------------------------------------------------
// Defaults
// ---------------------------------------------------------------------------

const DEFAULT_MAX_AGE_SECONDS: u64 = 30 * 60; // 30 minutes
const DEFAULT_STALE_COLLECTOR_PERIOD_SECONDS: u64 = 2 * 60; // 2 minutes

fn default_max_age_seconds() -> u64 {
    DEFAULT_MAX_AGE_SECONDS
}
fn default_stale_collector_period_seconds() -> u64 {
    DEFAULT_STALE_COLLECTOR_PERIOD_SECONDS
}

// ---------------------------------------------------------------------------
// EkmConfig
// ---------------------------------------------------------------------------

/// Flat TOML configuration for the EKM provider.
#[derive(Debug, Deserialize)]
pub struct EkmConfig {
    /// Maximum idle lifetime of a session in seconds (default: 1800 / 30 min).
    #[serde(default = "default_max_age_seconds")]
    pub max_age_seconds: u64,

    /// Background stale-eviction period in seconds (default: 120 / 2 min).
    #[serde(default = "default_stale_collector_period_seconds")]
    pub stale_collector_period_seconds: u64,

    /// Cosmian KMS connection settings (optional; key-management operations
    /// will fail with `NotSupported` when absent).
    #[serde(default)]
    pub kms: KmsConfig,
}

impl Default for EkmConfig {
    fn default() -> Self {
        Self {
            max_age_seconds: DEFAULT_MAX_AGE_SECONDS,
            stale_collector_period_seconds: DEFAULT_STALE_COLLECTOR_PERIOD_SECONDS,
            kms: KmsConfig::default(),
        }
    }
}

// ---------------------------------------------------------------------------
// KmsConfig
// ---------------------------------------------------------------------------

/// `[kms]` section — connection and mTLS settings for the Cosmian KMS.
#[derive(Debug, Deserialize, Default)]
pub struct KmsConfig {
    /// Base URL of the Cosmian KMS REST API, e.g. `https://kms.example.com:9998`.
    pub server_url: Option<String>,

    /// Accept invalid / self-signed TLS server certificates.
    /// Only enable for development.
    #[serde(default)]
    pub accept_invalid_certs: bool,

    /// Per-user client certificate entries for mTLS authentication.
    #[serde(default)]
    pub certificates: Vec<ClientCertEntry>,
}

/// `[[kms.certificates]]` — maps a SQL Server login (username) to a PEM
/// client certificate + key pair used for mTLS with the Cosmian KMS.
#[derive(Debug, Deserialize)]
pub struct ClientCertEntry {
    /// SQL Server login name (matched case-insensitively).
    pub username: String,
    /// Path to the PEM-encoded client certificate file.
    pub client_cert: String,
    /// Path to the PEM-encoded client private key file.
    pub client_key: String,
}

/// Return the EKM configuration directory: `%PROGRAMDATA%\Cosmian\EKM`.
pub fn ekm_config_dir() -> std::path::PathBuf {
    std::env::var("PROGRAMDATA")
        .map(|p| std::path::PathBuf::from(p).join("Cosmian").join("EKM"))
        .unwrap_or_else(|_| std::path::PathBuf::from(r"C:\ProgramData\Cosmian\EKM"))
}

impl EkmConfig {
    /// Load configuration from `%PROGRAMDATA%\Cosmian\EKM\config.toml`.
    ///
    /// * If the file does not exist, returns defaults silently (logged at INFO).
    /// * If the file exists but cannot be parsed, returns defaults and logs a WARNING.
    pub fn load() -> Self {
        let config_path = ekm_config_dir().join("config.toml");

        match std::fs::read_to_string(&config_path) {
            Ok(contents) => match toml::from_str::<EkmConfig>(&contents) {
                Ok(cfg) => {
                    info!(
                        config_path = %config_path.display(),
                        max_age_seconds = cfg.max_age_seconds,
                        stale_collector_period_seconds = cfg.stale_collector_period_seconds,
                        "EKM configuration loaded"
                    );
                    cfg
                }
                Err(e) => {
                    warn!(
                        config_path = %config_path.display(),
                        error = %e,
                        max_age_seconds = DEFAULT_MAX_AGE_SECONDS,
                        stale_collector_period_seconds = DEFAULT_STALE_COLLECTOR_PERIOD_SECONDS,
                        "config.toml parse error — using defaults"
                    );
                    Self::default()
                }
            },
            Err(_) => {
                // File simply doesn't exist yet — perfectly normal on first run.
                info!(
                    config_path = %config_path.display(),
                    max_age_seconds = DEFAULT_MAX_AGE_SECONDS,
                    stale_collector_period_seconds = DEFAULT_STALE_COLLECTOR_PERIOD_SECONDS,
                    "config.toml not found — using defaults"
                );
                Self::default()
            }
        }
    }
}
