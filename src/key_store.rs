//! Local persistent key store for mapping thumbprints to key metadata.
//!
//! The EKM provider needs to return the `PROVIDER_KEY_NAME` back to SQL
//! Server when it calls `GetKeyInfoByThumb` or `GetKeyInfoByName`.  The
//! Cosmian KMS `GetAttributes` response does not include the user-supplied
//! key name, so we persist a local mapping.
//!
//! Stored at `%PROGRAMDATA%\Cosmian\EKM\keystore.json`.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Mutex;
use tracing::{info, warn};

/// Entry for a single key in the local store.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyEntry {
    /// The `PROVIDER_KEY_NAME` from SQL Server.
    pub key_name: String,
    /// Whether this is a symmetric key.
    pub is_symmetric: bool,
    /// The algorithm bit length (e.g. 2048 for RSA, 256 for AES).
    pub bit_len: u32,
}

/// Thread-safe in-memory + file-backed key store.
///
/// Keys are indexed by the hex-encoded 16-byte thumbprint (UUID).
pub struct KeyStore {
    inner: Mutex<HashMap<String, KeyEntry>>,
    path: PathBuf,
}

impl KeyStore {
    /// Create a new store, loading any existing file.
    pub fn new(path: PathBuf) -> Self {
        let map = match std::fs::read_to_string(&path) {
            Ok(data) => serde_json::from_str(&data).unwrap_or_default(),
            Err(_) => HashMap::new(),
        };
        info!(path = %path.display(), entries = map.len(), "KeyStore loaded");
        Self {
            inner: Mutex::new(map),
            path,
        }
    }

    /// Insert (or update) a key entry and persist to disk.
    pub fn insert(&self, thumb_hex: &str, entry: KeyEntry) {
        let mut map = self.inner.lock().unwrap();
        map.insert(thumb_hex.to_string(), entry);
        self.persist(&map);
    }

    /// Look up a key by its hex-encoded thumbprint.
    pub fn get(&self, thumb_hex: &str) -> Option<KeyEntry> {
        let map = self.inner.lock().unwrap();
        map.get(thumb_hex).cloned()
    }

    /// Look up a key by its name (PROVIDER_KEY_NAME).
    /// Returns `(thumb_hex, entry)`.
    pub fn get_by_name(&self, key_name: &str) -> Option<(String, KeyEntry)> {
        let map = self.inner.lock().unwrap();
        map.iter()
            .find(|(_, v)| v.key_name == key_name)
            .map(|(k, v)| (k.clone(), v.clone()))
    }

    /// Remove a key entry and persist.
    pub fn remove(&self, thumb_hex: &str) {
        let mut map = self.inner.lock().unwrap();
        map.remove(thumb_hex);
        self.persist(&map);
    }

    fn persist(&self, map: &HashMap<String, KeyEntry>) {
        if let Some(parent) = self.path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        match serde_json::to_string_pretty(map) {
            Ok(json) => {
                if let Err(e) = std::fs::write(&self.path, json) {
                    warn!(path = %self.path.display(), error = %e, "KeyStore: failed to persist");
                }
            }
            Err(e) => warn!(error = %e, "KeyStore: failed to serialize"),
        }
    }
}
