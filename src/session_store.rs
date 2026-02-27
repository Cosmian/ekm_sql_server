//! Thread-safe session store with automatic stale-session eviction.
//!
//! # Design
//!
//! `SessionStore` wraps a `Mutex<HashMap<u32, SessionValue>>` and adds:
//!
//! * A **maximum session age** (`max_age_seconds`): every access (insert *or*
//!   read) resets the session's `stale_at` deadline to `now + max_age`.
//!   Accessing a session whose deadline has already passed returns `None` and
//!   removes the entry immediately.
//!
//! * A **background collector thread** that wakes every
//!   `stale_collector_period_seconds` seconds and bulk-removes any sessions
//!   whose `stale_at` deadline has passed since the last scan.
//!   The thread exits cleanly when `SessionStore` is dropped.
//!
//! `SessionStore` is `Send + Sync` and can therefore live in a `OnceLock<…>`
//! static without an outer `Mutex`.

use std::collections::HashMap;
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};
use tracing::{debug, info, warn};

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Credential data captured at `SqlCryptOpenSession` time.
/// All strings are decoded UTF-8 (converted from the caller's UTF-16LE).
pub struct SessionCredential {
    pub username: String,
    pub password: String,
}

/// Per-session state stored in the `SessionStore`.
pub struct SessionValue {
    pub credential: SessionCredential,
    /// Monotonic deadline: the session is stale once `Instant::now() >= stale_at`.
    pub stale_at: Instant,
}

// ---------------------------------------------------------------------------
// SessionStore
// ---------------------------------------------------------------------------

type InnerMap = Mutex<HashMap<u32, SessionValue>>;

/// `(stopped_flag, condvar)` — used to signal the collector thread to exit.
type ShutdownSignal = Arc<(Mutex<bool>, Condvar)>;

/// Thread-safe session store with TTL-based eviction.
pub struct SessionStore {
    max_age: Duration,
    map: Arc<InnerMap>,
    shutdown: ShutdownSignal,
    /// Wrapped in `Mutex` solely to satisfy `Sync` (needed for `OnceLock<SessionStore>`).
    /// `JoinHandle` is `Send` but not `Sync`; `Mutex<T: Send>` is `Sync`.
    collector_thread: Mutex<Option<std::thread::JoinHandle<()>>>,
}

impl SessionStore {
    /// Create a new `SessionStore` and immediately start the background
    /// stale-session collector thread.
    ///
    /// # Parameters
    /// * `max_age_seconds` – seconds a session can be idle before it is
    ///   considered stale.  Every access resets the clock.
    /// * `stale_collector_period_seconds` – how often (in seconds) the
    ///   background thread wakes to bulk-evict stale sessions.
    pub fn new(max_age_seconds: u64, stale_collector_period_seconds: u64) -> Self {
        let max_age = Duration::from_secs(max_age_seconds);
        let map: Arc<InnerMap> = Arc::new(Mutex::new(HashMap::new()));
        let shutdown: ShutdownSignal = Arc::new((Mutex::new(false), Condvar::new()));

        let map_bg = Arc::clone(&map);
        let shutdown_bg = Arc::clone(&shutdown);
        let period = Duration::from_secs(stale_collector_period_seconds);

        let handle = std::thread::Builder::new()
            .name("ekm-session-collector".into())
            .spawn(move || {
                info!(
                    max_age_seconds,
                    stale_collector_period_seconds, "Stale session collector thread started"
                );
                loop {
                    // Sleep for `period`, but wake immediately on shutdown signal.
                    let (stopped_lock, cvar) = &*shutdown_bg;
                    let guard = stopped_lock.lock().unwrap_or_else(|p| p.into_inner());
                    let (guard, _timeout) = cvar
                        .wait_timeout(guard, period)
                        .unwrap_or_else(|p| p.into_inner());
                    if *guard {
                        break; // shutdown requested
                    }
                    drop(guard);

                    // Evict all sessions whose deadline has passed.
                    let now = Instant::now();
                    let mut map = map_bg.lock().unwrap_or_else(|p| p.into_inner());
                    // Collect stale IDs before retain so we can warn per session.
                    let stale_ids: Vec<u32> = map
                        .iter()
                        .filter(|(_, v)| v.stale_at <= now)
                        .map(|(id, _)| *id)
                        .collect();
                    for &id in &stale_ids {
                        warn!(session_id = id, "Session evicted by stale collector");
                    }
                    map.retain(|_, v| v.stale_at > now);
                    if !stale_ids.is_empty() {
                        info!(
                            removed = stale_ids.len(),
                            remaining = map.len(),
                            "Stale session collector: eviction complete"
                        );
                    } else {
                        debug!(
                            remaining = map.len(),
                            "Stale session collector: no stale sessions found"
                        );
                    }
                }
                debug!("Stale session collector thread exiting");
            })
            .ok();

        Self {
            max_age,
            map,
            shutdown,
            collector_thread: Mutex::new(handle),
        }
    }

    // -----------------------------------------------------------------------
    // Public API
    // -----------------------------------------------------------------------

    /// Insert a new session.  The TTL clock starts immediately.
    pub fn insert(&self, id: u32, credential: SessionCredential) {
        let stale_at = Instant::now() + self.max_age;
        let mut map = self.map.lock().unwrap_or_else(|p| p.into_inner());
        map.insert(
            id,
            SessionValue {
                credential,
                stale_at,
            },
        );
    }

    /// Remove a session unconditionally (called on `SqlCryptCloseSession`).
    pub fn remove(&self, id: u32) {
        let mut map = self.map.lock().unwrap_or_else(|p| p.into_inner());
        map.remove(&id);
    }

    /// Run a closure with a shared reference to the session's credential,
    /// refreshing the TTL on every call.
    ///
    /// Returns `None` if the session does not exist or has gone stale
    /// (in which case the entry is evicted immediately).
    pub fn with_session<F, R>(&self, id: u32, f: F) -> Option<R>
    where
        F: FnOnce(&SessionCredential) -> R,
    {
        let now = Instant::now();
        let new_stale_at = now + self.max_age;
        let mut map = self.map.lock().unwrap_or_else(|p| p.into_inner());
        match map.get_mut(&id) {
            Some(v) if v.stale_at > now => {
                // Refresh TTL on access.
                v.stale_at = new_stale_at;
                Some(f(&v.credential))
            }
            Some(_) => {
                // Session exists but is stale — evict eagerly.
                warn!(session_id = id, "Session accessed but stale; evicting");
                map.remove(&id);
                None
            }
            None => None,
        }
    }

    /// Returns `true` if the session exists and is not stale, also refreshing its TTL.
    pub fn is_valid(&self, id: u32) -> bool {
        self.with_session(id, |_| ()).is_some()
    }

    /// Returns the number of live (non-stale) sessions currently in the store.
    pub fn len(&self) -> usize {
        let now = Instant::now();
        let map = self.map.lock().unwrap_or_else(|p| p.into_inner());
        map.values().filter(|v| v.stale_at > now).count()
    }
}

impl Drop for SessionStore {
    fn drop(&mut self) {
        // Signal the collector thread to stop.
        let (stopped_lock, cvar) = &*self.shutdown;
        *stopped_lock.lock().unwrap_or_else(|p| p.into_inner()) = true;
        cvar.notify_all();

        // Join the thread so it has flushed any in-progress log records.
        if let Ok(mut guard) = self.collector_thread.lock() {
            if let Some(handle) = guard.take() {
                let _ = handle.join();
            }
        }
        debug!("SessionStore dropped");
    }
}
