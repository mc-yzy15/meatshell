//! Session / application configuration.
//!
//! Persists a simple JSON file under the platform's standard config dir
//! (e.g. `%APPDATA%/meatshell/sessions.json` on Windows).
//!
//! Passwords are stored in the OS keychain when the `keyring-storage` feature
//! is enabled. The JSON file stores a reference key instead of the plaintext
//! password.

use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result};
use directories::ProjectDirs;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::Zeroize;

// ---------------------------------------------------------------------------
// Secret type with memory zeroing
// ---------------------------------------------------------------------------

/// A secret string (e.g. a session password) whose heap buffer is zeroed when
/// it is dropped, so plaintext credentials don't survive in freed memory and
/// turn up in core dumps, a debugger, or `/proc/<pid>/mem`.  `Clone` makes an
/// independent copy that is likewise zeroed on its own drop, and `Debug` is
/// redacted so a password can never be logged by accident.
#[derive(Clone, Default)]
pub struct Secret(String);

impl Secret {
    pub fn new(s: impl Into<String>) -> Self {
        Secret(s.into())
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never reveal the contents in logs / debug output.
        f.write_str(if self.0.is_empty() { "Secret(\"\")" } else { "Secret(***)" })
    }
}

impl Serialize for Secret {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for Secret {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Ok(Secret(String::deserialize(d)?))
    }
}

// ---------------------------------------------------------------------------
// Keyring password storage
// ---------------------------------------------------------------------------

/// Service name used for keyring entries.
const KEYRING_SERVICE: &str = "meatshell";

/// Generate the keyring entry key for a session.
fn keyring_key(session_id: &str) -> String {
    format!("session/{}", session_id)
}

/// Store a password in the OS keyring.
#[cfg(feature = "keyring-storage")]
fn store_password(session_id: &str, password: &str) -> Result<()> {
    let entry = keyring::Entry::new(KEYRING_SERVICE, &keyring_key(session_id))
        .context("create keyring entry")?;
    entry.set_password(password).context("store password in keyring")?;
    tracing::debug!("password stored in keyring for session {}", session_id);
    Ok(())
}

/// Retrieve a password from the OS keyring.
#[cfg(feature = "keyring-storage")]
fn get_password(session_id: &str) -> Option<String> {
    let entry = keyring::Entry::new(KEYRING_SERVICE, &keyring_key(session_id)).ok()?;
    match entry.get_password() {
        Ok(pw) => {
            tracing::debug!("password retrieved from keyring for session {}", session_id);
            Some(pw)
        }
        Err(keyring::Error::NoEntry) => {
            tracing::debug!("no keyring entry for session {}", session_id);
            None
        }
        Err(e) => {
            tracing::warn!("keyring error for session {}: {}", session_id, e);
            None
        }
    }
}

/// Delete a password from the OS keyring.
#[cfg(feature = "keyring-storage")]
fn delete_password(session_id: &str) -> Result<()> {
    let entry = keyring::Entry::new(KEYRING_SERVICE, &keyring_key(session_id))
        .context("create keyring entry for deletion")?;
    match entry.delete_credential() {
        Ok(()) => {
            tracing::debug!("password deleted from keyring for session {}", session_id);
            Ok(())
        }
        Err(keyring::Error::NoEntry) => {
            // Already gone, that's fine.
            Ok(())
        }
        Err(e) => {
            tracing::warn!("keyring delete error for session {}: {}", session_id, e);
            Err(anyhow::anyhow!("keyring delete error: {}", e))
        }
    }
}

// Non-keyring fallback: passwords stored in JSON (insecure, for dev/testing).
#[cfg(not(feature = "keyring-storage"))]
fn store_password(_session_id: &str, _password: &str) -> Result<()> {
    // Password will be stored in JSON directly (handled by caller).
    Ok(())
}

#[cfg(not(feature = "keyring-storage"))]
fn get_password(_session_id: &str) -> Option<String> {
    // Password should be in JSON.
    None
}

#[cfg(not(feature = "keyring-storage"))]
fn delete_password(_session_id: &str) -> Result<()> {
    Ok(())
}

// ---------------------------------------------------------------------------
// Authentication method
// ---------------------------------------------------------------------------

/// How a session authenticates.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum AuthMethod {
    Password,
    Key,
}

impl AuthMethod {
    pub fn as_str(&self) -> &'static str {
        match self {
            AuthMethod::Password => "password",
            AuthMethod::Key => "key",
        }
    }

    pub fn from_str(s: &str) -> Self {
        match s {
            "key" => AuthMethod::Key,
            _ => AuthMethod::Password,
        }
    }
}

// ---------------------------------------------------------------------------
// Session
// ---------------------------------------------------------------------------

/// A single saved SSH target.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub id: String,
    pub name: String,
    pub host: String,
    pub port: u16,
    pub user: String,
    pub auth: AuthMethod,
    /// Password for password auth. When `keyring-storage` is enabled, this
    /// field is empty in the JSON file; the actual password is in the keyring.
    #[serde(default)]
    pub password: Secret,
    #[serde(default)]
    pub private_key_path: String,
    /// Optional outbound proxy, e.g. "socks5://127.0.0.1:1080" or
    /// "http://user:pass@host:8080". Empty = use $ALL_PROXY, else direct.
    #[serde(default)]
    pub proxy: String,
    #[serde(default)]
    pub last_used: Option<String>,
    /// Group/folder name for organizing sessions.
    #[serde(default)]
    pub group: Option<String>,
}

impl Session {
    pub fn new_empty() -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            name: String::new(),
            host: String::new(),
            port: 22,
            user: "root".into(),
            auth: AuthMethod::Password,
            password: Secret::default(),
            private_key_path: String::new(),
            proxy: String::new(),
            last_used: None,
            group: None,
        }
    }

    /// Get the actual password, checking keyring first.
    pub fn get_password(&self) -> Secret {
        // Try keyring first (if enabled).
        if let Some(pw) = get_password(&self.id) {
            return Secret::new(pw);
        }
        // Fall back to stored password (for backward compatibility or non-keyring builds).
        self.password.clone()
    }

    /// Set the password, storing in keyring if enabled.
    pub fn set_password(&mut self, password: &str) {
        #[cfg(feature = "keyring-storage")]
        {
            if !password.is_empty() {
                if let Err(e) = store_password(&self.id, password) {
                    tracing::warn!("failed to store password in keyring: {}", e);
                    // Fall back to storing in the struct (will be serialized to JSON).
                    self.password = Secret::new(password);
                    return;
                }
                // Clear the in-memory password so it doesn't get serialized to JSON.
                self.password = Secret::default();
            } else {
                // Empty password - clear both keyring and struct.
                let _ = delete_password(&self.id);
                self.password = Secret::default();
            }
        }
        #[cfg(not(feature = "keyring-storage"))]
        {
            self.password = Secret::new(password);
        }
    }

    /// Delete the password from keyring (called when session is deleted).
    pub fn clear_password(&self) {
        let _ = delete_password(&self.id);
    }
}

// ---------------------------------------------------------------------------
// Config file and store
// ---------------------------------------------------------------------------

/// On-disk layout. Keep additive to ease forward-compat.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ConfigFile {
    #[serde(default)]
    pub sessions: Vec<Session>,
    /// Preset SFTP download directory. Empty = ask each time.
    #[serde(default)]
    pub download_dir: String,
    /// UI language code: "zh" (default) or "en".
    #[serde(default)]
    pub language: String,
    /// Theme mode: "dark" (default), "light", or "system".
    #[serde(default)]
    pub theme: String,
}

pub struct ConfigStore {
    path: PathBuf,
    cache: ConfigFile,
}

impl ConfigStore {
    /// Load (or initialise) the config file. On any parse error we back up the
    /// broken file and start fresh — losing saved sessions is better than
    /// crashing at launch.
    pub fn load() -> Result<Self> {
        let path = Self::config_path()?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).with_context(|| {
                format!("failed to create config dir {}", parent.display())
            })?;
        }

        let cache = if path.exists() {
            let raw = fs::read_to_string(&path)
                .with_context(|| format!("failed to read {}", path.display()))?;
            match serde_json::from_str::<ConfigFile>(&raw) {
                Ok(cfg) => cfg,
                Err(err) => {
                    let backup = path.with_extension("json.broken");
                    let _ = fs::rename(&path, &backup);
                    tracing::warn!(
                        "config file was corrupt ({err}); backed up to {}",
                        backup.display()
                    );
                    ConfigFile::default()
                }
            }
        } else {
            ConfigFile::default()
        };

        Ok(Self { path, cache })
    }

    fn config_path() -> Result<PathBuf> {
        let dirs = ProjectDirs::from("dev", "meatshell", "meatshell")
            .context("could not determine user config directory")?;
        Ok(dirs.config_dir().join("sessions.json"))
    }

    pub fn sessions(&self) -> &[Session] {
        &self.cache.sessions
    }

    #[allow(dead_code)] // reserved for an upcoming reorder/drag-drop feature
    pub fn sessions_mut(&mut self) -> &mut Vec<Session> {
        &mut self.cache.sessions
    }

    pub fn upsert(&mut self, mut session: Session) {
        // If updating an existing session, migrate password if needed.
        if let Some(existing) = self
            .cache
            .sessions
            .iter()
            .find(|s| s.id == session.id)
        {
            // If the new session has an empty password but the old one had one,
            // and we're now using keyring, migrate the old password.
            #[cfg(feature = "keyring-storage")]
            if session.password.as_str().is_empty() && !existing.password.as_str().is_empty() {
                // Old password was in JSON, migrate to keyring.
                session.set_password(existing.password.as_str());
            }
        }

        if let Some(existing) = self
            .cache
            .sessions
            .iter_mut()
            .find(|s| s.id == session.id)
        {
            *existing = session;
        } else {
            self.cache.sessions.push(session);
        }
    }

    pub fn remove(&mut self, id: &str) {
        // Delete password from keyring before removing the session.
        if let Some(session) = self.cache.sessions.iter().find(|s| s.id == id) {
            session.clear_password();
        }
        self.cache.sessions.retain(|s| s.id != id);
    }

    pub fn get(&self, id: &str) -> Option<&Session> {
        self.cache.sessions.iter().find(|s| s.id == id)
    }

    pub fn download_dir(&self) -> &str {
        &self.cache.download_dir
    }

    pub fn set_download_dir(&mut self, dir: String) {
        self.cache.download_dir = dir;
    }

    /// UI language code ("zh" default / "en").
    pub fn language(&self) -> &str {
        if self.cache.language.is_empty() {
            "zh"
        } else {
            &self.cache.language
        }
    }

    pub fn set_language(&mut self, lang: String) {
        self.cache.language = lang;
    }

    /// Theme mode ("dark" default / "light" / "system").
    pub fn theme(&self) -> &str {
        if self.cache.theme.is_empty() {
            "dark"
        } else {
            &self.cache.theme
        }
    }

    pub fn set_theme(&mut self, theme: String) {
        self.cache.theme = theme;
    }

    pub fn save(&self) -> Result<()> {
        let raw = serde_json::to_string_pretty(&self.cache)?;
        // Write to a sibling temp file then rename — cheap atomicity on most
        // platforms. Good enough for a config file.
        let tmp = self.path.with_extension("json.tmp");
        fs::write(&tmp, raw)
            .with_context(|| format!("failed to write {}", tmp.display()))?;
        fs::rename(&tmp, &self.path)
            .with_context(|| format!("failed to finalise {}", self.path.display()))?;
        Ok(())
    }
}
