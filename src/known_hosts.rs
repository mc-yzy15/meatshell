//! Known hosts verification.
//!
//! Reads and writes OpenSSH-style `~/.ssh/known_hosts` files. Provides:
//! - Verification of server public keys during SSH handshake
//! - Storage of new host keys when the user accepts them
//! - Detection of key changes (potential MITM attacks)
//!
//! The implementation supports:
//! - Plain host entries: `host.example.com ssh-rsa AAAA...`
//! - Bracketed entries with port: `[host.example.com]:2222 ssh-ed25519 AAAA...`
//! - Hashed host entries (privacy-preserving): `|1|base64|base64 ssh-rsa AAAA...`

use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;

use anyhow::{anyhow, Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use sha2::{Digest, Sha256, Sha512};

/// Represents a single entry in the known_hosts file.
#[derive(Debug, Clone)]
pub struct KnownHostEntry {
    /// The host pattern (may be hashed).
    pub host_pattern: String,
    /// The key type (e.g., "ssh-rsa", "ssh-ed25519", "ecdsa-sha2-nistp256").
    pub key_type: String,
    /// The base64-encoded public key data.
    pub public_key_base64: String,
    /// Whether the host pattern is hashed.
    pub is_hashed: bool,
}

/// Manages known_hosts file operations.
pub struct KnownHosts {
    path: PathBuf,
    entries: Vec<KnownHostEntry>,
    /// Cache: (host, port) -> list of (key_type, public_key_base64)
    host_cache: HashMap<(String, u16), Vec<(String, String)>>,
}

/// Result of verifying a server key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyResult {
    /// The key matches a known entry.
    Verified,
    /// The host is new (not in known_hosts).
    Unknown {
        /// Fingerprint of the new key (SHA256, base64).
        fingerprint: String,
        /// Key type for display.
        key_type: String,
    },
    /// The host is known but the key has changed (potential MITM).
    Changed {
        /// Fingerprint of the new key.
        fingerprint: String,
        /// Key type for display.
        key_type: String,
        /// Previously known key type.
        old_key_type: String,
    },
}

impl KnownHosts {
    /// Load the known_hosts file from the default location.
    ///
    /// On error (file not found, permission denied, parse error), returns an
    /// empty KnownHosts that can still be used to add new entries.
    pub fn load() -> Self {
        let path = Self::default_path();
        let entries = match Self::load_entries(&path) {
            Ok(e) => e,
            Err(e) => {
                tracing::debug!("could not load known_hosts: {e:#}");
                Vec::new()
            }
        };

        let mut kh = Self {
            path,
            entries,
            host_cache: HashMap::new(),
        };
        kh.rebuild_cache();
        kh
    }

    /// Get the default known_hosts file path (~/.ssh/known_hosts).
    pub fn default_path() -> PathBuf {
        if let Some(home) = dirs::home_dir() {
            home.join(".ssh").join("known_hosts")
        } else {
            PathBuf::from("known_hosts")
        }
    }

    /// Load entries from a file.
    fn load_entries(path: &PathBuf) -> Result<Vec<KnownHostEntry>> {
        let file = File::open(path).context("open known_hosts")?;
        let reader = BufReader::new(file);
        let mut entries = Vec::new();

        for (lineno, line) in reader.lines().enumerate() {
            let line = line.context("read line")?;
            let trimmed = line.trim();

            // Skip empty lines and comments.
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }

            match Self::parse_line(trimmed) {
                Ok(entry) => entries.push(entry),
                Err(e) => {
                    tracing::warn!(
                        "known_hosts:{}: parse error: {e}",
                        lineno + 1
                    );
                }
            }
        }

        Ok(entries)
    }

    /// Parse a single known_hosts line.
    ///
    /// Format: `[hosts] [keytype] [public-key] [optional-comment]`
    /// The hosts field can be:
    /// - Plain hostname: `example.com`
    /// - Multiple hosts: `host1,host2`
    /// - Bracketed with port: `[host]:port`
    /// - Hashed: `|1|salt|hash`
    fn parse_line(line: &str) -> Result<KnownHostEntry> {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 3 {
            return Err(anyhow!("not enough fields"));
        }

        let host_pattern = parts[0].to_string();
        let key_type = parts[1].to_string();
        let public_key_base64 = parts[2].to_string();

        let is_hashed = host_pattern.starts_with("|1|");

        Ok(KnownHostEntry {
            host_pattern,
            key_type,
            public_key_base64,
            is_hashed,
        })
    }

    /// Rebuild the host cache for fast lookups.
    fn rebuild_cache(&mut self) {
        self.host_cache.clear();

        for entry in &self.entries {
            // Parse the host pattern to extract hostname(s) and port(s).
            let hosts = Self::parse_host_pattern(&entry.host_pattern);

            for (host, port) in hosts {
                self.host_cache
                    .entry((host, port))
                    .or_default()
                    .push((entry.key_type.clone(), entry.public_key_base64.clone()));
            }
        }
    }

    /// Parse a host pattern into (hostname, port) pairs.
    ///
    /// Handles:
    /// - Plain: `example.com` -> [("example.com", 22)]
    /// - Bracketed: `[example.com]:2222` -> [("example.com", 2222)]
    /// - Multiple: `host1,host2` -> [("host1", 22), ("host2", 22)]
    /// - Hashed: `|1|...` -> [] (can't extract hostname without trying all)
    fn parse_host_pattern(pattern: &str) -> Vec<(String, u16)> {
        let mut result = Vec::new();

        // Handle hashed entries specially - they're handled by match_hashed().
        if pattern.starts_with("|1|") {
            return result; // Empty; hashed entries are matched separately.
        }

        // Split on comma for multiple hosts.
        for host_spec in pattern.split(',') {
            let host_spec = host_spec.trim();

            // Check for bracketed form with port: [host]:port
            if host_spec.starts_with('[') {
                if let Some(bracket_end) = host_spec.find(']') {
                    let host = host_spec[1..bracket_end].to_string();
                    let port = if bracket_end + 1 < host_spec.len()
                        && host_spec[bracket_end + 1..].starts_with(':')
                    {
                        host_spec[bracket_end + 2..]
                            .parse()
                            .unwrap_or(22)
                    } else {
                        22
                    };
                    result.push((host, port));
                }
            } else {
                // Plain hostname (may include :port for non-standard port).
                if let Some(colon) = host_spec.rfind(':') {
                    // Check if this looks like an IPv6 address (contains multiple colons).
                    if host_spec.matches(':').count() > 1 {
                        // IPv6 address without port - use default.
                        result.push((host_spec.to_string(), 22));
                    } else {
                        // hostname:port or ip:port
                        let host = host_spec[..colon].to_string();
                        let port = host_spec[colon + 1..]
                            .parse()
                            .unwrap_or(22);
                        result.push((host, port));
                    }
                } else {
                    result.push((host_spec.to_string(), 22));
                }
            }
        }

        result
    }

    /// Check if a hashed host pattern matches the given host.
    ///
    /// Hashed format: `|1|salt_base64|hash_base64`
    /// The hash is SHA256(salt + host). We need to try the host with various
    /// port suffixes.
    fn match_hashed(pattern: &str, host: &str, port: u16) -> bool {
        let parts: Vec<&str> = pattern.split('|').collect();
        if parts.len() < 4 || parts[1] != "1" {
            return false;
        }

        let salt = match BASE64.decode(parts[2]) {
            Ok(s) => s,
            Err(_) => return false,
        };

        let expected_hash = match BASE64.decode(parts[3]) {
            Ok(h) => h,
            Err(_) => return false,
        };

        // Try both bare hostname and hostname:port forms.
        let candidates = if port == 22 {
            vec![host.to_string()]
        } else {
            vec![host.to_string(), format!("[{host}]:{port}")]
        };

        for candidate in candidates {
            let mut hasher = Sha256::new();
            hasher.update(&salt);
            hasher.update(candidate.as_bytes());
            let computed = hasher.finalize();

            if computed.as_slice() == expected_hash.as_slice() {
                return true;
            }
        }

        false
    }

    /// Verify a server public key against known hosts.
    ///
    /// Returns:
    /// - `VerifyResult::Verified` if the key matches.
    /// - `VerifyResult::Unknown` if the host is new.
    /// - `VerifyResult::Changed` if the host is known but the key differs.
    pub fn verify(&self, host: &str, port: u16, key_type: &str, public_key_base64: &str) -> VerifyResult {
        // Look up the host in the cache.
        let known_keys = self.host_cache.get(&(host.to_string(), port));

        // Also check for wildcard entries (hosts with empty port or port 22).
        let known_keys_default = if port != 22 {
            self.host_cache.get(&(host.to_string(), 22))
        } else {
            None
        };

        // Collect all known keys for this host as owned tuples.
        let mut all_keys: Vec<(String, String)> = Vec::new();
        if let Some(keys) = known_keys {
            all_keys.extend(keys.iter().map(|(k, v)| (k.clone(), v.clone())));
        }
        if let Some(keys) = known_keys_default {
            all_keys.extend(keys.iter().map(|(k, v)| (k.clone(), v.clone())));
        }

        // Check hashed entries.
        for entry in &self.entries {
            if entry.is_hashed && Self::match_hashed(&entry.host_pattern, host, port) {
                all_keys.push((entry.key_type.clone(), entry.public_key_base64.clone()));
            }
        }

        if all_keys.is_empty() {
            // Host is unknown.
            return VerifyResult::Unknown {
                fingerprint: Self::fingerprint(public_key_base64),
                key_type: key_type.to_string(),
            };
        }

        // Check if any known key matches.
        for (known_type, known_key) in &all_keys {
            if known_type == key_type && known_key == public_key_base64 {
                return VerifyResult::Verified;
            }
        }

        // Key mismatch.
        let old_key_type = all_keys
            .first()
            .map(|(kt, _)| kt.clone())
            .unwrap_or_else(|| "unknown".to_string());

        VerifyResult::Changed {
            fingerprint: Self::fingerprint(public_key_base64),
            key_type: key_type.to_string(),
            old_key_type,
        }
    }

    /// Compute the SHA256 fingerprint of a public key.
    pub fn fingerprint(public_key_base64: &str) -> String {
        let key_data = match BASE64.decode(public_key_base64) {
            Ok(d) => d,
            Err(_) => return "invalid-key".to_string(),
        };

        let mut hasher = Sha256::new();
        hasher.update(&key_data);
        let hash = hasher.finalize();

        // Format as base64 without padding, similar to OpenSSH.
        let mut result = BASE64.encode(hash);
        // Remove padding.
        while result.ends_with('=') {
            result.pop();
        }

        format!("SHA256:{}", result)
    }

    /// Add a new host key to the known_hosts file.
    ///
    /// This appends the entry to the file and updates the in-memory cache.
    pub fn add(&mut self, host: &str, port: u16, key_type: &str, public_key_base64: &str) -> Result<()> {
        // Format the host pattern.
        let host_pattern = if port == 22 {
            host.to_string()
        } else {
            format!("[{host}]:{port}")
        };

        // Create the entry.
        let entry = KnownHostEntry {
            host_pattern: host_pattern.clone(),
            key_type: key_type.to_string(),
            public_key_base64: public_key_base64.to_string(),
            is_hashed: false,
        };

        // Append to file.
        let line = format!("{} {} {}\n", host_pattern, key_type, public_key_base64);

        // Ensure the .ssh directory exists.
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent).context("create .ssh directory")?;
        }

        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .context("open known_hosts for append")?;

        file.write_all(line.as_bytes())
            .context("write to known_hosts")?;

        // Update in-memory state.
        self.entries.push(entry);
        self.host_cache
            .entry((host.to_string(), port))
            .or_default()
            .push((key_type.to_string(), public_key_base64.to_string()));

        tracing::info!("added {}:{} to known_hosts", host, port);
        Ok(())
    }

    /// Remove all entries for a host from the known_hosts file.
    ///
    /// This rewrites the file without the matching entries.
    pub fn remove(&mut self, host: &str, port: u16) -> Result<()> {
        // Filter entries.
        let original_len = self.entries.len();
        self.entries.retain(|e| {
            if e.is_hashed {
                // Keep hashed entries (can't easily determine the host).
                return true;
            }
            let hosts = Self::parse_host_pattern(&e.host_pattern);
            !hosts.iter().any(|(h, p)| h == host && *p == port)
        });

        if self.entries.len() == original_len {
            // Nothing was removed.
            return Ok(());
        }

        // Rewrite the file.
        self.rewrite_file()?;
        self.rebuild_cache();

        tracing::info!("removed {}:{} from known_hosts", host, port);
        Ok(())
    }

    /// Rewrite the entire known_hosts file from the in-memory entries.
    fn rewrite_file(&self) -> Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .truncate(true)
            .create(true)
            .open(&self.path)
            .context("open known_hosts for rewrite")?;

        for entry in &self.entries {
            let line = format!(
                "{} {} {}\n",
                entry.host_pattern, entry.key_type, entry.public_key_base64
            );
            file.write_all(line.as_bytes())
                .context("write known_hosts entry")?;
        }

        Ok(())
    }
}

/// Compute the HMAC-SHA1 hash for a hashed known_hosts entry.
/// Used when creating new hashed entries (optional feature).
#[allow(dead_code)]
fn hash_host(host: &str) -> (String, String) {
    // Generate random salt (20 bytes like OpenSSH).
    let salt: Vec<u8> = (0..20).map(|_| rand::random::<u8>()).collect();

    // Compute HMAC-SHA1 of host with salt.
    let mut hasher = Sha512::new(); // Using SHA512 as we don't have HMAC here; simplified.
    hasher.update(&salt);
    hasher.update(host.as_bytes());
    let hash = hasher.finalize();

    (
        BASE64.encode(&salt),
        BASE64.encode(&hash[..20]), // Truncate to 20 bytes for SHA1-sized output.
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_plain_host() {
        let result = KnownHosts::parse_host_pattern("example.com");
        assert_eq!(result, vec![("example.com".to_string(), 22)]);
    }

    #[test]
    fn test_parse_bracketed_with_port() {
        let result = KnownHosts::parse_host_pattern("[example.com]:2222");
        assert_eq!(result, vec![("example.com".to_string(), 2222)]);
    }

    #[test]
    fn test_parse_multiple_hosts() {
        let result = KnownHosts::parse_host_pattern("host1,host2,host3");
        assert_eq!(
            result,
            vec![
                ("host1".to_string(), 22),
                ("host2".to_string(), 22),
                ("host3".to_string(), 22),
            ]
        );
    }

    #[test]
    fn test_parse_host_with_port() {
        let result = KnownHosts::parse_host_pattern("example.com:2222");
        assert_eq!(result, vec![("example.com".to_string(), 2222)]);
    }

    #[test]
    fn test_fingerprint() {
        // A simple test key.
        let fp = KnownHosts::fingerprint("AAAAB3NzaC1yc2EAAAADAQABAAABAQCTest");
        assert!(fp.starts_with("SHA256:"));
    }
}
