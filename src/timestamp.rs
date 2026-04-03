//! Timestamp-based credential caching.
//!
//! Security properties:
//! - Timestamp directory is created with 0700 root-only permissions
//! - Timestamp files are verified for ownership before trust
//! - Symlinks in the timestamp path are rejected
//! - Per-TTY isolation prevents cross-session credential reuse

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use anyhow::{Context, Result, bail};

use crate::validate::validate_username;

pub const DEFAULT_TIMESTAMP_DIR: &str = "/var/run/agnos/sudo";
pub const DEFAULT_TIMESTAMP_TTL_SECS: u64 = 300; // 5 minutes

/// Check if the user has a valid timestamp (recently authenticated).
///
/// Returns `false` if:
/// - No timestamp file exists
/// - The file is a symlink (potential attack)
/// - The file is not owned by root (potential tampering)
/// - The timestamp has expired
#[must_use]
pub fn check_timestamp(user: &str, ttl: Duration) -> bool {
    let ts_path = timestamp_path(user);

    // Use symlink_metadata to detect symlinks — do NOT follow them
    let meta = match std::fs::symlink_metadata(&ts_path) {
        Ok(m) => m,
        Err(_) => return false,
    };

    // Reject symlinks — an attacker could point to a recently-modified file
    if meta.file_type().is_symlink() {
        return false;
    }

    // Verify ownership: timestamp files must be owned by root
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::MetadataExt;
        if meta.uid() != 0 {
            return false;
        }
    }

    if let Ok(modified) = meta.modified()
        && let Ok(elapsed) = SystemTime::now().duration_since(modified)
    {
        return elapsed < ttl;
    }

    false
}

/// Update the timestamp for a user (mark as recently authenticated).
pub fn update_timestamp(user: &str) -> Result<()> {
    validate_username(user)?;
    let ts_path = timestamp_path(user);
    let dir = Path::new(DEFAULT_TIMESTAMP_DIR);

    ensure_timestamp_dir(dir)?;

    // Reject if the path is a symlink (race condition defense)
    if ts_path.is_symlink() {
        bail!(
            "Timestamp path is a symlink (possible attack): {}",
            ts_path.display()
        );
    }

    // Touch the file
    std::fs::write(&ts_path, b"")
        .with_context(|| format!("Failed to update timestamp: {}", ts_path.display()))?;

    // Set restrictive permissions on the timestamp file
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o600);
        std::fs::set_permissions(&ts_path, perms)
            .with_context(|| format!("Failed to set permissions on {}", ts_path.display()))?;
    }

    Ok(())
}

/// Remove timestamp for a user (invalidate cached credentials).
pub fn invalidate_timestamp(user: &str) -> Result<()> {
    validate_username(user)?;
    let ts_path = timestamp_path(user);

    // Use symlink_metadata to check existence without following symlinks
    if let Ok(meta) = std::fs::symlink_metadata(&ts_path) {
        // Refuse to follow symlinks when deleting
        if meta.file_type().is_symlink() {
            bail!(
                "Timestamp path is a symlink (possible attack): {}",
                ts_path.display()
            );
        }
        std::fs::remove_file(&ts_path)?;
    }
    Ok(())
}

/// Build the timestamp file path for a user, incorporating TTY for session isolation.
pub fn timestamp_path(user: &str) -> PathBuf {
    let tty_suffix = tty_session_id();
    let filename = if tty_suffix.is_empty() {
        user.to_string()
    } else {
        format!("{}:{}", user, tty_suffix)
    };
    PathBuf::from(DEFAULT_TIMESTAMP_DIR).join(filename)
}

/// Get a TTY-based session identifier for per-TTY timestamp isolation.
///
/// Returns a sanitized TTY name (e.g., "pts-3") or empty string if unavailable.
fn tty_session_id() -> String {
    // Try to get the TTY from the file descriptor directly
    #[cfg(target_os = "linux")]
    {
        if let Ok(tty) = nix::unistd::ttyname(std::io::stdin()) {
            let tty_str = tty.to_string_lossy();
            // Sanitize: replace / with - to make a safe filename component
            return tty_str.trim_start_matches("/dev/").replace('/', "-");
        }
    }

    // Fallback: no TTY isolation
    String::new()
}

/// Ensure the timestamp directory exists with proper permissions.
fn ensure_timestamp_dir(dir: &Path) -> Result<()> {
    if !dir.exists() {
        std::fs::create_dir_all(dir)
            .with_context(|| format!("Failed to create timestamp directory: {}", dir.display()))?;

        // Set restrictive permissions: only root can read/write/traverse
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o700);
            std::fs::set_permissions(dir, perms).with_context(|| {
                format!(
                    "Failed to set permissions on timestamp directory: {}",
                    dir.display()
                )
            })?;
        }
    } else {
        // Directory exists — verify it has safe permissions
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::fs::MetadataExt;
            let meta = std::fs::metadata(dir)?;

            // Must be owned by root
            if meta.uid() != 0 {
                bail!(
                    "Timestamp directory {} is not owned by root (uid={})",
                    dir.display(),
                    meta.uid()
                );
            }

            // Must not be world-writable
            if meta.mode() & 0o002 != 0 {
                bail!(
                    "Timestamp directory {} is world-writable (mode {:o})",
                    dir.display(),
                    meta.mode()
                );
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_timestamp_path_includes_user() {
        let path = timestamp_path("alice");
        let filename = path.file_name().unwrap().to_string_lossy();
        assert!(filename.starts_with("alice"));
    }

    #[test]
    fn test_check_timestamp_nonexistent() {
        assert!(!check_timestamp(
            "test_nonexistent_user_xyz",
            Duration::from_secs(300)
        ));
    }

    #[test]
    fn test_default_timestamp_dir() {
        assert_eq!(DEFAULT_TIMESTAMP_DIR, "/var/run/agnos/sudo");
    }

    #[test]
    fn test_tty_session_id_is_safe() {
        let id = tty_session_id();
        // Must not contain / (safe for filenames)
        assert!(!id.contains('/'));
        // Must not contain null bytes
        assert!(!id.contains('\0'));
    }
}
