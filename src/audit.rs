//! Audit logging for privilege escalation events.
//!
//! Supports multiple backends:
//! - **journald** (preferred on systemd systems) — structured fields via `tracing-journald`
//! - **file** (fallback) — append-only log at `/var/log/agnos/sudo.log`
//!
//! All authentication attempts (success and failure) and command executions
//! are logged with caller identity, target user, command, and outcome.

use std::env;
use std::path::Path;

use tracing::{info, warn};

/// Audit event types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AuditAction {
    /// A command execution was authorized and will proceed.
    Command,
    /// Authentication failed (wrong password, expired timestamp, etc.).
    AuthFailure,
    /// Credential timestamp was invalidated by the user.
    TimestampInvalidated,
}

impl AuditAction {
    #[must_use]
    fn as_str(self) -> &'static str {
        match self {
            Self::Command => "COMMAND",
            Self::AuthFailure => "AUTH_FAILURE",
            Self::TimestampInvalidated => "TIMESTAMP_INVALIDATED",
        }
    }
}

/// Log an audit event.
///
/// This writes to:
/// 1. The `tracing` subsystem (which may route to journald, stderr, or both)
/// 2. A file-based audit trail at `/var/log/agnos/sudo.log` (best-effort)
pub fn audit_log(
    action: AuditAction,
    caller: &str,
    target: &str,
    command: &str,
    success: bool,
    reason: &str,
) {
    let status = if success { "ALLOWED" } else { "DENIED" };
    let action_str = action.as_str();

    // Structured tracing event — picked up by journald layer if configured
    if success {
        info!(
            shakti_audit = true,
            action = action_str,
            caller = caller,
            target_user = target,
            command = command,
            status = status,
            reason = reason,
            "shakti: {} : {} ; USER={} ; COMMAND={} ; STATUS={} ; REASON={}",
            action_str,
            caller,
            target,
            command,
            status,
            reason
        );
    } else {
        warn!(
            shakti_audit = true,
            action = action_str,
            caller = caller,
            target_user = target,
            command = command,
            status = status,
            reason = reason,
            "shakti: {} : {} ; USER={} ; COMMAND={} ; STATUS={} ; REASON={}",
            action_str,
            caller,
            target,
            command,
            status,
            reason
        );
    }

    // File-based audit trail (best-effort fallback)
    #[cfg(target_os = "linux")]
    write_audit_file(caller, target, command);
}

/// Append a syslog-style line to the audit file.
#[cfg(target_os = "linux")]
fn write_audit_file(caller: &str, target: &str, command: &str) {
    use std::io::Write;
    use std::time::SystemTime;

    let timestamp = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let tty = env::var("TTY")
        .or_else(|_| env::var("SSH_TTY"))
        .unwrap_or_else(|_| "unknown".to_string());

    let pwd = env::current_dir()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| "unknown".to_string());

    let log_line = format!(
        "{} {} : TTY={} ; PWD={} ; USER={} ; COMMAND={}\n",
        timestamp, caller, tty, pwd, target, command,
    );

    let log_path = Path::new("/var/log/agnos/sudo.log");
    if let Err(e) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_path)
        .and_then(|mut f| f.write_all(log_line.as_bytes()))
    {
        // Don't use tracing here to avoid recursion — just stderr
        eprintln!(
            "WARNING: Failed to write audit log to {}: {}",
            log_path.display(),
            e
        );
    }
}

/// Initialize the tracing subscriber with optional journald support.
///
/// Call this once at program startup. Layers:
/// - stderr (always) — human-readable or JSON based on `AGNOS_LOG_FORMAT`
/// - journald (if available) — structured fields for `journalctl`
pub fn init_tracing() {
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;

    let env_filter =
        tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "warn".into());

    let format = env::var("AGNOS_LOG_FORMAT").unwrap_or_default();

    let registry = tracing_subscriber::registry().with(env_filter);

    // Try to add journald layer
    let journald_layer = tracing_journald::layer().ok();

    if format == "json" {
        let fmt_layer = tracing_subscriber::fmt::layer().json();
        registry.with(fmt_layer).with(journald_layer).init();
    } else {
        let fmt_layer = tracing_subscriber::fmt::layer();
        registry.with(fmt_layer).with(journald_layer).init();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_audit_action_as_str() {
        assert_eq!(AuditAction::Command.as_str(), "COMMAND");
        assert_eq!(AuditAction::AuthFailure.as_str(), "AUTH_FAILURE");
        assert_eq!(
            AuditAction::TimestampInvalidated.as_str(),
            "TIMESTAMP_INVALIDATED"
        );
    }

    #[test]
    fn test_audit_action_eq() {
        assert_eq!(AuditAction::Command, AuditAction::Command);
        assert_ne!(AuditAction::Command, AuditAction::AuthFailure);
    }
}
