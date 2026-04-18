//! Authentication backends for privilege escalation.
//!
//! Provides PAM-based authentication (when the `pam` feature is enabled)
//! and a fallback `/usr/bin/su` shim for systems without PAM development headers.

use anyhow::{Result, bail};

/// The PAM service name used for authentication.
pub const PAM_SERVICE: &str = "shakti";

/// Authenticate a user via PAM.
///
/// Opens a PAM session with service name "shakti", runs the authentication
/// conversation with the provided password, and returns whether authentication
/// succeeded.
///
/// # Errors
///
/// Returns an error if PAM initialization fails (e.g., missing PAM config).
/// Returns `Ok(false)` if the password is wrong.
#[cfg(feature = "pam")]
pub fn pam_authenticate(username: &str, password: &str) -> Result<bool> {
    use pam::Authenticator;

    let mut auth = match Authenticator::with_password(PAM_SERVICE) {
        Ok(a) => a,
        Err(e) => bail!("Failed to initialize PAM: {}", e),
    };

    auth.get_handler().set_credentials(username, password);

    match auth.authenticate() {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

/// Authenticate a user via the `/usr/bin/su` fallback.
///
/// This is used when PAM is not available (feature disabled or missing headers).
/// It spawns `su -c true <username>` and pipes the password to stdin.
#[cfg(target_os = "linux")]
pub fn su_authenticate(username: &str, password: &str) -> Result<bool> {
    use std::io::Write;
    use std::process::{Command, Stdio};

    let result = Command::new("/usr/bin/su")
        .arg("-c")
        .arg("true")
        .arg(username)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn();

    match result {
        Ok(mut child) => {
            if let Some(ref mut stdin_pipe) = child.stdin {
                let _ = stdin_pipe
                    .write_all(password.as_bytes())
                    .and_then(|_| stdin_pipe.write_all(b"\n"));
            }
            match child.wait() {
                Ok(status) => Ok(status.success()),
                Err(e) => bail!("Failed to wait for su: {}", e),
            }
        }
        Err(e) => bail!("Failed to spawn /usr/bin/su: {}", e),
    }
}

#[cfg(not(target_os = "linux"))]
pub fn su_authenticate(_username: &str, _password: &str) -> Result<bool> {
    bail!("su authentication not supported on this platform");
}

/// Authenticate a user using the best available backend.
///
/// Tries PAM first (if the feature is enabled), falls back to `/usr/bin/su`.
pub fn authenticate(username: &str, password: &str) -> Result<bool> {
    #[cfg(feature = "pam")]
    {
        match pam_authenticate(username, password) {
            Ok(result) => return Ok(result),
            Err(e) => {
                // PAM failed to initialize (missing service config, etc.)
                // Fall through to su
                tracing::debug!("PAM unavailable, falling back to su: {}", e);
            }
        }
    }

    su_authenticate(username, password)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pam_service_name() {
        assert_eq!(PAM_SERVICE, "shakti");
    }

    // NOTE: Actual PAM/su authentication tests require a running system
    // with configured PAM and known credentials. They are integration tests,
    // not unit tests.
}
