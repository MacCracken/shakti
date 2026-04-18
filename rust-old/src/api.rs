//! Consumer API for programmatic privilege escalation.
//!
//! This module provides the high-level API used by Shakti consumers:
//! - **argonaut** (init system) — service privilege escalation
//! - **agnoshi** (shell) — interactive `sudo` equivalent
//! - **daimon** (agent) — non-interactive agent privilege operations
//!
//! # Example
//!
//! ```no_run
//! use shakti::api::{ShaktiConfig, AuthMode, evaluate};
//!
//! let config = ShaktiConfig::builder()
//!     .target_user("root")
//!     .auth_mode(AuthMode::TimestampOnly)
//!     .build();
//!
//! let eval = evaluate(
//!     &config,
//!     "deploy",
//!     &["wheel".into()],
//!     &["/usr/bin/systemctl".into(), "restart".into(), "nginx".into()],
//! ).unwrap();
//!
//! if eval.authorized {
//!     // Use eval.resolved_command, eval.environment to exec
//! }
//! ```

use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Result, bail};

use crate::env::sanitize_environment;
use crate::policy::{self, AuthzResult, SudoPolicy};
use crate::timestamp::check_timestamp;
use crate::validate::{resolve_command, validate_command, validate_username};

// ---------------------------------------------------------------------------
// AuthMode
// ---------------------------------------------------------------------------

/// How authentication should be handled for a privilege escalation request.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum AuthMode {
    /// Interactive password prompt via terminal (for agnoshi / shell use).
    /// The caller is responsible for actually performing authentication —
    /// this mode simply indicates that auth *should* be attempted interactively.
    Interactive,

    /// Use cached timestamp credentials only. If the timestamp has expired or
    /// doesn't exist, the request fails rather than prompting. Suitable for
    /// daimon (agent operations) where no terminal is available.
    TimestampOnly,

    /// Skip authentication entirely. The caller asserts they have already
    /// verified the user's identity through other means (e.g., a PAM session
    /// established by argonaut at boot). Authorization policy is still checked.
    Skip,
}

// ---------------------------------------------------------------------------
// ShaktiConfig
// ---------------------------------------------------------------------------

/// Configuration for a privilege escalation evaluation.
///
/// Use [`ShaktiConfig::builder()`] to construct.
#[derive(Debug, Clone)]
pub struct ShaktiConfig {
    /// Path to the policy file.
    pub policy_path: PathBuf,
    /// Target user to run as.
    pub target_user: String,
    /// How authentication should be handled.
    pub auth_mode: AuthMode,
}

impl ShaktiConfig {
    /// Create a builder with sensible defaults.
    #[must_use]
    pub fn builder() -> ShaktiConfigBuilder {
        ShaktiConfigBuilder {
            policy_path: PathBuf::from(crate::policy::DEFAULT_POLICY_PATH),
            target_user: "root".to_string(),
            auth_mode: AuthMode::Interactive,
        }
    }
}

/// Builder for [`ShaktiConfig`].
#[derive(Debug, Clone)]
pub struct ShaktiConfigBuilder {
    policy_path: PathBuf,
    target_user: String,
    auth_mode: AuthMode,
}

impl ShaktiConfigBuilder {
    /// Set the policy file path.
    #[must_use]
    pub fn policy_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.policy_path = path.into();
        self
    }

    /// Set the target user to run as (default: "root").
    #[must_use]
    pub fn target_user(mut self, user: impl Into<String>) -> Self {
        self.target_user = user.into();
        self
    }

    /// Set the authentication mode (default: [`AuthMode::Interactive`]).
    #[must_use]
    pub fn auth_mode(mut self, mode: AuthMode) -> Self {
        self.auth_mode = mode;
        self
    }

    /// Build the configuration.
    #[must_use]
    pub fn build(self) -> ShaktiConfig {
        ShaktiConfig {
            policy_path: self.policy_path,
            target_user: self.target_user,
            auth_mode: self.auth_mode,
        }
    }
}

// ---------------------------------------------------------------------------
// Evaluation
// ---------------------------------------------------------------------------

/// Result of evaluating a privilege escalation request.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Evaluation {
    /// Whether the request is authorized by policy.
    pub authorized: bool,
    /// Whether the policy requires authentication for this request.
    /// When `auth_mode` is `Skip`, this reflects what the policy *would*
    /// require, but auth was bypassed.
    pub require_auth: bool,
    /// Whether the caller's cached credentials are still valid.
    /// Only meaningful when `require_auth` is true.
    pub timestamp_valid: bool,
    /// The resolved absolute path to the command binary.
    pub resolved_command: PathBuf,
    /// Sanitized environment variables for the target process.
    pub environment: Vec<(String, String)>,
    /// The loaded policy (available for inspection by the caller).
    pub policy: SudoPolicy,
}

/// Evaluate a privilege escalation request without executing anything.
///
/// This is the primary entry point for consumers. It:
/// 1. Validates the caller username
/// 2. Validates and resolves the command
/// 3. Loads the policy file (unless `policy` is provided via [`evaluate_with_policy`])
/// 4. Checks authorization
/// 5. Checks timestamp validity (if auth is required)
/// 6. Builds the sanitized environment
///
/// The caller is responsible for:
/// - Performing actual authentication (if `require_auth` and not `timestamp_valid`)
/// - Executing the command with the returned environment
/// - Audit logging
pub fn evaluate(
    config: &ShaktiConfig,
    caller: &str,
    groups: &[String],
    command_args: &[String],
) -> Result<Evaluation> {
    let policy = policy::load_policy(&config.policy_path)?;
    evaluate_with_policy(config, &policy, caller, groups, command_args)
}

/// Like [`evaluate`], but accepts a pre-loaded policy.
///
/// Useful when the consumer has already loaded/parsed the policy and wants
/// to evaluate multiple requests against the same policy without re-reading
/// the file each time.
pub fn evaluate_with_policy(
    config: &ShaktiConfig,
    policy: &SudoPolicy,
    caller: &str,
    groups: &[String],
    command_args: &[String],
) -> Result<Evaluation> {
    // Validate caller
    validate_username(caller)?;

    // Validate command
    validate_command(command_args, policy.defaults.max_command_len)?;

    // Resolve command to absolute path
    let resolved = resolve_command(&command_args[0])?;
    let resolved_str = resolved.to_str().ok_or_else(|| {
        anyhow::anyhow!("Command path is not valid UTF-8: {}", resolved.display())
    })?;

    // Build full command string with arguments for authorization
    let full_command = if command_args.len() > 1 {
        format!("{} {}", resolved_str, command_args[1..].join(" "))
    } else {
        resolved_str.to_string()
    };

    // Authorization check — pass full command with arguments so that
    // argument-level patterns in commands/deny_commands are evaluated.
    let authz =
        policy::check_authorization(policy, caller, groups, &config.target_user, &full_command);

    match authz {
        AuthzResult::Denied(reason) => {
            bail!("Authorization denied: {}", reason);
        }
        AuthzResult::Allowed { require_auth } => {
            // Determine effective auth requirement based on auth mode
            let effective_require_auth = require_auth && config.auth_mode != AuthMode::Skip;

            // Check timestamp
            let timestamp_valid = if effective_require_auth {
                let ttl = Duration::from_secs(policy.defaults.timestamp_ttl);
                check_timestamp(caller, ttl)
            } else {
                false
            };

            // For TimestampOnly mode, fail if auth is required but timestamp is expired
            if config.auth_mode == AuthMode::TimestampOnly
                && effective_require_auth
                && !timestamp_valid
            {
                bail!(
                    "Authentication required but timestamp expired (non-interactive mode). \
                     Re-authenticate interactively first."
                );
            }

            // Build sanitized environment
            // We need target user info for the environment — use the target user name
            // but let the caller provide home/shell if they have it. For now, use
            // reasonable defaults that the caller can override.
            let target_home = target_user_home(&config.target_user);
            let target_shell = target_user_shell(&config.target_user);

            let environment = sanitize_environment(
                policy,
                caller,
                &config.target_user,
                &target_home,
                &target_shell,
            );

            Ok(Evaluation {
                authorized: true,
                require_auth,
                timestamp_valid,
                resolved_command: resolved,
                environment,
                policy: policy.clone(),
            })
        }
        // AuthzResult is #[non_exhaustive] — handle unknown future variants
        #[allow(unreachable_patterns)]
        _ => bail!("Unexpected authorization result"),
    }
}

/// Look up a user's home directory. Falls back to `/root` or `/home/{user}`.
fn target_user_home(username: &str) -> String {
    if let Ok(Some(user)) = nix::unistd::User::from_name(username) {
        return user.dir.to_string_lossy().to_string();
    }
    if username == "root" {
        "/root".to_string()
    } else {
        format!("/home/{}", username)
    }
}

/// Look up a user's shell. Falls back to `/bin/sh`.
fn target_user_shell(username: &str) -> String {
    if let Ok(Some(user)) = nix::unistd::User::from_name(username) {
        return user.shell.to_string_lossy().to_string();
    }
    "/bin/sh".to_string()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- Builder tests --

    #[test]
    fn test_builder_defaults() {
        let config = ShaktiConfig::builder().build();
        assert_eq!(
            config.policy_path,
            PathBuf::from(crate::policy::DEFAULT_POLICY_PATH)
        );
        assert_eq!(config.target_user, "root");
        assert_eq!(config.auth_mode, AuthMode::Interactive);
    }

    #[test]
    fn test_builder_custom() {
        let config = ShaktiConfig::builder()
            .policy_path("/etc/custom/policy.toml")
            .target_user("postgres")
            .auth_mode(AuthMode::TimestampOnly)
            .build();

        assert_eq!(config.policy_path, PathBuf::from("/etc/custom/policy.toml"));
        assert_eq!(config.target_user, "postgres");
        assert_eq!(config.auth_mode, AuthMode::TimestampOnly);
    }

    #[test]
    fn test_builder_skip_auth() {
        let config = ShaktiConfig::builder().auth_mode(AuthMode::Skip).build();
        assert_eq!(config.auth_mode, AuthMode::Skip);
    }

    // -- evaluate_with_policy tests --

    fn test_policy() -> SudoPolicy {
        crate::policy::parse_policy(
            r#"
[defaults]
timestamp_ttl = 300
require_auth = true

[[rules]]
user = "admin"
run_as = "root"
commands = []
require_auth = true
description = "Admin full access"

[[rules]]
user = "deploy"
run_as = "root"
commands = ["/usr/bin/systemctl", "/usr/bin/docker"]
require_auth = false
description = "Deploy user (no password)"

[[rules]]
user = "*"
run_as = "root"
commands = ["/usr/bin/env"]
require_auth = true
description = "Anyone can run env"
"#,
        )
        .unwrap()
    }

    #[test]
    fn test_evaluate_authorized_nopasswd() {
        let policy = test_policy();
        let config = ShaktiConfig::builder().auth_mode(AuthMode::Skip).build();

        let eval = evaluate_with_policy(
            &config,
            &policy,
            "deploy",
            &[],
            &["/usr/bin/docker".to_string()],
        )
        .unwrap();

        assert!(eval.authorized);
        assert!(!eval.require_auth); // deploy rule has require_auth = false
        assert_eq!(eval.resolved_command, PathBuf::from("/usr/bin/docker"));
        assert!(!eval.environment.is_empty());
    }

    #[test]
    fn test_evaluate_authorized_with_auth() {
        let policy = test_policy();
        let config = ShaktiConfig::builder().auth_mode(AuthMode::Skip).build();

        // /usr/bin/env should exist on the system
        let eval = evaluate_with_policy(
            &config,
            &policy,
            "anybody",
            &[],
            &["/usr/bin/env".to_string()],
        )
        .unwrap();

        assert!(eval.authorized);
        // require_auth from the rule is true, but global is also true
        // However auth_mode is Skip, so effective_require_auth is false
        assert!(eval.require_auth); // policy says yes
    }

    #[test]
    fn test_evaluate_denied() {
        let policy = test_policy();
        let config = ShaktiConfig::builder().auth_mode(AuthMode::Skip).build();

        let result = evaluate_with_policy(
            &config,
            &policy,
            "unknown",
            &[],
            &["/usr/bin/docker".to_string()],
        );

        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("denied"));
    }

    #[test]
    fn test_evaluate_invalid_username() {
        let policy = test_policy();
        let config = ShaktiConfig::builder().auth_mode(AuthMode::Skip).build();

        let result = evaluate_with_policy(
            &config,
            &policy,
            "../evil",
            &[],
            &["/usr/bin/env".to_string()],
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_evaluate_invalid_command() {
        let policy = test_policy();
        let config = ShaktiConfig::builder().auth_mode(AuthMode::Skip).build();

        let result = evaluate_with_policy(
            &config,
            &policy,
            "admin",
            &[],
            &["/usr/bin/ls;rm".to_string()],
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_evaluate_timestamp_only_no_timestamp() {
        let policy = test_policy();
        let config = ShaktiConfig::builder()
            .auth_mode(AuthMode::TimestampOnly)
            .build();

        // admin rule requires auth, and there's no timestamp for this user
        let result = evaluate_with_policy(
            &config,
            &policy,
            "admin",
            &[],
            &["/usr/bin/env".to_string()],
        );

        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("timestamp expired"));
    }

    #[test]
    fn test_evaluate_timestamp_only_nopasswd_succeeds() {
        let policy = test_policy();
        let config = ShaktiConfig::builder()
            .auth_mode(AuthMode::TimestampOnly)
            .build();

        // deploy rule has require_auth = false, so TimestampOnly should succeed
        let eval = evaluate_with_policy(
            &config,
            &policy,
            "deploy",
            &[],
            &["/usr/bin/docker".to_string()],
        )
        .unwrap();

        assert!(eval.authorized);
        assert!(!eval.require_auth);
    }

    #[test]
    fn test_evaluate_environment_has_target_user() {
        let policy = test_policy();
        let config = ShaktiConfig::builder()
            .target_user("root")
            .auth_mode(AuthMode::Skip)
            .build();

        let eval = evaluate_with_policy(
            &config,
            &policy,
            "admin",
            &[],
            &["/usr/bin/env".to_string()],
        )
        .unwrap();

        let env_map: std::collections::HashMap<&str, &str> = eval
            .environment
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();

        assert_eq!(env_map["USER"], "root");
        assert_eq!(env_map["SUDO_USER"], "admin");
    }

    #[test]
    fn test_evaluate_custom_target_user() {
        let policy = crate::policy::parse_policy(
            r#"
[[rules]]
user = "admin"
run_as = "*"
commands = []
require_auth = false
"#,
        )
        .unwrap();

        let config = ShaktiConfig::builder()
            .target_user("postgres")
            .auth_mode(AuthMode::Skip)
            .build();

        let eval = evaluate_with_policy(
            &config,
            &policy,
            "admin",
            &[],
            &["/usr/bin/env".to_string()],
        )
        .unwrap();

        let env_map: std::collections::HashMap<&str, &str> = eval
            .environment
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();

        assert_eq!(env_map["USER"], "postgres");
    }

    // -- AuthMode tests --

    #[test]
    fn test_auth_mode_eq() {
        assert_eq!(AuthMode::Interactive, AuthMode::Interactive);
        assert_eq!(AuthMode::TimestampOnly, AuthMode::TimestampOnly);
        assert_eq!(AuthMode::Skip, AuthMode::Skip);
        assert_ne!(AuthMode::Interactive, AuthMode::Skip);
    }

    // -- Helper tests --

    #[test]
    fn test_target_user_home_root() {
        let home = target_user_home("root");
        // Should either find /root from the system or fall back
        assert!(home == "/root" || home.starts_with('/'));
    }

    #[test]
    fn test_target_user_shell_fallback() {
        let shell = target_user_shell("nonexistent_user_xyz_12345");
        assert_eq!(shell, "/bin/sh");
    }

    // -- Additional API edge cases --

    #[test]
    fn test_evaluate_empty_command_args() {
        let policy = test_policy();
        let config = ShaktiConfig::builder().auth_mode(AuthMode::Skip).build();

        let result = evaluate_with_policy(&config, &policy, "admin", &[], &[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_evaluate_custom_max_command_len() {
        let policy = crate::policy::parse_policy(
            r#"
[defaults]
max_command_len = 20

[[rules]]
user = "admin"
commands = []
"#,
        )
        .unwrap();
        let config = ShaktiConfig::builder().auth_mode(AuthMode::Skip).build();

        // Short command should pass
        let result =
            evaluate_with_policy(&config, &policy, "admin", &[], &["/usr/bin/ls".to_string()]);
        assert!(result.is_ok());

        // Long command should be rejected by the policy's max_command_len
        let result = evaluate_with_policy(
            &config,
            &policy,
            "admin",
            &[],
            &["/usr/bin/very_long_command_name_that_exceeds".to_string()],
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_evaluate_interactive_mode_flows_through() {
        let policy = test_policy();
        let config = ShaktiConfig::builder()
            .auth_mode(AuthMode::Interactive)
            .build();

        // For a NOPASSWD rule, Interactive mode should still succeed
        let eval = evaluate_with_policy(
            &config,
            &policy,
            "deploy",
            &[],
            &["/usr/bin/docker".to_string()],
        )
        .unwrap();

        assert!(eval.authorized);
        assert!(!eval.require_auth);
    }

    #[test]
    fn test_evaluate_environment_no_unsafe_vars() {
        let policy = test_policy();
        let config = ShaktiConfig::builder().auth_mode(AuthMode::Skip).build();

        let eval = evaluate_with_policy(
            &config,
            &policy,
            "admin",
            &[],
            &["/usr/bin/env".to_string()],
        )
        .unwrap();

        let keys: std::collections::HashSet<&str> =
            eval.environment.iter().map(|(k, _)| k.as_str()).collect();
        for var in crate::env::UNSAFE_ENV_VARS {
            assert!(
                !keys.contains(var),
                "Unsafe var {} in eval environment",
                var
            );
        }
    }

    #[test]
    fn test_evaluate_resolved_command_is_absolute() {
        let policy = test_policy();
        let config = ShaktiConfig::builder().auth_mode(AuthMode::Skip).build();

        // Pass basename — resolved_command should be an absolute path
        let eval =
            evaluate_with_policy(&config, &policy, "admin", &[], &["env".to_string()]).unwrap();

        assert!(
            eval.resolved_command.is_absolute(),
            "resolved_command should be absolute, got: {}",
            eval.resolved_command.display()
        );
    }
}
