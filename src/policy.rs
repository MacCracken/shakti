//! Policy types, parsing, loading, and authorization evaluation.

use std::path::Path;

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

use crate::validate::command_matches;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

pub const DEFAULT_POLICY_PATH: &str = "/etc/agnos/sudoers.toml";
pub const MAX_COMMAND_LEN: usize = 4096;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Top-level sudoers policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SudoPolicy {
    /// Global settings.
    #[serde(default)]
    pub defaults: PolicyDefaults,
    /// Per-user rules.
    #[serde(default)]
    pub rules: Vec<PolicyRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyDefaults {
    /// Credential cache TTL in seconds (0 = always ask).
    #[serde(default = "default_ttl")]
    pub timestamp_ttl: u64,
    /// Whether to require a password (false = NOPASSWD for all).
    #[serde(default = "default_true")]
    pub require_auth: bool,
    /// Whether to log all commands to audit.
    #[serde(default = "default_true")]
    pub audit_log: bool,
    /// Environment variables to preserve (in addition to SAFE_ENV_VARS).
    #[serde(default)]
    pub env_keep: Vec<String>,
    /// Maximum command length.
    #[serde(default = "default_max_cmd_len")]
    pub max_command_len: usize,
}

impl Default for PolicyDefaults {
    fn default() -> Self {
        Self {
            timestamp_ttl: crate::timestamp::DEFAULT_TIMESTAMP_TTL_SECS,
            require_auth: true,
            audit_log: true,
            env_keep: Vec::new(),
            max_command_len: MAX_COMMAND_LEN,
        }
    }
}

fn default_ttl() -> u64 {
    crate::timestamp::DEFAULT_TIMESTAMP_TTL_SECS
}
fn default_true() -> bool {
    true
}
fn default_max_cmd_len() -> usize {
    MAX_COMMAND_LEN
}

/// A single policy rule granting privileges.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRule {
    /// Username this rule applies to (or "*" for all).
    #[serde(default)]
    pub user: Option<String>,
    /// Group this rule applies to (prefixed with `%` in traditional sudo).
    #[serde(default)]
    pub group: Option<String>,
    /// Target user to run as (default: "root").
    #[serde(default = "default_target_user")]
    pub run_as: String,
    /// Allowed commands (empty = all commands).
    #[serde(default)]
    pub commands: Vec<String>,
    /// Denied commands (checked before allowed).
    #[serde(default)]
    pub deny_commands: Vec<String>,
    /// Whether authentication is required for this rule.
    #[serde(default = "default_true")]
    pub require_auth: bool,
    /// Human-readable description.
    #[serde(default)]
    pub description: String,
}

fn default_target_user() -> String {
    "root".to_string()
}

/// Result of an authorization check.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum AuthzResult {
    Allowed { require_auth: bool },
    Denied(String),
}

// ---------------------------------------------------------------------------
// Loading
// ---------------------------------------------------------------------------

/// Load the sudoers policy from a TOML file.
pub fn load_policy(path: &Path) -> Result<SudoPolicy> {
    if !path.exists() {
        bail!(
            "Policy file not found: {}. Create it or use --policy to specify a path.",
            path.display()
        );
    }

    // Security: policy file must be owned by root and not world-writable
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::MetadataExt;
        let meta = std::fs::metadata(path)
            .with_context(|| format!("Cannot stat policy file: {}", path.display()))?;
        if meta.uid() != 0 {
            bail!(
                "Policy file {} is not owned by root (uid={}). Refusing to use it.",
                path.display(),
                meta.uid()
            );
        }
        let mode = meta.mode();
        if mode & 0o002 != 0 {
            bail!(
                "Policy file {} is world-writable (mode {:o}). Refusing to use it.",
                path.display(),
                mode
            );
        }
    }

    let content = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read {}", path.display()))?;
    let policy: SudoPolicy =
        toml::from_str(&content).with_context(|| format!("Failed to parse {}", path.display()))?;

    Ok(policy)
}

/// Parse policy from a TOML string (for testing).
pub fn parse_policy(content: &str) -> Result<SudoPolicy> {
    let policy: SudoPolicy = toml::from_str(content)?;
    Ok(policy)
}

// ---------------------------------------------------------------------------
// Authorization
// ---------------------------------------------------------------------------

/// Check whether a user is authorized to run a command under a policy.
#[must_use]
pub fn check_authorization(
    policy: &SudoPolicy,
    username: &str,
    groups: &[String],
    target_user: &str,
    command: &str,
) -> AuthzResult {
    let mut matched_rule: Option<&PolicyRule> = None;

    for rule in &policy.rules {
        // Check user match
        let user_matches = match &rule.user {
            Some(u) if u == "*" => true,
            Some(u) => u == username,
            None => false,
        };

        // Check group match
        let group_matches = match &rule.group {
            Some(g) => groups.iter().any(|ug| ug == g),
            None => false,
        };

        if !user_matches && !group_matches {
            continue;
        }

        // Check target user
        if rule.run_as != "*" && rule.run_as != target_user {
            continue;
        }

        // Check denied commands first
        for deny in &rule.deny_commands {
            if command_matches(command, deny) {
                return AuthzResult::Denied(format!(
                    "Command '{}' is explicitly denied by rule: {}",
                    command, rule.description
                ));
            }
        }

        // Check allowed commands
        if rule.commands.is_empty() {
            // Empty = all commands allowed
            matched_rule = Some(rule);
            break;
        }

        for allowed in &rule.commands {
            if command_matches(command, allowed) {
                matched_rule = Some(rule);
                break;
            }
        }

        if matched_rule.is_some() {
            break;
        }
    }

    match matched_rule {
        Some(rule) => AuthzResult::Allowed {
            require_auth: rule.require_auth && policy.defaults.require_auth,
        },
        None => AuthzResult::Denied(format!(
            "User '{}' is not authorized to run '{}' as '{}'",
            username, command, target_user
        )),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_policy() -> &'static str {
        r#"
[defaults]
timestamp_ttl = 300
require_auth = true
audit_log = true
env_keep = ["EDITOR", "VISUAL"]
max_command_len = 4096

[[rules]]
user = "admin"
run_as = "root"
commands = []
require_auth = true
description = "Admin has full access"

[[rules]]
group = "wheel"
run_as = "root"
commands = ["/usr/bin/systemctl", "/usr/bin/journalctl"]
require_auth = true
description = "Wheel group can manage services"

[[rules]]
user = "deploy"
run_as = "root"
commands = ["/usr/bin/systemctl restart *", "/usr/bin/docker"]
deny_commands = ["/usr/bin/systemctl stop firewall"]
require_auth = false
description = "Deploy user can restart services (no password)"

[[rules]]
user = "*"
run_as = "root"
commands = ["/usr/bin/passwd"]
require_auth = true
description = "Anyone can change passwords"
"#
    }

    #[test]
    fn test_parse_policy() {
        let policy = parse_policy(sample_policy()).unwrap();
        assert_eq!(policy.defaults.timestamp_ttl, 300);
        assert!(policy.defaults.require_auth);
        assert!(policy.defaults.audit_log);
        assert_eq!(policy.defaults.env_keep, vec!["EDITOR", "VISUAL"]);
        assert_eq!(policy.rules.len(), 4);
    }

    #[test]
    fn test_parse_policy_defaults() {
        let policy = parse_policy("").unwrap();
        assert_eq!(
            policy.defaults.timestamp_ttl,
            crate::timestamp::DEFAULT_TIMESTAMP_TTL_SECS
        );
        assert!(policy.defaults.require_auth);
        assert!(policy.defaults.audit_log);
        assert_eq!(policy.defaults.max_command_len, MAX_COMMAND_LEN);
        assert!(policy.rules.is_empty());
    }

    #[test]
    fn test_parse_policy_minimal_rule() {
        let policy = parse_policy(
            r#"
[[rules]]
user = "bob"
"#,
        )
        .unwrap();
        assert_eq!(policy.rules.len(), 1);
        assert_eq!(policy.rules[0].run_as, "root");
        assert!(policy.rules[0].commands.is_empty());
        assert!(policy.rules[0].require_auth);
    }

    #[test]
    fn test_authz_admin_full_access() {
        let policy = parse_policy(sample_policy()).unwrap();
        let result = check_authorization(&policy, "admin", &[], "root", "/usr/bin/anything");
        assert_eq!(result, AuthzResult::Allowed { require_auth: true });
    }

    #[test]
    fn test_authz_wheel_group_allowed() {
        let policy = parse_policy(sample_policy()).unwrap();
        let groups = vec!["wheel".to_string()];
        let result = check_authorization(&policy, "jdoe", &groups, "root", "/usr/bin/systemctl");
        assert_eq!(result, AuthzResult::Allowed { require_auth: true });
    }

    #[test]
    fn test_authz_wheel_group_denied_command() {
        let policy = parse_policy(sample_policy()).unwrap();
        let groups = vec!["wheel".to_string()];
        let result = check_authorization(&policy, "jdoe", &groups, "root", "/usr/bin/rm");
        assert!(matches!(result, AuthzResult::Denied(_)));
    }

    #[test]
    fn test_authz_deploy_nopasswd() {
        let policy = parse_policy(sample_policy()).unwrap();
        let result = check_authorization(&policy, "deploy", &[], "root", "/usr/bin/docker");
        assert_eq!(
            result,
            AuthzResult::Allowed {
                require_auth: false
            }
        );
    }

    #[test]
    fn test_authz_deploy_denied_command() {
        let policy = parse_policy(sample_policy()).unwrap();
        let result = check_authorization(
            &policy,
            "deploy",
            &[],
            "root",
            "/usr/bin/systemctl stop firewall",
        );
        assert!(matches!(result, AuthzResult::Denied(_)));
    }

    #[test]
    fn test_authz_wildcard_user() {
        let policy = parse_policy(sample_policy()).unwrap();
        let result = check_authorization(&policy, "anybody", &[], "root", "/usr/bin/passwd");
        assert_eq!(result, AuthzResult::Allowed { require_auth: true });
    }

    #[test]
    fn test_authz_unknown_user_denied() {
        let policy = parse_policy(sample_policy()).unwrap();
        let result = check_authorization(&policy, "unknown", &[], "root", "/usr/bin/dangerous");
        assert!(matches!(result, AuthzResult::Denied(_)));
    }

    #[test]
    fn test_authz_wrong_target_user() {
        let policy = parse_policy(sample_policy()).unwrap();
        let result = check_authorization(&policy, "admin", &[], "postgres", "/usr/bin/anything");
        assert!(matches!(result, AuthzResult::Denied(_)));
    }

    #[test]
    fn test_authz_run_as_wildcard() {
        let policy = parse_policy(
            r#"
[[rules]]
user = "admin"
run_as = "*"
commands = []
"#,
        )
        .unwrap();
        let result = check_authorization(&policy, "admin", &[], "postgres", "/usr/bin/psql");
        assert_eq!(result, AuthzResult::Allowed { require_auth: true });
    }

    #[test]
    fn test_authz_no_rules() {
        let policy = parse_policy("").unwrap();
        let result = check_authorization(&policy, "admin", &[], "root", "/usr/bin/ls");
        assert!(matches!(result, AuthzResult::Denied(_)));
    }

    #[test]
    fn test_authz_group_only_rule() {
        let policy = parse_policy(
            r#"
[[rules]]
group = "devops"
run_as = "root"
commands = ["/usr/bin/docker"]
"#,
        )
        .unwrap();
        let result = check_authorization(&policy, "alice", &[], "root", "/usr/bin/docker");
        assert!(matches!(result, AuthzResult::Denied(_)));

        let groups = vec!["devops".to_string()];
        let result = check_authorization(&policy, "alice", &groups, "root", "/usr/bin/docker");
        assert_eq!(result, AuthzResult::Allowed { require_auth: true });
    }

    #[test]
    fn test_policy_require_auth_override() {
        let policy = parse_policy(
            r#"
[defaults]
require_auth = false

[[rules]]
user = "admin"
require_auth = true
"#,
        )
        .unwrap();
        let result = check_authorization(&policy, "admin", &[], "root", "/usr/bin/ls");
        assert_eq!(
            result,
            AuthzResult::Allowed {
                require_auth: false
            }
        );
    }

    #[test]
    fn test_policy_deny_takes_precedence() {
        let policy = parse_policy(
            r#"
[[rules]]
user = "admin"
commands = ["ALL"]
deny_commands = ["/usr/bin/rm"]
"#,
        )
        .unwrap();
        let result = check_authorization(&policy, "admin", &[], "root", "/usr/bin/rm");
        assert!(matches!(result, AuthzResult::Denied(_)));

        let result = check_authorization(&policy, "admin", &[], "root", "/usr/bin/ls");
        assert_eq!(result, AuthzResult::Allowed { require_auth: true });
    }

    #[test]
    fn test_policy_multiple_groups() {
        let policy = parse_policy(
            r#"
[[rules]]
group = "docker"
commands = ["/usr/bin/docker"]

[[rules]]
group = "admin"
commands = ["ALL"]
"#,
        )
        .unwrap();
        let groups = vec!["docker".to_string(), "admin".to_string()];

        let result = check_authorization(&policy, "bob", &groups, "root", "/usr/bin/docker");
        assert_eq!(result, AuthzResult::Allowed { require_auth: true });

        let result = check_authorization(&policy, "bob", &groups, "root", "/usr/bin/ls");
        assert_eq!(result, AuthzResult::Allowed { require_auth: true });
    }

    #[test]
    fn test_default_policy_path() {
        assert_eq!(DEFAULT_POLICY_PATH, "/etc/agnos/sudoers.toml");
    }
}
