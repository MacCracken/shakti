//! Shakti — AGNOS privilege escalation tool
//!
//! Library crate providing policy evaluation, environment sanitization,
//! command validation, and timestamp management for privilege escalation.

use std::collections::HashSet;
use std::env;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

pub const DEFAULT_POLICY_PATH: &str = "/etc/agnos/sudoers.toml";
pub const DEFAULT_TIMESTAMP_DIR: &str = "/var/run/agnos/sudo";
pub const DEFAULT_TIMESTAMP_TTL_SECS: u64 = 300; // 5 minutes
pub const MAX_AUTH_ATTEMPTS: u32 = 3;
pub const MAX_COMMAND_LEN: usize = 4096;

/// Environment variables that are always removed before exec.
pub const UNSAFE_ENV_VARS: &[&str] = &[
    // Dynamic linker — all LD_* are dangerous
    "LD_PRELOAD",
    "LD_LIBRARY_PATH",
    "LD_AUDIT",
    "LD_DYNAMIC_WEAK",
    "LD_BIND_NOW",
    "LD_AOUT_LIBRARY_PATH",
    "LD_AOUT_PRELOAD",
    "LD_ORIGIN_PATH",
    "LD_DEBUG",
    "LD_DEBUG_OUTPUT",
    "LD_PROFILE",
    "LD_PROFILE_OUTPUT",
    "LD_SHOW_AUXV",
    "LD_USE_LOAD_BIAS",
    "LD_HWCAP_MASK",
    "LD_TRACE_LOADED_OBJECTS",
    "LD_WARN",
    "LD_VERBOSE",
    "LD_TRACE_PRELINKING",
    // DNS/locale hijacking
    "LOCALDOMAIN",
    "RES_OPTIONS",
    "HOSTALIASES",
    "NLSPATH",
    "PATH_LOCALE",
    "GCONV_PATH",
    // Shell injection vectors
    "IFS",
    "ENV",
    "BASH_ENV",
    "CDPATH",
    "GLOBIGNORE",
    "SHELLOPTS",
    "BASHOPTS",
    "PS4",
    "PROMPT_COMMAND",
    // Interpreter code injection
    "PYTHONPATH",
    "PYTHONSTARTUP",
    "PYTHONHOME",
    "PERL5LIB",
    "PERL5OPT",
    "PERLLIB",
    "RUBYLIB",
    "RUBYOPT",
    "NODE_PATH",
    "NODE_OPTIONS",
    "CLASSPATH",
    "JAVA_TOOL_OPTIONS",
];

/// Environment variables preserved by default.
pub const SAFE_ENV_VARS: &[&str] = &[
    "TERM",
    "COLORTERM",
    "LANG",
    "LANGUAGE",
    "LC_ALL",
    "LC_CTYPE",
    "TZ",
    "DISPLAY",
    "XAUTHORITY",
];

// ---------------------------------------------------------------------------
// Policy types
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
            timestamp_ttl: DEFAULT_TIMESTAMP_TTL_SECS,
            require_auth: true,
            audit_log: true,
            env_keep: Vec::new(),
            max_command_len: MAX_COMMAND_LEN,
        }
    }
}

fn default_ttl() -> u64 {
    DEFAULT_TIMESTAMP_TTL_SECS
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

// ---------------------------------------------------------------------------
// Policy loading and evaluation
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

/// Result of an authorization check.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum AuthzResult {
    Allowed { require_auth: bool },
    Denied(String),
}

/// Check if a command matches a pattern.
///
/// Patterns:
/// - Exact path: `/usr/bin/systemctl` matches only that binary
/// - Glob-style: `/usr/bin/*` matches any binary in that dir
/// - Basename: `systemctl` matches any path ending in `systemctl`
/// - `ALL` or `*`: matches everything
#[must_use]
pub fn command_matches(command: &str, pattern: &str) -> bool {
    if pattern == "ALL" || pattern == "*" {
        return true;
    }

    let cmd_path = Path::new(command);
    // Exact match
    if command == pattern {
        return true;
    }

    // Glob: pattern ends with /*
    if let Some(prefix) = pattern.strip_suffix("/*")
        && let Some(parent) = cmd_path.parent()
    {
        return parent == Path::new(prefix);
    }

    // Basename match (pattern has no /)
    if !pattern.contains('/')
        && let Some(basename) = cmd_path.file_name()
    {
        return basename == pattern.as_ref() as &std::ffi::OsStr;
    }

    false
}

// ---------------------------------------------------------------------------
// Environment sanitization
// ---------------------------------------------------------------------------

/// Build a sanitized environment for the target command.
#[must_use]
#[allow(clippy::vec_init_then_push)]
pub fn sanitize_environment(
    policy: &SudoPolicy,
    caller_user: &str,
    target_user: &str,
    target_home: &str,
    target_shell: &str,
) -> Vec<(String, String)> {
    let mut env: Vec<(String, String)> = Vec::new();

    // Always set these
    env.push(("USER".to_string(), target_user.to_string()));
    env.push(("LOGNAME".to_string(), target_user.to_string()));
    env.push(("HOME".to_string(), target_home.to_string()));
    env.push(("SHELL".to_string(), target_shell.to_string()));
    env.push((
        "PATH".to_string(),
        "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".to_string(),
    ));
    env.push(("SUDO_USER".to_string(), caller_user.to_string()));
    env.push(("SUDO_UID".to_string(), nix::unistd::getuid().to_string()));
    env.push(("SUDO_GID".to_string(), nix::unistd::getgid().to_string()));

    // Preserve safe vars from current environment
    let keep_set: HashSet<&str> = SAFE_ENV_VARS
        .iter()
        .copied()
        .chain(policy.defaults.env_keep.iter().map(|s| s.as_str()))
        .collect();

    for (key, value) in env::vars() {
        // Block all LD_* regardless of explicit list — the linker namespace is unbounded
        if key.starts_with("LD_") {
            continue;
        }
        if keep_set.contains(key.as_str()) && !UNSAFE_ENV_VARS.contains(&key.as_str()) {
            env.push((key, value));
        }
    }

    env
}

// ---------------------------------------------------------------------------
// Timestamp credential cache
// ---------------------------------------------------------------------------

/// Check if the user has a valid timestamp (recently authenticated).
#[must_use]
pub fn check_timestamp(user: &str, ttl: Duration) -> bool {
    let ts_path = timestamp_path(user);
    match std::fs::metadata(&ts_path) {
        Ok(meta) => {
            if let Ok(modified) = meta.modified()
                && let Ok(elapsed) = SystemTime::now().duration_since(modified)
            {
                return elapsed < ttl;
            }
            false
        }
        Err(_) => false,
    }
}

/// Update the timestamp for a user (mark as recently authenticated).
pub fn update_timestamp(user: &str) -> Result<()> {
    validate_username(user)?;
    let ts_path = timestamp_path(user);
    let dir = Path::new(DEFAULT_TIMESTAMP_DIR);
    if !dir.exists() {
        std::fs::create_dir_all(dir)
            .with_context(|| format!("Failed to create timestamp directory: {}", dir.display()))?;
    }
    // Touch the file
    std::fs::write(&ts_path, b"")
        .with_context(|| format!("Failed to update timestamp: {}", ts_path.display()))?;
    Ok(())
}

/// Remove timestamp for a user (invalidate cached credentials).
pub fn invalidate_timestamp(user: &str) -> Result<()> {
    validate_username(user)?;
    let ts_path = timestamp_path(user);
    if ts_path.exists() {
        std::fs::remove_file(&ts_path)?;
    }
    Ok(())
}

/// Validate a username is safe for use in filesystem paths.
pub fn validate_username(user: &str) -> Result<()> {
    if user.is_empty() {
        bail!("Empty username");
    }
    if user.contains('/') || user.contains('\0') || user == "." || user == ".." {
        bail!("Invalid username: contains path traversal characters");
    }
    Ok(())
}

pub fn timestamp_path(user: &str) -> PathBuf {
    PathBuf::from(DEFAULT_TIMESTAMP_DIR).join(user)
}

// ---------------------------------------------------------------------------
// Input validation
// ---------------------------------------------------------------------------

/// Validate command arguments for safety.
pub fn validate_command(args: &[String], max_len: usize) -> Result<()> {
    if args.is_empty() {
        bail!("No command specified");
    }

    let total_len: usize = args.iter().map(|a| a.len()).sum::<usize>() + args.len();
    if total_len > max_len {
        bail!("Command too long ({} bytes, max {})", total_len, max_len);
    }

    // Reject null bytes in arguments (could be used to truncate strings in C APIs)
    for arg in args {
        if arg.contains('\0') {
            bail!("Command argument contains null byte");
        }
    }

    // The command (first arg) must be an absolute path or resolvable basename
    let cmd = &args[0];
    if cmd.is_empty() {
        bail!("Empty command name");
    }

    // Reject shell metacharacters in the command name itself.
    // Arguments may legitimately contain these (e.g., grep patterns),
    // but the command binary name must not.
    const SHELL_META: &[char] = &[';', '|', '&', '`', '$', '(', ')', '{', '}', '<', '>', '!'];
    if cmd.chars().any(|c| SHELL_META.contains(&c)) {
        bail!("Command name contains shell metacharacter: {}", cmd);
    }

    Ok(())
}

/// Check if a path is an executable regular file.
fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    match std::fs::metadata(path) {
        Ok(meta) => {
            // Must be a regular file (not a directory, symlink to dir, etc.)
            meta.is_file() && (meta.mode() & 0o111 != 0)
        }
        Err(_) => false,
    }
}

/// Resolve a command to its absolute path using PATH.
pub fn resolve_command(cmd: &str) -> Result<PathBuf> {
    // Already absolute
    if cmd.starts_with('/') {
        let path = PathBuf::from(cmd);
        if is_executable(&path) {
            return Ok(path);
        }
        bail!("Command not found or not executable: {}", cmd);
    }

    // Reject relative paths with / (e.g., ../bin/bash)
    if cmd.contains('/') {
        bail!(
            "Relative paths not allowed. Use an absolute path or a command name: {}",
            cmd
        );
    }

    // Search PATH
    let search_path = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
    for dir in search_path.split(':') {
        let candidate = PathBuf::from(dir).join(cmd);
        if is_executable(&candidate) {
            return Ok(candidate);
        }
    }

    bail!("Command not found in PATH: {}", cmd);
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Policy parsing
    // -----------------------------------------------------------------------

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
        assert_eq!(policy.defaults.timestamp_ttl, DEFAULT_TIMESTAMP_TTL_SECS);
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

    // -----------------------------------------------------------------------
    // Authorization
    // -----------------------------------------------------------------------

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

    // -----------------------------------------------------------------------
    // Command matching
    // -----------------------------------------------------------------------

    #[test]
    fn test_command_matches_exact() {
        assert!(command_matches("/usr/bin/ls", "/usr/bin/ls"));
        assert!(!command_matches("/usr/bin/rm", "/usr/bin/ls"));
    }

    #[test]
    fn test_command_matches_all() {
        assert!(command_matches("/usr/bin/anything", "ALL"));
        assert!(command_matches("/usr/bin/anything", "*"));
    }

    #[test]
    fn test_command_matches_glob() {
        assert!(command_matches("/usr/bin/ls", "/usr/bin/*"));
        assert!(!command_matches("/usr/sbin/reboot", "/usr/bin/*"));
    }

    #[test]
    fn test_command_matches_basename() {
        assert!(command_matches("/usr/bin/systemctl", "systemctl"));
        assert!(command_matches("/usr/local/bin/systemctl", "systemctl"));
        assert!(!command_matches("/usr/bin/systemd", "systemctl"));
    }

    #[test]
    fn test_command_matches_no_match() {
        assert!(!command_matches("/usr/bin/rm", "/usr/bin/ls"));
    }

    // -----------------------------------------------------------------------
    // Command validation
    // -----------------------------------------------------------------------

    #[test]
    fn test_validate_command_ok() {
        let args = vec!["ls".to_string(), "-la".to_string()];
        assert!(validate_command(&args, 4096).is_ok());
    }

    #[test]
    fn test_validate_command_empty() {
        let args: Vec<String> = vec![];
        assert!(validate_command(&args, 4096).is_err());
    }

    #[test]
    fn test_validate_command_too_long() {
        let args = vec!["a".repeat(5000)];
        assert!(validate_command(&args, 4096).is_err());
    }

    #[test]
    fn test_validate_command_null_byte() {
        let args = vec!["ls\0-la".to_string()];
        assert!(validate_command(&args, 4096).is_err());
    }

    #[test]
    fn test_validate_command_empty_name() {
        let args = vec!["".to_string()];
        assert!(validate_command(&args, 4096).is_err());
    }

    // -----------------------------------------------------------------------
    // Command resolution
    // -----------------------------------------------------------------------

    #[test]
    fn test_resolve_command_absolute() {
        let result = resolve_command("/usr/bin/env");
        if Path::new("/usr/bin/env").exists() {
            assert_eq!(result.unwrap(), PathBuf::from("/usr/bin/env"));
        }
    }

    #[test]
    fn test_resolve_command_basename() {
        let result = resolve_command("env");
        assert!(result.is_ok());
    }

    #[test]
    fn test_resolve_command_not_found() {
        let result = resolve_command("/nonexistent/path/to/binary");
        assert!(result.is_err());
    }

    #[test]
    fn test_resolve_command_relative_rejected() {
        let result = resolve_command("../bin/bash");
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("Relative paths not allowed"));
    }

    // -----------------------------------------------------------------------
    // Environment sanitization
    // -----------------------------------------------------------------------

    #[test]
    fn test_sanitize_environment() {
        let policy = parse_policy("").unwrap();
        let env = sanitize_environment(&policy, "alice", "root", "/root", "/bin/bash");

        let env_map: std::collections::HashMap<&str, &str> =
            env.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();

        assert_eq!(env_map["USER"], "root");
        assert_eq!(env_map["LOGNAME"], "root");
        assert_eq!(env_map["HOME"], "/root");
        assert_eq!(env_map["SHELL"], "/bin/bash");
        assert_eq!(env_map["SUDO_USER"], "alice");
        assert!(env_map.contains_key("PATH"));
    }

    #[test]
    fn test_sanitize_environment_no_unsafe_vars() {
        let policy = parse_policy("").unwrap();
        let env = sanitize_environment(&policy, "alice", "root", "/root", "/bin/bash");

        let keys: HashSet<&str> = env.iter().map(|(k, _)| k.as_str()).collect();
        for var in UNSAFE_ENV_VARS {
            assert!(
                !keys.contains(var),
                "Unsafe var {} should not be in env",
                var
            );
        }
    }

    #[test]
    fn test_sanitize_environment_with_env_keep() {
        let policy = parse_policy(
            r#"
[defaults]
env_keep = ["EDITOR"]
"#,
        )
        .unwrap();
        assert!(policy.defaults.env_keep.contains(&"EDITOR".to_string()));
    }

    // -----------------------------------------------------------------------
    // Timestamp cache
    // -----------------------------------------------------------------------

    #[test]
    fn test_timestamp_path() {
        let path = timestamp_path("alice");
        assert_eq!(path, PathBuf::from("/var/run/agnos/sudo/alice"));
    }

    #[test]
    fn test_check_timestamp_nonexistent() {
        assert!(!check_timestamp(
            "test_nonexistent_user_xyz",
            Duration::from_secs(300)
        ));
    }

    // -----------------------------------------------------------------------
    // AuthzResult
    // -----------------------------------------------------------------------

    #[test]
    fn test_authz_result_debug() {
        let allowed = AuthzResult::Allowed { require_auth: true };
        let dbg = format!("{:?}", allowed);
        assert!(dbg.contains("Allowed"));

        let denied = AuthzResult::Denied("nope".to_string());
        let dbg = format!("{:?}", denied);
        assert!(dbg.contains("Denied"));
        assert!(dbg.contains("nope"));
    }

    #[test]
    fn test_authz_result_eq() {
        assert_eq!(
            AuthzResult::Allowed { require_auth: true },
            AuthzResult::Allowed { require_auth: true }
        );
        assert_ne!(
            AuthzResult::Allowed { require_auth: true },
            AuthzResult::Allowed {
                require_auth: false
            }
        );
        assert_ne!(
            AuthzResult::Allowed { require_auth: true },
            AuthzResult::Denied("x".to_string())
        );
    }

    // -----------------------------------------------------------------------
    // Policy edge cases
    // -----------------------------------------------------------------------

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

    // -----------------------------------------------------------------------
    // Constants
    // -----------------------------------------------------------------------

    #[test]
    fn test_default_policy_path() {
        assert_eq!(DEFAULT_POLICY_PATH, "/etc/agnos/sudoers.toml");
    }

    #[test]
    fn test_default_timestamp_dir() {
        assert_eq!(DEFAULT_TIMESTAMP_DIR, "/var/run/agnos/sudo");
    }

    #[test]
    fn test_unsafe_env_vars_contains_ld_preload() {
        assert!(UNSAFE_ENV_VARS.contains(&"LD_PRELOAD"));
        assert!(UNSAFE_ENV_VARS.contains(&"LD_LIBRARY_PATH"));
        assert!(UNSAFE_ENV_VARS.contains(&"BASH_ENV"));
        assert!(UNSAFE_ENV_VARS.contains(&"IFS"));
    }

    #[test]
    fn test_safe_env_vars() {
        assert!(SAFE_ENV_VARS.contains(&"TERM"));
        assert!(SAFE_ENV_VARS.contains(&"LANG"));
        assert!(SAFE_ENV_VARS.contains(&"TZ"));
    }

    // -----------------------------------------------------------------------
    // Username validation (path traversal prevention)
    // -----------------------------------------------------------------------

    #[test]
    fn test_validate_username_ok() {
        assert!(validate_username("alice").is_ok());
        assert!(validate_username("bob_123").is_ok());
    }

    #[test]
    fn test_validate_username_empty() {
        assert!(validate_username("").is_err());
    }

    #[test]
    fn test_validate_username_path_traversal() {
        assert!(validate_username("../etc/passwd").is_err());
        assert!(validate_username("..").is_err());
        assert!(validate_username(".").is_err());
        assert!(validate_username("user/name").is_err());
    }

    #[test]
    fn test_validate_username_null_byte() {
        assert!(validate_username("alice\0bob").is_err());
    }

    // -----------------------------------------------------------------------
    // Shell metacharacter rejection in command name
    // -----------------------------------------------------------------------

    #[test]
    fn test_validate_command_shell_metachar_semicolon() {
        let args = vec!["/usr/bin/ls;rm".to_string()];
        assert!(validate_command(&args, 4096).is_err());
    }

    #[test]
    fn test_validate_command_shell_metachar_pipe() {
        let args = vec!["/usr/bin/cat|nc".to_string()];
        assert!(validate_command(&args, 4096).is_err());
    }

    #[test]
    fn test_validate_command_shell_metachar_backtick() {
        let args = vec!["/usr/bin/`whoami`".to_string()];
        assert!(validate_command(&args, 4096).is_err());
    }

    #[test]
    fn test_validate_command_shell_metachar_dollar() {
        let args = vec!["$(id)".to_string()];
        assert!(validate_command(&args, 4096).is_err());
    }

    #[test]
    fn test_validate_command_args_may_contain_metachar() {
        let args = vec!["grep".to_string(), "foo|bar".to_string()];
        assert!(validate_command(&args, 4096).is_ok());
    }

    // -----------------------------------------------------------------------
    // Expanded unsafe env var coverage
    // -----------------------------------------------------------------------

    #[test]
    fn test_unsafe_env_vars_ld_extras() {
        assert!(UNSAFE_ENV_VARS.contains(&"LD_HWCAP_MASK"));
        assert!(UNSAFE_ENV_VARS.contains(&"LD_TRACE_LOADED_OBJECTS"));
        assert!(UNSAFE_ENV_VARS.contains(&"LD_WARN"));
        assert!(UNSAFE_ENV_VARS.contains(&"LD_VERBOSE"));
        assert!(UNSAFE_ENV_VARS.contains(&"LD_TRACE_PRELINKING"));
    }

    #[test]
    fn test_unsafe_env_vars_interpreters() {
        assert!(UNSAFE_ENV_VARS.contains(&"PYTHONPATH"));
        assert!(UNSAFE_ENV_VARS.contains(&"PYTHONSTARTUP"));
        assert!(UNSAFE_ENV_VARS.contains(&"PERL5LIB"));
        assert!(UNSAFE_ENV_VARS.contains(&"RUBYLIB"));
        assert!(UNSAFE_ENV_VARS.contains(&"NODE_PATH"));
        assert!(UNSAFE_ENV_VARS.contains(&"NODE_OPTIONS"));
        assert!(UNSAFE_ENV_VARS.contains(&"CLASSPATH"));
        assert!(UNSAFE_ENV_VARS.contains(&"JAVA_TOOL_OPTIONS"));
    }

    // -----------------------------------------------------------------------
    // LD_* prefix catch-all in sanitization
    // -----------------------------------------------------------------------

    #[test]
    fn test_sanitize_environment_blocks_unknown_ld_vars() {
        let policy = parse_policy(
            r#"
[defaults]
env_keep = ["LD_FUTURE_EXPLOIT"]
"#,
        )
        .unwrap();

        // SAFETY: test runs are single-threaded for this test
        unsafe { std::env::set_var("LD_FUTURE_EXPLOIT", "gotcha") };
        let env = sanitize_environment(&policy, "alice", "root", "/root", "/bin/bash");
        let keys: HashSet<&str> = env.iter().map(|(k, _)| k.as_str()).collect();
        assert!(
            !keys.contains("LD_FUTURE_EXPLOIT"),
            "LD_* prefix catch-all should block even env_keep'd LD_ vars"
        );
        // SAFETY: test cleanup
        unsafe { std::env::remove_var("LD_FUTURE_EXPLOIT") };
    }

    // -----------------------------------------------------------------------
    // Command resolution — executable check
    // -----------------------------------------------------------------------

    #[test]
    fn test_resolve_command_directory_rejected() {
        let result = resolve_command("/usr/bin");
        assert!(result.is_err());
    }
}
