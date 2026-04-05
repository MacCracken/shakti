//! Command and username validation.

use std::path::{Path, PathBuf};

use anyhow::{Result, bail};

// ---------------------------------------------------------------------------
// Username validation
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Command validation
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

// ---------------------------------------------------------------------------
// Command matching
// ---------------------------------------------------------------------------

/// Check if a command matches a pattern.
///
/// The `command` string may contain arguments (e.g., `/usr/bin/systemctl restart nginx`).
///
/// Patterns:
/// - `ALL` or `*`: matches everything
/// - Exact: `/usr/bin/systemctl restart nginx` matches only that exact string
/// - Prefix wildcard: `/usr/bin/systemctl restart *` matches any command starting
///   with `/usr/bin/systemctl restart ` (trailing ` *` acts as argument wildcard)
/// - Directory glob: `/usr/bin/*` matches any binary path under `/usr/bin/`
///   (only the binary portion is checked — the part before the first space)
/// - Basename: `systemctl` matches any path whose binary basename is `systemctl`
#[must_use]
pub fn command_matches(command: &str, pattern: &str) -> bool {
    if pattern == "ALL" || pattern == "*" {
        return true;
    }

    // Exact match (including arguments)
    if command == pattern {
        return true;
    }

    // Prefix wildcard: pattern ends with " *" — match command prefix
    // e.g., "/usr/bin/systemctl restart *" matches "/usr/bin/systemctl restart nginx"
    if let Some(prefix) = pattern.strip_suffix(" *") {
        return command == prefix
            || (command.len() > prefix.len()
                && command.as_bytes()[prefix.len()] == b' '
                && command.starts_with(prefix));
    }

    // Extract just the binary path (part before first space) for path-level matching.
    // Avoid allocation — find the space index and slice.
    let cmd_binary = match command.find(' ') {
        Some(idx) => &command[..idx],
        None => command,
    };
    let cmd_path = Path::new(cmd_binary);

    // Directory glob: pattern ends with /*
    if let Some(dir_prefix) = pattern.strip_suffix("/*")
        && let Some(parent) = cmd_path.parent()
    {
        // Handle "/*" → dir_prefix is "" but parent is "/"
        let expected = if dir_prefix.is_empty() {
            Path::new("/")
        } else {
            Path::new(dir_prefix)
        };
        return parent == expected;
    }

    // Basename match (pattern has no / — matches just the binary name)
    if !pattern.contains('/')
        && let Some(basename) = cmd_path.file_name()
    {
        return basename == pattern.as_ref() as &std::ffi::OsStr;
    }

    false
}

// ---------------------------------------------------------------------------
// Command resolution
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- Username validation --

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

    // -- Command validation --

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

    // -- Command matching --

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

    // -- Argument-level wildcard matching --

    #[test]
    fn test_command_matches_arg_wildcard() {
        assert!(command_matches(
            "/usr/bin/systemctl restart nginx",
            "/usr/bin/systemctl restart *"
        ));
    }

    #[test]
    fn test_command_matches_arg_wildcard_different_args() {
        assert!(command_matches(
            "/usr/bin/systemctl restart sshd",
            "/usr/bin/systemctl restart *"
        ));
    }

    #[test]
    fn test_command_matches_arg_wildcard_no_args() {
        // Pattern requires at least "restart" argument — bare binary should not match
        assert!(!command_matches(
            "/usr/bin/systemctl",
            "/usr/bin/systemctl restart *"
        ));
    }

    #[test]
    fn test_command_matches_arg_wildcard_wrong_subcommand() {
        assert!(!command_matches(
            "/usr/bin/systemctl stop nginx",
            "/usr/bin/systemctl restart *"
        ));
    }

    #[test]
    fn test_command_matches_arg_wildcard_exact_prefix() {
        // Pattern "/usr/bin/systemctl restart *" with command matching just the prefix
        assert!(command_matches(
            "/usr/bin/systemctl restart",
            "/usr/bin/systemctl restart *"
        ));
    }

    #[test]
    fn test_command_matches_exact_with_args() {
        assert!(command_matches(
            "/usr/bin/systemctl stop firewall",
            "/usr/bin/systemctl stop firewall"
        ));
    }

    #[test]
    fn test_command_matches_exact_with_args_no_match() {
        assert!(!command_matches(
            "/usr/bin/systemctl stop nginx",
            "/usr/bin/systemctl stop firewall"
        ));
    }

    #[test]
    fn test_command_matches_glob_with_args() {
        // Directory glob should match just the binary part
        assert!(command_matches("/usr/bin/ls -la", "/usr/bin/*"));
    }

    #[test]
    fn test_command_matches_basename_with_args() {
        assert!(command_matches(
            "/usr/bin/systemctl restart nginx",
            "systemctl"
        ));
    }

    // -- Command matching edge cases --

    #[test]
    fn test_command_matches_empty_command_against_all() {
        assert!(command_matches("", "ALL"));
        assert!(command_matches("", "*"));
    }

    #[test]
    fn test_command_matches_empty_pattern() {
        assert!(!command_matches("/usr/bin/ls", ""));
    }

    #[test]
    fn test_command_matches_root_glob() {
        assert!(command_matches("/ls", "/*"));
    }

    #[test]
    fn test_command_matches_basename_no_parent() {
        // Bare command name against a directory glob
        assert!(!command_matches("ls", "/bin/*"));
    }

    // -- Validate command edge cases --

    #[test]
    fn test_validate_command_exact_boundary_len() {
        // Command at exactly max_len should pass
        let cmd = "a".repeat(10);
        let args = vec![cmd];
        // Total = 10 (command) + 1 (args.len()) = 11
        assert!(validate_command(&args, 11).is_ok());
        assert!(validate_command(&args, 10).is_err());
    }

    #[test]
    fn test_validate_command_pure_metachar() {
        assert!(validate_command(&["|".to_string()], 4096).is_err());
        assert!(validate_command(&["$".to_string()], 4096).is_err());
        assert!(validate_command(&[";".to_string()], 4096).is_err());
    }

    #[test]
    fn test_validate_command_unicode_accepted() {
        // Unicode command name without metacharacters should be accepted
        assert!(validate_command(&["/usr/bin/tëst".to_string()], 4096).is_ok());
    }

    #[test]
    fn test_validate_command_unicode_with_metachar() {
        // Unicode + shell metachar should be rejected
        assert!(validate_command(&["/usr/bin/tëst;evil".to_string()], 4096).is_err());
    }

    // -- Username edge cases --

    #[test]
    fn test_validate_username_very_long() {
        // Very long username should be accepted (no length limit in current impl)
        let long_name = "a".repeat(10000);
        assert!(validate_username(&long_name).is_ok());
    }

    #[test]
    fn test_validate_username_unicode() {
        // Unicode names without / or null should be accepted
        assert!(validate_username("ünïcödë").is_ok());
    }

    #[test]
    fn test_validate_username_null_in_middle() {
        assert!(validate_username("alice\0").is_err());
    }

    // -- Command resolution --

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

    #[test]
    fn test_resolve_command_directory_rejected() {
        let result = resolve_command("/usr/bin");
        assert!(result.is_err());
    }
}
