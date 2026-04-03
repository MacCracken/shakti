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
