use std::env;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process;
use std::time::Duration;

use anyhow::{Result, bail};
use tracing::{error, info, warn};
use zeroize::Zeroize;

use shakti::{
    AuditAction, AuthzResult, DEFAULT_POLICY_PATH, MAX_AUTH_ATTEMPTS, audit_log, authenticate,
    check_authorization, check_timestamp, init_tracing, invalidate_timestamp, lint_policy,
    load_policy, resolve_command, sanitize_environment, update_timestamp, validate_command,
};

// ---------------------------------------------------------------------------
// Signal handling
// ---------------------------------------------------------------------------

/// Mask interactive signals (SIGINT, SIGTSTP, SIGQUIT) during authentication.
///
/// Returns the previous signal mask so it can be restored after auth completes.
#[cfg(target_os = "linux")]
fn mask_auth_signals() -> Option<nix::sys::signal::SigSet> {
    use nix::sys::signal::{SigSet, SigmaskHow, Signal, sigprocmask};

    let mut mask = SigSet::empty();
    mask.add(Signal::SIGINT);
    mask.add(Signal::SIGTSTP);
    mask.add(Signal::SIGQUIT);

    let mut old_mask = SigSet::empty();
    if sigprocmask(SigmaskHow::SIG_BLOCK, Some(&mask), Some(&mut old_mask)).is_ok() {
        Some(old_mask)
    } else {
        None
    }
}

/// Restore the signal mask saved before authentication.
#[cfg(target_os = "linux")]
fn restore_signals(old_mask: Option<nix::sys::signal::SigSet>) {
    if let Some(mask) = old_mask {
        let _ = nix::sys::signal::sigprocmask(
            nix::sys::signal::SigmaskHow::SIG_SETMASK,
            Some(&mask),
            None,
        );
    }
}

// ---------------------------------------------------------------------------
// Authentication
// ---------------------------------------------------------------------------

/// RAII guard that restores terminal echo on drop.
///
/// This ensures echo is re-enabled even if the function panics or returns early.
#[cfg(target_os = "linux")]
struct EchoGuard {
    original: nix::sys::termios::Termios,
}

#[cfg(target_os = "linux")]
impl Drop for EchoGuard {
    fn drop(&mut self) {
        // Restore original terminal settings on stdin
        let _ = nix::sys::termios::tcsetattr(
            std::io::stdin(),
            nix::sys::termios::SetArg::TCSANOW,
            &self.original,
        );
    }
}

/// Read a password from stdin with terminal echo disabled.
fn read_password() -> Result<String> {
    use std::io::{self, BufRead};

    let stdin = io::stdin();

    // Try to disable echo — if it fails (e.g., not a terminal), fall back to plain read
    #[cfg(target_os = "linux")]
    let guard = if let Ok(original) = nix::sys::termios::tcgetattr(&stdin) {
        let mut noecho = original.clone();
        noecho
            .local_flags
            .remove(nix::sys::termios::LocalFlags::ECHO);
        if nix::sys::termios::tcsetattr(&stdin, nix::sys::termios::SetArg::TCSANOW, &noecho).is_ok()
        {
            Some(EchoGuard { original })
        } else {
            None
        }
    } else {
        None
    };

    let password = stdin.lock().lines().next().unwrap_or(Ok(String::new()))?;

    // Explicitly drop guard to restore echo before printing newline
    #[cfg(target_os = "linux")]
    drop(guard);
    eprintln!(); // newline after password (since echo was off)

    Ok(password)
}

/// Authenticate the calling user interactively.
///
/// Prompts for a password (with echo disabled), then delegates to the library's
/// `authenticate()` function which tries PAM first, then falls back to `/usr/bin/su`.
/// Password buffers are zeroized after use.
fn authenticate_user(username: &str) -> Result<bool> {
    use std::io::{self, Write};

    for attempt in 1..=MAX_AUTH_ATTEMPTS {
        eprint!("[shakti] password for {}: ", username);
        io::stderr().flush()?;

        let mut password = read_password()?;

        if password.is_empty() {
            password.zeroize();
            if attempt < MAX_AUTH_ATTEMPTS {
                eprintln!("Sorry, try again.");
                continue;
            }
            return Ok(false);
        }

        let result = authenticate(username, &password);

        // Clear password from memory immediately after use
        password.zeroize();

        match result {
            Ok(true) => return Ok(true),
            Ok(false) => {}
            Err(e) => {
                // Auth backend error — log but continue to next attempt
                tracing::debug!("Authentication backend error: {}", e);
            }
        }

        if attempt < MAX_AUTH_ATTEMPTS {
            eprintln!("Sorry, try again.");
        }
    }

    Ok(false)
}

// ---------------------------------------------------------------------------
// User info helpers
// ---------------------------------------------------------------------------

fn get_caller_username() -> Result<String> {
    let uid = nix::unistd::getuid();
    nix::unistd::User::from_uid(uid)?
        .map(|u| u.name)
        .ok_or_else(|| anyhow::anyhow!("Cannot determine username for UID {}", uid))
}

fn get_user_groups(username: &str) -> Vec<String> {
    // Use getgrouplist(3) via nix — this queries NSS (including LDAP/sssd),
    // not just /etc/group. This matches what sudo and other privilege tools do.
    let user = match nix::unistd::User::from_name(username) {
        Ok(Some(u)) => u,
        _ => return Vec::new(),
    };

    let cname = match std::ffi::CString::new(username) {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };

    let gids = match nix::unistd::getgrouplist(&cname, user.gid) {
        Ok(g) => g,
        Err(_) => return Vec::new(),
    };

    let mut groups = Vec::new();
    for gid in gids {
        if let Ok(Some(group)) = nix::unistd::Group::from_gid(gid)
            && !groups.contains(&group.name)
        {
            groups.push(group.name);
        }
    }

    groups
}

fn get_target_user_info(username: &str) -> Result<(u32, u32, String, String)> {
    let user = nix::unistd::User::from_name(username)?
        .ok_or_else(|| anyhow::anyhow!("Target user '{}' not found", username))?;
    Ok((
        user.uid.as_raw(),
        user.gid.as_raw(),
        user.dir.to_string_lossy().to_string(),
        user.shell.to_string_lossy().to_string(),
    ))
}

// ---------------------------------------------------------------------------
// CLI parsing
// ---------------------------------------------------------------------------

struct CliArgs {
    target_user: String,
    policy_path: PathBuf,
    invalidate: bool,
    list: bool,
    check: bool,
    command: Vec<String>,
}

fn parse_args() -> Result<CliArgs> {
    let args: Vec<String> = env::args().skip(1).collect();

    let mut target_user = "root".to_string();
    let mut policy_path = PathBuf::from(DEFAULT_POLICY_PATH);
    let mut invalidate = false;
    let mut list = false;
    let mut check = false;
    let mut command = Vec::new();
    let mut i = 0;

    while i < args.len() {
        match args[i].as_str() {
            "-u" | "--user" => {
                i += 1;
                if i >= args.len() {
                    bail!("-u requires a username argument");
                }
                target_user = args[i].clone();
            }
            "-p" | "--policy" => {
                i += 1;
                if i >= args.len() {
                    bail!("-p requires a file path argument");
                }
                policy_path = PathBuf::from(&args[i]);
            }
            "-k" | "--invalidate" => {
                invalidate = true;
            }
            "-l" | "--list" => {
                list = true;
            }
            "-c" | "--check" => {
                check = true;
            }
            "-h" | "--help" => {
                print_usage();
                process::exit(0);
            }
            "-V" | "--version" => {
                println!("shakti {}", env!("CARGO_PKG_VERSION"));
                process::exit(0);
            }
            "--" => {
                command.extend_from_slice(&args[i + 1..]);
                break;
            }
            arg if arg.starts_with('-') => {
                bail!("Unknown option: {}. Use --help for usage.", arg);
            }
            _ => {
                command.extend_from_slice(&args[i..]);
                break;
            }
        }
        i += 1;
    }

    Ok(CliArgs {
        target_user,
        policy_path,
        invalidate,
        list,
        check,
        command,
    })
}

fn print_usage() {
    eprintln!(
        "Usage: shakti [OPTIONS] [--] COMMAND [ARGS...]

AGNOS privilege escalation tool.

Options:
  -u, --user USER      Run command as USER (default: root)
  -p, --policy FILE    Use alternate policy file (default: {})
  -k, --invalidate     Invalidate cached credentials
  -l, --list           List allowed commands for current user
  -c, --check          Lint the policy file for errors and warnings
  -h, --help           Show this help message
  -V, --version        Show version

Examples:
  shakti systemctl restart llm-gateway
  shakti -u postgres psql
  shakti -k
  shakti --check
  shakti -c -p /etc/agnos/custom.toml",
        DEFAULT_POLICY_PATH
    );
}

// ---------------------------------------------------------------------------
// List mode
// ---------------------------------------------------------------------------

fn list_permissions(policy: &shakti::SudoPolicy, username: &str, groups: &[String]) {
    println!(
        "User {} may run the following commands on this host:",
        username
    );
    println!();

    let mut found = false;
    for rule in &policy.rules {
        let user_matches = match &rule.user {
            Some(u) if u == "*" => true,
            Some(u) => u == username,
            None => false,
        };
        let group_matches = match &rule.group {
            Some(g) => groups.iter().any(|ug| ug == g),
            None => false,
        };

        if !user_matches && !group_matches {
            continue;
        }

        found = true;
        let auth_tag = if rule.require_auth { "" } else { "NOPASSWD: " };
        let run_as = &rule.run_as;

        if rule.commands.is_empty() {
            println!("    ({}) {}ALL", run_as, auth_tag);
        } else {
            for cmd in &rule.commands {
                println!("    ({}) {}{}", run_as, auth_tag, cmd);
            }
        }

        if !rule.deny_commands.is_empty() {
            for cmd in &rule.deny_commands {
                println!("    ({}) DENY: {}", run_as, cmd);
            }
        }

        if !rule.description.is_empty() {
            println!("    # {}", rule.description);
        }
    }

    if !found {
        println!("    (none)");
    }
}

// ---------------------------------------------------------------------------
// Policy check mode
// ---------------------------------------------------------------------------

fn check_policy(policy: &shakti::SudoPolicy) -> Result<()> {
    let warnings = lint_policy(policy);

    println!(
        "Policy: {} rules, timestamp_ttl={}s, require_auth={}",
        policy.rules.len(),
        policy.defaults.timestamp_ttl,
        policy.defaults.require_auth
    );
    println!();

    if warnings.is_empty() {
        println!("No issues found.");
        return Ok(());
    }

    let mut errors = 0u32;
    let mut warns = 0u32;

    for w in &warnings {
        let prefix = match w.severity {
            "error" => {
                errors += 1;
                "ERROR"
            }
            _ => {
                warns += 1;
                "WARN"
            }
        };

        match w.rule_index {
            Some(i) => println!("  [{}] rule[{}]: {}", prefix, i, w.message),
            None => println!("  [{}] {}", prefix, w.message),
        }
    }

    println!();
    println!("Summary: {} error(s), {} warning(s)", errors, warns);

    if errors > 0 {
        bail!("Policy has errors — fix before use");
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

fn main() {
    // Initialize tracing with journald + stderr layers
    init_tracing();

    if let Err(e) = run() {
        error!("{:#}", e);
        eprintln!("shakti: {:#}", e);
        process::exit(1);
    }
}

fn run() -> Result<()> {
    let cli = parse_args()?;

    // Get caller identity from real UID (not effective — we may be setuid)
    let caller = get_caller_username()?;
    let groups = get_user_groups(&caller);

    // Handle credential invalidation
    if cli.invalidate {
        invalidate_timestamp(&caller)?;
        info!("Timestamp invalidated for user '{}'", caller);
        return Ok(());
    }

    // Load policy
    let policy = load_policy(&cli.policy_path)?;

    // Handle policy check mode
    if cli.check {
        return check_policy(&policy);
    }

    // Handle list mode
    if cli.list {
        list_permissions(&policy, &caller, &groups);
        return Ok(());
    }

    // Must have a command
    if cli.command.is_empty() {
        print_usage();
        bail!("No command specified");
    }

    // Validate command
    validate_command(&cli.command, policy.defaults.max_command_len)?;

    // Resolve command to absolute path
    let resolved = resolve_command(&cli.command[0])?;
    let resolved_str = resolved.to_str().ok_or_else(|| {
        anyhow::anyhow!("Command path is not valid UTF-8: {}", resolved.display())
    })?;

    // Build full command string with arguments for authorization and audit
    let cmd_str = if cli.command.len() > 1 {
        format!("{} {}", resolved_str, cli.command[1..].join(" "))
    } else {
        resolved_str.to_string()
    };

    // Authorization check — pass full command with arguments so that
    // argument-level patterns in commands/deny_commands are evaluated.
    let authz = check_authorization(&policy, &caller, &groups, &cli.target_user, &cmd_str);

    match authz {
        AuthzResult::Denied(reason) => {
            audit_log(
                AuditAction::Command,
                &caller,
                &cli.target_user,
                &cmd_str,
                false,
                &reason,
            );
            eprintln!("shakti: {}", reason);
            bail!("Permission denied");
        }
        AuthzResult::Allowed { require_auth } => {
            // Authentication
            if require_auth {
                let ttl = Duration::from_secs(policy.defaults.timestamp_ttl);
                if !check_timestamp(&caller, ttl) {
                    // Mask signals during auth to prevent SIGINT leaving us in
                    // a partially-privileged state
                    #[cfg(target_os = "linux")]
                    let saved_mask = mask_auth_signals();

                    let authenticated = authenticate_user(&caller);

                    #[cfg(target_os = "linux")]
                    restore_signals(saved_mask);

                    let authenticated = authenticated?;
                    if !authenticated {
                        audit_log(
                            AuditAction::AuthFailure,
                            &caller,
                            &cli.target_user,
                            &cmd_str,
                            false,
                            "authentication failed",
                        );
                        bail!("{} incorrect password attempts", MAX_AUTH_ATTEMPTS);
                    }
                    // Update timestamp on successful auth
                    if let Err(e) = update_timestamp(&caller) {
                        warn!("Failed to update credential timestamp: {}", e);
                    }
                }
            }

            // Audit log the allowed execution
            audit_log(
                AuditAction::Command,
                &caller,
                &cli.target_user,
                &cmd_str,
                true,
                "authorized",
            );

            // Get target user info
            let (target_uid, target_gid, target_home, target_shell) =
                get_target_user_info(&cli.target_user)?;

            // Build sanitized environment
            let env = sanitize_environment(
                &policy,
                &caller,
                &cli.target_user,
                &target_home,
                &target_shell,
            );

            // Execute the command
            // We use exec() to replace this process — the command inherits our PID
            let mut cmd = process::Command::new(&resolved);
            cmd.args(&cli.command[1..]);

            // Clear environment and set sanitized vars
            cmd.env_clear();
            for (k, v) in &env {
                cmd.env(k, v);
            }

            // Prepare target username as CString for initgroups (before pre_exec closure)
            let target_cname = std::ffi::CString::new(cli.target_user.as_bytes())
                .map_err(|_| anyhow::anyhow!("Target username contains null byte"))?;

            // Set uid/gid and close leaked fds before exec
            unsafe {
                cmd.pre_exec(move || {
                    // Close all file descriptors > stderr to prevent fd leaking
                    // to the child process. Read from /proc/self/fd to find open fds.
                    if let Ok(entries) = std::fs::read_dir("/proc/self/fd") {
                        for entry in entries.flatten() {
                            if let Ok(fd_str) = entry.file_name().into_string()
                                && let Ok(fd) = fd_str.parse::<i32>()
                                && fd > 2
                            {
                                // Ignore errors — the fd used to read /proc/self/fd
                                // will also appear and may already be closed
                                let _ = nix::unistd::close(fd);
                            }
                        }
                    }

                    // Set all supplementary groups for the target user via initgroups(3).
                    // This queries NSS (including LDAP/sssd) for the full group list,
                    // unlike the previous setgroups() which only set the primary GID.
                    let target_gid = nix::unistd::Gid::from_raw(target_gid);
                    nix::unistd::initgroups(&target_cname, target_gid).map_err(|e| {
                        std::io::Error::new(std::io::ErrorKind::PermissionDenied, e)
                    })?;
                    // Set GID first (must be done before setuid)
                    nix::unistd::setgid(target_gid).map_err(|e| {
                        std::io::Error::new(std::io::ErrorKind::PermissionDenied, e)
                    })?;
                    // Set UID last
                    nix::unistd::setuid(nix::unistd::Uid::from_raw(target_uid)).map_err(|e| {
                        std::io::Error::new(std::io::ErrorKind::PermissionDenied, e)
                    })?;
                    Ok(())
                });
            }

            // exec replaces this process — this never returns on success
            let err = cmd.exec();
            bail!("Failed to exec {}: {}", resolved.display(), err);
        }
        _ => bail!("Unexpected authorization result"),
    }
}
