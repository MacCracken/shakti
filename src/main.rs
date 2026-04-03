use std::env;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process;
use std::time::Duration;

use anyhow::{Result, bail};
use tracing::{error, info, warn};

use shakti::{
    AuthzResult, DEFAULT_POLICY_PATH, MAX_AUTH_ATTEMPTS, check_authorization, check_timestamp,
    invalidate_timestamp, load_policy, resolve_command, sanitize_environment, update_timestamp,
    validate_command,
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
#[cfg(target_os = "linux")]
fn read_password() -> Result<String> {
    use std::io::{self, BufRead};

    let stdin = io::stdin();

    // Try to disable echo — if it fails (e.g., not a terminal), fall back to plain read
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
    drop(guard);
    eprintln!(); // newline after password (since echo was off)

    Ok(password)
}

/// Authenticate the calling user.
///
/// Uses `/usr/bin/su` to verify the password (delegates to PAM under the hood).
/// Terminal echo is disabled during password input.
#[cfg(target_os = "linux")]
fn authenticate_user(username: &str) -> Result<bool> {
    use std::io::{self, Write};

    for attempt in 1..=MAX_AUTH_ATTEMPTS {
        eprint!("[shakti] password for {}: ", username);
        io::stderr().flush()?;

        let password = read_password()?;

        if password.is_empty() {
            if attempt < MAX_AUTH_ATTEMPTS {
                eprintln!("Sorry, try again.");
                continue;
            }
            return Ok(false);
        }

        // Use PAM via /usr/bin/su to validate
        let result = std::process::Command::new("/usr/bin/su")
            .arg("-c")
            .arg("true")
            .arg(username)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn();

        match result {
            Ok(mut child) => {
                if let Some(ref mut stdin_pipe) = child.stdin
                    && let Err(e) = stdin_pipe
                        .write_all(password.as_bytes())
                        .and_then(|_| stdin_pipe.write_all(b"\n"))
                {
                    eprintln!("Warning: failed to write credentials to su: {}", e);
                }
                match child.wait() {
                    Ok(status) if status.success() => return Ok(true),
                    _ => {}
                }
            }
            Err(_) => {
                // su not available, fall through
            }
        }

        if attempt < MAX_AUTH_ATTEMPTS {
            eprintln!("Sorry, try again.");
        }
    }

    Ok(false)
}

#[cfg(not(target_os = "linux"))]
fn authenticate_user(_username: &str) -> Result<bool> {
    bail!("Authentication not supported on this platform");
}

// ---------------------------------------------------------------------------
// Audit logging
// ---------------------------------------------------------------------------

fn audit_log(action: &str, caller: &str, target: &str, command: &str, success: bool, reason: &str) {
    let status = if success { "ALLOWED" } else { "DENIED" };
    let msg = format!(
        "shakti: {} : {} ; USER={} ; COMMAND={} ; STATUS={} ; REASON={}",
        action, caller, target, command, status, reason
    );

    if success {
        info!("{}", msg);
    } else {
        warn!("{}", msg);
    }

    // Also write to syslog-style audit trail
    #[cfg(target_os = "linux")]
    {
        let log_line = format!(
            "{} {} : TTY={} ; PWD={} ; USER={} ; COMMAND={}\n",
            chrono_now(),
            caller,
            tty_name(),
            env::current_dir()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|_| "unknown".to_string()),
            target,
            command,
        );
        if let Err(e) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open("/var/log/agnos/sudo.log")
            .and_then(|mut f| {
                use std::io::Write;
                f.write_all(log_line.as_bytes())
            })
        {
            eprintln!("WARNING: Failed to write sudo audit log: {}", e);
        }
    }
}

fn chrono_now() -> String {
    use std::time::SystemTime;
    let d = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    format!("{}", d.as_secs())
}

fn tty_name() -> String {
    env::var("TTY")
        .or_else(|_| env::var("SSH_TTY"))
        .unwrap_or_else(|_| "unknown".to_string())
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
    let content = match std::fs::read_to_string("/etc/group") {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };

    let mut groups = Vec::new();
    for line in content.lines() {
        let fields: Vec<&str> = line.split(':').collect();
        if fields.len() >= 4 {
            let group_name = fields[0];
            let members: Vec<&str> = fields[3].split(',').collect();
            if members.iter().any(|m| m.trim() == username) {
                groups.push(group_name.to_string());
            }
        }
    }

    // Also add primary group
    if let Ok(Some(user)) = nix::unistd::User::from_name(username)
        && let Ok(Some(group)) = nix::unistd::Group::from_gid(user.gid)
        && !groups.contains(&group.name)
    {
        groups.push(group.name);
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
    command: Vec<String>,
}

fn parse_args() -> Result<CliArgs> {
    let args: Vec<String> = env::args().skip(1).collect();

    let mut target_user = "root".to_string();
    let mut policy_path = PathBuf::from(DEFAULT_POLICY_PATH);
    let mut invalidate = false;
    let mut list = false;
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
  -h, --help           Show this help message
  -V, --version        Show version

Examples:
  shakti systemctl restart llm-gateway
  shakti -u postgres psql
  shakti -k",
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
// Main
// ---------------------------------------------------------------------------

fn main() {
    // Initialize tracing
    let format = env::var("AGNOS_LOG_FORMAT").unwrap_or_default();
    if format == "json" {
        tracing_subscriber::fmt()
            .json()
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| "warn".into()),
            )
            .init();
    } else {
        tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| "warn".into()),
            )
            .init();
    }

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
    let cmd_str = format!("{} {}", resolved.display(), cli.command[1..].join(" "));

    // Authorization check
    let authz = check_authorization(
        &policy,
        &caller,
        &groups,
        &cli.target_user,
        resolved.to_str().unwrap_or(""),
    );

    match authz {
        AuthzResult::Denied(reason) => {
            audit_log(
                "COMMAND",
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
                            "AUTH_FAILURE",
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
                "COMMAND",
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

                    // Set supplementary groups
                    nix::unistd::setgroups(&[nix::unistd::Gid::from_raw(target_gid)]).map_err(
                        |e| std::io::Error::new(std::io::ErrorKind::PermissionDenied, e),
                    )?;
                    // Set GID first (must be done before setuid)
                    nix::unistd::setgid(nix::unistd::Gid::from_raw(target_gid)).map_err(|e| {
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
