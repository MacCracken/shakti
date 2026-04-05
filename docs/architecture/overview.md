# Shakti Architecture Overview

## Purpose

Shakti is a privilege escalation tool for AGNOS, the equivalent of `sudo` in traditional Linux distributions. It allows authorized users to execute commands as other users (typically root) after authentication and policy evaluation.

## Security Model

Shakti follows the principle of **defense in depth** — multiple independent security layers must all pass before a command executes with elevated privileges.

### Trust Boundaries

```
User space (untrusted)
  |
  v
[CLI input validation]     -- reject shell injection, null bytes, length limits
  |
  v
[Policy file loading]      -- root-owned, not world-writable, no symlinks
  |
  v
[Authorization engine]     -- per-user/group/command rules with deny-first eval
  |
  v
[Authentication]           -- PAM or su fallback, rate-limited to 3 attempts
  |
  v
[Timestamp cache]          -- per-TTY, root-owned, symlink-resistant, O_NOFOLLOW
  |
  v
[Environment sanitization] -- LD_*, BASH_FUNC_*, interpreter vars, shell vars
  |
  v
[Process execution]        -- setuid/setgid/initgroups, fd sanitization, exec()
```

### Threat Model

As a setuid-root binary, Shakti is a high-value attack target. The security design addresses:

| Threat | Defense |
|--------|---------|
| Shell injection via command name | Metacharacter rejection in `validate_command` |
| Command argument injection | Arguments passed as separate exec argv, not shell-parsed |
| Environment variable injection | LD_*, BASH_FUNC_*, interpreter vars blocked by prefix and name |
| Timestamp tampering | Root ownership verification, symlink rejection, O_NOFOLLOW |
| Cross-session credential reuse | Per-TTY timestamp isolation |
| fd leaking to child process | Close all fds > stderr before exec |
| Signal interruption during auth | SIGINT/SIGTSTP/SIGQUIT masked during authentication |
| Password exposure in memory | `zeroize` crate clears password buffers |
| Password echo on terminal | termios ECHO disabled with RAII drop guard |
| Path traversal in usernames | `/`, `..`, null byte rejection in `validate_username` |
| Policy file tampering | Root ownership required, world-writable rejected |
| Group membership spoofing | `getgrouplist(3)` via NSS for accurate group resolution |

## Authentication Flow

```
1. Parse CLI args
2. Get caller identity (real UID, not effective)
3. Resolve caller's groups via getgrouplist(3)
4. Load and validate policy file
5. Check authorization (deny rules first, then allow rules)
6. If auth required and no valid timestamp:
   a. Mask SIGINT/SIGTSTP/SIGQUIT
   b. Prompt for password (echo disabled)
   c. Try PAM authentication (service: "shakti")
   d. If PAM unavailable, fall back to /usr/bin/su
   e. Zeroize password buffer
   f. Restore signal mask
   g. On success: update timestamp
   h. On failure (3 attempts): audit log, exit
7. Audit log the authorized command
8. Build sanitized environment
9. initgroups(3) + setgid + setuid for target user
10. Close leaked fds
11. exec() the command (replaces process)
```

## Policy Format

Policies are TOML files, typically at `/etc/agnos/sudoers.toml`.

### Structure

```toml
[defaults]
timestamp_ttl = 300          # Credential cache TTL in seconds (0 = always ask)
require_auth = true           # Global auth requirement
audit_log = true              # Log all commands
env_keep = ["EDITOR"]         # Additional safe env vars to preserve
max_command_len = 4096        # Max total command length in bytes
include_dir = "/etc/agnos/sudoers.d"  # Optional fragment directory

[[rules]]
user = "admin"                # Username or "*" for all
group = "wheel"               # Group name (optional, OR'd with user)
run_as = "root"               # Target user ("*" for any)
commands = ["/usr/bin/systemctl restart *"]  # Allowed commands (empty = all)
deny_commands = ["/usr/bin/systemctl stop firewall"]  # Deny overrides allow
require_auth = true           # Per-rule auth override
description = "Service management"
```

### Command Patterns

| Pattern | Matches |
|---------|---------|
| `/usr/bin/ls` | Exact binary path |
| `/usr/bin/*` | Any binary under `/usr/bin/` |
| `systemctl` | Any path with basename `systemctl` |
| `/usr/bin/systemctl restart *` | Binary with any args after "restart" |
| `ALL` or `*` | Everything |

### Rule Evaluation

1. Rules are evaluated in order (first match wins)
2. `deny_commands` are checked before `commands` within each rule
3. Both `user` and `group` are OR'd — either can grant access
4. `require_auth` is AND'd: both the rule and global default must be true

### Policy Fragments

Files in `include_dir` (e.g., `/etc/agnos/sudoers.d/*.toml`) are loaded in lexicographic order. Only `[[rules]]` from fragments are used; fragment-level `[defaults]` are ignored. Each fragment undergoes the same security checks as the main policy file.

## Module Structure

| Module | Responsibility |
|--------|---------------|
| `policy` | TOML parsing, fragment loading, authorization engine, policy linting |
| `validate` | Command validation, command matching, command resolution, username validation |
| `env` | Environment sanitization (unsafe var lists, LD_* prefix blocking) |
| `timestamp` | Credential caching with per-TTY isolation and tamper detection |
| `auth` | PAM and su authentication backends |
| `audit` | Structured journald logging and file-based audit trail |
| `api` | Consumer library API (`ShaktiConfig`, `Evaluation`, `evaluate()`) |

## Consumer API

Shakti exposes a library API for three AGNOS consumers:

- **argonaut** (init system): Uses `AuthMode::Skip` — already authenticated at boot
- **agnoshi** (shell): Uses `AuthMode::Interactive` — full sudo experience
- **daimon** (agent): Uses `AuthMode::TimestampOnly` — no terminal available

```rust
let config = ShaktiConfig::builder()
    .target_user("root")
    .auth_mode(AuthMode::TimestampOnly)
    .build();

let eval = evaluate(&config, "deploy", &groups, &command_args)?;
if eval.authorized && (!eval.require_auth || eval.timestamp_valid) {
    // exec with eval.resolved_command and eval.environment
}
```
