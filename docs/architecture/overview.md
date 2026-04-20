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
[Authentication]           -- /usr/bin/su shim, rate-limited to 3 attempts (real PAM blocked on cyrius NSS bootstrap, tracked for cyrius 5.5.x)
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
| Password exposure in memory | `secret var pbuf[1024]` (cyrius v5.3.5) — compiler-synthesised zeroise on every return path of `_prompt_and_authenticate`, plus explicit `memset` between attempts |
| Password echo on terminal | termios `ECHO` bit cleared via `TCSETS`, original saved and restored |
| Path traversal in usernames | `/`, `..`, null byte, empty rejection in `validate_username` |
| Policy file tampering | Root-ownership check (stat uid == 0), world-writable mode bit rejected |
| Group membership resolution | `/etc/group` parsing in `src/identity.cyr` (local-files only for 0.2.x). LDAP / sssd support via `getgrouplist(3)` is tracked for cyrius 5.5.x when the NSS dispatch bootstrap lands. |

## Authentication Flow

```
1. Parse CLI args
2. Get caller identity (real UID, not effective)
3. Resolve caller's groups by parsing `/etc/group` (`src/identity.cyr`)
4. Load and validate policy file
5. Check authorization (deny rules first, then allow rules)
6. If auth required and no valid timestamp:
   a. Mask SIGINT/SIGTSTP/SIGQUIT
   b. Prompt for password (termios ECHO cleared)
   c. `authenticate(user, password)` — `pam_authenticate` returns
      `SHK_ERR_PAM_UNAVAILABLE` (stub), caller falls through to
      `su_authenticate`, which pipes password to `/usr/bin/su -c true`
   d. `memset(&pbuf, 0, PW_BUF_CAP)` between attempts;
      `secret var` zeroise fires on every function-return path
   e. Restore signal mask
   f. On success: update timestamp
   g. On failure (3 attempts): audit log, exit
7. Audit log the authorized command
8. Build sanitized environment
9. `identity_lookup_gids(target, primary_gid, &supp_gids, 256)` →
   `setgroups(ngids, &supp_gids)` → `setgid` → `setuid`
10. `close_range(3, -1, 0)` to drop inherited fds > stderr
11. `execve()` the command (replaces process)
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

Shakti exposes a cyrius library API for AGNOS consumers. See
[`docs/guides/integration.md`](../guides/integration.md) for the full
consumer guide (manifest layout, public surface table, bundle vs
piecemeal module pickup, default paths, cyrius version floor).

Consumers and their auth mode:

- **argonaut** (init system): `AUTH_SKIP` — already authenticated at boot
- **agnoshi** (shell): `AUTH_INTERACTIVE` — full sudo experience
- **daimon** (agent): `AUTH_TIMESTAMP_ONLY` — no terminal available
- **ark** (package manager): `AUTH_TIMESTAMP_ONLY` for privileged ops

### Minimal consumer example

```cyrius
include "dist/shakti.cyr"

fn run_privileged(caller, command_argv) {
    var policy = load_policy(default_policy_path());
    if (policy == 0) { return SHK_ERR_POLICY; }

    var groups = identity_lookup_groups(caller);
    var config = shakti_config_new();
    cfg_set_target_user(config, "root");
    cfg_set_auth_mode(config, AUTH_TIMESTAMP_ONLY);

    var eval = evaluate_with_policy(config, policy, caller,
        sys_getuid(), sys_getgid(), groups, command_argv);
    if (eval_authorized(eval) == 0) { return SHK_ERR_DENIED; }
    if (eval_require_auth(eval) == 1) {
        if (eval_timestamp_valid(eval) == 0) { return SHK_ERR_AUTH_FAILED; }
    }
    # exec with eval_resolved_command(eval) + eval_environment(eval)
    return SHK_OK;
}
```

See `tests/integration/consumer_probe.cyr` for a working build that
exercises the bundle end-to-end.
