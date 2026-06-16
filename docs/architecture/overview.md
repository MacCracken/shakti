# Shakti Architecture Overview

## Purpose

Shakti is a privilege escalation tool for AGNOS, the equivalent of `sudo` in traditional Linux distributions. It allows authorized users to execute commands as other users (typically root) after authentication and policy evaluation.

> **Security reviewers**: the structured threat model
> ([`threat-model.md`](threat-model.md)) is the intended entry
> point — attacker classes, assumption register, per-threat
> mitigations. This overview focuses on the design and module
> structure.

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
[Authentication]           -- real PAM via unix_chkpwd(8) (ADR-006), rate-limited to 3 attempts; /usr/bin/su only as a helper-missing fallback
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
| Group membership resolution | `/etc/group` parsing in `src/identity.cyr` (local files). LDAP / sssd group resolution via `getgrouplist(3)` needs `fdlopen` and is tracked for 0.6.3, blocked on the cyrius setuid-safe helper-trust proposal. (Auth-side NSS already works via `unix_chkpwd`, ADR-006.) |

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
   c. `authenticate(user, password)` — `pam_authenticate` forks
      `unix_chkpwd(8)` (ADR-006) to verify against `/etc/shadow`; only
      if the helper is missing does it return `SHK_ERR_PAM_UNAVAILABLE`
      and fall through to `su_authenticate` (`/usr/bin/su -c true`)
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
log_session = false           # Record an output transcript per session (default off)
log_input = false             # Also capture keystrokes (echo-off redacted; default off)
session_log_dir = "/var/log/agnos/sessions"  # Where transcripts are written

[[rules]]
user = "admin"                # Username or "*" for all
group = "wheel"               # Group name (optional, OR'd with user)
run_as = "root"               # Target user ("*" for any)
commands = ["/usr/bin/systemctl restart *"]  # Allowed commands (empty = all)
deny_commands = ["/usr/bin/systemctl stop firewall"]  # Deny overrides allow
require_auth = true           # Per-rule auth override
capabilities = []             # Optional CAP_* set (empty = full root). See below.
log_session = false           # Optional per-rule I/O recording override
log_input = false             # Optional per-rule keystroke-capture override
selinux_context = ""          # Optional SELinux domain to transition into
apparmor_profile = ""         # Optional AppArmor profile to transition into
description = "Service management"
```

### Capability-based privilege (ADR-007)

By default an authorized command runs as `run_as` with the **full** root
capability set. A rule may instead grant a least-privilege subset via the
optional `capabilities` list:

```toml
[[rules]]
user = "deploy"
run_as = "nginx"
commands = ["/usr/sbin/nginx"]
capabilities = ["CAP_NET_BIND_SERVICE"]   # bind :80/:443 — nothing else
```

- Names are the kernel's `CAP_*` spelling (uppercase). An **unknown name
  is a hard error** — shakti refuses to exec (fail closed).
- **Absent or empty `capabilities` = today's behaviour exactly** (drop to
  `run_as` with the full set). The cap path is strictly opt-in.
- At exec, shakti narrows the bounding set, preserves the chosen caps
  across the uid drop (`PR_SET_KEEPCAPS` + `capset`), and raises them into
  the **ambient** set so they survive `execve`. The granted set is
  recorded in the audit trail as `CAPS=…` (`CAPS=ALL` for the full set).
- Kernel notes: ambient capabilities need Linux ≥ 4.3; `CAP_BPF`/
  `CAP_PERFMON`/`CAP_CHECKPOINT_RESTORE` need ≥ 5.8. The bit table pins
  `CAP_LAST_CAP = 40`.

### Session logging (ADR-008)

With `log_session = true` (per-rule, or as a default rules inherit), shakti
records an I/O transcript of the session:

```toml
[defaults]
log_session = false                          # global default (output transcript)
log_input = false                            # global default (keystroke capture)
session_log_dir = "/var/log/agnos/sessions"  # must be root-owned, mode 0700

[[rules]]
user = "oncall"
run_as = "root"
commands = ["/bin/bash"]
log_session = true                           # record this (per-rule override)
log_input = true                             # also capture keystrokes
```

- When enabled, shakti allocates a PTY and **stays alive as a relay
  parent**: a forked child drops privilege and `execve`s the target on the
  PTY slave, while the parent copies terminal I/O and tees the output to a
  transcript. When disabled (the default) shakti `execve`s directly with no
  fork or PTY — identical to pre-0.5.1 behaviour.
- Per rule, `log_session` and `log_input` are tri-state: unset inherits
  `[defaults]`, `true` forces on, `false` forces off.
- Transcripts are written to `session_log_dir` as
  `<ts>-<caller>-<pid>.log`, mode `0600`. The directory **must be
  root-owned and not group/other-writable** (same trust check as the
  policy file, opened TOCTOU-safe); shakti refuses to run (fail closed) if
  a requested log cannot be created securely. The audit record carries
  `SESSION_LOG=on|off ; INPUT_LOG=on|off`.
- The output transcript records the **output** stream (everything the
  command displayed, including echoed keystrokes). Terminal resizes are
  propagated live (SIGWINCH), so full-screen apps reflow.
- **Keystroke capture (`log_input`)** is a separate opt-in switch that
  rides the same relay (so it only applies when `log_session` is on). It
  records the user's input to a companion `<ts>-<caller>-<pid>.input.log`
  (also `0600`), and **redacts typed secrets**: input is never recorded
  while the child's tty has `ECHO` disabled (password prompts), failing
  safe to not-logging if the echo state can't be read.

### SELinux / AppArmor exec contexts (ADR-009)

On a system running a MAC LSM, a rule can launch the target under a
specific security domain rather than inheriting shakti's:

```toml
[[rules]]
user = "webadmin"
run_as = "root"
commands = ["/usr/sbin/nginx"]
selinux_context = "system_u:system_r:httpd_t:s0"   # SELinux hosts
# apparmor_profile = "nginx"                         # AppArmor hosts
```

- Set the field matching your host's LSM. `selinux_context` is written to
  `/proc/self/attr/exec`; `apparmor_profile` is written as
  `exec <profile>` to `/proc/self/attr/apparmor/exec` (fallback
  `/proc/self/attr/exec`) — both immediately before `execve`, after the
  privilege drop, on whichever process execs (the shakti process, or the
  forked child when session logging is on).
- **LSM-aware auto-selection:** shakti applies only the field whose LSM is
  actually active on the host (read from `/sys/kernel/security/lsm`), so a
  single policy can carry **both** `selinux_context` and `apparmor_profile`
  and do the right thing across a mixed fleet — the inactive LSM's field is
  skipped, not failed.
- **Fail-closed otherwise:** if the active LSM's write is rejected (context
  unparseable, transition denied), or confinement is requested but **no**
  matching LSM is active on the host, shakti aborts rather than run the
  target in the wrong (more privileged) domain.
- Absent/empty fields → no transition (default). The audit record carries
  `LSM=selinux=…|apparmor=…|none`.

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

| Module | In library bundle | Responsibility |
|---|:-:|---|
| `lib.cyr` | ✓ | Error codes (`SHK_ERR_*`), cross-module constants, version string, default paths. Required first in include order. |
| `validate.cyr` | ✓ | Command validation, command matching, command resolution, username validation |
| `env.cyr` | ✓ | Environment sanitization (unsafe var hashmap, `LD_*` / `BASH_FUNC_*` prefix blocking) |
| `identity.cyr` | ✓ | `/etc/passwd` / `/etc/group` lookups (uid → name, name → uid, group membership, supplementary GID vector) |
| `timestamp.cyr` | ✓ | Credential caching with per-TTY isolation and tamper detection |
| `audit.cyr` | ✓ | File-locked audit trail (`/var/log/agnos/sudo.log`) plus structured, level-filterable logging via sakshi (ALLOWED→INFO, DENIED/failure→WARN) |
| `auth.cyr` | ✓ | Real PAM auth via `unix_chkpwd(8)` (ADR-006); `/usr/bin/su` as helper-missing fallback |
| `caps.cyr` | ✓ | Linux capability name↔bit table + `capset`/`prctl` least-privilege drop (ADR-007) |
| `session.cyr` | ✓ | PTY allocation, raw termios, `poll` I/O relay, session/keystroke log writer (ADR-008) |
| `lsm.cyr` | ✓ | SELinux / AppArmor exec-context transitions via `/proc/self/attr/exec` (ADR-009) |
| `policy.cyr` | ✓ | TOML parsing, fragment loading (`include_dir`), authorization engine, policy linter |
| `api.cyr` | ✓ | High-level consumer API (`ShaktiConfig`, `Evaluation`, `evaluate`, `evaluate_with_policy`) |
| `main.cyr` | ✗ | CLI entry — argument parsing, interactive password prompt, exec drop, `syscall(SYS_EXIT, rc)`. Binary-only; excluded from the bundle. |

## Library boundary and distribution

Shakti ships two artefacts from one source tree:

```
src/main.cyr ─┐
              ├──► cyrius build ────► build/shakti     (CLI binary)
src/*.cyr ────┤
              └──► cyrius distlib ──► dist/shakti.cyr  (library bundle)
```

### The split

`src/lib.cyr` is the **development-time glue**: it declares the
shared constants and then `include`s every other `src/*.cyr`. Both
the binary (`src/main.cyr` includes `src/lib.cyr`) and the in-tree
test harnesses (`tests/tcyr/*.tcyr`) use it.

`src/main.cyr` is **CLI-only**: argument parsing, the interactive
password prompt with `secret var pbuf[1024]`, signal masking, fd
sanitisation, `execve`, and the top-level `syscall(SYS_EXIT, rc)`.
None of it is consumable as a library — its top-level exit call
would fire inside a consumer's `main()`.

`dist/shakti.cyr` is the **consumer bundle**. `cyrius distlib` reads
`[build] modules` from `cyrius.cyml`, concatenates each listed file
in order, strips every `include` directive, and writes the result.
Consumers `include "dist/shakti.cyr"` and supply their own stdlib
surface via `[deps] stdlib = [...]`.

### Bundle contents

The 9-file bundle order (defined in `cyrius.cyml [build] modules`)
is the same order `src/lib.cyr` `include`s them, because cyrius is
single-pass — every symbol must be defined before it's referenced:

```
src/lib.cyr   →  SHK_ERR_* enum, constants, default paths; includes
                 lib/sakshi.cyr (external dep) before the modules below
src/validate.cyr   ←  uses SHK_ERR_*
src/env.cyr        ←  stdlib only
src/identity.cyr   ←  uses SHK_ERR_IO
src/timestamp.cyr  ←  uses validate_username + default_timestamp_dir
src/audit.cyr      ←  uses sakshi_* (structured logging) + str builders
src/auth.cyr       ←  stdlib only
src/policy.cyr     ←  uses command_matches + MAX_COMMAND_LEN_DEFAULT + STAT_*
src/api.cyr        ←  uses everything above
```

### Publish flow

1. Edit `src/*.cyr`.
2. `cyrius test` — unit + property-fuzz suites must pass.
3. `cyrius distlib` — regenerate `dist/shakti.cyr`.
4. `sh tests/integration/cli.sh` — the consumer-probe step compiles
   `tests/integration/consumer_probe.cyr` against the fresh bundle;
   if it fails, the bundle is out of sync with `src/`.
5. `git add dist/shakti.cyr` and commit.

Bundle drift (source edit without regenerate) is a commit blocker —
the integration script catches it locally, and any consumer pulling
the git tag would otherwise compile against stale symbols.

### Version compatibility

The bundle is not versioned separately from the source — shakti's
`VERSION` file drives everything. Consumers pin the git tag (e.g.
`tag = "0.6.3"`), which is cut from the same commit that carries
the matching `dist/shakti.cyr`.

Cyrius toolchain for consumers: the version pinned in `cyrius.cyml`
(`[package].cyrius`, currently **6.2.11**). Consumers must also carry
`"pam"` in their stdlib list and declare the `sakshi` dep (see
README § Dependencies).

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
