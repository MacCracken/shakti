# Consumer Integration Guide

Shakti publishes both a **single-file bundle** (`dist/shakti.cyr`) for
drop-in consumption and **individual source modules** for consumers
that want to pick specific subsystems.

Three consumers are currently in scope: `argonaut` (init system),
`agnoshi` (shell `sudo` equivalent), `daimon` (agent privilege
operations). Ark (package manager) is adding shakti as a dep for its
privileged operations.

## Option 1 — Full distribution bundle (recommended)

Pull `dist/shakti.cyr`. One file, one `include`, no module ordering
to track. Update when shakti cuts a new tag.

### `cyrius.cyml`

```toml
[deps.shakti]
git = "https://github.com/MacCracken/shakti.git"
tag = "0.6.2"
modules = ["dist/shakti.cyr"]

# shakti's audit path uses sakshi; Cyrius does not resolve transitive
# deps, so declare it here too (must match shakti's pinned tag).
[deps.sakshi]
git = "https://github.com/MacCracken/sakshi.git"
tag = "2.2.5"
modules = ["dist/sakshi.cyr"]

[deps]
stdlib = [
    "syscalls", "string", "alloc", "freelist", "fmt", "str", "vec",
    "io", "fs", "args", "hashmap", "toml", "tagged", "process",
]
```

`cyrius distlib` strips `include` directives from the bundle, so
**the consumer is responsible for declaring the stdlib surface above
and the sakshi dep** — both are left unresolved in `dist/shakti.cyr`.
The stdlib list matches shakti's own `[deps] stdlib`; copy it verbatim
or trim to what your use of shakti actually touches.

### Consumer source

```cyrius
include "dist/shakti.cyr"

fn handle_request(user, command_argv) {
    var r = validate_command(command_argv, 4096);
    if (r != SHK_OK) { return r; }

    var policy = load_policy("/etc/agnos/sudoers.toml");
    if (policy == 0) { return SHK_ERR_POLICY; }

    var groups = identity_lookup_groups(user);
    var config = shakti_config_new();
    cfg_set_target_user(config, "root");
    cfg_set_auth_mode(config, AUTH_TIMESTAMP_ONLY);

    var eval = evaluate_with_policy(config, policy, user,
        sys_getuid(), sys_getgid(), groups, command_argv);
    if (eval_authorized(eval) == 0) { return SHK_ERR_DENIED; }
    # ... proceed with privileged op
    return SHK_OK;
}
```

A working end-to-end example lives at
`tests/integration/consumer_probe.cyr` — that probe is built and run
as part of shakti's integration test suite, so it's always in sync
with the current bundle.

## Option 2 — Piecemeal module pickup

If you only need one subsystem (e.g. `validate_command` from
`src/validate.cyr` but not the PAM shim), list individual files. Order
matters — each module references symbols defined in earlier modules.

### `cyrius.cyml`

```toml
[deps.shakti]
git = "https://github.com/MacCracken/shakti.git"
tag = "0.6.2"
modules = [
    "src/lib.cyr",        # SHK_ERR_* enum + constants (REQUIRED first;
                          # includes lib/sakshi.cyr + lib/pam.cyr → needs
                          # [deps.sakshi] and "pam" in [deps].stdlib)
    "src/validate.cyr",   # validate_username, validate_command, command_matches
    # "src/caps.cyr"      # capability name↔bit + capset/prctl drop — pull if needed
    # "src/session.cyr"   # PTY relay + session/keystroke log — pull if needed
    # "src/lsm.cyr"       # SELinux/AppArmor exec-context — pull if needed
    "src/env.cyr",        # is_unsafe_env, is_safe_env, sanitize_environment
    # "src/identity.cyr"  # uid/gid/group lookups — pull if needed
    # "src/timestamp.cyr" # credential cache — pull if needed
    # "src/audit.cyr"     # audit_log (uses sakshi_*) — pull if needed
    # "src/auth.cyr"      # PAM (unix_chkpwd) + su fallback — pull if needed
    # "src/policy.cyr"    # parse_policy, check_authorization, lint_policy
    # "src/api.cyr"       # ShaktiConfig / Evaluation / evaluate()
]

# Required: src/lib.cyr includes lib/sakshi.cyr (see the bundle example
# above for the full block).
[deps.sakshi]
git = "https://github.com/MacCracken/sakshi.git"
tag = "2.2.5"
modules = ["dist/sakshi.cyr"]
```

`src/main.cyr` is never a valid consumer module — it contains the CLI
entry point with a top-level `syscall(SYS_EXIT)` that would fire
inside the consumer's `main()`.

### Dependency order (if picking piecemeal)

1. `src/lib.cyr` — constants + error codes. Required first.
2. `src/validate.cyr` — defines `validate_username` and `command_matches`.
3. `src/env.cyr` — independent.
4. `src/identity.cyr` — uses `SHK_ERR_IO` from `lib.cyr`.
5. `src/timestamp.cyr` — uses `validate_username` from `validate.cyr` + `default_timestamp_dir` from `lib.cyr`.
6. `src/audit.cyr` — independent.
7. `src/auth.cyr` — independent.
8. `src/policy.cyr` — uses `command_matches` from `validate.cyr`, `MAX_COMMAND_LEN_DEFAULT` from `lib.cyr`.
9. `src/api.cyr` — uses everything above.

## Public API surface

All public functions return either `SHK_OK` (0), a positive
`SHK_ERR_*` code, or a pointer handle depending on the call. See
`src/lib.cyr` for the full error-code enum and `shk_err_msg()` for
human-readable strings.

| Subsystem | Entry points |
|---|---|
| Validation | `validate_username(s)`, `validate_command(argv, max_len)`, `command_matches(cmd, pattern)`, `resolve_command(cmd, out, out_cap)` |
| Env sanitisation | `is_unsafe_env(name)`, `is_safe_env(name)`, `sanitize_environment(env_keep, caller_user, caller_uid, caller_gid, target_user, target_home, target_shell)` |
| Identity | `identity_lookup_uid`, `identity_lookup_user`, `identity_lookup_groups`, `identity_lookup_gids` |
| Policy | `parse_policy(buf, buflen)`, `load_policy(path)`, `check_authorization(policy, caller, groups, target, command)`, `lint_policy(policy)` |
| Timestamp | `check_timestamp(user, ttl_secs)`, `update_timestamp(user)`, `invalidate_timestamp(user)` |
| Audit | `audit_log(action, caller, target, cmd, ok, reason)` |
| Auth | `authenticate(username, password)` — falls back to `/usr/bin/su`; real PAM blocked on cyrius NSS bootstrap |
| High-level | `ShaktiConfig` (`shakti_config_new`, `cfg_set_*`), `evaluate_with_policy`, `evaluate`, `Evaluation` accessors (`eval_authorized`, `eval_require_auth`, `eval_timestamp_valid`, `eval_resolved_command`, `eval_environment`, `eval_error_msg`) |

## Default paths

`default_policy_path()` returns `/etc/agnos/sudoers.toml`.
`default_timestamp_dir()` returns `/var/run/agnos/sudo`. Override via
`cfg_set_policy_path` / `cfg_set_timestamp_dir` if your consumer uses
a different domain root.

## Regenerating the bundle

Shakti commits `dist/shakti.cyr`. If you edit anything under `src/`,
regenerate:

```
cyrius distlib
git add dist/shakti.cyr
```

The integration test (`tests/integration/cli.sh`) compiles and runs
`tests/integration/consumer_probe.cyr` against the bundle, so a
stale bundle shows up as a test failure locally.

## Version compatibility

| Shakti | Cyrius toolchain | Notes |
|---|---|---|
| 0.2.x | 5.4.11+ | Uses `secret var` (v5.3.5), per-arch `Stat` enum (v5.4.11), hashmap (v5.1.x+) |

Consumers on cyrius < 5.4.11 will hit compile errors on the per-arch
syscall dispatch. Bump the consumer's toolchain to 5.4.11+ before
adding shakti as a dep.
