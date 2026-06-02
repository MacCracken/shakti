# ADR-009: SELinux / AppArmor Exec-Context Transitions

## Status

Accepted (2026-06-02)

## Context

On systems running a Mandatory Access Control LSM (SELinux or AppArmor),
a privileged command should run under the *right* security domain, not
just the right uid. `sudo` does this via `selinux_context` /
role-transition support and (with AppArmor) `aa_change_onexec`. Without
it, a command shakti launches inherits shakti's own domain, which is
either too broad (shakti is trusted) or wrong for the target workload.

Both LSMs expose a per-process "exec" attribute that stages the security
context to apply at the *next* `execve`:

- **SELinux**: write the context (e.g. `system_u:system_r:httpd_t:s0`) to
  `/proc/self/attr/exec`. Equivalent to `setexeccon(3)`. The
  domain-transition permission is checked by SELinux policy at `execve`.
- **AppArmor**: write `exec <profile>` to `/proc/self/attr/apparmor/exec`
  (newer kernels) or `/proc/self/attr/exec` (older). Equivalent to
  `aa_change_onexec(3)`.

This is a direct file write — no `fdlopen`/NSS/libselinux/libapparmor
dependency. It was on the roadmap's unblocked "Future" list.

## Decision

### Policy schema

Two optional per-rule string fields:

```toml
[[rules]]
user = "webadmin"
run_as = "root"
commands = ["/usr/sbin/nginx"]
selinux_context = "system_u:system_r:httpd_t:s0"   # SELinux systems
# apparmor_profile = "nginx"                        # AppArmor systems
```

Set the field that matches the LSM your system runs. Absent fields →
no transition (shakti's current behaviour). Non-breaking and opt-in.

### Mechanism

`src/lsm.cyr` writes the staged context immediately **before** `execve`,
after the privilege drop, in whichever process will exec (the shakti
process on the direct path; the forked child on the session-logged path):

- `lsm_set_selinux_exec(ctx)` → write `ctx` to `/proc/self/attr/exec`.
- `lsm_set_apparmor_exec(profile)` → write `exec <profile>` to
  `/proc/self/attr/apparmor/exec`, falling back to `/proc/self/attr/exec`.
- `lsm_apply_exec(ctx, profile)` → apply each field that is set; returns
  negative if any requested write fails.

### Strict fail-closed

If a rule requests a context but the write fails — LSM not active, context
unparseable, or transition denied (`EINVAL`/`EACCES`/`EPERM`) — shakti
**aborts before `execve`** rather than running the command in the wrong
(more privileged) domain. A requested-but-unenforceable confinement is a
security downgrade, so refusing is the safe outcome. The operator sets the
field matching their system's LSM; mixed-LSM fleets use per-host policy
fragments. (LSM-aware auto-selection — read `/sys/kernel/security/lsm` and
apply only the active LSM's field — is a possible future refinement;
strict is simpler and safer for v1.)

### Audit

The `AUDIT_COMMAND` record gains an `LSM=` field naming the applied
context/profile (or `LSM=none`), so the forensic trail shows the domain
the target was launched under.

## Consequences

- **Positive**: MAC-confined privileged execution — the target runs in
  its intended SELinux domain / AppArmor profile, not shakti's.
- **Positive**: no new dependency; two `/proc/self/attr` writes. Works on
  both the direct and session-logged exec paths (same pre-`execve` point).
- **Positive**: opt-in, non-breaking; absent fields = today's behaviour.
- **Negative**: strict fail-closed means a field set for a non-active LSM
  refuses to run. Documented; the field must match the system's LSM.
- **Negative**: successful enforcement can only be verified on an
  LSM-enabled host (CI tier); on a host without the LSM the write returns
  `EINVAL`, which the unit/integration tests use to confirm the
  fail-closed path.

## Testing

- **Unit** (`tests/tcyr/lsm.tcyr`): the AppArmor value formatting
  (`exec <profile>`); pure, no LSM needed.
- **Integration** (unprivileged): a probe calls `lsm_apply_exec` with a
  context on a host without the LSM and asserts it returns negative
  (`EINVAL`) — i.e. the fail-closed signal fires. Real enforcement
  (context actually applied at exec) is gated to an SELinux/AppArmor CI
  job.
