# Internal Adversarial Self-Review (0.6.1)

**Scope**: the exec-path features added in 0.5.0–0.6.0 —
`src/caps.cyr` (capability drop), `src/session.cyr` (PTY relay + session
log), `src/lsm.cyr` (SELinux/AppArmor exec contexts), and the restructured
exec path in `src/main.cyr` (`_drop_privileges`, `_exec_target`,
`_exec_target_logged`, `_open_session_log`, `_apply_lsm_or_die`) plus the
policy/api threading. Pre-audit internal pass with an adversarial-review
assist over the new privilege-critical code.

**Severity rubric**: same as
[`2026-04-20-internal-review.md`](2026-04-20-internal-review.md).

Fixes ship as shakti **0.6.1**.

## Findings & dispositions

### H2 — session-log dir check was symlink/TOCTOU-exposed (HIGH) — FIXED
`_open_session_log` ran `stat(dir)` (symlink-following) then `open(path)`
as root: a stat-then-open race and intermediate-symlink exposure, and it
only rejected world-writable (not group-writable) dirs. Rewritten to
`openat(O_PATH|O_DIRECTORY|O_NOFOLLOW)` + `fstat` the handle + `openat`
the leaf relative to that fd (`O_EXCL|O_NOFOLLOW`, 0600); now rejects
`mode & 0o22`. Verified live (group-writable dir refused).

### H1 — AppArmor write could target SELinux's node (HIGH) — FIXED
`lsm_set_apparmor_exec` fell back to `/proc/self/attr/exec` (SELinux's
node on a SELinux host). It failed *closed* (EINVAL), so no privilege
leak, but the design conflated two LSMs' nodes. Now both setters confirm
the matching LSM is active via `/sys/kernel/security/lsm` before writing.

### FORK — relay hang if child died before opening the slave (HIGH) — FIXED
In `_exec_target_logged` the child opened the PTY slave; a failure before
that open left the master with no slave opener and the parent's relay
blocked forever (DoS, not a leak). Switched to the forkpty pattern: parent
opens the slave pre-fork, child inherits it, parent closes its copy — the
master always `HUP`s when the child exits.

### M1 — no capability post-check (MEDIUM) — FIXED
`_drop_privileges` now reads the effective set back via `capget` after
`capset`+ambient and aborts unless it equals the requested mask (mirrors
the getuid/getgid post-checks). Verified live (`capget` == mask).

### M2 — relay could truncate the final output burst (MEDIUM) — FIXED
On a combined POLLIN+POLLHUP wake the relay read once (≤4096) then stopped;
a larger final write was lost from the transcript. Now drains the master
fully on HUP (safe — buffered data then EOF, no block).

### M4 — unchecked allocations (MEDIUM) — FIXED
`_build_ptr_array` (argv/envp) and the relay pollfd buffer now null-check
`alloc`, consistent with the rest of the codebase.

### Toolchain — x86_64 openat/newfstatat numbers (FIXED)
The stdlib syscall enum carries the aarch64 numbers (56/79); the binary
build needs the x86_64 values (257/262). Caught at build time; declared
locally like shakti's other x86_64-only syscalls. (Underscores the
standing cross-arch caveat in `dependency-watch.md`.)

### L2 — signal exit-status fidelity (LOW) — FIXED
Session-logged target killed by a signal now returns `128 + signum`.

### L3 — unchecked child setup syscalls (LOW) — FIXED
`dup2` failures in the logged child now `exit 127`.

## Considered, not changed
- **M3 — relay ignores log-write failures.** Kept best-effort: aborting a
  live session on a transient log-write error is worse than an incomplete
  transcript. The durable concern is noted; revisit if a consumer needs
  guaranteed-complete transcripts.
- **M5 — `CAPS=ALL` audit label.** Accurate for the common root target and
  documented in the CHANGELOG; left as-is.
- **L5 — `require_auth = rule & default`.** Pre-existing master-switch
  semantics, already surfaced by `lint_policy`. Out of scope; documented.

## Verification
Full cleanliness gate green after fixes (17 `.tcyr` suites, 21 integration
assertions, fmt/lint clean). The capability drop, session-log dir check,
group-writable rejection, and `capget` post-check were each verified live
in an unprivileged user namespace. Real LSM enforcement and the full
root exec path remain gated to a privileged CI job.
