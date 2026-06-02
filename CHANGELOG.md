# Changelog

All notable changes to Shakti will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.6.0] - 2026-06-02

Mandatory Access Control integration: a rule can launch its command under
a specific SELinux domain or AppArmor profile. Minor bump for new, opt-in,
non-breaking policy fields; existing policies are unaffected.

### Added

- **SELinux / AppArmor exec-context transitions (ADR-009).** A rule may
  carry `selinux_context = "system_u:system_r:httpd_t:s0"` and/or
  `apparmor_profile = "nginx"`. Immediately before `execve` (after the
  privilege drop, on both the direct and session-logged paths), shakti
  stages the context via the kernel's per-process exec attribute:
  `selinux_context` → `/proc/self/attr/exec` (`setexeccon`-equivalent);
  `apparmor_profile` → `exec <profile>` to `/proc/self/attr/apparmor/exec`
  (fallback `/proc/self/attr/exec`, `aa_change_onexec`-equivalent). New
  `src/lsm.cyr`; direct `/proc` writes, no libselinux/libapparmor
  dependency.
- **Audit `LSM=…`** on the `AUDIT_COMMAND` record (`selinux=<ctx>` /
  `apparmor=<profile>` / `none`).
- **`tests/integration/lsm_ctx.sh` + `lsm_probe.cyr`** — verify the
  fail-closed write behaviour against the host's active LSMs.

### Changed

- The policy `Rule` and `Evaluation` gained `selinux_context` /
  `apparmor_profile`; the matched rule's values thread through
  `check_authorization` → `evaluate()` → the exec path, like the
  capability and session-logging fields.

### Security

- **MAC-confined execution, strict fail-closed.** Rules can launch the
  target in its intended SELinux domain / AppArmor profile instead of
  shakti's. If a context is requested but cannot be applied (LSM inactive,
  unparseable, or transition denied), shakti **aborts before `execve`**
  rather than run the command in a more privileged domain. Opt-in and
  non-breaking: absent fields preserve today's behaviour.

## [0.5.1] - 2026-06-02

Session logging: shakti can now record a PTY transcript of a privileged
session, opt-in per rule. The default (non-logged) exec path is unchanged.
Also bumps the cyrius toolchain pin 6.0.31 → 6.0.32 (point release; no
source changes).

### Added

- **Session logging — per-rule PTY I/O recording (ADR-008).** With
  `log_session = true` (a `[defaults]` value rules inherit, or a per-rule
  override), shakti records a transcript of the privileged session. New
  `src/session.cyr` provides PTY allocation (`/dev/ptmx`, `TIOCGPTN`/
  `TIOCSPTLCK`), a raw-termios transform, a `poll(2)` relay loop, and the
  log header/footer writers. Policy gains `log_session` (tri-state
  per-rule: unset = inherit) and `session_log_dir`
  (default `/var/log/agnos/sessions`).
- **Audit `SESSION_LOG=on|off`** on the `AUDIT_COMMAND` record.
- **`tests/integration/session_log.sh` + `session_probe.cyr`** — verify
  the relay + log capture unprivileged (PTY probe) and, under root, the
  full shakti logged-exec path.

### Changed

- **The exec path forks when session logging is enabled.** `_exec_target`
  was refactored: the privilege drop is now a shared `_drop_privileges()`
  helper. The default (non-logged) path is **unchanged** — a direct,
  in-process `execve`, no fork, no PTY. The logged path forks: the child
  drops privilege and execs the target on a PTY slave
  (`setsid`/`TIOCSCTTY`/`dup2`), while shakti stays alive as the relay
  parent, tees output to the transcript, and exits with the child's
  status.
- **Cyrius toolchain pin 6.0.31 → 6.0.32.** Point-release bump aligning
  the pin with the current toolchain (the auto-updated 6.0.32 was drifting
  against the 6.0.31 pin). No source changes; `cyrius.lock` regenerated.

### Security

- **Session transcripts are written fail-closed to a trusted location.**
  `session_log_dir` must be root-owned and not world-writable (the same
  check `load_policy` applies); the per-session file is opened
  `O_EXCL|O_NOFOLLOW`, mode `0600`. If logging is requested but the log
  cannot be created securely, shakti refuses to run rather than execute
  unlogged. The relay parent retains root only to write the root-owned
  transcript and copy the PTY; it never interprets the byte stream.

## [0.5.0] - 2026-06-01

Least-privilege execution: a policy rule can now run an authorized command
with a chosen Linux capability set instead of full root. Minor bump for a
new, opt-in, non-breaking policy field (`capabilities`); existing policies
behave exactly as before.

### Added

- **Capability-based privilege — per-rule `CAP_*` drop (ADR-007).** A
  policy rule may now carry an optional `capabilities` list, e.g.
  `capabilities = ["CAP_NET_BIND_SERVICE"]`. When present, the authorized
  command runs as the target user with **exactly** those Linux
  capabilities instead of the full root set — least-privilege for the
  highest-value path in the tool. New `src/caps.cyr` provides the
  verified `CAP_*` bit table (0–40, `CAP_LAST_CAP = 40`), name↔bit
  mapping, and the `capset(2)`/`prctl(2)` plumbing.
- **Audit records the granted capability set.** The `AUDIT_COMMAND` line
  now carries `CAPS=<comma-separated names>` (or `CAPS=ALL` for the
  full-uid default), so forensics can see what the target ran with.
- **`tests/integration/caps_drop.sh` + `cap_probe.cyr`** — verify the
  live drop by reading `/proc/self/status` Cap* fields. Runs in an
  unprivileged user namespace (real CI coverage of the capset/ambient/
  bounding wrappers) or the full exec path under root; SKIPs otherwise.

### Changed

- **`_exec_target` gained a capability-aware drop sequence.** For a
  non-empty cap set: drop the bounding set of every unwanted cap (while
  `CAP_SETPCAP` is still effective as root) → `PR_SET_KEEPCAPS` →
  `setgroups`/`setgid`/`setuid` → `capset` (permitted=inheritable=
  effective=set) → raise each into the ambient set → `execve`. An empty
  cap set takes the **unchanged** full-uid drop path — no behavioural
  change for existing policies. Every new syscall is return-checked and
  fails closed (abort before `execve`).
- The policy `Rule` struct and `Evaluation` gained a capabilities field;
  the matched rule's set threads through `check_authorization` →
  `evaluate()` → `_exec_target`. An unknown capability name is a hard
  policy error — shakti refuses to exec (fail closed) before prompting
  for a password.

### Security

- **Least-privilege execution.** Rules can now grant a single capability
  (e.g. `CAP_NET_BIND_SERVICE`) instead of full uid-0, shrinking the
  blast radius of an authorized command. Opt-in and non-breaking: a rule
  without `capabilities` drops to the target uid with the full set
  exactly as before. The bounding-set narrowing also blocks the target
  (and anything it execs) from re-acquiring dropped caps via setuid or
  file-capability binaries.

## [0.4.2] - 2026-06-01

Closes the headline cyrius-port regression: real PAM authentication is
restored via Linux-PAM's `unix_chkpwd(8)` helper, demoting the
`/usr/bin/su` shim to a fallback. The consumer authorization/auth API
surface is unchanged; consumers must add `"pam"` to their stdlib list
(see **Changed**).

### Added

- **Real PAM authentication via `unix_chkpwd(8)`.** `src/auth.cyr::
  pam_authenticate` now forks Linux-PAM's setuid-root `unix_chkpwd`
  helper through the stdlib's `lib/pam.cyr::pam_unix_authenticate`
  (added `include "lib/pam.cyr"` in `src/lib.cyr`). This is the
  mechanism `pam_unix.so` itself uses from an unprivileged process; it
  verifies against `/etc/shadow` with a normal glibc lookup on the root
  side. New ADR-006 records the decision (and why we did **not** dlopen
  libpam directly — that path is still blocked on cyrius's NSS /
  helper-trust model).

### Changed

- **`/usr/bin/su` is demoted from primary auth backend to the
  helper-missing degradation path.** When `unix_chkpwd` is present (the
  common case) it is the authoritative backend; su is reached only when
  the helper is absent or hits a transient pipe/fork/exec error
  (`SHK_ERR_PAM_UNAVAILABLE` seam). A *rejected* password is never
  retried through su. Consumer authorization/auth API surface is
  unchanged.
- **`cyrius.cyml`: added `"pam"` to the `[deps].stdlib` list.** The
  distlib bundle now references `pam_unix_authenticate` as an unresolved
  symbol (like `sakshi_*`), so consumers of `dist/shakti.cyr` must carry
  `"pam"` in their own stdlib list. Documented in README § Dependencies;
  the integration consumer-probe enforces it.

### Security

- **Closes the headline cyrius-port regression: real PAM authentication
  is restored.** Since 0.2.0 the cyrius port authenticated through a
  `/usr/bin/su -c true` shim because `pam_authenticate` was a stub. Auth
  now goes through the distro's setuid-root `unix_chkpwd`, which honours
  every configured NSS backend (files, LDAP, SSSD, …) — closing the
  auth-side NSS gap from ADR-005 without touching the still-blocked
  `fdlopen` helper-trust path. Group-side NSS resolution
  (`src/identity.cyr`) remains local-files-only (bite 2b, still blocked).
  All auth paths (PAM success, PAM reject, su degradation) remain audit-
  logged unchanged.

## [0.4.1] - 2026-06-01

Toolchain pin maintenance. No source, API, or behavior change — the
binary, library API, and audit format are byte-for-byte equivalent to
0.4.0 apart from the embedded version string.

### Changed

- **Cyrius toolchain pin 6.0.3 → 6.0.31.** Point-release bump aligning
  the pin with the current toolchain; no breaking language change and no
  source edits required. Eliminates the per-command "pins 6.0.3 but cycc
  is 6.0.31 — toolchain drift" warning. `cyrius.lock` regenerated under
  6.0.31 (the 6.0.x stdlib resolution set shifted — e.g. `toml.cyr`,
  `regex.cyr`, `fs.cyr`, `freelist.cyr` — and is now deterministic
  again); `dist/shakti.cyr` re-emitted (cosmetic: two blank lines
  dropped). CI/release install the pinned version verbatim from the
  `[package].cyrius` line, so the pin is the single source of truth.

## [0.4.0] - 2026-05-27

Toolchain + ecosystem modernization, aligning shakti with its sibling
first-party projects (patra, sigil) now that both are on cyrius 6.0.3.
No change to the consumer authorization/auth API surface; the audit
*record* gains a structured stderr channel (see **Changed**).

### Changed

- **Cyrius toolchain pin 5.7.33 → 6.0.3.** v6.0.0 is the two-binary
  rename ceremony (`cyrc`→`cybs`, `cc5`→`cycc`); no breaking language
  change. Source idioms were already current — no rewrites required.
- **`cyrius.cyml`: moved `modules` from `[build]` to `[lib]`.** The
  compiler treats `[build].modules` as an auto-prepend list, which
  re-included every module that `src/lib.cyr` already pulls — emitting
  ~15 duplicate-fn warnings and inflating the unreachable-fn count.
  `[lib].modules` is read only by `cyrius distlib`. Build is now clean.
- **Audit stderr is now structured + level-filterable via sakshi.** The
  raw `file_write(2, …)` line is replaced by `sakshi_info` (ALLOWED) /
  `sakshi_warn` (DENIED, AUTH_FAILURE), emitting `[ts] [LEVEL] shakti: …`.
  The durable `/var/log/agnos/sudo.log` trail is unchanged (see
  **Security**). `init_tracing()` is no longer a no-op — it sets the
  sakshi level to `SK_INFO`.
- **CI/release: toolchain install now uses the upstream
  `scripts/install.sh`** (sourcing the version from `cyrius.cyml`'s pin)
  instead of a hand-rolled tarball fetch — matching patra/sigil. The
  vestigial tarball-cleanup step was removed from `release.yml`.
- **Stdlib is no longer vendored.** `lib/` was a stale 5.7.x copy tracked
  in git (and shadowed the version-pinned 6.0.3 stdlib). It is now
  gitignored and populated by `cyrius deps`, matching patra/sigil. Run
  `git rm -r --cached lib/` once to drop the tracked copy.
- Renamed the binary's `run()` → `shk_run()` to avoid colliding with the
  stdlib `process.run` (was a "duplicate fn, last definition wins"
  warning).

### Added

- **`sakshi` 2.2.5 dependency** (`[deps.sakshi]`) — structured logging,
  the `tracing` layer the Rust original always intended. Zero-alloc hot
  path, fixed stack buffers, no env reads — safe in the setuid post-fork
  path. Consumers of `dist/shakti.cyr` must declare it themselves (it is
  left unresolved in the bundle, like the stdlib); see README §
  Consumer API → Dependencies.
- **`cyrius.lock`** — now generated (shakti has a real external dep);
  CI's `cyrius deps --verify` enforces it.
- **`scripts/version-bump.sh`** — keeps VERSION, `shakti_version_string()`,
  and the CHANGELOG heading in lockstep (ports patra's pattern).

### Fixed

- **Release: removed `strip build/shakti`.** Cyrius emits minimal ELF
  with no symbol table, so `strip` didn't shrink the binary — but it
  corrupted the section/program headers, making the binary SIGSEGV on
  first run. The release `Verify version surface` step failed with exit
  139. patra/sigil never strip cyrius binaries.

### Security

- **Audit logging is preserved on every path, success and failure.** The
  authoritative record is still the file-locked, untruncated
  `/var/log/agnos/sudo.log` write (`file_append_locked`), unchanged. The
  new sakshi channel is additive; `SK_INFO` is chosen deliberately so
  ALLOWED actions still emit (a higher level would have silently dropped
  successful-command audit lines from stderr). sakshi's 256-byte line
  buffer may truncate a very long command on stderr — the file trail
  remains the complete record.

## [0.3.0] - 2026-04-28

Audit deferrals closeout — final 0.2.x-line polish before the
0.3.x feature line opens. Closes the last open finding from the
2026-04-20 internal audit (L-3) at a level the audit explicitly
deferred but a future external reviewer would expect. Nothing
removed, nothing renamed; consumer API surface unchanged.

### Security

- **L-3 — defensive `if (alloc == 0)` guards in `src/auth.cyr`
  and `src/env.cyr`.** From the 2026-04-20 internal audit's
  deferred-list. Before, an `alloc()` returning 0 (the bump
  allocator's OOM signal) would have been dereferenced by the
  next `memcpy` / `store*`, producing a SIGSEGV. After, every
  alloc site checks for 0 and returns the function's documented
  error contract — `0 - SHK_ERR_IO` for parent-side auth
  failures, `sys_exit(127)` (matching the existing exec-failure
  exit code) for child-side alloc failures inside the post-fork
  `su` invocation, `0` for pointer-returning helpers
  (`_mk_env_pair`, `_mk_env_pair_int`, `_env_key`), an empty
  vec for `shk_read_environment`, and graceful early-break for
  `_shk_read_environ`'s grow loop.

  Eleven guards added across:
  - `src/auth.cyr:su_authenticate` — pipe fd buf, child argv
    array, child empty envp, parent waitpid status buf. The
    waitpid path also calls `sys_waitpid(pid, 0, 0)` on alloc
    failure so the child is reaped rather than zombied.
  - `src/env.cyr` — initial environ buffer, grow-buffer in
    the read loop, length-out cell, per-entry copy, the two
    KEY=VAL pair builders, and the key-extractor.

  Per the audit's framing, OOM in a setuid binary is a
  terminal state and segfault is acceptable abort behaviour.
  The guards make that abort happen via documented error
  paths instead of unsynchronised SIGSEGV — eliminates the
  undefined-behaviour window between alloc and the first
  deref. Defensive hygiene; not exploitable as written.

### Notes

- **Test coverage of OOM paths**: shakti's bump allocator
  doesn't fail in any realistic test environment (it would
  require exhausting the mmap-able address space). The
  guards are reviewed by inspection, not exercised at unit
  level. A future audit could add an alloc-fault-injection
  hook in `lib/alloc.cyr` to make this testable.
- **Downstream propagation**: when `_mk_env_pair` returns 0
  on OOM, the existing `vec_push(out, 0)` in
  `sanitize_environment` will null-terminate `envp` early at
  execve marshalling, dropping subsequent entries (truncated
  but not corrupt env). Acceptable fail-soft per the audit
  framing; flagged for a future propagation pass if a
  consumer surfaces a concern.

### Roadmap

- [x] **L-3** — closed in this release.
- [ ] **L-2** — env-read buffer leak on grow remains deferred.
  Blocked on `free()` in shakti's allocator; would require
  switching to `lib/freelist.cyr` or pre-sizing via `stat(2)`.
  Not security-relevant for single-shot CLI; see roadmap.
- Capability-based privilege (CAP_*) is queued for **0.3.1**
  per the v0.3+ roadmap.

## [0.2.3] - 2026-04-28

Toolchain-modernization release. Bumps the cyrius pin from 5.4.17
to 5.7.33, re-formats the source tree under the new cyrfmt
continuation-indent rules (5.7.22), regenerates `dist/shakti.cyr`
against the bumped toolchain, and brings CI/release workflows up
to the daimon/nous standard. No behaviour changes; one runtime-
visible artefact is the version banner.

### Changed

- **cyrius `5.4.17` → `5.7.33`.** Stdlib API surface used by
  shakti is unchanged across the bump (verified against:
  `syscalls`, `string`, `alloc`, `freelist`, `fmt`, `str`,
  `vec`, `io`, `fs`, `args`, `hashmap`, `toml`, `regex`,
  `tagged`, `process`, `assert`, `bench`, `fnptr`). Picks up
  the v5.6.34 `alloc` grow-undersize SIGSEGV fix passively;
  silences the v5.7.8 `_SC_ARITY` SETSID warning that used to
  appear on every build.
- **`src/`, `tests/tcyr/`, `tests/bcyr/`, `tests/integration/`
  reformatted by cyrfmt 5.7.33.** v5.7.22's brace-tracking
  fix changed continuation-indent rules; rewrote 10 files
  (`src/env.cyr`, `src/main.cyr`, `src/policy.cyr`, `tests/
  tcyr/api.tcyr`, `tests/tcyr/audit.tcyr`, `tests/tcyr/
  fuzz.tcyr`, `tests/tcyr/policy.tcyr`, `tests/tcyr/validate.
  tcyr`, `tests/bcyr/core.bcyr`, `tests/integration/
  consumer_probe.cyr`) so `cyrfmt --check` is now clean across
  the tree.
- **`dist/shakti.cyr` regenerated** under the bumped toolchain
  + reformatted sources. Bundle line count unchanged (2417);
  byte-level diff reflects the cyrfmt rewrite plus the
  version-string bump.
- **`shakti_version_string()` → `"shakti 0.2.3 (cyrius port)"`**
  in `src/lib.cyr`.

### CI / Release

- **`.github/workflows/ci.yml` rewritten** to match the
  daimon/nous standard. Adds: `cyrius vet`, `cyrfmt --check`
  (hard fail on drift now that the tree is clean), `cyrius
  lint` (advisory pending the long-line hygiene pass on test
  fixtures), `cyrius deps --verify` (gated on
  `cyrius.lock` presence), ELF magic check, version-surface
  assertion (`./build/shakti --version` must contain
  `$VERSION`), `cyrius distlib` drift gate, integration script
  + consumer probe, `fuzz/*.fcyr` runs, `bench-history.sh`
  artefact upload, separate `security` job (forbidden-call
  scan + privilege-drop return-check audit), `docs` job
  (required-file inventory + cross-file version consistency).
- **`.github/workflows/release.yml` rewritten** to gate on the
  new ci.yml, verify `tag == VERSION`, build with `strip`,
  re-run tests + integration, hard-fail on `dist/shakti.cyr`
  drift at tag time, archive a versioned source tarball
  (`shakti-X.Y.Z-src.tar.gz`), x86_64 binary
  (`shakti-X.Y.Z-x86_64-linux`), and the consumer bundle
  (`shakti-X.Y.Z.cyr`), publish `cyrius.lock` + `SHA256SUMS`
  alongside, and auto-flag `0.x` tags as prerelease for the
  GitHub Release.

### Security

- **CI security scan tightened.** New `security` job hard-fails
  on: any `system(`, `exec_str(`, `sys_system(` call site (any
  shell-out is a bypass of the validate / authorize / drop
  pipeline); any unchecked `sys_setuid` / `sys_setgid` /
  `sys_setgroups` call site (regression guard for the H-1
  audit fix from 0.2.2). Carried over from the audit cadence
  established in 0.2.2.

### Refactored

- **NSS group resolution — bite 2a (files-only).** Both
  `identity_lookup_groups` and `identity_lookup_gids` in
  `src/identity.cyr` now delegate to `lib/grp.cyr`'s shared
  `/etc/group` reader (`grp_getgrouplist` + `grp_getgrgid`).
  Drops ~80 LOC of bespoke field-walking and a private
  `_identity_member_match` helper. `lib/grp.cyr` is added to
  `cyrius.cyml [deps] stdlib`. **This does not restore
  LDAP/sssd**: `lib/grp.cyr` bypasses NSS entirely (musl-style
  `/etc/group` parser), same as the code it replaces. Real
  NSS dispatch needs the libc-fdlopen path, blocked on a
  setuid-safe helper-trust model — captured as a future
  blocker on the roadmap.
- **Behaviour change — primary group now included in
  `identity_lookup_groups`.** Matches `getgrouplist(3)` /
  sudo semantics: a policy rule that names a user's primary
  group should match the user, even when the `/etc/group`
  member list is empty (the common case for `root` on stock
  Ubuntu/Debian). Previously a rule like `group = "users"`
  would not match a user whose primary group was `users`
  unless they were also in the member list. New test
  `t_lookup_groups_root_includes_primary` locks this in;
  `t_lookup_groups_root_well_formed` updated; new
  `t_lookup_groups_missing_user`. Identity test count
  23 → 30 (+7 portable assertions).

### Audit deferrals (closeout)

- **L-1 — `update_timestamp` no longer conflates open(2)
  errors as `SHK_ERR_SYMLINK`.** From the 2026-04-20 internal
  audit. `O_NOFOLLOW` on a symlinked path returns `-ELOOP`
  (40); other errors (`-EACCES`, `-ENOENT`, `-EMFILE`, …) now
  surface as `SHK_ERR_IO`. Operator-debuggability fix; no
  security delta.
- **L-2 (env-read buffer leak on grow)** remains deferred —
  `lib/alloc.cyr` is a bump allocator with no `free`, so the
  fix would require switching shakti to `lib/freelist.cyr` or
  pre-sizing via `stat(2)`. Not security-relevant for the
  single-shot CLI invocation.
- **L-3 (unchecked `alloc()` returns)** remains deferred —
  spans multiple call sites in `auth.cyr` and `env.cyr`;
  earmarked for a defensive-checks pass.

### Internal

- **NSS / PAM blocker note** updated in
  `~/.claude/projects/.../memory/blocker_dynlib_libc_init.md`.
  cyrius v5.5.27 shipped `lib/pam.cyr::pam_unix_authenticate`
  (forks `unix_chkpwd` setuid helper) and v5.5.34 completed
  `fdlopen_init_full` orchestration. The dynlib libc-init
  block cited in the parked memory is lifted; the migration
  from shakti's PAM stub is now a tractable feature task,
  not a parking lot. Tracked for v0.3.

## [0.2.2] - 2026-04-20

Audit-driven patch release. Pairs an internal adversarial self-
review with an external-CVE-surface survey; ships five hardening
fixes surfaced by the internal pass plus the two audit artefacts.

### Security

- **H-1 — privilege-drop return values now checked.**
  `src/main.cyr:_exec_target` previously ignored return values from
  `sys_setgroups` / `sys_setgid` / `sys_setuid`. A silent failure
  (SELinux/AppArmor denial, seccomp, `NO_NEW_PRIVS`, exotic
  capability state) would have let the process continue to
  `sys_execve` with its pre-drop uid — exactly the outcome the
  drop was meant to prevent. All three calls now abort with exit
  code 1 on negative return, and the post-condition is verified
  via `sys_getuid()` / `sys_getgid()` before exec. Matches the
  "check every drop return" pattern sudo adopted after historical
  setresuid incidents.
- **H-2 — integer-overflow guard on numeric field parsers.**
  `_identity_parse_uint` (`src/identity.cyr`) and `_shk_parse_int`
  (`src/policy.cyr`) now cap valid range at `UINT_MAX`
  (4,294,967,295 = Linux uid/gid ceiling). Inputs past the cap
  return the existing `-1` parse-error sentinel rather than
  wrapping silently. Gated on assumption S1 (root-writable
  `/etc/passwd` / policy files) so not an in-scope exploit path,
  but matches setuid-context parsing hygiene.
- **M-1 — timestamp-directory symlink check.**
  `_shk_ensure_ts_dir` now uses `SYS_LSTAT` (not `SYS_STAT`) and
  rejects `S_IFLNK` explicitly. Symmetric with `check_timestamp`
  which already used LSTAT. Defence in depth: a symlink at
  `/var/run/agnos/sudo` pointing at any other root-owned directory
  no longer silently redirects timestamp writes.
- **M-2 — empty-name `/etc/passwd` / `/etc/group` entries now
  skipped.** `identity_lookup_uid` and `identity_lookup_groups`
  previously allocated zero-length name cstrs for malformed
  entries starting with `:`. Downstream code fail-closed via
  `validate_username`, but emitting empty names was noise. Now
  those entries are skipped cleanly.
- **I-1 — clarifying comment** on empty-envp intent in
  `su_authenticate`. Documents that no-env is the injection-surface
  reduction, not an oversight.

### Added

- **`docs/audit/2026-04-20-internal-review.md`** — internal
  adversarial self-review. Findings H-1, H-2, M-1, M-2, I-1 (shipped
  in 0.2.2) plus L-1 / L-2 / L-3 deferred to v0.3 polish work.
  Severity rubric, method notes, review cadence.
- **`docs/audit/2026-04-20-external-cve-review.md`** — known-CVE
  surface survey. ~30 entries across sudo (6), OpenDoas (2),
  util-linux su/runuser (3), Linux-PAM (5 — all ⏳ gated on cyrius
  5.5.x PAM re-enablement), glibc NSS (3), LD_PRELOAD / env (3),
  TTY (3), timestamp (4), systemd-adjacent (2). Each mapped against
  shakti's implementation with status marker: ✅ Mitigated, ➖ N/A,
  ⏳ Blocked-on-future, ⚠️ Open, 🔍 Review. Zero Open CVE classes
  outside the TIOCSTI family. Handoff artefact for the post-release
  third-party audit.
- **`docs/audit/README.md`** — dated-report convention for the
  `docs/audit/` tree. Table of current entries, expected future
  entries, "don't edit, supersede" rule.
- **`tests/tcyr/identity.tcyr:parse_uint overflow guard`** — 5 new
  assertions covering the overflow-rejected path, the exactly-at-
  `UINT_MAX` boundary, `UINT_MAX + 1` rejection, and normal-value
  parsing as control.
- **`tests/tcyr/policy.tcyr:t_timestamp_ttl_overflow_rejected`**
  — policy parser rejects a ttl of `99999999999999999999`; default
  TTL (300) is preserved rather than silently accepting a wrapped
  value.

### Threat model

- **`docs/architecture/threat-model.md`** — added **T11 (TIOCSTI
  terminal-input injection)** surfaced by the CVE review. Lateral
  uid moves (caller → non-root target) share the caller's tty;
  mitigation today is partial (kernel-level `legacy_tiocsti` sysctl
  advisory); full PTY-allocation fix tracked in v0.3+ roadmap.
  "Related documents" section cross-links the CVE review.
- **`SECURITY.md`** — "Threat Model + CVE review" section now links
  both audit documents; T-count updated to 11.

### Test totals (post-0.2.2)

- **334 unit** assertions (up from 328) across 14 `.tcyr` files.
- **20,101 property-fuzz** assertions (unchanged).
- **18 integration** assertions (unchanged).

## [0.2.1] - 2026-04-20

### Changed

- **Cyrius toolchain pin 5.4.11 → 5.4.17**. Released specifically to
  unblock shakti's mini-TOML multi-line array work — `lib/toml.cyr`
  gained the canonical bracket/quote state-machine algorithm shakti
  ports in this release. Also inherits v5.4.12-1 (toolchain cleanup),
  v5.4.13 (`fncall7`/`fncall8`), v5.4.14 (dep-tag fix), v5.4.15
  (`lib/keccak.cyr`), v5.4.16 (keccak rotl64 inlining) — none
  load-bearing for shakti today.

### Fixed

- **Multi-line arrays in policy files now parse correctly.**
  Previously, any `commands = [` followed by a newline silently
  truncated to an empty array — operators writing reviewable
  one-entry-per-line policies got the fail-closed path (no commands
  matched) instead of the intended policy. Ported cyrius v5.4.17's
  `lib/toml.cyr:elif (vc == 91)` algorithm into `src/policy.cyr:
  parse_policy`: detect `[` as first non-space char after `=`, walk
  forward tracking quote state (quoted `]` inside a string doesn't
  close the outer bracket) and bracket depth (nested `[` bumps
  depth). Closes
  `docs/development/issues/2026-04-19-mini-toml-parser-limits.md`.
- **`_shk_parse_str_array` defensive advance-guard.** Unexpected
  characters inside array bodies (notably `#` — inline array
  comments remain out of scope) used to stall both inner loops with
  `pos` unchanged, infinite-looping the parser. Outer loop now
  records `loop_start` and force-advances 1 byte if the iteration
  didn't progress. Silent-drop of the malformed entry rather than
  hanging.

### Added

- **`tests/tcyr/policy.tcyr:t_multiline_array_parses` +
  `t_multiline_array_empty` + `t_multiline_array_with_deny`** —
  three new positive-assertion tests encoding the fixed behaviour
  (62 cases total in `policy.tcyr`, up from 50). Closes the
  resolution doc's acceptance gate 2.
- **`docs/examples/sudoers.toml` + `fragments/10-deploy.toml` +
  `fragments/20-ops.toml` un-squished** back to multi-line arrays
  for reviewability. Smoke-test at `tests/tcyr/examples_smoke.tcyr`
  still passes all 17 cases against the new shape.
- **`docs/examples/README.md` "Formatting limits" updated**: case 1
  (multi-line arrays) removed; case 2 (inline `#` in array body)
  documented with two workarounds (out-of-array comment, whole-rule
  comment); case 3 (triple-quoted strings) marked out of scope.



### Changed

- **Cyrius toolchain pin 5.2.1 → 5.4.11** (`cyrius.cyml`). Brings in
  three-and-a-half months of upstream work; relevant inheritance for
  shakti (all on the x86_64 Linux static target):
  - v5.2.1 `cyrius deps --lock` / `--verify` — supply-chain hash
    verification (SHA256 lockfile) available for CI.
  - v5.3.3 `mulh64(a, b)` builtin — not used directly by shakti
    today, but upstream sigil adopts it which drops AES-GCM paths
    that shakti may eventually depend on.
  - v5.3.5 `secret var name[N];` — zeroise-on-exit arrays. Adopted
    in `_prompt_and_authenticate` (see Security section below).
  - v5.3.7 → v5.3.14 dynlib machinery (IRELATIVE, IFUNC,
    cpu_features/TLS/stack_end bootstrap, bounds-checked indirect
    calls). Not unblocking NSS/PAM yet, but the infrastructure is
    in place and simple libc calls via `dynlib` work today.
  - v5.3.14 `lib/args.cyr` — empty-string args no longer silently
    dropped; argv/argc correctness fix inherited.
  - v5.4.9 ships sigil 2.8.4 (AES-GCM fix + hardening pass) in the
    toolchain dep graph.
  - v5.4.10 `lib/thread.cyr` post-clone trampoline — not used by
    shakti but inherited.
  - v5.4.11 per-arch `lib/syscalls.cyr` split with arch-dispatched
    `Stat` enum (`STAT_MODE` / `STAT_UID` / `STAT_GID` / `STAT_BUFSZ`).
    Shakti's hand-rolled `STAT_MODE_OFF` / `STAT_UID_OFF` /
    `STAT_BUF_SIZE` constants (x86_64 literals) are replaced with the
    cyrius enum names — the migration path the cyrius changelog
    recommends for downstream consumers. Residual x86_64-specific
    values (`SYS_LSTAT`, `SYS_READLINK`, `SYS_CLOCK_GETTIME`,
    `SYS_CLOSE_RANGE`, `STAT_MTIME_OFF`, `S_IF*`, `O_NOFOLLOW`)
    remain shakti-local with a comment noting aarch64 cross-build
    would need them remapped.
- Test suite: 239 cases across 9 `.tcyr` files + bench harness; all
  pass against the v5.4.9 toolchain with no source changes required.

### Added

- `src/identity.cyr` — local-files identity backend extracted from
  `main.cyr`. Public API: `identity_lookup_uid`,
  `identity_lookup_user`, `identity_lookup_groups`,
  `identity_lookup_gids`. The previous inline parsers in `main.cyr`
  (uid lookup, group lookup, target uid lookup) are removed in
  favour of this module.
- `tests/tcyr/identity.tcyr` — 12 cases covering uid/name lookup,
  missing-user fallthrough, substring-safety on colon-anchored
  matches, primary-gid-first ordering, and primary-vs-supp dedup.
- `docs/adr/005-identity-backend-port-to-cyrius.md` — captures the
  decision to use local-files parsing in `src/identity.cyr` for the
  0.2.x line, along with the cyrius dependency chain that gates
  restoring NSS backend parity. Replaces the stale "blocked on
  cyrius 5.3.1" note in the roadmap.

### Changed (P(-1) review cleanups)

- `policy.cyr:_shk_copy_trim` — removed the vestigial first trim-left
  loop (commented "Restart cleanly (the idiom above is to exit the
  trim-left loop)"). The second loop was the real trim-left; the
  first was broken and dead. No behaviour change; ~11 lines deleted.
- `policy.cyr:check_authorization` — replaced the `else { i = i; }`
  noop with an early `continue` when neither user nor group matches.
  Flow is now linear; same benchmarks (~1-2µs per call).
- `cyrius.cyml` — `version = "${file:VERSION}"` (v5.1.13 expansion)
  so the VERSION file is the single source of truth for the manifest.
- `src/lib.cyr:shakti_version_string()` — centralises the in-source
  version string; `main.cyr:--version` now reads from it rather than
  a hardcoded literal. Still hand-sync with VERSION on bumps.
- `cyrius.cyml [build] output = "build/shakti"` — binary lands under
  `build/` (gitignored) by default rather than the repo root.

### Performance

- **`sanitize_environment` 141µs → 33µs (4.3×)**. Replaced the linear
  vec scan of the 51-entry unsafe list + 9-entry safe list with a
  `lib/hashmap.cyr` lookup. `_shk_unsafe_cache` / `_shk_safe_cache`
  are still lazy singletons; first call still builds the map, every
  call thereafter is O(1). Other hot-path benchmarks unchanged:
  `command_matches/*` ~1µs, `validate_command` ~1µs,
  `check_authorization/*` 1–2µs, `parse_policy` ~14µs.

### Security

- **`_prompt_and_authenticate` adopts `secret var pbuf[1024]`**
  (cyrius v5.3.5). The password buffer is now a stack array with an
  auto-synthesised zeroise prologue wired into every return path —
  including early returns from MAX_AUTH_ATTEMPTS exhaustion, empty
  input, and successful authentication. Replaces the prior
  heap-allocated `alloc(1024)` + hand-rolled `_zeroize_cstr` (which
  only cleared `strlen(buf)` bytes, not the full buffer).
  `_read_password` split into `_read_password_into(buf, cap)` so the
  caller owns the lifetime and can apply `secret`. Between-attempt
  `memset(&pbuf, 0, PW_BUF_CAP)` remains as defense in depth for the
  in-loop window.
- **Fixed null-byte leak in `_print_usage`**. Hand-counted byte
  lengths drifted by +1 on seven usage lines, leaking one null byte
  per option into help output (`od -c` showed `\0` between lines).
  Replaced every `file_write(fd, s, N)` call with a `_write_line(fd,
  s)` helper that measures with `strlen`. Structural fix prevents
  the bug class.
- **`shakti` (no args) now prints usage instead of a policy-load
  error**. The "command required" check moved ahead of the policy
  load so running shakti bare no longer tries to read
  `/etc/agnos/sudoers.toml` and fails with "failed to load policy".

### Added

- `tests/tcyr/fragments.tcyr` — 13 cases covering
  `_shk_load_fragments` defense gates (nonexistent dir, world-
  writable dir, non-directory target), the lexicographic sort helper
  `_shk_sort_str_vec`, and `str_compare_lex`.
- `tests/tcyr/fuzz.tcyr` — property-based fuzz harness porting the
  four `rust-old/fuzz/fuzz_targets/` harnesses (`parse_policy`,
  `validate_command`, `command_matches`, `validate_username`) that
  regressed in the 0.2.0 port. Cyrius has no coverage-guided fuzzer
  infra; this uses a deterministic xorshift64 PRNG with an
  adversarial byte menu (`/ \ " ' [ ] = ; | $ ( ) space # , . - _`)
  and 2500 iterations per target. **20,101 assertions pass** per run
  with no crash or invariant breach. Seeds are printed on failure so
  any regression is deterministically reproducible. Iteration budget
  tunable via `FUZZ_ITERS`.
- `tests/integration/cli.sh` — 16 bash-harness assertions covering
  the non-privileged CLI surface (`--version`, `--help`, `-V`/`-h`
  aliases, no-args, unknown option, `--` delimiter). Policy-loading
  paths (`--list`, `--check`, `--invalidate`, full exec flow) still
  need a root-owned fixture to exercise — tracked for a v0.3 CI
  harness.
- Test count: **252 `.tcyr` unit assertions** (up from 239) +
  **20,101 fuzz assertions** + 18 integration + bench harness.

### Install

- **`scripts/install.sh`** — idempotent system installer. Installs
  `build/shakti` setuid-root to `/usr/bin/shakti` (mode 4755),
  creates `/etc/agnos/` with `sudoers.d/` fragment directory,
  provisions `/var/run/agnos/sudo` (mode 0700), drops the
  `tmpfiles.d` snippet, installs the PAM service config. Flags:
  `--with-example-policy` copies the annotated example in as the
  starting policy; `--no-pam` / `--no-tmpfiles` skip those steps;
  `PREFIX` / `SYSCONFDIR` / `RUNDIR` / `TMPFILESDIR` env
  overrides for non-standard layouts. Refuses to run non-root.
- **`etc/tmpfiles.d/shakti.conf`** — systemd-tmpfiles entry that
  recreates `/var/run/agnos/sudo` (0700 root:root) at every boot,
  since `/var/run` is tmpfs. Avoids first-invocation mkdir races
  between concurrent shakti calls.
- **README** — added Install section. Test-command list updated with
  integration script + cyrius version floor bumped to 5.4.11.

### CLI parser refactor + direct unit coverage

- **`src/cli.cyr`** (new) — CLI parsing extracted from `src/main.cyr`
  so tests can include it without triggering main's top-level
  `syscall(SYS_EXIT, rc)`. Not added to the consumer bundle —
  library consumers build their own entry points on
  `evaluate_with_policy`; shakti's CLI surface is binary-specific.
  `_parse_cli()` is now a thin wrapper over `_parse_cli_from(args_vec)`
  that collects the real argv from `argc()` / `argv()`.
- **`tests/tcyr/cli.tcyr`** — **47 direct unit assertions** across
  defaults, `--version`/`-V`, `--help`/`-h`, `-u`/`--user`,
  `-p`/`--policy` (including missing-arg error paths),
  `-k`/`-l`/`-c` flag shorthands, `--` delimiter handling,
  unknown-option rejection, first-positional-captures-rest
  semantics, and flag-ordering combinations. Previously only
  exercised via subprocess integration tests; now every branch
  in the parser has a targeted assertion.

### Known limitations

- **`docs/development/issues/2026-04-19-mini-toml-parser-limits.md`**
  — filed for language-agent review. Surfaced while writing
  `docs/examples/*` — shakti's local mini-TOML parser in
  `src/policy.cyr` doesn't support multi-line array values or
  inline `#` comments inside array bodies. Workaround today:
  collapse arrays to a single line. Fix is a downstream-only patch
  to `parse_policy` + `_shk_parse_str_array` (cyrius `lib/toml.cyr`
  is explicitly out of scope — shakti's local parser stays local).
  Security impact: none (fail-closed); ergonomic only. Issue file
  includes reproduction, two approach sketches, acceptance
  criteria.

### Policy examples

- **`docs/examples/sudoers.toml`** — fully annotated single-file
  policy covering every rule type: wheel full-access, named
  administrator, NOPASSWD CI deploy user with `deny_commands`
  precedence demo, ops group diagnostics, wildcard-user
  self-service passwd, dedicated build-bot account. Comments walk
  through `[defaults]` options and each pattern form.
- **`docs/examples/fragments/`** — four files demonstrating
  `include_dir` deployment: `main.toml` declares defaults, the
  numbered fragments (`00-base.toml`, `10-deploy.toml`,
  `20-ops.toml`) carry team-scoped rules loaded in lexicographic
  order.
- **`docs/examples/README.md`** — index, deployment steps for both
  single-file and fragment layouts (with correct `install -o root
  -g root -m 0644` invocations), `--check` linter output guide,
  rule-ordering + first-match-wins notes, and a dedicated
  "Formatting limits" section documenting the mini-TOML parser's
  single-line-array constraint.
- **`tests/tcyr/examples_smoke.tcyr`** — **17 assertions** that
  parse each shipped example through `parse_policy`, verify rule
  counts, confirm the deploy rule carries its `deny_commands`
  + NOPASSWD, and assert the annotated example produces zero
  `LINT_ERROR` warnings. Guards against silent schema drift.

### Documentation expansion

- **`docs/architecture/overview.md`** — added "Library boundary and
  distribution" section covering the binary/library split, the
  `cyrius distlib` mechanics, the 9-file bundle-order map with
  cross-module dependencies annotated, the publish flow
  (edit → test → distlib → integration probe → commit), and the
  cyrius-toolchain floor for consumers. Module Structure table now
  has an "In library bundle" column marking `main.cyr` as binary-
  only. Pointer note at the top directing security reviewers to the
  threat-model doc.
- **`docs/architecture/threat-model.md`** — new. Structured for an
  external security reviewer: five in-scope attacker classes
  (A1 local unpriv, A2 compromised authorised, A3 co-located
  process, A4 filesystem, A5 hostile policy author) and three
  out-of-scope (A6 kernel, A7 physical, A8 supply chain); trust
  boundary diagram + table; a ten-entry assumption register
  (S1–S10) documenting what must hold for mitigations to work;
  ten threat entries (T1 shell injection through T10 co-located
  setuid) each with attack description, mitigation, residual risk,
  and test coverage references; non-goals; open gaps table cross-
  referencing the port-regressions list.
- **`SECURITY.md`** — 0.1.x → 0.2.x version row swap; security
  properties list updated to reflect cyrius-era implementation
  (`secret var`, per-TTY timestamp, hashmap-backed env blocklist);
  new "Threat Model" section links the threat-model doc +
  architecture overview.

### Documentation audit

- **`docs/architecture/overview.md`** — purged Rust-era claims:
  threat model row now names `secret var pbuf[1024]` (v5.3.5) instead
  of the `zeroize` crate; group-resolution row honestly states
  `/etc/group` parsing with the NSS path tracked for cyrius 5.5.x;
  auth flow reflects the `su` shim + `SHK_ERR_PAM_UNAVAILABLE`
  fall-through rather than "try PAM first"; consumer-API example
  rewritten in cyrius syntax pointing at `dist/shakti.cyr` and
  `docs/guides/integration.md`.
- **`docs/development/dependency-watch.md`** — fully rewritten for
  the cyrius era. Active surface: cyrius toolchain pin, Linux
  syscall ABI, `/etc/passwd` + `/etc/group` format, `/usr/bin/su`
  semantics, PAM service config file, mini-TOML parser limits. Old
  RUSTSEC-2025-0040 / RUSTSEC-2023-0059 / RUSTSEC-2023-0040
  (`pam` 0.7.0 → `users` 0.8.1) advisories moved to **Resolved** —
  the Rust dependency graph is gone.
- **`docs/adr/001-timestamp-o-nofollow.md`** — added post-port note:
  decision preserved verbatim; implementation no longer goes through
  `nix::fcntl::open`, calls `syscall(SYS_OPEN, …, O_NOFOLLOW, 0600)`
  directly.
- **`docs/adr/002-initgroups-for-target-user.md`** — added post-port
  note: decision preserved; implementation regressed from
  `nix::unistd::initgroups` (NSS-aware) to local-files
  `/etc/group` parsing (`src/identity.cyr:identity_lookup_gids`);
  LDAP/sssd gap revisits at cyrius 5.5.x. Cross-references ADR-005.
- **`CLAUDE.md`** — replaced the cargo-era cleanliness-check
  command list (`cargo fmt`, `cargo clippy`, `cargo audit`,
  `cargo deny`, `cargo doc`) with the cyrius-era equivalents
  (`cyrius test`, `sh tests/integration/cli.sh`, `cyrfmt --check`,
  `cyrlint`, `cyrius build`, `cyrius distlib`). Added an explicit
  note that `dist/shakti.cyr` drift is a commit-blocker.
  Version-sync checklist updated: VERSION → `cyrius.cyml`
  (`${file:VERSION}`) → `shakti_version_string()` in `src/lib.cyr`
  → zugot recipe. Project-type line now "Cyrius binary + library"
  (was "Binary crate").
- **README** — "Consumer API" section references both the bundle
  and piecemeal module pickup; ark listed as fourth consumer
  alongside argonaut / agnoshi / daimon; points readers at
  `docs/guides/integration.md`.

### Library publishing

- **`dist/shakti.cyr`** — 80 KB self-contained bundle generated by
  `cyrius distlib`. Consumers pull it via
  `[deps.shakti] modules = ["dist/shakti.cyr"]` against a pinned tag,
  same pattern sigil / nous / yukti use. Commit the bundle alongside
  source — `cyrius distlib` after any `src/*.cyr` edit.
- **`cyrius.cyml [build] modules`** — declares the 9-module bundle
  order (`src/lib.cyr` first for constants, then validate → env →
  identity → timestamp → audit → auth → policy → api). `src/main.cyr`
  is deliberately excluded (it's the CLI entry; its top-level
  `syscall(SYS_EXIT)` would fire inside the consumer).
- **`tests/integration/consumer_probe.cyr`** — 8-assertion smoke test
  that compiles against `dist/shakti.cyr` with only the declared
  stdlib surface and exercises `validate_username`, `parse_policy`,
  `command_matches`, and `is_unsafe_env`. Wired into
  `tests/integration/cli.sh` so a stale bundle becomes a test
  failure. Regenerate with `cyrius distlib` and re-run.
- **`docs/guides/integration.md`** — consumer-facing guide covering
  both the bundle and piecemeal module patterns, dependency ordering,
  public API surface table, default paths, bundle-regeneration, and
  cyrius version floor.
- **README** — updated "Consumer API" section to point at both
  `dist/shakti.cyr` and individual modules; added ark as the fourth
  consumer alongside argonaut / agnoshi / daimon.

### Security

- **Supplementary groups regression closed**: `_exec_target` no
  longer calls `setgroups(0, NULL)` before dropping privileges.
  It now populates the target user's supplementary group list via
  `identity_lookup_gids` (initgroups(3) parity using `/etc/group`),
  matching the rust-old build with the `pam` feature disabled.
  LDAP/sssd resolution is still a known gap and remains tracked
  for the NSS-via-libc bite.

## [0.2.0] - 2026-04-17

### Changed

- **Language port**: reimplemented in [Cyrius](https://github.com/MacCracken/cyrius)
  (pinned to 5.2.1). The original Rust implementation is preserved in
  `rust-old/` for reference. Binary size dropped from ~1.8 MB (Rust release,
  dynamic libc + PAM) to 410 KB (static, no runtime).
- Project layout adopts patra flatten style: vendored stdlib in `lib/`,
  module-per-file in `src/`, tests in `tests/tcyr/`, benches in `tests/bcyr/`.
- `cyrius.cyml` replaces `Cargo.toml` as the build manifest.
- Error handling: anyhow::Result → integer `SHK_ERR_*` codes with
  `shk_err_msg()` for human-readable messages.
- Structs: serde-derive → manual offset enums + `store64`/`load64`
  accessors (`PolicyOff`, `DefOff`, `RuleOff`, `CfgOff`, `EvalOff`,
  `AuthzOff`, etc.).
- `AuthzResult` + `Evaluation` expose error codes and boolean fields
  rather than Rust enums / `#[non_exhaustive]` wrappers.
- Test suite grew from 130 to 219 cases across 8 `.tcyr` files.

### Added

- Benchmarks (`tests/bcyr/core.bcyr`) for the hot paths: command_matches
  (4 variants), validate_command, parse_policy, check_authorization
  (3 variants), sanitize_environment.
- `scripts/bench-history.sh` rewritten for cyrius bench output format.
- Local mini-TOML parser in `src/policy.cyr` — the stdlib parser only
  recognises `[[array]]` sections, but shakti's schema uses `[defaults]`.
- README expanded with architecture map and consumer-integration guidance.

### Removed

- `Cargo.toml`, `Cargo.lock`, `deny.toml`, `rust-toolchain.toml` (Rust
  tooling; see `rust-old/` if needed).
- `src/*.rs` (moved into `rust-old/` by `cyrius port`).
- Rust-only dependencies: anyhow, serde, toml, tracing, tracing-journald,
  nix, zeroize, pam, criterion.

### Security

- Preserved: O_NOFOLLOW timestamp open, per-TTY isolation, root-ownership
  checks on policy files / timestamps / include fragments, LD_*
  prefix catch-all, BASH_FUNC_* prefix catch-all, shell-metacharacter
  rejection in command names, path-traversal rejection in usernames,
  argument-level wildcard matching.
- **PAM**: the Rust `pam` crate integration is stubbed in `src/auth.cyr`
  pending a libpam binding via `dynlib.cyr`. All authentication currently
  falls through to the `/usr/bin/su` shim — same security posture as the
  Rust build with the `pam` feature disabled.
- **NSS group resolution**: the Rust `getgrouplist(3)` call is replaced
  with direct parsing of `/etc/group`. This regresses LDAP/sssd support
  that was added in 0.1.x; restoring it will require a libnss binding.
  File this as a known gap for consumers using remote identity stores.
- **initgroups**: the target process's supplementary groups are cleared
  via `setgroups(0, NULL)` rather than populated. `setgid`/`setuid` still
  set the primary GID/UID correctly, but callers who rely on supplementary
  group membership of the target user will see different behaviour than
  the Rust build.

---

The remainder of 0.2.0's scope was landed in Rust before the port and
is preserved verbatim from the pre-port changelog:

### Added

- Argument-level wildcard matching in policy patterns (e.g., `/usr/bin/systemctl restart *`)
- `BASH_FUNC_*` prefix block in env sanitization (ShellShock defense)
- 8 additional unsafe env vars: `GEM_HOME`, `GEM_PATH`, `BUNDLE_GEMFILE`, `LUA_PATH`, `LUA_CPATH`, `PHPRC`, `PERL_MM_OPT`, `INPUTRC`
- `#[non_exhaustive]` on `Evaluation` struct
- `--check` / `-c` CLI flag for policy linting (detects unreachable rules, dangerous wildcards, duplicate rules, missing user/group)
- `lint_policy()` function in library API for programmatic policy validation
- `cargo-fuzz` harnesses for `parse_policy`, `validate_command`, `command_matches`, `validate_username`
- 53 new tests (130 total, up from 77) covering security-critical paths
- Architecture documentation (`docs/architecture/overview.md`)
- 4 ADRs: O_NOFOLLOW timestamps, initgroups, argument matching, env sanitization strategy
- Dependency watch tracking (`docs/development/dependency-watch.md`)
- Root glob pattern fix: `/*` now correctly matches binaries in `/`

### Changed

- Group resolution now uses `getgrouplist(3)` via NSS instead of parsing `/etc/group` directly
- Supplementary group setup uses `initgroups(3)` instead of single-GID `setgroups`
- `command_matches` now extracts the binary portion for path-level matching when commands include arguments
- Bench history script rewritten to correctly parse criterion output format

### Security

- **Authorization bypass (critical)**: `check_authorization` now receives the full command string with arguments, not just the binary path. Previously, `deny_commands` patterns with arguments (e.g., `/usr/bin/systemctl stop firewall`) were completely ineffective at runtime.
- **Timestamp TOCTOU**: `update_timestamp` now uses `O_NOFOLLOW | O_CREAT | O_TRUNC` via `nix::fcntl::open()`, eliminating the race window between the symlink check and the file write.
- **Supplementary groups**: Target process now inherits the target user's full supplementary group list via `initgroups(3)`, not just the primary GID. Missing groups could have caused privilege inconsistencies.
- **Group resolution**: Caller's group membership is now queried via NSS (`getgrouplist`), supporting LDAP/sssd environments. Previously only `/etc/group` was read.
- **ShellShock**: Environment variables matching `BASH_FUNC_*` are now blocked by prefix, preventing exported bash function injection.
- **Interpreter injection**: Added `GEM_HOME`, `GEM_PATH`, `BUNDLE_GEMFILE` (Ruby), `LUA_PATH`, `LUA_CPATH` (Lua), `PHPRC` (PHP), `PERL_MM_OPT` (Perl), `INPUTRC` (readline) to the blocked env var list.
- **Non-UTF8 paths**: Command resolution now returns an explicit error for non-UTF8 paths instead of silently passing an empty string to authorization.

### Added

- Real PAM authentication via `pam` crate (feature-gated, `--features pam`)
- `auth` module with `authenticate()`, `pam_authenticate()`, `su_authenticate()`
- PAM falls back to `/usr/bin/su` shim when PAM service is unavailable
- PAM service config example (`etc/pam.d/shakti`)
- `audit` module with structured journald logging via `tracing-journald`
- `AuditAction` enum for typed audit events (`Command`, `AuthFailure`, `TimestampInvalidated`)
- `init_tracing()` — unified tracing setup with journald + stderr layers
- Policy fragment support via `include_dir` in `[defaults]`
- Fragment files (`*.toml`) loaded in lexicographic order with security checks
- Secure memory clearing of password buffers via `zeroize` crate
- Consumer API module (`api.rs`) with `ShaktiConfig`, `Evaluation`, `AuthMode`
- `ShaktiConfig::builder()` for ergonomic programmatic configuration
- `evaluate()` / `evaluate_with_policy()` — high-level entry points for consumers
- `AuthMode::Interactive` / `TimestampOnly` / `Skip` for different consumer needs
- Non-interactive auth path for daimon (agent operations via `AuthMode::TimestampOnly`)
- Module structure: split into `policy`, `env`, `timestamp`, `validate`, `api` modules
- Library crate (`lib.rs`) alongside binary for consumer and benchmark access
- Criterion benchmarks for all hot paths (`benches/core.rs`)
- Benchmark history tracking script (`scripts/bench-history.sh`)
- Roadmap (`docs/development/roadmap.md`)
- Per-TTY timestamp isolation (prevents cross-session credential reuse)
- Timestamp file ownership verification (must be root-owned)
- Timestamp symlink detection and rejection
- Timestamp directory permissions (0700 root-only)
- Secure password input via termios echo disable with RAII drop guard
- Signal masking (SIGINT/SIGTSTP/SIGQUIT) during authentication phase
- File descriptor sanitization (close fds > stderr before exec)
- Username path-traversal validation in timestamp operations
- Shell metacharacter rejection in command names
- `is_executable` check in command resolution (was `exists()`)
- LD_* prefix catch-all in environment sanitization
- 17 interpreter injection env vars (PYTHONPATH, NODE_OPTIONS, etc.)
- 5 additional LD_* variables to explicit blocklist
- `#[non_exhaustive]` on `AuthzResult` enum
- `#[must_use]` on pure functions

### Changed

- Rebranded from `agnos-sudo` to `shakti` in all user-facing strings
- Policy file non-root ownership is now a hard failure (was a warning)
- `update_timestamp` errors are now logged (was silently ignored)
- Cleaned unused license allowances from `deny.toml`

### Security

- **Timestamp tampering**: Files are now verified for root ownership and symlink attacks
- **Terminal echo**: Passwords are no longer visible during input
- **Signal safety**: Auth phase cannot be interrupted by SIGINT leaving partial state
- **fd leaking**: Child processes no longer inherit open file descriptors
- **Environment**: All LD_* variables blocked by prefix, not just an explicit list
- **Interpreter injection**: PYTHONPATH, NODE_OPTIONS, PERL5LIB, etc. now blocked
- **Path traversal**: Usernames with `/`, `..`, null bytes rejected in timestamp paths
- **Shell injection**: Command names with `;`, `|`, `$()`, etc. now rejected
- **Command resolution**: Non-executable files and directories no longer accepted

## [0.1.0] - 2026-04-03

### Added

- Initial extraction from AGNOS monolith (`userland/agnos-sudo/`)
- PAM authentication with rate limiting (max 3 attempts)
- TOML-based policy file (`/etc/agnos/sudoers.toml`)
- Per-user, per-group, and per-command rules
- Environment sanitization (LD_*, IFS, BASH_ENV, etc.)
- Command argument validation against shell injection
- Timestamp-based credential caching (configurable TTL)
- Audit logging of all authentication attempts
- 44 tests
