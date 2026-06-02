# Shakti Roadmap

## Completed

- [x] Extract from AGNOS monolith as standalone crate
- [x] TOML-based policy engine (per-user, per-group, per-command rules)
- [x] Environment sanitization (LD_*, shell injection vars, interpreter vars)
- [x] Command validation (null bytes, length, shell metacharacters)
- [x] Timestamp-based credential caching
- [x] Audit logging (tracing + file-based)
- [x] Scaffold hardening (P-1): lib/bin split, 55 tests, criterion benchmarks
- [x] Username path-traversal prevention
- [x] LD_* prefix catch-all in env sanitization
- [x] `#[non_exhaustive]` / `#[must_use]` compliance
- [x] Module restructure: `policy`, `env`, `timestamp`, `validate`
- [x] Timestamp hardening: permissions, ownership, symlink rejection, per-TTY isolation
- [x] Secure password input: termios echo disable with RAII drop guard
- [x] Signal handling: mask SIGINT/SIGTSTP/SIGQUIT during auth, restore before exec
- [x] fd sanitization: close fds > stderr before exec

- [x] Consumer library API: `ShaktiConfig`, `Evaluation`, `AuthMode`, `evaluate()`
- [x] Non-interactive auth: `AuthMode::TimestampOnly` for daimon, `AuthMode::Skip` for pre-authenticated

## Backlog (v0.1.x)

*All v0.1.x backlog items complete.*

## Completed (v0.2)

- [x] Real PAM integration via `pam` crate (feature-gated, falls back to su shim)
- [x] Syslog/journald audit backend via `tracing-journald`
- [x] Policy include files and directory-based policy fragments (`include_dir`)
- [x] Secure memory clearing for password buffers (`zeroize`)
- [x] P(-1) hardening: authorization bypass fix (full command string), timestamp TOCTOU fix (O_NOFOLLOW)
- [x] P(-1) hardening: argument-level wildcard matching in policy patterns
- [x] P(-1) hardening: NSS-aware group resolution (getgrouplist), initgroups for target user
- [x] P(-1) hardening: expanded env sanitization (BASH_FUNC_*, Ruby/Lua/PHP/Perl injection vars)
- [x] Fuzz testing: cargo-fuzz harnesses for parse_policy, validate_command, command_matches, validate_username
- [x] TOML policy linting tool (`--check` flag and `lint_policy()` API)
- [x] Security-critical test coverage: 130 tests (up from 77)
- [x] Architecture documentation, 4 ADRs, dependency watch tracking

## Completed (v0.4)

- [x] Cyrius toolchain pin 5.7.33 → 6.0.3 (cybs/cycc rename ceremony; no
      breaking language change)
- [x] `cyrius.cyml` `modules` moved `[build]` → `[lib]` — clean build, no
      duplicate-fn warnings
- [x] sakshi 2.2.5 adopted for structured, level-filterable audit logging
      (`init_tracing` / `audit_log`); durable file trail unchanged
- [x] CI/release toolchain install via upstream `scripts/install.sh`
      (matches patra/sigil); stdlib un-vendored (`lib/` now `cyrius deps`-
      populated + gitignored)
- [x] `scripts/version-bump.sh` for version-surface lockstep; `cyrius.lock`
      committed

## Completed (v0.5)

- [x] Real PAM authentication via `unix_chkpwd(8)` (ADR-006); `/usr/bin/su`
      demoted to helper-missing fallback
- [x] Capability-based privilege — per-rule `capabilities = [...]` drops
      the target to a chosen `CAP_*` set instead of full root (ADR-007).
      `src/caps.cyr` (name↔bit table, capset/prctl plumbing); bounding-set
      drop → KEEPCAPS → uid drop → capset → ambient raise in
      `_exec_target`. Opt-in, non-breaking; audited as `CAPS=`. Live drop
      verified by `tests/integration/caps_drop.sh` (unprivileged userns +
      root tiers).

## Completed (v0.5.1)

- [x] Session logging / I/O recording (ADR-008) — per-rule
      `log_session` records a PTY transcript of the session.
      `src/session.cyr` (PTY alloc, raw termios, `poll` relay, log
      writer); exec path forks into a relay parent + privilege-dropping
      child when enabled, unchanged direct `execve` when off. Transcripts
      are root-owned `0600` under `session_log_dir`, fail-closed. Verified
      by `tests/integration/session_log.sh` (unprivileged relay probe +
      root full-path tier).

## Completed (v0.6.0)

- [x] SELinux / AppArmor exec-context transitions (ADR-009) — per-rule
      `selinux_context` / `apparmor_profile` write the kernel's
      `/proc/self/attr/exec` (and `…/apparmor/exec`) just before
      `execve`, on both the direct and session-logged paths. `src/lsm.cyr`;
      direct `/proc` writes, no libselinux/libapparmor dependency. Strict
      fail-closed; audited as `LSM=`. Verified by
      `tests/integration/lsm_ctx.sh` (fail-closed signal on a no-LSM host;
      real enforcement gated to an LSM CI job).

## Cyrius port regressions (close before v1.0)

Tracked here to keep them visible against the v1.0 criteria below.
Each is a feature present in the Rust 0.1.x build that did not survive
the port to Cyrius in 0.2.0. Toolchain now pinned to Cyrius 6.0.31.

- [x] `initgroups` parity — populate target user's supplementary
      groups before privilege drop instead of `setgroups(0, NULL)`
      (closed via `src/identity.cyr` / `identity_lookup_gids`).
- [~] NSS group resolution — **partial as of 0.2.3 (bite 2a)**.
      `identity_lookup_groups` / `identity_lookup_gids` now delegate
      to `lib/grp.cyr`'s shared `/etc/group` reader (cyrius v5.5.26+).
      Drops ~80 LOC of bespoke field walking; primary group now
      included in `identity_lookup_groups` to match `getgrouplist(3)`.
      **Does NOT restore LDAP/sssd** — the cyrius reader is a musl-
      style `/etc/group` parser that bypasses NSS entirely, same as
      the code it replaced. Real NSS dispatch is bite 2b, blocked
      below.
- [x] Real PAM authentication — `src/auth.cyr::pam_authenticate` now
      forks Linux-PAM's `unix_chkpwd` setuid helper via
      `lib/pam.cyr::pam_unix_authenticate` (shipped cyrius v5.5.27).
      The `/usr/bin/su` shim is demoted to the helper-missing
      degradation path only. Because `unix_chkpwd` does a normal glibc
      lookup on the root side, the **auth** path now honours LDAP/sssd
      automatically — closing the auth-side NSS gap without touching the
      blocked `fdlopen` path. See
      [ADR-006](../adr/006-pam-auth-via-unix-chkpwd.md). Group-side NSS
      (bite 2b) remains blocked below.

## Blocked (later)

- **Real NSS dispatch (bite 2b — restore LDAP/sssd).**
  Path B from cyrius v5.5.34 (`lib/fdlopen.cyr::fdlopen_init_full`)
  is the only way to call libc `getgrouplist(3)` with full NSS
  resolution from a static cyrius binary. Blocked on a
  **setuid-safe helper-trust model** — cyrius's `dlopen-helper`
  ships at `~/.cyrius/dlopen-helper` (in the invoking user's
  `$HOME`), which a non-root caller can replace and we'd execute
  with root privileges before authentication. Closing this needs:
  (1) a root-owned system path for the helper
  (e.g. `/usr/lib/cyrius/dlopen-helper`), enforced via mode +
  ownership + non-symlink check, and (2) integrity verification
  (hash-pin or signature). Should land as an ADR before any code.
- **Remote policy fetch (fleet management).** Same blocker —
  `lib/tls.cyr` migrated to `fdlopen` at cyrius v5.6.37 for the
  `SSL_connect` deadlock fix, so any HTTPS path inherits the
  helper-trust requirement above. Defer until bite 2b's threat
  model is settled.

## Future (v0.3+)

Larger features that are NOT blocked on cyrius. Pick up in the
order consumers demand them.

- Session logging keystroke (input) capture — v1 (0.5.1) records the
  output stream only; input capture needs a redaction design for typed
  secrets before it ships.
- Live `SIGWINCH` window-resize propagation during a logged session —
  0.5.1 copies the window size at session start only.
- LSM-aware auto-selection for exec contexts — 0.6.0 applies exactly the
  `selinux_context` / `apparmor_profile` fields set (strict fail-closed);
  reading `/sys/kernel/security/lsm` to apply only the active LSM's field
  would let one policy serve a mixed-LSM fleet.

## Audit deferrals

Finer-grained items from the 2026-04-20 internal review
(see [`../audit/2026-04-20-internal-review.md`](../audit/2026-04-20-internal-review.md)).
H-1 / H-2 / M-1 / M-2 / I-1 shipped in 0.2.2.

- [x] **L-1** — `update_timestamp` differentiates `-ELOOP` (true
      symlink reject) from generic open(2) errors. Closed in 0.2.3.
- [ ] **L-2** — env-read buffer leak on grow. Blocked on `free()`
      in shakti's bump allocator; would need switch to
      `lib/freelist.cyr` or pre-size via `stat(2)`. Not security-
      relevant for single-shot CLI; affects long-running library
      consumers (daimon).
- [x] **L-3** — defensive `if (alloc == 0)` guards across 11
      alloc sites in `src/auth.cyr` + `src/env.cyr`. Closed in
      0.3.0. OOM is still a terminal state for shakti, but the
      abort now happens via documented error paths rather than
      SIGSEGV.

## v1.0 Criteria

Milestone-ever-hit checklist. Items marked [x] have a shipped
implementation *somewhere* in the project history; the port-
regressions section above tracks any that regressed in 0.2.0 and
need reshipping before v1.0 cuts. Do not uncheck a criterion here
when a regression lands — the port-regressions section is the
single source of truth for "not currently shipping".

- [x] All backlog items complete
- [x] Real PAM integration (not `/usr/bin/su` shim) — shipped in
      Rust 0.1.x; regressed in 0.2.0 cyrius port; **reshipped in 0.4.x**
      via `unix_chkpwd` (ADR-006). su is now the helper-missing
      degradation path only.
- [x] Full test coverage of all security-critical paths (252 `.tcyr`
      unit assertions in 0.2.x, up from 130 in Rust 0.1.x; +20,101
      property-fuzz assertions per run)
- [x] Fuzz testing on policy parser and command validation
      (`tests/tcyr/fuzz.tcyr` — 4 targets, non-coverage-guided
      xorshift64 + invariant assertions, 2500 iters per target)
- [ ] Security audit by at least one external reviewer
- [x] Documentation complete (architecture, usage guide, 5 ADRs)
- [ ] All three consumers (argonaut, agnoshi, daimon) integrated and tested
