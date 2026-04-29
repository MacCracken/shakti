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

## Cyrius port regressions (close before v1.0)

Tracked here to keep them visible against the v1.0 criteria below.
Each is a feature present in the Rust 0.1.x build that did not survive
the port to Cyrius in 0.2.0. Toolchain now pinned to Cyrius 5.7.33.

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
- [ ] Real PAM authentication — replaces the `/usr/bin/su` fallback
      in `src/auth.cyr`. cyrius v5.5.27 shipped
      `lib/pam.cyr::pam_unix_authenticate` (forks Linux-PAM's
      `unix_chkpwd` setuid helper). Migration is tractable feature
      work; unblocked from cyrius's side. Consumes the same
      threat-model review as bite 2b below if we want LDAP/sssd
      coverage on auth too.

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

## Next up (queued for 0.3.1, paused)

**Capability-based privilege (CAP_* instead of full root)** —
parked at the start of 0.3.1 on 2026-04-28 to be resumed in a
fresh session. Drop to a per-rule capability set at exec instead
of uid=0; uses `prctl(PR_CAPBSET_DROP, …)` + `capset(2)` direct
syscalls. No fdlopen dependency.

When resuming, the open design questions are:

- **Policy schema extension**: where does the capability set
  live? Per-rule (`capabilities = ["CAP_NET_BIND_SERVICE", …]`)
  is the obvious shape. New field is non-breaking — rules
  without it fall back to today's full-uid drop.
- **Compatibility default**: a rule with no `capabilities`
  field must keep working exactly as today (full-uid drop). The
  cap-drop path is opt-in per rule.
- **Capability name → bit mapping**: hand-rolled table in
  shakti vs reaching for a stdlib lookup. Linux capability
  names are stable; embed the table in `src/main.cyr` or split
  into `src/caps.cyr`.
- **Audit log shape**: emit the dropped cap set in
  `audit_log` so postmortem/forensics can see what the target
  ran with. Extends the existing audit format.
- **Test coverage**: verify cap drop via `/proc/self/status`
  CapBnd / CapEff lines after a synthetic exec (or via a
  dedicated test binary that prints its caps). Distro-portable.

Pre-flight before opening 0.3.1:

1. Confirm cyrius pin is current (we shipped 5.7.33 in 0.2.3).
2. Re-read `src/main.cyr:_exec_target` — the cap-drop must
   happen between `setuid` and `execve`, after the
   getuid/getgid post-condition checks. Order matters.
3. Sanity-check `prctl` / `capset` syscall numbers in
   `lib/syscalls_x86_64_linux.cyr` (or define locally if
   absent, like `SYS_LSTAT` in `timestamp.cyr`).

## Future (v0.3+)

Larger features that are NOT blocked on cyrius. Pick up in the
order consumers demand them.

- Session logging / I/O recording (openpty-based) — direct Linux
  syscalls; no fdlopen dependency.
- SELinux / AppArmor context transitions
  (`/proc/self/attr/exec`, feature-gated by distro). Direct file
  write; no fdlopen dependency.

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
      Rust 0.1.x; regressed in 0.2.0 cyrius port. Revisit at cyrius
      5.5.x when the NSS dispatch bootstrap lands (port-regressions
      section tracks the block).
- [x] Full test coverage of all security-critical paths (252 `.tcyr`
      unit assertions in 0.2.x, up from 130 in Rust 0.1.x; +20,101
      property-fuzz assertions per run)
- [x] Fuzz testing on policy parser and command validation
      (`tests/tcyr/fuzz.tcyr` — 4 targets, non-coverage-guided
      xorshift64 + invariant assertions, 2500 iters per target)
- [ ] Security audit by at least one external reviewer
- [x] Documentation complete (architecture, usage guide, 5 ADRs)
- [ ] All three consumers (argonaut, agnoshi, daimon) integrated and tested
