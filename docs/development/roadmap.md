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
the port to Cyrius 5.2.1 in 0.2.0.

- [x] `initgroups` parity — populate target user's supplementary
      groups before privilege drop instead of `setgroups(0, NULL)`
      (closed via `src/identity.cyr` / `identity_lookup_gids`).
- [ ] NSS group resolution via libc `getgrouplist(3)` (restore
      LDAP/sssd support; replaces the `/etc/group` parsing path
      in `identity_lookup_groups` / `identity_lookup_gids` behind
      the same API).
      **Blocked on cyrius v5.3.1** — `dynlib_open` resolves libc
      symbols but calling NSS-using functions SIGSEGVs because
      `lib/dynlib.cyr` skips IRELATIVE relocations and init arrays
      (the CPU-features struct + libc constructors aren't run).
      Tracked in cyrius `docs/development/roadmap.md` under v5.3.1.
      Probe verified: `getpid` works, `getgrouplist` segfaults.
- [ ] Real PAM authentication via `dlopen("libpam.so.0")` and a
      conversation callback (replaces the `/usr/bin/su` fallback
      currently used unconditionally in `src/auth.cyr`).
      **Blocked on cyrius v5.3.1** — same dynlib limitation as NSS.

## Future (v0.3+)

- Session logging / I/O recording
- Capability-based privilege (CAP_* instead of full root)
- SELinux/AppArmor context transitions
- Remote policy fetch (for fleet management)

## v1.0 Criteria

- [x] All backlog items complete
- [x] Real PAM integration (not `/usr/bin/su` shim)
- [x] Full test coverage of all security-critical paths (130 tests)
- [x] Fuzz testing on policy parser and command validation (4 harnesses)
- [ ] Security audit by at least one external reviewer
- [x] Documentation complete (architecture, usage guide, ADRs)
- [ ] All three consumers (argonaut, agnoshi, daimon) integrated and tested
