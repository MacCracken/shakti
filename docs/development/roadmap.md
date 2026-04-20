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
the port to Cyrius in 0.2.0. Toolchain now pinned to Cyrius 5.4.9.

- [x] `initgroups` parity — populate target user's supplementary
      groups before privilege drop instead of `setgroups(0, NULL)`
      (closed via `src/identity.cyr` / `identity_lookup_gids`).
- [ ] NSS group resolution via libc `getgrouplist(3)` (restore
      LDAP/sssd support; replaces the `/etc/group` parsing path
      in `identity_lookup_groups` / `identity_lookup_gids` behind
      the same API).
      **Blocked on cyrius NSS dispatch bootstrap** — as of v5.4.9,
      `lib/dynlib.cyr` handles IRELATIVE + IFUNC + DT_INIT +
      cpu_features / TLS / stack_end bootstrap (v5.3.7 → v5.3.14),
      so simple libc calls (`getpid`, `strlen`, `strcmp`, `memcmp`)
      work end-to-end. `getgrouplist` / `getpwent` / `getaddrinfo`
      still crash inside nsswitch.conf parsing and NSS-module
      dlopen because locale init, malloc arena setup, and the NSS
      module table are not yet populated. Cyrius tracks this as an
      open follow-up in its roadmap ("needs a dedicated session").
- [ ] Real PAM authentication via `dlopen("libpam.so.0")` and a
      conversation callback (replaces the `/usr/bin/su` fallback
      currently used unconditionally in `src/auth.cyr`).
      **Blocked on the same cyrius NSS dispatch bootstrap** — PAM
      loads NSS modules transitively for user lookups.

## Future (v0.3+)

Larger features deferred past the 0.2.x line while NSS/PAM remain
blocked on cyrius. Pick up in the order consumers demand them.

- Session logging / I/O recording (openpty-based).
- Capability-based privilege (CAP_* instead of full root) — drop to a
  per-rule capability set at exec instead of uid=0.
- SELinux / AppArmor context transitions
  (`/proc/self/attr/exec`, feature-gated by distro).
- Remote policy fetch (for fleet management).

## v1.0 Criteria

- [x] All backlog items complete
- [x] Real PAM integration (not `/usr/bin/su` shim)
- [x] Full test coverage of all security-critical paths (130 tests)
- [x] Fuzz testing on policy parser and command validation (4 harnesses)
- [ ] Security audit by at least one external reviewer
- [x] Documentation complete (architecture, usage guide, ADRs)
- [ ] All three consumers (argonaut, agnoshi, daimon) integrated and tested
