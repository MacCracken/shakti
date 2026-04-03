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

## Future (v0.2+)

- Real PAM integration via `pam-client` or direct `libpam` FFI
- Session logging / I/O recording
- Syslog/journald audit backend
- Policy include files and directory-based policy fragments
- TOML policy linting tool
- Secure memory clearing for password buffers
- Capability-based privilege (CAP_* instead of full root)
- SELinux/AppArmor context transitions
- Remote policy fetch (for fleet management)

## v1.0 Criteria

- All backlog items complete
- Real PAM integration (not `/usr/bin/su` shim)
- Full test coverage of all security-critical paths
- Fuzz testing on policy parser and command validation
- Security audit by at least one external reviewer
- Documentation complete (architecture, usage guide, ADRs)
- All three consumers (argonaut, agnoshi, daimon) integrated and tested
