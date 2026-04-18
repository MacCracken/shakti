# Changelog

All notable changes to Shakti will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
