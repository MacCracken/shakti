# Changelog

All notable changes to Shakti will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
