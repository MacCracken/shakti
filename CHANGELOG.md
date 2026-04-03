# Changelog

All notable changes to Shakti will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
