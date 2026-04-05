# ADR-001: Use O_NOFOLLOW for Timestamp Updates

## Status

Accepted (2026-04-04)

## Context

The `update_timestamp` function creates or updates a file to record when a user last authenticated. The original implementation checked for symlinks with `is_symlink()` and then wrote the file with `fs::write()`. This created a TOCTOU (time-of-check-to-time-of-use) race: an attacker could create a symlink between the check and the write, redirecting the write to an arbitrary file owned by root.

## Decision

Replace the check-then-write pattern with a single `open()` call using `O_NOFOLLOW | O_CREAT | O_WRONLY | O_TRUNC`. This atomically rejects symlinks at the kernel level, eliminating the race window entirely.

## Consequences

- **Positive**: No TOCTOU window. The kernel enforces symlink rejection atomically.
- **Positive**: Fewer syscalls (one open vs stat + write + chmod).
- **Negative**: Requires the `fs` feature flag for the `nix` crate (minimal dependency increase).
- **Negative**: Non-Linux platforms fall back to the original `fs::write` behavior (no `O_NOFOLLOW` equivalent in std). This is acceptable since Shakti targets Linux.
