# Dependency Watch

Tracked dependency issues that affect Shakti. Reviewed during each P(-1) hardening cycle.

## Active

### `users` 0.8.1 (transitive via `pam` 0.7.0)

**Severity**: High (unsoundness + unmaintained)

| Advisory | Title | Severity |
|----------|-------|----------|
| [RUSTSEC-2025-0040](https://rustsec.org/advisories/RUSTSEC-2025-0040) | `root` appended to group listings | Vulnerability |
| [RUSTSEC-2023-0059](https://rustsec.org/advisories/RUSTSEC-2023-0059) | Unaligned read of `*const *const c_char` pointer | Unsoundness |
| [RUSTSEC-2023-0040](https://rustsec.org/advisories/RUSTSEC-2023-0040) | `users` crate is unmaintained | Unmaintained |

**Impact**: Shakti does not call `users` directly — it enters through `pam` 0.7.0's dependency tree. The group-listing bug (RUSTSEC-2025-0040) could cause incorrect group membership results if `pam` internally queries groups, though Shakti's own group resolution uses `nix::unistd::getgrouplist` and is unaffected.

**Mitigation path**:
1. Monitor `pam` crate for a release that drops the `users` dependency.
2. Evaluate alternative PAM bindings (`pam-client`, `pam-sys` direct usage, or `libpam-sys`).
3. If no upstream fix by v0.3, consider vendoring a minimal PAM FFI wrapper using `pam-sys` directly.

**Added**: 2026-04-04

## Resolved

(none yet)
