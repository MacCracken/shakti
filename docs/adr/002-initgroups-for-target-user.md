# ADR-002: Use initgroups(3) for Target User Supplementary Groups

## Status

Accepted (2026-04-04)

## Context

The original implementation set supplementary groups using `setgroups(&[primary_gid])`, giving the target process only its primary group. This caused the executed command to run without the target user's supplementary groups (e.g., `docker`, `audio`, `plugdev`), leading to permission inconsistencies compared to a normal login session.

`sudo` and `su` both use `initgroups(3)` to set the full supplementary group list.

## Decision

Replace `setgroups` with `initgroups(3)` (via `nix::unistd::initgroups`), which queries NSS for the target user's complete group membership and sets all supplementary groups.

## Consequences

- **Positive**: Target process has the same group membership as a normal login. Commands that check supplementary groups (e.g., Docker socket access) work correctly.
- **Positive**: NSS-aware — works with LDAP, sssd, and other directory services, not just `/etc/group`.
- **Negative**: Requires a `CString` conversion of the target username before the `pre_exec` closure. This is done before `pre_exec` to avoid allocation in the fork child.

## Post-port note (2026-04-19)

The cyrius port (0.2.0) preserves the *decision* — `_exec_target`
populates supplementary groups before `setgid` / `setuid` — but
regressed the *implementation*. `nix::unistd::initgroups` is
unavailable without a libc binding; cyrius's `dynlib` path to
`libc.so.6:getgrouplist(3)` SIGSEGVs inside NSS module dispatch.

`src/identity.cyr:identity_lookup_gids` parses `/etc/group`
directly and calls `setgroups(ngids, &supp_gids)`. Local-files
membership is recovered; LDAP / sssd deployments see a regression
tracked as port-regression "NSS group resolution via libc
`getgrouplist(3)`" in the roadmap (revisit at cyrius 5.5.x). See
ADR-005 for the decision to adopt the local-files backend as the
0.2.x strategy.
