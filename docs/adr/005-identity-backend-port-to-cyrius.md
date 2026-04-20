# ADR-005: Identity Backend on the Cyrius Port

## Status

Accepted (2026-04-19)

## Context

The Rust 0.1.x build used libc `getgrouplist(3)` via `nix::unistd` for
group-membership queries, with `initgroups(3)` setting supplementary
groups before privilege drop (see ADR-002). That path honoured NSS, so
LDAP, sssd, and any other NSS source were picked up automatically.

The Cyrius 0.2.0 port could not carry that over. Cyrius's stdlib has no
libc binding; the dynamic-loader hook (`lib/dynlib.cyr`) can `dlopen`
`libc.so.6` and resolve symbols, but functions that dispatch through
NSS (`getgrouplist`, `getpwent`, `getaddrinfo`) crash inside
`/etc/nsswitch.conf` parsing and NSS-module `dlopen`.

A subprocess fallback (e.g. `getent initgroups`) was considered and
rejected — the AGNOS-wide policy is to fix the dynlib path in cyrius
so every downstream consumer benefits, not just shakti.

## Decision

Use a local `/etc/passwd` + `/etc/group` backend in `src/identity.cyr`
for the 0.2.x line. Public API (`identity_lookup_uid`,
`identity_lookup_user`, `identity_lookup_groups`,
`identity_lookup_gids`) is shaped so it can be re-implemented as an
NSS-over-dynlib backend behind the same signatures once cyrius ships
the NSS dispatch bootstrap.

`_exec_target` calls `identity_lookup_gids` before `setgroups` →
`setgid` → `setuid`, restoring initgroups(3) parity against /etc/group.
LDAP/sssd membership is a known gap; remote-identity deployments must
wait for the NSS backend.

## Consequences

- **Positive**: closes the 0.2.0 regression where `setgroups(0, NULL)`
  ran before privilege drop (supplementary groups were cleared entirely).
- **Positive**: no dependency on a stable libc ABI — static binary keeps
  its ~400 KB footprint.
- **Positive**: unit-testable without mocking libc — identity.tcyr
  exercises the parser directly.
- **Negative**: LDAP/sssd environments see local-files-only membership.
  Tracked on the roadmap as "NSS group resolution via libc".
- **Negative**: real PAM authentication (also NSS-dependent transitively)
  remains unavailable; auth falls through to the `/usr/bin/su` shim.

## Cyrius dependency chain

Tracked here rather than in the stale memory blob that originally
pointed at cyrius 5.3.1:

- v5.3.7 — `dynlib_init` + IRELATIVE/DT_INIT machinery
- v5.3.8 — `dynlib_bootstrap_cpu_features()` (IRELATIVE unblock)
- v5.3.9 — `dynlib_bootstrap_tls()` + `_stack_end` (simple libc calls work)
- v5.3.11 — IFUNC-aware `dynlib_sym` (string/mem functions work)
- v5.3.14 — bounds-checked indirect calls; safety gates tightened
- **v5.5.x (cyrius roadmap)** — locale init (`__ctype_init`), malloc
  arena setup, NSS module table population. Bite 2 (NSS) and bite 3
  (real PAM) resume when this lands; smoke-probe `getgrouplist` via
  `dynlib` first to confirm the fix before committing.
