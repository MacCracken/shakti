# ADR-010: NSS Group Dispatch via the Trusted fdlopen Helper

## Status

Accepted (2026-06-16) — amends [ADR-005](005-identity-backend-port-to-cyrius.md).

## Context

ADR-005 shipped a local `/etc/passwd` + `/etc/group` identity backend for
the Cyrius port and deliberately shaped the public API
(`identity_lookup_groups`, `identity_lookup_gids`, …) so it could be
re-implemented over real NSS "once cyrius ships the NSS dispatch
bootstrap." LDAP/sssd group membership has been a known gap ever since.

The blocker was specifically a **setuid-safety** one, not a missing
mechanism. cyrius gained foreign-`dlopen` (`fdlopen`, v5.5.28) and NSS
worked through it — but `fdlopen` resolved its helper binary inside the
**invoking user's** `$HOME` (`~/.cyrius/dlopen-helper`). shakti runs
setuid-root: an unprivileged caller `mallory` would have shakti `execve`
`/home/mallory/.cyrius/dlopen-helper` **as root, before authenticating
anyone** — arbitrary root code execution. shakti therefore could not
touch any `fdlopen`-backed path at all, and filed the upstream proposal
`2026-06-02-fdlopen-helper-trust-for-setuid-consumers.md`.

That proposal **shipped in cyrius v6.1.29** and is on shakti's pin as of
0.6.3 (6.2.11). `fdlopen_init_trusted()`:

- resolves the **root-owned system** helper `/usr/lib/cyrius/dlopen-helper`
  (installed by cyrius's `install.sh` when run as root),
- `lstat`-verifies it (regular file, `uid == 0`, **not** a symlink, **not**
  group/other-writable),
- **never** consults the `$HOME` copy, and
- **fails closed** with `FDL_ERR_UNTRUSTED` (`-9`) when no trusted helper
  is present.

This removes the exact hazard ADR-005 was waiting on. NSS group dispatch
is now buildable.

## Decision

Implement a real-NSS group path behind the unchanged ADR-005 signatures,
**off by default** and activated per-deployment.

1. **Opt-in policy flag.** A new `[defaults]` boolean `nss_groups`
   (default `false`). When false — the default — behaviour is byte-for-byte
   the local-files backend of ADR-005. No `fdlopen` path is reached, and
   no helper need exist. An admin who runs LDAP/sssd sets
   `nss_groups = true`.

2. **Both membership *and* names via NSS.** When enabled,
   `identity_lookup_gids` resolves membership through libc
   `getgrouplist(3)` and `identity_lookup_groups` resolves each GID's name
   through `getgrgid_r(3)` — so a policy rule naming an LDAP-only group
   (no local `/etc/group` entry) matches correctly. Resolving GIDs via NSS
   but names via files would silently fail to match such rules. The
   *primary*-GID input to `getgrouplist` is still read from the local
   `/etc/passwd` parser (ADR-005); `getgrouplist` returns the full NSS
   supplementary set regardless, so a bogus/absent primary only affects
   the primary entry, never the LDAP/sssd membership. passwd-side NSS
   (`getpwnam_r`) is a separate follow-on, not part of this ADR.

3. **Trusted bootstrap only.** The NSS path calls `fdlopen_init_trusted`
   exclusively. It is initialised **once per process, lazily** (first
   group lookup with the flag on), `dlopen`s `libc.so.6` once, and caches
   the resolved `getgrouplist` / `getgrgid_r` function pointers. The
   bootstrap runs in the already-sanitised environment (ADR-004), as root,
   in the same pre-drop trust window as PAM auth (ADR-006).

4. **Fail-safe fallback to files.** Any non-OK return from the trusted
   bootstrap — no system helper (`-9`), non-x86_64/non-Linux (`-6`), or a
   transient init error — falls back to the existing `/etc/group` parser.
   This is safe for a *privilege* decision: the files backend can only
   return a **subset** of a user's NSS groups, so a fallback can only
   *deny* an escalation, never grant one that NSS wouldn't. The fallback
   is to the **files parser**, never to the untrusted `$HOME` helper
   (`init_trusted` structurally forbids the latter).

5. **Wiring via a process-global toggle, signatures unchanged.**
   `src/identity.cyr` carries a module-level `nss_groups` switch set by
   `identity_set_nss_groups(enabled)`. `src/main.cyr` calls it once after
   loading policy, passing `def_nss_groups(defaults)`. The public lookup
   signatures from ADR-005 are untouched — consumers that look groups up
   themselves (per the integration guide) keep working with no source
   change, and may opt in via the same setter. This mirrors the
   module-global pattern `fdlopen` itself uses for `_fdl_trusted_mode`.

## Consequences

- **Positive**: closes the LDAP/sssd membership gap that has stood since
  0.2.0; advances the v1.0 criterion ("NSS … unblocked and shipped *or*
  explicitly descoped").
- **Positive**: default-off keeps the shipped posture a static-files,
  no-foreign-code binary. The root `fdlopen` path does not exist for any
  deployment until an admin asks for it.
- **Positive**: fallback is monotonic-safe — it can only shrink the group
  set, so it never broadens privilege.
- **Negative**: when enabled, shakti `dlopen`s `libc.so.6` (and,
  transitively, NSS modules such as `nss_ldap`/`nss_sss`) **as root**.
  This is the same trust model `sudo` operates under, and is gated by
  (a) the opt-in flag, (b) `init_trusted`'s root-owned/non-writable/
  non-symlink helper check, and (c) the sanitised environment. A new
  threat-model entry (T12) records it.
- **Negative**: enabling adds a deployment dependency — the root-owned
  `/usr/lib/cyrius/dlopen-helper` must be installed (cyrius `install.sh`
  as root). Its absence is not fatal: the path fails closed to the files
  fallback, and the condition is audit-logged.
- **Negative**: NSS dispatch is x86_64-Linux only (the `fdlopen`
  constraint). aarch64 and the AGNOS kernel fall back to files; real NSS
  there is folded into the 0.8.x AGNOS-kernel milestone.

## Security notes

- `init_trusted` is called, never `fdlopen_init` / `fdlopen_init_full` —
  the `$HOME` helper is never a candidate, by construction.
- The bootstrap is gated behind the `nss_groups` flag, so a default
  install presents **zero** new attack surface relative to 0.6.3.
- The backend-selection outcome is audit-logged **once at startup** under
  a dedicated `NSS_BACKEND` action — `success=1` when the trusted helper
  bootstraps (NSS ready), `success=0` when it was requested but
  unavailable (fell back to files). Logged only when `nss_groups` is
  requested, so a default install emits nothing new. One event per
  invocation rather than per-lookup keeps the trail readable while still
  recording every privilege-relevant backend decision.

## Cyrius dependency chain (continues ADR-005)

- v5.5.28 — `fdlopen` primitives (setjmp/longjmp, helper exec).
- v5.5.34 — `fdlopen_init_full` end-to-end (`dlopen`/`dlsym` callable).
- **v6.1.29 — `fdlopen_init_trusted`**: root-owned system helper +
  ownership/mode/non-symlink enforcement; fails closed. The piece this
  ADR depends on. On shakti's pin via 0.6.3 (cyrius 6.2.11).
