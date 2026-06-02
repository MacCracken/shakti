# ADR-006: Real PAM Authentication via unix_chkpwd(8)

## Status

Accepted (2026-06-01)

Supersedes the "auth falls through to the `/usr/bin/su` shim" consequence
recorded in [ADR-005](005-identity-backend-port-to-cyrius.md) (§Consequences).

## Context

The Rust 0.1.x build authenticated through the `pam` crate. The Cyrius
0.2.0 port could not carry that over (no libc/PAM binding in stdlib) and
shipped `pam_authenticate()` as a stub that always reported unavailable,
so every authentication fell through to a `/usr/bin/su -c true <user>`
shim. The su shim works, but it:

- depends on `/usr/bin/su` existing and behaving identically across
  distros (BusyBox `su`, util-linux `su`, and shadow `su` differ),
- spawns a full shell to run `true`, and
- is not how the rest of the platform expects password verification to
  happen (it is a workaround, not an auth backend).

Two real-PAM paths were available by cyrius 6.0.x:

1. **dlopen `libpam.so`** directly (via `lib/fdlopen.cyr`). Rejected:
   libpam's `pam_authenticate` transitively `dlopen`s NSS modules, which
   is still blocked on cyrius's **setuid-safe helper-trust model** — the
   `dlopen-helper` ships in the *invoking user's* `$HOME`, so a non-root
   caller could replace it and we would execute it as root before
   authentication (see roadmap "Blocked (later)"). Unblocking this needs
   a root-owned helper path + integrity verification and an ADR of its
   own. Same blocker as NSS group resolution (bite 2b).

2. **Fork Linux-PAM's `unix_chkpwd(8)` setuid-root helper**, shipped in
   the stdlib as `lib/pam.cyr::pam_unix_authenticate`. This is exactly
   what `pam_unix.so` itself invokes from an unprivileged process: pipe
   the password to the helper's stdin, read its exit status. The helper
   is **setuid-root and owned/shipped by the distro's pam package**, so
   it sidesteps the `$HOME` helper-trust problem entirely — there is no
   shakti-controlled binary in the trust path. Because verification runs
   inside `unix_chkpwd` with a normal glibc lookup on the root side, it
   honours **every NSS backend the system is configured for** (files,
   LDAP, SSSD, …) for the auth path.

## Decision

Implement `src/auth.cyr::pam_authenticate()` by calling
`lib/pam.cyr::pam_unix_authenticate(user, password)`, mapping its return
contract onto shakti's `authenticate()` contract:

| `pam_unix_authenticate` result        | `pam_authenticate` returns      | meaning |
|----------------------------------------|---------------------------------|---------|
| `PAM_AUTH_OK` (0)                      | `1`                             | authenticated |
| `PAM_AUTH_FAIL` (1)                    | `0`                             | rejected — no su retry |
| `PAM_AUTH_HELPER_MISSING` (−2)         | `0 - SHK_ERR_PAM_UNAVAILABLE`   | degrade to su |
| `PAM_AUTH_PIPE/FORK/EXEC_FAILED` (−3…−5)| `0 - SHK_ERR_PAM_UNAVAILABLE`   | degrade to su |

A **rejected** password (`PAM_AUTH_FAIL`) returns `0` and is *not* retried
through su — su reads the same `/etc/shadow`, so a second attempt would
only fail again while doubling the audit noise and the timing surface.

`su_authenticate` is **retained, but only as the helper-missing
degradation path**: when `unix_chkpwd` is absent (`PAM_AUTH_HELPER_MISSING`)
or unusable due to a transient pipe/fork/exec error, `authenticate()`
falls through to su exactly as before. This keeps shakti working on
minimal systems that ship no PAM helper, at the cost of su's portability
caveats on that narrow path only.

## Consequences

- **Positive**: closes the headline cyrius-port regression — real PAM
  authentication against the system password database, honouring NSS, on
  the auth path. The su shim is no longer the primary backend.
- **Positive**: no dlopen, no `fdlopen` helper-trust dependency, no NSS
  bootstrap block. Static binary footprint unchanged.
- **Positive**: the auth-side NSS gap from ADR-005 is effectively closed
  (LDAP/SSSD passwords verify through `unix_chkpwd`). The **group**-side
  NSS gap remains open — `src/identity.cyr` still parses local
  `/etc/group` (bite 2b, still blocked).
- **Negative**: fork+exec per verification (~1 ms). Acceptable for an
  interactive, one-shot auth path; noted in `lib/pam.cyr` that an inline
  SHA-512-crypt could remove the fork if a zero-fork consumer ever needs
  it.
- **Negative**: correctness now depends on the distro's `unix_chkpwd`
  being present and setuid-root. Where it is missing, behaviour silently
  degrades to the su shim (audited the same way). `pam_unix_available()`
  is exposed so consumers can detect this.
- **Operational**: the shipped `etc/pam.d/shakti` config is informational
  for `unix_chkpwd`-based auth — `unix_chkpwd` consults `pam_unix.so`'s
  `/etc/shadow` directly and does not read a per-service stack. A future
  dlopen-libpam backend (path 1, when unblocked) would make it
  load-bearing.

## Testing

`tests/tcyr/auth.tcyr` asserts the negative contract in an
environment-independent way: a bogus password never returns `1`, and
`pam_authenticate` returns either `0` (helper present, rejected) or the
`SHK_ERR_PAM_UNAVAILABLE` seam (helper missing). The positive path (a
correct password → success) needs known credentials and is left to a
root-requiring CI job, not the unit harness.
