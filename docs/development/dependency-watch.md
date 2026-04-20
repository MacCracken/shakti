# Dependency Watch

Tracked external surfaces that affect shakti. Reviewed during each
P(-1) hardening cycle. Shakti ships as a static cyrius binary with
**no external Rust crates** — the 0.1.x entries
(`pam` 0.7.0 / `users` 0.8.1 RUSTSEC advisories) are historical and
archived at the bottom of this file for reference.

## Active

### Cyrius toolchain — 5.4.11

Shakti pins `cyrius = "5.4.11"` in `cyrius.cyml`. Upgrades are
tracked in the Changed section of the project CHANGELOG with a
per-version rundown of relevant upstream work. Two open upstream
items are load-bearing for shakti:

| Cyrius milestone | Affects shakti | Status |
|---|---|---|
| NSS dispatch bootstrap | Unblocks bite 2 (`getgrouplist` via `dlopen`) and bite 3 (real PAM via `dlopen("libpam.so.0")`). | Roadmapped for cyrius 5.5.x; smoke-probe before committing. |
| `cyrius build --strict` (v5.4.12+) | Escalates `undefined function` warnings to hard errors — would catch a category of bugs shakti's current dead-code warnings mask. | Queued. |

### Linux syscall ABI

`lib/syscalls_x86_64_linux.cyr` (auto-included via `lib/syscalls.cyr`)
supplies `SYS_OPEN`, `SYS_STAT`, `SYS_IOCTL`, etc. Shakti also
hand-declares x86_64-only syscalls the stdlib doesn't expose
(`SYS_LSTAT = 6`, `SYS_READLINK = 89`, `SYS_CLOCK_GETTIME = 228`,
`SYS_CLOSE_RANGE = 436`) in `src/timestamp.cyr` and `src/main.cyr`.

These are stable forever under Linus's "no breaking userspace" rule.
The portability gap is cross-arch: aarch64 cross-build would need
these remapped. If cross-arch support becomes a requirement, migrate
to cyrius's per-arch `SysNr` enum (v5.4.11 expanded it significantly)
or add a shakti-side arch selector mirroring cyrius's
`lib/syscalls.cyr` pattern.

### `/etc/passwd` + `/etc/group` format

`src/identity.cyr` parses both directly (colon-delimited,
newline-terminated). The format is stable back to V7 Unix. Risk
surface: any distro that stops maintaining `/etc/group` entries
(pure NSS deployments — LDAP only, no files backend). Those
deployments need the NSS-via-`dlopen` path that's blocked on cyrius
5.5.x.

### `/usr/bin/su` semantics

Auth falls through to `/usr/bin/su -c true <user>` while real PAM is
blocked. Depends on `su` behaviour being:
1. Accept password on stdin.
2. Run `-c true` (succeed-or-fail with zero arg side-effects).
3. Exit 0 iff password matched the user's.

All three are POSIX-ish stable. util-linux `su(1)` and GNU coreutils
`su(1)` both satisfy them today. Failure mode: a distro replaces
`su` with one that prompts interactively instead of reading stdin
(e.g. a `doas`-symlinked variant). Low probability but tracked here.

### PAM service config (`etc/pam.d/shakti`)

Shipped in the repo for eventual real-PAM wiring. Unused today. When
cyrius 5.5.x lands the NSS bootstrap and we resume bite 3, this file
becomes load-bearing. No current drift risk.

### TOML policy format

`src/policy.cyr` implements a mini-TOML parser (the stdlib parser
recognises `[[array]]` but not `[table]` sections, which the
sudoers schema needs for `[defaults]`). TOML 1.0 format is frozen.
Risk: if the sudoers schema ever wants TOML features the mini-parser
doesn't support (inline tables, datetimes, multi-line strings),
rework needed.

## Resolved

### Rust crates (pre-0.2.0)

The 0.1.x Rust build carried RUSTSEC advisories for `pam` 0.7.0 and
its transitive `users` 0.8.1. The cyrius port (0.2.0) removed every
Rust dependency; the advisories no longer apply.

Historical entries for reference:

- `users` 0.8.1 — RUSTSEC-2025-0040 (`root` appended to group
  listings), RUSTSEC-2023-0059 (unaligned read), RUSTSEC-2023-0040
  (unmaintained). **Resolved 2026-04-17** by the cyrius port —
  shakti no longer uses the `users` crate.
- `pam` 0.7.0 — the only path to `users`. **Resolved 2026-04-17** —
  PAM is stubbed in the cyrius port; the su shim has no crate
  dependency. Real PAM re-enablement via `dlopen("libpam.so.0")`
  will not pull Rust crates.

## Review cadence

Re-run this audit at each P(-1) cycle (pre-feature hardening gate
per `CLAUDE.md`). Add a row under Active for any new external
surface the work introduces.
