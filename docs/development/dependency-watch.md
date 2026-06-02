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
| NSS dispatch bootstrap | Unblocks bite 2b (`getgrouplist` via `dlopen` for LDAP/sssd **group** resolution). Auth-side real PAM is already shipped via `unix_chkpwd` (ADR-006), so it no longer depends on this. | Blocked on setuid-safe helper-trust model; smoke-probe before committing. |
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

`src/caps.cyr` (ADR-007) hand-declares `SYS_CAPGET = 125` /
`SYS_CAPSET = 126` (x86_64; aarch64 is 90/91). Same cross-arch caveat.

`src/session.cyr` (ADR-008) hand-declares `SYS_POLL = 7` (x86_64; aarch64
has no `poll`, uses `ppoll = 73`) and the PTY/termios ioctls
(`TIOCGPTN`/`TIOCSPTLCK`/`TIOCSCTTY`/`TIOCGWINSZ`/`TIOCSWINSZ`,
`TCGETS`/`TCSETS`). ioctl numbers and the termios struct layout
(`c_lflag @12`, `c_cc @17`) are a stable kernel ABI; cross-arch is the
only caveat (the `_IOC`-encoded `TIOCGPTN`/`TIOCSPTLCK` values differ on
MIPS/PowerPC/Alpha, not on x86_64/arm). All constants were verified
against the kernel headers via cpp before use.

### Linux capability ABI

`src/caps.cyr` pins the `CAP_*` bit table to `CAP_LAST_CAP = 40`
(`CAP_CHECKPOINT_RESTORE`, the last cap as of Linux 6.x) and uses
`_LINUX_CAPABILITY_VERSION_3` (`0x20080522` = 537396514) for `capset(2)`.
Capability bit numbers are a stable kernel ABI; the watch item is purely
*additive* — a future kernel introducing `CAP_<41+>` would need a table
bump (and a name↔bit/`caps_describe` entry) before policies could name
it. Ambient capabilities require Linux ≥ 4.3; `CAP_BPF`/`CAP_PERFMON`/
`CAP_CHECKPOINT_RESTORE` require ≥ 5.8. No drift risk on existing names.

### `/etc/passwd` + `/etc/group` format

`src/identity.cyr` parses both directly (colon-delimited,
newline-terminated). The format is stable back to V7 Unix. Risk
surface: any distro that stops maintaining `/etc/group` entries
(pure NSS deployments — LDAP only, no files backend). Those
deployments need the NSS-via-`dlopen` path that's blocked on cyrius
5.5.x.

### `unix_chkpwd(8)` helper

Primary auth backend as of 0.4.x (ADR-006): `pam_authenticate` forks
Linux-PAM's setuid-root `unix_chkpwd` via `lib/pam.cyr`. Depends on the
helper being present at `/usr/sbin/unix_chkpwd` or `/usr/bin/unix_chkpwd`
and setuid-root (shipped by the distro's pam/linux-pam package).
Failure mode: a minimal system without linux-pam ships no helper —
`pam_unix_available()` returns 0 and auth degrades to the su shim below.
Tracked because it is now load-bearing for the auth path.

### `/usr/bin/su` semantics (degradation path only)

When `unix_chkpwd` is absent or unusable, auth falls through to
`/usr/bin/su -c true <user>`. Depends on `su` behaviour being:
1. Accept password on stdin.
2. Run `-c true` (succeed-or-fail with zero arg side-effects).
3. Exit 0 iff password matched the user's.

All three are POSIX-ish stable. util-linux `su(1)` and GNU coreutils
`su(1)` both satisfy them today. Failure mode: a distro replaces
`su` with one that prompts interactively instead of reading stdin
(e.g. a `doas`-symlinked variant). Low probability, and now reached only
on systems lacking `unix_chkpwd`, but tracked here.

### PAM service config (`etc/pam.d/shakti`)

Informational under the `unix_chkpwd` backend — the helper consults
`pam_unix.so`'s `/etc/shadow` directly and does not read a per-service
stack. It would become load-bearing only under a future dlopen-libpam
backend (blocked on the NSS/helper-trust model). No current drift risk.

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
