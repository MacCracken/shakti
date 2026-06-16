# ADR-011: PTY Isolation for Lateral UID Moves (TIOCSTI Mitigation)

## Status

Accepted (2026-06-16) — extends [ADR-008](008-session-logging-openpty.md).
Part of the 0.7.0 internal CVE/0-day audit.

## Context

`TIOCSTI` (and the related `TIOCSWINSZ`) terminal-input-injection class —
OpenDoas **CVE-2023-28339**, util-linux runuser **CVE-2016-2779** — lets a
process that holds a writable fd to a terminal push synthetic keystrokes
into that terminal's input queue. They are then read by whatever reads the
tty next.

shakti's default exec path (`_exec_target`) runs the target directly on the
**caller's** controlling tty: the target inherits stdin/stdout/stderr
unchanged. When the target uid differs from the caller's, a hostile target
can `ioctl(TIOCSTI)` against that shared tty and, after shakti exits,
inject a command line into the caller's shell — running as the *caller*.
This is the `sudo` `use_pty` motivation.

Two facts bound the exposure:

- **Direction matters.** The classic invocation `caller → root` is the
  least exposed: the elevated side is the target, and root could act
  directly anyway. The dangerous direction is a **lateral** move —
  `developer → service-account` — where a compromised service account
  injects back into the developer's session. Real usage, real exposure.
- **ADR-008 already defeats it when logging is on.** A `log_session` rule
  allocates a per-invocation PTY and relays I/O; the target runs on a
  fresh slave and never holds a writable fd to the caller's real tty.
- **Modern kernels gate it.** Linux ≥ 6.2 restricts `TIOCSTI` behind the
  `dev.tty.legacy_tiocsti` sysctl (default off). shakti targets AGNOS and
  current Linux, where the OS already neuters the default case.

The 0.7.0 TIOCSTI decision (recorded in the audit findings) chose to close
the lateral-move exposure now and keep an unconditional-PTY option for the
roadmap, rather than force every invocation onto a PTY immediately.

## Decision

Run a target on a dedicated PTY — reusing the ADR-008 relay — whenever it
is a **lateral uid move**, even if session logging is off. Concretely, the
PTY path is taken when:

```
needs_pty = log_session  OR  (target_uid != caller_uid AND target_uid != 0)
```

- `caller → root` (`target_uid == 0`) and `same-uid` targets keep the
  direct-exec fast path — no behavioural or performance change for the
  overwhelmingly common case.
- A lateral target runs on a PTY slave (own session, `TIOCSCTTY`), so it
  never holds a writable fd to the caller's original tty — `TIOCSTI`
  against that tty is structurally impossible.

When the PTY is taken **only** for the lateral-move reason (logging off),
the relay runs with `logfd = inlogfd = -1`: pure I/O relay, **no
transcript written**. No new logging surface, no `session_log_dir`
requirement, no behavioural coupling to ADR-008's log gating.

The decision is a single pure predicate, `_shk_needs_pty(do_log,
caller_uid, target_uid)`, unit-tested independently of the (fork/pty/tty)
exec machinery. `_exec_target_logged` is renamed `_exec_target_pty` — it is
now the general PTY-relay exec path (logged or not) — and its
unconditional log-header write is guarded on `logfd >= 0`.

The audit trail records `PTY=on|off` and, when applicable, that the PTY was
allocated for a lateral-uid move rather than for logging.

## Consequences

- **Positive**: closes the TIOCSTI Open finding (survey rows
  CVE-2023-28339, CVE-2016-2779, and the TTY-section TIOCSTI row) for the
  direction that actually matters, on every kernel — not only ≥ 6.2.
- **Positive**: zero change to the `caller → root` and same-uid fast
  paths; the PTY cost is paid only by lateral moves.
- **Positive**: reuses the audited ADR-008 relay; no new privileged code
  beyond the predicate and the `logfd`-guard.
- **Negative**: lateral-move targets now run on a PTY, which changes tty
  semantics slightly (job control, `isatty` already true, but it is a pipe
  to the relay) and adds the relay's overhead for those invocations. This
  matches `sudo -u otheruser` behaviour under `use_pty`.
- **Negative**: does not cover a hostile **root** target (`caller → root`
  stays on the shared tty). Accepted: a root target can compromise the
  caller by many other means; the kernel sysctl backstop (Linux ≥ 6.2)
  remains the mitigation there.

## Roadmap

**Unconditional PTY** — running *every* target on a PTY (full `use_pty`
parity, covering even `caller → root`) is the long-term direction, tracked
on the roadmap. It is deferred because it changes tty semantics and adds
overhead for the common case; it should land behind its own ADR with
measured overhead.
