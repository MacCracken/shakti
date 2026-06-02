# ADR-008: Session Logging via PTY Relay (openpty)

## Status

Accepted (2026-06-01)

## Context

Shakti's audit trail records *that* a command was authorized and run
(caller, target, command, capabilities — see ADR-006/007), but not *what
happened* during the session. For interactive privileged commands (a root
shell, `vipw`, a database console) operators and auditors want an I/O
transcript: what the command displayed, optionally what was typed. This is
sudo's `log_output` / I/O logging.

Capturing terminal I/O correctly requires a pseudo-terminal. Piping
stdout/stderr through shakti would make the child see a pipe, not a tty —
breaking `isatty()`, line editing, colour, `vim`, pagers, and prompts. A
PTY is mandatory for a general sudo-like tool.

This is direct Linux syscalls only — `/dev/ptmx`, `ioctl`, `setsid`,
`select` — no `fdlopen`/NSS dependency. It was on the roadmap's
unblocked "Future" list.

## Decision

### Exec-model change (the crux)

Today `_exec_target` drops privilege and `execve`s directly — shakti's
process is *replaced* by the target. Session logging needs shakti to stay
alive as a relay, so the logged path forks:

- **Parent (stays root):** owns the PTY master, relays bytes between the
  real terminal and the master, tees the output stream to a root-owned
  session log, `waitpid`s the child, restores terminal state, and exits
  with the child's status.
- **Child (drops to target):** `setsid()` → make the PTY slave its
  controlling terminal (`TIOCSCTTY`) → `dup2` slave onto stdin/stdout/
  stderr → run the **existing** privilege-drop sequence → `execve`.

**The non-logged path is unchanged**: still a direct in-process
`execve`, no fork, no PTY, zero overhead and zero behavioural change. The
privilege-drop sequence (`close_range`, `setgroups`/`setgid`/`setuid`,
getuid/getgid post-checks, capability drop from ADR-007) is **extracted**
into a shared `_drop_privileges()` helper called by both paths, so the
security-critical drop logic is written and reviewed once.

### Why the parent keeps root

The parent must write the session log into a root-owned, mode-0700
directory and read/write the PTY master after the child has dropped
privilege. A non-root user must not be able to read or tamper with another
session's transcript. The relay itself is a dumb byte-copier; it never
interprets the stream, so retained root is not an injection surface beyond
the file writes it already performs (which target a fixed, root-owned
path).

### Policy schema

Opt-in, non-breaking:

- `[defaults] log_session = false` (default) and `session_log_dir =
  "/var/log/agnos/sessions"`.
- Per-rule `log_session = true|false` overrides the default for matched
  rules.

A rule without `log_session` inherits the default (off) — existing
policies are unaffected and take the unchanged direct-exec path.

### Log file

One file per session, `session_log_dir/<ts>-<caller>-<pid>.log`, created
`0600` in a `0700` root-owned dir. Format: a header line (timestamp,
caller, target, resolved command, tty), the raw **output** stream
(everything the command wrote to the terminal), and a footer (exit
status, wall-clock duration). v1 logs the output direction only; input
(keystroke) capture is deferred — it is the more sensitive half
(passwords typed into the child) and warrants its own redaction design.

### Terminal handling

The parent sets the real terminal to raw mode (clear
`ICANON|ECHO|ISIG|IEXTEN|ECHONL`, `ICRNL|IXON|…`, `OPOST`; `CS8`;
`VMIN=1/VTIME=0`) so every keystroke and control char passes through to
the master, restoring the saved termios on exit (RAII-style, mirroring the
existing password-echo guard). Window size is copied master←real-tty at
start and on `SIGWINCH` (`TIOCGWINSZ`/`TIOCSWINSZ`).

## Consequences

- **Positive**: full I/O transcripts for interactive privileged sessions;
  correct tty semantics for the child (it gets a real pty).
- **Positive**: opt-in and non-breaking — default-off, and the disabled
  path is byte-for-byte today's direct exec.
- **Positive**: no new dependency; direct syscalls only.
- **Negative**: the logged path adds a long-lived root relay process and
  a fork; more moving parts (raw termios, SIGWINCH, EOF/exit races) than
  direct exec. Confined to the new logged branch.
- **Negative**: transcripts can contain sensitive output; the 0700/0600
  dir/file perms are load-bearing. Documented in `dependency-watch.md`.
- **Negative**: exit-status fidelity depends on faithfully translating
  the child's `wait` status into shakti's exit code.

## Testing

- **Unit** (`tests/tcyr/session.tcyr`): PTY open → slave-path resolution
  round-trip; raw-termios flag math (the mask values) without touching the
  real tty.
- **Integration** (unprivileged, no root needed): a probe opens a PTY,
  forks, runs a known command (`echo`) on the slave, relays + logs, and
  asserts the captured transcript contains the expected output and a
  well-formed header/footer. The privilege-drop-in-child path is covered
  by the existing exec tests + a root CI job.
