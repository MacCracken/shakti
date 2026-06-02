# ADR-007: Capability-Based Privilege (per-rule CAP_* drop)

## Status

Accepted (2026-06-01)

## Context

Shakti's only privilege model today is full-uid: an authorized command
runs as the target user (usually uid 0 = root) with the complete
capability set. Many privileged operations need just one Linux
capability — a service binding port 80 needs only `CAP_NET_BIND_SERVICE`,
a backup job reading every file needs only `CAP_DAC_READ_SEARCH`. Granting
full root for these is the classic over-privilege that capability sets
exist to avoid.

This was queued at the start of 0.3.1 and parked. It is **not** blocked on
cyrius's NSS/`fdlopen` helper-trust model — it uses direct `prctl(2)` and
`capset(2)` syscalls only.

## Decision

### Policy schema

Add an optional per-rule `capabilities` field — a list of capability
names:

```toml
[[rules]]
user = "deploy"
commands = ["/usr/bin/nginx"]
run_as = "nginx"
capabilities = ["CAP_NET_BIND_SERVICE"]
```

**Compatibility default (load-bearing):** a rule with no `capabilities`
field — or an empty list — keeps today's behaviour *exactly*: full-uid
drop, complete capability set. The cap-drop path is strictly opt-in. This
is what every existing policy and all four consumers rely on, so the
empty-set path must remain byte-for-byte the current `_exec_target`
sequence.

Capability names are the kernel's `CAP_*` spelling (uppercase, with the
`CAP_` prefix). An unknown name is a hard policy error — fail closed,
never silently drop an unrecognised cap to "nothing".

### Capability → bit mapping

A hand-rolled table in `src/caps.cyr`. Linux capability bit numbers are a
stable kernel ABI (0 = `CAP_CHOWN` … 40 = `CAP_CHECKPOINT_RESTORE`,
`CAP_LAST_CAP = 40` as of 6.x), so embedding them is safe and avoids any
libcap dependency. The set is represented as a single `i64` bitmask
(bit *n* set ⇒ capability *n* granted); caps 0–40 fit comfortably. For the
`capset(2)` v3 data structure the mask is split into two `u32` words
(lo = caps 0–31, hi = caps 32–63).

### The privilege-drop sequence (the careful part)

To run the target as a non-root uid while *retaining* a chosen capability
set across `execve` of an ordinary (non-setuid, no-file-caps) binary, the
caps must end up in the **ambient** set. Ambient requires the cap to be in
both *permitted* and *inheritable*, and dropping the bounding set requires
`CAP_SETPCAP` in the *effective* set. That dictates a strict order:

When the rule's cap set is **non-empty**, `_exec_target` does:

1. **`PR_CAPBSET_DROP`** every cap *not* in the requested set, caps
   `0..CAP_LAST_CAP`. Done **first**, while still uid 0 with `CAP_SETPCAP`
   effective (the bounding drop needs it). Prevents the target — and any
   setuid/file-cap binary it later execs — from re-acquiring dropped caps.
2. **`prctl(PR_SET_KEEPCAPS, 1)`** so the *permitted* set survives the
   coming `setuid` away from 0 (without it, the kernel clears all caps on
   the uid transition).
3. **`setgroups` → `setgid` → `setuid`** to the target (unchanged order,
   each return-checked, same getuid/getgid post-checks as today).
4. **`capset`** (v3): set permitted = inheritable = effective = the
   requested mask, all other caps cleared. Inheritable is what lets the
   cap become ambient; narrowing permitted here drops every cap we didn't
   ask for.
5. **`PR_CAP_AMBIENT_RAISE`** each requested cap — now that each is in
   permitted ∩ inheritable, it can be raised into ambient, which is the
   set preserved across `execve` of a normal binary.
6. **`execve`** — the target starts with exactly the requested caps in its
   effective/permitted/ambient sets and an empty bounding set beyond them.

**Empty cap set ⇒ skip 1–2 and 4–5 entirely** and run the existing
`setgroups/setgid/setuid` + getuid/getgid post-check + `execve`. No
behavioural change for the default path.

### Fail-closed discipline

Every new syscall is return-checked exactly like the existing drop
syscalls: any negative return aborts with a hard `sys_exit(1)` and an
audit-able stderr line *before* `execve`. A partial capability state must
never reach the target. In particular, if `capset`/ambient-raise fails
after `setuid`, the process is already non-root, so aborting is safe
(it cannot leak *more* than the target uid).

### Audit

`audit_log` gains the granted capability set in the record (e.g.
`CAPS=CAP_NET_BIND_SERVICE`), so forensics can see what the target ran
with. Empty set logs as `CAPS=ALL` (full-uid, today's behaviour) to make
the distinction explicit in the trail.

## Consequences

- **Positive**: least-privilege execution — a rule can grant one cap
  instead of all of root. Defence-in-depth for the highest-value path in
  the tool.
- **Positive**: no new dependency, no `fdlopen`/NSS block; direct
  syscalls only. Static-binary footprint essentially unchanged.
- **Positive**: fully opt-in and non-breaking; absent/empty `capabilities`
  is the current path verbatim.
- **Negative**: the ordering is subtle and kernel-version-sensitive at the
  margins (ambient caps need Linux ≥ 4.3; `CAP_CHECKPOINT_RESTORE`/`BPF`/
  `PERFMON` need ≥ 5.8). The bit table pins `CAP_LAST_CAP = 40`; newer
  caps would need a table bump. Documented in `dependency-watch.md`.
- **Negative**: verifying the drop in tests requires a child that reads
  `/proc/self/status` (`CapEff`/`CapBnd`/`CapAmb`) — the unit harness can
  only test the pure name↔bit/mask logic; the live drop is an
  integration/CI concern.

## Testing

- **Unit** (`tests/tcyr/caps.tcyr`): `caps_name_to_bit` round-trips,
  unknown-name rejection, `caps_parse_set` mask construction and
  fail-closed on a bad name. Pure, no privilege needed.
- **Integration**: a probe binary execs under a synthetic rule and prints
  its `/proc/self/status` Cap lines; assert `CapEff`/`CapAmb` equal the
  requested mask and `CapBnd` is narrowed. Distro-portable, gated to a
  root-capable CI job.
