# Internal Adversarial Self-Review

**Scope**: systematic probe of each security-critical `src/*.cyr` file
against the threat model T1–T11 and assumption register S1–S10. Not
a substitute for a third-party audit — this is the pre-audit internal
pass that catches the issues a reviewer shouldn't have to find first.

**Method**: file-by-file read with an adversarial mindset. For each
finding, classify severity, affected code, attack premise (even if
S-assumption-gated), and recommended fix. Fixes in this cycle ship
as shakti 0.2.2.

**Severity rubric**:

| Level | Criterion |
|---|---|
| **Critical** | Unauthenticated remote / same-uid-trusted RCE or privilege escalation exploitable in-scope threat model |
| **High** | In-scope privilege escalation gated on an S-assumption holding; or a defence gap that turns a low-cost error into a security problem |
| **Medium** | Defence-in-depth gap (security posture improves with fix) |
| **Low** | Hardening or correctness improvement |
| **Info** | Noted for the reviewer; no action recommended |

## Findings

### H-1 — privilege-drop return values ignored (HIGH)

**File**: `src/main.cyr:_exec_target` (lines ~360–370)

**Code pre-fix**:
```cyrius
sys_setgroups(ngids, &supp_gids);
sys_setgid(target_gid);
sys_setuid(target_uid);
# … build argv / envp …
sys_execve(resolved, argv_arr, envp_arr);
```

**Attack premise**: if `sys_setuid(target_uid)` fails (returns -1) for
any reason — SELinux/AppArmor deny, seccomp filter, prctl
`NO_NEW_PRIVS`, exotic capability state — the process continues to
`sys_execve` with its **pre-drop uid** (typically 0 when shakti is
installed setuid-root). The target command runs as root regardless
of policy.

Same shape as sudo's historical "always check return of setresuid"
defence pattern. POSIX says setuid almost always succeeds when
caller is euid=0, but "almost always" is exactly the gap an external
reviewer flags.

**Fix (0.2.2)**: check each return; abort with non-zero exit on any
failure. Post-condition verify via `sys_getuid()` / `sys_getgid()`.

**Acceptance**: new test asserting behaviour when one of the drops is
impossible (hard to exercise in a test without root privilege state).
Mitigation is defence-in-depth against a class of kernel-level
surprises; test coverage is code-review, not unit-level.

---

### H-2 — integer overflow in numeric field parsers (HIGH)

**Files**:
- `src/identity.cyr:_identity_parse_uint` (lines 19–29)
- `src/policy.cyr:_shk_parse_int` (lines ~159–172)

**Code pre-fix** (both):
```cyrius
var v = 0;
while (...) {
    var c = load8(s + i);
    if (c < 48 || c > 57) { return 0 - 1; }
    v = v * 10 + (c - 48);
    i = i + 1;
}
return v;
```

**Attack premise**: a malicious `/etc/passwd` or policy file with a
decimal field longer than `i64_max` digits wraps around during
`v * 10`. For identity lookups, `parsed_uid == uid` could match a
target uid the attacker didn't intend (e.g. wrapping to 0 = root).

Gated on assumption S1 (`/etc/passwd` / `/etc/group` root-writable)
and S1/S7 (policy files root-owned). So an in-scope attacker can't
reach this, but defence in depth:
1. Rejects garbage input from a partially-corrupted config rather
   than producing silently-wrong lookups.
2. Matches the "reject, don't wrap" hygiene a third-party reviewer
   expects from every setuid-context integer parser.

**Fix (0.2.2)**: cap valid range at `UINT_MAX = 4294967295` (kernel's
uid/gid max). Bail with `-1` on any digit that would push `v` past
the cap.

**Test coverage**: new `validate.tcyr:t_parse_uint_overflow_rejected`
(or adjacent) asserts that a 20-digit string returns the error
sentinel. Existing fuzz harness exercises the path indirectly.

---

### M-1 — timestamp directory symlink-at-path not caught (MEDIUM)

**File**: `src/timestamp.cyr:_shk_ensure_ts_dir` (line 112)

**Code pre-fix**:
```cyrius
var stbuf = alloc(STAT_BUFSZ);
var r = syscall(SYS_STAT, dir, stbuf);   # follows symlinks
```

**Attack premise**: if `/var/run/agnos/sudo` is a symlink to a
root-owned, non-world-writable directory elsewhere (e.g.
`/etc/ssl/private`), `SYS_STAT` follows the link and reports the
target's mode/uid. Both gates pass, `update_timestamp` proceeds. The
subsequent `O_NOFOLLOW` on the *last* path component only checks the
timestamp filename itself — not the parent dir — so shakti writes
into a redirected location.

Requires root write to `/var/run/` to create the symlink in the
first place (a root-equivalent attacker — out of primary threat
model). But `check_timestamp` already uses `SYS_LSTAT` on timestamp
files; the dir-bootstrap path should match for symmetry + defence in
depth.

**Fix (0.2.2)**: `SYS_LSTAT` the directory, reject `S_IFLNK`
explicitly before checking mode/uid.

**Test coverage**: new `timestamp.tcyr:t_ensure_ts_dir_rejects_symlink`
creates a tmpdir, symlinks a name into it, asserts
`_shk_ensure_ts_dir` returns non-OK (test runs as non-root with
altered `default_timestamp_dir` indirectly — actually, this needs a
harness refactor; may land as a roadmap item if not testable without
root).

---

### M-2 — identity parsers accept empty name fields (MEDIUM)

**Files**:
- `src/identity.cyr:identity_lookup_uid` (line 86)
- `src/identity.cyr:identity_lookup_groups` (line 161)

**Attack premise**: `/etc/passwd` line starting with `:` (empty name
field) produces `nlen = c1 - pos = 0`. The code allocates a 1-byte
buffer with just a null terminator and treats it as the resolved
name. Subsequent callers receive an empty cstr which `validate_username`
rejects — so the path is fail-closed today. Still, emitting empty
names is noise and masks malformed input.

Not exploitable; strictly a correctness/hygiene issue.

**Fix (0.2.2)**: skip entries where the name field is empty. Cleaner
semantics; faster failure for malformed input.

**Test coverage**: `identity.tcyr` gains a `t_skips_empty_name_entries`
case using an in-memory passwd buffer (no filesystem state needed —
refactor `_identity_lookup_*` helpers to accept a buffer/length
already exists indirectly).

---

### L-1 — `update_timestamp` conflates all open errors as SHK_ERR_SYMLINK (LOW)

**File**: `src/timestamp.cyr:update_timestamp` (line 170)

**Current**: any negative return from `syscall(SYS_OPEN, ...)` →
`SHK_ERR_SYMLINK`.

**Issue**: masks real errors (EACCES, ENOENT, EMFILE) as "symlink".
Operator debuggability suffers; no security impact.

**Fix**: defer. UX improvement, not a security finding.

---

### L-2 — `_shk_read_environ` leaks old buffer on grow (LOW)

**File**: `src/env.cyr:_shk_read_environ` (line 170)

**Issue**: when the read buffer doubles, old buffer is not freed.
Cyrius's freelist allocator may or may not reclaim. For a
single-shot CLI invocation this is irrelevant (kernel reclaims at
exec/exit). For long-running library consumers (daimon) calling
`shk_read_environment()` repeatedly, slow memory growth.

**Fix**: defer. No security impact; consumer-API concern.

---

### L-3 — allocation returns unchecked in hot paths (LOW)

**Files**:
- `src/auth.cyr:su_authenticate` (multiple `alloc()` calls)
- `src/env.cyr:_mk_env_pair` (line 221)

**Issue**: if `alloc` returns 0 (OOM), subsequent `memcpy` writes to
address 0, segfaulting. Fail-closed under kernel fault handling, but
defensive `if (buf == 0) { return SHK_ERR_IO; }` would be cleaner.

**Fix**: defer. OOM in a setuid binary is a terminal state; segfault
is acceptable abort behaviour.

---

### I-1 — envp is empty when invoking `/usr/bin/su` (INFO)

**File**: `src/auth.cyr:su_authenticate` (line 62)

**Observation**: the child `su` process runs with empty environment
(`envp` = `[0]`). Empty env means no PATH, no LANG, no TZ. Both
`bash` and `dash` have `true` as a builtin so `su -c true` works
without PATH. But a distro shipping a minimal shell that lacks
`true` builtin would fail. POSIX says shells should handle this.

**Action**: comment in `auth.cyr` documenting that empty env is
intentional (no inherited surface → no injection vector for the
auth step).

**Fix (0.2.2)**: add the clarifying comment; no code change.

---

## Fixes shipped in 0.2.2

- **H-1** — privilege-drop return-value checks + post-condition
  verification in `_exec_target`.
- **H-2** — `UINT_MAX` overflow guard in `_identity_parse_uint` and
  `_shk_parse_int`.
- **M-1** — `SYS_LSTAT` + `S_IFLNK` reject in `_shk_ensure_ts_dir`.
- **M-2** — skip empty-name entries in `identity_lookup_uid` and
  `identity_lookup_groups`.
- **I-1** — clarifying comment on empty-envp intent.

## Findings deferred

- **L-1** UX error-code differentiation on timestamp open
- **L-2** buffer leak on env-read grow (consumer-API concern)
- **L-3** alloc-returns-0 OOM defensive checks

All three are roadmap items, tracked in
[`../development/roadmap.md`](../development/roadmap.md) under v0.3+
polish work.

## Cross-references

- [`threat-model.md`](../architecture/threat-model.md) — T1–T11
  surface these findings map against.
- [`2026-04-20-external-cve-review.md`](2026-04-20-external-cve-review.md)
  — sister doc covering known-CVE surface. No finding here overlaps
  with an unmitigated CVE; they're complementary surfaces (known
  CVEs + shakti-local adversarial pass).

## Method notes

- Reviewer: self, with adversarial framing. Each file re-read cold
  with explicit hypothesis-first questions (where does an attacker
  reach this? what assumption am I relying on? what if that
  assumption is violated?).
- Depth: single-pass per file, approximately 30–60 minutes per file
  depending on complexity. `policy.cyr` (largest, ~750 lines) and
  `main.cyr` (exec-drop flow) got the most time.
- Known gaps: no coverage-guided sanitiser (cyrius has no
  AddressSanitizer / UndefinedBehaviorSanitizer equivalent); relies
  on the property-fuzz harness at `tests/tcyr/fuzz.tcyr` as the
  runtime backstop. A third-party reviewer with sanitiser-enabled
  Rust or C tooling would have additional signal.

## Review cadence

Re-run this exercise:
- Before every minor release (0.3+, 0.4+, …) as a gate.
- After any non-trivial change to `src/validate.cyr`,
  `src/timestamp.cyr`, `src/policy.cyr`, `src/auth.cyr`, or
  `src/main.cyr:_exec_target`.
- When a new T-entry lands in the threat model.
- When a third-party audit completes — validate their findings
  against this document; fold new issues as H- / M- / L- entries
  dated to the audit.
