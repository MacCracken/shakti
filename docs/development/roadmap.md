# Shakti Roadmap

Shipped feature history lives in [CHANGELOG.md](../../CHANGELOG.md) — this
roadmap tracks **open work only**. Current release: **0.7.0** (cyrius pin
6.2.12). The 0.1–0.6 line delivered the full Linux privilege surface: TOML
policy engine, env sanitization, command validation, timestamp caching,
audit logging, real PAM auth (ADR-006), capability-based privilege
(ADR-007), session logging + keystroke capture (ADR-008), and
SELinux/AppArmor exec contexts (ADR-009) — all Linux feature surfaces now
complete.

## Unblocked by cyrius `fdlopen_init_trusted` (6.1.29)

The setuid-`fdlopen` blocker is **resolved**: cyrius shipped
`fdlopen_init_trusted` in 6.1.29 (on shakti's pin since 0.6.3). It
resolves only the root-owned, non-writable, non-symlink
`/usr/lib/cyrius/dlopen-helper`, never the caller's `$HOME`, and fails
closed — exactly the helper-trust model shakti's upstream proposal asked
for (now archived). Both items below are buildable.

- [x] **Real NSS dispatch (LDAP/sssd group resolution).** **Shipped 0.6.4**
      (ADR-010). `getgrouplist(3)` + `getgrgid_r(3)` via the trusted
      `fdlopen` helper, opt-in behind `[defaults] nss_groups` (default
      off), fail-safe fallback to the `/etc/group` parser. Closes the
      group side; the auth side already honoured NSS via `unix_chkpwd`
      (ADR-006). *Follow-on:* passwd-side NSS (`getpwnam_r`) for the
      primary-GID input is still files-based — pull in when a consumer
      needs LDAP-only target users.
- [ ] **Remote policy fetch (fleet management).** HTTPS policy pull via
      `lib/tls.cyr` (itself `fdlopen`-backed). Now unblocked by the same
      trusted-helper path; not yet started. ADR before code.

## 0.7.0 — Internal security audit (CVE / 0-day research) — SHIPPED

Internal CVE/0-day pass shipped in 0.7.0. Findings:
[`docs/audit/2026-06-16-0.7.0-cve-audit.md`](../audit/2026-06-16-0.7.0-cve-audit.md).

- [x] **TIOCSTI** (CVE-2023-28339/2016-2779) — lateral-uid PTY isolation
      (ADR-011), fixed + tested.
- [x] **F-1 getgrouplist clamp** (CVE-2003-0689 class) — heap-write
      hardening on the new 0.6.4 NSS code, fixed + tested.
- [x] **Baron Samedit / sudoedit / pwnkit** classes — re-audited; N/A or
      mitigated by construction, documented in the findings doc.
- [x] **Re-baselined** the PAM/NSS rows the April survey had deferred as
      "blocked on cyrius" (PAM 0.4.2, NSS 0.6.4 now shipped).
- [x] Threat model refreshed (T11 mitigation, T12, related-docs).

**Carried (standing, non-blocking):**

- [ ] **Annual CVE re-scan** — a fresh web-research sweep for net-new
      sudo/doas/PAM/polkit CVEs published since the 2026-04-20 survey;
      confirm CVE-2025-8941 (Linux-PAM) against its advisory.
- [ ] **Timestamp Partials** — cross-session reuse + clock-rollback-vs-TTL
      (threat model S8); documented-partial today, revisit if a consumer
      needs hardening.

## 0.8.x — AGNOS kernel integration

Shakti's privilege mechanisms are currently built against the **Linux**
kernel ABI (setuid/setgroups, capset/prctl, `/proc/self/attr`, PTY ioctls,
`unix_chkpwd`). AGNOS ships its own kernel; this milestone re-does the same
work-up against AGNOS's interfaces, ideally behind one abstraction so a
single source serves both. (The existing x86_64-vs-aarch64 syscall-number
split already signals the need for a kernel/ABI seam.)

- [ ] Identity & privilege drop on the AGNOS kernel (uid/gid model,
      supplementary groups).
- [ ] Least-privilege / capability equivalent — map ADR-007's model onto
      AGNOS's mechanism.
- [ ] Authentication backend on AGNOS — the `unix_chkpwd`/PAM equivalent.
- [ ] MAC / exec-context equivalent (ADR-009 analogue), if AGNOS provides
      one.
- [ ] Session-logging PTY path against AGNOS tty/pty interfaces.
- [ ] Kernel/ABI abstraction layer so Linux and AGNOS share one source.

## 0.9.x — Consumer integration, v1 closeout, freeze

- [ ] Integrate and test all three consumers: **argonaut** (init system),
      **agnoshi** (shell `sudo` equivalent), **daimon** (agent privilege
      operations).
- [ ] v1.0-criteria review closeout (below).
- [ ] Freeze the consumer API + policy schema; document the stability
      guarantee.

## Deferred (non-blocking, unscheduled)

Real but low-priority; pull into a milestone when a consumer needs them.

- [ ] Session-log keystroke (input) capture — output-only today; needs a
      redaction design for typed secrets.
- [ ] Live `SIGWINCH` window-resize propagation during a logged session
      (start-of-session size is copied today).
- [ ] LSM-aware auto-selection for exec contexts — one policy across a
      mixed SELinux/AppArmor fleet.
- [ ] Audit **L-2** — env-read buffer leak on grow (bump-allocator `free()`
      limitation; affects long-running library consumers, not the
      single-shot CLI).
- [ ] **Unconditional PTY** (full `sudo use_pty` parity). 0.7.0 (ADR-011)
      put lateral uid moves on a PTY; this would extend it to *every*
      target, including `caller → root`, closing TIOCSTI on the shared-tty
      path without relying on the `legacy_tiocsti` sysctl. Deferred for the
      tty-semantics change + per-invocation relay overhead — land behind
      its own ADR with measured overhead.

## v1.0 Criteria

- [x] Security-critical feature set shipped — PAM auth, capabilities,
      session logging, LSM exec contexts (see CHANGELOG).
- [x] Full test coverage of security-critical paths + fuzz harnesses.
- [x] Documentation complete — architecture, threat model, 11 ADRs, guides.
- [x] Internal security audit complete — CVE/0-day pass shipped in **0.7.0**
      ([findings](../audit/2026-06-16-0.7.0-cve-audit.md)); every surveyed
      finding fixed or documented. Standing annual re-scan carried (above).
      External review is expected to arrive organically via consumer usage
      and downstream testing rather than a commissioned audit, so it is
      **not** a release gate.
- [ ] All three consumers integrated and tested (**0.9.x**).
- [x] NSS **group** resolution unblocked and shipped (**0.6.4**, ADR-010,
      opt-in). Remote policy fetch is unblocked by the same trusted-helper
      path but not yet shipped — descoped from the v1.0 gate (pull in when
      a fleet consumer needs it).
