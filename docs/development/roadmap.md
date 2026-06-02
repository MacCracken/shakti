# Shakti Roadmap

Shipped feature history lives in [CHANGELOG.md](../../CHANGELOG.md) — this
roadmap tracks **open work only**. Current release: **0.6.2** (cyrius pin
6.0.33). The 0.1–0.6 line delivered the full Linux privilege surface: TOML
policy engine, env sanitization, command validation, timestamp caching,
audit logging, real PAM auth (ADR-006), capability-based privilege
(ADR-007), session logging + keystroke capture (ADR-008), and
SELinux/AppArmor exec contexts (ADR-009) — all Linux feature surfaces now
complete.

## 0.6.3 — Proposal-blocked work (NSS + remote policy)

Both items are blocked on the upstream cyrius proposal
`docs/development/proposals/2026-06-02-fdlopen-helper-trust-for-setuid-consumers.md`
(in the cyrius repo, filed 2026-06-02): a setuid binary cannot use
`fdlopen` today because the helper resolves inside the invoking user's
`$HOME`. They ship once cyrius provides a trusted, root-owned helper path
(an `fdlopen_init_trusted`-style entry point with ownership/mode/
non-symlink + integrity checks).

- [ ] **Real NSS dispatch (bite 2b — LDAP/sssd group resolution).** Call
      libc `getgrouplist(3)` via `fdlopen` for full NSS group membership,
      replacing the local `/etc/group` parser in `src/identity.cyr`. The
      *auth* side already honours NSS via `unix_chkpwd` (ADR-006); this
      closes the *group* side. ADR before code.
- [ ] **Remote policy fetch (fleet management).** HTTPS policy pull via
      `lib/tls.cyr` (itself `fdlopen`-backed), inheriting the same
      helper-trust requirement.

If cyrius does not land the helper-trust model in time, both are
explicitly descoped from v1.0 (tracked in the criteria below).

## 0.7.0 — Internal security audit (CVE / 0-day research)

A research-driven internal pass: survey recent real-world
privilege-escalation vulnerabilities and map each against shakti's design,
fixing or documenting our posture for every one. This is the auditable
substitute for a commissioned review — *external* review is expected to
arrive organically through consumer usage and downstream testing (see v1.0
criteria), not as a gated deliverable.

- [ ] Web-research recent CVEs / 0-days in the `sudo` / `doas` / `polkit` /
      setuid / capability / PTY space and record each in a findings doc
      under `docs/audit/`. Known classes to cover explicitly:
      - **TIOCSTI / TIOCSWINSZ input injection** — directly relevant to the
        new session-logging PTY relay (ADR-008); confirm a less-privileged
        process can't inject into the controlling tty (the reason `sudo`
        added `use_pty`).
      - **Heap/parse overflows** à la CVE-2021-3156 (Baron Samedit) — re-audit
        the mini-TOML parser and all unescaping/length math.
      - **argv/escape handling** à la CVE-2023-22809 (sudoedit `--`/`EDITOR`)
        — re-audit command/arg parsing and the `--` delimiter.
      - **Environment-trust** à la CVE-2021-4034 (pwnkit) — re-audit env
        sanitization and argv[0]/empty-argv handling.
      - **Capability/ambient pitfalls**, **setuid return-value gaps**,
        **`$HOME`/helper-trust** (already filed upstream — see 0.6.3).
- [ ] For each finding: fix + regression test, or document why shakti is
      not affected. Re-run the full cleanliness + benchmark gates.
- [ ] Refresh the threat model and ADRs with anything the survey surfaces.

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

## v1.0 Criteria

- [x] Security-critical feature set shipped — PAM auth, capabilities,
      session logging, LSM exec contexts (see CHANGELOG).
- [x] Full test coverage of security-critical paths + fuzz harnesses.
- [x] Documentation complete — architecture, threat model, 9 ADRs, guides.
- [ ] Internal security audit complete — CVE/0-day research pass with every
      finding fixed or documented (**0.7.0**). External review is expected
      to arrive organically via consumer usage and downstream testing
      rather than a commissioned audit, so it is **not** a release gate.
- [ ] All three consumers integrated and tested (**0.9.x**).
- [ ] NSS group resolution + remote policy either unblocked and shipped
      (**0.6.3**) or explicitly descoped from v1.0.
