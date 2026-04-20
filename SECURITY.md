# Security Policy

## Reporting a Vulnerability

Shakti is a privilege escalation tool — security vulnerabilities are critical.

Please report security issues privately via GitHub Security Advisories or email to security@agnos.org. Do not open public issues for security vulnerabilities.

## Supported Versions

| Version | Supported | Notes |
|---|---|---|
| 0.2.x   | Yes | Cyrius port (current). Real PAM regressed; su shim in use until cyrius 5.5.x ships the NSS dispatch bootstrap. |
| 0.1.x   | No  | Rust build, preserved in `rust-old/` for reference. No security backports. |

## Security Properties

- All authentication attempts are audit-logged (`src/audit.cyr`)
- Environment is sanitised before exec — `LD_*` and `BASH_FUNC_*`
  blocked by prefix, plus a 52-entry explicit blocklist of
  shell / locale / interpreter variables (see
  [ADR-004](docs/adr/004-env-sanitization-strategy.md))
- Command arguments validated against shell injection
  ([ADR-003](docs/adr/003-argument-level-command-matching.md))
- Rate-limited authentication (max 3 attempts per invocation)
- Per-TTY timestamp-based credential caching with configurable TTL,
  atomic symlink-rejection on write
  ([ADR-001](docs/adr/001-timestamp-o-nofollow.md))
- Password buffer zeroised on every return path
  (`secret var` — cyrius v5.3.5)

## Threat Model + CVE review

Structured for an external reviewer:

- [`docs/architecture/threat-model.md`](docs/architecture/threat-model.md)
  — attacker classes (A1–A5 in scope, A6–A8 out of scope), trust
  boundaries, an assumption register (S1–S10), **11** threat vectors
  (T1–T11) with mitigations and residual risk, non-goals, and open
  gaps.
- [`docs/audit/2026-04-20-external-cve-review.md`](docs/audit/2026-04-20-external-cve-review.md)
  — known CVE-by-CVE coverage against shakti's implementation: sudo,
  OpenDoas, util-linux, Linux-PAM, glibc NSS, systemd, plus
  LD_PRELOAD / TTY / timestamp / race attack classes. Each entry
  marked Mitigated / N/A / Blocked-on-future / Open / Review.
  Dated for external-reviewer traceability; new audit reports land
  under `docs/audit/YYYY-MM-DD-…`.

For the architectural view, see
[`docs/architecture/overview.md`](docs/architecture/overview.md).
