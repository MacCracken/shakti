# Security Audit Reports

Dated, append-only audit artefacts. One file per review cycle.

## Convention

`YYYY-MM-DD-<short-name>.md` — date is the report's publication or
sign-off date, not the review start date. Example:
`2026-04-20-external-cve-review.md`.

Do not edit files here once published — they are the reviewer's (or
the project's) frozen snapshot at that date. Corrections or updates
land as a **new** dated entry that supersedes the earlier one, with
cross-reference.

## Current entries

| Date | File | Type | Summary |
|---|---|---|---|
| 2026-04-20 | [2026-04-20-external-cve-review.md](2026-04-20-external-cve-review.md) | Pre-audit known-CVE survey | ~30 known CVEs + attack classes (sudo, doas, su, PAM, NSS, LD_PRELOAD, TTY, timestamp, systemd) mapped against shakti's current implementation. Status per entry: Mitigated / N/A / Blocked-on-cyrius-5.5.x / Open / Review. Surfaced **T11 (TIOCSTI)** — added to the threat model. |
| 2026-04-20 | [2026-04-20-internal-review.md](2026-04-20-internal-review.md) | Internal adversarial self-review | File-by-file probe of each security-critical `src/*.cyr` against the T1–T11 / S1–S10 registers. Findings H-1 (privilege-drop return checks), H-2 (integer overflow in numeric parsers), M-1 (LSTAT on timestamp dir), M-2 (empty-name entries), I-1 (empty-envp comment) shipped in shakti 0.2.2. L-1 / L-2 / L-3 deferred. |
| 2026-06-02 | [2026-06-02-internal-review.md](2026-06-02-internal-review.md) | Internal adversarial self-review (0.6.1) | Audit of the 0.5–0.6 exec-path features (capabilities, session logging, LSM contexts). Fixed: session-log dir TOCTOU/symlink + group-writable (H2), AppArmor-vs-SELinux node confusion (H1), relay hang on child-setup failure, capget post-check (M1), relay HUP truncation (M2), x86_64 openat/newfstatat numbers, signal exit status. Shipped in 0.6.1. |

## Expected future entries

- **0.7.0 CVE / 0-day research audit** (v1.0 criterion) — the internal,
  research-driven pass over recent privilege-escalation CVEs/0-days
  (TIOCSTI, Baron Samedit, sudoedit, pwnkit, capability/ambient, …) with
  every finding fixed or documented. The two 2026-04-20 surveys are the
  baseline; external review is expected to arrive organically via consumer
  usage and downstream testing rather than as a commissioned audit.
- **Post-helper-trust NSS audit** — when cyrius ships the setuid-safe
  `fdlopen` helper (see the upstream proposal / shakti 0.6.3) and shakti
  wires real `getgrouplist`, a new dated review covers the NSS items.
  (Auth-side NSS already landed via `unix_chkpwd` in 0.4.2.)
- **Annual re-scan** — sudo / doas / PAM CVE landscape is active;
  re-survey at least once per calendar year.

## How to add an entry

1. Write the report to `YYYY-MM-DD-<short-name>.md`.
2. Add a row to the table above.
3. Cross-link from [`../architecture/threat-model.md`](../architecture/threat-model.md)
   (Related documents section) and
   [`../../SECURITY.md`](../../SECURITY.md) (Threat Model + CVE review).
4. Land any threat-model updates (new T-entries, changed status) in
   the same commit — audit-driven changes and threat-model changes
   travel together.
