# Shakti — Claude Code Instructions

## Project Identity

**Shakti** (Sanskrit: power/energy) — AGNOS privilege escalation tool

- **Type**: Cyrius binary + library (ships `build/shakti` CLI + `dist/shakti.cyr` consumer bundle)
- **License**: GPL-3.0-only
- **MSRV**: 1.89
- **Version**: SemVer — current in `VERSION` (0.7.0), the single source of truth
- **Genesis repo**: [agnosticos](https://github.com/MacCracken/agnosticos)
- **Philosophy**: [AGNOS Philosophy & Intention](https://github.com/MacCracken/agnosticos/blob/main/docs/philosophy.md)
- **Standards**: [First-Party Standards](https://github.com/MacCracken/agnosticos/blob/main/docs/development/applications/first-party-standards.md)

## Consumers

argonaut (init system), agnoshi (shell `sudo` equivalent), daimon (agent privilege operations)

## Development Process

### Cleanliness check (cyrius port)

Run after every work phase and after every review phase:

```
cyrius test                                   # unit + property-fuzz suites
sh tests/integration/cli.sh                   # CLI + consumer-bundle probe
cyrfmt --check src/*.cyr tests/tcyr/*.tcyr    # format (silent = clean)
for f in src/*.cyr; do cyrlint "$f"; done     # lint (must be "0 warnings")
cyrius build src/main.cyr build/shakti        # must end with OK
cyrius distlib                                # regenerate dist/shakti.cyr
```

`dist/shakti.cyr` drift is a commit-blocker — regenerate and restage
after any `src/*.cyr` edit. The integration script's consumer probe
catches this locally.

### P(-1): Scaffold Hardening (before any new features)

0. Read roadmap, CHANGELOG, and open issues — know what was intended before auditing what was built
1. Test + benchmark sweep of existing code
2. Cleanliness check (see above)
3. Get baseline benchmarks (`./scripts/bench-history.sh`)
4. Internal deep review — gaps, optimizations, security, logging/errors, docs
5. External research — domain completeness, missing capabilities, best practices, world-class accuracy
6. Cleanliness check — must be clean after review
7. Additional tests/benchmarks from findings
8. Post-review benchmarks — prove the wins
9. Repeat if heavy
10. Documentation audit — ADRs, source citations, guides, examples (see Documentation Standards in first-party-standards.md)

### Work Loop / Working Loop (continuous)

1. Work phase — new features, roadmap items, bug fixes
2. Cleanliness check (see above)
3. Test + benchmark additions for new code
4. Run benchmarks (`./scripts/bench-history.sh`)
5. Internal review — performance, memory, security, throughput, correctness
6. Cleanliness check — must be clean after review
7. Deeper tests/benchmarks from review observations
8. Run benchmarks again — prove the wins
9. If review heavy → return to step 5
10. Documentation — update CHANGELOG, roadmap, docs, ADRs for design decisions, guides and examples for new API surface
11. Version check — VERSION, cyrius.cyml (via `${file:VERSION}`), `shakti_version_string()` in `src/lib.cyr` all in sync
12. Return to step 1

### Task Sizing

- **Low/Medium effort**: Batch freely — multiple items per work loop cycle
- **Large effort**: Small bites only — break into sub-tasks, verify each before moving to the next. Never batch large items together
- **If unsure**: Treat it as large. Smaller bites are always safer than overcommitting

### Refactoring

- Refactor when the code tells you to — duplication, unclear boundaries, performance bottlenecks
- Never refactor speculatively. Wait for the third instance before extracting an abstraction
- Refactoring is part of the work loop, not a separate phase. If a review (step 5) reveals structural issues, refactor before moving to step 6
- Every refactor must pass the same cleanliness + benchmark gates as new code

### Key Principles

- Never skip benchmarks
- Security-critical code — privilege escalation is a high-value attack target
- Zero unwrap/panic — must never crash with elevated privileges
- All authentication paths must be audit-logged (success and failure)
- Environment sanitization must be comprehensive — remove all LD_* variables
- Command validation must reject shell injection vectors
- `#[non_exhaustive]` on ALL public enums (forward compatibility)
- `#[must_use]` on all pure functions

## DO NOT

- **Do not commit or push** — the user handles all git operations
- **NEVER use `gh` CLI** — use `curl` to GitHub API only
- Do not add unnecessary dependencies
- Do not skip benchmarks before claiming performance improvements
- Do not weaken environment sanitization
- Do not remove audit logging from any authentication path

## Documentation Structure

```
Root files (required):
  README.md, CHANGELOG.md, CLAUDE.md, CONTRIBUTING.md, SECURITY.md, CODE_OF_CONDUCT.md, LICENSE

docs/ (required):
  architecture/overview.md — security model, auth flow, policy format
  development/roadmap.md — completed, backlog, future, v1.0 criteria

docs/ (when earned):
  adr/ — architectural decision records
  guides/ — usage guides, integration patterns
  examples/ — worked examples
  standards/ — external spec conformance
  compliance/ — regulatory, audit, security compliance
  sources.md — source citations for algorithms/formulas (required for science/math crates)
```

## CHANGELOG Format

Follow [Keep a Changelog](https://keepachangelog.com/). Security-related changes get a **Security** section. Breaking changes get a **Breaking** section with migration guide.
