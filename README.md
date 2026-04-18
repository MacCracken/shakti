# Shakti

**Shakti** (Sanskrit: power/energy) — AGNOS privilege escalation tool.

Authenticates the calling user, checks a TOML-based policy file
(`/etc/agnos/sudoers.toml`), then executes the requested command with the
target user's credentials.

Written in [Cyrius](https://github.com/MacCracken/cyrius). Ported from
the original Rust implementation preserved in `rust-old/`.

## Security Properties

- All attempts (success and failure) are audit-logged
- Environment is sanitized before exec (LD_*, BASH_FUNC_*, interpreter
  injection vectors all blocked)
- Command arguments are validated against shell metacharacters
- Policy supports per-user, per-group, and per-command rules
- Per-TTY credential cache with root-ownership + symlink tamper checks
- Timestamps use `O_NOFOLLOW` to close the create-open TOCTOU window
- Rate-limited authentication (max 3 attempts)

## Build

```sh
cyrius build src/main.cyr build/shakti
```

Requires [Cyrius 5.2.1](https://github.com/MacCracken/cyrius) or later.
Stdlib is vendored under `lib/` for reproducible builds.

## Test / bench

```sh
cyrius test                   # auto-discovers tests/tcyr/*.tcyr (219 tests)
cyrius bench tests/bcyr/core.bcyr
./scripts/bench-history.sh    # appends to benchmarks/history.csv
```

## Architecture

```
src/
  main.cyr        entry point: CLI parsing, signal masking, exec flow
  lib.cyr         shared error codes, constants, module includes
  validate.cyr    username / command validation + pattern matching
  env.cyr         environment sanitization (unsafe/safe lists)
  timestamp.cyr   credential cache with TTY isolation + O_NOFOLLOW
  audit.cyr      audit logging (file + stderr)
  auth.cyr        authentication (su shim; PAM stubbed for future dynlib work)
  policy.cyr      mini-TOML parser + authz engine + linter
  api.cyr         consumer API (ShaktiConfig / evaluate)
```

See `docs/architecture/overview.md` for the full security model.

## Consumer API

Three AGNOS consumers integrate via `src/api.cyr`:

- **argonaut** (init system): uses `AUTH_SKIP` — already authenticated at boot
- **agnoshi** (shell): uses `AUTH_INTERACTIVE` — full sudo experience
- **daimon** (agent): uses `AUTH_TIMESTAMP_ONLY` — no terminal available

## Part of AGNOS

Shakti is a component of [AGNOS](https://agnosticos.org), the AI-Native
General Operating System.

## License

GPL-3.0-only
