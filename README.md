# Shakti

**Shakti** (Sanskrit: power/energy) — AGNOS privilege escalation tool.

Authenticates the calling user, checks a TOML-based policy file
(`/etc/agnos/sudoers.toml`), then executes the requested command with the
target user's credentials.

Written in [Cyrius](https://github.com/MacCracken/cyrius). Ported from
the original Rust implementation preserved in `rust-old/`.

## Security Properties

- Real PAM authentication via Linux-PAM's `unix_chkpwd(8)` helper
  (honours `/etc/shadow` + NSS: files, LDAP, SSSD); `su` only as a
  helper-missing fallback
- All attempts (success and failure) are audit-logged
- Environment is sanitized before exec (LD_*, BASH_FUNC_*, interpreter
  injection vectors all blocked)
- Command arguments are validated against shell metacharacters
- Policy supports per-user, per-group, and per-command rules
- **Capability-based privilege** — a rule can grant a specific `CAP_*`
  set instead of full root (least-privilege drop)
- **Session logging** — optional per-rule PTY transcript of the session,
  with opt-in keystroke capture (typed secrets redacted)
- **SELinux / AppArmor exec contexts** — a rule can launch the target
  under a specific MAC domain/profile
- Per-TTY credential cache with root-ownership + symlink tamper checks
- Timestamps use `O_NOFOLLOW` to close the create-open TOCTOU window
- Rate-limited authentication (max 3 attempts)

## Build

```sh
cyrius build src/main.cyr build/shakti
cyrius distlib                  # regenerate dist/shakti.cyr bundle
```

Requires the [Cyrius](https://github.com/MacCracken/cyrius) toolchain
pinned in `cyrius.cyml` (`[package].cyrius`). The stdlib and the `sakshi`
dep are resolved into `lib/` by `cyrius deps` (gitignored, not vendored);
`cyrius.lock` pins their hashes for reproducible builds.

## Install

```sh
sudo ./scripts/install.sh --with-example-policy
```

Installs `build/shakti` setuid-root to `/usr/bin/shakti`, creates
`/etc/agnos/` with example policy + `sudoers.d/` fragment directory,
sets up `/var/run/agnos/sudo` (0700), drops the `tmpfiles.d` snippet,
and installs the PAM service config. Idempotent — safe to re-run
after rebuilding. See `scripts/install.sh --help` for path overrides
and flag options.

## Test / bench

```sh
cyrius test                          # auto-discovers tests/tcyr/*.tcyr
cyrius bench tests/bcyr/core.bcyr
./scripts/bench-history.sh           # appends to benchmarks/history.csv
sh tests/integration/cli.sh          # CLI + consumer-bundle probe
```

## Architecture

```
src/
  main.cyr        entry point: CLI parsing, signal masking, exec flow
  lib.cyr         shared error codes, constants, module includes
  validate.cyr    username / command validation + pattern matching
  caps.cyr        Linux capability name↔bit table + capset/prctl drop
  session.cyr     PTY allocation, raw termios, poll relay + session log
  lsm.cyr         SELinux / AppArmor exec-context (/proc/self/attr/exec)
  env.cyr         environment sanitization (unsafe/safe lists)
  timestamp.cyr   credential cache with TTY isolation + O_NOFOLLOW
  audit.cyr       audit logging (file + stderr)
  auth.cyr        authentication (PAM via unix_chkpwd; su fallback)
  policy.cyr      mini-TOML parser + authz engine + linter
  api.cyr         consumer API (ShaktiConfig / evaluate)
```

See `docs/architecture/overview.md` for the full security model.

## Consumer API

Shakti ships as a library in two forms:

- **`dist/shakti.cyr`** — single-file bundle (`cyrius distlib`
  output). Drop-in `include`; consumer declares the stdlib surface.
- **`src/*.cyr` modules** — piecemeal pickup for consumers that want
  a subset (e.g. validation only, no auth).

**Dependencies.** The bundle leaves `sakshi_*` (structured audit
logging) as unresolved symbols, just like the stdlib — Cyrius does not
resolve transitive deps, so a consumer of `dist/shakti.cyr` must declare
sakshi in its own `cyrius.cyml` alongside `[deps.shakti]`:

```toml
[deps.sakshi]
git = "https://github.com/MacCracken/sakshi.git"
tag = "2.3.0"
modules = ["dist/sakshi.cyr"]
```

Keep the tag in sync with shakti's `cyrius.cyml` if it moves.

The bundle also references the stdlib `pam` module (`pam_unix_authenticate`,
for `unix_chkpwd`-based password verification — see ADR-006). Unlike
sakshi this is part of the cyrius stdlib, not a git dep, so a consumer
only needs `"pam"` present in its `[deps].stdlib` list (shakti's own list
in `cyrius.cyml` is the reference).

Four AGNOS consumers integrate via `src/api.cyr`:

- **argonaut** (init system): uses `AUTH_SKIP` — already authenticated at boot
- **agnoshi** (shell): uses `AUTH_INTERACTIVE` — full sudo experience
- **daimon** (agent): uses `AUTH_TIMESTAMP_ONLY` — no terminal available
- **ark** (package manager): uses `AUTH_TIMESTAMP_ONLY` for privileged ops

See [`docs/guides/integration.md`](docs/guides/integration.md) for the
full consumer guide (manifest layout, API surface, default paths,
cyrius version floor, bundle regeneration).

## Part of AGNOS

Shakti is a component of [AGNOS](https://agnosticos.org), the AI-Native
General Operating System.

## License

GPL-3.0-only
