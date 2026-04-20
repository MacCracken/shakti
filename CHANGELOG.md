# Changelog

All notable changes to Shakti will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- **Cyrius toolchain pin 5.2.1 → 5.4.11** (`cyrius.cyml`). Brings in
  three-and-a-half months of upstream work; relevant inheritance for
  shakti (all on the x86_64 Linux static target):
  - v5.2.1 `cyrius deps --lock` / `--verify` — supply-chain hash
    verification (SHA256 lockfile) available for CI.
  - v5.3.3 `mulh64(a, b)` builtin — not used directly by shakti
    today, but upstream sigil adopts it which drops AES-GCM paths
    that shakti may eventually depend on.
  - v5.3.5 `secret var name[N];` — zeroise-on-exit arrays. Adopted
    in `_prompt_and_authenticate` (see Security section below).
  - v5.3.7 → v5.3.14 dynlib machinery (IRELATIVE, IFUNC,
    cpu_features/TLS/stack_end bootstrap, bounds-checked indirect
    calls). Not unblocking NSS/PAM yet, but the infrastructure is
    in place and simple libc calls via `dynlib` work today.
  - v5.3.14 `lib/args.cyr` — empty-string args no longer silently
    dropped; argv/argc correctness fix inherited.
  - v5.4.9 ships sigil 2.8.4 (AES-GCM fix + hardening pass) in the
    toolchain dep graph.
  - v5.4.10 `lib/thread.cyr` post-clone trampoline — not used by
    shakti but inherited.
  - v5.4.11 per-arch `lib/syscalls.cyr` split with arch-dispatched
    `Stat` enum (`STAT_MODE` / `STAT_UID` / `STAT_GID` / `STAT_BUFSZ`).
    Shakti's hand-rolled `STAT_MODE_OFF` / `STAT_UID_OFF` /
    `STAT_BUF_SIZE` constants (x86_64 literals) are replaced with the
    cyrius enum names — the migration path the cyrius changelog
    recommends for downstream consumers. Residual x86_64-specific
    values (`SYS_LSTAT`, `SYS_READLINK`, `SYS_CLOCK_GETTIME`,
    `SYS_CLOSE_RANGE`, `STAT_MTIME_OFF`, `S_IF*`, `O_NOFOLLOW`)
    remain shakti-local with a comment noting aarch64 cross-build
    would need them remapped.
- Test suite: 239 cases across 9 `.tcyr` files + bench harness; all
  pass against the v5.4.9 toolchain with no source changes required.

### Added

- `src/identity.cyr` — local-files identity backend extracted from
  `main.cyr`. Public API: `identity_lookup_uid`,
  `identity_lookup_user`, `identity_lookup_groups`,
  `identity_lookup_gids`. The previous inline parsers in `main.cyr`
  (uid lookup, group lookup, target uid lookup) are removed in
  favour of this module.
- `tests/tcyr/identity.tcyr` — 12 cases covering uid/name lookup,
  missing-user fallthrough, substring-safety on colon-anchored
  matches, primary-gid-first ordering, and primary-vs-supp dedup.
- `docs/adr/005-identity-backend-port-to-cyrius.md` — captures the
  decision to use local-files parsing in `src/identity.cyr` for the
  0.2.x line, along with the cyrius dependency chain that gates
  restoring NSS backend parity. Replaces the stale "blocked on
  cyrius 5.3.1" note in the roadmap.

### Changed (P(-1) review cleanups)

- `policy.cyr:_shk_copy_trim` — removed the vestigial first trim-left
  loop (commented "Restart cleanly (the idiom above is to exit the
  trim-left loop)"). The second loop was the real trim-left; the
  first was broken and dead. No behaviour change; ~11 lines deleted.
- `policy.cyr:check_authorization` — replaced the `else { i = i; }`
  noop with an early `continue` when neither user nor group matches.
  Flow is now linear; same benchmarks (~1-2µs per call).
- `cyrius.cyml` — `version = "${file:VERSION}"` (v5.1.13 expansion)
  so the VERSION file is the single source of truth for the manifest.
- `src/lib.cyr:shakti_version_string()` — centralises the in-source
  version string; `main.cyr:--version` now reads from it rather than
  a hardcoded literal. Still hand-sync with VERSION on bumps.
- `cyrius.cyml [build] output = "build/shakti"` — binary lands under
  `build/` (gitignored) by default rather than the repo root.

### Performance

- **`sanitize_environment` 141µs → 33µs (4.3×)**. Replaced the linear
  vec scan of the 51-entry unsafe list + 9-entry safe list with a
  `lib/hashmap.cyr` lookup. `_shk_unsafe_cache` / `_shk_safe_cache`
  are still lazy singletons; first call still builds the map, every
  call thereafter is O(1). Other hot-path benchmarks unchanged:
  `command_matches/*` ~1µs, `validate_command` ~1µs,
  `check_authorization/*` 1–2µs, `parse_policy` ~14µs.

### Security

- **`_prompt_and_authenticate` adopts `secret var pbuf[1024]`**
  (cyrius v5.3.5). The password buffer is now a stack array with an
  auto-synthesised zeroise prologue wired into every return path —
  including early returns from MAX_AUTH_ATTEMPTS exhaustion, empty
  input, and successful authentication. Replaces the prior
  heap-allocated `alloc(1024)` + hand-rolled `_zeroize_cstr` (which
  only cleared `strlen(buf)` bytes, not the full buffer).
  `_read_password` split into `_read_password_into(buf, cap)` so the
  caller owns the lifetime and can apply `secret`. Between-attempt
  `memset(&pbuf, 0, PW_BUF_CAP)` remains as defense in depth for the
  in-loop window.
- **Fixed null-byte leak in `_print_usage`**. Hand-counted byte
  lengths drifted by +1 on seven usage lines, leaking one null byte
  per option into help output (`od -c` showed `\0` between lines).
  Replaced every `file_write(fd, s, N)` call with a `_write_line(fd,
  s)` helper that measures with `strlen`. Structural fix prevents
  the bug class.
- **`shakti` (no args) now prints usage instead of a policy-load
  error**. The "command required" check moved ahead of the policy
  load so running shakti bare no longer tries to read
  `/etc/agnos/sudoers.toml` and fails with "failed to load policy".

### Added

- `tests/tcyr/fragments.tcyr` — 13 cases covering
  `_shk_load_fragments` defense gates (nonexistent dir, world-
  writable dir, non-directory target), the lexicographic sort helper
  `_shk_sort_str_vec`, and `str_compare_lex`.
- `tests/tcyr/fuzz.tcyr` — property-based fuzz harness porting the
  four `rust-old/fuzz/fuzz_targets/` harnesses (`parse_policy`,
  `validate_command`, `command_matches`, `validate_username`) that
  regressed in the 0.2.0 port. Cyrius has no coverage-guided fuzzer
  infra; this uses a deterministic xorshift64 PRNG with an
  adversarial byte menu (`/ \ " ' [ ] = ; | $ ( ) space # , . - _`)
  and 2500 iterations per target. **20,101 assertions pass** per run
  with no crash or invariant breach. Seeds are printed on failure so
  any regression is deterministically reproducible. Iteration budget
  tunable via `FUZZ_ITERS`.
- `tests/integration/cli.sh` — 16 bash-harness assertions covering
  the non-privileged CLI surface (`--version`, `--help`, `-V`/`-h`
  aliases, no-args, unknown option, `--` delimiter). Policy-loading
  paths (`--list`, `--check`, `--invalidate`, full exec flow) still
  need a root-owned fixture to exercise — tracked for a v0.3 CI
  harness.
- Test count: **252 `.tcyr` unit assertions** (up from 239) +
  **20,101 fuzz assertions** + 18 integration + bench harness.

### Documentation expansion

- **`docs/architecture/overview.md`** — added "Library boundary and
  distribution" section covering the binary/library split, the
  `cyrius distlib` mechanics, the 9-file bundle-order map with
  cross-module dependencies annotated, the publish flow
  (edit → test → distlib → integration probe → commit), and the
  cyrius-toolchain floor for consumers. Module Structure table now
  has an "In library bundle" column marking `main.cyr` as binary-
  only. Pointer note at the top directing security reviewers to the
  threat-model doc.
- **`docs/architecture/threat-model.md`** — new. Structured for an
  external security reviewer: five in-scope attacker classes
  (A1 local unpriv, A2 compromised authorised, A3 co-located
  process, A4 filesystem, A5 hostile policy author) and three
  out-of-scope (A6 kernel, A7 physical, A8 supply chain); trust
  boundary diagram + table; a ten-entry assumption register
  (S1–S10) documenting what must hold for mitigations to work;
  ten threat entries (T1 shell injection through T10 co-located
  setuid) each with attack description, mitigation, residual risk,
  and test coverage references; non-goals; open gaps table cross-
  referencing the port-regressions list.
- **`SECURITY.md`** — 0.1.x → 0.2.x version row swap; security
  properties list updated to reflect cyrius-era implementation
  (`secret var`, per-TTY timestamp, hashmap-backed env blocklist);
  new "Threat Model" section links the threat-model doc +
  architecture overview.

### Documentation audit

- **`docs/architecture/overview.md`** — purged Rust-era claims:
  threat model row now names `secret var pbuf[1024]` (v5.3.5) instead
  of the `zeroize` crate; group-resolution row honestly states
  `/etc/group` parsing with the NSS path tracked for cyrius 5.5.x;
  auth flow reflects the `su` shim + `SHK_ERR_PAM_UNAVAILABLE`
  fall-through rather than "try PAM first"; consumer-API example
  rewritten in cyrius syntax pointing at `dist/shakti.cyr` and
  `docs/guides/integration.md`.
- **`docs/development/dependency-watch.md`** — fully rewritten for
  the cyrius era. Active surface: cyrius toolchain pin, Linux
  syscall ABI, `/etc/passwd` + `/etc/group` format, `/usr/bin/su`
  semantics, PAM service config file, mini-TOML parser limits. Old
  RUSTSEC-2025-0040 / RUSTSEC-2023-0059 / RUSTSEC-2023-0040
  (`pam` 0.7.0 → `users` 0.8.1) advisories moved to **Resolved** —
  the Rust dependency graph is gone.
- **`docs/adr/001-timestamp-o-nofollow.md`** — added post-port note:
  decision preserved verbatim; implementation no longer goes through
  `nix::fcntl::open`, calls `syscall(SYS_OPEN, …, O_NOFOLLOW, 0600)`
  directly.
- **`docs/adr/002-initgroups-for-target-user.md`** — added post-port
  note: decision preserved; implementation regressed from
  `nix::unistd::initgroups` (NSS-aware) to local-files
  `/etc/group` parsing (`src/identity.cyr:identity_lookup_gids`);
  LDAP/sssd gap revisits at cyrius 5.5.x. Cross-references ADR-005.
- **`CLAUDE.md`** — replaced the cargo-era cleanliness-check
  command list (`cargo fmt`, `cargo clippy`, `cargo audit`,
  `cargo deny`, `cargo doc`) with the cyrius-era equivalents
  (`cyrius test`, `sh tests/integration/cli.sh`, `cyrfmt --check`,
  `cyrlint`, `cyrius build`, `cyrius distlib`). Added an explicit
  note that `dist/shakti.cyr` drift is a commit-blocker.
  Version-sync checklist updated: VERSION → `cyrius.cyml`
  (`${file:VERSION}`) → `shakti_version_string()` in `src/lib.cyr`
  → zugot recipe. Project-type line now "Cyrius binary + library"
  (was "Binary crate").
- **README** — "Consumer API" section references both the bundle
  and piecemeal module pickup; ark listed as fourth consumer
  alongside argonaut / agnoshi / daimon; points readers at
  `docs/guides/integration.md`.

### Library publishing

- **`dist/shakti.cyr`** — 80 KB self-contained bundle generated by
  `cyrius distlib`. Consumers pull it via
  `[deps.shakti] modules = ["dist/shakti.cyr"]` against a pinned tag,
  same pattern sigil / nous / yukti use. Commit the bundle alongside
  source — `cyrius distlib` after any `src/*.cyr` edit.
- **`cyrius.cyml [build] modules`** — declares the 9-module bundle
  order (`src/lib.cyr` first for constants, then validate → env →
  identity → timestamp → audit → auth → policy → api). `src/main.cyr`
  is deliberately excluded (it's the CLI entry; its top-level
  `syscall(SYS_EXIT)` would fire inside the consumer).
- **`tests/integration/consumer_probe.cyr`** — 8-assertion smoke test
  that compiles against `dist/shakti.cyr` with only the declared
  stdlib surface and exercises `validate_username`, `parse_policy`,
  `command_matches`, and `is_unsafe_env`. Wired into
  `tests/integration/cli.sh` so a stale bundle becomes a test
  failure. Regenerate with `cyrius distlib` and re-run.
- **`docs/guides/integration.md`** — consumer-facing guide covering
  both the bundle and piecemeal module patterns, dependency ordering,
  public API surface table, default paths, bundle-regeneration, and
  cyrius version floor.
- **README** — updated "Consumer API" section to point at both
  `dist/shakti.cyr` and individual modules; added ark as the fourth
  consumer alongside argonaut / agnoshi / daimon.

### Security

- **Supplementary groups regression closed**: `_exec_target` no
  longer calls `setgroups(0, NULL)` before dropping privileges.
  It now populates the target user's supplementary group list via
  `identity_lookup_gids` (initgroups(3) parity using `/etc/group`),
  matching the rust-old build with the `pam` feature disabled.
  LDAP/sssd resolution is still a known gap and remains tracked
  for the NSS-via-libc bite.

## [0.2.0] - 2026-04-17

### Changed

- **Language port**: reimplemented in [Cyrius](https://github.com/MacCracken/cyrius)
  (pinned to 5.2.1). The original Rust implementation is preserved in
  `rust-old/` for reference. Binary size dropped from ~1.8 MB (Rust release,
  dynamic libc + PAM) to 410 KB (static, no runtime).
- Project layout adopts patra flatten style: vendored stdlib in `lib/`,
  module-per-file in `src/`, tests in `tests/tcyr/`, benches in `tests/bcyr/`.
- `cyrius.cyml` replaces `Cargo.toml` as the build manifest.
- Error handling: anyhow::Result → integer `SHK_ERR_*` codes with
  `shk_err_msg()` for human-readable messages.
- Structs: serde-derive → manual offset enums + `store64`/`load64`
  accessors (`PolicyOff`, `DefOff`, `RuleOff`, `CfgOff`, `EvalOff`,
  `AuthzOff`, etc.).
- `AuthzResult` + `Evaluation` expose error codes and boolean fields
  rather than Rust enums / `#[non_exhaustive]` wrappers.
- Test suite grew from 130 to 219 cases across 8 `.tcyr` files.

### Added

- Benchmarks (`tests/bcyr/core.bcyr`) for the hot paths: command_matches
  (4 variants), validate_command, parse_policy, check_authorization
  (3 variants), sanitize_environment.
- `scripts/bench-history.sh` rewritten for cyrius bench output format.
- Local mini-TOML parser in `src/policy.cyr` — the stdlib parser only
  recognises `[[array]]` sections, but shakti's schema uses `[defaults]`.
- README expanded with architecture map and consumer-integration guidance.

### Removed

- `Cargo.toml`, `Cargo.lock`, `deny.toml`, `rust-toolchain.toml` (Rust
  tooling; see `rust-old/` if needed).
- `src/*.rs` (moved into `rust-old/` by `cyrius port`).
- Rust-only dependencies: anyhow, serde, toml, tracing, tracing-journald,
  nix, zeroize, pam, criterion.

### Security

- Preserved: O_NOFOLLOW timestamp open, per-TTY isolation, root-ownership
  checks on policy files / timestamps / include fragments, LD_*
  prefix catch-all, BASH_FUNC_* prefix catch-all, shell-metacharacter
  rejection in command names, path-traversal rejection in usernames,
  argument-level wildcard matching.
- **PAM**: the Rust `pam` crate integration is stubbed in `src/auth.cyr`
  pending a libpam binding via `dynlib.cyr`. All authentication currently
  falls through to the `/usr/bin/su` shim — same security posture as the
  Rust build with the `pam` feature disabled.
- **NSS group resolution**: the Rust `getgrouplist(3)` call is replaced
  with direct parsing of `/etc/group`. This regresses LDAP/sssd support
  that was added in 0.1.x; restoring it will require a libnss binding.
  File this as a known gap for consumers using remote identity stores.
- **initgroups**: the target process's supplementary groups are cleared
  via `setgroups(0, NULL)` rather than populated. `setgid`/`setuid` still
  set the primary GID/UID correctly, but callers who rely on supplementary
  group membership of the target user will see different behaviour than
  the Rust build.

---

The remainder of 0.2.0's scope was landed in Rust before the port and
is preserved verbatim from the pre-port changelog:

### Added

- Argument-level wildcard matching in policy patterns (e.g., `/usr/bin/systemctl restart *`)
- `BASH_FUNC_*` prefix block in env sanitization (ShellShock defense)
- 8 additional unsafe env vars: `GEM_HOME`, `GEM_PATH`, `BUNDLE_GEMFILE`, `LUA_PATH`, `LUA_CPATH`, `PHPRC`, `PERL_MM_OPT`, `INPUTRC`
- `#[non_exhaustive]` on `Evaluation` struct
- `--check` / `-c` CLI flag for policy linting (detects unreachable rules, dangerous wildcards, duplicate rules, missing user/group)
- `lint_policy()` function in library API for programmatic policy validation
- `cargo-fuzz` harnesses for `parse_policy`, `validate_command`, `command_matches`, `validate_username`
- 53 new tests (130 total, up from 77) covering security-critical paths
- Architecture documentation (`docs/architecture/overview.md`)
- 4 ADRs: O_NOFOLLOW timestamps, initgroups, argument matching, env sanitization strategy
- Dependency watch tracking (`docs/development/dependency-watch.md`)
- Root glob pattern fix: `/*` now correctly matches binaries in `/`

### Changed

- Group resolution now uses `getgrouplist(3)` via NSS instead of parsing `/etc/group` directly
- Supplementary group setup uses `initgroups(3)` instead of single-GID `setgroups`
- `command_matches` now extracts the binary portion for path-level matching when commands include arguments
- Bench history script rewritten to correctly parse criterion output format

### Security

- **Authorization bypass (critical)**: `check_authorization` now receives the full command string with arguments, not just the binary path. Previously, `deny_commands` patterns with arguments (e.g., `/usr/bin/systemctl stop firewall`) were completely ineffective at runtime.
- **Timestamp TOCTOU**: `update_timestamp` now uses `O_NOFOLLOW | O_CREAT | O_TRUNC` via `nix::fcntl::open()`, eliminating the race window between the symlink check and the file write.
- **Supplementary groups**: Target process now inherits the target user's full supplementary group list via `initgroups(3)`, not just the primary GID. Missing groups could have caused privilege inconsistencies.
- **Group resolution**: Caller's group membership is now queried via NSS (`getgrouplist`), supporting LDAP/sssd environments. Previously only `/etc/group` was read.
- **ShellShock**: Environment variables matching `BASH_FUNC_*` are now blocked by prefix, preventing exported bash function injection.
- **Interpreter injection**: Added `GEM_HOME`, `GEM_PATH`, `BUNDLE_GEMFILE` (Ruby), `LUA_PATH`, `LUA_CPATH` (Lua), `PHPRC` (PHP), `PERL_MM_OPT` (Perl), `INPUTRC` (readline) to the blocked env var list.
- **Non-UTF8 paths**: Command resolution now returns an explicit error for non-UTF8 paths instead of silently passing an empty string to authorization.

### Added

- Real PAM authentication via `pam` crate (feature-gated, `--features pam`)
- `auth` module with `authenticate()`, `pam_authenticate()`, `su_authenticate()`
- PAM falls back to `/usr/bin/su` shim when PAM service is unavailable
- PAM service config example (`etc/pam.d/shakti`)
- `audit` module with structured journald logging via `tracing-journald`
- `AuditAction` enum for typed audit events (`Command`, `AuthFailure`, `TimestampInvalidated`)
- `init_tracing()` — unified tracing setup with journald + stderr layers
- Policy fragment support via `include_dir` in `[defaults]`
- Fragment files (`*.toml`) loaded in lexicographic order with security checks
- Secure memory clearing of password buffers via `zeroize` crate
- Consumer API module (`api.rs`) with `ShaktiConfig`, `Evaluation`, `AuthMode`
- `ShaktiConfig::builder()` for ergonomic programmatic configuration
- `evaluate()` / `evaluate_with_policy()` — high-level entry points for consumers
- `AuthMode::Interactive` / `TimestampOnly` / `Skip` for different consumer needs
- Non-interactive auth path for daimon (agent operations via `AuthMode::TimestampOnly`)
- Module structure: split into `policy`, `env`, `timestamp`, `validate`, `api` modules
- Library crate (`lib.rs`) alongside binary for consumer and benchmark access
- Criterion benchmarks for all hot paths (`benches/core.rs`)
- Benchmark history tracking script (`scripts/bench-history.sh`)
- Roadmap (`docs/development/roadmap.md`)
- Per-TTY timestamp isolation (prevents cross-session credential reuse)
- Timestamp file ownership verification (must be root-owned)
- Timestamp symlink detection and rejection
- Timestamp directory permissions (0700 root-only)
- Secure password input via termios echo disable with RAII drop guard
- Signal masking (SIGINT/SIGTSTP/SIGQUIT) during authentication phase
- File descriptor sanitization (close fds > stderr before exec)
- Username path-traversal validation in timestamp operations
- Shell metacharacter rejection in command names
- `is_executable` check in command resolution (was `exists()`)
- LD_* prefix catch-all in environment sanitization
- 17 interpreter injection env vars (PYTHONPATH, NODE_OPTIONS, etc.)
- 5 additional LD_* variables to explicit blocklist
- `#[non_exhaustive]` on `AuthzResult` enum
- `#[must_use]` on pure functions

### Changed

- Rebranded from `agnos-sudo` to `shakti` in all user-facing strings
- Policy file non-root ownership is now a hard failure (was a warning)
- `update_timestamp` errors are now logged (was silently ignored)
- Cleaned unused license allowances from `deny.toml`

### Security

- **Timestamp tampering**: Files are now verified for root ownership and symlink attacks
- **Terminal echo**: Passwords are no longer visible during input
- **Signal safety**: Auth phase cannot be interrupted by SIGINT leaving partial state
- **fd leaking**: Child processes no longer inherit open file descriptors
- **Environment**: All LD_* variables blocked by prefix, not just an explicit list
- **Interpreter injection**: PYTHONPATH, NODE_OPTIONS, PERL5LIB, etc. now blocked
- **Path traversal**: Usernames with `/`, `..`, null bytes rejected in timestamp paths
- **Shell injection**: Command names with `;`, `|`, `$()`, etc. now rejected
- **Command resolution**: Non-executable files and directories no longer accepted

## [0.1.0] - 2026-04-03

### Added

- Initial extraction from AGNOS monolith (`userland/agnos-sudo/`)
- PAM authentication with rate limiting (max 3 attempts)
- TOML-based policy file (`/etc/agnos/sudoers.toml`)
- Per-user, per-group, and per-command rules
- Environment sanitization (LD_*, IFS, BASH_ENV, etc.)
- Command argument validation against shell injection
- Timestamp-based credential caching (configurable TTL)
- Audit logging of all authentication attempts
- 44 tests
