# Policy Examples

Drop-in sudoers.toml examples covering the main shakti feature
surface. Copy, adapt, `--check`, deploy.

## Files

| File | Purpose |
|---|---|
| [`sudoers.toml`](sudoers.toml) | Single-file annotated policy — every feature (defaults, user / group / wildcard rules, `deny_commands`, NOPASSWD, basename / dirglob / arg-wildcard patterns). Lift-and-modify starting point. |
| [`fragments/main.toml`](fragments/main.toml) | Top-level policy that declares `[defaults]` and delegates all rules to an `include_dir`. |
| [`fragments/00-base.toml`](fragments/00-base.toml) | Baseline rules every system gets (wheel full-access, self-service passwd). |
| [`fragments/10-deploy.toml`](fragments/10-deploy.toml) | CI / deploy role — NOPASSWD, narrow command set, explicit denies for destructive patterns. |
| [`fragments/20-ops.toml`](fragments/20-ops.toml) | Ops team — diagnostics + log access, auth required. |

## Deployment

### Single-file

```sh
sudo install -o root -g root -m 0644 docs/examples/sudoers.toml /etc/agnos/sudoers.toml
sudo shakti -c -p /etc/agnos/sudoers.toml   # lint before you need it
```

### Fragment layout

```sh
sudo install -o root -g root -m 0755 -d /etc/agnos/sudoers.d
sudo install -o root -g root -m 0644 docs/examples/fragments/main.toml /etc/agnos/sudoers.toml
sudo install -o root -g root -m 0644 docs/examples/fragments/00-base.toml /etc/agnos/sudoers.d/00-base.toml
sudo install -o root -g root -m 0644 docs/examples/fragments/10-deploy.toml /etc/agnos/sudoers.d/10-deploy.toml
sudo install -o root -g root -m 0644 docs/examples/fragments/20-ops.toml /etc/agnos/sudoers.d/20-ops.toml
sudo shakti -c
```

The fragment loader verifies each file is root-owned and
non-world-writable (`src/policy.cyr:_shk_load_fragments`); the
integration tests cover the defense gates at
`tests/tcyr/fragments.tcyr`.

## Formatting limits

Multi-line arrays are supported (shakti 0.2.1+ — ported from the
canonical cyrius v5.4.17 `lib/toml.cyr` algorithm). Both styles
parse identically:

```toml
# Single line
commands = ["/usr/bin/systemctl restart *", "/usr/bin/docker"]

# Multi-line (recommended for reviewability)
commands = [
    "/usr/bin/systemctl restart *",
    "/usr/bin/docker",
]
```

Still **not supported** by shakti's local parser:

- **`#` comments inside array bodies.** An unquoted `#` between `[`
  and `]` is treated as content and will confuse
  `_shk_parse_str_array` — the defensive advance-guard prevents
  infinite loops, but the entry is silently dropped. To disable a
  command temporarily, move the `#` to a line outside the array:

  ```toml
  # disabled pending security review:
  # "/usr/bin/risky-tool",
  commands = [
      "/usr/bin/foo",
      "/usr/bin/baz",
  ]
  ```

  Or comment out the entire `[[rules]]` table.

- **Triple-quoted strings (`"""..."""`)**, datetimes, inline tables,
  heterogeneous arrays, dotted keys. The parser is deliberately
  minimal — shakti's sudoers schema uses scalar strings / ints /
  bools, `[defaults]` + `[[rules]]` sections, and string arrays.

Inline comments (`# text`) on scalar key-value lines are stripped
up to `\n`. Mixed `"`/`'` string quoting works.

## File permissions

Shakti **requires**:

- Policy file (`/etc/agnos/sudoers.toml`) owned by uid 0, not world-writable, not a symlink.
- `include_dir` (`/etc/agnos/sudoers.d/`) owned by uid 0, not world-writable.
- Each `*.toml` fragment in the directory: same two gates, applied independently.

The correct mode for policy files is `0644` (world-readable, root-
writable). Operations staff often want to read them; the security
property is "root owns and controls writes", not secrecy.

## Linting

The `--check` flag runs `lint_policy` over the configured policy
(plus any fragments) and reports:

- `[ERROR]` — rule has neither user nor group (will never match);
  wildcard-user NOPASSWD with ALL commands (worst-case).
- `[WARN]` — wildcard-user with NOPASSWD; duplicate user/group/run_as
  triplets (only first matches); unreachable deny pattern (no
  corresponding allow entry would ever let the command through);
  `timestamp_ttl = 0` with `require_auth = true` (prompts every
  invocation — intentional or oversight?).

Example output:

```
$ shakti -c
  [WARN]  rule[2]: rule grants all users (*) NOPASSWD access — verify intended
  [WARN]  rule[5]: duplicate user/group/run_as as a later rule — only the first matches
```

Warnings are advisory; errors cause a non-zero exit, so CI can gate
merges on `shakti -c`.

## Rule ordering

First-match-wins. Implications:

1. Put **more specific** rules before **more general** ones. A
   `user = "alice"` rule must come before a `group = "wheel"` that
   also grants alice, otherwise alice always hits the group rule
   first.
2. `deny_commands` is evaluated **within** a rule, not across rules.
   If rule 1 allows `/usr/bin/foo` and rule 2 denies `/usr/bin/foo`,
   the command is allowed — rule 1 matched first and rule 2 never
   runs.
3. For cross-rule denials, either (a) put the deny rule first and
   omit the matching allow rule, or (b) inline the deny in every
   allow rule that could reach the command.

## Cross-references

- Architecture: [`../architecture/overview.md`](../architecture/overview.md)
- Threat model: [`../architecture/threat-model.md`](../architecture/threat-model.md)
- Argument-level matching ADR: [`../adr/003-argument-level-command-matching.md`](../adr/003-argument-level-command-matching.md)
- Env sanitisation ADR: [`../adr/004-env-sanitization-strategy.md`](../adr/004-env-sanitization-strategy.md)
- Consumer integration (library API): [`../guides/integration.md`](../guides/integration.md)
