# Shakti Mini-TOML Parser Limits

**Status**: open. Surfaced 2026-04-19 while writing
`docs/examples/sudoers.toml` + the fragment files under
`docs/examples/fragments/`. The examples smoke-test
(`tests/tcyr/examples_smoke.tcyr`) forced each array onto a single
line to parse cleanly; operators reading the examples see an ergonomic
regression compared to the policy shape sudo users expect.

**Scope**: shakti's own **local** mini-TOML parser in
`src/policy.cyr` (`parse_policy`, `_shk_def_set`, `_shk_rule_set`,
`_shk_parse_str_array`). This is the parser shakti owns; changes
land here.

**Filed for**: language-agent review — what's the right shape for
the downstream fix? Straight patch to `_shk_parse_str_array` +
`parse_policy`'s line-scan, or rework the value extractor more
broadly?

## What's limited

The parser today assumes a strict one-key-per-line, one-value-per-
line shape. The cases below all fail silently or partially:

### 1. Multi-line array values

Common TOML idiom — operators write one pattern per line for
reviewability. Parsing stops at the first `\n` after `=`.

```toml
# FAILS — parser truncates at the newline after "["
commands = [
    "/usr/bin/systemctl restart *",
    "/usr/bin/systemctl reload *",
    "/usr/bin/journalctl -u *",
]
```

Actual parse result: `commands` becomes an empty vec (because the
captured value is just `[` and `_shk_parse_str_array` sees no `]`).

Workaround today: collapse to a single line.

```toml
# OK
commands = ["/usr/bin/systemctl restart *", "/usr/bin/systemctl reload *", "/usr/bin/journalctl -u *"]
```

See `docs/examples/sudoers.toml` and
`docs/examples/fragments/*.toml` — all arrays are single-line
specifically because of this limit.

### 2. Inline comments inside arrays

Even if (1) is fixed, `_shk_parse_str_array` has no `#` comment
handler. An unquoted `#` inside the array body would either be
treated as garbage (triggering the "skip leading whitespace" →
"try quoted string" → "skip comma" loop without advancing) or an
infinite loop:

```toml
commands = [
    "/usr/bin/foo",          # short form
    # "/usr/bin/bar",        # disabled pending review
    "/usr/bin/baz",
]
```

### 3. Continuation across quoted newlines

TOML allows `\n` inside `"""triple-quoted"""` strings. Shakti's
parser doesn't recognise triple quotes. Not load-bearing for the
sudoers schema today (all values are short paths + argv glob
patterns) but a reviewer should decide whether it's worth
supporting.

### 4. `max_command_len = 4096  # comment` on same line

This **does** work today — the inline-comment stripping in
`parse_policy` handles `# ... \n` for scalar values. The limit
only bites inside array bodies (case 2).

## Impact

| Severity | Case | Who sees it |
|---|---|---|
| Ergonomic | 1 — multi-line arrays | Operators writing policies |
| Ergonomic / quiet-wrong | 2 — comments inside arrays | Operators trying to disable a rule temporarily |
| Low | 3 — triple-quoted strings | Nobody today; would be nice |

Security impact: **none**. Every gate (shell metachar rejection,
policy file ownership, authz evaluator) still runs against whatever
the parser extracted. A malformed array becomes an empty list →
the rule matches no commands → command falls through to the next
rule or the default-deny. Fail-closed.

## Reproduction

```sh
# Single-line: works
cat > /tmp/ok.toml <<'EOF'
[[rules]]
user = "alice"
commands = ["/usr/bin/id", "/usr/bin/whoami"]
EOF
build/shakti -c -p /tmp/ok.toml   # (assuming root-owned; or use examples_smoke.tcyr)

# Multi-line: silently drops everything after "["
cat > /tmp/bad.toml <<'EOF'
[[rules]]
user = "alice"
commands = [
    "/usr/bin/id",
    "/usr/bin/whoami",
]
EOF
```

Programmatic repro — `tests/tcyr/examples_smoke.tcyr` already
demonstrates the working case. A failure mode could be captured by
adding:

```
fn t_multiline_array_silently_fails() {
    var s = "[[rules]]\nuser = \"alice\"\ncommands = [\n    \"/usr/bin/id\",\n    \"/usr/bin/whoami\",\n]\n";
    var p = parse_policy(s, strlen(s));
    var r = vec_get(policy_rules(p), 0);
    assert_eq(vec_len(rule_commands(r)), 0,
        "current parser truncates multi-line arrays to empty");
}
```

(Test not added yet — it would encode the limitation as a property
and need updating when the fix lands.)

## Approach sketches (for agent review)

Two shapes seem plausible; the agent should pick or propose a
third:

### A. Minimal surgical patch (case 1 only)

1. In `parse_policy`'s value-extraction block, after finding `eq`,
   peek past whitespace for the first non-space character.
2. If that character is `[`, scan forward through `buf` for the
   matching `]`, tracking quote state and bracket depth, ignoring
   `\n`. Set `lend2` to the position after the closing `]` (or the
   `\n` after it).
3. Otherwise, the old single-line logic applies unchanged.

Comment-stripping inside the array body remains a known gap (case
2). Operators document accordingly.

- **Pros**: small diff, covers the 90% case, `_shk_parse_str_array`
  untouched.
- **Cons**: case 2 still open; two separate follow-ups if we ever
  want it.

### B. Full re-worked value extractor

Replace the `lend2 = next \n` scan with a state-machine value
parser that understands:
- Scalar value → terminated by `\n` (minus trailing `# ...`)
- Array value → terminated by matching `]`, with `#` comments
  stripped per-line inside the body
- (Optionally) triple-quoted string value → terminated by matching `"""`

`_shk_parse_str_array` gets a sibling pass that strips `#`-to-`\n`
comments before the `_shk_copy_trim` call.

- **Pros**: covers cases 1, 2, and sets up 3 if we ever want it.
- **Cons**: larger diff, more test surface; `parse_policy`'s
  control flow grows a new arm.

### C. Other?

Agent call. The parser is ~200 lines today; either approach is
bounded.

## Acceptance criteria

If a fix lands:

1. `tests/tcyr/examples_smoke.tcyr` continues to pass.
2. A new test case covers the multi-line-array shape explicitly
   (currently implicit via the single-line fallback).
3. `docs/examples/sudoers.toml` + `docs/examples/fragments/*.toml`
   get un-squished back to multi-line arrays.
4. `docs/examples/README.md` "Formatting limits" section is updated
   or removed to reflect the new parser surface.
5. The `fuzz.tcyr` `fuzz_parse_policy` harness continues to pass
   (no crash regressions on random inputs).

## Non-goals

- **Do not** migrate to cyrius's `lib/toml.cyr` — that's a separate
  upstream decision outside shakti's scope. Shakti's local parser
  stays local; only its internal completeness improves.
- Full TOML 1.0 compliance. Shakti only needs what the sudoers
  schema uses: scalar strings / ints / bools, single-level
  `[table]` and `[[array of tables]]`, string arrays, comments.
  Inline tables, datetimes, heterogeneous arrays, and dotted keys
  are not in scope.
