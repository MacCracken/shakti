# Shakti Mini-TOML Parser Limits

**Status**: **resolved in shakti 0.2.1** (2026-04-20). Case 1
(multi-line arrays) closed by porting cyrius v5.4.17's canonical
algorithm from `lib/toml.cyr` into `src/policy.cyr:parse_policy`.
Case 2 (`#` inside array body) has a defensive advance-guard so it
fails closed; the case itself stays out of scope with README-level
workarounds documented. Case 3 (triple-quoted strings) deferred
indefinitely.

**History** — surfaced 2026-04-19 while writing
`docs/examples/sudoers.toml` + the fragment files under
`docs/examples/fragments/`. The examples smoke-test
(`tests/tcyr/examples_smoke.tcyr`) forced each array onto a single
line to parse cleanly; operators reading the examples saw an
ergonomic regression compared to the policy shape sudo users expect.

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

---

## Resolution (language-agent, 2026-04-19)

**Decision: Option A (surgical patch, case 1 only).** Ship case 2
(comments inside arrays) as a documented limitation; defer case 3
(triple-quoted strings) indefinitely.

### Why A over B

1. **Scope-fit for pre-1.0 shakti.** Shakti is at 0.2.x with
   NSS/PAM as the next major deliverable (cyrius v5.5.x pillar 3).
   A state-machine rewrite in `parse_policy` is engineering you'd
   re-evaluate at 0.3+ when the schema grows — too early to lock
   the parser shape.
2. **Bounded diff = low risk in security-adjacent code.** The
   `fuzz_parse_policy` harness is the backstop; a ~30-50 LOC
   localized change in the value-scan is far less likely to
   introduce regressions than a 150+ LOC state machine.
3. **Case 2 has ergonomic workarounds today.** Operators
   temporarily disabling a rule can:
   - Move the commented line **outside** the array (neighbor-line
     `# disabled "/usr/bin/bar"` followed by the live array).
   - Add a rule-level `enabled = false` boolean on the table
     (schema change — propose at shakti's next schema pass).
   - Comment out the entire `[[rules]]` table rather than a single
     command within it.
   None are as ergonomic as in-array `#`, but none are blocking.
4. **ARK-dep framing.** Shakti will be consumed by ARK as a
   `[deps.shakti]` entry — **not** folded in. Shakti's parser
   stays shakti's, and the investment calculus reflects that:
   fix what operators hit today, don't engineer for hypothetical
   future callers.
5. **The 90% case is all that matters for the examples
   regression.** `docs/examples/sudoers.toml` and
   `docs/examples/fragments/*.toml` can un-squish the moment
   case 1 lands; case 2 affects a narrower operator workflow
   that can wait.

### Concrete shape (what shakti-agent implements)

In `parse_policy` (src/policy.cyr:313+), locate the value-extract
block where `lend2` is set to the next `\n` after `eq`. Replace
with:

```
# After eq, skip leading whitespace to find the value's first char.
var vstart = eq + 1;
while (vstart < lend && (load8(buf + vstart) == 32 || load8(buf + vstart) == 9)) {
    vstart = vstart + 1;
}

# If value starts with '[', scan for matching ']' tracking quote
# and bracket state, ignoring '\n'. Otherwise fall back to old
# single-line behaviour.
if (load8(buf + vstart) == 91) {       # '[' = 0x5B = 91
    var depth = 1;
    var in_quote = 0;
    var i = vstart + 1;
    while (i < buflen && depth > 0) {
        var ch = load8(buf + i);
        if (in_quote == 1) {
            if (ch == 34) { in_quote = 0; }   # '"'
            # else: absorb everything including \n
        } else {
            if (ch == 34) { in_quote = 1; }
            elif (ch == 91) { depth = depth + 1; }   # nested '[' — defensive
            elif (ch == 93) { depth = depth - 1; }   # ']' = 0x5D = 93
        }
        i = i + 1;
    }
    # lend2 is the end of the array span (position after ']')
    lend2 = i;
    # Advance past optional trailing '\n' so the outer loop resumes cleanly
    if (lend2 < buflen && load8(buf + lend2) == 10) { lend2 = lend2 + 1; }
} else {
    # Unchanged single-line scan — old lend2 = next '\n' logic
    ...
}
```

Then `_shk_parse_str_array` (src/policy.cyr:184) receives the
multi-line value verbatim (including embedded `\n` whitespace). Its
existing whitespace-skip loop already tolerates `\n` as whitespace
since `_shk_copy_trim` trims everything ≤ ASCII 32. No change
needed to `_shk_parse_str_array` itself.

Edge cases the sketch above handles correctly:
- `commands = []` (empty array) — depth hits 0 after the `]`, fine.
- Quoted `]` inside a string (`commands = ["weird]path"]`) — quote
  state prevents bracket-depth from decrementing inside strings.
- Trailing comma (`"a",` then `]` on next line) — `_shk_parse_str_array`
  already tolerates trailing commas per its current comma-skip logic.

Edge cases it deliberately does NOT handle (case 2):
- `#` comments inside the array body are preserved into the raw
  value and passed to `_shk_parse_str_array`. If the `#` is
  unquoted, the existing parser will either trip on the `#` as
  unexpected non-string content (error path) or loop without
  advancing (the "infinite loop" risk the issue doc flagged). Guard
  against the infinite loop by ensuring `_shk_parse_str_array`'s
  main loop always advances by ≥1 byte per iteration even on
  unexpected input — and emit a clear error rather than silently
  dropping entries. That's a small adjacent fix worth bundling.

### Cyrius version to pin

**Shakti should be on cyrius ≥ 5.4.13 before starting this work.**
Current `cyrius.cyml` pin is `5.4.11`; bump to `5.4.13` as a
prerequisite. Nothing in v5.4.12 / v5.4.12-1 / v5.4.13 breaks
shakti — the three bumps are additive (tool-cleanup packaging,
release-lib dep-tag fix, `fncall7`/`fncall8` stdlib additions) —
but pinning current keeps shakti on a supported toolchain while
this parser work lands.

### Expected shakti release

**Shakti 0.2.1 (patch release).** Pure parser fix, no schema
change, no new dependencies. The `fuzz_parse_policy` harness gates
regression; the existing `examples_smoke.tcyr` test stays green;
add a new positive-assertion test `t_multiline_array_parses` that
encodes the fixed behaviour (instead of the failure-mode test the
issue doc sketches at line 124 — that was for pre-fix
documentation).

### Timeline — hold until after cyrius v5.4.17 ships

**Do not start shakti-side implementation until cyrius v5.4.17
ships.** Rationale: `lib/toml.cyr` has the *same* multi-line
array limit (confirmed 2026-04-19 by reading `lib/toml.cyr:192`
— the unquoted-value scan terminates at the first `\n`,
identical to shakti's own parser). v5.4.17 is a narrow single-
issue release dedicated to this fix (split out from the
originally-planned closeout bundle precisely so shakti doesn't
have to wait behind a big grab-bag release). v5.4.17 lands the
canonical fix in `lib/toml.cyr` with the same algorithm
described in "Concrete shape" above, plus a
`tests/tcyr/toml_multiline.tcyr` regression gate.

Holding until v5.4.17 lets shakti 0.2.1 **copy the canonical
fix pattern verbatim** rather than invent-then-diverge. When
v5.4.17 tags:

1. Bump `cyrius.cyml` pin `5.4.11` → `5.4.17` (picks up the
   v5.4.12 → v5.4.12-1 → v5.4.13 → v5.4.14 → v5.4.15 → v5.4.16
   intermediate bumps too — all additive, none break shakti).
2. Port the `lib/toml.cyr` fix algorithm to `src/policy.cyr`'s
   `parse_policy` value-extraction block. The cyrius side is
   the reference implementation; shakti's is a local copy
   because the non-goal is explicit: don't migrate to
   `lib/toml.cyr`.
3. Ship shakti 0.2.1 with the shakti-side fix + the un-squished
   `docs/examples/*.toml` files.

**No downstream shakti consumer is blocked** by this hold.
Operators writing policies today can keep using single-line
arrays (the existing examples shape); the ergonomic
regression is real but non-urgent. The brief v5.4.17 delay
is preferable to landing a shakti-local fix that diverges from
upstream's canonical pattern.

### Acceptance (re-stated from the issue + language-agent gates)

1. `tests/tcyr/examples_smoke.tcyr` continues to pass.
2. New test `t_multiline_array_parses` asserts `vec_len` matches
   the expected array length (not 0).
3. `docs/examples/sudoers.toml` + `docs/examples/fragments/*.toml`
   un-squished back to multi-line arrays.
4. `docs/examples/README.md` "Formatting limits" updated: case 1
   removed from the list, case 2 documented with the
   workarounds above, case 3 marked "not in scope".
5. `fuzz.tcyr` `fuzz_parse_policy` continues to pass — no crash
   regressions on random inputs.
6. `_shk_parse_str_array` main loop always advances ≥ 1 byte per
   iteration on unexpected input (defensive against case 2's
   infinite-loop risk even though case 2 isn't supported).

### Not in this release

- Case 2 (in-array `#` comments) — documented limitation with
  workarounds.
- Case 3 (triple-quoted strings) — deferred indefinitely; not in
  the sudoers schema scope.
- `lib/toml.cyr` migration — separate decision at shakti 0.3+ or
  never. Not forced by ARK-dep framing; shakti's parser stays
  shakti's.
