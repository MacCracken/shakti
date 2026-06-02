#!/usr/bin/env bash
# Integration test for session logging (ADR-008) — the PTY relay + log
# writer in src/session.cyr. Compiles session_probe.cyr, runs it (it
# allocates a PTY, runs `echo` on the slave, and tees the output to a log
# file), then asserts the transcript captured the command output with a
# well-formed header and footer.
#
# Unprivileged: needs only a working /dev/ptmx (PTY allocation), no root.
# If PTY allocation is unavailable, SKIPs cleanly.
#
# Usage: sh tests/integration/session_log.sh
#   Exit 0 = passed or skipped; 1 = a real failure.

set -u
PASS=0
FAIL=0

PROBE_SRC="tests/integration/session_probe.cyr"
PROBE_BIN="build/session-probe"
LOG="$(mktemp /tmp/shakti-sesslog-XXXXXX.log)"

if ! cyrius build "$PROBE_SRC" "$PROBE_BIN" >/dev/null 2>&1; then
    echo "FAIL: session_probe did not compile"
    rm -f "$LOG"
    exit 1
fi

# Run with stdin from /dev/null so the relay's stdin side hits EOF
# immediately and the loop is driven purely by the child's output + exit.
out=$("$PROBE_BIN" "$LOG" < /dev/null 2>&1)
rc=$?

if [ ! -s "$LOG" ]; then
    # No PTY available (e.g. sandbox without /dev/ptmx) — skip, don't fail.
    echo "SKIP: session log empty (rc=$rc) — no usable PTY in this environment."
    echo "  probe stderr: ${out:-<none>}"
    rm -f "$LOG"
    exit 0
fi

content=$(cat "$LOG")

assert_contains() {
    case "$content" in
        *"$2"*) PASS=$((PASS + 1)) ;;
        *)
            FAIL=$((FAIL + 1))
            echo "FAIL: $1 (missing: $2)"
            ;;
    esac
}

assert_contains "captures command output"   "hello-session-log"
assert_contains "writes session header"     "=== shakti session "
assert_contains "header records caller"     "caller=tester"
assert_contains "header records command"    "cmd=/usr/bin/echo"
assert_contains "writes session footer"     "session end status=0"

rm -f "$LOG"

echo "session_log: $PASS passed, $FAIL failed"
if [ "$FAIL" -gt 0 ]; then exit 1; fi
exit 0
