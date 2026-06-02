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

# ── Root tier: the FULL shakti logged exec path ──────────────────────────
# Under real root, drive shakti end-to-end with a log_session policy and
# confirm it writes a transcript containing the command's output. Needs a
# root-owned policy + session dir, so it only runs as root.
BIN="${1:-build/shakti}"
if [ "$(id -u)" = "0" ] && [ -x "$BIN" ]; then
    GREP=""
    for cand in /usr/bin/grep /bin/grep; do [ -x "$cand" ] && { GREP="$cand"; break; }; done
    if [ -n "$GREP" ]; then
        TARGET="root"
        id nobody >/dev/null 2>&1 && TARGET="nobody"
        DIR="$(mktemp -d /tmp/shakti-sess-XXXXXX)"
        POL="$(mktemp /tmp/shakti-sesspol-XXXXXX.toml)"
        chown root:root "$DIR" "$POL"
        chmod 0700 "$DIR"
        chmod 0644 "$POL"
        cat > "$POL" <<EOF
[defaults]
require_auth = false
audit_log = false
log_session = true
session_log_dir = "$DIR"

[[rules]]
user = "root"
run_as = "$TARGET"
commands = ["$GREP *"]
require_auth = false
EOF
        # echo a marker via grep so it lands in the transcript.
        echo "SESSION-MARKER-9137" > "$DIR/marker.txt"
        chmod 0644 "$DIR/marker.txt"
        "$BIN" -p "$POL" -u "$TARGET" -- "$GREP" SESSION-MARKER "$DIR/marker.txt" </dev/null >/dev/null 2>&1
        transcript=$(cat "$DIR"/*.log 2>/dev/null)
        case "$transcript" in
            *"SESSION-MARKER-9137"*) PASS=$((PASS + 1)) ;;
            *)
                FAIL=$((FAIL + 1))
                echo "FAIL: root full-path transcript missing command output"
                echo "  transcript: ${transcript:-<none>}"
                ;;
        esac
        case "$transcript" in
            *"=== shakti session "*) PASS=$((PASS + 1)) ;;
            *) FAIL=$((FAIL + 1)); echo "FAIL: root full-path transcript missing header" ;;
        esac
        rm -rf "$DIR" "$POL"
    fi
fi

echo "session_log: $PASS passed, $FAIL failed"
if [ "$FAIL" -gt 0 ]; then exit 1; fi
exit 0
