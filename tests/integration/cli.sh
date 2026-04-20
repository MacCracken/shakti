#!/usr/bin/env bash
# Integration tests for shakti's CLI surface that do NOT require root.
#
# Covers CLI paths where no policy load is attempted:
#   --version, --help, no args, unknown option.
#
# Paths that require a root-owned policy file (--list, --check,
# --invalidate, and the main exec flow) are not exercised here — they
# need a CI runner with sudo or fakeroot. Tracked on the roadmap.
#
# Exit codes:
#   0 — all assertions passed
#   1 — at least one assertion failed
#
# Usage: sh tests/integration/cli.sh [path/to/shakti]
#   Default binary path: build/shakti

set -u
BIN="${1:-build/shakti}"

if [ ! -x "$BIN" ]; then
    echo "error: $BIN not executable; build first (cyrius build src/main.cyr build/shakti)" >&2
    exit 2
fi

PASS=0
FAIL=0

assert() {
    local desc="$1"
    local actual="$2"
    local expected="$3"
    if [ "$actual" = "$expected" ]; then
        PASS=$((PASS + 1))
    else
        FAIL=$((FAIL + 1))
        echo "FAIL: $desc"
        echo "  expected: $expected"
        echo "  actual:   $actual"
    fi
}

assert_contains() {
    local desc="$1"
    local haystack="$2"
    local needle="$3"
    case "$haystack" in
        *"$needle"*)
            PASS=$((PASS + 1))
            ;;
        *)
            FAIL=$((FAIL + 1))
            echo "FAIL: $desc"
            echo "  expected substring: $needle"
            echo "  actual:             $haystack"
            ;;
    esac
}

# ── --version ──────────────────────────
out=$("$BIN" --version 2>&1)
rc=$?
assert "--version exit code" "$rc" "0"
assert_contains "--version stdout mentions cyrius port" "$out" "cyrius port"
# Check the version string matches VERSION file.
expected_ver=$(cat VERSION 2>/dev/null | tr -d '[:space:]')
assert_contains "--version stdout contains VERSION file value" "$out" "$expected_ver"

# Short flag alias
out_v=$("$BIN" -V 2>&1)
assert "-V exit code" "$?" "0"
assert "-V matches --version" "$out_v" "$out"

# ── --help ──────────────────────────
out=$("$BIN" --help 2>&1)
assert "--help exit code" "$?" "0"
assert_contains "--help includes Usage line" "$out" "Usage: shakti"
assert_contains "--help documents --user" "$out" "--user"
assert_contains "--help documents --policy" "$out" "--policy"
assert_contains "--help documents --check" "$out" "--check"

out_h=$("$BIN" -h 2>&1)
assert "-h matches --help" "$out_h" "$out"

# ── no args ──────────────────────────
out=$("$BIN" 2>&1)
rc=$?
assert "no args exits 1" "$rc" "1"
assert_contains "no args prints usage" "$out" "Usage: shakti"

# ── unknown option ──────────────────────────
out=$("$BIN" --nonesuch 2>&1)
rc=$?
assert "unknown option exits 1" "$rc" "1"
assert_contains "unknown option names itself in error" "$out" "--nonesuch"

# ── -- delimits positional args ──────────────────────────
# `shakti -- -foo` should treat "-foo" as the command, not an option.
# Since we're running as non-root, the evaluate path will fail, but the
# parse should not reject -foo as an unknown option.
out=$("$BIN" -- -foo 2>&1)
# Whatever the exit, the error should NOT be "unknown option"
case "$out" in
    *"unknown option"*)
        FAIL=$((FAIL + 1))
        echo "FAIL: -- delimiter didn't suppress option parsing"
        echo "  actual: $out"
        ;;
    *)
        PASS=$((PASS + 1))
        ;;
esac

# ── dist/shakti.cyr consumer probe ──────────────────────────
# Compiles + runs tests/integration/consumer_probe.cyr against
# dist/shakti.cyr to verify the bundle is consumable as a dep.
# If this fails after editing src/*.cyr, regenerate the bundle:
#     cyrius distlib
PROBE_BIN="build/consumer-probe"
if cyrius build tests/integration/consumer_probe.cyr "$PROBE_BIN" >/dev/null 2>&1; then
    probe_out=$("$PROBE_BIN" 2>&1)
    probe_rc=$?
    assert "consumer probe exits 0" "$probe_rc" "0"
    assert "consumer probe prints OK" "$probe_out" "consumer probe OK"
else
    FAIL=$((FAIL + 1))
    echo "FAIL: consumer probe did not compile against dist/shakti.cyr"
    echo "  → regenerate the bundle with: cyrius distlib"
fi

echo
echo "Integration: $PASS passed, $FAIL failed"
if [ "$FAIL" -gt 0 ]; then exit 1; fi
exit 0
