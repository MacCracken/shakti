#!/usr/bin/env bash
# Integration test for capability-based privilege (ADR-007).
#
# Verifies the LIVE capability drop by reading a probe's
# /proc/self/status Cap* lines after shakti (or the isolated cap_probe)
# narrows the set to exactly CAP_NET_BIND_SERVICE (bit 10 = 0x400).
#
# Three tiers, best available wins:
#   1. unprivileged user namespace (`unshare -Ucr`): runs cap_probe,
#      which exercises caps_bset_drop_complement / caps_capset /
#      caps_ambient_raise_set in isolation (uid stays 0; setgroups is
#      force-denied in unprivileged userns, so the full uid drop can't
#      run there). This is the path most CI gets — no root needed.
#   2. real root: runs the FULL shakti exec flow against a root-owned
#      policy, exercising setgroups/setgid/setuid + the cap drop together.
#   3. neither: SKIP (the name/bit/mask logic is unit-tested in
#      tests/tcyr/caps.tcyr).
#
# Exit 0 = passed or skipped; 1 = a real failure.

set -u
BIN="${1:-build/shakti}"
EXPECT="0000000000000400"   # CAP_NET_BIND_SERVICE only
PASS=0
FAIL=0

check_field() {
    local out="$1" label="$2" line
    line=$(echo "$out" | grep "^$label:")
    case "$line" in
        *"$EXPECT"*) PASS=$((PASS + 1)) ;;
        *)
            FAIL=$((FAIL + 1))
            echo "FAIL: $label expected $EXPECT"
            echo "  actual: ${line:-<missing>}"
            ;;
    esac
}

ran=0

# ── Tier 1: unprivileged user namespace ──────────────────────────
if [ "$(id -u)" != "0" ] && command -v unshare >/dev/null 2>&1 \
    && unshare -Ucr true >/dev/null 2>&1; then
    PROBE_BIN="build/cap-probe"
    if cyrius build tests/integration/cap_probe.cyr "$PROBE_BIN" >/dev/null 2>&1; then
        ran=1
        echo "Tier 1: unprivileged user namespace (cap_probe)"
        out=$(unshare -Ucr "./$PROBE_BIN" 2>&1)
        echo "$out" | sed 's/^/    /'
        # Effective/permitted/inheritable/bounding/ambient all == granted cap.
        for f in CapInh CapPrm CapEff CapBnd CapAmb; do check_field "$out" "$f"; done
    else
        FAIL=$((FAIL + 1))
        echo "FAIL: cap_probe did not compile"
    fi
fi

# ── Tier 2: real root — full shakti exec path ──────────────────────────
if [ "$(id -u)" = "0" ]; then
    GREP=""
    for cand in /usr/bin/grep /bin/grep; do
        [ -x "$cand" ] && { GREP="$cand"; break; }
    done
    if [ -n "$GREP" ] && [ -x "$BIN" ]; then
        TARGET="root"
        if id nobody >/dev/null 2>&1; then TARGET="nobody"; fi
        POL="$(mktemp /tmp/shakti-caps-XXXXXX.toml)"
        cat > "$POL" <<EOF
[defaults]
require_auth = false
audit_log = false

[[rules]]
user = "root"
run_as = "$TARGET"
commands = ["$GREP *"]
capabilities = ["CAP_NET_BIND_SERVICE"]
require_auth = false
EOF
        chown root:root "$POL"
        chmod 0644 "$POL"
        ran=1
        echo "Tier 2: full shakti exec path (target=$TARGET)"
        out=$("$BIN" -p "$POL" -u "$TARGET" -- "$GREP" -E "CapEff|CapBnd|CapAmb" /proc/self/status 2>&1)
        rm -f "$POL"
        echo "$out" | sed 's/^/    /'
        check_field "$out" "CapEff"
        check_field "$out" "CapBnd"
        # A root target re-derives permitted from the bounding set at
        # execve, so CapAmb may legitimately read 0 there; only assert it
        # for a non-root target where the ambient path carries the caps.
        if [ "$TARGET" != "root" ]; then check_field "$out" "CapAmb"; fi
    fi
fi

if [ "$ran" = "0" ]; then
    echo "SKIP: no user namespace and not root — cannot verify the live drop."
    echo "      Cap name/bit/mask logic is covered by tests/tcyr/caps.tcyr."
    exit 0
fi

echo
echo "caps_drop: $PASS passed, $FAIL failed"
if [ "$FAIL" -gt 0 ]; then exit 1; fi
exit 0
