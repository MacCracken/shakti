#!/usr/bin/env bash
# Integration test for SELinux/AppArmor exec-context transitions
# (ADR-009) — the writer in src/lsm.cyr. Compiles lsm_probe.cyr and
# checks its behaviour against the host's active LSMs:
#   - "nothing requested" must always be a no-op success (rc 0).
#   - On a host WITHOUT SELinux/AppArmor, writing a context must fail
#     (negative rc) — the fail-closed signal shakti depends on.
#   - On an LSM-enabled host the write may succeed; we only report it
#     (real enforcement is an LSM-CI concern, not asserted here).
#
# Unprivileged; no root required. Exit 0 = passed/skipped, 1 = failure.

set -u
PASS=0
FAIL=0
PROBE_BIN="build/lsm-probe"

if ! cyrius build tests/integration/lsm_probe.cyr "$PROBE_BIN" >/dev/null 2>&1; then
    echo "FAIL: lsm_probe did not compile"
    exit 1
fi

out=$("$PROBE_BIN" 2>&1)
noop=$(echo "$out"    | sed -n 's/^lsm-noop: //p')
selinux=$(echo "$out" | sed -n 's/^lsm-selinux: //p')
apparmor=$(echo "$out"| sed -n 's/^lsm-apparmor: //p')

# Which LSMs are active on this host?
active=$(cat /sys/kernel/security/lsm 2>/dev/null || echo "")
has_selinux=0; case "$active" in *selinux*) has_selinux=1;; esac
has_apparmor=0; case "$active" in *apparmor*) has_apparmor=1;; esac

# Nothing-requested is always a no-op success.
if [ "$noop" = "0" ]; then PASS=$((PASS + 1)); else
    FAIL=$((FAIL + 1)); echo "FAIL: lsm_apply_exec(none) expected 0, got '$noop'"
fi

# SELinux context write: fail-closed (non-zero) when SELinux is inactive.
if [ "$has_selinux" = "0" ]; then
    if [ -n "$selinux" ] && [ "$selinux" != "0" ]; then PASS=$((PASS + 1)); else
        FAIL=$((FAIL + 1)); echo "FAIL: selinux write should fail-closed without SELinux, got '$selinux'"
    fi
else
    echo "NOTE: SELinux active — selinux write rc=$selinux (enforcement not asserted here)"
    PASS=$((PASS + 1))
fi

# AppArmor profile write: fail-closed when AppArmor is inactive.
if [ "$has_apparmor" = "0" ]; then
    if [ -n "$apparmor" ] && [ "$apparmor" != "0" ]; then PASS=$((PASS + 1)); else
        FAIL=$((FAIL + 1)); echo "FAIL: apparmor write should fail-closed without AppArmor, got '$apparmor'"
    fi
else
    echo "NOTE: AppArmor active — apparmor write rc=$apparmor (enforcement not asserted here)"
    PASS=$((PASS + 1))
fi

echo "lsm_ctx: $PASS passed, $FAIL failed (active LSMs: ${active:-none})"
if [ "$FAIL" -gt 0 ]; then exit 1; fi
exit 0
