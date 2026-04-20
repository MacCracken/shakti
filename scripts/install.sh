#!/usr/bin/env bash
# install.sh — system installer for shakti.
#
# Idempotent: re-running is safe, it only replaces the binary + unit
# snippets. Policy files are NOT overwritten if they already exist
# (operators typically customise them; surprise-overwrite would be bad).
#
# Usage:
#   sudo ./scripts/install.sh                      # default paths
#   sudo PREFIX=/usr/local ./scripts/install.sh    # custom prefix
#   sudo ./scripts/install.sh --no-pam             # skip pam.d install
#   sudo ./scripts/install.sh --no-tmpfiles        # skip tmpfiles.d install
#   sudo ./scripts/install.sh --with-example-policy   # install docs/examples/sudoers.toml if no policy exists
#
# Paths (overridable via env vars):
#   PREFIX         /usr               binary install root
#   SYSCONFDIR     /etc               policy + pam.d live here
#   RUNDIR         /var/run/agnos/sudo  per-TTY timestamp cache
#   TMPFILESDIR    /usr/lib/tmpfiles.d  where tmpfiles.d entries go

set -euo pipefail

PREFIX="${PREFIX:-/usr}"
SYSCONFDIR="${SYSCONFDIR:-/etc}"
RUNDIR="${RUNDIR:-/var/run/agnos/sudo}"
TMPFILESDIR="${TMPFILESDIR:-/usr/lib/tmpfiles.d}"

INSTALL_PAM=1
INSTALL_TMPFILES=1
INSTALL_EXAMPLE=0

while [ $# -gt 0 ]; do
    case "$1" in
        --no-pam)                 INSTALL_PAM=0 ;;
        --no-tmpfiles)            INSTALL_TMPFILES=0 ;;
        --with-example-policy)    INSTALL_EXAMPLE=1 ;;
        -h|--help)
            sed -n '2,/^$/{ /^$/q; s/^# \?//p; }' "$0"
            exit 0
            ;;
        *)
            echo "unknown option: $1" >&2
            exit 1
            ;;
    esac
    shift
done

# ── Preconditions ──────────────────────────
if [ "$(id -u)" -ne 0 ]; then
    echo "install.sh: must run as root (setuid bit + root-owned policy files)" >&2
    exit 1
fi

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

if [ ! -x "$REPO_ROOT/build/shakti" ]; then
    echo "install.sh: build/shakti not found — build first:" >&2
    echo "    cyrius build src/main.cyr build/shakti" >&2
    exit 1
fi

# ── Binary: /usr/bin/shakti (mode 4755 — setuid root) ──────────────────
BIN_TARGET="$PREFIX/bin/shakti"
echo "install: $BIN_TARGET (mode 4755, root:root)"
install -o root -g root -m 4755 "$REPO_ROOT/build/shakti" "$BIN_TARGET"

# ── Runtime directory ─────────────────────
# Shakti also lazy-creates this, but tmpfiles.d is the canonical path.
if [ ! -d "$RUNDIR" ]; then
    echo "install: mkdir $RUNDIR (mode 0700, root:root)"
    install -o root -g root -m 0700 -d "$RUNDIR"
else
    # Fix perms in case they drifted.
    chown root:root "$RUNDIR"
    chmod 0700 "$RUNDIR"
fi

# ── Policy directories (never overwrite content) ─────────────────────
POLICY_DIR="$SYSCONFDIR/agnos"
POLICY_FILE="$POLICY_DIR/sudoers.toml"
FRAGMENTS_DIR="$POLICY_DIR/sudoers.d"

if [ ! -d "$POLICY_DIR" ]; then
    echo "install: mkdir $POLICY_DIR (mode 0755, root:root)"
    install -o root -g root -m 0755 -d "$POLICY_DIR"
fi

if [ ! -d "$FRAGMENTS_DIR" ]; then
    echo "install: mkdir $FRAGMENTS_DIR (mode 0755, root:root)"
    install -o root -g root -m 0755 -d "$FRAGMENTS_DIR"
fi

if [ ! -f "$POLICY_FILE" ]; then
    if [ "$INSTALL_EXAMPLE" -eq 1 ]; then
        echo "install: $POLICY_FILE (from docs/examples/sudoers.toml)"
        install -o root -g root -m 0644 "$REPO_ROOT/docs/examples/sudoers.toml" "$POLICY_FILE"
    else
        echo "install: NO policy at $POLICY_FILE — shakti will fail with 'failed to load policy' until one exists."
        echo "         re-run with --with-example-policy to install the annotated example,"
        echo "         or copy docs/examples/sudoers.toml and customise."
    fi
else
    echo "install: policy $POLICY_FILE already exists, leaving untouched."
fi

# ── tmpfiles.d snippet ────────────────────
if [ "$INSTALL_TMPFILES" -eq 1 ] && [ -d "$TMPFILESDIR" ]; then
    echo "install: $TMPFILESDIR/shakti.conf"
    install -o root -g root -m 0644 "$REPO_ROOT/etc/tmpfiles.d/shakti.conf" "$TMPFILESDIR/shakti.conf"
    if command -v systemd-tmpfiles >/dev/null 2>&1; then
        systemd-tmpfiles --create "$TMPFILESDIR/shakti.conf" || true
    fi
fi

# ── PAM service config ────────────────────
# Required for a future real-PAM path (blocked on cyrius 5.5.x NSS
# bootstrap). Installing it now is harmless — the su-shim auth path
# in 0.2.x doesn't consult PAM. Idempotent overwrite.
if [ "$INSTALL_PAM" -eq 1 ]; then
    PAM_TARGET="$SYSCONFDIR/pam.d/shakti"
    if [ -d "$SYSCONFDIR/pam.d" ]; then
        echo "install: $PAM_TARGET"
        install -o root -g root -m 0644 "$REPO_ROOT/etc/pam.d/shakti" "$PAM_TARGET"
    else
        echo "install: $SYSCONFDIR/pam.d not present, skipping pam.d config"
    fi
fi

# ── Smoke check ───────────────────────────
# A freshly-installed binary should at minimum print its version and
# exit 0. If this fails, something is very wrong with the build.
if ! "$BIN_TARGET" --version >/dev/null 2>&1; then
    echo "install: WARNING — $BIN_TARGET --version failed; investigate." >&2
fi

cat <<EOF

Shakti installed.

Binary:        $BIN_TARGET        (mode 4755 — setuid root)
Runtime dir:   $RUNDIR  (mode 0700)
Policy dir:    $POLICY_DIR
Policy file:   $POLICY_FILE
Fragments:     $FRAGMENTS_DIR

Next steps:
  1. Review or create $POLICY_FILE (see docs/examples/sudoers.toml).
  2. Lint it:  shakti -c
  3. Test:     shakti -l   # list allowed commands for yourself
EOF
