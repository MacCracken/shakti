#!/bin/sh
# Version bump script for shakti — single source of truth for all
# version references. Mirrors patra's / cyrius's scripts/version-bump.sh
# pattern, tailored to shakti's manifest layout.
#
# Usage: ./scripts/version-bump.sh 0.4.0
#
# Why this script exists: a bump touches three places that must stay in
# lockstep, and the CI docs job hard-fails on drift (see
# .github/workflows/ci.yml "Verify version consistency"):
#   - VERSION                         — the single source of truth
#   - src/lib.cyr shakti_version_string() — surfaced by `shakti --version`
#   - CHANGELOG.md                    — must contain the version heading
# cyrius.cyml needs NO edit: its `[package].version = "${file:VERSION}"`
# template derives the package version from the VERSION file directly.

set -e

if [ -z "$1" ]; then
    echo "Usage: $0 <version>"
    echo "Current: $(cat VERSION 2>/dev/null || echo '<no VERSION file>')"
    exit 1
fi

NEW="$1"
OLD=$(cat VERSION 2>/dev/null | tr -d '[:space:]' || echo '')

if [ -z "$OLD" ]; then
    echo "error: VERSION file missing or empty" >&2
    exit 1
fi

if [ "$NEW" = "$OLD" ]; then
    echo "Already at $OLD (no changes)"
    exit 0
fi

# Sanity: NEW looks like a semver
case "$NEW" in
    [0-9]*.[0-9]*.[0-9]*) ;;
    *) echo "error: '$NEW' does not look like a semver" >&2; exit 1 ;;
esac

# 1. VERSION file (source of truth)
echo "$NEW" > VERSION

# 2. src/lib.cyr shakti_version_string() — "shakti X.Y.Z (cyrius port)".
#    This is what `shakti --version` prints and what the CI version-surface
#    check greps for. cyrius.cyml is intentionally NOT touched (it pulls
#    the package version from VERSION via ${file:VERSION}).
if [ -f src/lib.cyr ]; then
    sed -i "s/shakti $OLD (cyrius port)/shakti $NEW (cyrius port)/" src/lib.cyr
fi

# 3. CHANGELOG.md — add a dated stub if no entry for $NEW yet. Inserts the
#    stub right after the "## [Unreleased]" heading. The stub is empty so
#    the human author writes the actual Changed/Added/Security sections —
#    this script only guarantees the version heading appears (CI requires it).
if [ -f CHANGELOG.md ]; then
    if ! grep -q "## \[$NEW\]" CHANGELOG.md; then
        TODAY=$(date +%Y-%m-%d)
        awk -v new="$NEW" -v today="$TODAY" '
            /^## \[Unreleased\]/ && !inserted {
                print
                print ""
                print "## [" new "] - " today
                print ""
                print "**TODO:** describe this release."
                inserted = 1
                next
            }
            { print }
        ' CHANGELOG.md > CHANGELOG.md.tmp && mv CHANGELOG.md.tmp CHANGELOG.md
    fi
fi

echo "$OLD -> $NEW"
echo ""
echo "Updated:"
echo "  VERSION"
echo "  src/lib.cyr (shakti_version_string)"
if grep -q "## \[$NEW\]" CHANGELOG.md 2>/dev/null; then
    echo "  CHANGELOG.md ([$NEW] stub)"
fi
echo ""
echo "Still manual:"
echo "  - CHANGELOG.md sections (Changed/Added/Security)"
echo "  - Regenerate dist: cyrius distlib && git add dist/shakti.cyr"
echo "    (the version label is embedded via src/lib.cyr)."
echo "  - Bump the cyrius toolchain pin in cyrius.cyml if needed."
echo "    (\`cyrius = \"X.Y.Z\"\` line — separate from package.version.)"
echo "    IMPORTANT: only pin to a RELEASED cyrius version (see"
echo "    https://github.com/MacCracken/cyrius/releases). The CI installer"
echo "    fetches that tag; an unreleased pin fails the install step."
echo "  - Update the zugot recipe (marketplace/shakti.cyml): version +"
echo "    the release-asset sha256 (computable only after the GH release)."
