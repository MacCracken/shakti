#!/usr/bin/env bash
set -euo pipefail

# Run cyrius benchmarks and append a summary line to benchmarks/history.csv
# Usage: ./scripts/bench-history.sh [bench.bcyr]

HISTORY_DIR="benchmarks"
HISTORY_FILE="$HISTORY_DIR/history.csv"
BENCH_FILE="${1:-tests/bcyr/core.bcyr}"

mkdir -p "$HISTORY_DIR"

if [ ! -f "$HISTORY_FILE" ]; then
    echo "timestamp,git_sha,benchmark,avg_ns,min_ns,max_ns,iters" > "$HISTORY_FILE"
fi

GIT_SHA=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

echo "Running benchmarks: $BENCH_FILE"
BENCH_OUTPUT=$(cyrius bench "$BENCH_FILE" 2>&1)
echo "$BENCH_OUTPUT"

# Parse lines like:
#   command_matches/exact: 1us avg (min=488ns max=498us) [1000000 iters]
convert_to_ns() {
    local val="$1"
    local num="${val//[^0-9.]/}"
    case "$val" in
        *ns)  echo "$num" ;;
        *us)  awk -v n="$num" 'BEGIN{printf "%.0f", n*1000}' ;;
        *ms)  awk -v n="$num" 'BEGIN{printf "%.0f", n*1000000}' ;;
        *s)   awk -v n="$num" 'BEGIN{printf "%.0f", n*1000000000}' ;;
        *)    echo "$num" ;;
    esac
}

echo "$BENCH_OUTPUT" | grep -E '^\s+\S.*: .* avg \(min=.* max=.*\) \[.* iters\]' \
| while IFS= read -r line; do
    name=$(echo "$line" | sed -E 's/^\s+([^:]+):.*/\1/')
    avg=$(echo "$line" | sed -E 's/.*: ([0-9.]+[a-z]+) avg.*/\1/')
    min=$(echo "$line" | sed -E 's/.*min=([0-9.]+[a-z]+).*/\1/')
    max=$(echo "$line" | sed -E 's/.*max=([0-9.]+[a-z]+).*/\1/')
    iters=$(echo "$line" | sed -E 's/.*\[([0-9]+) iters\].*/\1/')

    avg_ns=$(convert_to_ns "$avg")
    min_ns=$(convert_to_ns "$min")
    max_ns=$(convert_to_ns "$max")

    echo "$TIMESTAMP,$GIT_SHA,$name,$avg_ns,$min_ns,$max_ns,$iters" >> "$HISTORY_FILE"
done

echo
echo "Benchmark history saved to $HISTORY_FILE"
echo "Latest entries:"
tail -20 "$HISTORY_FILE"
