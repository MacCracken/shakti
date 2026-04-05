#!/usr/bin/env bash
set -euo pipefail

# Run criterion benchmarks and append a summary line to benchmarks/history.csv
# Usage: ./scripts/bench-history.sh [-- extra cargo bench args]

HISTORY_DIR="benchmarks"
HISTORY_FILE="$HISTORY_DIR/history.csv"

mkdir -p "$HISTORY_DIR"

# Create CSV header if it doesn't exist
if [ ! -f "$HISTORY_FILE" ]; then
    echo "timestamp,git_sha,benchmark,time_ns" > "$HISTORY_FILE"
fi

GIT_SHA=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

echo "Running benchmarks..."
BENCH_OUTPUT=$(cargo bench "$@" 2>&1)
echo "$BENCH_OUTPUT"

# Parse criterion output lines like:
#   parse_policy            time:   [14.051 µs 14.134 µs 14.226 µs]
# Extract benchmark name (first field) and median value (middle of bracket triple).
echo "$BENCH_OUTPUT" | grep -E '^\S.*time:' | while IFS= read -r line; do
    # Name is everything before "time:"
    name=$(echo "$line" | sed 's/\s*time:.*//' | xargs)

    # Extract [low unit median unit high unit] — we want the median (3rd number)
    bracket=$(echo "$line" | grep -oP '\[.*?\]')
    if [ -z "$bracket" ]; then
        continue
    fi

    # Parse: [14.051 µs 14.134 µs 14.226 µs]
    median=$(echo "$bracket" | awk '{print $3}')
    unit=$(echo "$bracket" | awk '{print $4}')

    if [ -z "$median" ] || [ -z "$unit" ]; then
        continue
    fi

    # Convert to ns
    case "$unit" in
        ps)   time_ns=$(echo "$median * 0.001" | bc -l 2>/dev/null || echo "$median") ;;
        ns)   time_ns="$median" ;;
        µs|us) time_ns=$(echo "$median * 1000" | bc -l 2>/dev/null || echo "$median") ;;
        ms)   time_ns=$(echo "$median * 1000000" | bc -l 2>/dev/null || echo "$median") ;;
        s)    time_ns=$(echo "$median * 1000000000" | bc -l 2>/dev/null || echo "$median") ;;
        *)    time_ns="$median" ;;
    esac

    if [ -n "$name" ] && [ -n "$time_ns" ]; then
        echo "$TIMESTAMP,$GIT_SHA,$name,$time_ns" >> "$HISTORY_FILE"
    fi
done

echo ""
echo "Benchmark history saved to $HISTORY_FILE"
echo "Latest entries:"
tail -20 "$HISTORY_FILE"
