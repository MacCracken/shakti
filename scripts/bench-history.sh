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
cargo bench "$@" 2>&1 | tee /dev/stderr | \
    grep -E "^[a-z_]+.*time:" | \
    while IFS= read -r line; do
        name=$(echo "$line" | sed 's/\s*time:.*//')
        # Extract the median time in ns
        time_ns=$(echo "$line" | grep -oP '\[[\d.]+ \w+ ([\d.]+) \w+ [\d.]+ \w+\]' | head -1 | awk '{print $2}')
        unit=$(echo "$line" | grep -oP '\[[\d.]+ \w+ ([\d.]+) (\w+) [\d.]+ \w+\]' | head -1 | awk '{print $3}')

        # Convert to ns
        case "${unit:-ns}" in
            ps) time_ns=$(echo "$time_ns * 0.001" | bc 2>/dev/null || echo "$time_ns") ;;
            ns) ;; # already ns
            µs|us) time_ns=$(echo "$time_ns * 1000" | bc 2>/dev/null || echo "$time_ns") ;;
            ms) time_ns=$(echo "$time_ns * 1000000" | bc 2>/dev/null || echo "$time_ns") ;;
            s)  time_ns=$(echo "$time_ns * 1000000000" | bc 2>/dev/null || echo "$time_ns") ;;
        esac

        if [ -n "$name" ] && [ -n "$time_ns" ]; then
            echo "$TIMESTAMP,$GIT_SHA,$name,$time_ns" >> "$HISTORY_FILE"
        fi
    done

echo ""
echo "Benchmark history saved to $HISTORY_FILE"
echo "Latest entries:"
tail -20 "$HISTORY_FILE"
