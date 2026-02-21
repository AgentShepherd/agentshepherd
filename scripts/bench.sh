#!/bin/bash
# Benchmark runner with comparison support
#
# Usage:
#   ./scripts/bench.sh                  # Run benchmarks and compare to baseline
#   ./scripts/bench.sh --save-baseline  # Save current results as baseline
#   ./scripts/bench.sh --quick          # Run quick benchmarks only (skip slow ones)

set -e

BASELINE_FILE="benchmarks/baseline.txt"
CURRENT_FILE="benchmarks/current.txt"
BENCH_PATTERN="."
COUNT=5

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --save-baseline)
            SAVE_BASELINE=1
            shift
            ;;
        --quick)
            # Only run fast benchmarks (exclude parallel and creation benchmarks)
            BENCH_PATTERN="Extractor|Normalizer|Matcher|JSONParsing|ContainsRegex"
            COUNT=3
            shift
            ;;
        *)
            echo "Unknown option: $1"
            echo "Usage: $0 [--save-baseline] [--quick]"
            exit 1
            ;;
    esac
done

# Ensure benchmarks directory exists
mkdir -p benchmarks

# Check if benchstat is installed
if ! command -v benchstat &> /dev/null; then
    echo "Installing benchstat..."
    go install golang.org/x/perf/cmd/benchstat@latest
fi

# Run benchmarks
echo "Running benchmarks (count=$COUNT, pattern=$BENCH_PATTERN)..."
go test -bench="$BENCH_PATTERN" -benchmem -count=$COUNT \
    ./internal/rules/... \
    ./internal/proxy/... \
    ./internal/security/... \
    2>&1 | tee "$CURRENT_FILE"

# Compare with baseline if exists
if [ -f "$BASELINE_FILE" ]; then
    echo ""
    echo "=========================================="
    echo "Comparing with baseline..."
    echo "=========================================="
    benchstat "$BASELINE_FILE" "$CURRENT_FILE"
else
    echo ""
    echo "No baseline found. Run '$0 --save-baseline' to create one."
fi

# Save as new baseline if requested
if [ -n "$SAVE_BASELINE" ]; then
    cp "$CURRENT_FILE" "$BASELINE_FILE"
    echo ""
    echo "Saved current results as baseline"
fi
