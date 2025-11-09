#!/usr/bin/env bash
# Wrapper script (name requested) to build and run time benchmarks and write results.
# Usage: ./run_becnhcpart.sh [ITERATIONS]
set -euo pipefail
ITER="${1:-100}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "[info] Building benchmark executables..."
make -s HORS_BENCH BFTVMHORS_BENCH

# Call the existing runner; it will also ensure dependencies and logs to benchmark_results.log
bash "$SCRIPT_DIR/run_time_benchmarks.sh" "$ITER"
