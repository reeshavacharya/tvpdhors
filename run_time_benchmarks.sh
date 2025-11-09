#!/usr/bin/env bash
set -euo pipefail

# tvpdhors benchmark runner: installs deps, builds, runs benches, logs output
# Usage: ./run_time_benchmarks.sh [ITERATIONS] [CONFIG_FILE] [MESSAGE_FILE]
# Defaults:
#   ITERATIONS=100
#   CONFIG_FILE=./config_sample
#   MESSAGE_FILE=./target/message.bin (auto-created if missing)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$SCRIPT_DIR"
BUILD_INCLUDE_DIR="$PROJECT_DIR/build/include"
LOG_FILE="$PROJECT_DIR/benchmark_results.log"
TARGET_DIR="$PROJECT_DIR/target"

ITERATIONS="${1:-100}"
CONFIG_FILE_REL="${2:-config_sample}"
MESSAGE_FILE_REL="${3:-target/message.bin}"
CONFIG_FILE="$PROJECT_DIR/$CONFIG_FILE_REL"
MESSAGE_FILE="$PROJECT_DIR/$MESSAGE_FILE_REL"

# Fresh log
: > "$LOG_FILE"

# Ensure message file exists (1KB of deterministic data)
if [[ ! -f "$MESSAGE_FILE" ]]; then
  mkdir -p "$(dirname "$MESSAGE_FILE")"
  head -c 1024 /dev/zero > "$MESSAGE_FILE"
fi

# Prepare sudo if needed
SUDO=""; if [[ "$(id -u)" -ne 0 ]]; then SUDO="sudo"; fi

# Install dependencies (quiet)
echo "[info] Installing dependencies..." | tee -a "$LOG_FILE"
$SUDO apt-get update -y >/dev/null
$SUDO apt-get install -y build-essential make gcc libssl-dev libtomcrypt-dev libxxhash-dev >/dev/null

# Build benches (Makefile already handles headers include)
echo "[info] Building HORS_BENCH and BFTVMHORS_BENCH..." | tee -a "$LOG_FILE"
make -C "$PROJECT_DIR" -s HORS_BENCH BFTVMHORS_BENCH >/dev/null

# Paths
HORS_BENCH="$TARGET_DIR/hors_bench"
BFTVMHORS_BENCH="$TARGET_DIR/bftvmhors_bench"

if [[ ! -x "$HORS_BENCH" ]] || [[ ! -x "$BFTVMHORS_BENCH" ]]; then
  echo "[error] Bench executables not found. Build failed." | tee -a "$LOG_FILE"; exit 1
fi

TS="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
echo "===== tvpdhors Benchmarks @ $TS =====" | tee -a "$LOG_FILE"
echo "Config: $CONFIG_FILE_REL  Iterations: $ITERATIONS" | tee -a "$LOG_FILE"
echo "Message: $MESSAGE_FILE_REL (size $(stat -c%s "$MESSAGE_FILE") bytes)" | tee -a "$LOG_FILE"

# Ensure seed file referenced by config exists
SEED_PATH_REL="$(sed -n 's/^\s*seed\s*=\s*//p' "$CONFIG_FILE" | head -n1 | tr -d '\r')"
if [[ -n "$SEED_PATH_REL" ]]; then
  SEED_PATH_ABS="$PROJECT_DIR/$SEED_PATH_REL"
  if [[ ! -f "$SEED_PATH_ABS" ]]; then
    echo "[info] Creating seed file at $SEED_PATH_REL" | tee -a "$LOG_FILE"
    head -c 32 /dev/zero > "$SEED_PATH_ABS"
  fi
else
  echo "[warn] Could not parse seed path from $CONFIG_FILE_REL; proceeding without ensuring seed file." | tee -a "$LOG_FILE"
fi

set +e
echo "--- HORS ---" | tee -a "$LOG_FILE"
( cd "$PROJECT_DIR" && "$HORS_BENCH" "$CONFIG_FILE" "$MESSAGE_FILE" "$ITERATIONS" ) 2>&1 | tee -a "$LOG_FILE"
ST_HORS=$?
echo "" | tee -a "$LOG_FILE"
echo "--- BFTVMHORS (OHBF) ---" | tee -a "$LOG_FILE"
( cd "$PROJECT_DIR" && "$BFTVMHORS_BENCH" "$CONFIG_FILE" "$MESSAGE_FILE" "$ITERATIONS" ) 2>&1 | tee -a "$LOG_FILE"
ST_BFT=$?
set -e

echo "===== Exit statuses: HORS=$ST_HORS, BFTVMHORS=$ST_BFT =====" | tee -a "$LOG_FILE"

if [[ $ST_HORS -ne 0 || $ST_BFT -ne 0 ]]; then
  echo "[warn] Some benchmarks failed. See details above." | tee -a "$LOG_FILE"
fi

echo "[done] Results written to $LOG_FILE"
