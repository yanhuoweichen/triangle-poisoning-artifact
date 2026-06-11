#!/usr/bin/env bash
set -euo pipefail

# Usage:
#   ./run_EdgeOrientDelta_laplace_attack.sh <dataset> <n|-1> <eps_list> <workers> <runs> <noise:0/1> <direction> <mode> <malicious_ratio_list> <poison_prob> <selector> [attack_value] [psi=0.5] [split_factor=0.5] [bias_factor=8]
#
# direction: increase | decrease | none
# mode:      fixed | scale | local
# attack_value:
#   fixed: fixed additive offset to each malicious local triangle report. Default: 10000
#   scale: multiplier of the Laplace noise scale. Default: 1.0
#   local: multiplier of |local count before Laplace noise|. Default: 0.5

DATASET=${1:-Gplus}
N=${2:-10000}
EPS_LIST=${3:-1.0}
WORKERS=${4:-2}
RUNS=${5:-5}
NOISE=${6:-1}
DIRECTION=${7:-increase}
MODE=${8:-fixed}
MAL_RATIOS=${9:-0.05,0.10,0.20}
POISON_PROB=${10:-1.0}
SELECTOR=${11:-high_degree}
ATTACK_VALUE=${12:-}
PSI=${13:-0.5}
SPLIT_FACTOR=${14:-0.5}
BIAS_FACTOR=${15:-8}
SEED=${SEED:-1776}

case "$MODE" in
  fixed|constant|const)
    ATTACK_VALUE=${ATTACK_VALUE:-10000}
    ;;
  scale|noise_scale|laplace_scale)
    ATTACK_VALUE=${ATTACK_VALUE:-1.0}
    ;;
  local|local_count|count)
    ATTACK_VALUE=${ATTACK_VALUE:-0.5}
    ;;
  *)
    echo "[error] unknown mode: $MODE. Use fixed, scale, or local." >&2
    exit 1
    ;;
esac

EDGE_FILE="../data/${DATASET}/edges.csv"
if [[ ! -f "$EDGE_FILE" ]]; then
  echo "[error] edge file not found: $EDGE_FILE" >&2
  exit 1
fi

BIN="./EdgeOrientDelta_TriangleLDP_LaplaceAttack"
SRC="EdgeOrientDelta_TriangleLDP_LaplaceAttack.cpp"

echo "[compile] g++ -O3 -std=c++11 -march=native $SRC -o $BIN"
g++ -O3 -std=c++11 -march=native "$SRC" -o "$BIN"

SAFE_EPS=${EPS_LIST//,/ _}
SAFE_EPS=${SAFE_EPS// /}
SAFE_RATIOS=${MAL_RATIOS//,/ _}
SAFE_RATIOS=${SAFE_RATIOS// /}
SAFE_VAL=${ATTACK_VALUE//./p}
OUT="../data/${DATASET}/EdgeOrientDelta_LaplaceAttack_${DIRECTION}_${MODE}_n${N}_eps${SAFE_EPS}_p${SAFE_RATIOS}_prob${POISON_PROB}_val${SAFE_VAL}.csv"

echo "[run] dataset=$DATASET, n=$N, eps=$EPS_LIST, workers=$WORKERS, runs=$RUNS, noise=$NOISE, direction=$DIRECTION, mode=$MODE, malicious=$MAL_RATIOS, poison_prob=$POISON_PROB, selector=$SELECTOR, attack_value=$ATTACK_VALUE"
"$BIN" "$EDGE_FILE" "$N" "$EPS_LIST" "$PSI" "$WORKERS" "$RUNS" "$NOISE" "$SEED" "$OUT" \
  "$DIRECTION" "$MODE" "$MAL_RATIOS" "$POISON_PROB" "$SELECTOR" "$ATTACK_VALUE" "$SPLIT_FACTOR" "$BIAS_FACTOR"

echo "Done. Results: $OUT"
