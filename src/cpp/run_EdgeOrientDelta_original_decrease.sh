#!/usr/bin/env bash
set -euo pipefail

# Original-data decrease attack version.
# Attack parameters are inside EdgeOrientDelta_OriginalDecreaseAttack.cpp:
#   MALICIOUS_RATIO and POISON_PROB
# Usage:
#   ./run_EdgeOrientDelta_original_decrease.sh Gplus 10000 0.5,1.0,2.0 4 5 1
# Optional:
#   ./run_EdgeOrientDelta_original_decrease.sh Gplus 10000 0.5,1.0,2.0 4 5 1 0.5 0.8 8 12 1776
# Args: dataset n epsilon_list workers runs noise [psi=0.5] [split_factor=0.8] [bias_factor=8] [dmax_slack_multiplier=12] [seed=1776]

DATASET=${1:?dataset name, e.g. Gplus}
N=${2:?n or -1}
EPS_LIST=${3:?epsilon list, e.g. 1.0 or 0.5,1.0,2.0}
WORKERS=${4:?workers}
RUNS=${5:?runs}
NOISE=${6:?noise 0/1}
PSI=${7:-0.5}
SPLIT=${8:-0.8}
BIAS=${9:-8}
SLACK=${10:-12}
SEED=${11:-1776}

SRC=${SRC:-EdgeOrientDelta_OriginalDecreaseAttack.cpp}
BIN=${BIN:-EdgeOrientDelta_OriginalDecreaseAttack}
EDGE_FILE=${EDGE_FILE:-../data/${DATASET}/edges.csv}
OUT=${OUT:-../data/${DATASET}/EdgeOrientDelta_original_decrease_results.csv}

if [[ ! -f "$SRC" ]]; then
  echo "Cannot find $SRC. Put this script in the same directory as $SRC, or set SRC=/path/to/cpp." >&2
  exit 2
fi

mkdir -p "$(dirname "$OUT")"
echo "[compile] g++ -O3 -std=c++11 -pthread -march=native $SRC -o $BIN"
g++ -O3 -std=c++11 -pthread -march=native "$SRC" -o "$BIN"

echo "[run] attack=original_decrease, dataset=$DATASET, n=$N, eps=$EPS_LIST, psi=$PSI, workers=$WORKERS, runs=$RUNS, noise=$NOISE, split=$SPLIT, bias=$BIAS, slack=$SLACK"
"./$BIN" "$EDGE_FILE" "$N" "$EPS_LIST" "$PSI" "$WORKERS" "$RUNS" "$NOISE" "$SEED" "$OUT" "$SPLIT" "$BIAS" "$SLACK"
