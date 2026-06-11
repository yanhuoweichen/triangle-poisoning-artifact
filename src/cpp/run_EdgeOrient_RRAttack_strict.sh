#!/usr/bin/env bash
set -euo pipefail

# Strict EdgeOrient RR poisoning experiment.
# Rule implemented in the C++ file:
#   RR attack only overrides randomized edge values X[i,j] where both endpoints i and j are malicious.
#   It does not modify malicious-honest pairs, honest-honest pairs, k-core, max-out-degree, or final count/Laplace reports.

CPP="EdgeOrientDelta_TriangleLDP_RRAttack_strict.cpp"
EXE="./EdgeOrientDelta_TriangleLDP_RRAttack_strict"
OUT_DIR="../results_edgeorient_rr_strict"
LOG_DIR="${OUT_DIR}/logs"
mkdir -p "${OUT_DIR}" "${LOG_DIR}"

# You can edit these parameters directly.
EPS_LIST="${EPS_LIST:-0.5,1.0,2.0}"
PSI="${PSI:-0.5}"
WORKERS="${WORKERS:-4}"
RUNS="${RUNS:-5}"
NOISE="${NOISE:-1}"
SEED="${SEED:-1776}"
SELECTOR="${SELECTOR:-random}"       # random | high_degree | low_degree
POISON_PROB="${POISON_PROB:-1.0}"
RATIOS="${RATIOS:-0.025,0.05,0.075,0.10,0.125,0.15,0.175,0.20}"
SPLIT_FACTOR="${SPLIT_FACTOR:-0.5}"
BIAS_FACTOR="${BIAS_FACTOR:-8}"

# Edit node numbers here if your local preprocessing uses different n.
DATASETS=(
  "Gplus ../data/Gplus/edges.csv 10000"
  "IMDB ../data/IMDB/edges.csv 20000"
)

echo "[Compile] ${CPP}"
g++ -std=c++17 -O2 -Wall -Wextra -o "${EXE}" "${CPP}"

for item in "${DATASETS[@]}"; do
  read -r DATASET EDGE_FILE NODE_NUM <<< "${item}"
  if [[ ! -f "${EDGE_FILE}" ]]; then
    echo "[Skip] ${DATASET}: edge file not found: ${EDGE_FILE}"
    continue
  fi

  echo "============================================================"
  echo "[Run clean baseline] dataset=${DATASET}"
  echo "============================================================"
  CLEAN_CSV="${OUT_DIR}/${DATASET}_EdgeOrient_RR_clean.csv"
  CLEAN_LOG="${LOG_DIR}/${DATASET}_clean.log"
  "${EXE}" "${EDGE_FILE}" "${NODE_NUM}" "${EPS_LIST}" "${PSI}" "${WORKERS}" "${RUNS}" "${NOISE}" "${SEED}" \
    "${CLEAN_CSV}" none 0 0 "${SELECTOR}" "${SPLIT_FACTOR}" "${BIAS_FACTOR}" 2>&1 | tee "${CLEAN_LOG}"

  for DIRECTION in increase decrease; do
    echo "============================================================"
    echo "[Run strict RR attack] dataset=${DATASET} direction=${DIRECTION} ratios=${RATIOS}"
    echo "============================================================"
    OUT_CSV="${OUT_DIR}/${DATASET}_EdgeOrient_RR_${DIRECTION}.csv"
    LOG_FILE="${LOG_DIR}/${DATASET}_${DIRECTION}.log"
    "${EXE}" "${EDGE_FILE}" "${NODE_NUM}" "${EPS_LIST}" "${PSI}" "${WORKERS}" "${RUNS}" "${NOISE}" "${SEED}" \
      "${OUT_CSV}" "${DIRECTION}" "${RATIOS}" "${POISON_PROB}" "${SELECTOR}" "${SPLIT_FACTOR}" "${BIAS_FACTOR}" 2>&1 | tee "${LOG_FILE}"
  done
done

echo "[Done] Results are in ${OUT_DIR}"
