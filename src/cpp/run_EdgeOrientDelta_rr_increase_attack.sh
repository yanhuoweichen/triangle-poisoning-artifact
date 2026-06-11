#!/usr/bin/env bash
set -euo pipefail

# TriangleLDP-style runner for RR-output increasing attack on EdgeOrientDelta.
# Put this script and EdgeOrientDelta_TriangleLDP_RR_IncreaseAttack.cpp under TriangleLDP/cpp/.
#
# Usage:
#   ./run_EdgeOrientDelta_rr_increase_attack.sh [Dataset] [n|-1] [epsilon_list] [workers] [runs] [noise:0|1] [malicious_ratio_list] [poison_prob] [selection] [owner_mode]
#
# Example:
#   ./run_EdgeOrientDelta_rr_increase_attack.sh Gplus 10000 1.0 2 5 1 0.05,0.10,0.20 1.0 random reporter
#
# selection: random | high_degree | low_degree
# owner_mode: reporter | either
#   reporter: only the reporter/owner of the upper-triangular RR bit can poison it; conservative and recommended.
#   either: the RR bit can be poisoned if either endpoint is malicious; stronger attack.

DATASET=${1:-Gplus}
N=${2:-10000}
EPS_LIST=${3:-1.0}
WORKERS=${4:-2}
RUNS=${5:-5}
NOISE=${6:-1}
MALICIOUS_RATIOS=${7:-0.05,0.10,0.20}
POISON_PROB=${8:-1.0}
SELECTION=${9:-random}
OWNER_MODE=${10:-reporter}

PSI=${PSI:-0.5}
SEED=${SEED:-1776}
SPLIT_FACTOR=${SPLIT_FACTOR:-0.5}
BIAS_FACTOR=${BIAS_FACTOR:-8}

CPP=EdgeOrientDelta_TriangleLDP_RR_IncreaseAttack.cpp
BIN=EdgeOrientDelta_TriangleLDP_RR_IncreaseAttack
EDGE_FILE=../data/${DATASET}/edges.csv
OUT_FILE=../data/${DATASET}/EdgeOrientDelta_RRAttack_increase_n${N}_eps${EPS_LIST//,/_}_p${MALICIOUS_RATIOS//,/_}_prob${POISON_PROB}.csv

if [[ ! -f "${EDGE_FILE}" ]]; then
  echo "Cannot find ${EDGE_FILE}"
  echo "Please run TriangleLDP preprocessing first, e.g. python/ReadGPlus.py or python/ReadIMDB.py."
  exit 1
fi

if [[ ! -f "${CPP}" ]]; then
  echo "Cannot find ${CPP}. Put this script and ${CPP} in TriangleLDP/cpp/."
  exit 1
fi

echo "[compile] g++ -O3 -std=c++11 -march=native ${CPP} -o ${BIN}"
g++ -O3 -std=c++11 -march=native "${CPP}" -o "${BIN}"

echo "[run] dataset=${DATASET}, n=${N}, eps=${EPS_LIST}, workers=${WORKERS}, runs=${RUNS}, noise=${NOISE}, rr_attack=increase, ratios=${MALICIOUS_RATIOS}, poison_prob=${POISON_PROB}, selection=${SELECTION}, owner_mode=${OWNER_MODE}"
./"${BIN}" "${EDGE_FILE}" "${N}" "${EPS_LIST}" "${PSI}" "${WORKERS}" "${RUNS}" "${NOISE}" "${SEED}" "${OUT_FILE}" "${MALICIOUS_RATIOS}" "${POISON_PROB}" "${SELECTION}" "${OWNER_MODE}" "${SPLIT_FACTOR}" "${BIAS_FACTOR}"

echo "Done. Results: ${OUT_FILE}"
