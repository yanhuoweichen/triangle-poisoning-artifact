#!/usr/bin/env bash
set -euo pipefail

DATASET="${1:-Gplus}"
SRC="TriangleCounting_OrigIncrease_ARROneNS.cpp"
EXE="./TriangleCounting_OrigIncrease_ARROneNS"

EDGE_FILE="../data/${DATASET}/edges.csv"
LOG_DIR="../data/${DATASET}/orig_increase_ARROneNS_logs"
mkdir -p "${LOG_DIR}"

if [[ ! -f "${SRC}" ]]; then
  echo "[Error] Cannot find ${SRC} in current directory."
  echo "[Hint] Put ${SRC} and this sh file under /home/allen/TriangleLDP/cpp"
  exit 1
fi

if [[ ! -f "${EDGE_FILE}" ]]; then
  echo "[Error] Cannot find edge file: ${EDGE_FILE}"
  echo "[Hint] Run this script under /home/allen/TriangleLDP/cpp, or check ../data/${DATASET}/edges.csv"
  exit 1
fi

CXX="${CXX:-g++}"
CXXFLAGS="${CXXFLAGS:--O3 -std=c++11}"

# This file is self-contained for the original mt19937ar calls, so do NOT add mt19937ar.c/h.
echo "[Compile] ${SRC} -> ${EXE}"
${CXX} ${CXXFLAGS} "${SRC}" -o "${EXE}" -lm

NODE_NUM="${NODE_NUM:-10000}"
EPS_MU="${EPS_MU:-1-0.001}"
NSTYPE="${NSTYPE:-2}"
CLIP="${CLIP:-6-150}"
ITR="${ITR:-1-1}"
ALG="3"   # ARROneNS in the original TriangleLDP code
BALLOC="${BALLOC:-1-1}"
POISON_PROB="${POISON_PROB:-1.0}"
SEED="${SEED:-1776}"
RATIOS="${RATIOS:-0.05 0.10 0.15 0.20}"

echo "============================================================"
echo "LDP original-data increase attack: ARROneNS only"
echo "Dataset      = ${DATASET}"
echo "Edge file    = ${EDGE_FILE}"
echo "NodeNum      = ${NODE_NUM}"
echo "Params       = eps_mu=${EPS_MU}, ns=${NSTYPE}, cl=${CLIP}, itr=${ITR}, alg=${ALG}, balloc=${BALLOC}"
echo "Ratios       = ${RATIOS}"
echo "PoisonProb   = ${POISON_PROB}"
echo "Seed         = ${SEED}"
echo "============================================================"

for RATIO in ${RATIOS}; do
  RATIO_TAG=$(python3 - <<PY
r=float("${RATIO}")
print(f"{int(round(r*100))}pct")
PY
)
  LOG_FILE="${LOG_DIR}/origInc_ARROneNS_${RATIO_TAG}.log"
  echo "[Run] ratio=${RATIO} (${RATIO_TAG})"
  "${EXE}" "${EDGE_FILE}" "${NODE_NUM}" "${EPS_MU}" "${NSTYPE}" "${CLIP}" "${ITR}" "${ALG}" "${BALLOC}" "${RATIO}" "${POISON_PROB}" "${SEED}" | tee "${LOG_FILE}"
  echo "[Log] ${LOG_FILE}"
done

echo "============================================================"
echo "[Done] Generated CSV files:"
ls -lh ../data/${DATASET}/res_n${NODE_NUM}_alg3_eps${EPS_MU}_ns${NSTYPE}_cl${CLIP}_ba${BALLOC}_itr1-1_origInc_r*pct.csv 2>/dev/null || true
echo "============================================================"
