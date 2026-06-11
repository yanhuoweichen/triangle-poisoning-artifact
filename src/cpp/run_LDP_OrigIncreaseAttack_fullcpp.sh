#!/usr/bin/env bash
set -euo pipefail

# Strict original-data increase attack for TriangleLDP.
# Put this script and TriangleCounting_OrigIncreaseAttack.cpp in TriangleLDP/cpp, then run:
#   chmod +x run_LDP_OrigIncreaseAttack_fullcpp.sh
#   ./run_LDP_OrigIncreaseAttack_fullcpp.sh Gplus
#
# Optional:
#   ./run_LDP_OrigIncreaseAttack_fullcpp.sh IMDB
#   ALGS="2" ./run_LDP_OrigIncreaseAttack_fullcpp.sh Gplus
#   POISON_PROB=0.5 ./run_LDP_OrigIncreaseAttack_fullcpp.sh Gplus

DATASET="${1:-Gplus}"
NODE_NUM="${2:-10000}"

# Keep the same commonly used parameters as your previous 2022 LDP runs.
EPS_MU="${EPS_MU:-1-0.001}"
NSTYPE="${NSTYPE:-2}"
CLIP="${CLIP:-6-150}"
ITR="${ITR:-1-1}"
BALLOC="${BALLOC:-1-1}"

# One run for each ratio, as requested.
RATIOS="${RATIOS:-0.05 0.10 0.15 0.20}"
ALGS="${ALGS:-2 3 4}"
POISON_PROB="${POISON_PROB:-1.0}"
ATTACK_SEED="${ATTACK_SEED:-20220610}"

CPP="TriangleCounting_OrigIncreaseAttack.cpp"
EXE="./TriangleCounting_OrigIncreaseAttack"
EDGE_FILE="../data/${DATASET}/edges.csv"
LOG_DIR="../data/${DATASET}/orig_increase_attack_strict_logs"

if [ ! -f "${CPP}" ]; then
  echo "[Error] Cannot find ${CPP}. Put it in the current cpp directory first."
  exit 1
fi

if [ ! -f "${EDGE_FILE}" ]; then
  echo "[Error] Cannot find edge file: ${EDGE_FILE}"
  exit 1
fi

RNG_SRC=""
if [ -f "mt19937ar.c" ]; then
  RNG_SRC="mt19937ar.c"
elif [ -f "mt19937ar.cpp" ]; then
  RNG_SRC="mt19937ar.cpp"
else
  echo "[Error] Cannot find mt19937ar.c or mt19937ar.cpp in current directory."
  exit 1
fi

mkdir -p "${LOG_DIR}"

echo "[Compile] ${CPP}"
g++ -O3 -std=c++11 -I. -Iinclude "${CPP}" "${RNG_SRC}" -o "${EXE}"

echo "============================================================"
echo "Strict original-data increase attack for 2022 TriangleLDP"
echo "Dataset      : ${DATASET}"
echo "Edge file    : ${EDGE_FILE}"
echo "NodeNum      : ${NODE_NUM}"
echo "eps-mu       : ${EPS_MU}"
echo "NSType       : ${NSTYPE}"
echo "clip         : ${CLIP}"
echo "Itr          : ${ITR}"
echo "Balloc       : ${BALLOC}"
echo "Algs         : ${ALGS}"
echo "Ratios       : ${RATIOS}"
echo "PoisonProb   : ${POISON_PROB}"
echo "AttackSeed   : ${ATTACK_SEED}"
echo "Log dir      : ${LOG_DIR}"
echo "============================================================"

for ALG in ${ALGS}; do
  for RATIO in ${RATIOS}; do
    RATIO_TAG="${RATIO/./p}"
    LOG_FILE="${LOG_DIR}/origInc_${DATASET}_n${NODE_NUM}_alg${ALG}_r${RATIO_TAG}_p${POISON_PROB}_seed${ATTACK_SEED}.log"

    echo "------------------------------------------------------------"
    echo "[Run] dataset=${DATASET} alg=${ALG} ratio=${RATIO}"
    echo "------------------------------------------------------------"

    "${EXE}" "${EDGE_FILE}" "${NODE_NUM}" "${EPS_MU}" "${NSTYPE}" "${CLIP}" "${ITR}" "${ALG}" "${BALLOC}" "${RATIO}" "${POISON_PROB}" "${ATTACK_SEED}" \
      2>&1 | tee "${LOG_FILE}"

    echo "[Done] log: ${LOG_FILE}"
  done
done

echo "============================================================"
echo "[All done]"
echo "Result CSV files are written next to ${EDGE_FILE}."
echo "Look for filenames containing: _origInc_r0p05 / _origInc_r0p10 / _origInc_r0p15 / _origInc_r0p20"
echo "In logs, check: added_edges > 0 and true_triangles_after changes."
echo "============================================================"
