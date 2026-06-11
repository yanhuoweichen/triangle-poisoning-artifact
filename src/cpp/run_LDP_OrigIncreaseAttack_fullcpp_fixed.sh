#!/usr/bin/env bash
set -euo pipefail

# Strict original-data increase attack for TriangleLDP.
# Put this script and TriangleCounting_OrigIncreaseAttack.cpp in TriangleLDP/cpp, then run:
#   chmod +x run_LDP_OrigIncreaseAttack_fullcpp_fixed.sh
#   ./run_LDP_OrigIncreaseAttack_fullcpp_fixed.sh Gplus
#
# This fixed version automatically searches for mt19937ar.c/cpp in the project tree,
# instead of requiring it to be in the current cpp directory.

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

# Locate the mt19937 implementation source.
# Some TriangleLDP copies put it in cpp/, some in the project root or other subdirectories.
RNG_SRC=""
for cand in \
  "mt19937ar.c" \
  "mt19937ar.cpp" \
  "../mt19937ar.c" \
  "../mt19937ar.cpp" \
  "../../mt19937ar.c" \
  "../../mt19937ar.cpp" \
  "src/mt19937ar.c" \
  "src/mt19937ar.cpp" \
  "../src/mt19937ar.c" \
  "../src/mt19937ar.cpp" \
  "../include/mt19937ar.c" \
  "../include/mt19937ar.cpp" \
  "include/mt19937ar.c" \
  "include/mt19937ar.cpp"
do
  if [ -f "${cand}" ]; then
    RNG_SRC="${cand}"
    break
  fi
done

if [ -z "${RNG_SRC}" ]; then
  RNG_SRC="$(find .. -name 'mt19937ar.c' -o -name 'mt19937ar.cpp' 2>/dev/null | head -n 1 || true)"
fi

if [ -z "${RNG_SRC}" ]; then
  echo "[Error] Cannot find mt19937ar.c or mt19937ar.cpp under this project."
  echo "[Hint] Run this command in /home/allen/TriangleLDP/cpp to check where it is:"
  echo "       find .. -name 'mt19937ar.*'"
  echo "[Hint] If only mt19937ar.o exists, run: make clean or provide the .c/.cpp file from the original repo."
  exit 1
fi

echo "[Info] Using RNG source: ${RNG_SRC}"
mkdir -p "${LOG_DIR}"

echo "[Compile] ${CPP}"
g++ -O3 -std=c++11 -I. -Iinclude -I.. -I../include "${CPP}" "${RNG_SRC}" -o "${EXE}"

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
