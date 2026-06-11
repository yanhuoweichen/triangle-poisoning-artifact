#!/bin/bash
set -euo pipefail

DATASET="Gplus"
EDGE_FILE="../data/${DATASET}/edges.csv"
NODE_NUM=20000
EPS_DELTA="1-8"
PAIR_NUM="-1"
ITR_BIP="20-1"
ALGS=("2n" "3n" "4n")
RATIOS=("0.025" "0.05" "0.075" "0.10" "0.125" "0.15" "0.175" "0.20")
LABELS=("2p5" "5" "7p5" "10" "12p5" "15" "17p5" "20")

# Put this script and the two cpp files under Triangle4CycleShuffle/cpp/.
# It compiles the strict attack binaries directly from the provided cpp files.
if [[ ! -f "SubgraphShuffle_RRAttack_strict.cpp" ]]; then
  echo "ERROR: SubgraphShuffle_RRAttack_strict.cpp not found in current directory." >&2
  exit 1
fi
if [[ ! -f "SubgraphShuffle_ShuffleAttack_strict.cpp" ]]; then
  echo "ERROR: SubgraphShuffle_ShuffleAttack_strict.cpp not found in current directory." >&2
  exit 1
fi

rm -f SubgraphShuffle_RRAttack_strict SubgraphShuffle_ShuffleAttack_strict

compile_one() {
  local SRC_CPP="$1"
  local BIN="$2"
  echo "[Compile] ${SRC_CPP}"
  if [[ -f "mt19937ar.c" ]]; then
    g++ -march=native -O3 -std=c++11 -isystem ./include -MMD "${SRC_CPP}" mt19937ar.c -o "${BIN}"
  else
    g++ -march=native -O3 -std=c++11 -isystem ./include -MMD "${SRC_CPP}" -o "${BIN}"
  fi
}

compile_one "SubgraphShuffle_RRAttack_strict.cpp" "SubgraphShuffle_RRAttack_strict"
compile_one "SubgraphShuffle_ShuffleAttack_strict.cpp" "SubgraphShuffle_ShuffleAttack_strict"

run_one() {
  local BIN="$1"          # SubgraphShuffle_RRAttack_strict or SubgraphShuffle_ShuffleAttack_strict
  local ATTACK_NAME="$2"  # RR or shuffle
  local DIR="$3"          # increase or decrease
  local RATIO="$4"
  local LABEL="$5"
  local ALG="$6"

  local OUTDIR="../data/${DATASET}/robust_strict_${ATTACK_NAME}_${DIR}"
  mkdir -p "${OUTDIR}"

  echo "============================================================"
  echo "[Run] dataset=${DATASET} attack=${ATTACK_NAME} direction=${DIR} ratio=${RATIO} alg=${ALG}"
  echo "============================================================"

  # Extra args after alg: malicious_ratio direction.
  # RR strict: only edge RR reports with both endpoints malicious are changed.
  # Shuffle strict: only wedge messages for fully malicious triangle candidates are changed.
  "./${BIN}" "${EDGE_FILE}" "${NODE_NUM}" "${EPS_DELTA}" "${PAIR_NUM}" "${ITR_BIP}" "${ALG}" "${RATIO}" "${DIR}"

  local SRC="../data/${DATASET}/res_n${NODE_NUM}_alg${ALG}_eps${EPS_DELTA}_pair${PAIR_NUM}_itr${ITR_BIP}.csv"
  local DST="${OUTDIR}/ratio_${LABEL}_res_n${NODE_NUM}_alg${ALG}_eps${EPS_DELTA}_pair${PAIR_NUM}_itr${ITR_BIP}.csv"
  if [[ ! -f "${SRC}" ]]; then
    echo "ERROR: expected output not found: ${SRC}" >&2
    exit 1
  fi
  mv -f "${SRC}" "${DST}"
  echo "[Saved] ${DST}"
}

for i in "${!RATIOS[@]}"; do
  RATIO="${RATIOS[$i]}"
  LABEL="${LABELS[$i]}"
  for ALG in "${ALGS[@]}"; do
    run_one "SubgraphShuffle_RRAttack_strict" "RR" "increase" "${RATIO}" "${LABEL}" "${ALG}"
    run_one "SubgraphShuffle_RRAttack_strict" "RR" "decrease" "${RATIO}" "${LABEL}" "${ALG}"
    run_one "SubgraphShuffle_ShuffleAttack_strict" "shuffle" "increase" "${RATIO}" "${LABEL}" "${ALG}"
    run_one "SubgraphShuffle_ShuffleAttack_strict" "shuffle" "decrease" "${RATIO}" "${LABEL}" "${ALG}"
  done
done

echo "All ${DATASET} strict shuffle-DP attack experiments finished."
