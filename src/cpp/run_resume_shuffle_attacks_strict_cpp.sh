#!/bin/bash
set -euo pipefail

# Resume-safe strict shuffle-DP attack runner.
# Put this file under Triangle4CycleShuffle/cpp/ together with:
#   SubgraphShuffle_RRAttack_strict.cpp
#   SubgraphShuffle_ShuffleAttack_strict.cpp
# It skips finished CSV files and only reruns missing or incomplete results.

NODE_NUM=20000
EPS_DELTA="1-8"
PAIR_NUM="-1"
ITR_BIP="20-1"
ALGS=("2n" "3n" "4n")
RATIOS=("0.025" "0.05" "0.075" "0.10" "0.125" "0.15" "0.175" "0.20")
LABELS=("2p5" "5" "7p5" "10" "12p5" "15" "17p5" "20")
DATASETS=("Gplus" "IMDB")

compile_one() {
  local SRC_CPP="$1"
  local BIN="$2"
  if [[ ! -f "${SRC_CPP}" ]]; then
    echo "ERROR: ${SRC_CPP} not found in current directory." >&2
    exit 1
  fi
  echo "[Compile] ${SRC_CPP} -> ${BIN}"
  if [[ -f "mt19937ar.c" ]]; then
    g++ -march=native -O3 -std=c++11 -isystem ./include -MMD "${SRC_CPP}" mt19937ar.c -o "${BIN}"
  else
    g++ -march=native -O3 -std=c++11 -isystem ./include -MMD "${SRC_CPP}" -o "${BIN}"
  fi
}

# A completed CSV should contain 20 numeric run rows and the final summary line "Triangles,".
is_complete_csv() {
  local FILE="$1"
  [[ -s "${FILE}" ]] || return 1
  local NUMERIC_ROWS
  NUMERIC_ROWS=$(awk -F',' 'NR>1 { if ($1 ~ /^[-+]?[0-9.]+([eE][-+]?[0-9]+)?$/) c++ } END { print c+0 }' "${FILE}")
  [[ "${NUMERIC_ROWS}" -eq 20 ]] || return 1
  grep -q '^Triangles,' "${FILE}" || return 1
  return 0
}

run_one() {
  local DATASET="$1"
  local BIN="$2"          # SubgraphShuffle_RRAttack_strict or SubgraphShuffle_ShuffleAttack_strict
  local ATTACK_NAME="$3"  # RR or shuffle
  local DIR="$4"          # increase or decrease
  local RATIO="$5"
  local LABEL="$6"
  local ALG="$7"

  local EDGE_FILE="../data/${DATASET}/edges.csv"
  local OUTDIR="../data/${DATASET}/robust_strict_${ATTACK_NAME}_${DIR}"
  local SRC="../data/${DATASET}/res_n${NODE_NUM}_alg${ALG}_eps${EPS_DELTA}_pair${PAIR_NUM}_itr${ITR_BIP}.csv"
  local DST="${OUTDIR}/ratio_${LABEL}_res_n${NODE_NUM}_alg${ALG}_eps${EPS_DELTA}_pair${PAIR_NUM}_itr${ITR_BIP}.csv"

  if [[ ! -f "${EDGE_FILE}" ]]; then
    echo "ERROR: edge file not found: ${EDGE_FILE}" >&2
    exit 1
  fi

  mkdir -p "${OUTDIR}"

  if is_complete_csv "${DST}"; then
    echo "[Skip] completed: ${DST}"
    return 0
  fi

  echo "============================================================"
  echo "[Run] dataset=${DATASET} attack=${ATTACK_NAME} direction=${DIR} ratio=${RATIO} alg=${ALG}"
  echo "============================================================"

  rm -f "${SRC}"
  "./${BIN}" "${EDGE_FILE}" "${NODE_NUM}" "${EPS_DELTA}" "${PAIR_NUM}" "${ITR_BIP}" "${ALG}" "${RATIO}" "${DIR}"

  if [[ ! -f "${SRC}" ]]; then
    echo "ERROR: expected output not found: ${SRC}" >&2
    exit 1
  fi

  mv -f "${SRC}" "${DST}"

  if ! is_complete_csv "${DST}"; then
    echo "ERROR: output seems incomplete: ${DST}" >&2
    exit 1
  fi

  echo "[Saved] ${DST}"
}

check_progress() {
  local DATASET="$1"
  local DONE=0
  local EXPECTED=$(( ${#RATIOS[@]} * ${#ALGS[@]} * 4 ))
  local LABEL ALG ATTACK_DIR DIR OUTDIR DST
  for LABEL in "${LABELS[@]}"; do
    for ALG in "${ALGS[@]}"; do
      for ATTACK_DIR in "RR:increase" "RR:decrease" "shuffle:increase" "shuffle:decrease"; do
        ATTACK_NAME="${ATTACK_DIR%%:*}"
        DIR="${ATTACK_DIR##*:}"
        OUTDIR="../data/${DATASET}/robust_strict_${ATTACK_NAME}_${DIR}"
        DST="${OUTDIR}/ratio_${LABEL}_res_n${NODE_NUM}_alg${ALG}_eps${EPS_DELTA}_pair${PAIR_NUM}_itr${ITR_BIP}.csv"
        if is_complete_csv "${DST}"; then
          DONE=$((DONE+1))
        fi
      done
    done
  done
  echo "[Progress] ${DATASET}: ${DONE}/${EXPECTED} completed"
}

compile_one "SubgraphShuffle_RRAttack_strict.cpp" "SubgraphShuffle_RRAttack_strict"
compile_one "SubgraphShuffle_ShuffleAttack_strict.cpp" "SubgraphShuffle_ShuffleAttack_strict"

for DATASET in "${DATASETS[@]}"; do
  echo "############################################################"
  echo "[Dataset] ${DATASET}"
  echo "############################################################"
  for i in "${!RATIOS[@]}"; do
    RATIO="${RATIOS[$i]}"
    LABEL="${LABELS[$i]}"
    for ALG in "${ALGS[@]}"; do
      run_one "${DATASET}" "SubgraphShuffle_RRAttack_strict" "RR" "increase" "${RATIO}" "${LABEL}" "${ALG}"
      run_one "${DATASET}" "SubgraphShuffle_RRAttack_strict" "RR" "decrease" "${RATIO}" "${LABEL}" "${ALG}"
      run_one "${DATASET}" "SubgraphShuffle_ShuffleAttack_strict" "shuffle" "increase" "${RATIO}" "${LABEL}" "${ALG}"
      run_one "${DATASET}" "SubgraphShuffle_ShuffleAttack_strict" "shuffle" "decrease" "${RATIO}" "${LABEL}" "${ALG}"
    done
  done
  check_progress "${DATASET}"
done

echo "All missing strict shuffle-DP attack experiments finished."
