#!/bin/bash
set -euo pipefail

# Quick original-data poisoning experiments for Shuffle DP triangle counting.
# Put this script and SubgraphShuffle_OriginalDataAttack_strict.cpp under Triangle4CycleShuffle/cpp/.

SRC_CPP="SubgraphShuffle_OriginalDataAttack_strict.cpp"
BIN="SubgraphShuffle_OriginalDataAttack_strict"
NODE_NUM=20000
EPS_DELTA="1-8"
PAIR_NUM="-1"
ITR_BIP="20-1"
DATASETS=("Gplus" "IMDB")
ALGS=("2n" "3n" "4n")
RATIOS=("0.05" "0.10" "0.15" "0.20")
LABELS=("5" "10" "15" "20")
DIRECTIONS=("increase" "decrease")

if [[ ! -f "${SRC_CPP}" ]]; then
  echo "ERROR: ${SRC_CPP} not found in current directory." >&2
  exit 1
fi

compile_one() {
  echo "[Compile] ${SRC_CPP}"
  rm -f "${BIN}"
  if [[ -f "mt19937ar.c" ]]; then
    g++ -march=native -O3 -std=c++11 -isystem ./include -MMD "${SRC_CPP}" mt19937ar.c -o "${BIN}"
  else
    g++ -march=native -O3 -std=c++11 -isystem ./include -MMD "${SRC_CPP}" -o "${BIN}"
  fi
}

run_one() {
  local DATASET="$1"
  local DIR="$2"
  local RATIO="$3"
  local LABEL="$4"
  local ALG="$5"
  local EDGE_FILE="../data/${DATASET}/edges.csv"
  local OUTDIR="../data/${DATASET}/robust_strict_original_${DIR}"
  local SRC="../data/${DATASET}/res_n${NODE_NUM}_alg${ALG}_eps${EPS_DELTA}_pair${PAIR_NUM}_itr${ITR_BIP}.csv"
  local DST="${OUTDIR}/ratio_${LABEL}_res_n${NODE_NUM}_alg${ALG}_eps${EPS_DELTA}_pair${PAIR_NUM}_itr${ITR_BIP}.csv"

  mkdir -p "${OUTDIR}"
  if [[ -f "${DST}" ]]; then
    line_count=$(wc -l < "${DST}" | tr -d ' ')
    if [[ "${line_count}" -ge 24 ]]; then
      echo "[Skip] already complete: ${DST}"
      return 0
    else
      echo "[Redo] incomplete existing file: ${DST}"
      rm -f "${DST}"
    fi
  fi

  echo "============================================================"
  echo "[Run] dataset=${DATASET} attack=original-data direction=${DIR} ratio=${RATIO} alg=${ALG}"
  echo "============================================================"

  # Extra args after alg: malicious_ratio direction.
  # Original-data strict attack:
  #   increase: malicious-malicious original edges are forced to 1.
  #   decrease: malicious-malicious original edges are forced to 0.
  "./${BIN}" "${EDGE_FILE}" "${NODE_NUM}" "${EPS_DELTA}" "${PAIR_NUM}" "${ITR_BIP}" "${ALG}" "${RATIO}" "${DIR}"

  if [[ ! -f "${SRC}" ]]; then
    echo "ERROR: expected output not found: ${SRC}" >&2
    exit 1
  fi
  mv -f "${SRC}" "${DST}"
  echo "[Saved] ${DST}"
}

compile_one

for DATASET in "${DATASETS[@]}"; do
  for i in "${!RATIOS[@]}"; do
    RATIO="${RATIOS[$i]}"
    LABEL="${LABELS[$i]}"
    for ALG in "${ALGS[@]}"; do
      for DIR in "${DIRECTIONS[@]}"; do
        run_one "${DATASET}" "${DIR}" "${RATIO}" "${LABEL}" "${ALG}"
      done
    done
  done
done

echo "All quick strict original-data shuffle-DP attack experiments finished."
