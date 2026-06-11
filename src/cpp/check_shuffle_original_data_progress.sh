#!/bin/bash
set -euo pipefail
NODE_NUM=20000
EPS_DELTA="1-8"
PAIR_NUM="-1"
ITR_BIP="20-1"
DATASETS=("Gplus" "IMDB")
ALGS=("2n" "3n" "4n")
LABELS=("5" "10" "15" "20")
DIRECTIONS=("increase" "decrease")
TOTAL=0
OK=0
for DATASET in "${DATASETS[@]}"; do
  DATASET_TOTAL=0
  DATASET_OK=0
  for DIR in "${DIRECTIONS[@]}"; do
    for LABEL in "${LABELS[@]}"; do
      for ALG in "${ALGS[@]}"; do
        TOTAL=$((TOTAL+1)); DATASET_TOTAL=$((DATASET_TOTAL+1))
        FILE="../data/${DATASET}/robust_strict_original_${DIR}/ratio_${LABEL}_res_n${NODE_NUM}_alg${ALG}_eps${EPS_DELTA}_pair${PAIR_NUM}_itr${ITR_BIP}.csv"
        if [[ -f "${FILE}" ]] && [[ $(wc -l < "${FILE}" | tr -d ' ') -ge 24 ]]; then
          OK=$((OK+1)); DATASET_OK=$((DATASET_OK+1))
        else
          echo "[Missing/Incomplete] ${FILE}"
        fi
      done
    done
  done
  echo "${DATASET}: ${DATASET_OK}/${DATASET_TOTAL} completed"
done
echo "Total: ${OK}/${TOTAL} completed"
