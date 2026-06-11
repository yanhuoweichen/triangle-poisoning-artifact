#!/bin/bash -x
set -euo pipefail

# Run only the corrected malicious-pair RR attacks for CCS25 ShuffleDP triangle counting.
# Run from TriangleLDP/TriangleLDP/cpp after placing this script and
# CCS25ShuffleTriangle_fixed_malpairRR.cpp in the cpp directory.
# This script does NOT require renaming the cpp file.

CXX=${CXX:-g++}
SRC=CCS25ShuffleTriangle_fixed_malpairRR.cpp
TARGET=CCS25ShuffleTriangle_fixed_malpairRR

if [ ! -f "${SRC}" ]; then
  echo "ERROR: ${SRC} not found in current directory."
  echo "Please put CCS25ShuffleTriangle_fixed_malpairRR.cpp in this cpp directory first."
  exit 1
fi

# Recompile if executable is missing or source is newer.
if [ ! -f "${TARGET}" ] || [ "${SRC}" -nt "${TARGET}" ]; then
  ${CXX} -O3 -std=c++11 -march=native ${SRC} -o ${TARGET}
fi

RESULT_DIR=../results_ccs25_shuffle_rr_fixed
LOG_DIR=${RESULT_DIR}/logs
mkdir -p ${RESULT_DIR} ${LOG_DIR}
OUT=${RESULT_DIR}/summary_rr_fixed.csv

# Fresh RR-only fixed run. This avoids mixing old wide-RR results with corrected RR results.
rm -f ${OUT}

DATASETS=("Gplus" "IMDB")
NODE_NUMS=("10000" "20000")
EPS_LIST=("1" "6")
RATIOS=("0.025" "0.05" "0.075" "0.10" "0.125" "0.15" "0.175" "0.20")
ATTACKS=("rr_increase" "rr_decrease")
RUNS=5
SEED_BASE=1776
Q=0.05
M=10
ATTACK_STRENGTH=1.0
BUDGET_MODE=simple
COMPUTE_TRUE_AFTER=0

for idx in ${!DATASETS[@]}; do
  DATASET=${DATASETS[$idx]}
  NODE_NUM=${NODE_NUMS[$idx]}
  EDGE_FILE=../data/${DATASET}/edges.csv

  echo "============================================================"
  echo "Corrected malicious-pair RR attacks only"
  echo "Dataset=${DATASET} NodeNum=${NODE_NUM} EdgeFile=${EDGE_FILE}"
  echo "Ratios=${RATIOS[*]}"
  echo "Attacks=${ATTACKS[*]}"
  echo "Eps=${EPS_LIST[*]} q=${Q} m=${M} strength=${ATTACK_STRENGTH}"
  echo "Output=${OUT}"
  echo "============================================================"

  CLEAN_LOG=${LOG_DIR}/${DATASET}_exact.log
  ./${TARGET} --mode exact --dataset ${DATASET} --edge_file ${EDGE_FILE} --node_num ${NODE_NUM} | tee ${CLEAN_LOG}
  CLEAN_TRIANGLES=$(grep "clean_triangles=" ${CLEAN_LOG} | head -n 1 | cut -d= -f2)
  echo "[Clean triangles] ${DATASET}: ${CLEAN_TRIANGLES}"

  for EPS in ${EPS_LIST[@]}; do
    for ((RUN=0; RUN<${RUNS}; RUN++)); do
      SEED=$((SEED_BASE + RUN))

      # Clean baseline for every run, so this RR-only CSV can be plotted independently.
      ./${TARGET} \
        --mode run \
        --dataset ${DATASET} \
        --edge_file ${EDGE_FILE} \
        --node_num ${NODE_NUM} \
        --eps ${EPS} \
        --q ${Q} \
        --m ${M} \
        --budget_mode ${BUDGET_MODE} \
        --attack_type clean \
        --malicious_ratio 0 \
        --attack_strength 0 \
        --run ${RUN} \
        --seed ${SEED} \
        --clean_triangles ${CLEAN_TRIANGLES} \
        --compute_true_after ${COMPUTE_TRUE_AFTER} \
        --output ${OUT} \
        2>&1 | tee ${LOG_DIR}/${DATASET}_eps${EPS}_run${RUN}_clean.log

      for ATTACK in ${ATTACKS[@]}; do
        for RATIO in ${RATIOS[@]}; do
          ./${TARGET} \
            --mode run \
            --dataset ${DATASET} \
            --edge_file ${EDGE_FILE} \
            --node_num ${NODE_NUM} \
            --eps ${EPS} \
            --q ${Q} \
            --m ${M} \
            --budget_mode ${BUDGET_MODE} \
            --attack_type ${ATTACK} \
            --malicious_ratio ${RATIO} \
            --attack_strength ${ATTACK_STRENGTH} \
            --run ${RUN} \
            --seed ${SEED} \
            --clean_triangles ${CLEAN_TRIANGLES} \
            --compute_true_after ${COMPUTE_TRUE_AFTER} \
            --output ${OUT} \
            2>&1 | tee ${LOG_DIR}/${DATASET}_eps${EPS}_run${RUN}_${ATTACK}_r${RATIO}.log
        done
      done
    done
  done
done

echo "Corrected RR-only experiments finished. Summary CSV: ${OUT}"
