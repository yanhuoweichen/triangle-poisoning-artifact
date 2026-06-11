#!/bin/bash -x
set -euo pipefail

# Robustness experiments for CCS 2025 shuffle-DP triangle counting.
# Run from TriangleLDP/TriangleLDP/cpp after placing CCS25ShuffleTriangle.cpp here.
# Data files are expected at ../data/Gplus/edges.csv and ../data/IMDB/edges.csv.

CXX=${CXX:-g++}
TARGET=CCS25ShuffleTriangle
SRC=CCS25ShuffleTriangle.cpp

if [ ! -f "${TARGET}" ]; then
  ${CXX} -O3 -std=c++11 -march=native ${SRC} -o ${TARGET}
fi

RESULT_DIR=../results_ccs25_shuffle
LOG_DIR=${RESULT_DIR}/logs
mkdir -p ${RESULT_DIR} ${LOG_DIR}
OUT=${RESULT_DIR}/summary.csv

# Clear previous summary for a fresh full run. Comment this line if you want to append.
rm -f ${OUT}

DATASETS=("Gplus" "IMDB")
NODE_NUMS=("10000" "20000")
EPS_LIST=("1" "6")
RATIOS=("0.025" "0.05" "0.075" "0.10" "0.125" "0.15" "0.175" "0.20")
ATTACKS=("orig_increase" "orig_decrease" "rr_increase" "rr_decrease")
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
  echo "Dataset=${DATASET} NodeNum=${NODE_NUM} EdgeFile=${EDGE_FILE}"
  echo "Ratios=${RATIOS[*]}"
  echo "Attacks=${ATTACKS[*]}"
  echo "Eps=${EPS_LIST[*]} q=${Q} m=${M} strength=${ATTACK_STRENGTH}"
  echo "============================================================"

  # Compute the exact clean triangle count once per dataset and reuse it.
  CLEAN_LOG=${LOG_DIR}/${DATASET}_exact.log
  ./${TARGET} --mode exact --dataset ${DATASET} --edge_file ${EDGE_FILE} --node_num ${NODE_NUM} | tee ${CLEAN_LOG}
  CLEAN_TRIANGLES=$(grep "clean_triangles=" ${CLEAN_LOG} | head -n 1 | cut -d= -f2)
  echo "[Clean triangles] ${DATASET}: ${CLEAN_TRIANGLES}"

  for EPS in ${EPS_LIST[@]}; do
    for ((RUN=0; RUN<${RUNS}; RUN++)); do
      SEED=$((SEED_BASE + RUN))

      # Clean baseline for every run. Ratio is zero and attack strength is zero.
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

echo "All experiments finished. Summary CSV: ${OUT}"
