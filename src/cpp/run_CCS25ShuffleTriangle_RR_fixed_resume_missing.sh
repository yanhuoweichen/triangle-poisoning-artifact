#!/usr/bin/env bash
set -euo pipefail
set -x

EXE=./CCS25ShuffleTriangle_fixed_malpairRR
CPP=CCS25ShuffleTriangle_fixed_malpairRR.cpp

OUT_DIR=../results_ccs25_shuffle_rr_fixed
OUT_CSV=${OUT_DIR}/summary_rr_fixed.csv
LOG_DIR=${OUT_DIR}/logs_resume_missing

mkdir -p "${OUT_DIR}"
mkdir -p "${LOG_DIR}"

if [ ! -x "${EXE}" ]; then
    g++ -O3 -std=c++11 -o CCS25ShuffleTriangle_fixed_malpairRR "${CPP}"
fi

DATASET=IMDB
EDGE_FILE=../data/IMDB/edges.csv
NODE_NUM=20000
CLEAN_TRIANGLES=54097

Q=0.05
M=10
BUDGET_MODE=simple
ATTACK_STRENGTH=1.0

RATIOS=(0.025 0.05 0.075 0.10 0.125 0.15 0.175 0.20)

# ============================================================
# Missing part 1:
# IMDB eps=1 run=3 only missing rr_decrease ratio=0.175 and 0.20
# seed = 1776 + run = 1779
# ============================================================

EPS=1
RUN=3
SEED=$((1776 + RUN))

for RATIO in 0.175 0.20; do
    "${EXE}" \
      --mode run \
      --dataset "${DATASET}" \
      --edge_file "${EDGE_FILE}" \
      --node_num "${NODE_NUM}" \
      --eps "${EPS}" \
      --q "${Q}" \
      --m "${M}" \
      --budget_mode "${BUDGET_MODE}" \
      --attack_type rr_decrease \
      --malicious_ratio "${RATIO}" \
      --attack_strength "${ATTACK_STRENGTH}" \
      --run "${RUN}" \
      --seed "${SEED}" \
      --clean_triangles "${CLEAN_TRIANGLES}" \
      --compute_true_after 0 \
      --output "${OUT_CSV}" \
      2>&1 | tee "${LOG_DIR}/IMDB_eps${EPS}_run${RUN}_rr_decrease_r${RATIO}.log"
done

# ============================================================
# Missing part 2:
# IMDB eps=1 run=4 all clean + rr attacks
# seed = 1776 + run = 1780
# ============================================================

EPS=1
RUN=4
SEED=$((1776 + RUN))

"${EXE}" \
  --mode run \
  --dataset "${DATASET}" \
  --edge_file "${EDGE_FILE}" \
  --node_num "${NODE_NUM}" \
  --eps "${EPS}" \
  --q "${Q}" \
  --m "${M}" \
  --budget_mode "${BUDGET_MODE}" \
  --attack_type clean \
  --malicious_ratio 0.0 \
  --attack_strength 0.0 \
  --run "${RUN}" \
  --seed "${SEED}" \
  --clean_triangles "${CLEAN_TRIANGLES}" \
  --compute_true_after 0 \
  --output "${OUT_CSV}" \
  2>&1 | tee "${LOG_DIR}/IMDB_eps${EPS}_run${RUN}_clean.log"

for ATTACK in rr_increase rr_decrease; do
    for RATIO in "${RATIOS[@]}"; do
        "${EXE}" \
          --mode run \
          --dataset "${DATASET}" \
          --edge_file "${EDGE_FILE}" \
          --node_num "${NODE_NUM}" \
          --eps "${EPS}" \
          --q "${Q}" \
          --m "${M}" \
          --budget_mode "${BUDGET_MODE}" \
          --attack_type "${ATTACK}" \
          --malicious_ratio "${RATIO}" \
          --attack_strength "${ATTACK_STRENGTH}" \
          --run "${RUN}" \
          --seed "${SEED}" \
          --clean_triangles "${CLEAN_TRIANGLES}" \
          --compute_true_after 0 \
          --output "${OUT_CSV}" \
          2>&1 | tee "${LOG_DIR}/IMDB_eps${EPS}_run${RUN}_${ATTACK}_r${RATIO}.log"
    done
done

# ============================================================
# Missing part 3:
# IMDB eps=6 run=0~4 all clean + rr attacks
# ============================================================

EPS=6

for RUN in 0 1 2 3 4; do
    SEED=$((1776 + RUN))

    "${EXE}" \
      --mode run \
      --dataset "${DATASET}" \
      --edge_file "${EDGE_FILE}" \
      --node_num "${NODE_NUM}" \
      --eps "${EPS}" \
      --q "${Q}" \
      --m "${M}" \
      --budget_mode "${BUDGET_MODE}" \
      --attack_type clean \
      --malicious_ratio 0.0 \
      --attack_strength 0.0 \
      --run "${RUN}" \
      --seed "${SEED}" \
      --clean_triangles "${CLEAN_TRIANGLES}" \
      --compute_true_after 0 \
      --output "${OUT_CSV}" \
      2>&1 | tee "${LOG_DIR}/IMDB_eps${EPS}_run${RUN}_clean.log"

    for ATTACK in rr_increase rr_decrease; do
        for RATIO in "${RATIOS[@]}"; do
            "${EXE}" \
              --mode run \
              --dataset "${DATASET}" \
              --edge_file "${EDGE_FILE}" \
              --node_num "${NODE_NUM}" \
              --eps "${EPS}" \
              --q "${Q}" \
              --m "${M}" \
              --budget_mode "${BUDGET_MODE}" \
              --attack_type "${ATTACK}" \
              --malicious_ratio "${RATIO}" \
              --attack_strength "${ATTACK_STRENGTH}" \
              --run "${RUN}" \
              --seed "${SEED}" \
              --clean_triangles "${CLEAN_TRIANGLES}" \
              --compute_true_after 0 \
              --output "${OUT_CSV}" \
              2>&1 | tee "${LOG_DIR}/IMDB_eps${EPS}_run${RUN}_${ATTACK}_r${RATIO}.log"
        done
    done
done

echo "Resume missing RR-fixed experiments finished."
echo "Check rows:"
wc -l "${OUT_CSV}"
