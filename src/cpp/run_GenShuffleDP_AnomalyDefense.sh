#!/usr/bin/env bash
set -euo pipefail

# GenShuffleDP: choose one representative defense group.
# Representative attack: strict malicious-pair RR increase.
DATASET=${1:-Gplus}
NODE_NUM=${2:-10000}
RUNS=${3:-3}
EDGE_FILE=${EDGE_FILE:-../data/${DATASET}/edges.csv}
OUT_DIR=${OUT_DIR:-../results_anomaly_defense}
mkdir -p "${OUT_DIR}"
SRC=GenShuffleDP_AnomalyDefense.cpp
EXE=./GenShuffleDP_AnomalyDefense
OUT=${OUT_DIR}/${DATASET}_GenShuffleDP_rr_inc_defense.csv

EPS=${EPS:-1.0}
RATIOS=${RATIOS:-"0 0.025 0.05 0.075 0.10"}
ATTACK=${ATTACK:-rr_inc}
ATTACK_STRENGTH=${ATTACK_STRENGTH:-1.0}
POISON_PROB=${POISON_PROB:-1.0}
SEED=${SEED:-1776}
SELECTOR=${SELECTOR:-random}
GAMMA=${GAMMA:-2.0}
TAU=${TAU:-4.0}
SMOOTH=${SMOOTH:-0.0}
CANDIDATE_MULTIPLIER=${CANDIDATE_MULTIPLIER:-1.5}
MIN_WEIGHT=${MIN_WEIGHT:-0.10}
NORMALIZE_WEIGHTS=${NORMALIZE_WEIGHTS:-0}

if [[ ! -f "${SRC}" || ! -f RobustAnomalyDefenseCommon.hpp ]]; then
  echo "[Error] Put ${SRC} and RobustAnomalyDefenseCommon.hpp in the current cpp directory." >&2
  exit 1
fi
if [[ ! -f "${EDGE_FILE}" ]]; then
  echo "[Error] Edge file not found: ${EDGE_FILE}" >&2
  exit 1
fi

echo "[Compile] ${SRC} -> ${EXE}"
g++ -O3 -std=c++11 "${SRC}" -o "${EXE}"
rm -f "${OUT}"

for MR in ${RATIOS}; do
  echo "[Run] GenShuffle attack=${ATTACK} eps=${EPS} ratio=${MR}"
  "${EXE}" --input "${EDGE_FILE}" --n "${NODE_NUM}" --protocol GenShuffle \
    --epsilon "${EPS}" --runs "${RUNS}" --attack "${ATTACK}" \
    --malicious_ratio "${MR}" --poison_prob "${POISON_PROB}" \
    --attack_strength "${ATTACK_STRENGTH}" --selector "${SELECTOR}" \
    --gamma "${GAMMA}" --tau "${TAU}" --smooth "${SMOOTH}" \
    --candidate_multiplier "${CANDIDATE_MULTIPLIER}" --min_weight "${MIN_WEIGHT}" --normalize_weights "${NORMALIZE_WEIGHTS}" \
    --seed "${SEED}" --out "${OUT}"
done

echo "[Done] ${OUT}"
