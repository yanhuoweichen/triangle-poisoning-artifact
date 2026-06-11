#!/bin/bash
set -euo pipefail

# Usage:
#   cd TriangleLDP/cpp
#   chmod +x run_DDP_Phase2_Robust.sh
#   ./run_DDP_Phase2_Robust.sh Gplus 10000 5
#
# Output:
#   ../data/Gplus/ddp_phase2_logs/Gplus_n10000_DDP_Phase2_Robust.csv

if [ $# -lt 1 ] || [ $# -gt 3 ]; then
  echo "USAGE: $0 [Dataset] [n|-1, default=10000] [runs, default=5]"
  exit 1
fi

DATASET="$1"
N="${2:-10000}"
RUNS="${3:-5}"
EDGE_FILE="../data/${DATASET}/edges.csv"
OUT_DIR="../data/${DATASET}/ddp_phase2_logs"
OUT_CSV="${OUT_DIR}/${DATASET}_n${N}_DDP_Phase2_Robust.csv"
BIN="./DDP_Phase2_Robust"
SRC="DDP_Phase2_Robust.cpp"

mkdir -p "${OUT_DIR}"

if [ ! -f "${EDGE_FILE}" ]; then
  echo "[Error] Edge file not found: ${EDGE_FILE}"
  exit 1
fi

echo "[Compile] ${SRC} -> ${BIN}"
g++ -std=c++11 -O3 -march=native "${SRC}" -o "${BIN}"

# ===== Protocol parameters =====
# The CCS'19 triangle experiment uses eps1 = 0.1 * eps in its h-selection figure.
DELTA="1e-6"
H_PRIME="100"
EPS1_FRAC="0.1"
SEED_BASE="20260602"

# ===== Experimental grid: edit here =====
EPS_LIST=("0.5" "1.0" "2.0")

# Malicious user ratio: proportion of real users controlled by attacker.
MAL_RATIOS=("0.05" "0.10" "0.15" "0.20")

# Original-data attack strength: probability of adding/deleting each edge among malicious users.
ORIG_POISON_PROBS=("0.25" "0.50" "0.75" "1.00")

# Phase-2 Laplace attack strength:
#   fixed: report += +/- LAP_STRENGTH
#   scale: report += +/- LAP_STRENGTH * lambda
#   count: report += +/- LAP_STRENGTH * local_triangle_count
LAP_STRENGTHS=("0.25" "0.50" "1.00" "2.00")

NONE_ATTACKS=("none")
ORIG_ATTACKS=("orig_increase" "orig_decrease")
LAP_ATTACKS=(
  "lap_fixed_increase" "lap_fixed_decrease"
  "lap_scale_increase" "lap_scale_decrease"
  "lap_count_increase" "lap_count_decrease"
)

echo "[Start] dataset=${DATASET}, n=${N}, runs=${RUNS}, out=${OUT_CSV}"
rm -f "${OUT_CSV}"

# 1) Non-attack baseline: mal_ratio=0, strengths recorded as 0.
for EPS in "${EPS_LIST[@]}"; do
  echo "[Run] eps=${EPS} attack=none"
  "${BIN}" "${EDGE_FILE}" "${N}" "${EPS}" "${DELTA}" "${H_PRIME}" "${RUNS}" \
    "none" "0" "0" "0" "${SEED_BASE}" "${OUT_CSV}" "${EPS1_FRAC}"
done

# 2) Original-data attacks: modify edges among malicious users before protocol execution.
for EPS in "${EPS_LIST[@]}"; do
  for MR in "${MAL_RATIOS[@]}"; do
    for PP in "${ORIG_POISON_PROBS[@]}"; do
      for ATTACK in "${ORIG_ATTACKS[@]}"; do
        echo "[Run] eps=${EPS} attack=${ATTACK} mal_ratio=${MR} orig_poison_prob=${PP}"
        "${BIN}" "${EDGE_FILE}" "${N}" "${EPS}" "${DELTA}" "${H_PRIME}" "${RUNS}" \
          "${ATTACK}" "${MR}" "${PP}" "0" "${SEED_BASE}" "${OUT_CSV}" "${EPS1_FRAC}"
      done
    done
  done
done

# 3) Phase-2 Laplace report attacks: keep Phase 1 honest; only malicious users' final reports are biased.
for EPS in "${EPS_LIST[@]}"; do
  for MR in "${MAL_RATIOS[@]}"; do
    for LS in "${LAP_STRENGTHS[@]}"; do
      for ATTACK in "${LAP_ATTACKS[@]}"; do
        echo "[Run] eps=${EPS} attack=${ATTACK} mal_ratio=${MR} lap_strength=${LS}"
        "${BIN}" "${EDGE_FILE}" "${N}" "${EPS}" "${DELTA}" "${H_PRIME}" "${RUNS}" \
          "${ATTACK}" "${MR}" "0" "${LS}" "${SEED_BASE}" "${OUT_CSV}" "${EPS1_FRAC}"
      done
    done
  done
done

echo "[Done] ${OUT_CSV}"
