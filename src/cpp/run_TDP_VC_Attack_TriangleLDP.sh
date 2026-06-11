#!/usr/bin/env bash
set -euo pipefail

# ============================================================
# TriangleLDP-repo-ready runner for TDP-VC reproduction + attacks
# Put this file and TDP_VC_Attack.cpp under TriangleLDP/cpp/.
# Usage from TriangleLDP/cpp/:
#   chmod +x run_TDP_VC_Attack_TriangleLDP.sh
#   ./run_TDP_VC_Attack_TriangleLDP.sh Gplus 10000 5
#   ./run_TDP_VC_Attack_TriangleLDP.sh IMDB 10000 5
# ============================================================

DATASET=${1:-Gplus}
NODE_NUM=${2:-10000}
RUNS=${3:-5}

CPP_FILE="TDP_VC_Attack.cpp"
BIN="tdp_vc_attack"
DATA_FILE="../data/${DATASET}/edges.csv"
OUT_DIR="../data/${DATASET}/tdp_vc_attack_logs"
mkdir -p "${OUT_DIR}"

# Paper-like settings for TDP-VC.
ALPHA=150
EPS0_RATIO=0.1
BUDGET_MODE="auto"
EPS1_TOTAL_RATIO=0.45   # used only when BUDGET_MODE=fixed

# IMPORTANT for TriangleLDP-preprocessed edges.csv:
# ReadGPlus.py/ReadIMDB.py outputs 3 non-edge header lines:
#   #nodes
#   <node_num>
#   node,node
# Our parser safely ignores them when HAS_HEADER=0. Do NOT set HAS_HEADER=1 here.
REMAP=0
HAS_HEADER=0

MALICIOUS_RATIOS=(0.03 0.05 0.08 0.10 0.13 0.15 0.18 0.20)
POISON_PROBS=(1.0)
EPS_LIST=(0.5 1.0 2.0)

FIXED_OFFSET=10000
SCALE_K=3
LOCAL_K=0.5

ATTACKS=(
  none
  orig_inc orig_dec
  rr_inc rr_dec
  lap_fixed_inc lap_fixed_dec
  lap_scale_inc lap_scale_dec
  lap_local_inc lap_local_dec
)

SEED=20260601

if [[ ! -f "${DATA_FILE}" ]]; then
  echo "[Error] Cannot find ${DATA_FILE}. Run the TriangleLDP preprocessing first." >&2
  exit 1
fi

# TriangleLDP README uses CentOS 7.5 / gcc 4.8.5, so keep C++11.
echo "[Compile] ${CPP_FILE} -> ${BIN}"
g++ -O3 -std=c++11 "${CPP_FILE}" -o "${BIN}"

RESULT_CSV="${OUT_DIR}/${DATASET}_n${NODE_NUM}_TDPVC_results.csv"
rm -f "${RESULT_CSV}"

echo "[Start] dataset=${DATASET}, file=${DATA_FILE}, n=${NODE_NUM}, runs=${RUNS}, out=${RESULT_CSV}"

for eps in "${EPS_LIST[@]}"; do
  for attack in "${ATTACKS[@]}"; do
    if [[ "${attack}" == "none" ]]; then
      echo "[Run] eps=${eps} attack=${attack}"
      ./"${BIN}" \
        --input "${DATA_FILE}" \
        --n "${NODE_NUM}" \
        --epsilon "${eps}" \
        --runs "${RUNS}" \
        --attack "${attack}" \
        --malicious_ratio 0 \
        --poison_prob 0 \
        --alpha "${ALPHA}" \
        --eps0_ratio "${EPS0_RATIO}" \
        --budget_mode "${BUDGET_MODE}" \
        --eps1_total_ratio "${EPS1_TOTAL_RATIO}" \
        --fixed_offset "${FIXED_OFFSET}" \
        --scale_k "${SCALE_K}" \
        --local_k "${LOCAL_K}" \
        --seed "${SEED}" \
        --remap "${REMAP}" \
        --has_header "${HAS_HEADER}" \
        --out "${RESULT_CSV}"
      continue
    fi

    for mr in "${MALICIOUS_RATIOS[@]}"; do
      for pp in "${POISON_PROBS[@]}"; do
        echo "[Run] eps=${eps} attack=${attack} mr=${mr} poison=${pp}"
        ./"${BIN}" \
          --input "${DATA_FILE}" \
          --n "${NODE_NUM}" \
          --epsilon "${eps}" \
          --runs "${RUNS}" \
          --attack "${attack}" \
          --malicious_ratio "${mr}" \
          --poison_prob "${pp}" \
          --alpha "${ALPHA}" \
          --eps0_ratio "${EPS0_RATIO}" \
          --budget_mode "${BUDGET_MODE}" \
          --eps1_total_ratio "${EPS1_TOTAL_RATIO}" \
          --fixed_offset "${FIXED_OFFSET}" \
          --scale_k "${SCALE_K}" \
          --local_k "${LOCAL_K}" \
          --seed "${SEED}" \
          --remap "${REMAP}" \
          --has_header "${HAS_HEADER}" \
          --out "${RESULT_CSV}"
      done
    done
  done
done

echo "[Done] ${RESULT_CSV}"
