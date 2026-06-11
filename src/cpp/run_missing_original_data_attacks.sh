#!/usr/bin/env bash
set -euo pipefail

# ============================================================
# Supplement missing PRIVET original-data attack experiments.
#
# This script is designed for your current setting:
#   - Gplus original-data attack has not been run.
#   - IMDB original-data attack has been partially run, but its ratios
#     are not fully aligned with the final ratio list.
#
# It will run / resume:
#   Gplus: clean + add_edges/remove_edges for ratios
#          0.03 0.05 0.08 0.10 0.13 0.15 0.18 0.20
#          NodeNum=10000
#
#   IMDB : only missing ratio groups from the same ratio list
#          NodeNum=20000
#
# For each group, it runs eps=1 and eps=6, schemes:
#   CaliToUpper CaliToLS CaliToTrunc
#
# Output dirs are the same as run_PRIVET_with_attack.sh:
#   ../data/Gplus/privet_cpp_results/
#   ../data/IMDB/privet_cpp_results/
#
# Usage:
#   chmod +x run_missing_original_data_attacks.sh
#   ./run_missing_original_data_attacks.sh
# ============================================================

BASE_RUN_SCRIPT="${BASE_RUN_SCRIPT:-./run_PRIVET_with_attack.sh}"

RATIOS=("0.03" "0.05" "0.08" "0.10" "0.13" "0.15" "0.18" "0.20")
ATTACKS=("add_edges" "remove_edges")
SCHEMES=("CaliToUpper" "CaliToLS" "CaliToTrunc")
EPS_LIST=("1" "6")

SEED="${SEED:-1776}"
POISON_PROB="${POISON_PROB:-1.0}"

GPLUS_NODE_NUM="${GPLUS_NODE_NUM:-10000}"
IMDB_NODE_NUM="${IMDB_NODE_NUM:-20000}"

if [[ ! -x "${BASE_RUN_SCRIPT}" ]]; then
  echo "[Error] Cannot execute ${BASE_RUN_SCRIPT}."
  echo "Please put this script in the same cpp directory as run_PRIVET_with_attack.sh and run:"
  echo "  chmod +x run_PRIVET_with_attack.sh"
  exit 1
fi

is_group_finished() {
  local dataset="$1"
  local attack="$2"
  local ratio="$3"
  local prob="$4"
  local dir="../data/${dataset}/privet_cpp_results/${attack}_r${ratio}_z${prob}"

  for eps in "${EPS_LIST[@]}"; do
    for scheme in "${SCHEMES[@]}"; do
      local log="${dir}/${scheme}_eps${eps}.log"
      if [[ ! -f "${log}" ]] || ! grep -q "counting finished" "${log}"; then
        return 1
      fi
    done
  done
  return 0
}

run_group_if_needed() {
  local dataset="$1"
  local node_num="$2"
  local attack="$3"
  local ratio="$4"
  local prob="$5"

  if is_group_finished "${dataset}" "${attack}" "${ratio}" "${prob}"; then
    echo "[Skip] ${dataset} ${attack} ratio=${ratio} z=${prob}"
  else
    echo "[Run]  ${dataset} ${attack} ratio=${ratio} z=${prob}"
    "${BASE_RUN_SCRIPT}" "${dataset}" "${node_num}" "${SEED}" "${attack}" "${ratio}" "${prob}"
  fi
}

run_clean_if_needed() {
  local dataset="$1"
  local node_num="$2"
  local dir="../data/${dataset}/privet_cpp_results/clean_r0_z0"

  local ok=1
  for eps in "${EPS_LIST[@]}"; do
    for scheme in "${SCHEMES[@]}"; do
      local log="${dir}/${scheme}_eps${eps}.log"
      if [[ ! -f "${log}" ]] || ! grep -q "counting finished" "${log}"; then
        ok=0
      fi
    done
  done

  if [[ "${ok}" == "1" ]]; then
    echo "[Skip] ${dataset} clean baseline"
  else
    echo "[Run]  ${dataset} clean baseline"
    "${BASE_RUN_SCRIPT}" "${dataset}" "${node_num}"
  fi
}

echo "============================================================"
echo "Supplement PRIVET original-data attacks"
echo "Ratios: ${RATIOS[*]}"
echo "Attacks: ${ATTACKS[*]}"
echo "Eps: ${EPS_LIST[*]}"
echo "Schemes: ${SCHEMES[*]}"
echo "Gplus NodeNum=${GPLUS_NODE_NUM}"
echo "IMDB  NodeNum=${IMDB_NODE_NUM}"
echo "PoisonProb=${POISON_PROB}"
echo "============================================================"

# Gplus: run the full final ratio list.
run_clean_if_needed "Gplus" "${GPLUS_NODE_NUM}"
for attack in "${ATTACKS[@]}"; do
  for ratio in "${RATIOS[@]}"; do
    run_group_if_needed "Gplus" "${GPLUS_NODE_NUM}" "${attack}" "${ratio}" "${POISON_PROB}"
  done
done

# IMDB: only fill missing groups in the final ratio list.
run_clean_if_needed "IMDB" "${IMDB_NODE_NUM}"
for attack in "${ATTACKS[@]}"; do
  for ratio in "${RATIOS[@]}"; do
    run_group_if_needed "IMDB" "${IMDB_NODE_NUM}" "${attack}" "${ratio}" "${POISON_PROB}"
  done
done

echo "============================================================"
echo "Finished supplementing original-data attack experiments."
echo "Check outputs:"
echo "  ../data/Gplus/privet_cpp_results/"
echo "  ../data/IMDB/privet_cpp_results/"
echo "============================================================"
