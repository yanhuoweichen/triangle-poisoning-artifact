#!/usr/bin/env bash
set -euo pipefail

# ============================================================
# Run all Laplace post-perturbation report attacks for PRIVET
# Attack types: fixed / scale / count
# Attack directions: increase (+1) / decrease (-1)
# Malicious ratios: 3%, 5%, 8%, 10%, 13%, 15%, 18%, 20%
# Attack strength lambda: 1
#
# Usage:
#   chmod +x run_all_laplace_report_attacks.sh
#   ./run_all_laplace_report_attacks.sh
#
# Optional usage:
#   ./run_all_laplace_report_attacks.sh <DATASET> <NODE_NUM> "<EPS_LIST>" "<SCHEME_LIST>"
#
# Example:
#   ./run_all_laplace_report_attacks.sh Gplus 10000 "0.5 1 2" "CaliToUpper CaliToLS CaliToTrunc"
#
# You can also override paths by environment variables:
#   EDGE_FILE=../data/Gplus/edges.csv OUT_DIR=my_results ./run_all_laplace_report_attacks.sh
# ============================================================

DATASET="${1:-Gplus}"
NODE_NUM="${2:-10000}"
EPS_LIST="${3:-0.5 1 2}"
SCHEME_LIST="${4:-CaliToUpper CaliToLS CaliToTrunc}"

# ---- Basic PRIVET parameters ----
DELTA="${DELTA:-5e-6}"
BETA="${BETA:-0.2}"
ALPHA="${ALPHA:-0.5}"
H_PRIME="${H_PRIME:-100}"
R="${R:-5}"
P="${P:-0.01}"
TRIAL_NUM="${TRIAL_NUM:-30}"
SEED="${SEED:-1776}"

# ---- Attack parameters ----
ATTACK_TYPES=("fixed" "scale" "count")
DIRECTIONS=("1" "-1")
MALICIOUS_RATIOS=("0.03" "0.05" "0.08" "0.10" "0.13" "0.15" "0.18" "0.20")
ATTACK_LAMBDA="1"
MALICIOUS_SEED="${MALICIOUS_SEED:-1776}"

# ---- Files ----
SRC="${SRC:-PRIVET_laplace_attack.cpp}"
BIN="${BIN:-PRIVET_laplace_attack}"
EDGE_FILE="${EDGE_FILE:-../data/${DATASET}/edges.csv}"
OUT_DIR="${OUT_DIR:-results_laplace_all_attacks}"

mkdir -p "${OUT_DIR}"

echo "============================================================"
echo "PRIVET Laplace report attack batch"
echo "DATASET=${DATASET}"
echo "NODE_NUM=${NODE_NUM}"
echo "EDGE_FILE=${EDGE_FILE}"
echo "EPS_LIST=${EPS_LIST}"
echo "SCHEME_LIST=${SCHEME_LIST}"
echo "ATTACK_TYPES=${ATTACK_TYPES[*]}"
echo "DIRECTIONS=${DIRECTIONS[*]}   # 1=increase, -1=decrease"
echo "MALICIOUS_RATIOS=${MALICIOUS_RATIOS[*]}"
echo "ATTACK_LAMBDA=${ATTACK_LAMBDA}"
echo "OUT_DIR=${OUT_DIR}"
echo "============================================================"

# ---- Compile if binary does not exist or source is newer ----
if [[ ! -x "${BIN}" || "${SRC}" -nt "${BIN}" ]]; then
  echo "[Compile] g++ -O3 -std=c++11 ${SRC} -o ${BIN}"
  g++ -O3 -std=c++11 "${SRC}" -o "${BIN}"
fi

# ---- Clean baseline: one run for each epsilon and scheme ----
# This is useful for comparing attack results with no attack.
for EPS in ${EPS_LIST}; do
  for SCHEME in ${SCHEME_LIST}; do
    LOG="${OUT_DIR}/${DATASET}_${SCHEME}_eps${EPS}_clean.log"
    echo "[Run clean] dataset=${DATASET}, scheme=${SCHEME}, eps=${EPS}"
    "./${BIN}" "${EDGE_FILE}" "${NODE_NUM}" "${EPS}" "${SCHEME}" \
      "${DELTA}" "${BETA}" "${ALPHA}" "${H_PRIME}" "${R}" "${P}" \
      "${TRIAL_NUM}" "${SEED}" "${DATASET}" \
      clean 0 0 1 "${MALICIOUS_SEED}" \
      > "${LOG}" 2>&1
  done
done

# ---- Attack runs ----
for EPS in ${EPS_LIST}; do
  for SCHEME in ${SCHEME_LIST}; do
    for ATTACK_TYPE in "${ATTACK_TYPES[@]}"; do
      for DIRECTION in "${DIRECTIONS[@]}"; do

        if [[ "${DIRECTION}" == "1" ]]; then
          DIR_NAME="increase"
        else
          DIR_NAME="decrease"
        fi

        for MR in "${MALICIOUS_RATIOS[@]}"; do
          LOG="${OUT_DIR}/${DATASET}_${SCHEME}_eps${EPS}_${ATTACK_TYPE}_${DIR_NAME}_mr${MR}_lambda${ATTACK_LAMBDA}.log"

          echo "[Run attack] dataset=${DATASET}, scheme=${SCHEME}, eps=${EPS}, attack=${ATTACK_TYPE}, direction=${DIR_NAME}, mr=${MR}, lambda=${ATTACK_LAMBDA}"

          "./${BIN}" "${EDGE_FILE}" "${NODE_NUM}" "${EPS}" "${SCHEME}" \
            "${DELTA}" "${BETA}" "${ALPHA}" "${H_PRIME}" "${R}" "${P}" \
            "${TRIAL_NUM}" "${SEED}" "${DATASET}" \
            "${ATTACK_TYPE}" "${MR}" "${ATTACK_LAMBDA}" "${DIRECTION}" "${MALICIOUS_SEED}" \
            > "${LOG}" 2>&1

        done
      done
    done
  done
done

# ---- Extract summary ----
SUMMARY="${OUT_DIR}/summary.csv"
echo "dataset,scheme,epsilon,attack_type,direction,malicious_ratio,lambda,true_triangle_count,avg_estimated_triangle_count,relative_signed_error,mre,log_file" > "${SUMMARY}"

for LOG in "${OUT_DIR}"/*.log; do
  BASE="$(basename "${LOG}" .log)"

  DATASET_NAME="$(echo "${BASE}" | cut -d'_' -f1)"
  SCHEME_NAME="$(echo "${BASE}" | cut -d'_' -f2)"
  EPS_VAL="$(echo "${BASE}" | sed -n 's/.*_eps\([^_]*\).*/\1/p')"

  if [[ "${BASE}" == *"_clean" ]]; then
    ATTACK_NAME="clean"
    DIR_NAME="none"
    MR_VAL="0"
    LAMBDA_VAL="0"
  else
    ATTACK_NAME="$(echo "${BASE}" | sed -n 's/.*_eps[^_]*_\([^_]*\)_\(increase\|decrease\)_mr.*/\1/p')"
    DIR_NAME="$(echo "${BASE}" | sed -n 's/.*_\(increase\|decrease\)_mr.*/\1/p')"
    MR_VAL="$(echo "${BASE}" | sed -n 's/.*_mr\([^_]*\)_lambda.*/\1/p')"
    LAMBDA_VAL="$(echo "${BASE}" | sed -n 's/.*_lambda\([^_]*\).*/\1/p')"
  fi

  TRUE_TRI="$(grep -m1 'true_triangle_count' "${LOG}" | awk -F':' '{print $NF}' | tr -d ' ' || true)"
  AVG_EST="$(grep -m1 'avg_estimated_triangle_count' "${LOG}" | awk -F':' '{print $NF}' | tr -d ' ' || true)"
  REL_SIGNED="$(grep -m1 'relative_signed_error' "${LOG}" | awk -F':' '{print $NF}' | tr -d ' ' || true)"

  # Different schemes may print MRE with slightly different labels.
  MRE_VAL="$(grep -m1 'MRE with calibration' "${LOG}" | awk -F':' '{print $NF}' | tr -d ' ' || true)"
  if [[ -z "${MRE_VAL}" ]]; then
    MRE_VAL="$(grep -m1 'MRE for' "${LOG}" | awk -F':' '{print $NF}' | tr -d ' ' || true)"
  fi

  echo "${DATASET_NAME},${SCHEME_NAME},${EPS_VAL},${ATTACK_NAME},${DIR_NAME},${MR_VAL},${LAMBDA_VAL},${TRUE_TRI},${AVG_EST},${REL_SIGNED},${MRE_VAL},${LOG}" >> "${SUMMARY}"
done

echo "============================================================"
echo "All runs finished."
echo "Logs saved to: ${OUT_DIR}"
echo "Summary CSV: ${SUMMARY}"
echo "============================================================"
