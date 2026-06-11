#!/usr/bin/env bash
set -euo pipefail

# ============================================================
# Resume Gplus + run IMDB for PRIVET Laplace report attacks
#
# It will:
#   1) Continue Gplus in results_laplace_all_attacks/
#   2) Run IMDB in results_laplace_all_attacks_IMDB/
#   3) Skip logs that already contain "counting finished"
#   4) Generate summary.csv for each dataset
#   5) Generate combined_summary.csv
#
# Put this script in the same directory as:
#   PRIVET_laplace_attack.cpp
#
# Usage:
#   chmod +x run_gplus_resume_and_imdb_all_laplace_attacks.sh
#   ./run_gplus_resume_and_imdb_all_laplace_attacks.sh
#
# Optional environment overrides:
#   GPLUS_NODE_NUM=10000
#   IMDB_NODE_NUM=xxxx        # If not set, auto-detect from ../data/IMDB/edges.csv
#   EPS_LIST="0.5 1 2"
#   SCHEME_LIST="CaliToUpper CaliToLS CaliToTrunc"
#   TRIAL_NUM=30
#   P=0.01
# ============================================================

# ---- Global experiment settings ----
EPS_LIST="${EPS_LIST:-0.5 1 2}"
SCHEME_LIST="${SCHEME_LIST:-CaliToUpper CaliToLS CaliToTrunc}"

DELTA="${DELTA:-5e-6}"
BETA="${BETA:-0.2}"
ALPHA="${ALPHA:-0.5}"
H_PRIME="${H_PRIME:-100}"
R="${R:-5}"
P="${P:-0.01}"
TRIAL_NUM="${TRIAL_NUM:-30}"
SEED="${SEED:-1776}"

ATTACK_TYPES=("fixed" "scale" "count")
DIRECTIONS=("1" "-1")
MALICIOUS_RATIOS=("0.03" "0.05" "0.08" "0.10" "0.13" "0.15" "0.18" "0.20")
ATTACK_LAMBDA="1"
MALICIOUS_SEED="${MALICIOUS_SEED:-1776}"

SRC="${SRC:-PRIVET_laplace_attack.cpp}"
BIN="${BIN:-PRIVET_laplace_attack}"

GPLUS_NODE_NUM="${GPLUS_NODE_NUM:-10000}"
GPLUS_EDGE_FILE="${GPLUS_EDGE_FILE:-../data/Gplus/edges.csv}"
GPLUS_OUT_DIR="${GPLUS_OUT_DIR:-results_laplace_all_attacks}"

IMDB_EDGE_FILE="${IMDB_EDGE_FILE:-../data/IMDB/edges.csv}"
IMDB_OUT_DIR="${IMDB_OUT_DIR:-results_laplace_all_attacks_IMDB}"

COMBINED_SUMMARY="${COMBINED_SUMMARY:-combined_laplace_attack_summary.csv}"

infer_node_num_from_edges() {
  local edge_file="$1"
  if [[ ! -f "${edge_file}" ]]; then
    echo ""
    return
  fi

  # Skip the first 3 lines to match PRIVET_laplace_attack.cpp default reader.
  # Node ids are assumed to be 0-based. node_num = max_id + 1.
  awk '
    NR > 3 {
      gsub(",", " ");
      if ($1 ~ /^[0-9]+$/ && $2 ~ /^[0-9]+$/) {
        if ($1 > max) max = $1;
        if ($2 > max) max = $2;
      }
    }
    END {
      if (max == "") print "";
      else print max + 1;
    }
  ' "${edge_file}"
}

if [[ -z "${IMDB_NODE_NUM:-}" ]]; then
  IMDB_NODE_NUM="$(infer_node_num_from_edges "${IMDB_EDGE_FILE}")"
fi

if [[ -z "${IMDB_NODE_NUM:-}" ]]; then
  echo "[Error] Cannot infer IMDB_NODE_NUM from ${IMDB_EDGE_FILE}."
  echo "Please run with: IMDB_NODE_NUM=<your_node_num> ./run_gplus_resume_and_imdb_all_laplace_attacks.sh"
  exit 1
fi

echo "============================================================"
echo "Gplus + IMDB PRIVET Laplace report attack batch"
echo "EPS_LIST=${EPS_LIST}"
echo "SCHEME_LIST=${SCHEME_LIST}"
echo "ATTACK_TYPES=${ATTACK_TYPES[*]}"
echo "DIRECTIONS=${DIRECTIONS[*]}   # 1=increase, -1=decrease"
echo "MALICIOUS_RATIOS=${MALICIOUS_RATIOS[*]}"
echo "ATTACK_LAMBDA=${ATTACK_LAMBDA}"
echo "Gplus: edge=${GPLUS_EDGE_FILE}, node_num=${GPLUS_NODE_NUM}, out=${GPLUS_OUT_DIR}"
echo "IMDB : edge=${IMDB_EDGE_FILE}, node_num=${IMDB_NODE_NUM}, out=${IMDB_OUT_DIR}"
echo "============================================================"

if [[ ! -f "${SRC}" ]]; then
  echo "[Error] Cannot find ${SRC}. Put this script next to PRIVET_laplace_attack.cpp."
  exit 1
fi

if [[ ! -x "${BIN}" || "${SRC}" -nt "${BIN}" ]]; then
  echo "[Compile] g++ -O3 -std=c++11 ${SRC} -o ${BIN}"
  g++ -O3 -std=c++11 "${SRC}" -o "${BIN}"
fi

is_finished() {
  local log_file="$1"
  [[ -f "${log_file}" ]] && grep -q "counting finished" "${log_file}"
}

run_one() {
  local log_file="$1"
  shift

  if is_finished "${log_file}"; then
    echo "[Skip] $(basename "${log_file}")"
  else
    mkdir -p "$(dirname "${log_file}")"
    echo "[Run]  $(basename "${log_file}")"
    "$@" > "${log_file}" 2>&1
  fi
}

make_summary() {
  local dataset="$1"
  local out_dir="$2"
  local summary="${out_dir}/summary.csv"

  echo "dataset,scheme,epsilon,attack_type,direction,malicious_ratio,lambda,true_triangle_count,avg_estimated_triangle_count,relative_signed_error,mre,finished,log_file" > "${summary}"

  shopt -s nullglob
  for LOG in "${out_dir}"/*.log; do
    BASE="$(basename "${LOG}" .log)"

    DATASET_NAME="${dataset}"
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

    MRE_VAL="$(grep -m1 'MRE with calibration' "${LOG}" | awk -F':' '{print $NF}' | tr -d ' ' || true)"
    if [[ -z "${MRE_VAL}" ]]; then
      MRE_VAL="$(grep -m1 'MRE for' "${LOG}" | awk -F':' '{print $NF}' | tr -d ' ' || true)"
    fi

    FINISHED="0"
    if grep -q "counting finished" "${LOG}"; then
      FINISHED="1"
    fi

    echo "${DATASET_NAME},${SCHEME_NAME},${EPS_VAL},${ATTACK_NAME},${DIR_NAME},${MR_VAL},${LAMBDA_VAL},${TRUE_TRI},${AVG_EST},${REL_SIGNED},${MRE_VAL},${FINISHED},${LOG}" >> "${summary}"
  done
}

run_dataset() {
  local dataset="$1"
  local node_num="$2"
  local edge_file="$3"
  local out_dir="$4"

  if [[ ! -f "${edge_file}" ]]; then
    echo "[Error] Cannot find edge file: ${edge_file}"
    exit 1
  fi

  mkdir -p "${out_dir}"

  echo "------------------------------------------------------------"
  echo "Dataset=${dataset}, NodeNum=${node_num}, EdgeFile=${edge_file}"
  echo "Output=${out_dir}"
  echo "------------------------------------------------------------"

  # ---- Clean baseline ----
  for EPS in ${EPS_LIST}; do
    for SCHEME in ${SCHEME_LIST}; do
      LOG="${out_dir}/${dataset}_${SCHEME}_eps${EPS}_clean.log"
      run_one "${LOG}" "./${BIN}" "${edge_file}" "${node_num}" "${EPS}" "${SCHEME}" \
        "${DELTA}" "${BETA}" "${ALPHA}" "${H_PRIME}" "${R}" "${P}" \
        "${TRIAL_NUM}" "${SEED}" "${dataset}" \
        clean 0 0 1 "${MALICIOUS_SEED}"
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
            LOG="${out_dir}/${dataset}_${SCHEME}_eps${EPS}_${ATTACK_TYPE}_${DIR_NAME}_mr${MR}_lambda${ATTACK_LAMBDA}.log"

            run_one "${LOG}" "./${BIN}" "${edge_file}" "${node_num}" "${EPS}" "${SCHEME}" \
              "${DELTA}" "${BETA}" "${ALPHA}" "${H_PRIME}" "${R}" "${P}" \
              "${TRIAL_NUM}" "${SEED}" "${dataset}" \
              "${ATTACK_TYPE}" "${MR}" "${ATTACK_LAMBDA}" "${DIRECTION}" "${MALICIOUS_SEED}"
          done
        done
      done
    done
  done

  make_summary "${dataset}" "${out_dir}"

  FINISHED_COUNT="$(grep -l "counting finished" "${out_dir}"/*.log 2>/dev/null | wc -l)"
  echo "[Dataset finished] ${dataset}: ${FINISHED_COUNT}/441 logs finished"
  echo "[Summary] ${out_dir}/summary.csv"
}

run_dataset "Gplus" "${GPLUS_NODE_NUM}" "${GPLUS_EDGE_FILE}" "${GPLUS_OUT_DIR}"
run_dataset "IMDB" "${IMDB_NODE_NUM}" "${IMDB_EDGE_FILE}" "${IMDB_OUT_DIR}"

# ---- Combined summary ----
echo "dataset,scheme,epsilon,attack_type,direction,malicious_ratio,lambda,true_triangle_count,avg_estimated_triangle_count,relative_signed_error,mre,finished,log_file" > "${COMBINED_SUMMARY}"

if [[ -f "${GPLUS_OUT_DIR}/summary.csv" ]]; then
  tail -n +2 "${GPLUS_OUT_DIR}/summary.csv" >> "${COMBINED_SUMMARY}"
fi

if [[ -f "${IMDB_OUT_DIR}/summary.csv" ]]; then
  tail -n +2 "${IMDB_OUT_DIR}/summary.csv" >> "${COMBINED_SUMMARY}"
fi

echo "============================================================"
echo "All requested datasets finished or resumed."
echo "Gplus summary: ${GPLUS_OUT_DIR}/summary.csv"
echo "IMDB summary : ${IMDB_OUT_DIR}/summary.csv"
echo "Combined     : ${COMBINED_SUMMARY}"
echo "============================================================"
