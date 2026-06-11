#!/usr/bin/env bash
set -euo pipefail

# Run post-Laplace report attacks for PRIVET.
# Put this script and PRIVET_laplace_attack.cpp in the same cpp directory, then run it there.
#
# Usage:
#   ./run_PRIVET_laplace_attack.sh \
#       [DATASET] [NODE_NUM] [EPS_LIST] [SCHEME_LIST] [ATTACK_MODES] [DIRECTIONS] \
#       [MAL_RATIOS] [LAMBDAS] [EDGE_FILE] [TRIAL_NUM] [P] [DELTA] [BETA] [ALPHA] \
#       [H_PRIME] [R] [SEED] [OUTDIR]
#
# Example:
#   ./run_PRIVET_laplace_attack.sh Gplus 10000 "0.5 1 2" "CaliToUpper CaliToLS CaliToTrunc" \
#       "scale" "1 -1" "0.05 0.10 0.20" "0.5 1 2"

DATASET=${1:-Gplus}
NODE_NUM=${2:-10000}
EPS_LIST=${3:-"0.5 1 2"}
SCHEME_LIST=${4:-"CaliToUpper CaliToLS CaliToTrunc"}
ATTACK_MODES=${5:-"scale"}          # clean, fixed, scale, count; can be "fixed scale count"
DIRECTIONS=${6:-"1 -1"}             # 1=increase, -1=decrease
MAL_RATIOS=${7:-"0.05 0.10 0.20"}
LAMBDAS=${8:-"1"}
EDGE_FILE=${9:-"../data/${DATASET}/edges.csv"}
TRIAL_NUM=${10:-30}
P=${11:-0.01}
DELTA=${12:-5e-6}
BETA=${13:-0.2}
ALPHA=${14:-0.5}
H_PRIME=${15:-100}
R=${16:-5}
SEED=${17:-1776}
OUTDIR=${18:-"results_laplace_report_attack"}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CPP_FILE="${SCRIPT_DIR}/PRIVET_laplace_attack.cpp"
BIN_FILE="${SCRIPT_DIR}/PRIVET_laplace_attack"

if [[ ! -f "${CPP_FILE}" ]]; then
    echo "Cannot find ${CPP_FILE}. Put PRIVET_laplace_attack.cpp in the same directory as this script." >&2
    exit 1
fi

mkdir -p "${OUTDIR}"

echo "+ compiling ${CPP_FILE}"
g++ -O3 -std=c++11 "${CPP_FILE}" -o "${BIN_FILE}"

echo "+ dataset=${DATASET} node_num=${NODE_NUM} edge_file=${EDGE_FILE}"
echo "+ eps_list=${EPS_LIST}"
echo "+ scheme_list=${SCHEME_LIST}"
echo "+ attack_modes=${ATTACK_MODES} directions=${DIRECTIONS} malicious_ratios=${MAL_RATIOS} lambdas=${LAMBDAS}"
echo "+ trial_num=${TRIAL_NUM} p=${P} delta=${DELTA} beta=${BETA} alpha=${ALPHA} h_prime=${H_PRIME} r=${R} seed=${SEED}"

for ATTACK_MODE in ${ATTACK_MODES}; do
  for DIR in ${DIRECTIONS}; do
    for MAL in ${MAL_RATIOS}; do
      for LAM in ${LAMBDAS}; do
        for EPS in ${EPS_LIST}; do
          for SCHEME in ${SCHEME_LIST}; do
            TAG="${DATASET}_${SCHEME}_eps${EPS}_${ATTACK_MODE}_dir${DIR}_mal${MAL}_lam${LAM}"
            LOG_FILE="${OUTDIR}/${TAG}.log"
            echo "============================================================"
            echo "+ running ${TAG}"
            "${BIN_FILE}" \
              "${EDGE_FILE}" "${NODE_NUM}" "${EPS}" "${SCHEME}" \
              "${DELTA}" "${BETA}" "${ALPHA}" "${H_PRIME}" \
              "${R}" "${P}" "${TRIAL_NUM}" "${SEED}" "${DATASET}" \
              "${ATTACK_MODE}" "${MAL}" "${LAM}" "${DIR}" "${SEED}" \
              | tee "${LOG_FILE}"
          done
        done
      done
    done
  done
done

echo "+ all runs finished. Logs are in ${OUTDIR}"
