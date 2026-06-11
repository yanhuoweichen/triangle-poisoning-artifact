#!/bin/bash -x
# run_PRIVET_with_attack.sh
# Place this file under Triangle4CycleShuffle/cpp/ together with PRIVET_with_attack.cpp.
#
# Clean run:
#   ./run_PRIVET_with_attack.sh IMDB
#
# Original-data poisoning attack:
#   ./run_PRIVET_with_attack.sh IMDB 20000 1776 add_edges 0.10 1.0
#   ./run_PRIVET_with_attack.sh IMDB 20000 1776 remove_edges 0.10 1.0
#
# Positional args:
#   $1 Dataset
#   $2 NodeNum, default 20000
#   $3 Seed, default 1776
#   $4 AttackType: clean/add_edges/remove_edges, default clean
#   $5 MaliciousRatio, default 0
#   $6 PoisonProb Z, default 0
#
# This mirrors the original Python PRIEVET run.sh:
# epsilon = 1 and 6; schemes = CaliToUpper, CaliToLS, CaliToTrunc.
# Other parameters use Python defaults:
# delta=5e-6, beta=0.2, alpha=0.5, h_prime=100, r=5, p=0.01, trial_num=300.

if [ $# -lt 1 ]; then
  echo "USAGE: run_PRIVET_with_attack.sh [Dataset] [NodeNum=20000] [Seed=1776] [AttackType=clean] [MaliciousRatio=0] [PoisonProb=0]"
  exit 1
fi

DATASET=$1
NODE_NUM=${2:-20000}
SEED=${3:-1776}
ATTACK_TYPE=${4:-clean}
MALICIOUS_RATIO=${5:-0}
POISON_PROB=${6:-0}

EDGE_FILE="../data/${DATASET}/edges.csv"

DELTA=5e-6
BETA=0.2
ALPHA=0.5
H_PRIME=100
R=5
P=0.01
TRIAL_NUM=300

if [ ! -f "${EDGE_FILE}" ]; then
  echo "Cannot find edge file: ${EDGE_FILE}"
  exit 1
fi

g++ -O3 -std=c++11 PRIVET_with_attack.cpp -o PRIVET
if [ $? -ne 0 ]; then
  echo "Compilation failed."
  exit 1
fi

RESULT_DIR="../data/${DATASET}/privet_cpp_results/${ATTACK_TYPE}_r${MALICIOUS_RATIO}_z${POISON_PROB}"
mkdir -p "${RESULT_DIR}"

for EPS in 1 6; do
  for SCHEME in CaliToUpper CaliToLS CaliToTrunc; do
    OUT="${RESULT_DIR}/${SCHEME}_eps${EPS}.log"
    ./PRIVET "${EDGE_FILE}" "${NODE_NUM}" "${EPS}" "${SCHEME}" \
      "${DELTA}" "${BETA}" "${ALPHA}" "${H_PRIME}" "${R}" "${P}" \
      "${TRIAL_NUM}" "${SEED}" "${DATASET}" \
      "${ATTACK_TYPE}" "${MALICIOUS_RATIO}" "${POISON_PROB}" | tee "${OUT}"
  done
done
