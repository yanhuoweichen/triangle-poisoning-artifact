#!/bin/bash -x
# run_PRIVET.sh
# Place this file under Triangle4CycleShuffle/cpp/ together with PRIVET.cpp.
#
# Usage:
#   cd cpp/
#   chmod +x run_PRIVET.sh
#   ./run_PRIVET.sh Gplus
#   ./run_PRIVET.sh IMDB
#
# This mirrors the original Python PRIEVET run.sh:
# epsilon = 1 and 6; schemes = CaliToUpper, CaliToLS, CaliToTrunc.
# Other parameters use Python defaults:
# delta=5e-6, beta=0.2, alpha=0.5, h_prime=100, r=5, p=0.01, trial_num=300.

if [ $# -lt 1 ]; then
  echo "USAGE: run_PRIVET.sh [Dataset] [NodeNum=20000] [Seed=1776]"
  exit 1
fi

DATASET=$1
NODE_NUM=${2:-20000}
SEED=${3:-1776}

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

g++ -O3 -std=c++11 PRIVET.cpp -o PRIVET
if [ $? -ne 0 ]; then
  echo "Compilation failed."
  exit 1
fi

mkdir -p "../data/${DATASET}/privet_cpp_results"

for EPS in 1 6; do
  for SCHEME in CaliToUpper CaliToLS CaliToTrunc; do
    OUT="../data/${DATASET}/privet_cpp_results/${SCHEME}_eps${EPS}.log"
    ./PRIVET "${EDGE_FILE}" "${NODE_NUM}" "${EPS}" "${SCHEME}" \
      "${DELTA}" "${BETA}" "${ALPHA}" "${H_PRIME}" "${R}" "${P}" \
      "${TRIAL_NUM}" "${SEED}" "${DATASET}" | tee "${OUT}"
  done
done
