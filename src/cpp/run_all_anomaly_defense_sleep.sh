#!/bin/bash

# ============================================================
# Unified runner for anomaly-defense experiments
# Put this script in your cpp directory, then run:
#   chmod +x run_all_anomaly_defense_sleep.sh
#   nohup ./run_all_anomaly_defense_sleep.sh Gplus 10000 3 > run_all_anomaly_defense_nohup.out 2>&1 &
#
# Usage:
#   ./run_all_anomaly_defense_sleep.sh [DATASET] [NODE_NUM] [RUNS]
#
# Example:
#   ./run_all_anomaly_defense_sleep.sh Gplus 10000 3
# ============================================================

DATASET=${1:-Gplus}
NODE_NUM=${2:-10000}
RUNS=${3:-3}

OUT_DIR="../results_anomaly_defense"
LOG_DIR="${OUT_DIR}/logs_all_defense_${DATASET}_n${NODE_NUM}_r${RUNS}_$(date +%Y%m%d_%H%M%S)"
STATUS_CSV="${LOG_DIR}/run_status.csv"
MASTER_LOG="${LOG_DIR}/master.log"

mkdir -p "${LOG_DIR}"

echo "experiment,status,start_time,end_time,log_file" > "${STATUS_CSV}"

echo "============================================================" | tee -a "${MASTER_LOG}"
echo "Start all anomaly-defense experiments" | tee -a "${MASTER_LOG}"
echo "DATASET  = ${DATASET}" | tee -a "${MASTER_LOG}"
echo "NODE_NUM = ${NODE_NUM}" | tee -a "${MASTER_LOG}"
echo "RUNS     = ${RUNS}" | tee -a "${MASTER_LOG}"
echo "LOG_DIR  = ${LOG_DIR}" | tee -a "${MASTER_LOG}"
echo "============================================================" | tee -a "${MASTER_LOG}"

SCRIPTS=(
  "run_DDP_AnomalyDefense.sh"
  "run_LDP2022_ARROneNS_AnomalyDefense.sh"
  "run_PRIVET_AnomalyDefense.sh"
  "run_TDPVC_AnomalyDefense.sh"
  "run_EdgeOrient_AnomalyDefense.sh"
  "run_GenShuffleDP_AnomalyDefense.sh"
)

for SCRIPT in "${SCRIPTS[@]}"; do
    EXP_NAME="${SCRIPT%.sh}"
    EXP_LOG="${LOG_DIR}/${EXP_NAME}.log"

    START_TIME="$(date '+%Y-%m-%d %H:%M:%S')"

    echo "" | tee -a "${MASTER_LOG}"
    echo "============================================================" | tee -a "${MASTER_LOG}"
    echo "[Run] ${SCRIPT}" | tee -a "${MASTER_LOG}"
    echo "Start time: ${START_TIME}" | tee -a "${MASTER_LOG}"
    echo "Log file: ${EXP_LOG}" | tee -a "${MASTER_LOG}"
    echo "============================================================" | tee -a "${MASTER_LOG}"

    if [ ! -f "${SCRIPT}" ]; then
        END_TIME="$(date '+%Y-%m-%d %H:%M:%S')"
        echo "[Missing] ${SCRIPT} not found. Skip." | tee -a "${MASTER_LOG}"
        echo "${EXP_NAME},MISSING,\"${START_TIME}\",\"${END_TIME}\",\"${EXP_LOG}\"" >> "${STATUS_CSV}"
        continue
    fi

    chmod +x "${SCRIPT}"

    bash "./${SCRIPT}" "${DATASET}" "${NODE_NUM}" "${RUNS}" > "${EXP_LOG}" 2>&1
    RET=$?

    END_TIME="$(date '+%Y-%m-%d %H:%M:%S')"

    if [ ${RET} -eq 0 ]; then
        echo "[OK] ${SCRIPT} finished successfully." | tee -a "${MASTER_LOG}"
        echo "${EXP_NAME},OK,\"${START_TIME}\",\"${END_TIME}\",\"${EXP_LOG}\"" >> "${STATUS_CSV}"
    else
        echo "[FAILED] ${SCRIPT} failed with exit code ${RET}. Continue next." | tee -a "${MASTER_LOG}"
        echo "${EXP_NAME},FAILED_${RET},\"${START_TIME}\",\"${END_TIME}\",\"${EXP_LOG}\"" >> "${STATUS_CSV}"
    fi

    echo "End time: ${END_TIME}" | tee -a "${MASTER_LOG}"
    sync
done

echo "" | tee -a "${MASTER_LOG}"
echo "============================================================" | tee -a "${MASTER_LOG}"
echo "All anomaly-defense experiments finished." | tee -a "${MASTER_LOG}"
echo "Status CSV: ${STATUS_CSV}" | tee -a "${MASTER_LOG}"
echo "Master log: ${MASTER_LOG}" | tee -a "${MASTER_LOG}"
echo "============================================================" | tee -a "${MASTER_LOG}"

echo ""
echo "Done. Check:"
echo "  ${STATUS_CSV}"
echo "  ${MASTER_LOG}"
