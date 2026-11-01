#!/bin/bash

STATE_DIR="/tmp/rtest_state"
LOG_FILE="recovery_test_log.txt"
mkdir -p "$STATE_DIR"

if [ -f "$STATE_DIR/counter" ]; then
    COUNTER=$(cat "$STATE_DIR/counter")
else
    COUNTER=1
fi

ACTION="$2"
STEP_NAME="$1"

if [ "$1" == "SUMMARY" ]; then
    if [ -f "$STATE_DIR/total_start" ]; then
        START_TIME=$(cat "$STATE_DIR/total_start")
        END_TIME=$(date +%s)
        ELAPSED=$((END_TIME - START_TIME))
        MINS=$((ELAPSED / 60))
        SECS=$((ELAPSED % 60))
        
        echo "==================================================" | tee -a "$LOG_FILE"
        echo "RECOVERY TEST SUMMARY" | tee -a "$LOG_FILE"
        echo "Total Elapsed Time: ${MINS}m ${SECS}s" | tee -a "$LOG_FILE"
        echo "Declared RTO: 30m 00s" | tee -a "$LOG_FILE"
        
        if [ "$ELAPSED" -le 1800 ]; then
            echo "RTO MET: YES (PASS)" | tee -a "$LOG_FILE"
        else
            echo "RTO MET: NO (FAIL)" | tee -a "$LOG_FILE"
        fi
        echo "==================================================" | tee -a "$LOG_FILE"
    else
        echo "Error: No timer started."
    fi
    exit 0
fi

if [ "$ACTION" == "START" ]; then
    if [ ! -f "$STATE_DIR/total_start" ]; then
        date +%s > "$STATE_DIR/total_start"
    fi
    
    NOW_STR=$(date '+%H:%M:%S')
    NOW_EPOCH=$(date +%s)
    
    echo "$NOW_STR" > "$STATE_DIR/step_${COUNTER}_start_str"
    echo "$NOW_EPOCH" > "$STATE_DIR/step_${COUNTER}_start_epoch"
    echo "Started step: $STEP_NAME"
    exit 0
fi

if [ "$ACTION" == "PASS" ] || [ "$ACTION" == "FAIL" ]; then
    NOW_STR=$(date '+%H:%M:%S')
    NOW_EPOCH=$(date +%s)
    
    START_STR=$(cat "$STATE_DIR/step_${COUNTER}_start_str")
    START_EPOCH=$(cat "$STATE_DIR/step_${COUNTER}_start_epoch")
    
    ELAPSED=$((NOW_EPOCH - START_EPOCH))
    MINS=$((ELAPSED / 60))
    SECS=$((ELAPSED % 60))
    
    STEP_NUM_FMT=$(printf "%02d" "$COUNTER")
    
    LOG_LINE="[STEP ${STEP_NUM_FMT}] ${STEP_NAME} | Start: ${START_STR} | End: ${NOW_STR} | Duration: ${MINS}m ${SECS}s | ${ACTION}"
    echo "$LOG_LINE" | tee -a "$LOG_FILE"
    
    COUNTER=$((COUNTER + 1))
    echo "$COUNTER" > "$STATE_DIR/counter"
    exit 0
fi
