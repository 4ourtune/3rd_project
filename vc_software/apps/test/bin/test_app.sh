#!/bin/bash
LOG_FILE="/home/hj/vc_software/apps/test/test_app.log"

echo "[test_app_v3.0.0] 실행됨 - $(date)" >> "$LOG_FILE"

while true; do
    echo "[test_app_v3.0.0] heartbeat - $(date)" >> "$LOG_FILE"
    sleep 10
done
