#!/bin/sh
while true; do
    python /app/wg_sync.py
    sleep ${SYNC_INTERVAL:-10}
done

