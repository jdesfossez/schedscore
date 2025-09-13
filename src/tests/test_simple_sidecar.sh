#!/bin/bash
# Simple test to verify sidecar cleanup

# Get the directory of this script and find schedscore binary
DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
SCHEDSCORE="$DIR/../../schedscore"

echo "Testing sidecar process cleanup with a simple test..."

# Clean up any existing perf processes
sudo pkill -f "perf record" 2>/dev/null || true
sleep 1

echo "Starting schedscore with perf sidecar..."

# Start schedscore with perf in background for a short duration
timeout 5 sudo $SCHEDSCORE --perf --perf-args "record -e cycles" --duration 3 -- sleep 2 &
SCHEDSCORE_PID=$!

# Wait a moment for processes to start
sleep 1

# Check if perf process is running
PERF_COUNT=$(pgrep -f "perf record" | wc -l)
echo "Perf processes running: $PERF_COUNT"

if [ "$PERF_COUNT" -gt 0 ]; then
    echo "✓ Perf sidecar started successfully"
    
    # Show the process tree
    echo "Process tree:"
    pstree -p $SCHEDSCORE_PID 2>/dev/null || ps --forest -o pid,ppid,pgid,comm,args -g $(ps -o pgid= -p $SCHEDSCORE_PID | tr -d ' ')
else
    echo "✗ Perf sidecar did not start"
fi

# Wait for schedscore to finish
wait $SCHEDSCORE_PID 2>/dev/null || true

# Check if perf processes are cleaned up
sleep 1
PERF_COUNT_AFTER=$(pgrep -f "perf record" | wc -l)
echo "Perf processes after cleanup: $PERF_COUNT_AFTER"

if [ "$PERF_COUNT_AFTER" -eq 0 ]; then
    echo "✓ SUCCESS: All perf processes were properly cleaned up"
    exit 0
else
    echo "✗ FAILURE: $PERF_COUNT_AFTER perf processes still running"
    echo "Remaining processes:"
    pgrep -f "perf record" | xargs ps -p 2>/dev/null || true
    exit 1
fi
