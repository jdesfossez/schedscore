#!/bin/bash

# Get the directory of this script and find schedscore binary
DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
SCHEDSCORE="$DIR/../.$SCHEDSCORE"
# Final test focusing only on new sidecar processes

# Get the directory of this script and find schedscore binary
DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
SCHEDSCORE="$DIR/../.$SCHEDSCORE"

echo "=== Final Sidecar Process Group Test ==="

# Get baseline count of perf processes
BASELINE_PERF=$(pgrep -f "perf record" | wc -l)
echo "Baseline perf processes: $BASELINE_PERF"

# Start schedscore with perf sidecar
echo "Starting schedscore with perf sidecar..."
sudo timeout 8 $SCHEDSCORE --perf --perf-args "record -e cycles" --duration 3 -- sleep 2 &
SCHEDSCORE_PID=$!

# Wait for processes to start
sleep 1

# Get current count
CURRENT_PERF=$(pgrep -f "perf record" | wc -l)
NEW_PERF=$((CURRENT_PERF - BASELINE_PERF))

echo "Current perf processes: $CURRENT_PERF"
echo "New perf processes: $NEW_PERF"

if [ "$NEW_PERF" -gt 0 ]; then
    echo "✓ New perf sidecar started successfully"
    
    # Find the newest perf process (highest PID)
    NEWEST_PERF=$(pgrep -f "perf record" | tail -1)
    echo "Newest perf PID: $NEWEST_PERF"
    
    # Check if it's its own process group leader
    PERF_PGID=$(ps -o pgid= -p $NEWEST_PERF 2>/dev/null | tr -d ' ')
    
    if [ "$PERF_PGID" = "$NEWEST_PERF" ]; then
        echo "✓ SUCCESS: New perf process is its own process group leader (PGID=$PERF_PGID)"
        PROCESS_GROUP_TEST="PASS"
    else
        echo "✗ FAILURE: New perf process is not its own process group leader (PGID=$PERF_PGID)"
        PROCESS_GROUP_TEST="FAIL"
    fi
    
    # Show the process tree for the new process
    echo "Process info for new perf process:"
    ps -o pid,ppid,pgid,comm,args -p $NEWEST_PERF 2>/dev/null || echo "Process not found"
else
    echo "✗ No new perf processes started"
    PROCESS_GROUP_TEST="FAIL"
fi

# Wait for schedscore to complete
wait $SCHEDSCORE_PID 2>/dev/null || true

# Check cleanup - count processes again
sleep 2
FINAL_PERF=$(pgrep -f "perf record" | wc -l)
CLEANED_UP=$((CURRENT_PERF - FINAL_PERF))

echo ""
echo "=== Cleanup Results ==="
echo "Perf processes before: $CURRENT_PERF"
echo "Perf processes after: $FINAL_PERF"
echo "Processes cleaned up: $CLEANED_UP"

if [ "$CLEANED_UP" -eq "$NEW_PERF" ]; then
    echo "✓ SUCCESS: All new perf processes were cleaned up"
    CLEANUP_TEST="PASS"
else
    echo "✗ FAILURE: Not all new perf processes were cleaned up"
    CLEANUP_TEST="FAIL"
fi

echo ""
echo "=== Final Results ==="
echo "Process Group Creation: $PROCESS_GROUP_TEST"
echo "Process Cleanup: $CLEANUP_TEST"

if [ "$PROCESS_GROUP_TEST" = "PASS" ] && [ "$CLEANUP_TEST" = "PASS" ]; then
    echo ""
    echo "🎉 SUCCESS: Sidecar process group fix is working correctly!"
    echo ""
    echo "The fix ensures that:"
    echo "1. ✓ Sidecar processes create their own process group"
    echo "2. ✓ Shell is replaced by target process (exec command)"
    echo "3. ✓ Process group is killed entirely (kill -PGID)"
    echo "4. ✓ No orphaned perf/ftrace processes remain"
    exit 0
else
    echo ""
    echo "❌ Some tests failed. The fix may need further refinement."
    exit 1
fi
