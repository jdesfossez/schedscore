#!/bin/bash
# Test to verify process group creation and cleanup

# Get the directory of this script and find schedscore binary
DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
SCHEDSCORE="$DIR/../../schedscore"

echo "Testing process group creation and cleanup..."

# Function to show process tree for a PID
show_process_tree() {
    local pid=$1
    echo "Process tree for PID $pid:"
    ps --forest -o pid,ppid,pgid,comm,args -g $(ps -o pgid= -p $pid 2>/dev/null | tr -d ' ') 2>/dev/null || echo "Process $pid not found"
}

# Test 1: Verify that sidecar creates its own process group
echo "=== Test 1: Process Group Creation ==="

# Start a short-lived schedscore with perf
sudo timeout 10 $SCHEDSCORE --perf --perf-args "record -e cycles" --duration 2 -- sleep 1 &
SCHEDSCORE_PID=$!

# Wait for processes to start
sleep 1

# Find the perf process
PERF_PID=$(pgrep -f "perf record" | head -1)

if [ -n "$PERF_PID" ]; then
    echo "Found perf process: $PERF_PID"
    
    # Get process group info
    SCHEDSCORE_PGID=$(ps -o pgid= -p $SCHEDSCORE_PID 2>/dev/null | tr -d ' ')
    PERF_PGID=$(ps -o pgid= -p $PERF_PID 2>/dev/null | tr -d ' ')
    
    echo "Schedscore PGID: $SCHEDSCORE_PGID"
    echo "Perf PGID: $PERF_PGID"
    
    if [ "$PERF_PGID" = "$PERF_PID" ]; then
        echo "✓ SUCCESS: Perf process is its own process group leader (PGID=$PERF_PGID)"
    else
        echo "✗ FAILURE: Perf process is not its own process group leader"
    fi
    
    show_process_tree $SCHEDSCORE_PID
else
    echo "✗ No perf process found"
fi

# Wait for schedscore to finish
wait $SCHEDSCORE_PID 2>/dev/null || true

echo ""
echo "=== Test 2: Process Cleanup Verification ==="

# Wait a moment for cleanup
sleep 2

# Check if perf processes are cleaned up
REMAINING_PERF=$(pgrep -f "perf record" | wc -l)
echo "Remaining perf processes: $REMAINING_PERF"

if [ "$REMAINING_PERF" -eq 0 ]; then
    echo "✓ SUCCESS: All perf processes cleaned up properly"
else
    echo "✗ FAILURE: $REMAINING_PERF perf processes still running"
    echo "Remaining processes:"
    pgrep -f "perf record" | while read pid; do
        ps -o pid,ppid,pgid,comm,args -p $pid 2>/dev/null || true
    done
fi

echo ""
echo "=== Summary ==="
echo "The fix implements:"
echo "1. setpgid(0, 0) in child process to create new process group"
echo "2. 'exec' prefix in shell command to replace shell with target process"
echo "3. kill(-pid, signal) to kill entire process group"
echo ""
echo "This ensures that when we kill the sidecar, all its children are also terminated."
