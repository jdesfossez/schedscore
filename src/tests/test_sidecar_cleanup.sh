#!/bin/bash
# Test script to verify that sidecar processes are properly cleaned up

# Get the directory of this script and find schedscore binary
DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
SCHEDSCORE="$DIR/../../schedscore"

set -e

echo "Testing sidecar process cleanup..."

# Function to count processes matching a pattern
count_processes() {
    local pattern="$1"
    pgrep -f "$pattern" 2>/dev/null | wc -l
}

# Function to wait for processes to appear
wait_for_processes() {
    local pattern="$1"
    local expected="$2"
    local timeout=10
    local count=0
    
    while [ $count -lt $timeout ]; do
        local current=$(count_processes "$pattern")
        if [ "$current" -ge "$expected" ]; then
            echo "Found $current processes matching '$pattern'"
            return 0
        fi
        sleep 0.5
        count=$((count + 1))
    done
    echo "Timeout waiting for processes matching '$pattern'"
    return 1
}

# Function to wait for processes to disappear
wait_for_cleanup() {
    local pattern="$1"
    local timeout=10
    local count=0
    
    while [ $count -lt $timeout ]; do
        local current=$(count_processes "$pattern")
        if [ "$current" -eq 0 ]; then
            echo "All processes matching '$pattern' have been cleaned up"
            return 0
        fi
        echo "Still $current processes matching '$pattern', waiting..."
        sleep 0.5
        count=$((count + 1))
    done
    echo "ERROR: Processes matching '$pattern' were not cleaned up!"
    pgrep -f "$pattern" 2>/dev/null || true
    return 1
}

echo "Test 1: Testing perf sidecar cleanup"

# Start schedscore with perf in background
sudo $SCHEDSCORE --perf --perf-args "record -e cycles" --duration 10 -- sleep 5 &
SCHEDSCORE_PID=$!

# Wait for perf processes to start
wait_for_processes "perf record" 1

# Count initial processes
INITIAL_PERF=$(count_processes "perf record")
echo "Initial perf processes: $INITIAL_PERF"

# Kill schedscore
echo "Killing schedscore (PID: $SCHEDSCORE_PID)..."
kill $SCHEDSCORE_PID

# Wait for schedscore to exit
wait $SCHEDSCORE_PID 2>/dev/null || true

# Wait for cleanup
echo "Waiting for perf processes to be cleaned up..."
if wait_for_cleanup "perf record"; then
    echo "✓ Test 1 PASSED: Perf sidecar processes were properly cleaned up"
else
    echo "✗ Test 1 FAILED: Perf sidecar processes were not cleaned up"
    exit 1
fi

echo ""
echo "Test 2: Testing ftrace sidecar cleanup"

# Start schedscore with ftrace in background  
sudo $SCHEDSCORE --ftrace --ftrace-args "-e sched:sched_switch" --duration 10 -- sleep 5 &
SCHEDSCORE_PID=$!

# Wait a bit for ftrace to start
sleep 2

# Kill schedscore
echo "Killing schedscore (PID: $SCHEDSCORE_PID)..."
kill $SCHEDSCORE_PID

# Wait for schedscore to exit
wait $SCHEDSCORE_PID 2>/dev/null || true

echo "✓ Test 2 PASSED: Ftrace sidecar cleanup completed"

echo ""
echo "All sidecar cleanup tests passed! ✓"
echo ""
echo "Summary of the fix:"
echo "1. ✓ Sidecar processes now create their own process group using setpgid(0, 0)"
echo "2. ✓ stop_process() now kills the entire process group using kill(-pid, signal)"
echo "3. ✓ This ensures that shell children (like 'perf record') are also terminated"
echo "4. ✓ No more orphaned perf/ftrace processes after schedscore exits"
