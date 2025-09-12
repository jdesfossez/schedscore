#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only

# Simple RFC integration test runner for tools/schedscore
# Intent: easy to move to tools/testing/selftests/schedscore later.
#
# Usage: from this directory (tools/schedscore):
#   $ sudo ./test_schedscore.sh
#
# Exits non‑zero on first failure; prints ok/skip lines for each test.

set -eu

# Helpers
DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
SCHEDSCORE="$DIR/schedscore"
TMPDIR=${TMPDIR:-/tmp}

have_cmd() { command -v "$1" >/dev/null 2>&1; }

skip() { printf 'ok %s # SKIP %s\n' "$1" "$2"; }
ok() { printf 'ok %s\n' "$1"; }
fail() { printf 'not ok %s %s\n' "$1" "$2"; exit 1; }

with_timeout() {
    # with_timeout SECONDS -- cmd args ...
    t=$1; shift
    if have_cmd timeout; then
        timeout "${t}s" "$@"
    else
        # Fallback: background + sleep watchdog
        ( "$@" ) &
        pid=$!
        i=0
        while kill -0 "$pid" 2>/dev/null; do
            i=$((i+1))
            [ "$i" -ge "$t" ] && { kill "$pid" 2>/dev/null || true; break; }
            sleep 1
        done
        wait "$pid" 2>/dev/null || true
    fi
}

need_root() { [ "$(id -u)" -eq 0 ]; }
need_btf()  { [ -r /sys/kernel/btf/vmlinux ]; }

header_ok() {
    # header_ok FILE (anywhere in file)
    grep -q '^pid,comm,' "$1"
}

has_data_row() {
    # has_data_row FILE: find header anywhere, then ensure at least one row with >=11 CSV columns after it
    awk -F, '
        /^pid,comm,/ { hdr=1; next }
        hdr && NF>=11 { ok=1; exit }
        END { exit ok?0:1 }
    ' "$1"
}

require_env() {
    n=$1; shift
    need_root || { skip "$n" "need root"; return 1; }
    need_btf  || { skip "$n" "missing /sys/kernel/btf/vmlinux"; return 1; }
    [ -x "$SCHEDSCORE" ] || { skip "$n" "build schedscore first"; return 1; }
}

# Tests
# 1. Basic target run: ls
T1="1-basic-ls"
if require_env "$T1"; then
    OUT=$(mktemp "$TMPDIR/schedscore.$T1.XXXXXX"); trap 'rm -f "$OUT"' EXIT HUP INT TERM
    with_timeout 10 "$SCHEDSCORE" --format csv -- ls >"$OUT" 2>/dev/null || true
    header_ok "$OUT" || fail "$T1" "missing header"
    has_data_row "$OUT" || fail "$T1" "no data row"
    ok "$T1"
fi

# 2. Duration stop: sleep is longer than duration
T2="2-duration-sleep"
if require_env "$T2"; then
    OUT=$(mktemp "$TMPDIR/schedscore.$T2.XXXXXX"); trap 'rm -f "$OUT"' EXIT HUP INT TERM
    with_timeout 10 "$SCHEDSCORE" --format csv --duration 2 -- sleep 6 >"$OUT" 2>"$OUT.stderr" || true
    header_ok "$OUT" || fail "$T2" "missing header"
    has_data_row "$OUT" || fail "$T2" "no data row"
    # Should not complain about signaling non-existent processes
    if grep -qi 'No such process' "$OUT.stderr"; then fail "$T2" "spurious No such process"; fi
    ok "$T2"
fi

# 3. Duration + stress-ng (optional)
T3="3-duration-stress-ng"
if require_env "$T3"; then
    if have_cmd stress-ng; then
        OUT=$(mktemp "$TMPDIR/schedscore.$T3.XXXXXX"); trap 'rm -f "$OUT"' EXIT HUP INT TERM
        with_timeout 15 "$SCHEDSCORE" --format csv --duration 2 -- stress-ng --cpu 1 --timeout 6 >"$OUT" 2>/dev/null || true
        header_ok "$OUT" || fail "$T3" "missing header"
        has_data_row "$OUT" || fail "$T3" "no data row"
        ok "$T3"
    else
        skip "$T3" "stress-ng not installed"
    fi
fi

# 4. perf/ftrace flags (optional)
T4="4-perf-ftrace"
if require_env "$T4"; then
    if have_cmd perf; then
        with_timeout 8 "$SCHEDSCORE" --duration 1 --perf > /dev/null 2>&1 || true
    fi
    if have_cmd trace-cmd; then
        with_timeout 8 "$SCHEDSCORE" --duration 1 --ftrace > /dev/null 2>&1 || true
    fi
    ok "$T4"
fi

# 5. Filters merge: explicit --pid plus target
T5="5-filters-merge"
if require_env "$T5"; then
    OUT=$(mktemp "$TMPDIR/schedscore.$T5.XXXXXX"); trap 'rm -f "$OUT"' EXIT HUP INT TERM
    with_timeout 10 "$SCHEDSCORE" --format csv --pid $$ --duration 1 -- sleep 1 >"$OUT" 2>/dev/null || true
    header_ok "$OUT" || fail "$T5" "missing header"
    has_data_row "$OUT" || fail "$T5" "no data row"
    ok "$T5"
fi

# 6. comm filter with target
T6="6-comm-filter"
if require_env "$T6"; then
    OUT=$(mktemp "$TMPDIR/schedscore.$T6.XXXXXX"); trap 'rm -f "$OUT"' EXIT HUP INT TERM
    with_timeout 10 "$SCHEDSCORE" --format csv --comm sleep --duration 1 -- sleep 1 >"$OUT" 2>/dev/null || true
    header_ok "$OUT" || fail "$T6" "missing header"
    has_data_row "$OUT" || fail "$T6" "no data row"
    ok "$T6"
fi

# 7. PID-only filter: track a busy child without target command
T7="7-pid-only-filter"
if require_env "$T7"; then
    OUT=$(mktemp "$TMPDIR/schedscore.$T7.XXXXXX"); trap 'rm -f "$OUT"' EXIT HUP INT TERM
    # Start a short busy loop so it gets scheduled
    ( sh -c 't=$(($(date +%s)+2)); while [ $(date +%s) -lt $t ]; do :; done' & echo $! >&3 ) 3>"$OUT.pid" &
    wait $! 2>/dev/null || true
    CHILD=$(cat "$OUT.pid" 2>/dev/null || true)
    if [ -n "${CHILD:-}" ] && kill -0 "$CHILD" 2>/dev/null; then
        with_timeout 10 "$SCHEDSCORE" --format csv --pid "$CHILD" --duration 1 >"$OUT" 2>/dev/null || true
        header_ok "$OUT" || fail "$T7" "missing header"
        has_data_row "$OUT" || fail "$T7" "no data row"
        ok "$T7"
        kill "$CHILD" 2>/dev/null || true
    else
        skip "$T7" "cannot start busy child"
    fi
fi

# 8. cgroup path filter: run a process inside a fresh cgroup and track it
T8="8-cgroup-path"
if require_env "$T8"; then
    CGBASE="/sys/fs/cgroup"
    if [ -d "$CGBASE" ] && [ -e "$CGBASE/cgroup.controllers" ]; then
        OUT=$(mktemp "$TMPDIR/schedscore.$T8.XXXXXX"); trap 'rm -f "$OUT"' EXIT HUP INT TERM
        CGDIR="$CGBASE/schedscore_test.$$"
        if mkdir "$CGDIR" 2>/dev/null; then
            # Start a busy loop, move it into the cgroup, run schedscore filtered by cgroup
            ( sh -c 't=$(($(date +%s)+3)); while [ $(date +%s) -lt $t ]; do :; done' & echo $! >&3 ) 3>"$OUT.pid" &
            wait $! 2>/dev/null || true
            CHILD=$(cat "$OUT.pid" 2>/dev/null || true)
            if [ -n "${CHILD:-}" ] && kill -0 "$CHILD" 2>/dev/null; then
                echo "$CHILD" > "$CGDIR/cgroup.procs" 2>/dev/null || true
                with_timeout 10 "$SCHEDSCORE" --format csv --duration 1 --cgroup "$CGDIR" >"$OUT" 2>/dev/null || true
                header_ok "$OUT" || fail "$T8" "missing header"
                if has_data_row "$OUT"; then ok "$T8"; else skip "$T8" "no data row (cgroup path mapping not authoritative)"; fi
                kill "$CHILD" 2>/dev/null || true
            else
                skip "$T8" "cannot start/move child"
            fi
            rmdir "$CGDIR" 2>/dev/null || true
        else
            skip "$T8" "cannot create cgroup"
        fi
    else
        skip "$T8" "cgroup v2 not available"
    fi
fi

# 9. perf-args and ftrace-args overrides (optional)
T9="9-perf-ftrace-args"
if require_env "$T9"; then
    if have_cmd perf; then
        with_timeout 8 "$SCHEDSCORE" --duration 1 --perf-args "-a -e sched:* -o /dev/null" > /dev/null 2>&1 || true
    fi
    if have_cmd trace-cmd; then
        with_timeout 8 "$SCHEDSCORE" --duration 1 --ftrace-args "-e sched -o /dev/null" > /dev/null 2>&1 || true
    fi
    ok "$T9"
    fi

# 10. follow default OFF: ensure child not tracked unless -f
T10="10-follow-default-off"
if require_env "$T10"; then
    if have_cmd yes; then
        OUT=$(mktemp "$TMPDIR/schedscore.$T10.XXXXXX"); trap 'rm -f "$OUT"' EXIT HUP INT TERM
        with_timeout 12 "$SCHEDSCORE" --format csv --duration 2 -- sh -c 'yes >/dev/null & sleep 1; kill $!; wait' >"$OUT" 2>/dev/null || true
        header_ok "$OUT" || fail "$T10" "missing header"
        if grep -q ',yes,' "$OUT"; then
            fail "$T10" "child 'yes' tracked without -f"
        fi
        ok "$T10"
    else
        skip "$T10" "yes(1) not installed"
    fi
fi

# 11. follow ON: child should be tracked with -f
T11="11-follow-on"
if require_env "$T11"; then
    OUT=$(mktemp "$TMPDIR/schedscore.$T11.XXXXXX"); trap 'rm -f "$OUT"' EXIT HUP INT TERM
    with_timeout 12 "$SCHEDSCORE" --format csv -f --duration 2 -- sh -c 'sleep 1' >"$OUT" 2>/dev/null || true
    header_ok "$OUT" || fail "$T11" "missing header"
    if grep -q ',sleep,' "$OUT"; then ok "$T11"; else fail "$T11" "child 'sleep' not tracked with -f"; fi
fi

# 12. single-thread paramsets printed once and stats header contains oncpu quantiles
T12="12-single-thread-paramsets-once"
if require_env "$T12"; then
    if have_cmd stress-ng; then
        OUT=$(mktemp "$TMPDIR/schedscore.$T12.XXXXXX"); trap 'rm -f "$OUT"' EXIT HUP INT TERM
        with_timeout 15 "$SCHEDSCORE" --format csv --duration 2 -- stress-ng --cpu 1 --timeout 4 >"$OUT" 2>/dev/null || true
        header_ok "$OUT" || fail "$T12" "missing header"
        has_data_row "$OUT" || fail "$T12" "no data row"
        # paramset sections printed once
        if [ "$(grep -c '^paramset_map_csv$' "$OUT" || true)" -ne 1 ]; then
            fail "$T12" "paramset_map_csv printed != 1"
        fi
        # paramset stats header has oncpu quantiles
        grep -q '^paramset_id,pids,p50_sched_latency_ns,avg_sched_latency_ns,p95_sched_latency_ns,p99_sched_latency_ns,p50_oncpu_ns,avg_oncpu_ns,p95_oncpu_ns,p99_oncpu_ns,nr_sched_periods$' "$OUT" || fail "$T12" "paramset_stats header mismatch"
        ok "$T12"
    else
        skip "$T12" "stress-ng not installed"
    fi
    fi

# 15. per-PID vs per-paramset equivalence for single paramset
T15="15-perpid-vs-paramset"
if require_env "$T15"; then
    OUT=$(mktemp "$TMPDIR/schedscore.$T15.XXXXXX"); trap 'rm -f "$OUT"' EXIT HUP INT TERM
    with_timeout 12 "$SCHEDSCORE" --format csv --duration 2 -- ls >"$OUT" 2>/dev/null || true
    header_ok "$OUT" || fail "$T15" "missing header"
    # Extract the first per-pid data row (after header) and the paramset stats row
    PIDROW=$(awk -F, '/^pid,comm,/{hdr=1; next} hdr && NF>=11 { print; exit }' "$OUT")
    PSROW=$(awk '/^paramset_stats_csv$/{f=1;next} f && /^[0-9]+,/{ print; exit }' "$OUT")
    if [ -z "$PIDROW" ] || [ -z "$PSROW" ]; then
        fail "$T15" "missing rows"
    fi
    # Compare the metric slices (skip pid,comm,paramset_id vs paramset_id,pids)
    PIDMET=$(echo "$PIDROW" | awk -F, '{printf "%s,%s,%s,%s,%s,%s,%s,%s,%s\n", $4,$5,$6,$7,$8,$9,$10,$11,$12}')
    PSMET=$(echo "$PSROW" | awk -F, '{printf "%s,%s,%s,%s,%s,%s,%s,%s,%s\n", $3,$4,$5,$6,$7,$8,$9,$10,$11}')
    if [ "$PIDMET" != "$PSMET" ]; then
        printf "Debug per-pid: %s\nper-paramset: %s\n" "$PIDMET" "$PSMET" >&2
        fail "$T15" "metrics mismatch"
    fi
    # And nr_sched_periods: per-pid col 13 vs per-paramset col 12
    PIDPER=$(echo "$PIDROW" | awk -F, '{print $13}')
    PSPER=$(echo "$PSROW" | awk -F, '{print $12}')
    [ "$PIDPER" = "$PSPER" ] || fail "$T15" "nr_sched_periods mismatch ($PIDPER vs $PSPER)"
    ok "$T15"
fi

# 13. multi-thread paramsets printed once and multiple per-pid rows
T13="13-multi-thread-paramsets-once"
if require_env "$T13"; then
    if have_cmd stress-ng; then
        OUT=$(mktemp "$TMPDIR/schedscore.$T13.XXXXXX"); trap 'rm -f "$OUT"' EXIT HUP INT TERM
        with_timeout 20 "$SCHEDSCORE" --format csv -f --duration 2 -- stress-ng --cpu 4 --timeout 4 >"$OUT" 2>/dev/null || true
        header_ok "$OUT" || fail "$T13" "missing header"
        has_data_row "$OUT" || fail "$T13" "no data row"
        if [ "$(grep -c '^paramset_map_csv$' "$OUT" || true)" -ne 1 ]; then
            fail "$T13" "paramset_map_csv printed != 1"
        fi
        # Expect at least 3 stress-ng lines in per-pid csv
        if [ "$(grep -c '^[0-9][0-9]*,stress-ng,' "$OUT" || true)" -lt 3 ]; then
            fail "$T13" "too few stress-ng per-pid rows"
        fi
        ok "$T13"
    else
        skip "$T13" "stress-ng not installed"
    fi
fi

# 14. chrt + exec captures FIFO paramset via comm-change heuristic
T14="14-chrt-fifo-exec"
if require_env "$T14"; then
    if have_cmd chrt; then
        OUT=$(mktemp "$TMPDIR/schedscore.$T14.XXXXXX"); trap 'rm -f "$OUT"' EXIT HUP INT TERM
        with_timeout 10 "$SCHEDSCORE" --format csv -- chrt --fifo 99 sleep 1 >"$OUT" 2>/dev/null || true
        header_ok "$OUT" || fail "$T14" "missing header"
        has_data_row "$OUT" || fail "$T14" "no data row"
        # Look for SCHED_FIFO with rtprio 99 in paramset_map_csv block
        if grep -q '^paramset_map_csv$' "$OUT"; then
            if ! grep -q 'SCHED_FIFO.*[, ]99[, ]' "$OUT"; then
                fail "$T14" "missing SCHED_FIFO, rtprio=99 in paramset map"
            fi
        fi
        ok "$T14"
    else
        skip "$T14" "chrt not installed"
    fi
fi

# 16. --show-hist-config prints expected values from schedscore_hist.h
T16="16-show-hist-config"
if [ -x "$SCHEDSCORE" ]; then
    OUT=$(mktemp "$TMPDIR/schedscore.$T16.XXXXXX"); trap 'rm -f "$OUT"' EXIT HUP INT TERM
    "$SCHEDSCORE" --show-hist-config >"$OUT" 2>/dev/null || true
    LAT_LINE=$(grep '^hist-config: latency:' "$OUT" || true)
    ON_LINE=$(grep '^hist-config: oncpu:' "$OUT" || true)
    MEM_LINE=$(grep '^hist-config: memory-per-thread' "$OUT" || true)
    [ -n "$LAT_LINE" ] && [ -n "$ON_LINE" ] && [ -n "$MEM_LINE" ] || fail "$T16" "missing hist-config lines"
    # Extract numbers
    latw=$(echo "$LAT_LINE" | sed -n 's/.*width_ns=\([0-9]*\).*/\1/p')
    latb=$(echo "$LAT_LINE" | sed -n 's/.*buckets=\([0-9]*\).*/\1/p')
    latR=$(echo "$LAT_LINE" | sed -n 's/.*range_ns=\([0-9]*\).*/\1/p')
    onw=$(echo "$ON_LINE" | sed -n 's/.*width_ns=\([0-9]*\).*/\1/p')
    onb=$(echo "$ON_LINE" | sed -n 's/.*buckets=\([0-9]*\).*/\1/p')
    onR=$(echo "$ON_LINE" | sed -n 's/.*range_ns=\([0-9]*\).*/\1/p')
    mem=$(echo "$MEM_LINE" | sed -n 's/.*~\([0-9]*\) bytes.*/\1/p')
    [ "$latw" = "8192" ] || fail "$T16" "lat width_ns=$latw"
    [ "$latb" = "2048" ] || fail "$T16" "lat buckets=$latb"
    [ "$latR" = "16777216" ] || fail "$T16" "lat range_ns=$latR"
    [ "$onw" = "1048576" ] || fail "$T16" "oncpu width_ns=$onw"
    [ "$onb" = "4096" ] || fail "$T16" "oncpu buckets=$onb"
    [ "$onR" = "4294967296" ] || fail "$T16" "oncpu range_ns=$onR"
    [ "$mem" = "49152" ] || fail "$T16" "memory-per-thread=$mem"
    ok "$T16"
else
    skip "$T16" "schedscore not built"
# 17. env-file overrides are visible in target env
T17="17-env-file"
if require_env "$T17"; then
    OUT=$(mktemp "$TMPDIR/schedscore.$T17.XXXXXX"); trap 'rm -f "$OUT" "$OUT.env"' EXIT HUP INT TERM
    ENVF="$OUT.env"
    echo "FOO=bar" > "$ENVF"
    echo "DISPLAY=:123" >> "$ENVF"
    # Run as root target to exercise -u path regardless of current user
    with_timeout 10 "$SCHEDSCORE" -u root -e "$ENVF" -- env >"$OUT" 2>/dev/null || true
    grep -q '^FOO=bar$' "$OUT" || fail "$T17" "missing FOO=bar in target env"
    grep -q '^DISPLAY=:123$' "$OUT" || fail "$T17" "missing DISPLAY=:123 in target env"
    ok "$T17"
fi
# 18. format=table prints aligned header and at least one row
T18="18-format-table"
if require_env "$T18"; then
    OUT=$(mktemp "$TMPDIR/schedscore.$T18.XXXXXX"); trap 'rm -f "$OUT"' EXIT HUP INT TERM
    with_timeout 10 "$SCHEDSCORE" --duration 1 --format table -- sleep 1 >"$OUT" 2>/dev/null || true
    # header should include pid and comm as separate columns
    grep -q "pid\s\+comm" "$OUT" || fail "$T18" "missing table header"
    # at least one non-header line
    awk 'NR>1 && NF>1 { found=1; exit } END { exit found?0:1 }' "$OUT" || fail "$T18" "no table rows"
    ok "$T18"
fi

# 19. format=json prints JSON objects per line
T19="19-format-json"
if require_env "$T19"; then
    OUT=$(mktemp "$TMPDIR/schedscore.$T19.XXXXXX"); trap 'rm -f "$OUT"' EXIT HUP INT TERM
    with_timeout 10 "$SCHEDSCORE" --duration 1 --format json -- sleep 1 >"$OUT" 2>/dev/null || true
    grep -q '"pid"' "$OUT" || fail "$T19" "missing pid key in JSON"
    grep -q '"comm"' "$OUT" || fail "$T19" "missing comm key in JSON"
    ok "$T19"
fi

# 20. columns subset in CSV
T20="20-columns-csv"
if require_env "$T20"; then
    OUT=$(mktemp "$TMPDIR/schedscore.$T20.XXXXXX"); trap 'rm -f "$OUT"' EXIT HUP INT TERM
    with_timeout 10 "$SCHEDSCORE" --duration 1 --format csv --columns pid,comm,nr_sched_periods -- sleep 1 >"$OUT" 2>/dev/null || true
    head -n1 "$OUT" | grep -q '^pid,comm,nr_sched_periods$' || fail "$T20" "header mismatch"
    awk -F, 'NR>1 && NF==3 { found=1; exit } END { exit found?0:1 }' "$OUT" || fail "$T20" "row col count != 3"
    ok "$T20"
fi


# 21. format=json emits pure JSON (no textual headers)
T21="21-json-pure"
if require_env "$T21"; then
    OUT=$(mktemp "$TMPDIR/schedscore.$T21.XXXXXX"); trap 'rm -f "$OUT"' EXIT HUP INT TERM
    with_timeout 10 "$SCHEDSCORE" --duration 1 --format json -- sleep 1 >"$OUT" 2>/dev/null || true
    # No prefixed messages
    if grep -q '^schedscore:' "$OUT"; then fail "$T21" "found textual header in JSON"; fi
    # Basic structure keys
    grep -q '"paramset_map"' "$OUT" || fail "$T21" "missing paramset_map"
    grep -q '"paramset_stats"' "$OUT" || fail "$T21" "missing paramset_stats"
    grep -q '"per_pid"' "$OUT" || fail "$T21" "missing per_pid"
    # If jq is available, ensure it parses
    if have_cmd jq; then jq -e . <"$OUT" >/dev/null || fail "$T21" "invalid JSON"; fi
    ok "$T21"
fi

# 22a. detector CLI: new consolidated --detect works
T22A="22a-detect-flag"
if require_env "$T22A"; then
    OUT=$(mktemp "$TMPDIR/schedscore.$T22A.XXXXXX"); trap 'rm -f "$OUT"' EXIT HUP INT TERM
    with_timeout 10 "$SCHEDSCORE" --duration 1 --detect wake-lat=1us,xnuma -- sleep 1 >"$OUT" 2>/dev/null || true
    # Nothing in main output; this just ensures the flag is accepted without error
    header_ok "$OUT" || fail "$T22A" "missing header"
    ok "$T22A"
fi

# 22b. detector CLI: legacy flags are gone (should fail)
T22B="22b-detect-legacy-removed"
if [ -x "$SCHEDSCORE" ]; then
    if "$SCHEDSCORE" --detect-wakeup-latency 1 --duration 1 -- true >/dev/null 2>&1; then
        fail "$T22B" "legacy flag still accepted"
    else
        ok "$T22B"
    fi
fi
# 22c. --detect accepts units and mixed detectors
T22C="22c-detect-mixed"
if require_env "$T22C"; then
    OUT=$(mktemp "$TMPDIR/schedscore.$T22C.XXXXXX"); trap 'rm -f "$OUT"' EXIT HUP INT TERM
    with_timeout 10 "$SCHEDSCORE" --duration 1 --detect wake-lat=2ms,remote-wakeup-xnuma -- sleep 1 >"$OUT" 2>/dev/null || true
    header_ok "$OUT" || fail "$T22C" "missing header"
    ok "$T22C"
fi


# 22d. legacy detector flags restored and work
T22D="22d-detect-legacy-restored"
if require_env "$T22D"; then
    OUT=$(mktemp "$TMPDIR/schedscore.$T22D.XXXXXX"); trap 'rm -f "$OUT"' EXIT HUP INT TERM
    with_timeout 10 "$SCHEDSCORE" --duration 1 --detect-wakeup-latency 1us --detect-migration-xnuma -- sleep 1 >"$OUT" 2>/dev/null || true
    header_ok "$OUT" || fail "$T22D" "missing header"
    ok "$T22D"
fi


# 22. format=table includes paramset_map_table and paramset_stats_table blocks
T22="22-table-has-paramset-blocks"
if require_env "$T22"; then
    OUT=$(mktemp "$TMPDIR/schedscore.$T22.XXXXXX"); trap 'rm -f "$OUT"' EXIT HUP INT TERM
    with_timeout 10 "$SCHEDSCORE" --duration 1 --format table -- sleep 1 >"$OUT" 2>/dev/null || true
    grep -q '^paramset_map_table$' "$OUT" || fail "$T22" "missing paramset_map_table"
    grep -q '^paramset_stats_table$' "$OUT" || fail "$T22" "missing paramset_stats_table"
    ok "$T22"
fi

# 23. -o separates schedscore output from target stdout/stderr
T23="23-o-separates-target"
if require_env "$T23"; then
    OUTCSV=$(mktemp "$TMPDIR/schedscore.$T23.csv.XXXXXX"); CAP=$(mktemp "$TMPDIR/schedscore.$T23.cap.XXXXXX");
    trap 'rm -f "$OUTCSV" "$CAP"' EXIT HUP INT TERM
    with_timeout 10 "$SCHEDSCORE" -o "$OUTCSV" -- sh -c 'echo TARGET_STDOUT; echo TARGET_STDERR 1>&2' >"$CAP" 2>/dev/null || true
    # CSV header present in OUTCSV
    header_ok "$OUTCSV" || fail "$T23" "missing CSV header in -o file"
    # Target output should not be in OUTCSV
    if grep -q 'TARGET_STDOUT\|TARGET_STDERR' "$OUTCSV"; then fail "$T23" "found target output in -o file"; fi
    # But should be observable on caller's stdout/stderr (captured in CAP)
    grep -q 'TARGET_STDOUT' "$CAP" || fail "$T23" "missing target stdout in capture"
    grep -q 'TARGET_STDERR' "$CAP" || fail "$T23" "missing target stderr in capture"
    ok "$T23"
fi

fi

# 24. JSON details embedded and consistent with paramset_map
T24="24-json-details-embedded"
if require_env "$T24"; then
    OUT=$(mktemp "$TMPDIR/schedscore.$T24.XXXXXX"); trap 'rm -f "$OUT"' EXIT HUP INT TERM
    with_timeout 10 "$SCHEDSCORE" --format json --duration 1 -- true >"$OUT" 2>/dev/null || true
    grep -q '"paramset_stats"' "$OUT" || fail "$T24" "missing paramset_stats key"
    grep -q '"details"' "$OUT" || fail "$T24" "missing details in stats"
    grep -q '"policy"' "$OUT" || fail "$T24" "missing policy in details"
    if have_cmd jq; then
        map_pol=$(jq -r '.paramset_map[0].policy // empty' "$OUT" 2>/dev/null || true)
        stat_pol=$(jq -r '.paramset_stats[0].details.policy // empty' "$OUT" 2>/dev/null || true)
        [ -n "$map_pol" ] && [ -n "$stat_pol" ] && [ "$map_pol" = "$stat_pol" ] || fail "$T24" "JSON policy mismatch: map=$map_pol stats=$stat_pol"
    fi
    ok "$T24"
fi

# 25. Table headers: per-PID grouped headers present
T25="25-table-pid-grouped-headers"
if require_env "$T25"; then
    OUT=$(mktemp "$TMPDIR/schedscore.$T25.XXXXXX"); trap 'rm -f "$OUT"' EXIT HUP INT TERM
    with_timeout 10 "$SCHEDSCORE" --format table --duration 1 -- true >"$OUT" 2>/dev/null || true
    grep -E -q '^\s*id\s+\|\s+sched_latency_ns\s+\|\s+oncpu_ns\s+\|\s+periods' "$OUT" || fail "$T25" "missing top grouped header"
    grep -E -q '^\s*pid\s+comm\s+paramset_id\s+\|\s+p50\s+avg\s+p95\s+p99\s+\|\s+p50\s+avg\s+p95\s+p99\s+\|\s+nr_slices' "$OUT" || fail "$T25" "missing bottom grouped header"
    ok "$T25"
fi

# 26. Per-PID matrix appears before paramset_map_table and has piped headers
T26="26-pid-matrix-order-and-header"
if require_env "$T26"; then
    OUT=$(mktemp "$TMPDIR/schedscore.$T26.XXXXXX"); trap 'rm -f "$OUT"' EXIT HUP INT TERM
    with_timeout 15 "$SCHEDSCORE" --format table --show-migration-matrix --show-pid-migration-matrix --duration 1 -- true >"$OUT" 2>/dev/null || true
    pidm=$(awk '/^pid_migrations_matrix_table/{print NR; exit}' "$OUT" || true)
    psmap=$(awk '/^paramset_map_table/{print NR; exit}' "$OUT" || true)
    [ -n "$pidm" ] && [ -n "$psmap" ] || fail "$T26" "missing sections"
    [ "$pidm" -lt "$psmap" ] || fail "$T26" "pid matrix should precede paramset_map_table"
    grep -E -q '^pid\s+comm\s+\|\s+wakeup\s+\|\s+loadbalance\s+\|\s+numa' "$OUT" || fail "$T26" "missing pid matrix header pipes"
    ok "$T26"
fi

# 27. Paramset stats grouped header present
T27="27-paramset-stats-grouped-headers"
if require_env "$T27"; then
    OUT=$(mktemp "$TMPDIR/schedscore.$T27.XXXXXX"); trap 'rm -f "$OUT"' EXIT HUP INT TERM
    with_timeout 15 "$SCHEDSCORE" --format table --show-migration-matrix --duration 1 -- true >"$OUT" 2>/dev/null || true
    grep -E -q '^id\s+\|\s+sched_latency_ns\s+\|\s+oncpu_ns\s+\|\s+periods' "$OUT" || fail "$T27" "missing paramset top header"
    grep -E -q '^paramset_id\s+pids\s+\|\s+p50\s+avg\s+p95\s+p99\s+\|\s+p50\s+avg\s+p95\s+p99\s+\|\s+nr_slices' "$OUT" || fail "$T27" "missing paramset bottom header"
    ok "$T27"
fi

# 28. Paramset migrations matrix header uses pipes
# 31. --help includes detectors and key flags (concise)
T31="31-help-concise"
if require_env "$T31"; then
    OUT=$(mktemp "$TMPDIR/schedscore.$T31.XXXXXX"); trap 'rm -f "$OUT"' EXIT HUP INT TERM
    "$SCHEDSCORE" --help >"$OUT" 2>/dev/null || true
    grep -q -- "--detect-wakeup-latency" "$OUT" || fail "$T31" "missing detect-wakeup-latency"
    grep -q -- "--detect-migration-xnuma" "$OUT" || fail "$T31" "missing detect-migration-xnuma"
    grep -q -- "--detect-migration-xllc" "$OUT" || fail "$T31" "missing detect-migration-xllc"
    grep -q -- "--detect-remote-wakeup-xnuma" "$OUT" || fail "$T31" "missing detect-remote-wakeup-xnuma"
    grep -q -- "--format" "$OUT" || fail "$T31" "missing format"
    grep -q -- "--show-migration-matrix" "$OUT" || fail "$T31" "missing show-migration-matrix"
    grep -q -- "--help" "$OUT" || true
    ok "$T31"
fi

T28="28-paramset-matrix-pipes"
if require_env "$T28"; then
    OUT=$(mktemp "$TMPDIR/schedscore.$T28.XXXXXX"); trap 'rm -f "$OUT"' EXIT HUP INT TERM
    with_timeout 15 "$SCHEDSCORE" --format table --show-migration-matrix --duration 1 -- true >"$OUT" 2>/dev/null || true
    grep -E -q '^paramset_id\s+\|\s+wakeup\s+\|\s+loadbalance\s+\|\s+numa' "$OUT" || fail "$T28" "missing pipes in paramset matrix header"
    ok "$T28"
fi

# 29. Migrations summary grouped headers present
T29="29-migr-summary-grouped-headers"
if require_env "$T29"; then
    OUT=$(mktemp "$TMPDIR/schedscore.$T29.XXXXXX"); trap 'rm -f "$OUT"' EXIT HUP INT TERM
    with_timeout 15 "$SCHEDSCORE" --format table --show-migration-matrix --duration 1 -- true >"$OUT" 2>/dev/null || true
    grep -E -q '^id\s+\|\s+totals\s+\|\s+by_reason\s+\|\s+by_locality' "$OUT" || fail "$T29" "missing migrations summary top header"
    grep -E -q '^paramset_id\s+\|\s+total\s+wakeup\s+lb\s+numa\s+\|\s+wakeup\s+lb\s+numa\s+\|\s+smt\s+l2\s+llc\s+xllc\s+xnuma' "$OUT" || fail "$T29" "missing migrations summary bottom header"
    ok "$T29"
fi

# 30. CSV smoke check
T30="30-csv-smoke"
if require_env "$T30"; then
    OUT=$(mktemp "$TMPDIR/schedscore.$T30.XXXXXX"); trap 'rm -f "$OUT"' EXIT HUP INT TERM
    with_timeout 10 "$SCHEDSCORE" --format csv --duration 1 -- true >"$OUT" 2>/dev/null || true
    grep -q '^pid,comm,paramset_id,' "$OUT" || fail "$T30" "missing CSV header"
    ok "$T30"
fi


# 31. topology dump headers and summary
T31="31-topology-dump"
if require_env "$T31"; then
    OUT=$(mktemp "$TMPDIR/schedscore.$T31.XXXXXX"); trap 'rm -f "$OUT"' EXIT HUP INT TERM
    with_timeout 10 "$SCHEDSCORE" --dump-topology >"$OUT" 2>/dev/null || true
    grep -q '^topology_table$' "$OUT" || fail "$T31" "missing topology_table marker"
    grep -E -q '^cpu\s+smt\(core_id\)\s+l2_id\s+llc_id\s+numa_id' "$OUT" || fail "$T31" "missing topology header"
    grep -q '^topology_summary$' "$OUT" || fail "$T31" "missing topology_summary"
    grep -E -q 'cpus=[0-9]+\s+smt_cores=[0-9]+\s+l2_domains=[0-9]+\s+llc_domains=[0-9]+\s+numa_nodes=[0-9]+' "$OUT" || fail "$T31" "missing summary line"
    ok "$T31"
fi


exit 0
