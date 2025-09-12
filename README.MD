schedscore — Scorecard for the kernel scheduler
===============================================

Overview
--------
Schedscore is an eBPF-based tool to measure and report:
- Wakeup scheduling latency (ns)
- On-CPU slice duration (ns)
- Task migrations by reason (wakeup/lb/numa) and locality (core/LLC/xLLC)
- Aggregation per PID and per “paramset” (policy, uclamp, cpus/mems mask, cgroup)

It provides table, CSV, and JSON outputs suitable for interactive inspection and tooling.

Requirements
------------
- Kernel with BTF available at /sys/kernel/btf/vmlinux (CONFIG_DEBUG_INFO_BTF=y)
- libbpf development files (pkg-config libbpf)
- bpftool in PATH
- clang/LLVM (for BPF object) and a C compiler (for userspace)
- libelf, zlib, pthread
- Root access

Build (standalone)
------------------
- Configure and build:
  $ ./configure
  $ make -j

- Tests (requires sudo -n for BPF):
  $ sudo make test

- Static glibc binary (requires static libbpf/glibc):
  $ make static
  Produces ./schedscore-static

- Static musl binary (portable; requires musl-gcc and static libbpf):
  $ make static-musl
  Produces ./schedscore-static-musl

Usage
-----
Basic 10s run (table, track all processes):
  $ sudo ./schedscore --duration 10

Launch and follow a program; exit when it exits:
  $ sudo ./schedscore -- -- stress-ng --cpu 8 --timeout 10

Filter by pid or comm (examples):
  $ sudo ./schedscore --pid 1234 --duration 5
  $ sudo ./schedscore --comm chrome --duration 5

Record perf and/or ftrace alongside schedscore:
- Enable perf record with defaults:
  $ sudo ./schedscore --duration 10 --perf
  (writes perf.data in the current directory unless overridden via --perf-args)
- Customize perf args (replaces defaults entirely):
  $ sudo ./schedscore --duration 10 --perf-args "-a -e sched:* -o /tmp/perf.data"
- Enable ftrace:
  $ sudo ./schedscore --duration 10 --ftrace
- Customize ftrace args:
  $ sudo ./schedscore --duration 10 --ftrace-args "-e sched -o /tmp/trace.dat"

Output formats:
- Table (default):
  $ sudo ./schedscore --format table --duration 3

- CSV:
  $ sudo ./schedscore --format csv --duration 3 -- true > out.csv

- JSON (paramset_stats[].details embeds policy/masks/etc):
  $ sudo ./schedscore --format json --duration 3 -- true | jq
  Example filtering: all SCHED_OTHER paramsets
  $ jq '.paramset_stats[] | select(.details.policy=="SCHED_OTHER")' out.json

Migration matrices (table mode):
- Paramset-level matrix:
  $ sudo ./schedscore --format table --show-migration-matrix --duration 3 -- true

- Per-PID migration matrix (placed after per-PID table):
  $ sudo ./schedscore --format table --show-migration-matrix --show-pid-migration-matrix --duration 3 -- true

Common flags
------------
- --duration N                   Stop after N seconds (Ctrl-C also stops)
- --format {table|csv|json}
- --pid PID, --comm NAME         Focus collection on matching tasks
- --show-migration-matrix        Add paramset migration matrix tables
- --show-pid-migration-matrix    Add per-PID migration matrix table
- --columns ...                  Select table columns (table mode)
- --user NAME, --env-file PATH   Drop privileges / load env before launching command
- --                             Separator; everything after is the program to launch and follow
- Detectors (see DETECTORS.md for details):
  - --detect-wakeup-latency <ns>
  - --detect-migration-xnuma
  - --detect-migration-xllc
  - --detect-remote-wakeup-xnuma


Outputs
-------
Table
- Per-PID table with two-line grouped header:
  id | sched_latency_ns | oncpu_ns | periods
  pid comm paramset_id | p50 avg p95 p99 | p50 avg p95 p99 | nr_slices
- Optional per-PID migration matrix:
  pid comm | wakeup | loadbalance | numa
  core/llc/xllc under each group
- Paramset map and paramset stats with grouped headers
- Paramset migration matrix (grouped)
- Migrations summary (grouped: totals, by_reason, by_locality)

CSV
- Per-PID rows, followed by paramset sections and migrations summary CSV

JSON
- paramset_map: array of paramset definitions (for compatibility)
- paramset_stats: array of metrics per paramset with embedded details
  { "paramset_id": 1,
    "details": { "policy": "SCHED_OTHER", "nice": 0, "uclamp_max": 1024, "cpus_ranges": "0-23", ... },
    "pids": 12, "p50_sched_latency_ns": 12288, "avg_oncpu_ns": 123456, ...,
    "migrations": { "total": 42 },
    "migrations_by_reason": { "wakeup": 10, "lb": 30, "numa": 2 },
    "migrations_by_locality": { "core": 33, "llc": 7, "xllc": 2 },
    "migrations_grid": { ... }
  }

Privileges
----------
- Run as root or with passwordless sudo to load BPF programs
- BTF must be available at /sys/kernel/btf/vmlinux

Troubleshooting
---------------
- bpftool not found: install bpftool or set BPFTOOL_BIN in config.mk (./configure will write hints)
- libbpf not found: install libbpf-dev (pkg-config libbpf)
- /sys/kernel/btf/vmlinux missing: enable CONFIG_DEBUG_INFO_BTF in your kernel
- Static glibc build warnings about NSS calls are expected; for portability use static-musl

Tuning
------
See TUNING.md for histogram resolution/range trade-offs and guidance. You can show current histogram settings with:
  $ ./schedscore --show-hist-config

License
-------
- GPL-2.0-only (SPDX in all files). eBPF object declares "GPL" to enable GPL-only helpers.
- See README.license for details.
