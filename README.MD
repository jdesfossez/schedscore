schedscore — Scorecard for the kernel scheduler
===============================================

Overview
--------
schedscore in a tool to evaluate the behavior of the kernel scheduler under
real workloads. The goal is to automatically collect metrics and statistics to
understand how the scheduler behaves. The tool allow to either observe a full
system or a specific set of processes (and their children).

Under the hood, schedscore connects to kernel tracepoints using eBPF and tracks
a set of processes using in-kernel maps in real-time (no postprocessing of
traces). Various options are available to specify the set of processes to track,
or to run and track a command directly. At the end, it displays the data in
various formats (ascii table, CSV or JSON).

To be able to evaluate the scheduler, the tool creates a "paramset" based on the
set of parameters that can influence the scheduler:
 - the scheduling policy (SCHED_OTHER, SCHED_NORMAL, etc)
 - the various priorities (nice, rt_prio, dl_runtime, dl_deadline, dl_period)
 - uclamp
 - cgroup_id
 - CPU ranges
 - memory ranges

Everytime it encounters a new process to track, it evaluates this set of
parameters and creates a "paramset" for every unique set of combinations. This
allows to interpret the data by scheduling properties. The per-pid view is also
always captured, but for larger applications like a browser it may be more
interesting to look at the overall profile. By default this paramset is only
evaluated the first time we encounter a new process to track, or when it
changes its comm value (common after exec), but it can be reevaluated at every
sched_switch with --paramset-recheck (which can become costly).

Currently, this tool computes:
- wakeup latency (delay between sched_waking and sched_switch)
- oncpu time (sched_switch in/out)
- number of slices
- migration main reasons (wakeup on a different CPU, load-balancing,
  numa-balancing)
- migration distance (SMT, L2, LLC, cross-LLC, cross-NUMA)

These are computed both per-PID and per-paramset and can be displayed in a
variety of formats.

Finally, schedscore can launch perf and/or trace-cmd to record the full trace
while tracking. This gives an easy way to investigate the full trace after the
fact if needed. It also supports various "detectors" to log in the trace buffer
interesting events at the exact time they happen (long wakeup latencies,
migrations across NUMA or LLC, wakeup across NUMA).

To control the memory usage, keep the data in per-cpu maps and be able to
compute the metrics as they happen, the metrics are grouped into linear
buckets. Tradeoffs between memory usage, range and resolution are documented in
TUNING.md and can be changed with defines in schedscore_hist.h depending on the
environment and needs (server, desktop, embedded, etc).


Requirements
------------

- Kernel with BTF available at /sys/kernel/btf/vmlinux (CONFIG_DEBUG_INFO_BTF=y)
- libbpf >= 1.0 development files (pkg-config libbpf)
- bpftool in PATH
- clang/LLVM (for BPF object) and a C compiler (for userspace)
- libelf, zlib, pthread
- Root access


Building
--------

This tool is written in C with the minimal set of dependencies possible. The
only complex dependency is libbpf which needs to be >= 1.0, it is not packaged
for all distros, so the build system pulls and builds a static version locally
if needed. The tool also supports to build for another environment (see
scripts/build-static-in-docker.sh to see how to cross-compile)

To build:

```
./configure && make
```

Examples
--------

Launch a simple command and track its children:
```
$ sudo ./schedscore -f -- <my command>
```

Follow a running process and its children for 10s:
```
$ sudo ./schedscore -f --pid <PID> --duration 10
```

Follow all the running processes for 10s and show the average scheduling latency of the processes using SCHED_FIFO:
```
$ sudo ./schedscore -f --format json --duration 10 | jq '.paramset_stats[] | select(.details.policy=="SCHED_FIFO") | .avg_sched_latency_ns' 
17563
27095
22776
[...]
```

Follow stress-ng while recording a perf trace, then find the trace of a wakeup latency > 1000ns
```
$ sudo ./schedscore --detect-wakeup-latency 1000 -f --perf -- stress-ng --cpu 1 --timeout 2
stress-ng: info:  [923978] setting to a 2 second run per stressor
stress-ng: info:  [923978] dispatching hogs: 1 cpu
stress-ng: info:  [923978] successful run completed in 2.02s
[ perf record: Woken up 1 times to write data ]
[ perf record: Captured and wrote 4.295 MB perf.data (15232 samples) ]
id                                  | sched_latency_ns            | oncpu_ns                            | periods  
pid    comm             paramset_id | p50    avg    p95    p99    | p50      avg      p95      p99      | nr_slices
923985 stress-ng                  1 |  12288   8534  12288  12288 | 18931712 84226306 67100672 67100672 |        24
923978 stress-ng                  1 |  36864  59677 126976 126976 |   466944  1022761  7413760  7413760 |        12

$ sudo perf script | grep 923985 | grep -B3 bpf
         swapper       0 [002] 1176252.301843:                     sched:sched_waking: comm=stress-ng pid=923985 prio=120 target_cpu=002
         swapper       0 [002] 1176252.301849:                     sched:sched_wakeup: stress-ng:923985 [120]<CANT FIND FIELD success> CPU:002
         swapper       0 [002] 1176252.301852:                     sched:sched_switch: swapper/2:0 [120] R ==> stress-ng:923985 [120]
         swapper       0 [002] 1176252.301860:             bpf_trace:bpf_trace_printk: schedscore:detect_wakeup_latency: pid=923985 latency=8534

$ echo 301852-301843 | bc -l
9
```

Launch and track firefox as a normal user
```
$ env > myenv.txt
$ sudo ./schedscore -f -u julien -e myenv.txt -- firefox
[...firefox runs, after it is closed, the summary is output...]


# The per-PID summary:
id                                  | sched_latency_ns            | oncpu_ns                          | periods  
pid    comm             paramset_id | p50    avg    p95    p99    | p50     avg     p95      p99      | nr_slices
919526 firefox:sh5                2 | 274432 277937 274432 274432 |   24576   17665    57344    57344 |         4
919477 TaskCon~ller #2            2 |   4096  13424  20480 266240 |    8192   15274    57344   368640 |        70
919844 Chroot Helper              2 | 102400 104550 102400 102400 |  237568  164714   647168   647168 |         6
919589 Worker Launcher            2 | 176128 176502 176128 176128 |   24576   23348    57344    57344 |         4
919543 MainThread                 2 | 126976 127610 126976 126976 |   40960   24932    57344    57344 |         4
919448                            2 |      0      0      0      0 |  958464  479982   958464   958464 |         2
919703 StreamTrans #2             2 |   4096  15097   4096 217088 |   24576  147552  1007616  5005312 |        46

[...]


# The list of identified unique paramsets
paramset_map_table
paramset_id  policy        nice rtprio  dl_runtime_ns dl_deadline_ns   dl_period_ns uclamp_min uclamp_max cgroup_id      cpus_ranges  pop mems_ranges   pop
1            SCHED_OTHER      0      0              0              0              0          0       1024 0x00000025b1f0 0-11,64-255  204               0
3            SCHED_BATCH      0      0              0              0              0          0       1024 0x000000273f56 0-11,64-255  204               0
2            SCHED_OTHER      0      0              0              0              0          0       1024 0x000000273f56 0-11,64-255  204               0
6            SCHED_RR         0     10              0              0              0       1024       1024 0x000000273f56 0-11,64-255  204               0
5            SCHED_OTHER      1      0              0              0              0          0       1024 0x000000273f56 0-11,64-255  204               0
4            SCHED_BATCH     19      0              0              0              0          0       1024 0x000000273f56 0-11,64-255  204               0


# The per-paramset summary:
paramset_stats_table
id               | sched_latency_ns            | oncpu_ns                      | periods
paramset_id pids | p50    avg    p95    p99    | p50    avg    p95     p99     | nr_slices
          3    0 |      0      0      0      0 |  73728  38036  106496  106496 |    10
          6    1 |  77824  79066  77824  77824 | 122880  61781  122880  122880 |     2
          4    5 | 266240 179431 290816 290816 |   8192  11313   40960   40960 |    10
          1   58 |   4096  13554  61440 110592 |   8192  77518  712704 2793472 |  1361
          2  412 |   4096  20594  86016 184320 |  40960 146816 1040384 5447680 | 28600
          5    1 |  45056  49265  86016 217088 |  40960  19650   57344   57344 |    44


# The per-paramset migration matrix (reason vs distance):
paramset_migrations_matrix_table
paramset_id  | wakeup                    | loadbalance               | numa                     
             | smt  l2   llc  xllc xnuma | smt  l2   llc  xllc xnuma | smt  l2   llc  xllc xnuma
3            |    0    0    0    0     0 |    0    0    2    0     0 |    0    0    0    0     0
6            |    0    0    0    0     0 |    0    0    0    0     0 |    0    0    0    0     0
4            |    0    0    0    0     0 |    0    0    0    0     0 |    0    0    0    0     0
1            |    0    0    0    0     0 |    0   20   40    0     0 |    0    0    0    0     0
2            |    0    0    0    0     0 |   23 1327 2273    0     0 |    0    0    0    0     0
5            |    0    0    0    0     0 |    0    0    0    0     0 |    0    0    0    0     0


# The per-paramset migration summary:
migrations_summary_table
id          | totals | by_reason                    | by_locality             
paramset_id | total  | wakeup lb   numa             | smt l2   llc  xllc xnuma
3           | 2      | 0      2    0                | 0   0    2    0    0    
6           | 0      | 0      0    0                | 0   0    0    0    0    
4           | 0      | 0      0    0                | 0   0    0    0    0    
1           | 60     | 0      60   0                | 0   20   40   0    0    
2           | 3623   | 0      3623 0                | 23  1327 2273 0    0    
5           | 0      | 0      0    0                | 0   0    0    0    0    
```

Questions ?
-----------
Reach out via github (@jdesfossez), email (j AT jdfz.org), IRC (jdesfossez).

LLM usage disclaimer
--------------------
A lot of the plumbing code was written by an LLM, all the algorithmic work (how
to track, how to store the data, how to manage processes, etc) was designed by
a human.
