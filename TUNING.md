schedscore TUNING guide
=======================

This guide explains how to tune schedscore’s histogram resolution/range to your workload, and how to interpret clamp warnings.

Quick concepts
--------------
- Both latency and on-CPU histograms are linear with power-of-two width:
  - width_ns = 1 << WIDTH_SHIFT
  - index = min(ns >> WIDTH_SHIFT, BUCKETS-1)
  - quantile representative = (i + 0.5) << WIDTH_SHIFT
- Trade-offs:
  - Resolution: smaller width gives finer low-end detail
  - Range: more buckets (or larger width) increases coverage before clamping
  - Memory: bytes per thread ≈ 4 * (LAT_BUCKETS + ON_BUCKETS)
    (we have both latency and on-CPU histograms)
- All constants are shared in schedscore_hist.h (used by BPF and userspace).

Defaults (balanced for common cases)
------------------------------------
- Latency: LAT_WIDTH_SHIFT=13 (8192 ns/bin ≈ 8.192 µs), LAT_BUCKETS=2048 (~16.78 ms)
- On-CPU:  ON_WIDTH_SHIFT=20 (1,048,576 ns/bin ≈ 1.048 ms), ON_BUCKETS=4096 (~4.29 s)
- Per-thread histogram memory: ≈ (2048 + 4096) * 4 bytes ≈ 24 KB; doubled internally across both histograms → ~48 KB per tracked thread.

Clamp warnings
--------------
- If the top bucket is hit (per-PID or per-paramset), we print a warning and suggest using:
  - --show-hist-config to view current resolution, range, memory per thread
  - Then increase BUCKETS or WIDTH_SHIFT accordingly
- Typical rule: first increase BUCKETS; if you hit kernel PERCPU value-size limits, bump WIDTH_SHIFT by 1 (coarser bins) and reduce BUCKETS if necessary.

Recommended settings by scenario
--------------------------------
1) Large servers (CFS) — finding fairness and tail latency outliers
   - Goal: capture µs–ms latency tails and ms-scale on-CPU bursts
   - Suggested:
     - Latency: 8–16 µs/bin, 2048–4096 buckets (16–33 ms range)
     - On-CPU: ~1 ms/bin, 4096 buckets (~4.29 s range)
   - Why: avoids clamping for typical web workloads under load; on-CPU captures long bursts during transient overloads.

2) Desktop/browser profiling (CFS) — smoothness, responsiveness
   - Goal: emphasize low-end latency and short on-CPU bursts
   - Suggested:
     - Latency: 4–8 µs/bin, 4096 buckets (16–33 ms range)
     - On-CPU: 0.5–1.0 ms/bin, 2048–4096 buckets (1–4 s range)
   - Why: finer granularity helps reason about responsiveness; range remains ample.

3) Embedded with RT tasks (FIFO/Deadline/CFS mix) — fairness and preemption gaps
   - Goal: keep long uninterrupted RT on-CPU segments visible without clamping
   - Suggested:
     - Latency: 16–32 µs/bin, 2048 buckets (33–67 ms range)
     - On-CPU: 1–2 ms/bin, 4096–8192 buckets (~4–8 s range)
   - Why: RT segments can be very long; coarser width with more buckets covers seconds while keeping memory manageable.

Memory planning for N threads
-----------------------------
- Rough per-thread histogram memory ≈ 4*(LAT_BUCKETS + ON_BUCKETS)
- Examples (both histograms combined):
  - 2048 + 4096 → ~24 KB raw; ~48 KB effective per thread
  - 4096 + 4096 → ~32 KB raw; ~64 KB effective per thread
  - 2048 + 8192 → ~41 KB raw; ~82 KB effective per thread
- For 500 threads: 500 × ~48 KB ≈ ~24 MB; adjust as needed.

How to change settings
----------------------
- Edit schedscore_hist.h:
  - LAT_WIDTH_SHIFT / LAT_BUCKETS
  - ON_WIDTH_SHIFT / ON_BUCKETS
- Rebuild tools/schedscore: make clean && make -j

Interpreting small-sample quantiles
-----------------------------------
- With very few samples (e.g., nr_sched_periods < 10), quantiles land on coarse bins; averages are more informative.
- Consider running a longer duration (e.g., 10–30 s) for stable quantiles.

Troubleshooting
---------------
- Warning: on-CPU histogram hit top bin (per-pid+paramset)
  - Action: increase ON_BUCKETS or ON_WIDTH_SHIFT (see --show-hist-config)
- Load error: -E2BIG after bumping buckets
  - Cause: PERCPU map value size too large
  - Action: reduce BUCKETS and increase WIDTH_SHIFT by 1; rebuild

Appendix: choosing WIDTH_SHIFT
------------------------------
- Start from a target resolution r_ns and desired range R_ns:
  - WIDTH_SHIFT = round(log2(r_ns))
  - BUCKETS ≈ ceil(R_ns / (1<<WIDTH_SHIFT))
- Prefer power-of-two widths to keep mapping as a single shift in BPF hot path.

