/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * schedscore_hist.h - Shared histogram configuration for schedscore
 *
 * We use linear, power-of-two bucket widths to avoid divisions in eBPF fast paths.
 *
 * Mapping:
 *  - bin width (ns) = 1ULL << WIDTH_SHIFT
 *  - bin index = clamp(ns >> WIDTH_SHIFT, 0, BUCKETS-1)
 *  - representative value used for quantiles = (i + 0.5) << WIDTH_SHIFT
 *
 * Choose (WIDTH_SHIFT, BUCKETS) to balance resolution vs range vs memory.
 *
 * Memory cost per entry (bytes) for one histogram = 4 * BUCKETS
 * We track two histograms per entry (latency + on-CPU).
 *
 * Back-of-the-envelope memory for 5000 threads (histograms only):
 *   - BUCKETS=256  → per entry ~ 2*256*4 = 2048 bytes ≈ 2.0 KB  → ~10 MB total
 *   - BUCKETS=512  → per entry ~ 2*512*4 = 4096 bytes ≈ 4.0 KB  → ~20 MB total
 *   - BUCKETS=1024 → per entry ~ 2*1024*4 = 8192 bytes ≈ 8.0 KB → ~40 MB total
 * (plus struct/map overhead)
 *
 * Range examples:
 *   Latency (WIDTH_SHIFT=13 → 8192 ns/bin ≈ 8.192 µs):
 *     • BUCKETS=512  → ~4.19 ms coverage
 *     • BUCKETS=1024 → ~8.39 ms coverage
 *
 *   On-CPU (WIDTH_SHIFT=20 → 1,048,576 ns/bin ≈ 1.048 ms):
 *     • BUCKETS=256  → ~268 ms coverage
 *     • BUCKETS=512  → ~536 ms coverage
 *     • BUCKETS=1024 → ~1.07 s coverage
 *
 * For typical experiments with thousands of runnable threads and 10s durations,
 * BUCKETS=1024 provides generous headroom while keeping memory reasonable
 * (~40 MB for 5000 threads). Tune BUCKETS/SHIFT for your expected ranges.
 *
 * Profiles (copy/paste these defines as a block if you want a preset):
 *
 * 1) Balanced default (common case, clamp extreme FIFO):
 *    - Lat:  8.192 µs/bin, 2048 bins → ~16.78 ms
 *    - CPU:  1.048 ms/bin, 4096 bins → ~4.29 s
 *    Memory per thread (both hists): ~48 KB
 *
 * 2) Desktop/browser (finer low-end latency):
 *    - Lat:  4.096 µs/bin, 4096 bins → ~16.78 ms
 *      #define LAT_WIDTH_SHIFT 12
 *      #define LAT_BUCKETS     4096
 *    - CPU:  1.048 ms/bin, 2048–4096 bins → 2.15–4.29 s
 *      #define ON_WIDTH_SHIFT  20
 *      #define ON_BUCKETS      2048
 *    Memory per thread: ~32–48 KB
 *
 * 3) Embedded + RT (long RT bursts, coarser bins):
 *    - Lat:  16.384 µs/bin, 2048 bins → ~33.55 ms
 *      #define LAT_WIDTH_SHIFT 14
 *      #define LAT_BUCKETS     2048
 *    - CPU:  2.097 ms/bin, 4096–8192 bins → 8.59–17.18 s
 *      #define ON_WIDTH_SHIFT  21
 *      #define ON_BUCKETS      4096
 *    Memory per thread: ~48–80 KB
 *
 * 4) Big server tail hunting (more latency headroom):
 *    - Lat:  8.192 µs/bin, 4096 bins → ~33.55 ms
 *      #define LAT_WIDTH_SHIFT 13
 *      #define LAT_BUCKETS     4096
 *    - CPU:  1.048 ms/bin, 4096 bins → ~4.29 s
 *      #define ON_WIDTH_SHIFT  20
 *      #define ON_BUCKETS      4096
 *    Memory per thread: ~64 KB
 *
 * Note: PERCPU map value-size limits can be hit with very large buckets.
 * If load fails (-E2BIG), increase WIDTH_SHIFT by 1 and/or reduce BUCKETS.

 */

#ifndef SCHEDSCORE_HIST_H
#define SCHEDSCORE_HIST_H

/* Latency histogram */
#define LAT_WIDTH_SHIFT 13   /* 8192 ns/bin  (~8.192 µs resolution) */
#define LAT_BUCKETS     2048 /* ~16.78 ms coverage before clamp */

/* On-CPU histogram */
#define ON_WIDTH_SHIFT  20    /* 1,048,576 ns/bin  (~1.048 ms resolution) */
#define ON_BUCKETS      4096  /* ~4.29 s coverage before clamp */

#endif /* SCHEDSCORE_HIST_H */

