// SPDX-License-Identifier: GPL-2.0-only
#ifndef OUTPUT_COMMON_H
#define OUTPUT_COMMON_H

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>

/* Minimal copies of enums needed for unit tests to avoid dragging full
 * schedscore headers and build dependencies. Keep in sync with uapi. */

enum { SC_MR_WAKEUP, SC_MR_LB, SC_MR_NUMA, SC_MR__COUNT };
/* Locality tiers: smt (same core), l2, llc (L3), xllc, xnuma */
enum { SC_ML_CORE, SC_ML_L2, SC_ML_LLC, SC_ML_XLLC, SC_ML_XNUMA, SC_ML__COUNT };

/* Snapshot of the minimal data needed by output formatters for unit tests
 * and (later) for runtime emission. Keep this small and stable. */

#define SS_MAX_PIDS       64
#define SS_MAX_PARAMSETS  64

struct ss_pid_stats {
    uint32_t pid;
    char comm[16];
    uint64_t migr_grid[SC_MR__COUNT][SC_ML__COUNT];
};

struct ss_paramset_stats {
    uint32_t paramset_id;
    uint64_t migr_grid[SC_MR__COUNT][SC_ML__COUNT];
};

struct ss_snapshot {
    struct ss_pid_stats pids[SS_MAX_PIDS];
    int nr_pids;
    struct ss_paramset_stats sets[SS_MAX_PARAMSETS];
    int nr_sets;
};

/* Emitters for snapshot-based testing (do not depend on libbpf). */
int output_table_from_snapshot(FILE *out, const struct ss_snapshot *snap);
int output_csv_from_snapshot(FILE *out, const struct ss_snapshot *snap);
int output_json_from_snapshot(FILE *out, const struct ss_snapshot *snap);

#endif /* OUTPUT_COMMON_H */

