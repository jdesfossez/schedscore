// SPDX-License-Identifier: GPL-2.0-only
#ifndef SCHEDSCORE_OPTS_H
#define SCHEDSCORE_OPTS_H

#include <stdbool.h>

struct opts {
    int duration_sec;          /* 0 => run until Ctrl-C */
    long latency_warn_us;      /* bpf_printk threshold */
    bool warn_enable;

    /* filters */
    int pid;
    char *comm;
    char *cgroup_path;
    unsigned long long cgroup_id;
    bool have_cgroup_id;

    /* run target as user */
    char *env_file;            /* env injection file for target */

    /* optional output file/dir */
    char *out_path;
    char *out_dir;

    /* formatting */
    char *format;    /* csv (default), json, table */
    char *columns;   /* comma-separated list of columns */

    char *run_as_user; /* name or numeric uid string */

    /* external capture */
    bool perf_enable;
    bool ftrace_enable;
    char *perf_args;
    char *ftrace_args;

    /* behavior */
    bool follow_children;

    /* aggregation */
    bool aggregate_enable;   /* default true */
    bool paramset_recheck;   /* default false */
    bool timeline_enable;    /* default false */
    bool resolve_masks;      /* default true (userspace only) */

    /* info */
    bool show_hist_config;

    /* table output options */
    bool show_migration_matrix;     /* table mode: show reason×locality grid tables */
    bool show_pid_migration_matrix; /* table mode: per-PID migration matrix */
    bool dump_topology;             /* print detected cpu->(core,l2,llc,numa) */
};

#endif /* SCHEDSCORE_OPTS_H */

