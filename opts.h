// SPDX-License-Identifier: GPL-2.0-only
#ifndef SCHEDSCORE_OPTS_H
#define SCHEDSCORE_OPTS_H

#include <stdbool.h>

struct opts {
	int duration_sec;		/* 0 => run until Ctrl-C */
	long latency_warn_us;		/* bpf_printk threshold */
	bool warn_enable;

	/* Filters. */
	int pid;
	char *comm;
	char *cgroup_path;
	unsigned long long cgroup_id;
	bool have_cgroup_id;

	/* Run target as user. */
	char *env_file;			/* Env injection file for target. */

	/* Optional output file/dir. */
	char *out_path;
	char *out_dir;

	/* Formatting. */
	char *format;			/* csv (default), json, table */
	char *columns;			/* Comma-separated list of columns. */

	char *run_as_user;		/* Name or numeric uid string. */

	/* External capture. */
	bool perf_enable;
	bool ftrace_enable;
	char *perf_args;
	char *ftrace_args;

	/* Behavior. */
	bool follow_children;

	/* Aggregation. */
	bool aggregate_enable;		/* default true */
	bool paramset_recheck;		/* default false */
	bool timeline_enable;		/* default false */
	bool resolve_masks;		/* default true (userspace only) */

	/* Info. */
	bool show_hist_config;

	/* Table output options. */
	bool show_migration_matrix;	/* paramset/pid migration matrices */
	bool show_pid_migration_matrix;	/* per-PID migration matrix */
	bool dump_topology;		/* print cpu->(core,l2,llc,numa) */

	/* Detectors. */
	unsigned long long detect_wakeup_lat_ns; /* 0 disables */
	bool detect_migration_xnuma;
	bool detect_migration_xllc;
	bool detect_remote_wakeup_xnuma;

};

#endif /* SCHEDSCORE_OPTS_H */

