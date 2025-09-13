/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * schedscore_uapi.h - Shared map value/type layout for BPF and userspace
 *
 * Keep this header minimal and UAPI-safe: fixed-width types (__uXX), no libc.
 * Included by both schedscore.bpf.c and schedscore.c to avoid drift.
 */
#ifndef SCHEDSCORE_UAPI_H
#define SCHEDSCORE_UAPI_H

/* Define minimal fixed-width types for BPF and userspace without external deps */
typedef unsigned char __u8;
typedef signed char __s8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;

#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif

/* Config set by userspace, consumed by BPF */
struct config {
	__u64 latency_warn_ns;
	__u8  enable_warn;
	__u8  use_pid_filter;
	__u8  use_comm_filter;
	__u8  use_cgrp_filter;
	__u8  follow_children;
	__u8  aggregate_enable;
	__u8  paramset_recheck;
	__u8  timeline_enable;

	/* detectors */
	__u64 detect_wakeup_lat_ns;      /* 0 disables */
	__u8  detect_migration_xnuma;    /* bool */
	__u8  detect_migration_xllc;     /* bool */
	__u8  detect_remote_wakeup_xnuma;/* bool */
};

/* Exact comm filter key */
struct comm_key { char comm[TASK_COMM_LEN]; };

/* Paramset grouping key extracted from task_struct */
struct schedscore_paramset_key {
	__u8  policy;      /* SCHED_* */
	__s8  nice;        /* Linux nice (static_prio - 120) */
	__u8  rtprio;      /* realtime priority if any */
	__u64 dl_runtime;  /* deadline runtime (ns) */
	__u64 dl_deadline; /* deadline (ns) */
	__u64 dl_period;   /* period (ns) */
	__u16 uclamp_min;  /* 0..1024 */
	__u16 uclamp_max;  /* 0..1024 */
	__u64 cgroup_id;   /* cgroup v2 id */
	__u64 cpus_mask[4];/* up to 256 CPUs */
	__u16 cpus_weight; /* popcount of cpus_mask */
	__u64 mems_mask[4];/* up to 256 NUMA nodes */
	__u16 mems_weight; /* popcount of mems_mask */
};

struct schedscore_paramset_info {
	struct schedscore_paramset_key key;
};

/* schedscore-specific migration enums (avoid kernel collisions) */
enum sc_migr_reason { SC_MR_WAKEUP, SC_MR_LB, SC_MR_NUMA, SC_MR__COUNT };
/* Locality tiers: smt (same core), l2, llc (L3), xllc (other LLC, same NUMA), xnuma (other NUMA) */
enum sc_migr_loc { SC_ML_CORE, /* smt */ SC_ML_L2, SC_ML_LLC, SC_ML_XLLC, SC_ML_XNUMA, SC_ML__COUNT };

/* Per-PID stats map value */
struct schedscore_pid_stats {
	__u64 runtime_ns;
	__u64 oncpu_start_ns;
	__u64 wake_lat_sum_ns;
	__u64 wake_lat_cnt;
	__u32 lat_hist[LAT_BUCKETS];
	__u32 on_hist[ON_BUCKETS];
	__u32 last_cpu;
	__u32 last_paramset_id;
	__u32 nr_periods;
	/* migration grid: reason x locality */
	__u64 migr_grid[SC_MR__COUNT][SC_ML__COUNT];
	char  comm[TASK_COMM_LEN];
};

/* Per-paramset aggregated stats */
struct schedscore_paramset_stats {
	__u64 runtime_ns;
	__u64 wake_lat_sum_ns;
	__u64 wake_lat_cnt;
	__u32 lat_hist[LAT_BUCKETS];
	__u32 on_hist[ON_BUCKETS];
	__u32 nr_periods;
	/* migration grid aggregated */
	__u64 migr_grid[SC_MR__COUNT][SC_ML__COUNT];
};

#endif /* SCHEDSCORE_UAPI_H */

