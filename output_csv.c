// SPDX-License-Identifier: GPL-2.0-only
#include <stdio.h>
#include <string.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "schedscore.skel.h"
#include "schedscore_hist.h"
#include "schedscore_uapi.h"
#include "emit_helpers.h"
#include "output_csv.h"


void dump_paramset_csv(struct schedscore_bpf *skel, bool resolve_masks)
{
	int info_fd = bpf_map__fd(skel->maps.paramset_info);
	int stats_fd = bpf_map__fd(skel->maps.stats_by_paramset);
	int pid2set_fd = bpf_map__fd(skel->maps.pid_to_paramset);
	__u32 key = 0, next = 0;
	int err;
	char cpus[512], mems[512];

	printf("\nparamset_map_csv\n");
	printf("paramset_id,policy,nice,rtprio,dl_runtime_ns,dl_deadline_ns,dl_period_ns,"
	       "uclamp_min,uclamp_max,cgroup_id,cpus_ranges,cpus_weight,mems_ranges,mems_weight\n");
	key = next = 0;
	while ((err = bpf_map_get_next_key(info_fd, &key, &next)) == 0) {
		struct schedscore_paramset_info info;
		if (bpf_map_lookup_elem(info_fd, &next, &info) == 0) {
			cpus[0] = mems[0] = '\0';
			if (resolve_masks) {
				mask_to_ranges(info.key.cpus_mask, cpus, sizeof(cpus));
				mask_to_ranges(info.key.mems_mask, mems, sizeof(mems));
			}
			printf("%u,%s,%d,%u,%llu,%llu,%llu,%u,%u,0x%llx,%s,%u,%s,%u\n",
			       next, policy_name(info.key.policy), info.key.nice, info.key.rtprio,
			       (unsigned long long)info.key.dl_runtime,
			       (unsigned long long)info.key.dl_deadline,
			       (unsigned long long)info.key.dl_period,
			       info.key.uclamp_min, info.key.uclamp_max,
			       (unsigned long long)info.key.cgroup_id,
			       cpus, info.key.cpus_weight, mems, info.key.mems_weight);
		}
		key = next;
	}

	printf("\nparamset_stats_csv\n");
	printf("paramset_id,pids,p50_sched_latency_ns,avg_sched_latency_ns,p95_sched_latency_ns,p99_sched_latency_ns,"
	       "p50_oncpu_ns,avg_oncpu_ns,p95_oncpu_ns,p99_oncpu_ns,nr_sched_periods\n");
	key = next = 0;
	while ((err = bpf_map_get_next_key(stats_fd, &key, &next)) == 0) {
		struct schedscore_paramset_stats st;
		if (bpf_map_lookup_elem(stats_fd, &next, &st) == 0) {
			double p50=0,p95=0,p99=0,avg_lat=0,avg_on=0;
			compute_metrics(st.lat_hist, st.wake_lat_sum_ns, st.wake_lat_cnt,
					st.runtime_ns, st.nr_periods,
					&p50, &p95, &p99, &avg_lat, &avg_on);
			double p50_on=0,p95_on=0,p99_on=0;
			compute_oncpu_quantiles(st.on_hist, &p50_on, &p95_on, &p99_on);
			/* count pids bound to this set id */
			unsigned int cnt = 0;
			__u32 k = 0, n = 0, id = 0; int er2;
			while ((er2 = bpf_map_get_next_key(pid2set_fd, &k, &n)) == 0) {
				if (bpf_map_lookup_elem(pid2set_fd, &n, &id) == 0 && id == next)
					cnt++;
				k = n;
			}
			printf("%u,%u,%.0f,%.0f,%.0f,%.0f,%.0f,%.0f,%.0f,%.0f,%u\n",
			       next, cnt,
			       p50, avg_lat, p95, p99,
			       p50_on, avg_on, p95_on, p99_on,
			       st.nr_periods);
		}
		key = next;
	}
}

void dump_migrations_csv(struct schedscore_bpf *skel, bool show_migration_matrix)
{
	int stats_fd = bpf_map__fd(skel->maps.stats_by_paramset);
	int pid_fd   = bpf_map__fd(skel->maps.stats);
	__u32 key = 0, next = 0;
	int err;

	/* Summary by paramset */
	printf("\nmigrations_summary_csv\n");
	printf("paramset_id,migr_total,migr_wakeup,migr_lb,migr_numa,migr_loc_core,migr_loc_llc,migr_loc_xllc\n");
	key = next = 0;
	while ((err = bpf_map_get_next_key(stats_fd, &key, &next)) == 0) {
		struct schedscore_paramset_stats st;
		if (bpf_map_lookup_elem(stats_fd, &next, &st) == 0) {
			unsigned long long r_w = 0, r_lb = 0, r_n = 0, l_c = 0, l_l = 0, l_x = 0, total = 0;
			r_w  = st.migr_grid[SC_MR_WAKEUP][SC_ML_CORE] + st.migr_grid[SC_MR_WAKEUP][SC_ML_LLC] + st.migr_grid[SC_MR_WAKEUP][SC_ML_XLLC];
			r_lb = st.migr_grid[SC_MR_LB][SC_ML_CORE]     + st.migr_grid[SC_MR_LB][SC_ML_LLC]     + st.migr_grid[SC_MR_LB][SC_ML_XLLC];
			r_n  = st.migr_grid[SC_MR_NUMA][SC_ML_CORE]   + st.migr_grid[SC_MR_NUMA][SC_ML_LLC]   + st.migr_grid[SC_MR_NUMA][SC_ML_XLLC];
			l_c  = st.migr_grid[SC_MR_WAKEUP][SC_ML_CORE] + st.migr_grid[SC_MR_LB][SC_ML_CORE] + st.migr_grid[SC_MR_NUMA][SC_ML_CORE];
			l_l  = st.migr_grid[SC_MR_WAKEUP][SC_ML_LLC]  + st.migr_grid[SC_MR_LB][SC_ML_LLC]  + st.migr_grid[SC_MR_NUMA][SC_ML_LLC];
			l_x  = st.migr_grid[SC_MR_WAKEUP][SC_ML_XLLC] + st.migr_grid[SC_MR_LB][SC_ML_XLLC] + st.migr_grid[SC_MR_NUMA][SC_ML_XLLC];
			total = r_w + r_lb + r_n;
			printf("%u,%llu,%llu,%llu,%llu,%llu,%llu,%llu\n", next, total, r_w, r_lb, r_n, l_c, l_l, l_x);
		}
		key = next;
	}

	if (!show_migration_matrix)
		return;

	/* Paramset matrix */
	printf("\nparamset_migrations_matrix_csv\n");
	printf("paramset_id,wk/smt,wk/l2,wk/llc,wk/xllc,wk/xnuma,lb/smt,lb/l2,lb/llc,lb/xllc,lb/xnuma,numa/smt,numa/l2,numa/llc,numa/xllc,numa/xnuma\n");
	key = next = 0;
	while ((err = bpf_map_get_next_key(stats_fd, &key, &next)) == 0) {
		struct schedscore_paramset_stats st;
		if (bpf_map_lookup_elem(stats_fd, &next, &st) == 0) {
			printf("%u,", next);
			printf("%llu,%llu,%llu,%llu,%llu,",
				st.migr_grid[SC_MR_WAKEUP][SC_ML_CORE], st.migr_grid[SC_MR_WAKEUP][SC_ML_L2], st.migr_grid[SC_MR_WAKEUP][SC_ML_LLC], st.migr_grid[SC_MR_WAKEUP][SC_ML_XLLC], st.migr_grid[SC_MR_WAKEUP][SC_ML_XNUMA]);
			printf("%llu,%llu,%llu,%llu,%llu,",
				st.migr_grid[SC_MR_LB][SC_ML_CORE], st.migr_grid[SC_MR_LB][SC_ML_L2], st.migr_grid[SC_MR_LB][SC_ML_LLC], st.migr_grid[SC_MR_LB][SC_ML_XLLC], st.migr_grid[SC_MR_LB][SC_ML_XNUMA]);
			printf("%llu,%llu,%llu,%llu,%llu\n",
				st.migr_grid[SC_MR_NUMA][SC_ML_CORE], st.migr_grid[SC_MR_NUMA][SC_ML_L2], st.migr_grid[SC_MR_NUMA][SC_ML_LLC], st.migr_grid[SC_MR_NUMA][SC_ML_XLLC], st.migr_grid[SC_MR_NUMA][SC_ML_XNUMA]);
		}
		key = next;
	}

	/* Per-PID matrix */
	printf("\npid_migrations_matrix_csv\n");
	printf("pid,wk/smt,wk/l2,wk/llc,wk/xllc,wk/xnuma,lb/smt,lb/l2,lb/llc,lb/xllc,lb/xnuma,numa/smt,numa/l2,numa/llc,numa/xllc,numa/xnuma\n");
	key = next = 0;
	while ((err = bpf_map_get_next_key(pid_fd, &key, &next)) == 0) {
		struct schedscore_pid_stats val;
		if (bpf_map_lookup_elem(pid_fd, &next, &val) == 0) {
			printf("%u,", next);
			printf("%llu,%llu,%llu,%llu,%llu,",
				val.migr_grid[SC_MR_WAKEUP][SC_ML_CORE], val.migr_grid[SC_MR_WAKEUP][SC_ML_L2], val.migr_grid[SC_MR_WAKEUP][SC_ML_LLC], val.migr_grid[SC_MR_WAKEUP][SC_ML_XLLC], val.migr_grid[SC_MR_WAKEUP][SC_ML_XNUMA]);
			printf("%llu,%llu,%llu,%llu,%llu,",
				val.migr_grid[SC_MR_LB][SC_ML_CORE], val.migr_grid[SC_MR_LB][SC_ML_L2], val.migr_grid[SC_MR_LB][SC_ML_LLC], val.migr_grid[SC_MR_LB][SC_ML_XLLC], val.migr_grid[SC_MR_LB][SC_ML_XNUMA]);
			printf("%llu,%llu,%llu,%llu,%llu\n",
				val.migr_grid[SC_MR_NUMA][SC_ML_CORE], val.migr_grid[SC_MR_NUMA][SC_ML_L2], val.migr_grid[SC_MR_NUMA][SC_ML_LLC], val.migr_grid[SC_MR_NUMA][SC_ML_XLLC], val.migr_grid[SC_MR_NUMA][SC_ML_XNUMA]);
		}
		key = next;
	}
}

