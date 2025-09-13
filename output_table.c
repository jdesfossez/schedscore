// SPDX-License-Identifier: GPL-2.0-only
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "schedscore.skel.h"
#include "schedscore_hist.h"
#include "schedscore_uapi.h"
#include "output_table.h"
#include "emit_helpers.h"

const char *col_name[COL__COUNT] = {
	[COL_PID] = "pid",
	[COL_COMM] = "comm",
	[COL_PARAMSET_ID] = "paramset_id",
	[COL_P50_LAT] = "p50_sched_latency_ns",
	[COL_AVG_LAT] = "avg_sched_latency_ns",
	[COL_P95_LAT] = "p95_sched_latency_ns",
	[COL_P99_LAT] = "p99_sched_latency_ns",
	[COL_P50_ON] = "p50_oncpu_ns",
	[COL_AVG_ON] = "avg_oncpu_ns",
	[COL_P95_ON] = "p95_oncpu_ns",
	[COL_P99_ON] = "p99_oncpu_ns",
	[COL_NR_PERIODS] = "nr_slices",
};


#include <unistd.h>

/* Now using shared helpers from emit_helpers.c */



void compute_pid_table_widths(struct schedscore_bpf *skel, const struct col_set *cs, int *widths)
{
	int fd = bpf_map__fd(skel->maps.stats);
	__u32 key = 0, next = 0; int err;
	struct schedscore_pid_stats val;
	char buf[64];
	for (int i = 0; i < cs->cnt; i++) {
		/* Initialize widths to header label length for id group only; others from data. */
		int id = cs->idx[i];
		if (id == COL_PID || id == COL_COMM || id == COL_PARAMSET_ID)
			widths[i] = (int)strlen(col_name[id]);
		else
			widths[i] = 0;
	}
	while ((err = bpf_map_get_next_key(fd, &key, &next)) == 0) {
		if (bpf_map_lookup_elem(fd, &next, &val) == 0) {
			double p50 = 0, p95 = 0, p99 = 0, avg_lat = 0, avg_on = 0;
			compute_metrics(val.lat_hist, val.wake_lat_sum_ns, val.wake_lat_cnt,
					val.runtime_ns, val.nr_periods,
					&p50, &p95, &p99, &avg_lat, &avg_on);
			double p50_on = 0, p95_on = 0, p99_on = 0;
			compute_oncpu_quantiles(val.on_hist, &p50_on, &p95_on, &p99_on);
			for (int i = 0; i < cs->cnt; i++) {
				int id = cs->idx[i];
				int l = 0;
				switch (id) {
				case COL_PID: snprintf(buf, sizeof buf, "%u", next); l = strlen(buf); break;
				case COL_COMM: l = TASK_COMM_LEN; break;
				case COL_PARAMSET_ID: snprintf(buf, sizeof buf, "%u", val.last_paramset_id); l = strlen(buf); break;
				case COL_P50_LAT: snprintf(buf, sizeof buf, "%.0f", p50); l = strlen(buf); break;
				case COL_AVG_LAT: snprintf(buf, sizeof buf, "%.0f", avg_lat); l = strlen(buf); break;
				case COL_P95_LAT: snprintf(buf, sizeof buf, "%.0f", p95); l = strlen(buf); break;
				case COL_P99_LAT: snprintf(buf, sizeof buf, "%.0f", p99); l = strlen(buf); break;
				case COL_P50_ON: snprintf(buf, sizeof buf, "%.0f", p50_on); l = strlen(buf); break;
				case COL_AVG_ON: snprintf(buf, sizeof buf, "%.0f", avg_on); l = strlen(buf); break;
				case COL_P95_ON: snprintf(buf, sizeof buf, "%.0f", p95_on); l = strlen(buf); break;
				case COL_P99_ON: snprintf(buf, sizeof buf, "%.0f", p99_on); l = strlen(buf); break;
				case COL_NR_PERIODS: snprintf(buf, sizeof buf, "%u", val.nr_periods); l = strlen(buf); break;
				default: l = 0; break;
				}
				if (l > widths[i])
					widths[i] = l;
			}
		}
		key = next;
	}
	/* After measuring data widths, cap some minimums and ensure group labels fit */

	for (int i=0;i<cs->cnt;i++) {
		int id = cs->idx[i];
		int minw = 6;
		if (id == COL_COMM) minw = 16; /* match per-PID matrix comm width */
		if (id == COL_NR_PERIODS) {
			int ns = (int)strlen("nr_slices");
			if (minw < ns) minw = ns;
		}
		if (widths[i] < minw) widths[i] = minw;
	}
}

void print_table_header_w(const struct col_set *cs, const int *widths)
{
	/* Two-line grouped header with pipes to compact output */
	/* Determine groups: id (pid,comm,paramset_id), lat, oncpu, periods */
	int group_of[32];
	const char *gname[4] = { "id", "sched_latency_ns", "oncpu_ns", "periods" };
	for (int i=0;i<cs->cnt;i++) {
		int id = cs->idx[i]; int g = 0;
		switch (id) {
			case COL_PID: case COL_COMM: case COL_PARAMSET_ID: g = 0; break;
			case COL_P50_LAT: case COL_AVG_LAT: case COL_P95_LAT: case COL_P99_LAT: g = 1; break;
			case COL_P50_ON: case COL_AVG_ON: case COL_P95_ON: case COL_P99_ON: g = 2; break;
			case COL_NR_PERIODS: g = 3; break;
			default: g = 0; break;
		}
		group_of[i] = g;
	}
	/* Compute group spans */

	int first_idx[32], groups=0;
	for (int i=0;i<cs->cnt;) {
		int g = group_of[i];
		first_idx[groups] = i;
		int j=i;
		while (j<cs->cnt && group_of[j]==g) { j++; }
		groups++;
		i = j;
	}
	/* Top line: group labels; sum inner widths plus inter-column spaces */

	for (int gi=0; gi<groups; gi++) {
		int start = first_idx[gi];
		int end = (gi+1<groups) ? first_idx[gi+1] : cs->cnt;
		int inner = 0;
		for (int k=start; k<end; k++) inner += widths[k];
		int spaces = (end-start>0) ? (end-start-1) : 0;
		int block = inner + spaces;
		const char *name = gname[group_of[first_idx[gi]]];
		if (gi==0) printf("%-*s", block, name);
		else printf(" | %-*s", block, name);
	}
	printf("\n");
	/* Bottom line: compact column labels */

	for (int i=0;i<cs->cnt;i++) {
		if (i>0 && group_of[i]!=group_of[i-1]) printf(" | ");
		int id = cs->idx[i]; int w = widths[i];
		const char *lbl = col_name[id];
		if (id==COL_P50_LAT || id==COL_P50_ON) lbl = "p50";
		else if (id==COL_AVG_LAT || id==COL_AVG_ON) lbl = "avg";
		else if (id==COL_P95_LAT || id==COL_P95_ON) lbl = "p95";
		else if (id==COL_P99_LAT || id==COL_P99_ON) lbl = "p99";
		printf("%-*s", w, lbl);
		if (i+1<cs->cnt && group_of[i+1]==group_of[i]) printf(" ");
	}
	printf("\n");
}

void print_table_row_w(const struct col_set *cs, const int *widths, __u32 pid, const struct schedscore_pid_stats *val,
	     double p50,double avg_lat,double p95,double p99,
	     double p50_on,double avg_on,double p95_on,double p99_on)
{
	int group_of[32];
	for (int i=0;i<cs->cnt;i++) {
		int id = cs->idx[i]; int g = 0;
		switch (id) {
		case COL_PID: case COL_COMM: case COL_PARAMSET_ID: g = 0; break;
		case COL_P50_LAT: case COL_AVG_LAT: case COL_P95_LAT: case COL_P99_LAT: g = 1; break;
		case COL_P50_ON: case COL_AVG_ON: case COL_P95_ON: case COL_P99_ON: g = 2; break;
		case COL_NR_PERIODS: g = 3; break;
		default: g = 0; break;
		}
		group_of[i] = g;
	}
	for (int i=0;i<cs->cnt;i++) {
		int id = cs->idx[i]; int w = widths[i];
		switch (id) {
		case COL_PID: printf("%*u", w, pid); break;
		case COL_COMM: printf("%-*.*s", w, TASK_COMM_LEN, val->comm); break;
		case COL_PARAMSET_ID: printf("%*u", w, val->last_paramset_id); break;
		case COL_P50_LAT: printf("%*.0f", w, p50); break;
		case COL_AVG_LAT: printf("%*.0f", w, avg_lat); break;
		case COL_P95_LAT: printf("%*.0f", w, p95); break;
		case COL_P99_LAT: printf("%*.0f", w, p99); break;
		case COL_P50_ON: printf("%*.0f", w, p50_on); break;
		case COL_AVG_ON: printf("%*.0f", w, avg_on); break;
		case COL_P95_ON: printf("%*.0f", w, p95_on); break;
		case COL_P99_ON: printf("%*.0f", w, p99_on); break;
		case COL_NR_PERIODS: printf("%*u", w, val->nr_periods); break;
		default: break;
		}
		if (i+1 < cs->cnt) {
			if (group_of[i+1] == group_of[i])
				printf(" ");
			else
				printf(" | ");
		} else {
			printf("\n");
		}
	}
}

void dump_paramset_map_table(struct schedscore_bpf *skel, bool resolve_masks)
{
	int info_fd = bpf_map__fd(skel->maps.paramset_info);
	__u32 key=0,next=0; int err;
	char cpus[512], mems[512];
	printf("\nparamset_map_table\n");
	printf("%-12s %-12s %5s %6s %14s %14s %14s %10s %10s %-14s %-24s %5s %-24s %5s\n",
		"paramset_id","policy","nice","rtprio","dl_runtime_ns","dl_deadline_ns","dl_period_ns",
		"uclamp_min","uclamp_max","cgroup_id","cpus_ranges","pop","mems_ranges","pop");
	key = next = 0;
	while ((err = bpf_map_get_next_key(info_fd, &key, &next)) == 0) {
		struct schedscore_paramset_info info;
		if (bpf_map_lookup_elem(info_fd, &next, &info) == 0) {
			cpus[0]=mems[0]='\0';
			if (resolve_masks) {
				mask_to_ranges(info.key.cpus_mask, cpus, sizeof(cpus));
				mask_to_ranges(info.key.mems_mask, mems, sizeof(mems));
			}
			printf("%-12u %-12s %5d %6u %14llu %14llu %14llu %10u %10u 0x%012llx %-24s %5u %-24s %5u\n",
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
}

void dump_paramset_stats_table(struct schedscore_bpf *skel)
{
	int stats_fd = bpf_map__fd(skel->maps.stats_by_paramset);
	int pid2set_fd = bpf_map__fd(skel->maps.pid_to_paramset);
	__u32 key=0,next=0; int err;
	int widths[11] = {0};
	char buf[64];

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
			unsigned int cnt = count_pids_for_paramset(pid2set_fd, next);
			int l;
			snprintf(buf,sizeof buf, "%u", next); l=strlen(buf); if (l>widths[0]) widths[0]=l;
			snprintf(buf,sizeof buf, "%u", cnt);  l=strlen(buf); if (l>widths[1]) widths[1]=l;
			snprintf(buf,sizeof buf, "%.0f", p50); l=strlen(buf); if (l>widths[2]) widths[2]=l;
			snprintf(buf,sizeof buf, "%.0f", avg_lat); l=strlen(buf); if (l>widths[3]) widths[3]=l;
			snprintf(buf,sizeof buf, "%.0f", p95); l=strlen(buf); if (l>widths[4]) widths[4]=l;
			snprintf(buf,sizeof buf, "%.0f", p99); l=strlen(buf); if (l>widths[5]) widths[5]=l;
			snprintf(buf,sizeof buf, "%.0f", p50_on); l=strlen(buf); if (l>widths[6]) widths[6]=l;
			snprintf(buf,sizeof buf, "%.0f", avg_on);  l=strlen(buf); if (l>widths[7]) widths[7]=l;
			snprintf(buf,sizeof buf, "%.0f", p95_on); l=strlen(buf); if (l>widths[8]) widths[8]=l;
			snprintf(buf,sizeof buf, "%.0f", p99_on); l=strlen(buf); if (l>widths[9]) widths[9]=l;
			snprintf(buf,sizeof buf, "%u", st.nr_periods); l=strlen(buf); if (l>widths[10]) widths[10]=l;
		}
		key = next;
	}
	int min_id0 = (int)strlen("paramset_id"); if (widths[0] < min_id0) widths[0] = min_id0;
	int min_id1 = (int)strlen("pids");        if (widths[1] < min_id1) widths[1] = min_id1;
	for (int i=2;i<=10;i++) if (widths[i] < 4) widths[i] = 4;

	printf("\nparamset_stats_table\n");
	int group_start[4] = {0, 2, 6, 10};
	int group_end[4]   = {2, 6, 10, 11};
	const char *gname[4] = { "id", "sched_latency_ns", "oncpu_ns", "periods" };
	for (int gi=0; gi<4; gi++) {
		int start = group_start[gi], end = group_end[gi];
		int inner = 0;
		for (int k=start; k<end; k++) inner += widths[k];
		int spaces = (end-start>0) ? (end-start-1) : 0;
		int block = inner + spaces;
		if (gi==0) printf("%-*s", block, gname[gi]);
		else printf(" | %-*s", block, gname[gi]);
	}
	printf("\n");
	const char *lbls[11] = { "paramset_id", "pids", "p50", "avg", "p95", "p99",
			       "p50", "avg", "p95", "p99", "nr_slices" };
	for (int i=0;i<11;i++) {
		if (i==group_start[1] || i==group_start[2] || i==group_start[3]) printf(" | ");
		printf("%-*s", widths[i], lbls[i]);
		if (!(i==group_end[0]-1 || i==group_end[1]-1 || i==group_end[2]-1 || i==group_end[3]-1)) printf(" ");
	}
	printf("\n");

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
			unsigned int cnt = count_pids_for_paramset(pid2set_fd, next);
			for (int i=0;i<11;i++) {
				if (i==group_start[1] || i==group_start[2] || i==group_start[3]) printf(" | ");
				switch (i) {
				case 0: printf("%*u", widths[i], next); break;
				case 1: printf("%*u", widths[i], cnt); break;
				case 2: printf("%*.0f", widths[i], p50); break;
				case 3: printf("%*.0f", widths[i], avg_lat); break;
				case 4: printf("%*.0f", widths[i], p95); break;
				case 5: printf("%*.0f", widths[i], p99); break;
				case 6: printf("%*.0f", widths[i], p50_on); break;
				case 7: printf("%*.0f", widths[i], avg_on); break;
				case 8: printf("%*.0f", widths[i], p95_on); break;
				case 9: printf("%*.0f", widths[i], p99_on); break;
				case 10: printf("%*u", widths[i], st.nr_periods); break;
				}
				if (!(i==group_end[0]-1 || i==group_end[1]-1 || i==group_end[2]-1 || i==group_end[3]-1)) printf(" ");
			}
			printf("\n");
		}
		key = next;
	}
}


void dump_paramset_migrations_matrix_table(struct schedscore_bpf *skel)
{
	printf("\nparamset_migrations_matrix_table\n");
	int loc_block = 4+1+4+1+4+1+4+1+5;
	printf("%-12s | %-*s | %-*s | %-*s\n", "paramset_id", loc_block, "wakeup", loc_block, "loadbalance", loc_block, "numa");
	printf("%-12s | %-4s %-4s %-4s %-4s %-5s | %-4s %-4s %-4s %-4s %-5s | %-4s %-4s %-4s %-4s %-5s\n",
		"", "smt","l2","llc","xllc","xnuma",  "smt","l2","llc","xllc","xnuma",  "smt","l2","llc","xllc","xnuma");
	int stats_fd = bpf_map__fd(skel->maps.stats_by_paramset);
	__u32 k=0,n=0; int err2;
	while ((err2 = bpf_map_get_next_key(stats_fd, &k, &n)) == 0) {
		struct schedscore_paramset_stats st;
		if (bpf_map_lookup_elem(stats_fd, &n, &st) == 0) {
			printf("%-12u | %4llu %4llu %4llu %4llu %5llu | %4llu %4llu %4llu %4llu %5llu | %4llu %4llu %4llu %4llu %5llu\n",
				n,
				st.migr_grid[SC_MR_WAKEUP][SC_ML_CORE], st.migr_grid[SC_MR_WAKEUP][SC_ML_L2],   st.migr_grid[SC_MR_WAKEUP][SC_ML_LLC], st.migr_grid[SC_MR_WAKEUP][SC_ML_XLLC], st.migr_grid[SC_MR_WAKEUP][SC_ML_XNUMA],
				st.migr_grid[SC_MR_LB][SC_ML_CORE],     st.migr_grid[SC_MR_LB][SC_ML_L2],     st.migr_grid[SC_MR_LB][SC_ML_LLC],     st.migr_grid[SC_MR_LB][SC_ML_XLLC],     st.migr_grid[SC_MR_LB][SC_ML_XNUMA],
				st.migr_grid[SC_MR_NUMA][SC_ML_CORE],   st.migr_grid[SC_MR_NUMA][SC_ML_L2],   st.migr_grid[SC_MR_NUMA][SC_ML_LLC],   st.migr_grid[SC_MR_NUMA][SC_ML_XLLC],   st.migr_grid[SC_MR_NUMA][SC_ML_XNUMA]);
		}
		k = n;
	}
}

void dump_pid_migrations_matrix_table(struct schedscore_bpf *skel)
{
	printf("\npid_migrations_matrix_table\n");
	int loc_block = 4+1+4+1+4+1+4+1+5;
	printf("%-8s  %-16s  | %-*s | %-*s | %-*s\n",
		"pid", "comm", loc_block, "wakeup", loc_block, "loadbalance", loc_block, "numa");
	printf("%-8s  %-16s  | %-4s %-4s %-4s %-4s %-5s | %-4s %-4s %-4s %-4s %-5s | %-4s %-4s %-4s %-4s %-5s\n",
		"", "", "smt","l2","llc","xllc","xnuma",  "smt","l2","llc","xllc","xnuma",  "smt","l2","llc","xllc","xnuma");
	int pid_fd = bpf_map__fd(skel->maps.stats);
	__u32 kpid=0,npid=0; int err;
	while ((err = bpf_map_get_next_key(pid_fd, &kpid, &npid)) == 0) {
		struct schedscore_pid_stats v;
		if (bpf_map_lookup_elem(pid_fd, &npid, &v) == 0) {
			printf("%-8u  %-16.16s  | %4llu %4llu %4llu %4llu %5llu | %4llu %4llu %4llu %4llu %5llu | %4llu %4llu %4llu %4llu %5llu\n",
				npid, v.comm,
				v.migr_grid[SC_MR_WAKEUP][SC_ML_CORE], v.migr_grid[SC_MR_WAKEUP][SC_ML_L2],   v.migr_grid[SC_MR_WAKEUP][SC_ML_LLC], v.migr_grid[SC_MR_WAKEUP][SC_ML_XLLC], v.migr_grid[SC_MR_WAKEUP][SC_ML_XNUMA],
				v.migr_grid[SC_MR_LB][SC_ML_CORE],     v.migr_grid[SC_MR_LB][SC_ML_L2],     v.migr_grid[SC_MR_LB][SC_ML_LLC],     v.migr_grid[SC_MR_LB][SC_ML_XLLC],     v.migr_grid[SC_MR_LB][SC_ML_XNUMA],
				v.migr_grid[SC_MR_NUMA][SC_ML_CORE],   v.migr_grid[SC_MR_NUMA][SC_ML_L2],   v.migr_grid[SC_MR_NUMA][SC_ML_LLC],   v.migr_grid[SC_MR_NUMA][SC_ML_XLLC],   v.migr_grid[SC_MR_NUMA][SC_ML_XNUMA]);
		}
		kpid = npid;
	}
}

void dump_migrations_summary_table(struct schedscore_bpf *skel)
{
	int stats_fd = bpf_map__fd(skel->maps.stats_by_paramset);
	__u32 key=0,next=0; int err;
	printf("\nmigrations_summary_table\n");
	int w_id=0, w_tot=0, w_rw=0, w_lb=0, w_n=0, w_smt=0, w_l2=0, w_llc=0, w_xllc=0, w_xnuma=0; char buf[64];
	key = next = 0;
	while ((err = bpf_map_get_next_key(stats_fd, &key, &next)) == 0) {
		struct schedscore_paramset_stats st;
		if (bpf_map_lookup_elem(stats_fd, &next, &st) == 0) {
			unsigned long long r_w=0,r_lb=0,r_n=0,l_smt=0,l2=0,l_llc=0,l_xllc=0,l_xnuma=0;
			r_w  = st.migr_grid[SC_MR_WAKEUP][SC_ML_CORE] + st.migr_grid[SC_MR_WAKEUP][SC_ML_L2] + st.migr_grid[SC_MR_WAKEUP][SC_ML_LLC] + st.migr_grid[SC_MR_WAKEUP][SC_ML_XLLC] + st.migr_grid[SC_MR_WAKEUP][SC_ML_XNUMA];
			r_lb = st.migr_grid[SC_MR_LB][SC_ML_CORE]     + st.migr_grid[SC_MR_LB][SC_ML_L2]     + st.migr_grid[SC_MR_LB][SC_ML_LLC]     + st.migr_grid[SC_MR_LB][SC_ML_XLLC]     + st.migr_grid[SC_MR_LB][SC_ML_XNUMA];
			r_n  = st.migr_grid[SC_MR_NUMA][SC_ML_CORE]   + st.migr_grid[SC_MR_NUMA][SC_ML_L2]   + st.migr_grid[SC_MR_NUMA][SC_ML_LLC]   + st.migr_grid[SC_MR_NUMA][SC_ML_XLLC]   + st.migr_grid[SC_MR_NUMA][SC_ML_XNUMA];
			l_smt  = st.migr_grid[SC_MR_WAKEUP][SC_ML_CORE] + st.migr_grid[SC_MR_LB][SC_ML_CORE] + st.migr_grid[SC_MR_NUMA][SC_ML_CORE];
			l2     = st.migr_grid[SC_MR_WAKEUP][SC_ML_L2]   + st.migr_grid[SC_MR_LB][SC_ML_L2]   + st.migr_grid[SC_MR_NUMA][SC_ML_L2];
			l_llc  = st.migr_grid[SC_MR_WAKEUP][SC_ML_LLC]  + st.migr_grid[SC_MR_LB][SC_ML_LLC]  + st.migr_grid[SC_MR_NUMA][SC_ML_LLC];
			l_xllc = st.migr_grid[SC_MR_WAKEUP][SC_ML_XLLC] + st.migr_grid[SC_MR_LB][SC_ML_XLLC] + st.migr_grid[SC_MR_NUMA][SC_ML_XLLC];
			l_xnuma= st.migr_grid[SC_MR_WAKEUP][SC_ML_XNUMA]+ st.migr_grid[SC_MR_LB][SC_ML_XNUMA]+ st.migr_grid[SC_MR_NUMA][SC_ML_XNUMA];
			#define UPW(w,v) do { snprintf(buf,sizeof buf, "%llu", (unsigned long long)(v)); int L=strlen(buf); if ((w) < L) (w) = L; } while(0)
			UPW(w_id, next);
			UPW(w_tot, (r_w+r_lb+r_n)); UPW(w_rw, r_w); UPW(w_lb, r_lb); UPW(w_n, r_n);
			UPW(w_smt, l_smt); UPW(w_l2, l2); UPW(w_llc, l_llc); UPW(w_xllc, l_xllc); UPW(w_xnuma, l_xnuma);
			#undef UPW
		}
		key = next;
	}
	int idw = (int)strlen("paramset_id"); if (w_id < idw) w_id = idw;
	int totw = (int)strlen("total"); if (w_tot < totw) w_tot = totw;
	int totalsw = (int)strlen("totals"); if (w_tot < totalsw) w_tot = totalsw;
	int rww = (int)strlen("wakeup"); if (w_rw < rww) w_rw = rww;
	int lbw = (int)strlen("lb");     if (w_lb < lbw) w_lb = lbw;
	int nw  = (int)strlen("numa");   if (w_n  < nw)  w_n  = nw;
	/* Ensure minimum widths for locality labels */
	int smtw = (int)strlen("smt");   if (w_smt < smtw) w_smt = smtw;
	int l2w  = (int)strlen("l2");    if (w_l2 < l2w) w_l2 = l2w;
	int llcw = (int)strlen("llc");   if (w_llc < llcw) w_llc = llcw;
	int xllcw = (int)strlen("xllc"); if (w_xllc < xllcw) w_xllc = xllcw;
	int xnumaw = (int)strlen("xnuma"); if (w_xnuma < xnumaw) w_xnuma = xnumaw;
	int locw = 5; /* width for empty columns in by_reason section */
	int loc_block = w_smt+1+w_l2+1+w_llc+1+w_xllc+1+w_xnuma;
	int reason_block = w_rw+1+w_lb+1+w_n+1+locw+1+locw;
	printf("%-*s | %-*s | %-*s | %-*s\n",
		w_id, "id", w_tot, "totals", reason_block, "by_reason", loc_block, "by_locality");
	printf("%-*s | %-*s | %-*s %-*s %-*s %-*s %-*s | %-*s %-*s %-*s %-*s %-*s\n",
		w_id, "paramset_id",
		w_tot, "total",
		w_rw, "wakeup", w_lb, "lb", w_n, "numa", locw, "", locw, "",
		w_smt, "smt", w_l2, "l2", w_llc, "llc", w_xllc, "xllc", w_xnuma, "xnuma");
	key = next = 0;
	while ((err = bpf_map_get_next_key(stats_fd, &key, &next)) == 0) {
		struct schedscore_paramset_stats st;
		if (bpf_map_lookup_elem(stats_fd, &next, &st) == 0) {
			unsigned long long r_w=0,r_lb=0,r_n=0,l_smt=0,l2=0,l_llc=0,l_xllc=0,l_xnuma=0;
			r_w  = st.migr_grid[SC_MR_WAKEUP][SC_ML_CORE] + st.migr_grid[SC_MR_WAKEUP][SC_ML_L2] + st.migr_grid[SC_MR_WAKEUP][SC_ML_LLC] + st.migr_grid[SC_MR_WAKEUP][SC_ML_XLLC] + st.migr_grid[SC_MR_WAKEUP][SC_ML_XNUMA];
			r_lb = st.migr_grid[SC_MR_LB][SC_ML_CORE]     + st.migr_grid[SC_MR_LB][SC_ML_L2]     + st.migr_grid[SC_MR_LB][SC_ML_LLC]     + st.migr_grid[SC_MR_LB][SC_ML_XLLC]     + st.migr_grid[SC_MR_LB][SC_ML_XNUMA];
			r_n  = st.migr_grid[SC_MR_NUMA][SC_ML_CORE]   + st.migr_grid[SC_MR_NUMA][SC_ML_L2]   + st.migr_grid[SC_MR_NUMA][SC_ML_LLC]   + st.migr_grid[SC_MR_NUMA][SC_ML_XLLC]   + st.migr_grid[SC_MR_NUMA][SC_ML_XNUMA];
			l_smt  = st.migr_grid[SC_MR_WAKEUP][SC_ML_CORE] + st.migr_grid[SC_MR_LB][SC_ML_CORE] + st.migr_grid[SC_MR_NUMA][SC_ML_CORE];
			l2     = st.migr_grid[SC_MR_WAKEUP][SC_ML_L2]   + st.migr_grid[SC_MR_LB][SC_ML_L2]   + st.migr_grid[SC_MR_NUMA][SC_ML_L2];
			l_llc  = st.migr_grid[SC_MR_WAKEUP][SC_ML_LLC]  + st.migr_grid[SC_MR_LB][SC_ML_LLC]  + st.migr_grid[SC_MR_NUMA][SC_ML_LLC];
			l_xllc = st.migr_grid[SC_MR_WAKEUP][SC_ML_XLLC] + st.migr_grid[SC_MR_LB][SC_ML_XLLC] + st.migr_grid[SC_MR_NUMA][SC_ML_XLLC];
			l_xnuma= st.migr_grid[SC_MR_WAKEUP][SC_ML_XNUMA]+ st.migr_grid[SC_MR_LB][SC_ML_XNUMA]+ st.migr_grid[SC_MR_NUMA][SC_ML_XNUMA];
			printf("%-*u | %-*llu | %-*llu %-*llu %-*llu %*s %*s | %-*llu %-*llu %-*llu %-*llu %-*llu\n",
				w_id, next,
				w_tot, (r_w+r_lb+r_n),
				w_rw, r_w, w_lb, r_lb, w_n, r_n, locw, "", locw, "",
				w_smt, l_smt, w_l2, l2, w_llc, l_llc, w_xllc, l_xllc, w_xnuma, l_xnuma);
		}
		key = next;
	}
}

