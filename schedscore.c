// SPDX-License-Identifier: GPL-2.0-only
/*
 * schedscore userspace driver (tools/schedscore/)
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <pwd.h>
#include <grp.h>
#include <limits.h>
#include <dirent.h>
#include <fcntl.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>                 /* <-- syscall wrappers: bpf_map_* */
#include "schedscore.skel.h"     /* skeleton */
#include "schedscore_hist.h"      /* shared histogram defines */
#include "schedscore_uapi.h"      /* shared structs for maps */


// Keep in sync with BPF side
#define TASK_COMM_LEN 16

static volatile sig_atomic_t exiting;

/* Cached settings passed from parent to child */
static const char *g_env_file = NULL;
static const char *g_run_as_user = NULL;
static int g_saved_stdout = -1, g_saved_stderr = -1;


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
	/* env injection file for target */
	char *env_file;

	/* optional output file (default stdout) */
	char *out_path;
	/* optional output directory */
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

	bool show_migration_matrix;     /* table mode: show reason×locality grid tables */
	bool show_pid_migration_matrix; /* table mode: per-PID migration matrix */
	bool dump_topology;             /* print detected cpu->(core,l2,llc,numa) */

};

struct sidecar {
	const char *exe;
	char *args;
	pid_t pid;
};

static void sig_handler(int signo)
{
	(void) signo;
	exiting = 1;
}
static int cpu_in_cpulist(const char *s, int cpu);
static int detect_numa_id(int cpu, unsigned int *numa_id);


static void usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s [--duration SEC] [--pid PID] [--comm NAME]\n"
		"          [--cgroup PATH | --cgroupid ID]\n"
		"          [--latency-warn-us N] [--warn-enable]\n"
		"          [--perf] [--ftrace] [--perf-args 'ARGS'] [--ftrace-args 'ARGS']\n"
		"          [-f]  # follow children like strace\n"
		"          [-u USER]  # run target command as user/uid\n"
		"          [--env-file FILE]  # file with KEY=VALUE lines to add to target env\n"
		"          [-o FILE]         # write all output to FILE (not stdout)\n"
		"          [--out-dir DIR]   # write multiple outputs under DIR\n"
			"          [--show-migration-matrix]  # add paramset/pid migration matrices\n"
		"          [--format csv|json|table]  # output format (default: table)\n"
			"          [--dump-topology]         # print cpu->(smt,l2,llc,numa) map and exit\n"


		"          [--columns COL1,COL2,...]  # select/reorder columns\n"
		"          [--show-hist-config]\n",
		prog);
}
/* Column selection and formatting helpers */
enum col_id {
	COL_PID,
	COL_COMM,
	COL_PARAMSET_ID,
	COL_P50_LAT,
	COL_AVG_LAT,
	COL_P95_LAT,
	COL_P99_LAT,
	COL_P50_ON,
	COL_AVG_ON,
	COL_P95_ON,
	COL_P99_ON,
	COL_NR_PERIODS,
	COL__COUNT
};

static void dump_topology_table(struct schedscore_bpf *skel)
{
	int core_fd = bpf_map__fd(skel->maps.cpu_core_id);
	int l2_fd   = bpf_map__fd(skel->maps.cpu_l2_id);
	int llc_fd  = bpf_map__fd(skel->maps.cpu_llc_id);
	int numa_fd = bpf_map__fd(skel->maps.cpu_numa_id);
	long nproc = sysconf(_SC_NPROCESSORS_CONF);
	if (nproc <= 0 || nproc > 4096) nproc = 4096;
	printf("\ntopology_table\n");
	/* Column widths */
	int w_cpu=4, w_id=10; /* cpu as %-4d, ids shown as 0x%08x, plus two spaces between */
	printf("%-*s  %-*s  %-*s  %-*s  %-*s\n",
		w_cpu, "cpu", w_id, "smt(core_id)", w_id, "l2_id", w_id, "llc_id", w_id, "numa_id");
	for (int cpu = 0; cpu < nproc; cpu++) {
		__u32 k = cpu; __u32 core=0,l2=0,llc=0,numa=0;
		(void)bpf_map_lookup_elem(core_fd, &k, &core);
		(void)bpf_map_lookup_elem(l2_fd,   &k, &l2);
		(void)bpf_map_lookup_elem(llc_fd,  &k, &llc);
		(void)bpf_map_lookup_elem(numa_fd, &k, &numa);
		printf("%-*d  0x%08x  0x%08x  0x%08x  0x%08x\n",
			w_cpu, cpu, core, l2, llc, numa);
	}
	/* Summary */
	printf("\ntopology_summary\n");
	__u32 seen_core[4096] = {0}, seen_l2[4096] = {0}, seen_llc[4096] = {0}, seen_numa[4096] = {0};
	__u32 cores=0,l2s=0,llcs=0,numas=0;
	for (int cpu = 0; cpu < nproc; cpu++) {
		__u32 k = cpu; __u32 core=0,l2=0,llc=0,numa=0;
		(void)bpf_map_lookup_elem(core_fd, &k, &core);
		(void)bpf_map_lookup_elem(l2_fd,   &k, &l2);
		(void)bpf_map_lookup_elem(llc_fd,  &k, &llc);
		(void)bpf_map_lookup_elem(numa_fd, &k, &numa);
		if (!seen_core[core & 0xFFF]) { seen_core[core & 0xFFF]=1; cores++; }
		if (!seen_l2[l2 & 0xFFF])     { seen_l2[l2 & 0xFFF]=1;     l2s++; }
		if (!seen_llc[llc & 0xFFF])   { seen_llc[llc & 0xFFF]=1;   llcs++; }
		if (!seen_numa[numa & 0xFFF]) { seen_numa[numa & 0xFFF]=1; numas++; }
	}
	printf("cpus=%ld smt_cores=%u l2_domains=%u llc_domains=%u numa_nodes=%u\n", nproc, cores, l2s, llcs, numas);
}

static const char *col_name[COL__COUNT] = {
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

struct col_set {
	int idx[32];
	int cnt;
};

static int parse_columns_string(const char *s, struct col_set *out)
{
	struct col_set cs = {};
	char buf[512];
	if (!s || !*s) { out->cnt = 0; return 0; }
	snprintf(buf, sizeof(buf), "%s", s);
	char *saveptr = NULL; char *tok = strtok_r(buf, ",", &saveptr);
	while (tok) {
		while (*tok == ' ' || *tok == '\t') tok++;
		int found = -1;
		for (int i = 0; i < COL__COUNT; i++) {
			if (strcmp(tok, col_name[i]) == 0) { found = i; break; }
		}
		if (found >= 0 && cs.cnt < (int)(sizeof(cs.idx)/sizeof(cs.idx[0])))
			cs.idx[cs.cnt++] = found;
		tok = strtok_r(NULL, ",", &saveptr);
	}
	*out = cs;
	return 0;
}

static void json_escape(const char *in, char *out, size_t outsz)
{
	size_t j = 0;
	for (size_t i = 0; in[i] && j + 2 < outsz; i++) {
		char c = in[i];
		if (c == '"' || c == '\\') { if (j+2 < outsz) { out[j++]='\\'; out[j++]=c; } }
		else if ((unsigned char)c < 0x20) { /* skip control chars */ }
		else { out[j++] = c; }
	}
	out[j] = '\0';
}

/* Per-pid table width computation and printing */
/* Forward decls for helpers used below */
static void compute_metrics(const __u32 *lat_hist, __u64 lat_sum, __u64 lat_cnt,
				__u64 runtime_ns, __u32 nr_periods,
				double *p50, double *p95, double *p99,
				double *avg_lat, double *avg_on);
static void compute_oncpu_quantiles(const __u32 *on_hist,
				double *p50_on, double *p95_on, double *p99_on);
static const char *policy_name(int pol);
static void mask_to_ranges(const unsigned long long m[4], char *buf, size_t bufsz);
static unsigned int count_pids_for_paramset(int pid2set_fd, __u32 set_id);

static void compute_pid_table_widths(struct schedscore_bpf *skel, const struct col_set *cs, int *widths)
{
	int fd = bpf_map__fd(skel->maps.stats);
	__u32 key=0, next=0; int err;
	struct schedscore_pid_stats val;
	char buf[64];
	for (int i=0;i<cs->cnt;i++) {
		/* Initialize widths to header label length for id group only; others from data */
		int id = cs->idx[i];
		if (id==COL_PID || id==COL_COMM || id==COL_PARAMSET_ID)
			widths[i] = (int)strlen(col_name[id]);
		else
			widths[i] = 0;
	}
	while ((err = bpf_map_get_next_key(fd, &key, &next)) == 0) {
		if (bpf_map_lookup_elem(fd, &next, &val) == 0) {
			double p50=0,p95=0,p99=0,avg_lat=0,avg_on=0;
			compute_metrics(val.lat_hist, val.wake_lat_sum_ns, val.wake_lat_cnt,
					val.runtime_ns, val.nr_periods,
					&p50, &p95, &p99, &avg_lat, &avg_on);
			double p50_on=0,p95_on=0,p99_on=0;
			compute_oncpu_quantiles(val.on_hist, &p50_on, &p95_on, &p99_on);
			for (int i=0;i<cs->cnt;i++) {
				int id = cs->idx[i]; int l=0;
				switch (id) {
				case COL_PID: snprintf(buf,sizeof buf, "%u", next); l=strlen(buf); break;
				case COL_COMM: l=TASK_COMM_LEN; break;
				case COL_PARAMSET_ID: snprintf(buf,sizeof buf, "%u", val.last_paramset_id); l=strlen(buf); break;
				case COL_P50_LAT: snprintf(buf,sizeof buf, "%.0f", p50); l=strlen(buf); break;
				case COL_AVG_LAT: snprintf(buf,sizeof buf, "%.0f", avg_lat); l=strlen(buf); break;
				case COL_P95_LAT: snprintf(buf,sizeof buf, "%.0f", p95); l=strlen(buf); break;
				case COL_P99_LAT: snprintf(buf,sizeof buf, "%.0f", p99); l=strlen(buf); break;
				case COL_P50_ON: snprintf(buf,sizeof buf, "%.0f", p50_on); l=strlen(buf); break;
				case COL_AVG_ON: snprintf(buf,sizeof buf, "%.0f", avg_on); l=strlen(buf); break;
				case COL_P95_ON: snprintf(buf,sizeof buf, "%.0f", p95_on); l=strlen(buf); break;
				case COL_P99_ON: snprintf(buf,sizeof buf, "%.0f", p99_on); l=strlen(buf); break;
				case COL_NR_PERIODS: snprintf(buf,sizeof buf, "%u", val.nr_periods); l=strlen(buf); break;
				default: l=0; break;
				}
				if (l > widths[i]) widths[i] = l;
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

static void print_table_header_w(const struct col_set *cs, const int *widths)
{
	/* Two-line grouped header with pipes to compact output */
	/* Determine groups: id (pid,comm,paramset_id), lat, oncpu, periods */
	int group_of[32];
	const char *gname[4] = { "id", "sched_latency_ns", "oncpu_ns", "periods" };
	for (int i=0;i<cs->cnt;i++) {
		int id = cs->idx[i];
		int g = 0;
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
		int spaces = (end-start>0) ? (end-start-1) : 0; /* one space between columns inside group */
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

static void print_table_row_w(const struct col_set *cs, const int *widths, __u32 pid, const struct schedscore_pid_stats *val,
			     double p50,double avg_lat,double p95,double p99,
			     double p50_on,double avg_on,double p95_on,double p99_on)
{
	/* Determine groups to align with grouped headers: id | latency | oncpu | periods */
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
				printf(" | "); /* exact group separator to match header */
		} else {
			printf("\n");
		}
	}
}

/* Paramset tables for table format */
static void dump_paramset_map_table(struct schedscore_bpf *skel, bool resolve_masks)
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

static void dump_paramset_stats_table(struct schedscore_bpf *skel)
{
	int stats_fd = bpf_map__fd(skel->maps.stats_by_paramset);
	int pid2set_fd = bpf_map__fd(skel->maps.pid_to_paramset);
	__u32 key=0,next=0; int err;
	int widths[11] = {0};
	char buf[64];

	/* First pass: compute widths from data */
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
			snprintf(buf,sizeof buf, "%u", next); l=strlen(buf); if (l>widths[0]) widths[0]=l; /* paramset_id */
			snprintf(buf,sizeof buf, "%u", cnt);  l=strlen(buf); if (l>widths[1]) widths[1]=l; /* pids */
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
	/* Minimums and ensure id headers fit */
	int min_id0 = (int)strlen("paramset_id"); if (widths[0] < min_id0) widths[0] = min_id0;
	int min_id1 = (int)strlen("pids");        if (widths[1] < min_id1) widths[1] = min_id1;
	for (int i=2;i<=10;i++) if (widths[i] < 4) widths[i] = 4; /* allow p50 etc */

	/* Header */
	printf("\nparamset_stats_table\n");
	/* Top line: group labels */
	int group_start[4] = {0, 2, 6, 10};
	int group_end[4]   = {2, 6, 10, 11}; /* end is exclusive */
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
	/* Bottom line: column labels */
	const char *lbls[11] = { "paramset_id", "pids", "p50", "avg", "p95", "p99",
			       "p50", "avg", "p95", "p99", "nr_slices" };
	for (int i=0;i<11;i++) {
		/* Pipe between groups */
		if (i==group_start[1] || i==group_start[2] || i==group_start[3]) printf(" | ");
		printf("%-*s", widths[i], lbls[i]);
		/* Space inside group */
		if (!(i==group_end[0]-1 || i==group_end[1]-1 || i==group_end[2]-1 || i==group_end[3]-1)) printf(" ");
	}
	printf("\n");

	/* Rows */
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
				/* Space inside group except last column of group */
				if (!(i==group_end[0]-1 || i==group_end[1]-1 || i==group_end[2]-1 || i==group_end[3]-1)) printf(" ");
			}
			printf("\n");
		}
		key = next;
	}
}
static void dump_migrations_summary_table(struct schedscore_bpf *skel)
{
	int stats_fd = bpf_map__fd(skel->maps.stats_by_paramset);
	__u32 key=0,next=0; int err;
	printf("\nmigrations_summary_table\n");
	/* First pass: compute widths */
	int w_id=0, w_tot=0, w_rw=0, w_lb=0, w_n=0, w_smt=0, w_l2=0, w_llc=0, w_xllc=0, w_xnuma=0; char buf[64];
	key = next = 0;
	while ((err = bpf_map_get_next_key(stats_fd, &key, &next)) == 0) {
		struct schedscore_paramset_stats st;
		if (bpf_map_lookup_elem(stats_fd, &next, &st) == 0) {
			unsigned long long r_w=0,r_lb=0,r_n=0,l_smt=0,l2=0,l_llc=0,l_xllc=0,l_xnuma=0,total=0;
			r_w  = st.migr_grid[SC_MR_WAKEUP][SC_ML_CORE] + st.migr_grid[SC_MR_WAKEUP][SC_ML_L2] + st.migr_grid[SC_MR_WAKEUP][SC_ML_LLC] + st.migr_grid[SC_MR_WAKEUP][SC_ML_XLLC] + st.migr_grid[SC_MR_WAKEUP][SC_ML_XNUMA];
			r_lb = st.migr_grid[SC_MR_LB][SC_ML_CORE]     + st.migr_grid[SC_MR_LB][SC_ML_L2]     + st.migr_grid[SC_MR_LB][SC_ML_LLC]     + st.migr_grid[SC_MR_LB][SC_ML_XLLC]     + st.migr_grid[SC_MR_LB][SC_ML_XNUMA];
			r_n  = st.migr_grid[SC_MR_NUMA][SC_ML_CORE]   + st.migr_grid[SC_MR_NUMA][SC_ML_L2]   + st.migr_grid[SC_MR_NUMA][SC_ML_LLC]   + st.migr_grid[SC_MR_NUMA][SC_ML_XLLC]   + st.migr_grid[SC_MR_NUMA][SC_ML_XNUMA];
			l_smt  = st.migr_grid[SC_MR_WAKEUP][SC_ML_CORE] + st.migr_grid[SC_MR_LB][SC_ML_CORE] + st.migr_grid[SC_MR_NUMA][SC_ML_CORE];
			l2     = st.migr_grid[SC_MR_WAKEUP][SC_ML_L2]   + st.migr_grid[SC_MR_LB][SC_ML_L2]   + st.migr_grid[SC_MR_NUMA][SC_ML_L2];
			l_llc  = st.migr_grid[SC_MR_WAKEUP][SC_ML_LLC]  + st.migr_grid[SC_MR_LB][SC_ML_LLC]  + st.migr_grid[SC_MR_NUMA][SC_ML_LLC];
			l_xllc = st.migr_grid[SC_MR_WAKEUP][SC_ML_XLLC] + st.migr_grid[SC_MR_LB][SC_ML_XLLC] + st.migr_grid[SC_MR_NUMA][SC_ML_XLLC];
			l_xnuma= st.migr_grid[SC_MR_WAKEUP][SC_ML_XNUMA]+ st.migr_grid[SC_MR_LB][SC_ML_XNUMA]+ st.migr_grid[SC_MR_NUMA][SC_ML_XNUMA];
			total = r_w + r_lb + r_n;
			snprintf(buf,sizeof buf, "%u", next); int l=strlen(buf); if (l>w_id) w_id=l;
			snprintf(buf,sizeof buf, "%llu", total); l=strlen(buf); if (l>w_tot) w_tot=l;
			snprintf(buf,sizeof buf, "%llu", r_w); l=strlen(buf); if (l>w_rw) w_rw=l;
			snprintf(buf,sizeof buf, "%llu", r_lb); l=strlen(buf); if (l>w_lb) w_lb=l;
			snprintf(buf,sizeof buf, "%llu", r_n); l=strlen(buf); if (l>w_n) w_n=l;
			snprintf(buf,sizeof buf, "%llu", l_smt); l=strlen(buf); if (l>w_smt) w_smt=l;
			snprintf(buf,sizeof buf, "%llu", l2); l=strlen(buf); if (l>w_l2) w_l2=l;
			snprintf(buf,sizeof buf, "%llu", l_llc); l=strlen(buf); if (l>w_llc) w_llc=l;
			snprintf(buf,sizeof buf, "%llu", l_xllc); l=strlen(buf); if (l>w_xllc) w_xllc=l;
			snprintf(buf,sizeof buf, "%llu", l_xnuma); l=strlen(buf); if (l>w_xnuma) w_xnuma=l;
		}
		key = next;
	}
	/* Minimums to fit labels */
	if (w_id < (int)strlen("paramset_id")) w_id = (int)strlen("paramset_id");
	if (w_tot < (int)strlen("total")) w_tot = (int)strlen("total");
	if (w_rw < (int)strlen("wakeup")) w_rw = (int)strlen("wakeup");
	if (w_lb < (int)strlen("lb")) w_lb = (int)strlen("lb");
	if (w_n < (int)strlen("numa")) w_n = (int)strlen("numa");
	if (w_smt < (int)strlen("smt")) w_smt = (int)strlen("smt");
	if (w_l2 < (int)strlen("l2")) w_l2 = (int)strlen("l2");
	if (w_llc < (int)strlen("llc")) w_llc = (int)strlen("llc");
	if (w_xllc < (int)strlen("xllc")) w_xllc = (int)strlen("xllc");
	if (w_xnuma < (int)strlen("xnuma")) w_xnuma = (int)strlen("xnuma");

	/* Top grouped header */
	int totals_block = w_tot + 1 + w_rw + 1 + w_lb + 1 + w_n;
	int reason_block = w_rw + 1 + w_lb + 1 + w_n;
	int locality_block = w_smt + 1 + w_l2 + 1 + w_llc + 1 + w_xllc + 1 + w_xnuma;
	printf("%-*s | %-*s | %-*s | %-*s\n",
		w_id, "id", totals_block, "totals", reason_block, "by_reason", locality_block, "by_locality");
	/* Bottom labels */
	printf("%-*s | %-*s %-*s %-*s %-*s | %-*s %-*s %-*s | %-*s %-*s %-*s %-*s %-*s\n",
		w_id, "paramset_id",
		w_tot, "total", w_rw, "wakeup", w_lb, "lb", w_n, "numa",
		w_rw, "wakeup", w_lb, "lb", w_n, "numa",
		w_smt, "smt", w_l2, "l2", w_llc, "llc", w_xllc, "xllc", w_xnuma, "xnuma");
	/* Rows */
	key = next = 0;
	while ((err = bpf_map_get_next_key(stats_fd, &key, &next)) == 0) {
		struct schedscore_paramset_stats st;
		if (bpf_map_lookup_elem(stats_fd, &next, &st) == 0) {
			unsigned long long r_w=0,r_lb=0,r_n=0,l_smt=0,l2=0,l_llc=0,l_xllc=0,l_xnuma=0,total=0;
			r_w  = st.migr_grid[SC_MR_WAKEUP][SC_ML_CORE] + st.migr_grid[SC_MR_WAKEUP][SC_ML_L2] + st.migr_grid[SC_MR_WAKEUP][SC_ML_LLC] + st.migr_grid[SC_MR_WAKEUP][SC_ML_XLLC] + st.migr_grid[SC_MR_WAKEUP][SC_ML_XNUMA];
			r_lb = st.migr_grid[SC_MR_LB][SC_ML_CORE]     + st.migr_grid[SC_MR_LB][SC_ML_L2]     + st.migr_grid[SC_MR_LB][SC_ML_LLC]     + st.migr_grid[SC_MR_LB][SC_ML_XLLC]     + st.migr_grid[SC_MR_LB][SC_ML_XNUMA];
			r_n  = st.migr_grid[SC_MR_NUMA][SC_ML_CORE]   + st.migr_grid[SC_MR_NUMA][SC_ML_L2]   + st.migr_grid[SC_MR_NUMA][SC_ML_LLC]   + st.migr_grid[SC_MR_NUMA][SC_ML_XLLC]   + st.migr_grid[SC_MR_NUMA][SC_ML_XNUMA];
			l_smt  = st.migr_grid[SC_MR_WAKEUP][SC_ML_CORE] + st.migr_grid[SC_MR_LB][SC_ML_CORE] + st.migr_grid[SC_MR_NUMA][SC_ML_CORE];
			l2     = st.migr_grid[SC_MR_WAKEUP][SC_ML_L2]   + st.migr_grid[SC_MR_LB][SC_ML_L2]   + st.migr_grid[SC_MR_NUMA][SC_ML_L2];
			l_llc  = st.migr_grid[SC_MR_WAKEUP][SC_ML_LLC]  + st.migr_grid[SC_MR_LB][SC_ML_LLC]  + st.migr_grid[SC_MR_NUMA][SC_ML_LLC];
			l_xllc = st.migr_grid[SC_MR_WAKEUP][SC_ML_XLLC] + st.migr_grid[SC_MR_LB][SC_ML_XLLC] + st.migr_grid[SC_MR_NUMA][SC_ML_XLLC];
			l_xnuma= st.migr_grid[SC_MR_WAKEUP][SC_ML_XNUMA]+ st.migr_grid[SC_MR_LB][SC_ML_XNUMA]+ st.migr_grid[SC_MR_NUMA][SC_ML_XNUMA];
			total = r_w + r_lb + r_n;
			printf("%-*u | %*llu %*llu %*llu %*llu | %*llu %*llu %*llu | %*llu %*llu %*llu %*llu %*llu\n",
				w_id, next,
				w_tot, total, w_rw, r_w, w_lb, r_lb, w_n, r_n,
				w_rw, r_w, w_lb, r_lb, w_n, r_n,
				w_smt, l_smt, w_l2, l2, w_llc, l_llc, w_xllc, l_xllc, w_xnuma, l_xnuma);
		}
		key = next;
	}
}
static void dump_pid_migrations_matrix_table(struct schedscore_bpf *skel)
{
	printf("\npid_migrations_matrix_table\n");
	/* Grouped header with pipes to clarify sections */
	int loc_block = 4+1+4+1+4+1+4+1+5; /* smt l2 llc xllc xnuma widths incl spaces */
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



/* JSON document */
static int dump_json(struct schedscore_bpf *skel, const struct opts *o)
{
	(void)o; /* current JSON output does not depend on opts */
	int info_fd = bpf_map__fd(skel->maps.paramset_info);
	int stats_fd = bpf_map__fd(skel->maps.stats_by_paramset);
	int pid_fd = bpf_map__fd(skel->maps.stats);
	int pid2set_fd = bpf_map__fd(skel->maps.pid_to_paramset);
	__u32 key=0,next=0; int err;
	struct schedscore_pid_stats val;
	char cpus[512], mems[512];
	printf("{\n");
	printf("  \"format\": \"json\",\n");
	/* Retain paramset_map for backward compatibility, but details are embedded per-stat */
	printf("  \"paramset_map\": [\n");
	key = next = 0; int first=1;
	while ((err = bpf_map_get_next_key(info_fd, &key, &next)) == 0) {
		struct schedscore_paramset_info info;
		if (bpf_map_lookup_elem(info_fd, &next, &info) == 0) {
			cpus[0]=mems[0]='\0';
			mask_to_ranges(info.key.cpus_mask, cpus, sizeof(cpus));
			mask_to_ranges(info.key.mems_mask, mems, sizeof(mems));
			printf("%s    {\"paramset_id\":%u,\"policy\":\"%s\",\"nice\":%d,\"rtprio\":%u,\"dl_runtime_ns\":%llu,\"dl_deadline_ns\":%llu,\"dl_period_ns\":%llu,\"uclamp_min\":%u,\"uclamp_max\":%u,\"cgroup_id\":%llu,\"cpus_ranges\":\"%s\",\"cpus_weight\":%u,\"mems_ranges\":\"%s\",\"mems_weight\":%u}\n",
				first?"":",",
				next, policy_name(info.key.policy), info.key.nice, info.key.rtprio,
				(unsigned long long)info.key.dl_runtime,
				(unsigned long long)info.key.dl_deadline,
				(unsigned long long)info.key.dl_period,
				info.key.uclamp_min, info.key.uclamp_max,
				(unsigned long long)info.key.cgroup_id,
				cpus, info.key.cpus_weight, mems, info.key.mems_weight);
			first=0;
		}
		key = next;
	}
	printf("  ],\n");
	printf("  \"paramset_stats\": [\n");
	key = next = 0; first=1;
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
			unsigned long long r_w=0,r_lb=0,r_n=0,l_smt=0,l2=0,l_llc=0,l_xllc=0,l_xnuma=0;
			r_w  = st.migr_grid[SC_MR_WAKEUP][SC_ML_CORE] + st.migr_grid[SC_MR_WAKEUP][SC_ML_L2] + st.migr_grid[SC_MR_WAKEUP][SC_ML_LLC] + st.migr_grid[SC_MR_WAKEUP][SC_ML_XLLC] + st.migr_grid[SC_MR_WAKEUP][SC_ML_XNUMA];
			r_lb = st.migr_grid[SC_MR_LB][SC_ML_CORE]     + st.migr_grid[SC_MR_LB][SC_ML_L2]     + st.migr_grid[SC_MR_LB][SC_ML_LLC]     + st.migr_grid[SC_MR_LB][SC_ML_XLLC]     + st.migr_grid[SC_MR_LB][SC_ML_XNUMA];
			r_n  = st.migr_grid[SC_MR_NUMA][SC_ML_CORE]   + st.migr_grid[SC_MR_NUMA][SC_ML_L2]   + st.migr_grid[SC_MR_NUMA][SC_ML_LLC]   + st.migr_grid[SC_MR_NUMA][SC_ML_XLLC]   + st.migr_grid[SC_MR_NUMA][SC_ML_XNUMA];
			l_smt  = st.migr_grid[SC_MR_WAKEUP][SC_ML_CORE] + st.migr_grid[SC_MR_LB][SC_ML_CORE] + st.migr_grid[SC_MR_NUMA][SC_ML_CORE];
			l2     = st.migr_grid[SC_MR_WAKEUP][SC_ML_L2]   + st.migr_grid[SC_MR_LB][SC_ML_L2]   + st.migr_grid[SC_MR_NUMA][SC_ML_L2];
			l_llc  = st.migr_grid[SC_MR_WAKEUP][SC_ML_LLC]  + st.migr_grid[SC_MR_LB][SC_ML_LLC]  + st.migr_grid[SC_MR_NUMA][SC_ML_LLC];
			l_xllc = st.migr_grid[SC_MR_WAKEUP][SC_ML_XLLC] + st.migr_grid[SC_MR_LB][SC_ML_XLLC] + st.migr_grid[SC_MR_NUMA][SC_ML_XLLC];
			l_xnuma= st.migr_grid[SC_MR_WAKEUP][SC_ML_XNUMA]+ st.migr_grid[SC_MR_LB][SC_ML_XNUMA]+ st.migr_grid[SC_MR_NUMA][SC_ML_XNUMA];
			/* Embed paramset_map details inside each paramset_stats entry */
			struct schedscore_paramset_info info;
			int have_info = (bpf_map_lookup_elem(info_fd, &next, &info) == 0);
			char cpus2[512] = "", mems2[512] = "";
			if (have_info) {
				mask_to_ranges(info.key.cpus_mask, cpus2, sizeof(cpus2));
				mask_to_ranges(info.key.mems_mask, mems2, sizeof(mems2));
			}
			printf("%s    {\"paramset_id\":%u,\"details\":{\"policy\":\"%s\",\"nice\":%d,\"rtprio\":%u,\"dl_runtime_ns\":%llu,\"dl_deadline_ns\":%llu,\"dl_period_ns\":%llu,\"uclamp_min\":%u,\"uclamp_max\":%u,\"cgroup_id\":%llu,\"cpus_ranges\":\"%s\",\"cpus_weight\":%u,\"mems_ranges\":\"%s\",\"mems_weight\":%u},\"pids\":%u,\"p50_sched_latency_ns\":%.0f,\"avg_sched_latency_ns\":%.0f,\"p95_sched_latency_ns\":%.0f,\"p99_sched_latency_ns\":%.0f,\"p50_oncpu_ns\":%.0f,\"avg_oncpu_ns\":%.0f,\"p95_oncpu_ns\":%.0f,\"p99_oncpu_ns\":%.0f,\"nr_sched_periods\":%u,\"migrations\":{\"total\":%llu},\"migrations_by_reason\":{\"wakeup\":%llu,\"lb\":%llu,\"numa\":%llu},\"migrations_by_locality\":{\"smt\":%llu,\"l2\":%llu,\"llc\":%llu,\"xllc\":%llu,\"xnuma\":%llu},\"migrations_grid\":{\"wakeup\":{\"smt\":%llu,\"l2\":%llu,\"llc\":%llu,\"xllc\":%llu,\"xnuma\":%llu},\"lb\":{\"smt\":%llu,\"l2\":%llu,\"llc\":%llu,\"xllc\":%llu,\"xnuma\":%llu},\"numa\":{\"smt\":%llu,\"l2\":%llu,\"llc\":%llu,\"xllc\":%llu,\"xnuma\":%llu}}}\n",
				first?"":",", next,
				have_info?policy_name(info.key.policy):"", have_info?info.key.nice:0, have_info?info.key.rtprio:0,
				(unsigned long long)(have_info?info.key.dl_runtime:0ULL),
				(unsigned long long)(have_info?info.key.dl_deadline:0ULL),
				(unsigned long long)(have_info?info.key.dl_period:0ULL),
				have_info?info.key.uclamp_min:0, have_info?info.key.uclamp_max:0,
				(unsigned long long)(have_info?info.key.cgroup_id:0ULL),
				cpus2, have_info?info.key.cpus_weight:0, mems2, have_info?info.key.mems_weight:0,
				cnt, p50, avg_lat, p95, p99, p50_on, avg_on, p95_on, p99_on, st.nr_periods,
				(r_w+r_lb+r_n), r_w, r_lb, r_n, l_smt, l2, l_llc, l_xllc, l_xnuma,
				st.migr_grid[SC_MR_WAKEUP][SC_ML_CORE], st.migr_grid[SC_MR_WAKEUP][SC_ML_L2],   st.migr_grid[SC_MR_WAKEUP][SC_ML_LLC], st.migr_grid[SC_MR_WAKEUP][SC_ML_XLLC], st.migr_grid[SC_MR_WAKEUP][SC_ML_XNUMA],
				st.migr_grid[SC_MR_LB][SC_ML_CORE],     st.migr_grid[SC_MR_LB][SC_ML_L2],     st.migr_grid[SC_MR_LB][SC_ML_LLC],     st.migr_grid[SC_MR_LB][SC_ML_XLLC],     st.migr_grid[SC_MR_LB][SC_ML_XNUMA],
				st.migr_grid[SC_MR_NUMA][SC_ML_CORE],   st.migr_grid[SC_MR_NUMA][SC_ML_L2],   st.migr_grid[SC_MR_NUMA][SC_ML_LLC],   st.migr_grid[SC_MR_NUMA][SC_ML_XLLC],   st.migr_grid[SC_MR_NUMA][SC_ML_XNUMA]);
			first=0;
		}
		key = next;
	}
	printf("  ],\n");
	printf("  \"per_pid\": [\n");
	key = next = 0; first=1;
	while ((err = bpf_map_get_next_key(pid_fd, &key, &next)) == 0) {
		if (bpf_map_lookup_elem(pid_fd, &next, &val) == 0) {
			double p50=0,p95=0,p99=0,avg_lat=0,avg_on=0;
			compute_metrics(val.lat_hist, val.wake_lat_sum_ns, val.wake_lat_cnt,
					val.runtime_ns, val.nr_periods,
					&p50, &p95, &p99, &avg_lat, &avg_on);
			double p50_on=0,p95_on=0,p99_on=0;
			compute_oncpu_quantiles(val.on_hist, &p50_on, &p95_on, &p99_on);
			char esc[TASK_COMM_LEN*2+4]; json_escape((const char*)val.comm, esc, sizeof esc);
			unsigned long long r_w=0,r_lb=0,r_n=0,l_smt=0,l2=0,l_llc=0,l_xllc=0,l_xnuma=0;
			r_w  = val.migr_grid[SC_MR_WAKEUP][SC_ML_CORE] + val.migr_grid[SC_MR_WAKEUP][SC_ML_L2] + val.migr_grid[SC_MR_WAKEUP][SC_ML_LLC] + val.migr_grid[SC_MR_WAKEUP][SC_ML_XLLC] + val.migr_grid[SC_MR_WAKEUP][SC_ML_XNUMA];
			r_lb = val.migr_grid[SC_MR_LB][SC_ML_CORE]     + val.migr_grid[SC_MR_LB][SC_ML_L2]     + val.migr_grid[SC_MR_LB][SC_ML_LLC]     + val.migr_grid[SC_MR_LB][SC_ML_XLLC]     + val.migr_grid[SC_MR_LB][SC_ML_XNUMA];
			r_n  = val.migr_grid[SC_MR_NUMA][SC_ML_CORE]   + val.migr_grid[SC_MR_NUMA][SC_ML_L2]   + val.migr_grid[SC_MR_NUMA][SC_ML_LLC]   + val.migr_grid[SC_MR_NUMA][SC_ML_XLLC]   + val.migr_grid[SC_MR_NUMA][SC_ML_XNUMA];
			l_smt  = val.migr_grid[SC_MR_WAKEUP][SC_ML_CORE] + val.migr_grid[SC_MR_LB][SC_ML_CORE] + val.migr_grid[SC_MR_NUMA][SC_ML_CORE];
			l2     = val.migr_grid[SC_MR_WAKEUP][SC_ML_L2]   + val.migr_grid[SC_MR_LB][SC_ML_L2]   + val.migr_grid[SC_MR_NUMA][SC_ML_L2];
			l_llc  = val.migr_grid[SC_MR_WAKEUP][SC_ML_LLC]  + val.migr_grid[SC_MR_LB][SC_ML_LLC]  + val.migr_grid[SC_MR_NUMA][SC_ML_LLC];
			l_xllc = val.migr_grid[SC_MR_WAKEUP][SC_ML_XLLC] + val.migr_grid[SC_MR_LB][SC_ML_XLLC] + val.migr_grid[SC_MR_NUMA][SC_ML_XLLC];
			l_xnuma= val.migr_grid[SC_MR_WAKEUP][SC_ML_XNUMA]+ val.migr_grid[SC_MR_LB][SC_ML_XNUMA]+ val.migr_grid[SC_MR_NUMA][SC_ML_XNUMA];
			printf("%s    {\"pid\":%u,\"comm\":\"%s\",\"paramset_id\":%u,\"p50_sched_latency_ns\":%.0f,\"avg_sched_latency_ns\":%.0f,\"p95_sched_latency_ns\":%.0f,\"p99_sched_latency_ns\":%.0f,\"p50_oncpu_ns\":%.0f,\"avg_oncpu_ns\":%.0f,\"p95_oncpu_ns\":%.0f,\"p99_oncpu_ns\":%.0f,\"nr_sched_periods\":%u,\"migrations\":{\"total\":%llu},\"migrations_by_reason\":{\"wakeup\":%llu,\"lb\":%llu,\"numa\":%llu},\"migrations_by_locality\":{\"smt\":%llu,\"l2\":%llu,\"llc\":%llu,\"xllc\":%llu,\"xnuma\":%llu},\"migrations_grid\":{\"wakeup\":{\"smt\":%llu,\"l2\":%llu,\"llc\":%llu,\"xllc\":%llu,\"xnuma\":%llu},\"lb\":{\"smt\":%llu,\"l2\":%llu,\"llc\":%llu,\"xllc\":%llu,\"xnuma\":%llu},\"numa\":{\"smt\":%llu,\"l2\":%llu,\"llc\":%llu,\"xllc\":%llu,\"xnuma\":%llu}}}\n",
				first?"":",", next, esc, val.last_paramset_id, p50, avg_lat, p95, p99, p50_on, avg_on, p95_on, p99_on, val.nr_periods,
				(r_w+r_lb+r_n), r_w, r_lb, r_n, l_smt, l2, l_llc, l_xllc, l_xnuma,
				val.migr_grid[SC_MR_WAKEUP][SC_ML_CORE], val.migr_grid[SC_MR_WAKEUP][SC_ML_L2],   val.migr_grid[SC_MR_WAKEUP][SC_ML_LLC], val.migr_grid[SC_MR_WAKEUP][SC_ML_XLLC], val.migr_grid[SC_MR_WAKEUP][SC_ML_XNUMA],
				val.migr_grid[SC_MR_LB][SC_ML_CORE],     val.migr_grid[SC_MR_LB][SC_ML_L2],     val.migr_grid[SC_MR_LB][SC_ML_LLC],     val.migr_grid[SC_MR_LB][SC_ML_XLLC],     val.migr_grid[SC_MR_LB][SC_ML_XNUMA],
				val.migr_grid[SC_MR_NUMA][SC_ML_CORE],   val.migr_grid[SC_MR_NUMA][SC_ML_L2],   val.migr_grid[SC_MR_NUMA][SC_ML_LLC],   val.migr_grid[SC_MR_NUMA][SC_ML_XLLC],   val.migr_grid[SC_MR_NUMA][SC_ML_XNUMA]);
			first=0;
		}
		key = next;
	}
	printf("  ]\n");
	printf("}\n");
	return 0;
}


static int add_pid_filter(struct schedscore_bpf *skel, int pid)
{
	int fd = bpf_map__fd(skel->maps.pid_filter);
	__u8 one = 1;

	if (pid <= 0)
		return 0;

	if (bpf_map_update_elem(fd, &pid, &one, BPF_ANY)) {
		perror("pid_filter update");
		return -1;
	}

	return 0;
}

static int add_comm_filter(struct schedscore_bpf *skel, const char *comm)
{
	struct comm_key key = {};
	__u8 one = 1;
	int fd;

	if (!comm || !*comm)
		return 0;

	fd = bpf_map__fd(skel->maps.comm_filter);
	snprintf(key.comm, sizeof(key.comm), "%s", comm);

	if (bpf_map_update_elem(fd, &key, &one, BPF_ANY)) {
		perror("comm_filter update");
		return -1;
	}
	return 0;
}

static int mark_tracked_pid(struct schedscore_bpf *skel, __u32 pid)
{
	__u8 one = 1;
	int fd = bpf_map__fd(skel->maps.tracked);
	if (pid <= 0)
		return 0;
	if (fd < 0)
		return -1;
	if (bpf_map_update_elem(fd, &pid, &one, BPF_ANY)) {
		perror("tracked map update");
		return -1;
	}
	return 0;
}

/* Preferred: explicit numeric cgroup id from CLI */
static int add_cgroup_filter_id(struct schedscore_bpf *skel, unsigned long long cgid)
{
	__u8 one = 1;
	int fd = bpf_map__fd(skel->maps.cgrp_filter);

	if (!cgid)
		return 0;

	if (bpf_map_update_elem(fd, &cgid, &one, BPF_ANY)) {
		perror("cgrp_filter update (id)");
		return -1;
	}
	return 0;
}

static int setup_output_file(const char *path)
{
	/* Save console fds for child exec */
	if (g_saved_stdout < 0) g_saved_stdout = dup(STDOUT_FILENO);
	if (g_saved_stderr < 0) g_saved_stderr = dup(STDERR_FILENO);
	int fd = open(path, O_CREAT|O_TRUNC|O_WRONLY, 0644);
	if (fd < 0) {
		perror("open -o file");
		return -1;
	}
	if (dup2(fd, STDOUT_FILENO) < 0) { perror("dup2 stdout"); close(fd); return -1; }
	if (dup2(fd, STDERR_FILENO) < 0) { perror("dup2 stderr"); close(fd); return -1; }
	close(fd);
	return 0;
}

/*
 * This is NOT guaranteed to match bpf_get_current_cgroup_id() on all kernels.
 * Keep for convenience; recommend --cgroupid for authoritative filtering.
 */
static int add_cgroup_filter_path(struct schedscore_bpf *skel, const char *path)
{
	struct stat st;
	__u8 one = 1;
	int fd = bpf_map__fd(skel->maps.cgrp_filter);
	__u64 cgid;

	if (!path || !*path)
		return 0;

	if (stat(path, &st)) {
		perror("stat(cgroup path)");
		return -1;
	}

	cgid = st.st_ino;

	if (bpf_map_update_elem(fd, &cgid, &one, BPF_ANY)) {
		perror("cgrp_filter update (path)");
		return -1;
	}

	fprintf(stderr,
		"NOTE: --cgroup PATH used; mapping path->id via inode (%llu). "
		"For exact matching use --cgroupid.\n",
		(unsigned long long)cgid);

	return 0;
}


/* spawn sidecar via /bin/sh -c for arg string */
static pid_t spawn_sidecar(const char *exe, const char *args)
{
	pid_t pid = fork();
	if (pid < 0) {
		perror("fork");
		return -1;
	}
	if (pid == 0) {
		if (args && *args) {
			size_t len = strlen(exe) + 1 + strlen(args) + 1;
			char *cmd = malloc(len);
			if (!cmd)
				_exit(127);
			snprintf(cmd, len, "%s %s", exe, args);
			(void)execl("/bin/sh", "sh", "-c", cmd, (char *)NULL);
			free(cmd);
		} else {
			(void)execlp(exe, exe, (char *)NULL);
		}
		perror("exec sidecar");
		_exit(127);
	}
	return pid;
}

static void apply_env_file(const char *path)
{
	FILE *f = fopen(path, "re");
	if (!f) return;
	char *line = NULL; size_t n = 0;
	while (getline(&line, &n, f) > 0) {
		/* trim */
		char *s = line; while (*s == ' ' || *s == '\t') s++;
		if (*s == '#' || *s == '\n' || *s == '\0') continue;
		char *nl = strchr(s, '\n'); if (nl) *nl = '\0';
		char *eq = strchr(s, '=');
		if (!eq) continue;
		*eq = '\0'; char *key = s; char *val = eq + 1;
		/* overwrite existing vars to match docker --env-file semantics */
		setenv(key, val, 1);
	}
	free(line);
	fclose(f);
}

static int drop_to_user_and_env(const char *user_str)
{
	struct passwd pw, *res = NULL;
	char buf[4096];
	uid_t uid = (uid_t)-1; gid_t gid = (gid_t)-1;
	int is_numeric = 1; for (const char *p = user_str; *p; p++) { if (*p < '0' || *p > '9') { is_numeric = 0; break; } }
	if (is_numeric) {
		uid = (uid_t)strtoul(user_str, NULL, 10);
		if (getpwuid_r(uid, &pw, buf, sizeof(buf), &res) == 0 && res) {
			gid = pw.pw_gid;
		} else {
			/* no passwd entry; default gid=uid, minimal env */
			gid = uid;
		}
	} else {
		if (getpwnam_r(user_str, &pw, buf, sizeof(buf), &res) != 0 || !res)
			return -1;
		uid = pw.pw_uid; gid = pw.pw_gid;
	}
	if (res) {
		/* set env before dropping privileges to avoid surprises with restricted env */
		setenv("HOME",   pw.pw_dir ? pw.pw_dir : "", 1);
		setenv("SHELL",  pw.pw_shell ? pw.pw_shell : "/bin/sh", 1);
		setenv("USER",   pw.pw_name ? pw.pw_name : "", 1);
		setenv("LOGNAME",pw.pw_name ? pw.pw_name : "", 1);
	}
	/* apply env file (if provided via --env-file) before dropping privs */
	if (g_env_file && *g_env_file)
		apply_env_file(g_env_file);
	if (!is_numeric && res && initgroups(pw.pw_name, gid) != 0)
		return -1;
	if (setgid(gid) != 0)
		return -1;
	if (setuid(uid) != 0)
		return -1;
	return 0;
}


/* spawn target workload stopped (SIGSTOP) so parent can attach before exec */
static pid_t spawn_target(char *const argv[])
{
	pid_t pid = fork();
	if (pid < 0) {
		perror("fork(target)");
		return -1;
	}

	if (pid == 0) {
		/* drop user if requested, set a reasonable default env */
		if (g_run_as_user && *g_run_as_user) {
			if (drop_to_user_and_env(g_run_as_user) != 0)
				_exit(127);
		}

		/* Restore stdout/stderr to console for the child if parent redirected with -o */
		if (g_saved_stdout >= 0) dup2(g_saved_stdout, STDOUT_FILENO);
		if (g_saved_stderr >= 0) dup2(g_saved_stderr, STDERR_FILENO);
		/* stop self; parent will SIGSTOP/SIGCONT around BPF attach */
		if (raise(SIGSTOP) != 0)
			_exit(127);
		execvp(argv[0], argv);
		perror("exec target");
		_exit(127);
	}
	return pid;
}

static int add_pid_filter_multi(struct schedscore_bpf *skel, __u32 pid)
{
	if (pid <= 0)
		return 0;
	return add_pid_filter(skel, pid);
}

static void stop_process(pid_t pid)
{
	int i, st;
	pid_t r;

	if (pid <= 0)
		return;

	/* If already exited/reaped, nothing to do */
	r = waitpid(pid, &st, WNOHANG);
	if (r == pid)
		return;
	if (r < 0 && errno == ECHILD)
		return; /* not our child or already reaped */

	/* If process is not alive, nothing to do */
	if (kill(pid, 0) != 0 && errno == ESRCH)
		return;

	(void)kill(pid, SIGINT);
	for (i = 0; i < 30; i++) {
		r = waitpid(pid, &st, WNOHANG);
		if (r == pid)
			return;
		usleep(100 * 1000);
	}
	(void)kill(pid, SIGTERM);
	for (i = 0; i < 20; i++) {
		r = waitpid(pid, &st, WNOHANG);
		if (r == pid)
			return;
		usleep(100 * 1000);
	}
	(void)kill(pid, SIGKILL);
	waitpid(pid, &st, 0);
}


/* Convert linear, power-of-two width histograms back to approximate ns quantiles.
 *
 * For a histogram with width_shift and N buckets, representative value for bin i is
 * rep_ns = (i + 0.5) << width_shift. Callsite should pass the right bucket count
 * and we infer width_shift from whether it's a latency or oncpu histogram.
 */
static double quantile_from_hist(const __u32 *hist, int buckets, double q)
{
	unsigned long total = 0, tgt, cum = 0;
	int i;

	for (i = 0; i < buckets; i++)
		total += hist[i];

	if (!total)
		return 0.0;


	if (q < 0.0) q = 0.0;
	else if (q > 1.0) q = 1.0;

	tgt = (unsigned long)(q * (double)total + 0.5);

	for (i = 0; i < buckets; i++) {
		cum += hist[i];
		if (cum >= tgt) {
			/* Decide which width_shift: caller passes buckets; we assume LAT vs ON by size */
			int width_shift = (buckets == LAT_BUCKETS) ? LAT_WIDTH_SHIFT : ON_WIDTH_SHIFT;
			double rep = ((double)i + 0.5) * (double)(1ULL << width_shift);
			return rep;
		}
	}

	return 0.0;
}

/* Use shared UAPI structs instead of local copies */

static const char *policy_name(int pol)
{
	switch (pol) {
	case 0: return "SCHED_OTHER"; case 1: return "SCHED_FIFO";
	case 2: return "SCHED_RR";    case 3: return "SCHED_BATCH";
	case 5: return "SCHED_IDLE";  case 6: return "SCHED_DEADLINE";
	default: return "SCHED_UNKNOWN";
	}
}
static void mask_to_ranges(const unsigned long long m[4], char *buf, size_t bufsz)
{
	int first = -1; size_t off = 0;
	for (int i = 0; i < 256; i++) {
		int set = (m[i>>6] >> (i & 63)) & 1ULL;
		if (set && first < 0) first = i;
		else if (!set && first >= 0) {
			int last = i - 1;
			off += snprintf(buf + off, bufsz > off ? bufsz - off : 0,
				       off ? ",%d%s%d" : "%d%s%d",
				       first, (last > first ? "-" : ","),
				       last > first ? last : first);
			first = -1;
		}
	}
	if (first >= 0)
		snprintf(buf + off, bufsz > off ? bufsz - off : 0,
			 off ? ",%d-%d" : "%d-%d", first, 255);
}
static void compute_metrics(const __u32 *lat_hist, __u64 lat_sum, __u64 lat_cnt,
                            __u64 runtime_ns, __u32 nr_periods,
                            double *p50, double *p95, double *p99,
                            double *avg_lat, double *avg_on)
{
    if (p50) *p50 = quantile_from_hist(lat_hist, LAT_BUCKETS, 0.50);
    if (p95) *p95 = quantile_from_hist(lat_hist, LAT_BUCKETS, 0.95);
    if (p99) *p99 = quantile_from_hist(lat_hist, LAT_BUCKETS, 0.99);
    if (avg_lat) *avg_lat = lat_cnt ? (double)lat_sum / (double)lat_cnt : 0.0;
    if (avg_on) *avg_on = nr_periods ? (double)runtime_ns / (double)nr_periods : 0.0;
}

static void compute_oncpu_quantiles(const __u32 *on_hist,
                                    double *p50_on, double *p95_on, double *p99_on)
{
    if (p50_on) *p50_on = quantile_from_hist(on_hist, ON_BUCKETS, 0.50);
    if (p95_on) *p95_on = quantile_from_hist(on_hist, ON_BUCKETS, 0.95);
    if (p99_on) *p99_on = quantile_from_hist(on_hist, ON_BUCKETS, 0.99);
}
static void print_hist_config(void)
{
	unsigned long long lat_width = 1ULL << LAT_WIDTH_SHIFT;
	unsigned long long on_width  = 1ULL << ON_WIDTH_SHIFT;
	unsigned long long lat_range = lat_width * (unsigned long long)LAT_BUCKETS;
	unsigned long long on_range  = on_width  * (unsigned long long)ON_BUCKETS;
	unsigned long mem_per_entry = 2u * (LAT_BUCKETS + ON_BUCKETS) * 4u;
	fprintf(stdout,
		"hist-config: latency: width_ns=%llu buckets=%u range_ns=%llu\n",
		lat_width, LAT_BUCKETS, lat_range);
	fprintf(stdout,
		"hist-config: oncpu:   width_ns=%llu buckets=%u range_ns=%llu\n",
		on_width, ON_BUCKETS, on_range);
	fprintf(stdout,
		"hist-config: memory-per-thread (both histograms) ~%lu bytes\n",
		mem_per_entry);
}

static unsigned int count_pids_for_paramset(int pid2set_fd, __u32 set_id)
{
	__u32 k = 0, n = 0, id = 0; unsigned int cnt = 0; int err;
	while ((err = bpf_map_get_next_key(pid2set_fd, &k, &n)) == 0) {
		if (bpf_map_lookup_elem(pid2set_fd, &n, &id) == 0 && id == set_id)
			cnt++;
		k = n;
	}
	return cnt;
}

static void dump_paramset_human(struct schedscore_bpf *skel, bool resolve_masks)
{
	int info_fd = bpf_map__fd(skel->maps.paramset_info);
	__u32 key = 0, next = 0; int err;
	char cpus[512], mems[512];

	printf("\nparamset map (human)\n");
	while ((err = bpf_map_get_next_key(info_fd, &key, &next)) == 0) {
		struct schedscore_paramset_info info;
		if (bpf_map_lookup_elem(info_fd, &next, &info) == 0) {
			cpus[0] = mems[0] = '\0';
			if (resolve_masks) {
				mask_to_ranges(info.key.cpus_mask, cpus, sizeof(cpus));
				mask_to_ranges(info.key.mems_mask, mems, sizeof(mems));
			}
			printf("paramset id=%u policy=%s nice=%d rtprio=%u "
			       "uclamp=(%u,%u) cgv2=0x%llx cpus=%s(pop=%u) mems=%s(pop=%u)\n",
			       next, policy_name(info.key.policy), info.key.nice, info.key.rtprio,
			       info.key.uclamp_min, info.key.uclamp_max,
			       (unsigned long long)info.key.cgroup_id,
			       cpus, info.key.cpus_weight, mems, info.key.mems_weight);
		}
		key = next;
	}
}

static void dump_paramset_csv(struct schedscore_bpf *skel, bool resolve_masks)
{
	int info_fd = bpf_map__fd(skel->maps.paramset_info);
	int stats_fd = bpf_map__fd(skel->maps.stats_by_paramset);
	int pid2set_fd = bpf_map__fd(skel->maps.pid_to_paramset);
	__u32 key = 0, next = 0; int err;
	char cpus[512], mems[512];

	printf("\nparamset_map_csv\n");
	printf("paramset_id,policy,nice,rtprio,dl_runtime_ns,dl_deadline_ns,dl_period_ns," \
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
	printf("paramset_id,pids,p50_sched_latency_ns,avg_sched_latency_ns,p95_sched_latency_ns,p99_sched_latency_ns," \
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
			unsigned int cnt = count_pids_for_paramset(pid2set_fd, next);
			printf("%u,%u,%.0f,%.0f,%.0f,%.0f,%.0f,%.0f,%.0f,%.0f,%u\n",
			       next, cnt,
			       p50, avg_lat, p95, p99,
			       p50_on, avg_on, p95_on, p99_on,
			       st.nr_periods);
		}
		key = next;
	}
}


static void warn_on_clamps(struct schedscore_bpf *skel)
{
	/* per-PID */
	int fd = bpf_map__fd(skel->maps.stats);
	__u32 key = 0, next = 0; int err;
	int lat_top_pid = 0, on_top_pid = 0;
	struct schedscore_pid_stats v;
	while ((err = bpf_map_get_next_key(fd, &key, &next)) == 0) {
		if (bpf_map_lookup_elem(fd, &next, &v) == 0) {
			if (v.lat_hist[LAT_BUCKETS-1]) lat_top_pid = 1;
			if (v.on_hist[ON_BUCKETS-1]) on_top_pid = 1;
		}
		key = next;
	}

	/* per-paramset aggregate */
	int sfd = bpf_map__fd(skel->maps.stats_by_paramset);
	__u32 k2 = 0, n2 = 0;
	int lat_top_ps = 0, on_top_ps = 0;
	struct schedscore_paramset_stats ps;
	while ((err = bpf_map_get_next_key(sfd, &k2, &n2)) == 0) {
		if (bpf_map_lookup_elem(sfd, &n2, &ps) == 0) {
			if (ps.lat_hist[LAT_BUCKETS-1]) lat_top_ps = 1;
			if (ps.on_hist[ON_BUCKETS-1]) on_top_ps = 1;
		}
		k2 = n2;
	}

	if (lat_top_ps || on_top_ps)
		fprintf(stderr,
			"schedscore: warning: histogram hit top bin (paramset%s)%s\n",
			lat_top_ps ? " latency" : "",
			on_top_ps ? " and oncpu" : "");

	if (lat_top_pid || lat_top_ps)
		fprintf(stderr,
			"schedscore: warning: latency histogram hit top bin (per-pid%s); "
			"increase LAT_BUCKETS and/or LAT_WIDTH_SHIFT. "
			"Use --show-hist-config to inspect current settings.\n",
			lat_top_ps ? "+paramset" : "");
	if (on_top_pid || on_top_ps)
		fprintf(stderr,
			"schedscore: warning: on-CPU histogram hit top bin (per-pid%s); "
			"increase ON_BUCKETS and/or ON_WIDTH_SHIFT. "
			"Use --show-hist-config to inspect current settings.\n",
			on_top_ps ? "+paramset" : "");
}


static void dump_migrations_csv(struct schedscore_bpf *skel, const struct opts *o)
{
	int stats_fd = bpf_map__fd(skel->maps.stats_by_paramset);
	int pid_fd   = bpf_map__fd(skel->maps.stats);
	__u32 key=0,next=0; int err;

	/* Summary by paramset */
	printf("\nmigrations_summary_csv\n");
	printf("paramset_id,migr_total,migr_wakeup,migr_lb,migr_numa,migr_loc_core,migr_loc_llc,migr_loc_xllc\n");
	key = next = 0;
	while ((err = bpf_map_get_next_key(stats_fd, &key, &next)) == 0) {
		struct schedscore_paramset_stats st;
		if (bpf_map_lookup_elem(stats_fd, &next, &st) == 0) {
			unsigned long long r_w=0,r_lb=0,r_n=0,l_c=0,l_l=0,l_x=0,total=0;
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

	if (!o->show_migration_matrix)
		return;

	/* Paramset matrix */
	printf("\nparamset_migrations_matrix_csv\n");
	printf("paramset_id,wk/smt,wk/l2,wk/llc,wk/xllc,wk/xnuma,lb/smt,lb/l2,lb/llc,lb/xllc,lb/xnuma,numa/smt,numa/l2,numa/llc,numa/xllc,numa/xnuma\n");
	key = next = 0;
	while ((err = bpf_map_get_next_key(stats_fd, &key, &next)) == 0) {
		struct schedscore_paramset_stats st;
		if (bpf_map_lookup_elem(stats_fd, &next, &st) == 0) {
			printf("%u,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu\n",
				next,
				st.migr_grid[SC_MR_WAKEUP][SC_ML_CORE], st.migr_grid[SC_MR_WAKEUP][SC_ML_L2],   st.migr_grid[SC_MR_WAKEUP][SC_ML_LLC], st.migr_grid[SC_MR_WAKEUP][SC_ML_XLLC], st.migr_grid[SC_MR_WAKEUP][SC_ML_XNUMA],
				st.migr_grid[SC_MR_LB][SC_ML_CORE],     st.migr_grid[SC_MR_LB][SC_ML_L2],     st.migr_grid[SC_MR_LB][SC_ML_LLC],     st.migr_grid[SC_MR_LB][SC_ML_XLLC],     st.migr_grid[SC_MR_LB][SC_ML_XNUMA],
				st.migr_grid[SC_MR_NUMA][SC_ML_CORE],   st.migr_grid[SC_MR_NUMA][SC_ML_L2],   st.migr_grid[SC_MR_NUMA][SC_ML_LLC],   st.migr_grid[SC_MR_NUMA][SC_ML_XLLC],   st.migr_grid[SC_MR_NUMA][SC_ML_XNUMA]);
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
			printf("%u,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu\n",
				next,
				val.migr_grid[SC_MR_WAKEUP][SC_ML_CORE], val.migr_grid[SC_MR_WAKEUP][SC_ML_L2],   val.migr_grid[SC_MR_WAKEUP][SC_ML_LLC], val.migr_grid[SC_MR_WAKEUP][SC_ML_XLLC], val.migr_grid[SC_MR_WAKEUP][SC_ML_XNUMA],
				val.migr_grid[SC_MR_LB][SC_ML_CORE],     val.migr_grid[SC_MR_LB][SC_ML_L2],     val.migr_grid[SC_MR_LB][SC_ML_LLC],     val.migr_grid[SC_MR_LB][SC_ML_XLLC],     val.migr_grid[SC_MR_LB][SC_ML_XNUMA],
				val.migr_grid[SC_MR_NUMA][SC_ML_CORE],   val.migr_grid[SC_MR_NUMA][SC_ML_L2],   val.migr_grid[SC_MR_NUMA][SC_ML_LLC],   val.migr_grid[SC_MR_NUMA][SC_ML_XLLC],   val.migr_grid[SC_MR_NUMA][SC_ML_XNUMA]);
		}
		key = next;
	}
}





static void dump_paramsets(struct schedscore_bpf *skel, bool resolve_masks)
{
	dump_paramset_human(skel, resolve_masks);
	dump_paramset_csv(skel, resolve_masks);
}



static int dump_output(struct schedscore_bpf *skel, const struct opts *o)
{
	struct schedscore_pid_stats val;
	struct col_set cs = {};
	int fd = bpf_map__fd(skel->maps.stats);
	__u32 key = 0, next_key = 0;
	int err;
	int saved_errno = 0;
	const char *fmt = o->format ? o->format : "table";

	/* JSON full document */
	if (strcmp(fmt, "json") == 0) {
		return dump_json(skel, o);
	}

	/* columns: default full set in standard order if not provided */
	if (o->columns && *o->columns)
		parse_columns_string(o->columns, &cs);
	if (cs.cnt == 0) {
		int def[] = { COL_PID, COL_COMM, COL_PARAMSET_ID,
			      COL_P50_LAT, COL_AVG_LAT, COL_P95_LAT, COL_P99_LAT,
			      COL_P50_ON, COL_AVG_ON, COL_P95_ON, COL_P99_ON,
			      COL_NR_PERIODS };
		for (size_t i = 0; i < sizeof(def)/sizeof(def[0]); i++) cs.idx[cs.cnt++] = def[i];
	}

	if (strcmp(fmt, "csv") == 0) {
		/* header */
		for (int i = 0; i < cs.cnt; i++) printf("%s%s", col_name[cs.idx[i]], (i+1<cs.cnt)?",":"\n");
	} else if (strcmp(fmt, "table") == 0) {
		int widths[32] = {0};
		compute_pid_table_widths(skel, &cs, widths);
		print_table_header_w(&cs, widths);

	}

	while ((err = bpf_map_get_next_key(fd, &key, &next_key)) == 0) {
		if (bpf_map_lookup_elem(fd, &next_key, &val) == 0) {
			double p50=0,p95=0,p99=0,avg_lat=0,avg_on=0;
			compute_metrics(val.lat_hist, val.wake_lat_sum_ns, val.wake_lat_cnt,
					val.runtime_ns, val.nr_periods,
					&p50, &p95, &p99, &avg_lat, &avg_on);
			double p50_on=0,p95_on=0,p99_on=0;
			compute_oncpu_quantiles(val.on_hist, &p50_on, &p95_on, &p99_on);

			if (strcmp(fmt, "csv") == 0) {
				for (int i = 0; i < cs.cnt; i++) {
					int id = cs.idx[i];
					switch (id) {
					case COL_PID: printf("%u", next_key); break;
					case COL_COMM: printf("%.*s", TASK_COMM_LEN, val.comm); break;
					case COL_PARAMSET_ID: printf("%u", val.last_paramset_id); break;
					case COL_P50_LAT: printf("%.0f", p50); break;
					case COL_AVG_LAT: printf("%.0f", avg_lat); break;
					case COL_P95_LAT: printf("%.0f", p95); break;
					case COL_P99_LAT: printf("%.0f", p99); break;
					case COL_P50_ON: printf("%.0f", p50_on); break;
					case COL_AVG_ON: printf("%.0f", avg_on); break;
					case COL_P95_ON: printf("%.0f", p95_on); break;
					case COL_P99_ON: printf("%.0f", p99_on); break;
					case COL_NR_PERIODS: printf("%u", val.nr_periods); break;
					default: break;
					}
					printf("%s", (i+1<cs.cnt)?",":"\n");
				}
			} else { /* table */
				int widths[32] = {0};
				compute_pid_table_widths(skel, &cs, widths);
				print_table_row_w(&cs, widths, next_key, &val, p50, avg_lat, p95, p99, p50_on, avg_on, p95_on, p99_on);
			}
		}
		key = next_key;
	}
	saved_errno = errno;

	/* ENOENT means end-of-iteration; anything else is unexpected */
	if (err < 0 && saved_errno != ENOENT) {
		perror("bpf_map_get_next_key");
		return -1;
	}
	/* Extra sections */
	if (strcmp(fmt, "csv") == 0) {
		dump_paramsets(skel, true);
		dump_migrations_csv(skel, o);
	} else if (strcmp(fmt, "table") == 0) {

			/* Per-PID matrix comes immediately after the per-PID main table */
			if (o->show_migration_matrix && o->show_pid_migration_matrix)
				dump_pid_migrations_matrix_table(skel);

		dump_paramset_map_table(skel, true);
		dump_paramset_stats_table(skel);
		if (o->show_migration_matrix) {
			/* Paramset migration matrix */
			printf("\nparamset_migrations_matrix_table\n");
			int loc_block = 4+1+4+1+4+1+4+1+5;
			printf("%-12s | %-*s | %-*s | %-*s\n", "paramset_id", loc_block, "wakeup", loc_block, "loadbalance", loc_block, "numa");
			printf("%-12s | %-4s %-4s %-4s %-4s %-5s | %-4s %-4s %-4s %-4s %-5s | %-4s %-4s %-4s %-4s %-5s\n",
				"", "smt","l2","llc","xllc","xnuma",  "smt","l2","llc","xllc","xnuma",  "smt","l2","llc","xllc","xnuma");
			int stats_fd = bpf_map__fd(skel->maps.stats_by_paramset);
			__u32 k=0,n=0; int err;
			while ((err = bpf_map_get_next_key(stats_fd, &k, &n)) == 0) {
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

		dump_migrations_summary_table(skel);
	}

	/* After printing all sections, warn if any top-bin clamping occurred */
	warn_on_clamps(skel);

	return 0;
}


/* Helpers to shrink main() for readability */
static int prepare_filters_and_target(struct schedscore_bpf *skel, struct opts *o,
				char **target_argv, pid_t *target_pid, struct config *cfg)
{
	/* init cfg */
	memset(cfg, 0, sizeof(*cfg));
	if (o->warn_enable) {
		cfg->enable_warn = 1;
		if (o->latency_warn_us > 0)
			cfg->latency_warn_ns = (unsigned long long)o->latency_warn_us * 1000ULL;
	}

	cfg->follow_children = o->follow_children ? 1 : 0;
	cfg->aggregate_enable = o->aggregate_enable ? 1 : 0;
	cfg->paramset_recheck = o->paramset_recheck ? 1 : 0;
	cfg->timeline_enable = o->timeline_enable ? 1 : 0;

	/* Spawn target stopped, wait, add pid filter */
	if (target_argv) {
		*target_pid = spawn_target(target_argv);

		if (*target_pid < 0) {
			fprintf(stderr, "failed to spawn target\n");
			return -1;
		}
		{
			int st;
			pid_t wr = waitpid(*target_pid, &st, WUNTRACED);
			if (wr != *target_pid || !WIFSTOPPED(st))
				fprintf(stderr, "warn: target did not report stopped state\n");
		}
		if (add_pid_filter_multi(skel, *target_pid))
			fprintf(stderr, "warn: pid filter update failed for target pid\n");
		cfg->use_pid_filter = 1;
		if (mark_tracked_pid(skel, *target_pid))
			fprintf(stderr, "warn: failed to seed tracked map for target pid\n");
	}

	/* Merge explicit --pid */
	if (o->pid > 0) {
		if (add_pid_filter_multi(skel, o->pid))
			fprintf(stderr, "warn: pid filter update failed\n");
		cfg->use_pid_filter = 1;
	}

	/* Other filters */
	if (o->comm) {
		if (add_comm_filter(skel, o->comm))
			fprintf(stderr, "warn: comm filter update failed\n");
		cfg->use_comm_filter = 1;
	}
	if (o->have_cgroup_id) {
		if (add_cgroup_filter_id(skel, o->cgroup_id))
			fprintf(stderr, "warn: cgroupid filter update failed\n");
		cfg->use_cgrp_filter = 1;
	} else if (o->cgroup_path) {
		if (add_cgroup_filter_path(skel, o->cgroup_path))
			fprintf(stderr, "warn: cgroup path filter update failed\n");
		cfg->use_cgrp_filter = 1;
	}

	/* push cfg */
	{
		int mfd = bpf_map__fd(skel->maps.conf);
		__u32 idx0 = 0;
		if (bpf_map_update_elem(mfd, &idx0, cfg, BPF_ANY)) {
			perror("config update");
			return -1;
		}
	}
	return 0;
}

static int attach_and_launch(struct schedscore_bpf *skel, pid_t target_pid,
			   char **target_argv, struct opts *o,
			   struct sidecar *perf, struct sidecar *trce)
{
	(void)target_argv;
	if (schedscore_bpf__attach(skel)) {
		fprintf(stderr, "failed to attach BPF programs. Ensure BTF and CONFIG_DEBUG_INFO_BTF are enabled.\n");
		return -1;
	}
	if (target_pid > 0) {
		if (kill(target_pid, SIGCONT) != 0)
			perror("kill(SIGCONT target)");
	}
	if (o->perf_enable || o->perf_args) {
		if (!o->perf_args)
			o->perf_args = strdup("-a -e sched:* -o perf.data");
		if (!o->perf_args)
			return -1;
		perf->pid = spawn_sidecar(perf->exe, o->perf_args);
		if (perf->pid < 0)
			return -1;
	}
	if (o->ftrace_enable || o->ftrace_args) {
		if (!o->ftrace_args)
			o->ftrace_args = strdup("-e sched -e irq -e softirq -o trace.dat");
		if (!o->ftrace_args)
			return -1;
		trce->pid = spawn_sidecar(trce->exe, o->ftrace_args);
		if (trce->pid < 0)
			return -1;
	}
	return 0;
}

static void setup_signals(void)
{
	struct sigaction sa;
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = sig_handler;
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);
	/* Ignore SIGALRM; we don't use it and some targets may set alarms */
	{
		struct sigaction sa_ign = {};
		sa_ign.sa_handler = SIG_IGN;
		sigaction(SIGALRM, &sa_ign, NULL);
	}
}

static void run_until_done(pid_t target_pid, int duration_sec)
{
	if (target_pid > 0) {
		int st; pid_t r;
		if (duration_sec > 0) {
			int i, iters = duration_sec * 10;
			for (i = 0; i < iters && !exiting; i++) {
				r = waitpid(target_pid, &st, WNOHANG);
				if (r == target_pid) {
					exiting = 1;
					break;
				}
				usleep(100 * 1000);
			}
			exiting = 1;
		} else {
			while (!exiting) {
				r = waitpid(target_pid, &st, WNOHANG);
				if (r == target_pid) {
					exiting = 1;
					break;
				}
				usleep(100 * 1000);
			}
		}
	} else {
		if (duration_sec > 0) {
			int i;
			for (i = 0; i < duration_sec && !exiting; i++)
				sleep(1);
			exiting = 1;
		} else {
			while (!exiting)
				pause();
		}
	}
}

static int cleanup_and_dump(struct schedscore_bpf *skel, struct sidecar *perf,
			   struct sidecar *trce, pid_t target_pid, const struct opts *o)
{
	if (target_pid > 0) {
		int st; pid_t r;
		r = waitpid(target_pid, &st, WNOHANG);
		if (r == 0) {
			if (kill(target_pid, 0) == 0)
				(void)kill(target_pid, SIGINT);
		}
	}
	stop_process(perf->pid);
	stop_process(trce->pid);
	stop_process(target_pid);
	return dump_output(skel, o);
}

static int parse_opts(int argc, char **argv, struct opts *o, char ***target_argv);
static int push_cpu_topology(struct schedscore_bpf *skel);

static void setup_rlimit(void);
static int open_and_load(struct schedscore_bpf **skel);

static int parse_opts(int argc, char **argv, struct opts *o, char ***target_argv)
{
	static const struct option long_opts[] = {
		{ "duration",           required_argument, 0, 'd' },
		{ "pid",                required_argument, 0, 'p' },
		{ "comm",               required_argument, 0, 'n' },
		{ "cgroup",             required_argument, 0, 'g' },
		{ "cgroupid",           required_argument, 0, 'G' },
		{ "latency-warn-us",    required_argument, 0, 'l' },
		{ "warn-enable",        no_argument,       0, 'w' },
		{ "perf",               no_argument,       0, 'P' },
		{ "ftrace",             no_argument,       0, 'F' },
		{ "perf-args",          required_argument, 0, 'A' },
		{ "ftrace-args",        required_argument, 0, 'R' },
		{ "follow",             no_argument,       0, 'f' },
		{ "user",               required_argument, 0, 'u' },
		{ "env-file",           required_argument, 0, 'e' },
		{ "output",             required_argument, 0, 'o' },
		{ "out-dir",            required_argument, 0, 'D' },
		{ "format",             required_argument, 0, 'M' },
		{ "columns",            required_argument, 0, 'C' },
		{ "show-migration-matrix", no_argument,    0,  6  },
		{ "show-pid-migration-matrix", no_argument,0,  7  },
		{ "dump-topology",      no_argument,       0,  8  },
		{ "no-aggregate",       no_argument,       0,  1  },
		{ "paramset-recheck",   no_argument,       0,  2  },
		{ "timeline",           no_argument,       0,  3  },
		{ "no-resolve-masks",   no_argument,       0,  4  },
		{ "show-hist-config",   no_argument,       0,  5  },
		{ "show-migration-matrix", no_argument,    0,  6  },
		{ 0, 0, 0, 0 }
	};
	int c;

	memset(o, 0, sizeof(*o));
	o->pid = -1;
	*target_argv = NULL;

	o->aggregate_enable = true;
	o->paramset_recheck = false;
	o->show_pid_migration_matrix = false;

	o->timeline_enable = false;
	o->resolve_masks = true;
		o->show_migration_matrix = false;


	while ((c = getopt_long(argc, argv, "d:p:n:g:G:l:wPFA:R:fu:e:o:D:M:C:", long_opts, NULL)) != -1) {
		switch (c) {
		case 'd': o->duration_sec = atoi(optarg); break;
		case 'p': o->pid = atoi(optarg); break;
		case 'n':
			o->comm = strdup(optarg);
			if (!o->comm) { fprintf(stderr, "oom\n"); return -1; }
			break;
		case 'g':
			o->cgroup_path = strdup(optarg);
			if (!o->cgroup_path) { fprintf(stderr, "oom\n"); return -1; }
			break;
		case 'G':
			o->cgroup_id = strtoull(optarg, NULL, 0);
			o->have_cgroup_id = true;
			break;
		case 'l': o->latency_warn_us = atol(optarg); break;
	case 'w': o->warn_enable = true; break;
		case 'P': o->perf_enable = true; break;
		case 'F': o->ftrace_enable = true; break;
		case 'u':
			o->run_as_user = strdup(optarg);
			if (!o->run_as_user) { fprintf(stderr, "oom\n"); return -1; }
			break;
		case 'e':
			o->env_file = strdup(optarg);
			if (!o->env_file) { fprintf(stderr, "oom\n"); return -1; }
			break;
		case 'o':
			o->out_path = strdup(optarg);
			if (!o->out_path) { fprintf(stderr, "oom\n"); return -1; }
			break;
		case 'D':
			o->out_dir = strdup(optarg);
			if (!o->out_dir) { fprintf(stderr, "oom\n"); return -1; }
			break;
		case 'M':
			o->format = strdup(optarg);
			if (!o->format) { fprintf(stderr, "oom\n"); return -1; }
			break;
		case 'C':
			o->columns = strdup(optarg);
			if (!o->columns) { fprintf(stderr, "oom\n"); return -1; }
			break;
		case 'A':
			o->perf_args = strdup(optarg);
			if (!o->perf_args) { fprintf(stderr, "oom\n"); return -1; }
			break;
		case 'R':
			o->ftrace_args = strdup(optarg);
			if (!o->ftrace_args) { fprintf(stderr, "oom\n"); return -1; }
			break;
		case 'f': o->follow_children = true; break;
		case 1: o->aggregate_enable = false; break;
		case 2: o->paramset_recheck = true; break;
		case 3: o->timeline_enable = true; break;
		case 4: o->resolve_masks = false; break;
		case 5: o->show_hist_config = true; break;
		case 6: o->show_migration_matrix = true; break;
		case 7: o->show_pid_migration_matrix = true; break;
			case 8: o->dump_topology = true; break;

		default:
		usage(argv[0]);
			return -1;
		}
	}
	if (optind < argc)
		*target_argv = &argv[optind];
	return 0;
}

static void setup_rlimit(void)
{
	struct rlimit r = { .rlim_cur = RLIM_INFINITY, .rlim_max = RLIM_INFINITY };
	if (setrlimit(RLIMIT_MEMLOCK, &r))
		fprintf(stderr, "WARN: setrlimit RLIMIT_MEMLOCK failed: %s\n", strerror(errno));
}

static int open_and_load(struct schedscore_bpf **skel)
{

	*skel = schedscore_bpf__open();
	if (!*skel) {
		fprintf(stderr, "failed to open BPF skeleton\n");


		return -1;
	}
	/* hist config is printed in main(), where opts are available */

	if (schedscore_bpf__load(*skel)) {
		fprintf(stderr, "failed to load BPF skeleton\n");
		schedscore_bpf__destroy(*skel);
		*skel = NULL;
		return -1;
	}
	/* Push CPU topology after maps are loaded */
	push_cpu_topology(*skel);

	return 0;
}


int main(int argc, char **argv)
{
	char **target_argv = NULL;
	pid_t target_pid = 0;
	struct schedscore_bpf *skel = NULL;
	struct sidecar perf = { .exe = "perf", .args = NULL, .pid = 0 };
	struct sidecar trce = { .exe = "trace-cmd", .args = NULL, .pid = 0 };
	struct config cfg = {};
	struct opts o;
	int err = 0;

	if (parse_opts(argc, argv, &o, &target_argv))
		return 1;

	/* Redirect output early if requested */
	if (o.out_path) {
		if (setup_output_file(o.out_path)) return 1;
	}

	/* If just inspecting histogram config, print and exit */
	if (o.show_hist_config) {
		print_hist_config();
		return 0;
	}

	/* libbpf strict mode: future-proof ABI expectations */
	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
	setup_rlimit();

	/* cache run-as-user and env-file for child */
	g_run_as_user = o.run_as_user;
	g_env_file = o.env_file;
	if (open_and_load(&skel)) { err = 1; goto out; }
		if (o.dump_topology) { dump_topology_table(skel); goto out; }

	if (prepare_filters_and_target(skel, &o, target_argv, &target_pid, &cfg)) { err = 1; goto out; }
	if (attach_and_launch(skel, target_pid, target_argv, &o, &perf, &trce)) { err = 1; goto out; }

	setup_signals();
	run_until_done(target_pid, o.duration_sec);
	err = cleanup_and_dump(skel, &perf, &trce, target_pid, &o);

out:
	if (skel)
		schedscore_bpf__destroy(skel);
	free(o.comm);
	free(o.cgroup_path);
	free(o.perf_args);
	free(o.ftrace_args);
	return err ? 1 : 0;
}

static int cpu_in_cpulist(const char *s, int cpu)
{
	/* Parse cpulist like "0-3,8,10-11" and check if cpu is in it */
	const char *p = s;
	while (*p) {
		while (*p == ' ' || *p == '\t' || *p == '\n' || *p == ',') p++;
		if (!*p) break;
		long a = -1, b = -1; char *endp = NULL;
		a = strtol(p, &endp, 10);
		if (endp && *endp == '-') {
			p = endp + 1;
			b = strtol(p, &endp, 10);
			if (a >= 0 && b >= 0 && cpu >= a && cpu <= b) return 1;
		} else {
			if (a >= 0 && cpu == a) return 1;
			p = endp ? endp : p+1;
		}
		p = endp ? endp : p;
	}
	return 0;
}

static int detect_numa_id(int cpu, unsigned int *numa_id)
{
	/* Try to find node whose cpulist contains this cpu */
	char path[256]; char buf[4096];
	for (unsigned int node = 0; node < 1024; node++) {
		snprintf(path, sizeof(path), "/sys/devices/system/node/node%u/cpulist", node);
		FILE *f = fopen(path, "r");
		if (!f) continue;
		size_t n = fread(buf, 1, sizeof(buf)-1, f);
		fclose(f);
		if (n == 0) continue;
		buf[n] = '\0';
		if (cpu_in_cpulist(buf, cpu)) { *numa_id = node; return 0; }
	}
	return -1;
}



static int read_uint_file(const char *path, unsigned int *out)
{
	FILE *f = fopen(path, "r");
	if (!f) return -1;
	unsigned int v = 0; int rc = fscanf(f, "%u", &v);
	fclose(f);
	if (rc == 1) { *out = v; return 0; }
	return -1;
}

static int detect_llc_id(int cpu, unsigned int *llc_id)
{
	char p[256];
	for (int idx = 0; idx < 10; idx++) {
		snprintf(p, sizeof(p), "/sys/devices/system/cpu/cpu%d/cache/index%d/type", cpu, idx);
		FILE *f = fopen(p, "r");
		if (!f) continue;
		char typebuf[32] = {0};
		if (!fgets(typebuf, sizeof(typebuf), f)) { fclose(f); continue; }
		fclose(f);
		/* Look for unified cache and pick the highest level */
		if (strstr(typebuf, "Unified")) {
			snprintf(p, sizeof(p), "/sys/devices/system/cpu/cpu%d/cache/index%d/id", cpu, idx);
			if (read_uint_file(p, llc_id) == 0)
				return 0;
		}
	}
	return -1;
}
static int detect_l2_id(int cpu, unsigned int *l2_id)
{
	char p[256];
	unsigned int best_id=0, best_lvl=0;
	for (int idx = 0; idx < 10; idx++) {
		snprintf(p, sizeof(p), "/sys/devices/system/cpu/cpu%d/cache/index%d/type", cpu, idx);
		FILE *f = fopen(p, "r"); if (!f) continue;
		char typebuf[32] = {0}; if (!fgets(typebuf, sizeof(typebuf), f)) { fclose(f); continue; }
		fclose(f);
		if (!strstr(typebuf, "Unified")) continue;
		snprintf(p, sizeof(p), "/sys/devices/system/cpu/cpu%d/cache/index%d/level", cpu, idx);
		unsigned int lvl=0; if (read_uint_file(p, &lvl)) continue;
		if (lvl == 2) {
			snprintf(p, sizeof(p), "/sys/devices/system/cpu/cpu%d/cache/index%d/id", cpu, idx);
			if (read_uint_file(p, &best_id) == 0) { *l2_id = best_id; return 0; }
		}
	}
	return -1;
}


static int detect_llc_highest(int cpu, unsigned int *llc_id)
{
	char p[256]; unsigned int best_id=0, best_lvl=0;
	for (int idx = 0; idx < 10; idx++) {
		snprintf(p, sizeof(p), "/sys/devices/system/cpu/cpu%d/cache/index%d/type", cpu, idx);
		FILE *f = fopen(p, "r"); if (!f) continue;
		char typebuf[32] = {0}; if (!fgets(typebuf, sizeof(typebuf), f)) { fclose(f); continue; }
		fclose(f);
		if (!strstr(typebuf, "Unified")) continue;
		snprintf(p, sizeof(p), "/sys/devices/system/cpu/cpu%d/cache/index%d/level", cpu, idx);
		unsigned int lvl=0; if (read_uint_file(p, &lvl)) continue;
		if (lvl >= best_lvl) {
			snprintf(p, sizeof(p), "/sys/devices/system/cpu/cpu%d/cache/index%d/id", cpu, idx);
			unsigned int id; if (read_uint_file(p, &id)) continue;
			best_lvl = lvl; best_id = id;
		}
	}
	if (best_lvl) { *llc_id = best_id; return 0; }
	return -1;
}

static int push_cpu_topology(struct schedscore_bpf *skel)
{
	long nproc = sysconf(_SC_NPROCESSORS_CONF);
	if (nproc <= 0 || nproc > 4096) nproc = 4096;
	int core_fd = bpf_map__fd(skel->maps.cpu_core_id);
	int llc_fd  = bpf_map__fd(skel->maps.cpu_llc_id);
	int l2_fd   = bpf_map__fd(skel->maps.cpu_l2_id);
	int numa_fd = bpf_map__fd(skel->maps.cpu_numa_id);
	if (core_fd < 0 || llc_fd < 0 || l2_fd < 0 || numa_fd < 0)
		return -1;
	for (int cpu = 0; cpu < nproc; cpu++) {
		char p[256]; unsigned int core_id=0, pkg_id=0, llc_id=0, l2_id=0, core_key=0, numa_id=0;
		snprintf(p, sizeof(p), "/sys/devices/system/cpu/cpu%d/topology/core_id", cpu);
		read_uint_file(p, &core_id);
		snprintf(p, sizeof(p), "/sys/devices/system/cpu/cpu%d/topology/physical_package_id", cpu);
		read_uint_file(p, &pkg_id);
		/* combine socket and core to get a globally unique core identity */
		core_key = (pkg_id << 16) | (core_id & 0xFFFF);
		if (detect_llc_highest(cpu, &llc_id) != 0)
			llc_id = (pkg_id << 16); /* fallback: package as LLC cluster */
		if (detect_l2_id(cpu, &l2_id) != 0)
			l2_id = core_key; /* fallback: per-core L2 */
		/* NUMA id via sysfs node mapping; fallback to package if not found */
		if (detect_numa_id(cpu, &numa_id) != 0) {
			snprintf(p, sizeof(p), "/sys/devices/system/cpu/cpu%d/topology/physical_package_id", cpu);
			read_uint_file(p, &numa_id);
		}
		__u32 k = cpu;
		if (bpf_map_update_elem(core_fd, &k, &core_key, BPF_ANY)) perror("cpu_core_id update");
		if (bpf_map_update_elem(llc_fd,  &k, &llc_id,   BPF_ANY)) perror("cpu_llc_id update");
		if (bpf_map_update_elem(l2_fd,   &k, &l2_id,    BPF_ANY)) perror("cpu_l2_id update");
		if (bpf_map_update_elem(numa_fd, &k, &numa_id,  BPF_ANY)) perror("cpu_numa_id update");
	}
	return 0;
}
