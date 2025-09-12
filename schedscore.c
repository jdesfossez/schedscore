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
#include "output_dispatch.h"
#include "emit_helpers.h"


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
		/* detectors */
		unsigned long long detect_wakeup_lat_ns; /* 0 disables */
		bool detect_migration_xnuma;
		bool detect_migration_xllc;
		bool detect_remote_wakeup_xnuma;


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

/* Parse a number with optional unit suffix into nanoseconds. Supports ns, us, ms, s. */
static unsigned long long parse_time_to_ns(const char *s)
{
	char *end = NULL;
	unsigned long long v = strtoull(s, &end, 10);
	if (end == s) return 0ULL;
	if (*end == '\0' || strcmp(end, "ns") == 0) return v;
	if (strcmp(end, "us") == 0) return v * 1000ULL;
	if (strcmp(end, "ms") == 0) return v * 1000000ULL;
	if (strcmp(end, "s") == 0)  return v * 1000000000ULL;
	return 0ULL; /* invalid suffix */
}


static int cpu_in_cpulist(const char *s, int cpu);
static int detect_numa_id(int cpu, unsigned int *numa_id);

static int cpu_in_cpulist(const char *s, int cpu);
static int detect_numa_id(int cpu, unsigned int *numa_id);
static void print_help_aligned(const char *prog);





#if 0

static void usage(const char *prog)
{
	print_help_aligned(prog);
	return;
	/* cleaned concise help */
#if 0


	print_help_aligned(prog);
	return;

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

#endif


		"          [--columns COL1,COL2,...]  # select/reorder columns\n"
		"          [--show-hist-config]\n",
		prog);
/* legacy verbose usage block end */

}
#endif /* disable legacy usage() */


static void print_help_aligned(const char *prog)
{
	printf("Usage: %s [options] -- [command...]\n\n", prog);
	printf("Options:\n");
	printf("  --duration SEC                run for SEC seconds (0=until Ctrl-C)\n");
	printf("  --pid PID                     filter by PID\n");
	printf("  --comm NAME                   filter by comm\n");
	printf("  --cgroup PATH                 filter by cgroup path\n");
	printf("  --cgroupid ID                 filter by cgroup id\n");
	printf("  --latency-warn-us N           set bpf_printk threshold (us)\n");
	printf("  --warn-enable                 enable warning prints\n");
	printf("  --perf                        capture with perf(1)\n");
	printf("  --ftrace                      capture with trace-cmd(1)\n");
	printf("  --perf-args 'ARGS'            perf(1) arguments\n");
	printf("  --ftrace-args 'ARGS'          trace-cmd(1) arguments\n");
	printf("  -f, --follow                  follow children\n");
	printf("  --user USER                   run target as user/uid\n");
	printf("  --env-file FILE               add KEY=VALUE lines to target env\n");
	printf("  --output FILE                 write all output to FILE\n");
	printf("  --out-dir DIR                 write multiple outputs under DIR\n");
	printf("  --format csv|json|table       output format (default: table)\n");
	printf("  --columns NAMES               select/reorder columns\n");
	printf("  --show-hist-config            print histogram config and exit\n");
	printf("  --show-migration-matrix       include paramset migration matrix\n");
	printf("  --show-pid-migration-matrix   include per-PID migration matrix\n");
	printf("  --detect-wakeup-latency VAL   set wakeup detector (e.g. 1us, 1ms)\n");
	printf("  --detect-migration-xnuma      enable cross-NUMA migration detector\n");
	printf("  --detect-migration-xllc       enable cross-LLC migration detector\n");
	printf("  --detect-remote-wakeup-xnuma  enable remote wakeup xNUMA detector\n");
	printf("  --dump-topology               print cpu->(smt,l2,llc,numa) and exit\n");
	printf("  -h, --help                    show this help\n");
}

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
	__u32 core_ids[4096], l2_ids[4096], llc_ids[4096], numa_ids[4096];
	__u32 cores=0,l2s=0,llcs=0,numas=0;
	for (int cpu = 0; cpu < nproc; cpu++) {
		__u32 k = cpu; __u32 core=0,l2=0,llc=0,numa=0;
		(void)bpf_map_lookup_elem(core_fd, &k, &core);
		(void)bpf_map_lookup_elem(l2_fd,   &k, &l2);
		(void)bpf_map_lookup_elem(llc_fd,  &k, &llc);
		(void)bpf_map_lookup_elem(numa_fd, &k, &numa);
		bool found=false; for (__u32 i=0;i<cores;i++){ if (core_ids[i]==core){found=true;break;} } if(!found) core_ids[cores++]=core;
		found=false; for (__u32 i=0;i<l2s;i++){ if (l2_ids[i]==l2){found=true;break;} } if(!found) l2_ids[l2s++]=l2;
		found=false; for (__u32 i=0;i<llcs;i++){ if (llc_ids[i]==llc){found=true;break;} } if(!found) llc_ids[llcs++]=llc;
		found=false; for (__u32 i=0;i<numas;i++){ if (numa_ids[i]==numa){found=true;break;} } if(!found) numa_ids[numas++]=numa;
	}
	printf("cpus=%ld smt_cores=%u l2_domains=%u llc_domains=%u numa_nodes=%u\n", nproc, cores, l2s, llcs, numas);
}

struct col_set {
	int idx[32];
	int cnt;
};

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

		/* detectors always set regardless of filters */
		cfg->detect_wakeup_lat_ns = o->detect_wakeup_lat_ns;
		cfg->detect_migration_xnuma = o->detect_migration_xnuma ? 1 : 0;
		cfg->detect_migration_xllc  = o->detect_migration_xllc  ? 1 : 0;
		cfg->detect_remote_wakeup_xnuma = o->detect_remote_wakeup_xnuma ? 1 : 0;

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
	return output_emit(skel, o);
}

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
		{ "detect-wakeup-latency", required_argument, 0,  9 },
		{ "detect-migration-xnuma", no_argument, 0, 10 },
		{ "detect-migration-xllc",  no_argument, 0, 11 },
		{ "detect-remote-wakeup-xnuma", no_argument, 0, 12 },
		{ "dump-topology",      no_argument,       0,  8  },
		{ "no-aggregate",       no_argument,       0,  1  },
		{ "paramset-recheck",   no_argument,       0,  2  },
		{ "timeline",           no_argument,       0,  3  },
		{ "no-resolve-masks",   no_argument,       0,  4  },
		{ "show-hist-config",   no_argument,       0,  5  },
		{ "help",               no_argument,       0, 'h' },
		{ 0, 0, 0,  0 }
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


	while ((c = getopt_long(argc, argv, "hd:p:n:g:G:l:wPFA:R:fu:e:o:D:M:C:", long_opts, NULL)) != -1) {
		switch (c) {
		case 'd': o->duration_sec = atoi(optarg); break;
		case 'p': o->pid = atoi(optarg); break;
		case 'n':
			o->comm = strdup(optarg);
			if (!o->comm) { fprintf(stderr, "oom\n"); return -1; }
			break;
		case 9: {
			unsigned long long ns = parse_time_to_ns(optarg);
			if (!ns) { fprintf(stderr, "invalid --detect-wakeup-latency value\n"); return -1; }
			o->detect_wakeup_lat_ns = ns;
			break; }
		case 10: o->detect_migration_xnuma = true; break;
		case 11: o->detect_migration_xllc  = true; break;
		case 12: o->detect_remote_wakeup_xnuma = true; break;
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
		case 'h': return 2; /* help requested */
		default:
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

	int prc = parse_opts(argc, argv, &o, &target_argv);
	if (prc == 2) {
		print_help_aligned(argv[0]);
		return 0;
	}
	if (prc)
		return 1;

	/* --help/-h should not require root */
	for (int i = 1; i < argc; i++) {
		if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
			print_help_aligned(argv[0]);
			return 0;
		}
	}

	/* Require root for normal runs */
	if (geteuid() != 0) {
		fprintf(stderr, "schedscore: needs root (CAP_BPF etc.). Try: sudo %s ...\n", argv[0]);
		return 1;
	}

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

static int detect_l2_id(int cpu, unsigned int *l2_id)
{
	char p[256];
	unsigned int best_id=0;
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
