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

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "schedscore.skel.h"
#include "schedscore_hist.h"
#include "schedscore_uapi.h"
#include "output_dispatch.h"
#include "emit_helpers.h"
#include "opts.h"
#include "opts_parse.h"
#include "topo.h"

static volatile sig_atomic_t exiting;

/* Cached settings passed from parent to child */
static const char *g_env_file = NULL;
static const char *g_run_as_user = NULL;
static int g_saved_stdout = -1, g_saved_stderr = -1;

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
	printf("  --paramset-recheck            force paramset recheck on every event\n");
	printf("  --detect-wakeup-latency VAL   set wakeup detector (e.g. 1us, 1ms)\n");
	printf("  --detect-migration-xnuma      enable cross-NUMA migration detector\n");
	printf("  --detect-migration-xllc       enable cross-LLC migration detector\n");
	printf("  --detect-remote-wakeup-xnuma  enable remote wakeup xNUMA detector\n");
	printf("  --dump-topology               print cpu->(smt,l2,llc,numa) and exit\n");
	printf("  -h, --help                    show this help\n");
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
	int fd = open(path, O_CREAT|O_TRUNC|O_WRONLY, 0644);

	/* Save console fds for child exec */
	if (g_saved_stdout < 0)
		g_saved_stdout = dup(STDOUT_FILENO);
	if (g_saved_stderr < 0)
		g_saved_stderr = dup(STDERR_FILENO);
	if (fd < 0) {
		perror("open -o file");
		return -1;
	}
	if (dup2(fd, STDOUT_FILENO) < 0) {
		perror("dup2 stdout");
		close(fd);
		return -1;
	}
	if (dup2(fd, STDERR_FILENO) < 0) {
		perror("dup2 stderr");
		close(fd);
		return -1;
	}
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
			(void) execl("/bin/sh", "sh", "-c", cmd, (char *)NULL);
			/* If execl returns, preserve errno then free */
			int saved = errno;
			free(cmd);
			errno = saved;
		} else {
			(void) execlp(exe, exe, (char *)NULL);
		}
		perror("exec sidecar");
		_exit(127);
	}
	return pid;
}

static void apply_env_file(const char *path)
{
	FILE *f = fopen(path, "re");
	char *line = NULL;
	size_t n = 0;

	if (!f)
		return;

	while (getline(&line, &n, f) > 0) {
		/* trim */
		char *s = line;
		while (*s == ' ' || *s == '\t')
			s++;
		if (*s == '#' || *s == '\n' || *s == '\0')
			continue;
		char *nl = strchr(s, '\n');
		if (nl)
			*nl = '\0';
		char *eq = strchr(s, '=');
		if (!eq)
			continue;
		*eq = '\0';
		char *key = s;
		char *val = eq + 1;
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
	uid_t uid = (uid_t) - 1;
	gid_t gid = (gid_t) - 1;
	int is_numeric = 1;

	for (const char *p = user_str; *p; p++) {
		if (*p < '0' || *p > '9') {
			is_numeric = 0;
			break;
		}
	}
	if (is_numeric) {
		uid = (uid_t) strtoul(user_str, NULL, 10);
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
		setenv("HOME", pw.pw_dir ? pw.pw_dir : "", 1);
		setenv("SHELL", pw.pw_shell ? pw.pw_shell : "/bin/sh", 1);
		setenv("USER", pw.pw_name ? pw.pw_name : "", 1);
		setenv("LOGNAME", pw.pw_name ? pw.pw_name : "", 1);
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
		if (g_saved_stdout >= 0)
			dup2(g_saved_stdout, STDOUT_FILENO);
		if (g_saved_stderr >= 0)
			dup2(g_saved_stderr, STDERR_FILENO);
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

	(void) kill(pid, SIGINT);
	for (i = 0; i < 30; i++) {
		r = waitpid(pid, &st, WNOHANG);
		if (r == pid)
			return;
		usleep(100 * 1000);
	}
	(void) kill(pid, SIGTERM);
	for (i = 0; i < 20; i++) {
		r = waitpid(pid, &st, WNOHANG);
		if (r == pid)
			return;
		usleep(100 * 1000);
	}
	(void) kill(pid, SIGKILL);

	/* Final bounded reap */
	for (i = 0; i < 10; i++) {
		r = waitpid(pid, &st, WNOHANG);
		if (r == pid)
			return;
		if (r < 0 && errno == ECHILD)
			return;
		usleep(100 * 1000);
	}
	return;
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
	__u32 idx0 = 0;
	int spawned = 0;
	int mfd;

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
		int st;

		*target_pid = spawn_target(target_argv);
		if (*target_pid < 0) {
			fprintf(stderr, "failed to spawn target\n");
			return -1;
		}
		spawned = 1;

		pid_t wr = waitpid(*target_pid, &st, WUNTRACED);
		if (wr == -1) {
			perror("waitpid(target)");
		} else if (wr != *target_pid || !WIFSTOPPED(st)) {
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

	/* detectors always set regardless of filters */
	cfg->detect_wakeup_lat_ns = o->detect_wakeup_lat_ns;
	cfg->detect_migration_xnuma = o->detect_migration_xnuma ? 1 : 0;
	cfg->detect_migration_xllc  = o->detect_migration_xllc  ? 1 : 0;
	cfg->detect_remote_wakeup_xnuma = o->detect_remote_wakeup_xnuma ? 1 : 0;

	/* push cfg */
	mfd = bpf_map__fd(skel->maps.conf);
	if (bpf_map_update_elem(mfd, &idx0, cfg, BPF_ANY)) {
		perror("config update");
		if (spawned && *target_pid > 0)
			stop_process(*target_pid);
		return -1;
	}
	return 0;
}

static int attach_and_launch(struct schedscore_bpf *skel, pid_t target_pid,
		char **target_argv, struct opts *o,
		struct sidecar *perf, struct sidecar *ftrace)
{
	int perf_started = 0, ftrace_started = 0;
	(void) target_argv;

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
			goto fail;
		perf->pid = spawn_sidecar(perf->exe, o->perf_args);
		if (perf->pid < 0)
			goto fail;
		perf_started = 1;
	}
	if (o->ftrace_enable || o->ftrace_args) {
		if (!o->ftrace_args)
			o->ftrace_args = strdup("-e sched -e irq -e softirq -o trace.dat");
		if (!o->ftrace_args)
			goto fail;
		ftrace->pid = spawn_sidecar(ftrace->exe, o->ftrace_args);
		if (ftrace->pid < 0)
			goto fail;
		ftrace_started = 1;
	}
	return 0;

fail:
	if (ftrace_started)
		stop_process(ftrace->pid);
	if (perf_started)
		stop_process(perf->pid);
	return -1;
}

static void setup_signals(void)
{
	struct sigaction sa;
	struct sigaction sa_ign = {};

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = sig_handler;
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);

	/* Ignore SIGALRM; we don't use it and some targets may set alarms */
	sa_ign.sa_handler = SIG_IGN;
	sigaction(SIGALRM, &sa_ign, NULL);
}

static void run_until_done(pid_t target_pid, int duration_sec)
{
	int st; pid_t r;
	int i, iters = duration_sec * 10;

	if (target_pid > 0) {
		if (duration_sec > 0) {
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
	int st;
	pid_t r;

	if (target_pid > 0) {
		r = waitpid(target_pid, &st, WNOHANG);
		if (r == 0) {
			/* Only signal if still alive */
			if (kill(target_pid, 0) == 0)
				(void) kill(target_pid, SIGINT);
		}
	}
	stop_process(perf->pid);
	stop_process(trce->pid);
	stop_process(target_pid);
	return output_emit(skel, o);
}

static void setup_rlimit(void)
{
	struct rlimit r = {
		.rlim_cur = RLIM_INFINITY,
		.rlim_max = RLIM_INFINITY
	};

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
	int prc;

	memset(&o, 0, sizeof(o));
	prc = parse_opts(argc, argv, &o, &target_argv);

	if (prc == 2) {
		print_help_aligned(argv[0]);
		err = 0;
		goto out;
	}
	if (prc) {
		err = 1;
		goto out;
	}


	/* Require root for normal runs */
	if (geteuid() != 0) {
		fprintf(stderr, "schedscore: needs root (CAP_BPF etc.). Try: sudo %s ...\n", argv[0]);
		err = 1;
		goto out;
	}

	/* Redirect output early if requested */
	if (o.out_path) {
		if (setup_output_file(o.out_path)) {
			err = 1;
			goto out;
		}
	}

	/* If just inspecting histogram config, print and exit */
	if (o.show_hist_config) {
		print_hist_config();
		err = 0;
		goto out;
	}

	/* libbpf strict mode: future-proof ABI expectations */
	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
	setup_rlimit();

	/* cache run-as-user and env-file for child */
	g_run_as_user = o.run_as_user;
	g_env_file = o.env_file;
	if (open_and_load(&skel)) {
		err = 1;
		goto out;
	}
	if (o.dump_topology) {
		dump_topology_table(skel);
		goto out;
	}

	if (prepare_filters_and_target(skel, &o, target_argv, &target_pid, &cfg)) {
		err = 1;
		goto out;
	}
	if (attach_and_launch(skel, target_pid, target_argv, &o, &perf, &trce)) {
		err = 1;
		goto out;
	}

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
	free(o.run_as_user);
	free(o.env_file);
	free(o.out_path);
	free(o.out_dir);
	free(o.format);
	free(o.columns);
	return err ? 1 : 0;
}
