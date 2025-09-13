// SPDX-License-Identifier: GPL-2.0-only
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#include "schedscore_hist.h"
#include "schedscore_uapi.h"

char LICENSE[] SEC("license") = "GPL";

/* ---------- config (set by userspace) ---------- */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct config);
} conf SEC(".maps");

/* ---------- filters ---------- */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16384);
	__type(key, __u32);   // pid
	__type(value, __u8);
} pid_filter SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 256);
	__type(key, struct comm_key); // exact comm
	__type(value, __u8);
} comm_filter SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 64);
	__type(key, __u64);  // cgroupid
	__type(value, __u8);
} cgrp_filter SEC(".maps");

/* ---------- state/results ---------- */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 16384);
	__type(key, __u32);              // pid
	__type(value, struct schedscore_pid_stats);
} stats SEC(".maps");

/* pending wake timestamp */
/* CPU topology read-only maps for locality classification */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 4096);
	__type(key, __u32); // cpu
	__type(value, __u32); // core_id
} cpu_core_id SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 4096);
	__type(key, __u32);
	__type(value, __u32); // llc_id
} cpu_llc_id SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 4096);
	__type(key, __u32);
	__type(value, __u32); // l2_id
} cpu_l2_id SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 4096);
	__type(key, __u32);
	__type(value, __u32); // numa_id
} cpu_numa_id SEC(".maps");

struct wake_info { __u64 ts; __u32 waker_cpu; };

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16384);
	__type(key, __u32);  // pid
	__type(value, struct wake_info);
} wake_ts SEC(".maps");

/* track children of tracked pids */
struct tracked_map {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16384);
	__type(key, __u32);  // pid
	__type(value, __u8); // tracked=1
} tracked SEC(".maps");

/* ---------- paramset aggregation ---------- */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16384);
	__type(key, __u32); // pid
	__type(value, __u32); // paramset id
} pid_to_paramset SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, struct schedscore_paramset_key);
	__type(value, __u32); // id
} paramset_ids SEC(".maps");

/* Scratch zero-initialized templates to avoid large stack allocations.
 * Use PERCPU to keep accesses local to the CPU, but keep value sizes within limits.
 */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct schedscore_pid_stats);
} zero_pid SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct schedscore_paramset_stats);
} zero_param SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, __u32); // id
	__type(value, struct schedscore_paramset_info);
} paramset_info SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, __u32); // id
	__type(value, struct schedscore_paramset_stats);
} stats_by_paramset SEC(".maps");

struct next_id_state {
	struct bpf_spin_lock lock;
	__u32 next;
};
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct next_id_state);
} next_paramset_id SEC(".maps");

static __always_inline void read_mask64(const unsigned long *bits, __u64 out[4],
					 __u16 *weight)
{
	__u64 w = 0;
	int ret;

	if (!bits || !out || !weight)
		return;

#pragma clang loop unroll(full)
	for (int i = 0; i < 4; i++) {
		__u64 v = 0;

		ret = bpf_core_read(&v, sizeof(v), &(((__u64 *)bits)[i]));
		if (ret < 0)
			v = 0;
		out[i] = v;
		w += (__u64)__builtin_popcountll(v);
	}
	*weight = (__u16)w;
}

static __always_inline void add_latency_bucket(__u32 *hist, __u64 ns)
{
	__u64 idx;

	if (!hist)
		return;

	/*
	 * Linear, power-of-two bucket:
	 * idx = min(ns >> LAT_WIDTH_SHIFT, LAT_BUCKETS-1)
	 */
	idx = ns >> LAT_WIDTH_SHIFT;
	if (idx >= LAT_BUCKETS)
		idx = LAT_BUCKETS - 1;

	__atomic_fetch_add(&hist[idx], 1, __ATOMIC_RELAXED);
}

static __always_inline void add_oncpu_bucket(__u32 *hist, __u64 ns)
{
	__u64 idx;

	if (!hist)
		return;

	/*
	 * Linear, power-of-two bucket:
	 * idx = min(ns >> ON_WIDTH_SHIFT, ON_BUCKETS-1)
	 */
	idx = ns >> ON_WIDTH_SHIFT;
	if (idx >= ON_BUCKETS)
		idx = ON_BUCKETS - 1;

	__atomic_fetch_add(&hist[idx], 1, __ATOMIC_RELAXED);
}

static __always_inline void build_paramset_key(struct task_struct *t,
						struct schedscore_paramset_key *k)
{
	struct sched_dl_entity dl = {};
	__u32 static_prio = 0;
	int ret;

	if (!t || !k)
		return;

	__builtin_memset(k, 0, sizeof(*k));

	/* Read scheduling policy */
	ret = bpf_core_read(&k->policy, sizeof(k->policy), &t->policy);
	if (ret < 0)
		k->policy = 0;

	/* Derive nice from static_prio: Linux nice = static_prio - 120 */
	ret = bpf_core_read(&static_prio, sizeof(static_prio), &t->static_prio);
	if (ret < 0)
		static_prio = 120; /* Default to nice 0 */
	k->nice = (__s8)((int)static_prio - 120);

	/* Read RT priority */
	ret = bpf_core_read(&k->rtprio, sizeof(k->rtprio), &t->rt_priority);
	if (ret < 0)
		k->rtprio = 0;

	/* Read deadline scheduling parameters */
	ret = bpf_core_read(&dl, sizeof(dl), &t->dl);
	if (ret < 0) {
		k->dl_runtime = 0;
		k->dl_deadline = 0;
		k->dl_period = 0;
	} else {
		k->dl_runtime = dl.runtime;
		k->dl_deadline = dl.deadline;
		k->dl_period = dl.dl_period;
		/*
		 * Note: dl_period name can differ across kernels
		 * (dl_period vs period); we read dl_period
		 */
	}
	/* Read uclamp values if present */
	{
		struct uclamp_se ucmin = {}, ucmax = {};

		ret = bpf_core_read(&ucmin, sizeof(ucmin), &t->uclamp_req[0]);
		if (ret < 0)
			k->uclamp_min = 0;
		else
			k->uclamp_min = ucmin.value;

		ret = bpf_core_read(&ucmax, sizeof(ucmax), &t->uclamp_req[1]);
		if (ret < 0)
			k->uclamp_max = 1024; /* Default max */
		else
			k->uclamp_max = ucmax.value;
	}

	/* Read cgroup v2 id */
	{
		struct css_set *c = NULL;
		struct cgroup_subsys_state *dfl_css = NULL;
		struct cgroup *cg = NULL;
		struct kernfs_node *kn = NULL;

		ret = bpf_core_read(&c, sizeof(c), &t->cgroups);
		if (ret < 0)
			goto skip_cgroup;

		ret = bpf_core_read(&dfl_css, sizeof(dfl_css), &c->dfl_cgrp);
		if (ret < 0)
			goto skip_cgroup;

		ret = bpf_core_read(&cg, sizeof(cg), &dfl_css->cgroup);
		if (ret < 0)
			goto skip_cgroup;

		ret = bpf_core_read(&kn, sizeof(kn), &cg->kn);
		if (ret < 0)
			goto skip_cgroup;

		ret = bpf_core_read(&k->cgroup_id, sizeof(k->cgroup_id), &kn->id);
		if (ret < 0)
			k->cgroup_id = 0;
		goto read_masks;

skip_cgroup:
		k->cgroup_id = 0;
	}
read_masks:
	/* Read CPU and memory masks */
	{
		const struct cpumask *cp = NULL;

		ret = bpf_core_read(&cp, sizeof(cp), &t->cpus_ptr);
		if (ret < 0 || !cp) {
			/* Set default mask values on error */
			for (int i = 0; i < 4; i++)
				k->cpus_mask[i] = 0;
			k->cpus_weight = 0;
		} else {
			read_mask64((const unsigned long *)cp->bits,
				    k->cpus_mask, &k->cpus_weight);
		}
	}
	{
		const nodemask_t *nm = NULL;

		ret = bpf_core_read(&nm, sizeof(nm), &t->mems_allowed);
		if (ret < 0 || !nm) {
			/* Set default mask values on error */
			for (int i = 0; i < 4; i++)
				k->mems_mask[i] = 0;
			k->mems_weight = 0;
		} else {
			read_mask64((const unsigned long *)nm->bits,
				    k->mems_mask, &k->mems_weight);
		}
	}
}

static __always_inline __u32 get_or_create_paramset_id(struct schedscore_paramset_key *key)
{
	__u32 *found = bpf_map_lookup_elem(&paramset_ids, key);
	if (found)
		return *found;

	__u32 k0 = 0;
	struct next_id_state *st = bpf_map_lookup_elem(&next_paramset_id, &k0);
	if (!st)
		return 0;
	__u32 id;
	bpf_spin_lock(&st->lock);
	id = st->next + 1;
	st->next = id;
	bpf_spin_unlock(&st->lock);
	/* Try to create mapping; if another CPU won, use the existing id */
	int ret = bpf_map_update_elem(&paramset_ids, key, &id, BPF_NOEXIST);
	if (ret == 0) {
		struct schedscore_paramset_info info = { .key = *key };
		bpf_map_update_elem(&paramset_info, &id, &info, BPF_ANY);
		return id;
	}
	/* fallback: someone else inserted first */
	{
		__u32 *ex = bpf_map_lookup_elem(&paramset_ids, key);
		return ex ? *ex : 0;
	}
}

static __always_inline struct schedscore_paramset_stats *get_or_init_paramset_stats(__u32 id)
{
	struct schedscore_paramset_stats *as = bpf_map_lookup_elem(&stats_by_paramset, &id);
	if (!as) {
		__u32 zkey = 0;
		struct schedscore_paramset_stats *z = bpf_map_lookup_elem(&zero_param, &zkey);
		if (z)
			bpf_map_update_elem(&stats_by_paramset, &id, z, BPF_NOEXIST);
		as = bpf_map_lookup_elem(&stats_by_paramset, &id);
	}
	return as;
}

static __always_inline void mark_oncpu_and_bump_periods(struct schedscore_pid_stats *ps,
					    const struct config *cfg,
					    __u32 id,
					    __u64 ts,
					    __u32 cpu)
{
	ps->oncpu_start_ns = ts;
	ps->last_cpu = cpu;
	ps->nr_periods++;
	if (cfg && cfg->aggregate_enable && id) {
		struct schedscore_paramset_stats *as = get_or_init_paramset_stats(id);
		if (as)
			as->nr_periods++;
	}
}

static __always_inline void mirror_latency_to_paramset(__u32 id, __u64 lat);

static __always_inline struct schedscore_pid_stats *get_or_init_pid_stats(__u32 pid)
{
	struct schedscore_pid_stats *ps = bpf_map_lookup_elem(&stats, &pid);
	if (!ps) {
		__u32 zkey = 0;
		struct schedscore_pid_stats *z = bpf_map_lookup_elem(&zero_pid, &zkey);
		if (z)
			bpf_map_update_elem(&stats, &pid, z, BPF_NOEXIST);
		ps = bpf_map_lookup_elem(&stats, &pid);
	}
	return ps;
}

static __always_inline void handle_wake_latency(const struct config *cfg,
						__u32 pid, __u64 ts, __u32 id,
						struct task_struct *task,
						struct schedscore_pid_stats *ps)
{
	__u64 *wts;
	__u64 lat;
	int ret;

	if (!ps || !task)
		return;

	wts = bpf_map_lookup_elem(&wake_ts, &pid);
	if (!wts || !*wts)
		return;

	lat = ts - *wts;

	/* Snapshot comm after possible exec */
	ret = bpf_core_read_str(ps->comm, sizeof(ps->comm), &task->comm);
	if (ret < 0) {
		/* On error, keep the existing comm */
	}

	ps->wake_lat_sum_ns += lat;
	ps->wake_lat_cnt++;
	add_latency_bucket(ps->lat_hist, lat);

	if (cfg && cfg->aggregate_enable && id)
		mirror_latency_to_paramset(id, lat);

	if (cfg && cfg->enable_warn && cfg->latency_warn_ns &&
	    lat > cfg->latency_warn_ns)
		bpf_printk("schedscore: pid=%d wake_lat_ns=%llu > thr_ns=%llu",
			   pid, lat, cfg->latency_warn_ns);

	/* Detector: wakeup latency */
	if (cfg && cfg->detect_wakeup_lat_ns && lat > cfg->detect_wakeup_lat_ns)
		bpf_printk("schedscore:detect_wakeup_latency: pid=%d latency=%llu",
			   pid, lat);

	*wts = 0;
}

static __always_inline void end_period_for_prev(const struct config *cfg,
						 struct task_struct *prev,
						 __u64 ts)
{
	struct schedscore_pid_stats *pps;
	__u32 ppid;
	__u64 delta;

	if (!prev)
		return;

	ppid = BPF_CORE_READ(prev, pid);
	if (!ppid)
		return;

	pps = bpf_map_lookup_elem(&stats, &ppid);
	if (!pps || !pps->oncpu_start_ns)
		return;

	delta = ts - pps->oncpu_start_ns;
	pps->runtime_ns += delta;
	add_oncpu_bucket(pps->on_hist, delta);
	pps->nr_periods++;

	if (cfg && cfg->aggregate_enable) {
		__u32 id = 0;
		__u32 *pid = bpf_map_lookup_elem(&pid_to_paramset, &ppid);
		if (pid)
			id = *pid;
		if (!id)
			id = pps->last_paramset_id;
		if (id) {
			struct schedscore_paramset_stats *as = get_or_init_paramset_stats(id);
			if (as) {
				as->runtime_ns += delta;
				add_oncpu_bucket(as->on_hist, delta);
				as->nr_periods++;
			}
		}
	}
	pps->oncpu_start_ns = 0;
}

static __always_inline void mirror_latency_to_paramset(__u32 id, __u64 lat)
{
	struct schedscore_paramset_stats *as = bpf_map_lookup_elem(&stats_by_paramset, &id);
	if (!as) {
		__u32 zkey = 0;
		struct schedscore_paramset_stats *zero = bpf_map_lookup_elem(&zero_param, &zkey);
		if (zero)
			bpf_map_update_elem(&stats_by_paramset, &id, zero, BPF_NOEXIST);
		as = bpf_map_lookup_elem(&stats_by_paramset, &id);
		if (!as)
			return;
	}
	as->wake_lat_sum_ns += lat;
	as->wake_lat_cnt++;
	add_latency_bucket(as->lat_hist, lat);
	/* add_latency_bucket is defined below */

}


static __always_inline void account_sample(struct schedscore_pid_stats *ps, struct schedscore_paramset_stats *as,
					  __u64 now, __u32 cpu, bool do_latency)
{
	/* ps->runtime_ns updated by caller for prev on switch; we only do next */
	if (do_latency) {
		/* mirrored in per-PID and per-paramset */
		/* wake_lat_sum_ns/wake_lat_cnt and histogram already updated by caller for ps */
		/* add to aggregated histogram */
	}
	/* mark oncpu and increment periods */
	ps->oncpu_start_ns = now;
	ps->last_cpu = cpu;
	ps->nr_periods++;
	if (as)
		as->nr_periods++;
}



static __always_inline bool is_tracked(__u32 pid)
{
	__u8 *v = bpf_map_lookup_elem(&tracked, &pid);
	return v != NULL;
}

static __always_inline void mark_tracked(__u32 pid)
{
	__u8 one = 1;
	bpf_map_update_elem(&tracked, &pid, &one, BPF_ANY);
}

static __always_inline bool follow_children_enabled(void)
{
	__u32 k0 = 0;
	struct config *cfg = bpf_map_lookup_elem(&conf, &k0);
	return cfg && cfg->follow_children;
}



static __always_inline bool pass_filters(struct task_struct *task, __u32 pid)
{
	struct config *cfg;
	__u32 k0 = 0;
	int ret;

	if (!task || !pid)
		return false;

	cfg = bpf_map_lookup_elem(&conf, &k0);
	if (!cfg)
		return true;

	if (cfg->use_pid_filter) {
		__u8 *ok = bpf_map_lookup_elem(&pid_filter, &pid);
		if (ok)
			return true;
		/* Fall through to check other filters */
	}

	if (cfg->use_comm_filter) {
		struct comm_key ck = {};

		ret = bpf_core_read_str(ck.comm, sizeof(ck.comm), &task->comm);
		if (ret > 0) {
			__u8 *ok = bpf_map_lookup_elem(&comm_filter, &ck);
			if (ok)
				return true;
		}
	}

	if (cfg->use_cgrp_filter) {
		__u64 cgid = bpf_get_current_cgroup_id();
		__u8 *ok = bpf_map_lookup_elem(&cgrp_filter, &cgid);
		if (ok)
			return true;
	}

	/*
	 * If any filter is enabled and none matched -> reject;
	 * if no filters enabled -> accept.
	 */
	if (cfg->use_pid_filter || cfg->use_comm_filter || cfg->use_cgrp_filter)
		return false;

	return true;
}

static __always_inline bool track_if_passing_filters(struct task_struct *task,
						      __u32 pid)
{
	__u32 ppid, leader;

	if (!task || !pid)
		return false;

	if (is_tracked(pid))
		return true;

	/* If follow is enabled, inherit tracking from parent or group leader */
	if (follow_children_enabled()) {
		ppid = BPF_CORE_READ(task, real_parent, pid);
		if (ppid && is_tracked(ppid)) {
			mark_tracked(pid);
			return true;
		}

		/* Also follow threads in same thread-group when leader is tracked */
		leader = BPF_CORE_READ(task, group_leader, pid);
		if (leader && is_tracked(leader)) {
			mark_tracked(pid);
			return true;
		}
	}
	if (!pass_filters(task, pid))
		return false;
	mark_tracked(pid);
	return true;
}


/* --------- tp_btf handlers (typed tracepoints) --------- */

SEC("tp_btf/sched_process_fork")
int BPF_PROG(sched_process_fork, struct task_struct *parent, struct task_struct *child)
{
	__u32 ppid = BPF_CORE_READ(parent, pid);
	__u32 cpid = BPF_CORE_READ(child, pid);

	if (follow_children_enabled()) {
		if (is_tracked(ppid) || pass_filters(parent, ppid))
			mark_tracked(cpid);
	}
	return 0;
}

SEC("tp_btf/sched_process_exit")
int BPF_PROG(sched_process_exit, struct task_struct *p, int group_dead)
{
	__u32 pid = BPF_CORE_READ(p, pid);
	bpf_map_delete_elem(&wake_ts, &pid);
	bpf_map_delete_elem(&tracked, &pid);
	return 0;
}



SEC("tp_btf/sched_waking")
int BPF_PROG(sched_waking, struct task_struct *p, int prio, int success, int target_cpu)
{
	__u32 pid = BPF_CORE_READ(p, pid);

	if (!track_if_passing_filters(p, pid))
		return 0;

	__u64 ts = bpf_ktime_get_ns();
	bpf_map_update_elem(&wake_ts, &pid, &ts, BPF_ANY);
	return 0;
}

SEC("tp_btf/sched_switch")
int BPF_PROG(sched_switch, bool preempt, struct task_struct *prev, struct task_struct *next)
{
	__u64 ts  = bpf_ktime_get_ns();
	__u32 cpu = bpf_get_smp_processor_id();
	__u32 k0 = 0;
	struct config *cfg = bpf_map_lookup_elem(&conf, &k0);

	/* account runtime for prev */
	end_period_for_prev(cfg, prev, ts);

	/* next: latency + enrollment + mark oncpu */

	if (next) {
		/* declarations at block top */
		__u32 npid = BPF_CORE_READ(next, pid);
		struct schedscore_pid_stats *ps;
		char cur_comm[TASK_COMM_LEN] = {};
		bool comm_changed = false;
		__u32 id = 0, *oldid = NULL;

		if (!track_if_passing_filters(next, npid))
			return 0;


		ps = bpf_map_lookup_elem(&stats, &npid);
		if (!ps) {
			__u32 zkey = 0;
			struct schedscore_pid_stats *zero = bpf_map_lookup_elem(&zero_pid, &zkey);
			if (zero)
				bpf_map_update_elem(&stats, &npid, zero, BPF_NOEXIST);
			ps = bpf_map_lookup_elem(&stats, &npid);
		}
		if (!ps) return 0;

		/* detect comm change (exec) before enrollment */
		bpf_core_read_str(cur_comm, sizeof(cur_comm), &next->comm);
		#pragma clang loop unroll(full)
		for (int i = 0; i < TASK_COMM_LEN; i++) {
			if (cur_comm[i] != ps->comm[i]) { comm_changed = true; break; }
		}

		/* paramset enrollment/recheck */
		if (cfg && cfg->aggregate_enable) {
			struct schedscore_paramset_key key;
			bool need_rebuild = false;
			if (!cfg->paramset_recheck) {
				oldid = bpf_map_lookup_elem(&pid_to_paramset, &npid);
				if (oldid)
					id = *oldid;
			}
			/* Heuristic: rebuild on comm change (exec) */
			if (id && comm_changed)
				need_rebuild = true;
			if (!id || need_rebuild) {
				build_paramset_key(next, &key);
				id = get_or_create_paramset_id(&key);
				bpf_map_update_elem(&pid_to_paramset, &npid, &id, BPF_ANY);
				if (cfg->timeline_enable && oldid && *oldid != id)
					bpf_printk(
						"schedscore:paramset pid=%u old=%u new=%u",
						npid, *oldid, id);

			}
		}

		ps->last_paramset_id = id;

		/* wake latency if any */
		__u64 *wts = bpf_map_lookup_elem(&wake_ts, &npid);
		if (wts && *wts) {
			/* Delegate computation, aggregation, warnings and detectors to helper */
			handle_wake_latency(cfg, npid, ts, id, next, ps);
			*wts = 0;
		}

		/* mark oncpu and period count */
		mark_oncpu_and_bump_periods(ps, cfg, id, ts, cpu);
	}

	return 0;
}


/* ---- migration accounting below ---- */

static __always_inline int classify_loc(__u32 from_cpu, __u32 to_cpu)
{
	__u32 *from_core, *to_core;
	__u32 *from_l2, *to_l2;
	__u32 *from_llc, *to_llc;
	__u32 *from_numa, *to_numa;

	if (from_cpu == to_cpu)
		return SC_ML_CORE; /* Degenerate case */

	/* Check SMT (same core) */
	from_core = bpf_map_lookup_elem(&cpu_core_id, &from_cpu);
	to_core = bpf_map_lookup_elem(&cpu_core_id, &to_cpu);
	if (from_core && to_core && *from_core == *to_core)
		return SC_ML_CORE; /* SMT migration */

	/* Check L2 cache domain */
	from_l2 = bpf_map_lookup_elem(&cpu_l2_id, &from_cpu);
	to_l2 = bpf_map_lookup_elem(&cpu_l2_id, &to_cpu);
	if (from_l2 && to_l2 && *from_l2 == *to_l2)
		return SC_ML_L2;

	/* Check LLC (Last Level Cache) domain */
	from_llc = bpf_map_lookup_elem(&cpu_llc_id, &from_cpu);
	to_llc = bpf_map_lookup_elem(&cpu_llc_id, &to_cpu);
	if (from_llc && to_llc && *from_llc == *to_llc)
		return SC_ML_LLC;

	/* Check NUMA domain */
	from_numa = bpf_map_lookup_elem(&cpu_numa_id, &from_cpu);
	to_numa = bpf_map_lookup_elem(&cpu_numa_id, &to_cpu);
	if (from_numa && to_numa && *from_numa != *to_numa)
		return SC_ML_XNUMA; /* Cross-NUMA migration */

	/* Default: cross-LLC but same NUMA */
	return SC_ML_XLLC;
}

static __always_inline void bump_migration(__u32 pid, int reason,
					   __u32 from_cpu, __u32 to_cpu)
{
	struct schedscore_pid_stats *ps;
	int loc;

	if (!pid)
		return;

	ps = bpf_map_lookup_elem(&stats, &pid);
	if (!ps) {
		__u32 zkey = 0;
		struct schedscore_pid_stats *z;

		z = bpf_map_lookup_elem(&zero_pid, &zkey);
		if (z)
			bpf_map_update_elem(&stats, &pid, z, BPF_NOEXIST);
		ps = bpf_map_lookup_elem(&stats, &pid);
		if (!ps)
			return;
	}

	loc = classify_loc(from_cpu, to_cpu);
	if (reason >= 0 && reason < SC_MR__COUNT &&
	    loc >= 0 && loc < SC_ML__COUNT)
		__sync_fetch_and_add(&ps->migr_grid[reason][loc], 1);

	ps->last_cpu = to_cpu;

	/* Mirror to paramset aggregate if enabled */
	__u32 k0 = 0; struct config *cfg = bpf_map_lookup_elem(&conf, &k0);
	if (cfg && cfg->aggregate_enable) {
		__u32 id = 0;
		__u32 *pid_id = bpf_map_lookup_elem(&pid_to_paramset, &pid);
		if (pid_id) id = *pid_id;
		if (!id) id = ps->last_paramset_id;
		if (id) {
			struct schedscore_paramset_stats *as = get_or_init_paramset_stats(id);
			if (as && reason >= 0 && reason < SC_MR__COUNT && loc >= 0 && loc < SC_ML__COUNT)
				__sync_fetch_and_add(&as->migr_grid[reason][loc], 1);
		}
	}

	/* detectors for migration locality */
	if (cfg) {
		if (loc == SC_ML_XNUMA && cfg->detect_migration_xnuma)
			bpf_printk("schedscore:detect_migration_xnuma pid=%d from_cpu=%u to_cpu=%u",
				pid, from_cpu, to_cpu);
		else if (loc == SC_ML_XLLC && cfg->detect_migration_xllc)
			bpf_printk("schedscore:detect_migration_xllc pid=%d from_cpu=%u to_cpu=%u",
				pid, from_cpu, to_cpu);
	}

}

SEC("tp_btf/sched_migrate_task")
int BPF_PROG(sched_migrate_task, struct task_struct *p, int dest_cpu)
{
	__u32 pid = BPF_CORE_READ(p, pid);
	if (!track_if_passing_filters(p, pid))
		return 0;
	int orig_cpu = BPF_CORE_READ(p, wake_cpu); /* best effort: previous CPU-of-record */
	bump_migration(pid, SC_MR_LB, orig_cpu, dest_cpu);
	return 0;
}

SEC("tp_btf/sched_move_numa")
int BPF_PROG(sched_move_numa, struct task_struct *p, int src_cpu, int dst_cpu)
{
	__u32 pid = BPF_CORE_READ(p, pid);
	if (!track_if_passing_filters(p, pid))
		return 0;
	bump_migration(pid, SC_MR_NUMA, src_cpu, dst_cpu);
	return 0;
}

SEC("tp_btf/sched_swap_numa")
int BPF_PROG(sched_swap_numa, struct task_struct *src_p, int src_cpu,
	     struct task_struct *dst_p, int dst_cpu)
{
	__u32 src_pid, dst_pid;
	struct config *cfg;
	__u32 k0 = 0;

	if (!src_p)
		return 0;

	src_pid = BPF_CORE_READ(src_p, pid);
	if (!track_if_passing_filters(src_p, src_pid))
		return 0;

	/* Detector: remote wakeup xNUMA at waking time */
	cfg = bpf_map_lookup_elem(&conf, &k0);
	if (cfg && cfg->detect_remote_wakeup_xnuma) {
		/* Remote-wakeup detector moved to sched_waking; no-op here */
	}

	bump_migration(src_pid, SC_MR_NUMA, src_cpu, dst_cpu);

	if (dst_p) {
		dst_pid = BPF_CORE_READ(dst_p, pid);
		if (track_if_passing_filters(dst_p, dst_pid))
			bump_migration(dst_pid, SC_MR_NUMA, dst_cpu, src_cpu);
	}

	return 0;
}

/* Augment waking to count wakeup-based migrations */
SEC("tp_btf/sched_waking")
int BPF_PROG(sched_waking_mig, struct task_struct *p)
{
	struct schedscore_pid_stats *ps;
	__u32 pid, last;
	int target_cpu;

	if (!p)
		return 0;

	pid = BPF_CORE_READ(p, pid);
	if (!track_if_passing_filters(p, pid))
		return 0;

	target_cpu = BPF_CORE_READ(p, wake_cpu);
	if (target_cpu < 0)
		return 0;

	ps = bpf_map_lookup_elem(&stats, &pid);
	last = ps ? ps->last_cpu : (__u32)target_cpu;

	if (last != (__u32)target_cpu)
		bump_migration(pid, SC_MR_WAKEUP, last, (__u32)target_cpu);

	return 0;
}
