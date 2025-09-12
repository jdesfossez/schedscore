// SPDX-License-Identifier: GPL-2.0-only
#include <stdio.h>
#include <string.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "schedscore.skel.h"
#include "schedscore_hist.h"
#include "schedscore_uapi.h"
#include "emit_helpers.h"
#include "output_json.h"

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

int dump_json(struct schedscore_bpf *skel, const struct opts *o)
{
    (void)o; /* current JSON output does not depend on opts */
    int info_fd = bpf_map__fd(skel->maps.paramset_info);
    int stats_fd = bpf_map__fd(skel->maps.stats_by_paramset);
    int pid_fd = bpf_map__fd(skel->maps.stats);
    int pid2set_fd = bpf_map__fd(skel->maps.pid_to_paramset);
    __u32 key = 0, next = 0;
    int err;
    struct schedscore_pid_stats val;
    char cpus[512], mems[512];
    printf("{\n");
    printf("  \"format\": \"json\",\n");
    /* Retain paramset_map for backward compatibility, but details are embedded per-stat */
    printf("  \"paramset_map\": [\n");
    key = next = 0;
    int first = 1;
    while ((err = bpf_map_get_next_key(info_fd, &key, &next)) == 0) {
        struct schedscore_paramset_info info;
        if (bpf_map_lookup_elem(info_fd, &next, &info) == 0) {
            cpus[0] = mems[0] = '\0';
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

    /* Paramset stats with embedded paramset info */
    printf("  \"paramset_stats\": [\n");
    key = next = 0;
    first = 1;
    while ((err = bpf_map_get_next_key(stats_fd, &key, &next)) == 0) {
        struct schedscore_paramset_stats st;
        if (bpf_map_lookup_elem(stats_fd, &next, &st) == 0) {
            double p50 = 0, p95 = 0, p99 = 0, avg_lat = 0, avg_on = 0;
            compute_metrics(st.lat_hist, st.wake_lat_sum_ns, st.wake_lat_cnt,
                            st.runtime_ns, st.nr_periods,
                            &p50, &p95, &p99, &avg_lat, &avg_on);
            double p50_on = 0, p95_on = 0, p99_on = 0;
            compute_oncpu_quantiles(st.on_hist, &p50_on, &p95_on, &p99_on);
            unsigned int cnt = 0; /* pid count */
            __u32 k = 0, n = 0, id = 0;
            int er2;
            while ((er2 = bpf_map_get_next_key(pid2set_fd, &k, &n)) == 0) {
                if (bpf_map_lookup_elem(pid2set_fd, &n, &id) == 0 && id == next)
                    cnt++;
                k = n;
            }
            /* Embed paramset details as expected by snapshot */
            struct schedscore_paramset_info info; int have_info = (bpf_map_lookup_elem(info_fd, &next, &info) == 0);
            char cpus2[512] = "", mems2[512] = "";
            if (have_info) {
                mask_to_ranges(info.key.cpus_mask, cpus2, sizeof(cpus2));
                mask_to_ranges(info.key.mems_mask, mems2, sizeof(mems2));
            }
            printf("%s    {\"paramset_id\":%u,\"details\":{\"policy\":\"%s\",\"nice\":%d,\"rtprio\":%u,\"dl_runtime_ns\":%llu,\"dl_deadline_ns\":%llu,\"dl_period_ns\":%llu,\"uclamp_min\":%u,\"uclamp_max\":%u,\"cgroup_id\":%llu,\"cpus_ranges\":\"%s\",\"cpus_weight\":%u,\"mems_ranges\":\"%s\",\"mems_weight\":%u},\"pids\":%u,\"p50_sched_latency_ns\":%.0f,\"avg_sched_latency_ns\":%.0f,\"p95_sched_latency_ns\":%.0f,\"p99_sched_latency_ns\":%.0f,\"p50_oncpu_ns\":%.0f,\"avg_oncpu_ns\":%.0f,\"p95_oncpu_ns\":%.0f,\"p99_oncpu_ns\":%.0f,\"nr_sched_periods\":%u}\n",
                   first?"":",",
                   next,
                   have_info?policy_name(info.key.policy):"", have_info?info.key.nice:0, have_info?info.key.rtprio:0,
                   (unsigned long long)(have_info?info.key.dl_runtime:0ULL),
                   (unsigned long long)(have_info?info.key.dl_deadline:0ULL),
                   (unsigned long long)(have_info?info.key.dl_period:0ULL),
                   have_info?info.key.uclamp_min:0, have_info?info.key.uclamp_max:0,
                   (unsigned long long)(have_info?info.key.cgroup_id:0ULL),
                   cpus2, have_info?info.key.cpus_weight:0, mems2, have_info?info.key.mems_weight:0,
                   cnt, p50, avg_lat, p95, p99, p50_on, avg_on, p95_on, p99_on, st.nr_periods);
            first=0;
        }
        key = next;
    }
    printf("  ],\n");

    /* Per-pid section */
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

