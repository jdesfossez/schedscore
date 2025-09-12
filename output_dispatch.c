// SPDX-License-Identifier: GPL-2.0-only
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <linux/limits.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "schedscore.skel.h"
#include "schedscore_hist.h"
#include "schedscore_uapi.h"
#include "emit_helpers.h"
#include "output_table.h"
#include "output_csv.h"
#include "output_json.h"
#include "opts.h"
#include "output_dispatch.h"



/* Local utilities originally in schedscore.c */
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

/* Full output path dispatcher */
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
        dump_migrations_csv(skel, o->show_migration_matrix);
    } else if (strcmp(fmt, "table") == 0) {
        /* Per-PID matrix comes immediately after the per-PID main table */
        dump_pid_migrations_matrix_table(skel);

        /* Paramset map and stats */
        dump_paramset_map_table(skel, true);
        dump_paramset_stats_table(skel);

        /* Paramset migration matrix (by-paramset grid) */
        if (o->show_migration_matrix)
            dump_paramset_migrations_matrix_table(skel);

        /* Summary */
        dump_migrations_summary_table(skel);
    }

    /* After printing all sections, warn if any top-bin clamping occurred */
    warn_on_clamps(skel);

    return 0;
}

int output_emit(struct schedscore_bpf *skel, const struct opts *o)
{
    return dump_output(skel, o);
}
