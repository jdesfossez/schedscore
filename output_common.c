// SPDX-License-Identifier: GPL-2.0-only
#include "output_common.h"
#include <string.h>

static void fprint_migr_block(FILE *out, const uint64_t g[SC_MR__COUNT][SC_ML__COUNT])
{
    /* wakeup | loadbalance | numa with smt l2 llc xllc xnuma */
    fprintf(out, " | %llu %llu %llu %llu %llu",
            (unsigned long long)g[SC_MR_WAKEUP][SC_ML_CORE],
            (unsigned long long)g[SC_MR_WAKEUP][SC_ML_L2],
            (unsigned long long)g[SC_MR_WAKEUP][SC_ML_LLC],
            (unsigned long long)g[SC_MR_WAKEUP][SC_ML_XLLC],
            (unsigned long long)g[SC_MR_WAKEUP][SC_ML_XNUMA]);
    fprintf(out, " | %llu %llu %llu %llu %llu",
            (unsigned long long)g[SC_MR_LB][SC_ML_CORE],
            (unsigned long long)g[SC_MR_LB][SC_ML_L2],
            (unsigned long long)g[SC_MR_LB][SC_ML_LLC],
            (unsigned long long)g[SC_MR_LB][SC_ML_XLLC],
            (unsigned long long)g[SC_MR_LB][SC_ML_XNUMA]);
    fprintf(out, " | %llu %llu %llu %llu %llu",
            (unsigned long long)g[SC_MR_NUMA][SC_ML_CORE],
            (unsigned long long)g[SC_MR_NUMA][SC_ML_L2],
            (unsigned long long)g[SC_MR_NUMA][SC_ML_LLC],
            (unsigned long long)g[SC_MR_NUMA][SC_ML_XLLC],
            (unsigned long long)g[SC_MR_NUMA][SC_ML_XNUMA]);
}

int output_table_from_snapshot(FILE *out, const struct ss_snapshot *snap)
{
    /* Minimal printable verification: pid and paramset matrices only */
    fprintf(out, "pid_migrations_matrix_table\n");
    fprintf(out, "%-8s  %-16s  | %-23s | %-23s | %-23s\n", "pid", "comm", "wakeup", "loadbalance", "numa");
    fprintf(out, "%-8s  %-16s  | %-3s %-3s %-3s %-4s %-5s | %-3s %-3s %-3s %-4s %-5s | %-3s %-3s %-3s %-4s %-5s\n",
            "", "", "smt","l2","llc","xllc","xnuma",  "smt","l2","llc","xllc","xnuma",  "smt","l2","llc","xllc","xnuma");
    for (int i = 0; i < snap->nr_pids; i++) {
        const struct ss_pid_stats *p = &snap->pids[i];
        fprintf(out, "%-8u  %-16.16s", p->pid, p->comm);
        fprint_migr_block(out, p->migr_grid);
        fprintf(out, "\n");
    }

    fprintf(out, "\nparamset_migrations_matrix_table\n");
    fprintf(out, "%-12s | %-23s | %-23s | %-23s\n", "paramset_id", "wakeup", "loadbalance", "numa");
    fprintf(out, "%-12s | %-3s %-3s %-3s %-4s %-5s | %-3s %-3s %-3s %-4s %-5s | %-3s %-3s %-3s %-4s %-5s\n",
            "", "smt","l2","llc","xllc","xnuma",  "smt","l2","llc","xllc","xnuma",  "smt","l2","llc","xllc","xnuma");
    for (int i = 0; i < snap->nr_sets; i++) {
        const struct ss_paramset_stats *s = &snap->sets[i];
        fprintf(out, "%-12u", s->paramset_id);
        fprint_migr_block(out, s->migr_grid);
        fprintf(out, "\n");
    }

    return 0;
}

int output_csv_from_snapshot(FILE *out, const struct ss_snapshot *snap)
{
    /* Basic CSV coverage: per-pid and per-paramset matrix rows only */
    fprintf(out, "pid_migrations_matrix_csv\n");
    fprintf(out, "pid,wk/smt,wk/l2,wk/llc,wk/xllc,wk/xnuma,lb/smt,lb/l2,lb/llc,lb/xllc,lb/xnuma,numa/smt,numa/l2,numa/llc,numa/xllc,numa/xnuma\n");
    for (int i = 0; i < snap->nr_pids; i++) {
        const struct ss_pid_stats *p = &snap->pids[i];
        fprintf(out, "%u,", p->pid);
        fprintf(out, "%llu,%llu,%llu,%llu,%llu,",
            (unsigned long long)p->migr_grid[SC_MR_WAKEUP][SC_ML_CORE],
            (unsigned long long)p->migr_grid[SC_MR_WAKEUP][SC_ML_L2],
            (unsigned long long)p->migr_grid[SC_MR_WAKEUP][SC_ML_LLC],
            (unsigned long long)p->migr_grid[SC_MR_WAKEUP][SC_ML_XLLC],
            (unsigned long long)p->migr_grid[SC_MR_WAKEUP][SC_ML_XNUMA]);
        fprintf(out, "%llu,%llu,%llu,%llu,%llu,",
            (unsigned long long)p->migr_grid[SC_MR_LB][SC_ML_CORE],
            (unsigned long long)p->migr_grid[SC_MR_LB][SC_ML_L2],
            (unsigned long long)p->migr_grid[SC_MR_LB][SC_ML_LLC],
            (unsigned long long)p->migr_grid[SC_MR_LB][SC_ML_XLLC],
            (unsigned long long)p->migr_grid[SC_MR_LB][SC_ML_XNUMA]);
        fprintf(out, "%llu,%llu,%llu,%llu,%llu\n",
            (unsigned long long)p->migr_grid[SC_MR_NUMA][SC_ML_CORE],
            (unsigned long long)p->migr_grid[SC_MR_NUMA][SC_ML_L2],
            (unsigned long long)p->migr_grid[SC_MR_NUMA][SC_ML_LLC],
            (unsigned long long)p->migr_grid[SC_MR_NUMA][SC_ML_XLLC],
            (unsigned long long)p->migr_grid[SC_MR_NUMA][SC_ML_XNUMA]);
    }

    fprintf(out, "paramset_migrations_matrix_csv\n");
    fprintf(out, "paramset_id,wk/smt,wk/l2,wk/llc,wk/xllc,wk/xnuma,lb/smt,lb/l2,lb/llc,lb/xllc,lb/xnuma,numa/smt,numa/l2,numa/llc,numa/xllc,numa/xnuma\n");
    for (int i = 0; i < snap->nr_sets; i++) {
        const struct ss_paramset_stats *s = &snap->sets[i];
        fprintf(out, "%u,", s->paramset_id);
        fprintf(out, "%llu,%llu,%llu,%llu,%llu,",
            (unsigned long long)s->migr_grid[SC_MR_WAKEUP][SC_ML_CORE],
            (unsigned long long)s->migr_grid[SC_MR_WAKEUP][SC_ML_L2],
            (unsigned long long)s->migr_grid[SC_MR_WAKEUP][SC_ML_LLC],
            (unsigned long long)s->migr_grid[SC_MR_WAKEUP][SC_ML_XLLC],
            (unsigned long long)s->migr_grid[SC_MR_WAKEUP][SC_ML_XNUMA]);
        fprintf(out, "%llu,%llu,%llu,%llu,%llu,",
            (unsigned long long)s->migr_grid[SC_MR_LB][SC_ML_CORE],
            (unsigned long long)s->migr_grid[SC_MR_LB][SC_ML_L2],
            (unsigned long long)s->migr_grid[SC_MR_LB][SC_ML_LLC],
            (unsigned long long)s->migr_grid[SC_MR_LB][SC_ML_XLLC],
            (unsigned long long)s->migr_grid[SC_MR_LB][SC_ML_XNUMA]);
        fprintf(out, "%llu,%llu,%llu,%llu,%llu\n",
            (unsigned long long)s->migr_grid[SC_MR_NUMA][SC_ML_CORE],
            (unsigned long long)s->migr_grid[SC_MR_NUMA][SC_ML_L2],
            (unsigned long long)s->migr_grid[SC_MR_NUMA][SC_ML_LLC],
            (unsigned long long)s->migr_grid[SC_MR_NUMA][SC_ML_XLLC],
            (unsigned long long)s->migr_grid[SC_MR_NUMA][SC_ML_XNUMA]);
    }

    return 0;
}

int output_json_from_snapshot(FILE *out, const struct ss_snapshot *snap)
{
    /* Minimal JSON verification: emit only migrations_by_locality and grid */
    fprintf(out, "{\n  \"paramset_stats\": [\n");
    for (int i = 0; i < snap->nr_sets; i++) {
        const struct ss_paramset_stats *s = &snap->sets[i];
        unsigned long long l_smt=0,l2=0,l_llc=0,l_xllc=0,l_xnuma=0;
        for (int r = 0; r < SC_MR__COUNT; r++) {
            l_smt  += s->migr_grid[r][SC_ML_CORE];
            l2     += s->migr_grid[r][SC_ML_L2];
            l_llc  += s->migr_grid[r][SC_ML_LLC];
            l_xllc += s->migr_grid[r][SC_ML_XLLC];
            l_xnuma+= s->migr_grid[r][SC_ML_XNUMA];
        }
        fprintf(out,
            "%s    {\"paramset_id\":%u,\"migrations_by_locality\":{\"smt\":%llu,\"l2\":%llu,\"llc\":%llu,\"xllc\":%llu,\"xnuma\":%llu},\"migrations_grid\":{\"wakeup\":{\"smt\":%llu,\"l2\":%llu,\"llc\":%llu,\"xllc\":%llu,\"xnuma\":%llu},\"lb\":{\"smt\":%llu,\"l2\":%llu,\"llc\":%llu,\"xllc\":%llu,\"xnuma\":%llu},\"numa\":{\"smt\":%llu,\"l2\":%llu,\"llc\":%llu,\"xllc\":%llu,\"xnuma\":%llu}}}\n",
            i?",":"", s->paramset_id,
            l_smt,l2,l_llc,l_xllc,l_xnuma,
            (unsigned long long)s->migr_grid[SC_MR_WAKEUP][SC_ML_CORE], (unsigned long long)s->migr_grid[SC_MR_WAKEUP][SC_ML_L2], (unsigned long long)s->migr_grid[SC_MR_WAKEUP][SC_ML_LLC], (unsigned long long)s->migr_grid[SC_MR_WAKEUP][SC_ML_XLLC], (unsigned long long)s->migr_grid[SC_MR_WAKEUP][SC_ML_XNUMA],
            (unsigned long long)s->migr_grid[SC_MR_LB][SC_ML_CORE],     (unsigned long long)s->migr_grid[SC_MR_LB][SC_ML_L2],     (unsigned long long)s->migr_grid[SC_MR_LB][SC_ML_LLC],     (unsigned long long)s->migr_grid[SC_MR_LB][SC_ML_XLLC],     (unsigned long long)s->migr_grid[SC_MR_LB][SC_ML_XNUMA],
            (unsigned long long)s->migr_grid[SC_MR_NUMA][SC_ML_CORE],   (unsigned long long)s->migr_grid[SC_MR_NUMA][SC_ML_L2],   (unsigned long long)s->migr_grid[SC_MR_NUMA][SC_ML_LLC],   (unsigned long long)s->migr_grid[SC_MR_NUMA][SC_ML_XLLC],   (unsigned long long)s->migr_grid[SC_MR_NUMA][SC_ML_XNUMA]);
    }
    fprintf(out, "  ]\n}\n");
    return 0;
}

