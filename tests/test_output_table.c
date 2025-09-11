// SPDX-License-Identifier: GPL-2.0-only
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include "output_common.h"

int main(void)
{
    struct ss_snapshot s = {0};
    s.nr_pids = 1; s.pids[0].pid = 1234; strcpy(s.pids[0].comm, "foo");
    s.pids[0].migr_grid[SC_MR_WAKEUP][SC_ML_CORE] = 1;
    s.nr_sets = 1; s.sets[0].paramset_id = 1;
    s.sets[0].migr_grid[SC_MR_LB][SC_ML_L2] = 2;

    char buf[2048];
    FILE *mem = fmemopen(buf, sizeof(buf), "w"); assert(mem);
    output_table_from_snapshot(mem, &s);
    fclose(mem);

    /* Expect headers and at least some numbers */
    assert(strstr(buf, "pid_migrations_matrix_table"));
    assert(strstr(buf, "paramset_migrations_matrix_table"));
    /* Snapshot uses compact widths: ensure labels appear */
    assert(strstr(buf, "smt"));
    assert(strstr(buf, "l2"));
    assert(strstr(buf, "llc"));
    assert(strstr(buf, "xllc"));
    assert(strstr(buf, "xnuma"));
    /* Expect pid wk/smt=1 and paramset lb/l2=2 somewhere in the blocks */
    assert(strstr(buf, "| 1 0 0 0 0"));
    assert(strstr(buf, "| 0 2 0 0 0"));
    printf("ok table\n");
    return 0;
}

