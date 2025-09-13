// SPDX-License-Identifier: GPL-2.0-only
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include "../userspace/output_common.h"

int main(void)
{
    struct ss_snapshot s = {0};
    s.nr_pids = 1; s.pids[0].pid = 42; strcpy(s.pids[0].comm, "bar");
    s.pids[0].migr_grid[SC_MR_WAKEUP][SC_ML_CORE] = 3;
    s.nr_sets = 1; s.sets[0].paramset_id = 7;
    s.sets[0].migr_grid[SC_MR_NUMA][SC_ML_XNUMA] = 9;

    char buf[2048];
    FILE *mem = fmemopen(buf, sizeof(buf), "w"); assert(mem);
    output_csv_from_snapshot(mem, &s);
    fclose(mem);

    assert(strstr(buf, "pid_migrations_matrix_csv"));
    assert(strstr(buf, "paramset_migrations_matrix_csv"));
    assert(strstr(buf, "42,3,"));
    assert(strstr(buf, "7,"));
    /* NUMA/xnuma value 9 should appear in the paramset line */
    assert(strstr(buf, ",9"));
    printf("ok csv\n");
    return 0;
}

