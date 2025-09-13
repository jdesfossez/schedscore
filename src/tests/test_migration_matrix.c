// SPDX-License-Identifier: GPL-2.0-only
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include "../userspace/output_common.h"

int main(void)
{
    struct ss_snapshot s = {0};
    
    /* Create test data with migration counts */
    s.nr_sets = 2;
    
    /* Paramset 1: some wakeup migrations */
    s.sets[0].paramset_id = 1;
    s.sets[0].migr_grid[SC_MR_WAKEUP][SC_ML_CORE] = 5;   /* wakeup/smt */
    s.sets[0].migr_grid[SC_MR_WAKEUP][SC_ML_L2] = 3;     /* wakeup/l2 */
    s.sets[0].migr_grid[SC_MR_LB][SC_ML_LLC] = 2;        /* lb/llc */
    s.sets[0].migr_grid[SC_MR_NUMA][SC_ML_XNUMA] = 1;    /* numa/xnuma */
    
    /* Paramset 2: different migration pattern */
    s.sets[1].paramset_id = 2;
    s.sets[1].migr_grid[SC_MR_WAKEUP][SC_ML_XLLC] = 4;   /* wakeup/xllc */
    s.sets[1].migr_grid[SC_MR_LB][SC_ML_L2] = 6;         /* lb/l2 */
    s.sets[1].migr_grid[SC_MR_LB][SC_ML_CORE] = 2;       /* lb/smt */

    char buf[4096];
    FILE *mem = fmemopen(buf, sizeof(buf), "w"); 
    assert(mem);
    output_table_from_snapshot(mem, &s);
    fclose(mem);

    /* Check that basic migration matrices are present (this is what snapshot testing covers) */
    assert(strstr(buf, "pid_migrations_matrix_table"));
    assert(strstr(buf, "paramset_migrations_matrix_table"));

    /* Check that the paramset data is correctly formatted */
    assert(strstr(buf, "1            | 5 3 0 0 0 | 0 0 2 0 0 | 0 0 0 0 1"));
    assert(strstr(buf, "2            | 0 0 0 4 0 | 2 6 0 0 0 | 0 0 0 0 0"));

    printf("ok migration_matrix\n");
    return 0;
}
