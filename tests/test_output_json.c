// SPDX-License-Identifier: GPL-2.0-only
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include "output_common.h"

int main(void)
{
    struct ss_snapshot s = {0};
    s.nr_sets = 1; s.sets[0].paramset_id = 5;
    s.sets[0].migr_grid[SC_MR_WAKEUP][SC_ML_CORE] = 1;
    s.sets[0].migr_grid[SC_MR_LB][SC_ML_L2] = 2;
    s.sets[0].migr_grid[SC_MR_NUMA][SC_ML_LLC] = 3;
    s.sets[0].migr_grid[SC_MR_NUMA][SC_ML_XLLC] = 4;
    s.sets[0].migr_grid[SC_MR_NUMA][SC_ML_XNUMA] = 5;

    char buf[4096];
    FILE *mem = fmemopen(buf, sizeof(buf), "w"); assert(mem);
    output_json_from_snapshot(mem, &s);
    fclose(mem);

    assert(strstr(buf, "\"paramset_id\":5"));
    assert(strstr(buf, "\"migrations_by_locality\""));
    assert(strstr(buf, "\"smt\":1"));
    assert(strstr(buf, "\"l2\":2"));
    assert(strstr(buf, "\"llc\":3"));
    assert(strstr(buf, "\"xllc\":4"));
    assert(strstr(buf, "\"xnuma\":5"));
    assert(strstr(buf, "\"wakeup\""));
    assert(strstr(buf, "\"lb\""));
    assert(strstr(buf, "\"numa\""));
    printf("ok json\n");
    return 0;
}

