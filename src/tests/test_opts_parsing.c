// SPDX-License-Identifier: GPL-2.0-only
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include "../userspace/opts.h"
#include "../userspace/opts_parse.h"

int main(void)
{
    printf("Starting opts parsing test\n");

    /* Just test that we can call parse_opts without crashing */
    struct opts o;
    char **target_argv;
    char *argv[] = {"schedscore", "--show-migration-matrix", "--", "ls", NULL};
    int result = parse_opts(4, argv, &o, &target_argv);

    printf("parse_opts returned %d\n", result);
    printf("show_migration_matrix = %d\n", o.show_migration_matrix);
    printf("show_pid_migration_matrix = %d\n", o.show_pid_migration_matrix);
    printf("paramset_recheck = %d\n", o.paramset_recheck);

    if (result == 0 && o.show_migration_matrix == 1) {
        printf("ok opts_parsing\n");
        return 0;
    } else {
        printf("FAIL: expected show_migration_matrix=1, got %d\n", o.show_migration_matrix);
        return 1;
    }
}
