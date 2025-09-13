// SPDX-License-Identifier: GPL-2.0-only
#ifndef SCHEDSCORE_OUTPUT_CSV_H
#define SCHEDSCORE_OUTPUT_CSV_H

#include <linux/types.h>
#include <stdbool.h>

struct schedscore_bpf;

void dump_paramset_csv(struct schedscore_bpf *skel, bool resolve_masks);
void dump_migrations_csv(struct schedscore_bpf *skel, bool show_migration_matrix);

#endif /* SCHEDSCORE_OUTPUT_CSV_H */

