// SPDX-License-Identifier: GPL-2.0-only
#ifndef SCHEDSCORE_OUTPUT_TABLE_H
#define SCHEDSCORE_OUTPUT_TABLE_H

#include <stdbool.h>
#include <linux/types.h>

struct schedscore_bpf;
struct schedscore_pid_stats;

/* Column selection and formatting helpers (shared) */
enum col_id {
	COL_PID,
	COL_COMM,
	COL_PARAMSET_ID,
	COL_P50_LAT,
	COL_AVG_LAT,
	COL_P95_LAT,
	COL_P99_LAT,
	COL_P50_ON,
	COL_AVG_ON,
	COL_P95_ON,
	COL_P99_ON,
	COL_NR_PERIODS,
	COL__COUNT
};

extern const char *col_name[COL__COUNT];

struct col_set { int idx[32]; int cnt; };

void compute_pid_table_widths(struct schedscore_bpf *skel, const struct col_set *cs, int *widths);
void print_table_header_w(const struct col_set *cs, const int *widths);
void print_table_row_w(const struct col_set *cs, const int *widths, __u32 pid, const struct schedscore_pid_stats *val,
                       double p50,double avg_lat,double p95,double p99,
                       double p50_on,double avg_on,double p95_on,double p99_on);
void dump_paramset_map_table(struct schedscore_bpf *skel, bool resolve_masks);
void dump_paramset_stats_table(struct schedscore_bpf *skel);
void dump_pid_migrations_matrix_table(struct schedscore_bpf *skel);
/* Temporarily keep this external to preserve behavior; will move to its own file or JSON/CVS later */
void dump_migrations_summary_table(struct schedscore_bpf *skel);

#endif /* SCHEDSCORE_OUTPUT_TABLE_H */

