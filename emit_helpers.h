// SPDX-License-Identifier: GPL-2.0-only
#ifndef SCHEDSCORE_EMIT_HELPERS_H
#define SCHEDSCORE_EMIT_HELPERS_H

#include <linux/types.h>
#include <stddef.h>

/* schedscore_hist.h must be included by each TU before including this header */

#ifdef __cplusplus
extern "C" {
#endif

double quantile_from_hist(const __u32 *hist, int buckets, double q);
void compute_metrics(const __u32 *lat_hist, __u64 lat_sum, __u64 lat_cnt,
                     __u64 runtime_ns, __u32 nr_periods,
                     double *p50, double *p95, double *p99,
                     double *avg_lat, double *avg_on);
void compute_oncpu_quantiles(const __u32 *on_hist,
                             double *p50_on, double *p95_on, double *p99_on);
const char *policy_name(int pol);
void mask_to_ranges(const unsigned long long m[4], char *buf, size_t bufsz);
unsigned int count_pids_for_paramset(int pid2set_fd, __u32 set_id);

#ifdef __cplusplus
}
#endif

#endif /* SCHEDSCORE_EMIT_HELPERS_H */

