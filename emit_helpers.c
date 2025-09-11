// SPDX-License-Identifier: GPL-2.0-only
#include <stdio.h>
#include <string.h>
#include <bpf/bpf.h>
#include "schedscore_hist.h"
#include "emit_helpers.h"

/* Convert linear, power-of-two width histograms back to approximate ns quantiles.
 *
 * For a histogram with width_shift and N buckets, representative value for bin i is
 * rep_ns = (i + 0.5) << width_shift. Callsite should pass the right bucket count
 * and we infer width_shift from whether it's a latency or oncpu histogram.
 */
double quantile_from_hist(const __u32 *hist, int buckets, double q)
{
	unsigned long total = 0, tgt, cum = 0;
	int i;

	for (i = 0; i < buckets; i++)
		total += hist[i];

	if (!total)
		return 0.0;


	if (q < 0.0) q = 0.0;
	else if (q > 1.0) q = 1.0;

	tgt = (unsigned long)(q * (double)total + 0.5);

	for (i = 0; i < buckets; i++) {
		cum += hist[i];
		if (cum >= tgt) {
			/* Decide which width_shift: caller passes buckets; we assume LAT vs ON by size */
			int width_shift = (buckets == LAT_BUCKETS) ? LAT_WIDTH_SHIFT : ON_WIDTH_SHIFT;
			double rep = ((double)i + 0.5) * (double)(1ULL << width_shift);
			return rep;
		}
	}

	return 0.0;
}

void compute_metrics(const __u32 *lat_hist, __u64 lat_sum, __u64 lat_cnt,
                     __u64 runtime_ns, __u32 nr_periods,
                     double *p50, double *p95, double *p99,
                     double *avg_lat, double *avg_on)
{
    if (p50) *p50 = quantile_from_hist(lat_hist, LAT_BUCKETS, 0.50);
    if (p95) *p95 = quantile_from_hist(lat_hist, LAT_BUCKETS, 0.95);
    if (p99) *p99 = quantile_from_hist(lat_hist, LAT_BUCKETS, 0.99);
    if (avg_lat) *avg_lat = lat_cnt ? (double)lat_sum / (double)lat_cnt : 0.0;
    if (avg_on) *avg_on = nr_periods ? (double)runtime_ns / (double)nr_periods : 0.0;
}

void compute_oncpu_quantiles(const __u32 *on_hist,
                             double *p50_on, double *p95_on, double *p99_on)
{
    if (p50_on) *p50_on = quantile_from_hist(on_hist, ON_BUCKETS, 0.50);
    if (p95_on) *p95_on = quantile_from_hist(on_hist, ON_BUCKETS, 0.95);
    if (p99_on) *p99_on = quantile_from_hist(on_hist, ON_BUCKETS, 0.99);
}

const char *policy_name(int pol)
{
    switch (pol) {
    case 0: return "SCHED_OTHER"; case 1: return "SCHED_FIFO";
    case 2: return "SCHED_RR";    case 3: return "SCHED_BATCH";
    case 5: return "SCHED_IDLE";  case 6: return "SCHED_DEADLINE";
    default: return "SCHED_UNKNOWN";
    }
}

void mask_to_ranges(const unsigned long long m[4], char *buf, size_t bufsz)
{
    int first = -1; size_t off = 0;
    for (int i = 0; i < 256; i++) {
        int set = (m[i>>6] >> (i & 63)) & 1ULL;
        if (set && first < 0) first = i;
        else if (!set && first >= 0) {
            int last = i - 1;
            off += snprintf(buf + off, bufsz > off ? bufsz - off : 0,
                           off ? ",%d%s%d" : "%d%s%d",
                           first, (last > first ? "-" : ","),
                           last > first ? last : first);
            first = -1;
        }
    }
    if (first >= 0)
        snprintf(buf + off, bufsz > off ? bufsz - off : 0,
                 off ? ",%d-%d" : "%d-%d", first, 255);
}

unsigned int count_pids_for_paramset(int pid2set_fd, __u32 set_id)
{
    __u32 k = 0, n = 0, id = 0; unsigned int cnt = 0; int err;
    while ((err = bpf_map_get_next_key(pid2set_fd, &k, &n)) == 0) {
        if (bpf_map_lookup_elem(pid2set_fd, &n, &id) == 0 && id == set_id)
            cnt++;
        k = n;
    }
    return cnt;
}

