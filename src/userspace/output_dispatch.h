// SPDX-License-Identifier: GPL-2.0-only
#ifndef SCHEDSCORE_OUTPUT_DISPATCH_H
#define SCHEDSCORE_OUTPUT_DISPATCH_H

struct schedscore_bpf;
struct opts;

int output_emit(struct schedscore_bpf *skel, const struct opts *o);

#endif /* SCHEDSCORE_OUTPUT_DISPATCH_H */

