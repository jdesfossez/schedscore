// SPDX-License-Identifier: GPL-2.0-only
#ifndef SCHEDSCORE_OUTPUT_JSON_H
#define SCHEDSCORE_OUTPUT_JSON_H

#include <linux/types.h>
#include <stdbool.h>
#include "opts.h"
struct schedscore_bpf;

int dump_json(struct schedscore_bpf *skel, const struct opts *o);

#endif /* SCHEDSCORE_OUTPUT_JSON_H */

