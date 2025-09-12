// SPDX-License-Identifier: GPL-2.0-only
#ifndef SCHEDSCORE_TOPO_H
#define SCHEDSCORE_TOPO_H

#include "schedscore.skel.h"

int push_cpu_topology(struct schedscore_bpf *skel);
void dump_topology_table(struct schedscore_bpf *skel);

#endif /* SCHEDSCORE_TOPO_H */

