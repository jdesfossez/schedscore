// SPDX-License-Identifier: GPL-2.0-only
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "../bpf/schedscore.skel.h"
#include "topo.h"

static int read_uint_file(const char *path, unsigned int *out)
{
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    unsigned int v = 0; int rc = fscanf(f, "%u", &v);
    fclose(f);
    if (rc == 1) { *out = v; return 0; }
    return -1;
}

static int cpu_in_cpulist(const char *s, int cpu)
{
    const char *p = s;
    while (*p) {
        while (*p == ' ' || *p == '\t' || *p == '\n' || *p == ',') p++;
        if (!*p) break;
        long a = -1, b = -1; char *endp = NULL;
        a = strtol(p, &endp, 10);
        if (endp && *endp == '-') {
            p = endp + 1;
            b = strtol(p, &endp, 10);
            if (a >= 0 && b >= 0 && cpu >= a && cpu <= b) return 1;
        } else {
            if (a >= 0 && cpu == a) return 1;
            p = endp ? endp : p+1;
        }
        p = endp ? endp : p;
    }
    return 0;
}

static int detect_numa_id(int cpu, unsigned int *numa_id)
{
    char path[256]; char buf[4096];
    for (unsigned int node = 0; node < 1024; node++) {
        snprintf(path, sizeof(path), "/sys/devices/system/node/node%u/cpulist", node);
        FILE *f = fopen(path, "r");
        if (!f) continue;
        size_t n = fread(buf, 1, sizeof(buf)-1, f);
        fclose(f);
        if (n == 0) continue;
        buf[n] = '\0';
        if (cpu_in_cpulist(buf, cpu)) { *numa_id = node; return 0; }
    }
    return -1;
}

static int detect_l2_id(int cpu, unsigned int *l2_id)
{
    char p[256];
    unsigned int best_id=0;
    for (int idx = 0; idx < 10; idx++) {
        snprintf(p, sizeof(p), "/sys/devices/system/cpu/cpu%d/cache/index%d/type", cpu, idx);
        FILE *f = fopen(p, "r"); if (!f) continue;
        char typebuf[32] = {0}; if (!fgets(typebuf, sizeof(typebuf), f)) { fclose(f); continue; }
        fclose(f);
        if (!strstr(typebuf, "Unified")) continue;
        snprintf(p, sizeof(p), "/sys/devices/system/cpu/cpu%d/cache/index%d/level", cpu, idx);
        unsigned int lvl=0; if (read_uint_file(p, &lvl)) continue;
        if (lvl == 2) {
            snprintf(p, sizeof(p), "/sys/devices/system/cpu/cpu%d/cache/index%d/id", cpu, idx);
            if (read_uint_file(p, &best_id) == 0) { *l2_id = best_id; return 0; }
        }
    }
    return -1;
}

static int detect_llc_highest(int cpu, unsigned int *llc_id)
{
    char p[256]; unsigned int best_id=0, best_lvl=0;
    for (int idx = 0; idx < 10; idx++) {
        snprintf(p, sizeof(p), "/sys/devices/system/cpu/cpu%d/cache/index%d/type", cpu, idx);
        FILE *f = fopen(p, "r"); if (!f) continue;
        char typebuf[32] = {0}; if (!fgets(typebuf, sizeof(typebuf), f)) { fclose(f); continue; }
        fclose(f);
        if (!strstr(typebuf, "Unified")) continue;
        snprintf(p, sizeof(p), "/sys/devices/system/cpu/cpu%d/cache/index%d/level", cpu, idx);
        unsigned int lvl=0; if (read_uint_file(p, &lvl)) continue;
        if (lvl >= best_lvl) {
            snprintf(p, sizeof(p), "/sys/devices/system/cpu/cpu%d/cache/index%d/id", cpu, idx);
            unsigned int id; if (read_uint_file(p, &id)) continue;
            best_lvl = lvl; best_id = id;
        }
    }
    if (best_lvl) { *llc_id = best_id; return 0; }
    return -1;
}

int push_cpu_topology(struct schedscore_bpf *skel)
{
    long nproc = sysconf(_SC_NPROCESSORS_CONF);
    if (nproc <= 0 || nproc > 4096) nproc = 4096;
    int core_fd = bpf_map__fd(skel->maps.cpu_core_id);
    int llc_fd  = bpf_map__fd(skel->maps.cpu_llc_id);
    int l2_fd   = bpf_map__fd(skel->maps.cpu_l2_id);
    int numa_fd = bpf_map__fd(skel->maps.cpu_numa_id);
    if (core_fd < 0 || llc_fd < 0 || l2_fd < 0 || numa_fd < 0)
        return -1;
    for (int cpu = 0; cpu < nproc; cpu++) {
        char p[256]; unsigned int core_id=0, pkg_id=0, llc_id=0, l2_id=0, core_key=0, numa_id=0;
        snprintf(p, sizeof(p), "/sys/devices/system/cpu/cpu%d/topology/core_id", cpu);
        read_uint_file(p, &core_id);
        snprintf(p, sizeof(p), "/sys/devices/system/cpu/cpu%d/topology/physical_package_id", cpu);
        read_uint_file(p, &pkg_id);
        core_key = (pkg_id << 16) | (core_id & 0xFFFF);
        if (detect_llc_highest(cpu, &llc_id) != 0)
            llc_id = (pkg_id << 16);
        if (detect_l2_id(cpu, &l2_id) != 0)
            l2_id = core_key;
        if (detect_numa_id(cpu, &numa_id) != 0) {
            snprintf(p, sizeof(p), "/sys/devices/system/cpu/cpu%d/topology/physical_package_id", cpu);
            read_uint_file(p, &numa_id);
        }
        __u32 k = cpu;
        (void)bpf_map_update_elem(core_fd, &k, &core_key, BPF_ANY);
        (void)bpf_map_update_elem(llc_fd,  &k, &llc_id,   BPF_ANY);
        (void)bpf_map_update_elem(l2_fd,   &k, &l2_id,    BPF_ANY);
        (void)bpf_map_update_elem(numa_fd, &k, &numa_id,  BPF_ANY);
    }
    return 0;
}

void dump_topology_table(struct schedscore_bpf *skel)
{
    int core_fd = bpf_map__fd(skel->maps.cpu_core_id);
    int l2_fd   = bpf_map__fd(skel->maps.cpu_l2_id);
    int llc_fd  = bpf_map__fd(skel->maps.cpu_llc_id);
    int numa_fd = bpf_map__fd(skel->maps.cpu_numa_id);
    long nproc = sysconf(_SC_NPROCESSORS_CONF);
    if (nproc <= 0 || nproc > 4096) nproc = 4096;

    printf("\ntopology_table\n");
    int w_cpu = 4, w_id = 10; /* cpu as %-4d, ids shown as 0x%08x, two spaces between */
    printf("%-*s  %-*s  %-*s  %-*s  %-*s\n",
           w_cpu, "cpu", w_id, "smt(core_id)", w_id, "l2_id", w_id, "llc_id", w_id, "numa_id");
    for (int cpu = 0; cpu < nproc; cpu++) {
        __u32 k = cpu; __u32 core=0,l2=0,llc=0,numa=0;
        (void)bpf_map_lookup_elem(core_fd, &k, &core);
        (void)bpf_map_lookup_elem(l2_fd,   &k, &l2);
        (void)bpf_map_lookup_elem(llc_fd,  &k, &llc);
        (void)bpf_map_lookup_elem(numa_fd, &k, &numa);
        printf("%-*d  0x%08x  0x%08x  0x%08x  0x%08x\n",
               w_cpu, cpu, core, l2, llc, numa);
    }

    printf("\ntopology_summary\n");
    __u32 core_ids[4096], l2_ids[4096], llc_ids[4096], numa_ids[4096];
    __u32 cores=0,l2s=0,llcs=0,numas=0;
    for (int cpu = 0; cpu < nproc; cpu++) {
        __u32 k = cpu; __u32 core=0,l2=0,llc=0,numa=0;
        (void)bpf_map_lookup_elem(core_fd, &k, &core);
        (void)bpf_map_lookup_elem(l2_fd,   &k, &l2);
        (void)bpf_map_lookup_elem(llc_fd,  &k, &llc);
        (void)bpf_map_lookup_elem(numa_fd, &k, &numa);
        bool found=false; for (__u32 i=0;i<cores;i++){ if (core_ids[i]==core){found=true;break;} } if(!found) core_ids[cores++]=core;
        found=false; for (__u32 i=0;i<l2s;i++){ if (l2_ids[i]==l2){found=true;break;} } if(!found) l2_ids[l2s++]=l2;
        found=false; for (__u32 i=0;i<llcs;i++){ if (llc_ids[i]==llc){found=true;break;} } if(!found) llc_ids[llcs++]=llc;
        found=false; for (__u32 i=0;i<numas;i++){ if (numa_ids[i]==numa){found=true;break;} } if(!found) numa_ids[numas++]=numa;
    }
    printf("cpus=%ld smt_cores=%u l2_domains=%u llc_domains=%u numa_nodes=%u\n", nproc, cores, l2s, llcs, numas);
}


