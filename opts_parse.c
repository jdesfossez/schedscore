// SPDX-License-Identifier: GPL-2.0-only
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include "opts.h"
#include "opts_parse.h"

static unsigned long long parse_time_to_ns(const char *s)
{
    char *end = NULL;
    unsigned long long v = strtoull(s, &end, 10);
    if (end == s) return 0ULL;
    if (*end == '\0' || strcmp(end, "ns") == 0) return v;
    if (strcmp(end, "us") == 0) return v * 1000ULL;
    if (strcmp(end, "ms") == 0) return v * 1000ULL * 1000ULL;
    if (strcmp(end, "s") == 0)  return v * 1000ULL * 1000ULL * 1000ULL;
    return 0ULL; /* invalid suffix */
}


int parse_opts(int argc, char **argv, struct opts *o, char ***target_argv)
{
    static const struct option long_opts[] = {
        { "duration",           required_argument, 0, 'd' },
        { "pid",                required_argument, 0, 'p' },
        { "comm",               required_argument, 0, 'n' },
        { "cgroup",             required_argument, 0, 'g' },
        { "cgroupid",           required_argument, 0, 'G' },
        { "latency-warn-us",    required_argument, 0, 'l' },
        { "warn-enable",        no_argument,       0, 'w' },
        { "perf",               no_argument,       0, 'P' },
        { "ftrace",             no_argument,       0, 'F' },
        { "perf-args",          required_argument, 0, 'A' },
        { "ftrace-args",        required_argument, 0, 'R' },
        { "follow",             no_argument,       0, 'f' },
        { "user",               required_argument, 0, 'u' },
        { "env-file",           required_argument, 0, 'e' },
        { "output",             required_argument, 0, 'o' },
        { "out-dir",            required_argument, 0, 'D' },
        { "format",             required_argument, 0, 'M' },
        { "columns",            required_argument, 0, 'C' },
        { "show-migration-matrix", no_argument,    0,  6  },
        { "show-pid-migration-matrix", no_argument,0,  7  },
        { "detect-wakeup-latency", required_argument, 0,  9 },
        { "detect-migration-xnuma", no_argument, 0, 10 },
        { "detect-migration-xllc",  no_argument, 0, 11 },
        { "detect-remote-wakeup-xnuma", no_argument, 0, 12 },
        { "dump-topology",      no_argument,       0,  8  },
        { "no-aggregate",       no_argument,       0,  1  },
        { "paramset-recheck",   no_argument,       0,  2  },
        { "timeline",           no_argument,       0,  3  },
        { "no-resolve-masks",   no_argument,       0,  4  },
        { "show-hist-config",   no_argument,       0,  5  },
        { "help",               no_argument,       0, 'h' },
        { 0, 0, 0,  0 }
    };

    int c;
    memset(o, 0, sizeof(*o));
    o->pid = -1;
    *target_argv = NULL;

    o->aggregate_enable = true;
    o->paramset_recheck = false;
    o->show_pid_migration_matrix = false;

    o->timeline_enable = false;
    o->resolve_masks = true;
    o->show_migration_matrix = false;

    while ((c = getopt_long(argc, argv, "hd:p:n:g:G:l:wPFA:R:fu:e:o:D:M:C:", long_opts, NULL)) != -1) {
        switch (c) {
        case 'd': o->duration_sec = atoi(optarg); break;
        case 'p': o->pid = atoi(optarg); break;
        case 'n': o->comm = strdup(optarg); if (!o->comm) return -1; break;
        case 9: {
            unsigned long long ns = parse_time_to_ns(optarg);
            if (!ns) return -1;
            o->detect_wakeup_lat_ns = ns;
            break; }
        case 10: o->detect_migration_xnuma = true; break;
        case 11: o->detect_migration_xllc  = true; break;
        case 12: o->detect_remote_wakeup_xnuma = true; break;
        case 'g': o->cgroup_path = strdup(optarg); if (!o->cgroup_path) return -1; break;
        case 'G': o->cgroup_id = strtoull(optarg, NULL, 0); o->have_cgroup_id = true; break;
        case 'l': o->latency_warn_us = atol(optarg); break;
        case 'w': o->warn_enable = true; break;
        case 'P': o->perf_enable = true; break;
        case 'F': o->ftrace_enable = true; break;
        case 'u': o->run_as_user = strdup(optarg); if (!o->run_as_user) return -1; break;
        case 'e': o->env_file = strdup(optarg); if (!o->env_file) return -1; break;
        case 'o': o->out_path = strdup(optarg); if (!o->out_path) return -1; break;
        case 'D': o->out_dir = strdup(optarg); if (!o->out_dir) return -1; break;
        case 'M': o->format = strdup(optarg); if (!o->format) return -1; break;
        case 'C': o->columns = strdup(optarg); if (!o->columns) return -1; break;
        case 'A': o->perf_args = strdup(optarg); if (!o->perf_args) return -1; break;
        case 'R': o->ftrace_args = strdup(optarg); if (!o->ftrace_args) return -1; break;
        case 'f': o->follow_children = true; break;
        case 1: o->aggregate_enable = false; break;
        case 2: o->paramset_recheck = true; break;
        case 3: o->timeline_enable = true; break;
        case 4: o->resolve_masks = false; break;
        case 5: o->show_hist_config = true; break;
        case 6: o->show_migration_matrix = true; break;
        case 7: o->show_pid_migration_matrix = true; break;
        case 8: o->dump_topology = true; break;
        case 'h': return 2; /* help */
        default: return -1;
        }
    }
    if (optind < argc)
        *target_argv = &argv[optind];
    return 0;
}

