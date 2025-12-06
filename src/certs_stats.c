/*
 * certs_stats.c - Lock-free statistics implementation
 */

#include "../include/certs_stats.h"

/* Global statistics instance */
certs_stats_t g_stats;

void certs_stats_init(void) {
    atomic_counter_init(&g_stats.ctx_total, 0);
    atomic_counter_init(&g_stats.ctx_hit, 0);
    atomic_counter_init(&g_stats.ctx_miss, 0);
    atomic_counter_init(&g_stats.ctx_purge, 0);
    atomic_counter_init(&g_stats.certs_gen, 0);
    atomic_counter_init(&g_stats.certs_cached, 0);
    atomic_timestamp_set(&g_stats.last_flush, 0);
}
