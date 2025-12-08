/*
 * certs_stats.h - Lock-free statistics counters
 */

#ifndef _CERTS_STATS_H_
#define _CERTS_STATS_H_

#include "certs/certs_atomic.h"

/* Statistics structure - all lock-free */
typedef struct {
    atomic_counter_t ctx_total;     /* Total SSL contexts created */
    atomic_counter_t ctx_hit;       /* Cache hits */
    atomic_counter_t ctx_miss;      /* Cache misses */
    atomic_counter_t ctx_purge;     /* Purged entries */
    atomic_counter_t certs_gen;     /* Certificates generated */
    atomic_counter_t certs_cached;  /* Certificates loaded from cache */
    atomic_timestamp_t last_flush;  /* Last cache flush time */
} certs_stats_t;

/* Global stats instance */
extern certs_stats_t g_stats;

/* Initialize statistics */
void certs_stats_init(void);

/* Increment functions */
static inline void stats_inc_hit(void) { atomic_counter_inc(&g_stats.ctx_hit); }
static inline void stats_inc_miss(void) { atomic_counter_inc(&g_stats.ctx_miss); }
static inline void stats_inc_purge(void) { atomic_counter_inc(&g_stats.ctx_purge); }
static inline void stats_inc_gen(void) { atomic_counter_inc(&g_stats.certs_gen); }
static inline void stats_inc_cached(void) { atomic_counter_inc(&g_stats.certs_cached); }

/* Getter functions */
static inline int stats_get_total(void) { return atomic_counter_get(&g_stats.ctx_total); }
static inline int stats_get_hit(void) { return atomic_counter_get(&g_stats.ctx_hit); }
static inline int stats_get_miss(void) { return atomic_counter_get(&g_stats.ctx_miss); }
static inline int stats_get_purge(void) { return atomic_counter_get(&g_stats.ctx_purge); }
static inline int stats_get_gen(void) { return atomic_counter_get(&g_stats.certs_gen); }
static inline int stats_get_cached(void) { return atomic_counter_get(&g_stats.certs_cached); }

/* Set total (for initialization) */
static inline void stats_set_total(int val) { atomic_counter_init(&g_stats.ctx_total, val); }
static inline int stats_inc_total(void) { return atomic_counter_inc_get(&g_stats.ctx_total); }

#endif /* _CERTS_STATS_H_ */
