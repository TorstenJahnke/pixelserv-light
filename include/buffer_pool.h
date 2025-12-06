/*
 * buffer_pool.h - Pre-allocated Buffer Pool for Zero-Malloc Operation
 *
 * Designed for 10M+ concurrent connections
 * All buffers are pre-allocated at startup, no malloc during request handling
 */

#ifndef BUFFER_POOL_H
#define BUFFER_POOL_H

#include <stdint.h>
#include <stdatomic.h>
#include <stddef.h>

/* =============================================================================
 * Buffer Configuration
 * =============================================================================
 * For 10M connections with 4KB buffers each:
 *   Read buffers:  10M * 4KB = 40GB
 *   Write buffers: 10M * 4KB = 40GB (but we can share/reuse)
 *   Total: ~80GB worst case, 50GB typical
 *
 * On 256GB system: plenty of headroom
 */

#define BUFFER_SIZE_SMALL   4096      /* 4KB - typical HTTP request/response */
#define BUFFER_SIZE_LARGE   65536     /* 64KB - for large POST bodies */

/* =============================================================================
 * Buffer Pool Structure
 * =============================================================================
 */

typedef struct buffer_slot {
    char *data;                       /* Actual buffer memory */
    struct buffer_slot *next;         /* Free list linkage */
    uint32_t size;                    /* Buffer size */
    _Atomic uint32_t refcount;        /* Reference count for sharing */
} buffer_slot_t;

typedef struct buffer_pool {
    /* Memory region */
    char *memory;                     /* Contiguous memory block */
    size_t memory_size;               /* Total allocated bytes */

    /* Slot management */
    buffer_slot_t *slots;             /* Array of slot metadata */
    uint32_t slot_count;              /* Number of slots */
    uint32_t slot_size;               /* Size of each slot */

    /* Lock-free free list (Treiber stack) */
    _Atomic(buffer_slot_t *) free_head;

    /* Statistics */
    _Atomic uint64_t alloc_count;
    _Atomic uint64_t free_count;
    _Atomic uint64_t alloc_fail;
    _Atomic uint32_t in_use;          /* Current buffers in use */
    uint32_t high_water;              /* Peak usage */
} buffer_pool_t;

/* =============================================================================
 * Global Buffer Pools
 * =============================================================================
 */

/* Small buffers for HTTP requests/responses */
extern buffer_pool_t g_small_pool;

/* Large buffers for POST bodies (fewer needed) */
extern buffer_pool_t g_large_pool;

/* =============================================================================
 * API Functions
 * =============================================================================
 */

/*
 * Initialize a buffer pool
 * @param pool      Pool to initialize
 * @param count     Number of buffers
 * @param size      Size of each buffer
 * @return          0 on success, -1 on failure
 */
int buffer_pool_init(buffer_pool_t *pool, uint32_t count, uint32_t size);

/*
 * Destroy a buffer pool and free all memory
 */
void buffer_pool_destroy(buffer_pool_t *pool);

/*
 * Allocate a buffer from pool (lock-free)
 * @param pool      Pool to allocate from
 * @return          Buffer pointer or NULL if exhausted
 */
char *buffer_alloc(buffer_pool_t *pool);

/*
 * Free a buffer back to pool (lock-free)
 * @param pool      Pool to return buffer to
 * @param buf       Buffer to free
 */
void buffer_free(buffer_pool_t *pool, char *buf);

/*
 * Get pool statistics
 */
void buffer_pool_stats(buffer_pool_t *pool, uint64_t *allocs, uint64_t *frees,
                       uint64_t *fails, uint32_t *in_use);

/* =============================================================================
 * Convenience Functions
 * =============================================================================
 */

/* Initialize global pools for target connection count */
int buffer_pools_init(uint32_t max_connections);
void buffer_pools_destroy(void);

/* Allocate from appropriate global pool */
static inline char *buf_alloc_small(void) {
    return buffer_alloc(&g_small_pool);
}

static inline char *buf_alloc_large(void) {
    return buffer_alloc(&g_large_pool);
}

static inline void buf_free_small(char *buf) {
    buffer_free(&g_small_pool, buf);
}

static inline void buf_free_large(char *buf) {
    buffer_free(&g_large_pool, buf);
}

#endif /* BUFFER_POOL_H */
