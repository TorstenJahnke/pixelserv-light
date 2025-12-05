/*
 * buffer_pool.c - Pre-allocated Buffer Pool Implementation
 *
 * TLSGate - Ultra-Scale TLS Pixel Server
 * Lock-free buffer management for 10M+ concurrent connections
 */

#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

#include "../include/buffer_pool.h"

/* Global pools */
buffer_pool_t g_small_pool;
buffer_pool_t g_large_pool;

/* =============================================================================
 * Buffer Pool Implementation
 * =============================================================================
 */

int buffer_pool_init(buffer_pool_t *pool, uint32_t count, uint32_t size)
{
    if (!pool || count == 0 || size == 0)
        return -1;

    memset(pool, 0, sizeof(*pool));

    pool->slot_count = count;
    pool->slot_size = size;
    pool->memory_size = (size_t)count * size;

    /*
     * Allocate contiguous memory block using mmap for better performance
     * MAP_POPULATE pre-faults pages to avoid page faults during runtime
     */
    int use_mmap = 1;
    pool->memory = mmap(NULL, pool->memory_size,
                        PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE,
                        -1, 0);

    if (pool->memory == MAP_FAILED) {
        /* Fallback to malloc */
        use_mmap = 0;
        pool->memory = aligned_alloc(4096, pool->memory_size);
        if (!pool->memory)
            return -1;
        /* Touch pages to avoid page faults later */
        memset(pool->memory, 0, pool->memory_size);
    }

    /* Allocate slot metadata */
    pool->slots = calloc(count, sizeof(buffer_slot_t));
    if (!pool->slots) {
        if (use_mmap)
            munmap(pool->memory, pool->memory_size);
        else
            free(pool->memory);
        return -1;
    }

    /* Initialize slots and build free list */
    for (uint32_t i = 0; i < count; i++) {
        pool->slots[i].data = pool->memory + (i * size);
        pool->slots[i].size = size;
        atomic_store(&pool->slots[i].refcount, 0);

        if (i < count - 1)
            pool->slots[i].next = &pool->slots[i + 1];
        else
            pool->slots[i].next = NULL;
    }

    atomic_store(&pool->free_head, &pool->slots[0]);
    atomic_store(&pool->alloc_count, 0);
    atomic_store(&pool->free_count, 0);
    atomic_store(&pool->alloc_fail, 0);
    atomic_store(&pool->in_use, 0);
    pool->high_water = 0;

    return 0;
}

void buffer_pool_destroy(buffer_pool_t *pool)
{
    if (!pool)
        return;

    if (pool->slots) {
        free(pool->slots);
        pool->slots = NULL;
    }

    if (pool->memory) {
        /* Try munmap first, fallback to free */
        if (munmap(pool->memory, pool->memory_size) != 0)
            free(pool->memory);
        pool->memory = NULL;
    }

    pool->slot_count = 0;
    pool->memory_size = 0;
}

/*
 * Lock-free buffer allocation using Treiber stack pop
 */
char *buffer_alloc(buffer_pool_t *pool)
{
    buffer_slot_t *head;
    buffer_slot_t *next;

    do {
        head = atomic_load(&pool->free_head);
        if (!head) {
            atomic_fetch_add(&pool->alloc_fail, 1);
            return NULL;
        }
        next = head->next;
    } while (!atomic_compare_exchange_weak(&pool->free_head, &head, next));

    atomic_fetch_add(&pool->alloc_count, 1);
    uint32_t in_use = atomic_fetch_add(&pool->in_use, 1) + 1;

    /* Update high water mark (not atomic, but close enough for stats) */
    if (in_use > pool->high_water)
        pool->high_water = in_use;

    atomic_store(&head->refcount, 1);
    return head->data;
}

/*
 * Lock-free buffer free using Treiber stack push
 */
void buffer_free(buffer_pool_t *pool, char *buf)
{
    if (!pool || !buf)
        return;

    /* Find the slot for this buffer */
    size_t offset = buf - pool->memory;
    if (offset >= pool->memory_size)
        return;  /* Not from this pool */

    uint32_t index = offset / pool->slot_size;
    if (index >= pool->slot_count)
        return;

    buffer_slot_t *slot = &pool->slots[index];

    /* Decrement refcount, only free if it reaches 0 */
    uint32_t old_ref = atomic_fetch_sub(&slot->refcount, 1);
    if (old_ref != 1)
        return;  /* Still has references */

    /* Push to free list */
    buffer_slot_t *head;
    do {
        head = atomic_load(&pool->free_head);
        slot->next = head;
    } while (!atomic_compare_exchange_weak(&pool->free_head, &head, slot));

    atomic_fetch_add(&pool->free_count, 1);
    atomic_fetch_sub(&pool->in_use, 1);
}

void buffer_pool_stats(buffer_pool_t *pool, uint64_t *allocs, uint64_t *frees,
                       uint64_t *fails, uint32_t *in_use)
{
    if (allocs) *allocs = atomic_load(&pool->alloc_count);
    if (frees) *frees = atomic_load(&pool->free_count);
    if (fails) *fails = atomic_load(&pool->alloc_fail);
    if (in_use) *in_use = atomic_load(&pool->in_use);
}

/* =============================================================================
 * Global Pool Management
 * =============================================================================
 */

int buffer_pools_init(uint32_t max_connections)
{
    int ret;

    /*
     * Small pool: 2 buffers per connection (read + write)
     * Add 10% headroom for bursts
     */
    uint32_t small_count = max_connections * 2 + (max_connections / 10);
    ret = buffer_pool_init(&g_small_pool, small_count, BUFFER_SIZE_SMALL);
    if (ret != 0)
        return -1;

    /*
     * Large pool: 1% of connections might need large buffers
     * Minimum 1000 large buffers
     */
    uint32_t large_count = max_connections / 100;
    if (large_count < 1000)
        large_count = 1000;
    ret = buffer_pool_init(&g_large_pool, large_count, BUFFER_SIZE_LARGE);
    if (ret != 0) {
        buffer_pool_destroy(&g_small_pool);
        return -1;
    }

    return 0;
}

void buffer_pools_destroy(void)
{
    buffer_pool_destroy(&g_small_pool);
    buffer_pool_destroy(&g_large_pool);
}
