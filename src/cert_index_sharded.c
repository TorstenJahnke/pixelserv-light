/*
 * cert_index_sharded.c - Per-Algorithm Sharded Certificate Index
 *
 * Implementation with separate mmap'd index files per algorithm.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <ctype.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <pthread.h>

#include "../include/cert_index_sharded.h"
#include "../include/index_udp.h"

/* FNV-1a constants */
#define FNV_OFFSET 2166136261U
#define FNV_PRIME  16777619U

/* Per-algorithm index shard */
typedef struct {
    /* mmap'd file */
    void *mmap_base;
    size_t mmap_size;
    int fd;

    /* Pointers into mmap */
    shard_index_header_t *header;
    shard_index_entry_t *entries;

    /* Write lock (master only) */
    pthread_mutex_t write_lock;

    /* Statistics */
    atomic_uint_fast64_t stat_lookups;
    atomic_uint_fast64_t stat_hits;
    atomic_uint_fast64_t stat_misses;
} algo_shard_t;

/* Main index handle */
struct shard_index {
    char *pem_dir;
    size_t max_entries;
    bool read_only;
    bool udp_enabled;

    algo_shard_t shards[SHARD_ALG_MAX];
};

/* Magic values per algorithm */
static const uint32_t ALGO_MAGIC[SHARD_ALG_MAX] = {
    SHARD_INDEX_MAGIC_RSA,
    SHARD_INDEX_MAGIC_ECDSA,
    SHARD_INDEX_MAGIC_SM2
};

/* ==========================================================================
 * Hash Function
 * ========================================================================== */

uint32_t shard_index_hash(const char *domain) {
    uint32_t hash = FNV_OFFSET;
    while (*domain) {
        hash ^= (uint32_t)(unsigned char)tolower(*domain);
        hash *= FNV_PRIME;
        domain++;
    }
    return hash;
}

/* ==========================================================================
 * Binary Search with Prefetch
 * ========================================================================== */

static const shard_index_entry_t *
binary_search_prefetch(const shard_index_entry_t *entries,
                       size_t count,
                       uint32_t target) {
    if (count == 0) return NULL;

    size_t lo = 0;
    size_t hi = count;

    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;

        /* Prefetch next comparisons */
        size_t next_lo = mid + 1 + (hi - mid - 1) / 2;
        size_t next_hi = lo + (mid - lo) / 2;

        if (next_lo < count) {
            __builtin_prefetch(&entries[next_lo], 0, 3);
        }
        if (next_hi < count && next_hi != mid) {
            __builtin_prefetch(&entries[next_hi], 0, 3);
        }

        uint32_t mid_hash = entries[mid].domain_hash;

        if (mid_hash == target) {
            return &entries[mid];
        } else if (mid_hash < target) {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }

    return NULL;
}

/* ==========================================================================
 * Shard Management
 * ========================================================================== */

static int open_algo_shard(shard_index_t *idx, shard_algo_t algo) {
    algo_shard_t *shard = &idx->shards[algo];

    /* Build path: pem_dir/ALGO/index */
    char path[1024];
    snprintf(path, sizeof(path), "%s/%s/index",
             idx->pem_dir, shard_algo_name(algo));

    /* Ensure directory exists */
    char dir[1024];
    snprintf(dir, sizeof(dir), "%s/%s", idx->pem_dir, shard_algo_name(algo));
    mkdir(dir, 0755);

    /* Calculate sizes */
    size_t header_size = sizeof(shard_index_header_t);
    size_t entries_size = idx->max_entries * sizeof(shard_index_entry_t);
    shard->mmap_size = header_size + entries_size;

    /* Open file */
    int flags = idx->read_only ? O_RDONLY : (O_RDWR | O_CREAT);
    shard->fd = open(path, flags, 0644);
    if (shard->fd < 0) {
        fprintf(stderr, "[SHARD-INDEX] Failed to open %s: %s\n",
                path, strerror(errno));
        return -1;
    }

    /* Extend file if needed */
    if (!idx->read_only) {
        struct stat st;
        if (fstat(shard->fd, &st) == 0 && (size_t)st.st_size < shard->mmap_size) {
            if (ftruncate(shard->fd, shard->mmap_size) < 0) {
                close(shard->fd);
                shard->fd = -1;
                return -1;
            }
        }
    }

    /* mmap */
    int prot = idx->read_only ? PROT_READ : (PROT_READ | PROT_WRITE);
    int mmap_flags = MAP_SHARED;

#ifdef MAP_POPULATE
    mmap_flags |= MAP_POPULATE;
#endif

    shard->mmap_base = mmap(NULL, shard->mmap_size, prot, mmap_flags,
                            shard->fd, 0);
    if (shard->mmap_base == MAP_FAILED) {
        close(shard->fd);
        shard->fd = -1;
        shard->mmap_base = NULL;
        return -1;
    }

    /* Setup pointers */
    shard->header = (shard_index_header_t *)shard->mmap_base;
    shard->entries = (shard_index_entry_t *)((char *)shard->mmap_base + header_size);

    /* Initialize header if new */
    if (!idx->read_only && shard->header->magic != ALGO_MAGIC[algo]) {
        memset(shard->header, 0, sizeof(*shard->header));
        shard->header->magic = ALGO_MAGIC[algo];
        shard->header->version = SHARD_INDEX_VERSION;
        shard->header->capacity = idx->max_entries;
        shard->header->algo_id = algo;
        shard->header->next_cert_id = 1;
        shard->header->created_at = (uint64_t)time(NULL);
        shard->header->updated_at = shard->header->created_at;
        msync(shard->header, sizeof(*shard->header), MS_ASYNC);
    }

    /* Validate header */
    if (shard->header->magic != ALGO_MAGIC[algo]) {
        fprintf(stderr, "[SHARD-INDEX] Invalid magic for %s: 0x%08x\n",
                shard_algo_name(algo), shard->header->magic);
        munmap(shard->mmap_base, shard->mmap_size);
        close(shard->fd);
        shard->fd = -1;
        shard->mmap_base = NULL;
        return -1;
    }

    /* Initialize lock */
    if (!idx->read_only) {
        pthread_mutex_init(&shard->write_lock, NULL);
    }

    /* Initialize stats */
    atomic_init(&shard->stat_lookups, 0);
    atomic_init(&shard->stat_hits, 0);
    atomic_init(&shard->stat_misses, 0);

    /* Advise kernel */
    madvise(shard->mmap_base, shard->mmap_size, MADV_RANDOM);

    return 0;
}

static void close_algo_shard(shard_index_t *idx, shard_algo_t algo) {
    algo_shard_t *shard = &idx->shards[algo];

    if (shard->mmap_base && shard->mmap_base != MAP_FAILED) {
        msync(shard->mmap_base, shard->mmap_size, MS_SYNC);
        munmap(shard->mmap_base, shard->mmap_size);
        shard->mmap_base = NULL;
    }

    if (shard->fd >= 0) {
        close(shard->fd);
        shard->fd = -1;
    }

    if (!idx->read_only) {
        pthread_mutex_destroy(&shard->write_lock);
    }
}

/* ==========================================================================
 * Lifecycle
 * ========================================================================== */

shard_index_t *shard_index_open(const shard_index_config_t *config) {
    if (!config || !config->pem_dir) {
        return NULL;
    }

    shard_index_t *idx = calloc(1, sizeof(shard_index_t));
    if (!idx) return NULL;

    idx->pem_dir = strdup(config->pem_dir);
    if (!idx->pem_dir) {
        free(idx);
        return NULL;
    }

    idx->max_entries = config->max_entries_per_algo
                     ? config->max_entries_per_algo
                     : SHARD_INDEX_DEFAULT_MAX_ENTRIES;
    idx->read_only = config->read_only;
    idx->udp_enabled = config->enable_udp;

    /* Initialize all shard fds to -1 */
    for (int i = 0; i < SHARD_ALG_MAX; i++) {
        idx->shards[i].fd = -1;
    }

    /* Open all algorithm shards */
    for (shard_algo_t algo = 0; algo < SHARD_ALG_MAX; algo++) {
        if (open_algo_shard(idx, algo) < 0) {
            /* Non-fatal: some algorithms may not be configured */
            fprintf(stderr, "[SHARD-INDEX] Warning: Failed to open %s index\n",
                    shard_algo_name(algo));
        } else {
            fprintf(stderr, "[SHARD-INDEX] Opened %s index: %lu entries, capacity %lu\n",
                    shard_algo_name(algo),
                    (unsigned long)idx->shards[algo].header->entry_count,
                    (unsigned long)idx->shards[algo].header->capacity);
        }
    }

    /* Initialize UDP if enabled */
    if (config->enable_udp && !config->read_only) {
        /* UDP client initialization is done separately */
    }

    return idx;
}

void shard_index_close(shard_index_t *idx) {
    if (!idx) return;

    for (shard_algo_t algo = 0; algo < SHARD_ALG_MAX; algo++) {
        close_algo_shard(idx, algo);
    }

    free(idx->pem_dir);
    free(idx);
}

/* ==========================================================================
 * Lookups
 * ========================================================================== */

shard_index_err_t shard_index_lookup(const shard_index_t *idx,
                                      const char *domain,
                                      shard_algo_t algo,
                                      shard_index_result_t *result) {
    if (!idx || !domain || !result || algo >= SHARD_ALG_MAX) {
        return SHARD_IDX_ERR_NOTFOUND;
    }

    uint32_t hash = shard_index_hash(domain);
    return shard_index_lookup_hash(idx, hash, algo, result);
}

shard_index_err_t shard_index_lookup_hash(const shard_index_t *idx,
                                           uint32_t hash,
                                           shard_algo_t algo,
                                           shard_index_result_t *result) {
    if (!idx || !result || algo >= SHARD_ALG_MAX) {
        return SHARD_IDX_ERR_NOTFOUND;
    }

    const algo_shard_t *shard = &idx->shards[algo];
    if (!shard->mmap_base) {
        return SHARD_IDX_ERR_ALGO;
    }

    /* Update stats */
    atomic_fetch_add(&((algo_shard_t *)shard)->stat_lookups, 1);

    /* Initialize result */
    memset(result, 0, sizeof(*result));
    result->algo = algo;

    /* Binary search */
    const shard_index_entry_t *entry = binary_search_prefetch(
        shard->entries,
        shard->header->entry_count,
        hash
    );

    if (!entry) {
        atomic_fetch_add(&((algo_shard_t *)shard)->stat_misses, 1);
        return SHARD_IDX_ERR_NOTFOUND;
    }

    /* Fill result */
    result->shard_id = shard_index_shard_id(hash);
    result->cert_id = entry->cert_id;
    result->expiry = entry->expiry;
    result->found = true;

    atomic_fetch_add(&((algo_shard_t *)shard)->stat_hits, 1);
    return SHARD_IDX_OK;
}

shard_index_err_t shard_index_lookup_any(const shard_index_t *idx,
                                          const char *domain,
                                          shard_algo_t prefer_algo,
                                          shard_index_result_t *result) {
    if (!idx || !domain || !result) {
        return SHARD_IDX_ERR_NOTFOUND;
    }

    /* Search order based on preference and fallback */
    shard_algo_t search_order[SHARD_ALG_MAX];
    int order_idx = 0;

    /* Preferred algorithm first */
    if (prefer_algo < SHARD_ALG_MAX) {
        search_order[order_idx++] = prefer_algo;
    }

    /* Then RSA (most common fallback) */
    if (prefer_algo != SHARD_ALG_RSA) {
        search_order[order_idx++] = SHARD_ALG_RSA;
    }

    /* Then ECDSA */
    if (prefer_algo != SHARD_ALG_ECDSA) {
        search_order[order_idx++] = SHARD_ALG_ECDSA;
    }

    /* Finally SM2 */
    if (prefer_algo != SHARD_ALG_SM2) {
        search_order[order_idx++] = SHARD_ALG_SM2;
    }

    /* Try each in order */
    for (int i = 0; i < order_idx; i++) {
        if (shard_index_lookup(idx, domain, search_order[i], result) == SHARD_IDX_OK) {
            return SHARD_IDX_OK;
        }
    }

    return SHARD_IDX_ERR_NOTFOUND;
}

/* ==========================================================================
 * Updates
 * ========================================================================== */

uint32_t shard_index_alloc_cert_id(shard_index_t *idx, shard_algo_t algo) {
    if (!idx || algo >= SHARD_ALG_MAX) {
        return 0;
    }

    algo_shard_t *shard = &idx->shards[algo];
    if (!shard->mmap_base || idx->read_only) {
        return 0;
    }

    pthread_mutex_lock(&shard->write_lock);
    uint32_t cert_id = shard->header->next_cert_id++;
    pthread_mutex_unlock(&shard->write_lock);

    return cert_id;
}

shard_index_err_t shard_index_insert(shard_index_t *idx,
                                      const char *domain,
                                      shard_algo_t algo,
                                      uint64_t expiry,
                                      uint32_t *out_cert_id) {
    if (!idx || idx->read_only || !domain || algo >= SHARD_ALG_MAX) {
        return SHARD_IDX_ERR_IO;
    }

    algo_shard_t *shard = &idx->shards[algo];
    if (!shard->mmap_base) {
        return SHARD_IDX_ERR_ALGO;
    }

    /* Allocate cert ID */
    uint32_t cert_id = shard_index_alloc_cert_id(idx, algo);
    if (cert_id == 0) {
        return SHARD_IDX_ERR_IO;
    }

    /* If UDP enabled, queue via UDP instead of direct write */
    if (idx->udp_enabled) {
        if (out_cert_id) *out_cert_id = cert_id;
        /* Convert to cert_algo_t for UDP (same values) */
        return (index_udp_client_insert(domain, (int)algo, cert_id, expiry) == 0)
             ? SHARD_IDX_OK : SHARD_IDX_ERR_IO;
    }

    pthread_mutex_lock(&shard->write_lock);

    /* Check capacity */
    if (shard->header->entry_count >= shard->header->capacity) {
        pthread_mutex_unlock(&shard->write_lock);
        return SHARD_IDX_ERR_FULL;
    }

    /* Compute hash */
    uint32_t hash = shard_index_hash(domain);

    /* Find insertion point */
    size_t count = shard->header->entry_count;
    size_t insert_pos = 0;

    size_t lo = 0, hi = count;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (shard->entries[mid].domain_hash < hash) {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    insert_pos = lo;

    /* Check for duplicate */
    if (insert_pos < count && shard->entries[insert_pos].domain_hash == hash) {
        /* Update existing */
        shard->entries[insert_pos].cert_id = cert_id;
        shard->entries[insert_pos].expiry = expiry;
    } else {
        /* Shift and insert */
        if (insert_pos < count) {
            memmove(&shard->entries[insert_pos + 1],
                    &shard->entries[insert_pos],
                    (count - insert_pos) * sizeof(shard_index_entry_t));
        }

        shard->entries[insert_pos].domain_hash = hash;
        shard->entries[insert_pos].cert_id = cert_id;
        shard->entries[insert_pos].expiry = expiry;

        shard->header->entry_count++;
    }

    shard->header->updated_at = (uint64_t)time(NULL);

    /* Async sync */
    msync(&shard->entries[insert_pos], sizeof(shard_index_entry_t), MS_ASYNC);
    msync(shard->header, sizeof(*shard->header), MS_ASYNC);

    pthread_mutex_unlock(&shard->write_lock);

    if (out_cert_id) *out_cert_id = cert_id;
    return SHARD_IDX_OK;
}

shard_index_err_t shard_index_remove(shard_index_t *idx,
                                      const char *domain,
                                      shard_algo_t algo) {
    if (!idx || idx->read_only || !domain || algo >= SHARD_ALG_MAX) {
        return SHARD_IDX_ERR_IO;
    }

    algo_shard_t *shard = &idx->shards[algo];
    if (!shard->mmap_base) {
        return SHARD_IDX_ERR_ALGO;
    }

    /* If UDP enabled, queue via UDP */
    if (idx->udp_enabled) {
        return (index_udp_client_remove(domain, (int)algo) == 0)
             ? SHARD_IDX_OK : SHARD_IDX_ERR_IO;
    }

    pthread_mutex_lock(&shard->write_lock);

    uint32_t hash = shard_index_hash(domain);
    size_t count = shard->header->entry_count;

    /* Find entry */
    const shard_index_entry_t *entry = binary_search_prefetch(
        shard->entries, count, hash
    );

    if (!entry) {
        pthread_mutex_unlock(&shard->write_lock);
        return SHARD_IDX_ERR_NOTFOUND;
    }

    /* Shift entries */
    size_t pos = entry - shard->entries;
    if (pos < count - 1) {
        memmove(&shard->entries[pos],
                &shard->entries[pos + 1],
                (count - pos - 1) * sizeof(shard_index_entry_t));
    }

    shard->header->entry_count--;
    shard->header->updated_at = (uint64_t)time(NULL);

    msync(shard->header, sizeof(*shard->header), MS_ASYNC);

    pthread_mutex_unlock(&shard->write_lock);
    return SHARD_IDX_OK;
}

shard_index_err_t shard_index_compact(shard_index_t *idx) {
    if (!idx || idx->read_only) {
        return SHARD_IDX_ERR_IO;
    }

    for (shard_algo_t algo = 0; algo < SHARD_ALG_MAX; algo++) {
        algo_shard_t *shard = &idx->shards[algo];
        if (shard->mmap_base) {
            pthread_mutex_lock(&shard->write_lock);
            msync(shard->mmap_base, shard->mmap_size, MS_SYNC);
            pthread_mutex_unlock(&shard->write_lock);
        }
    }

    return SHARD_IDX_OK;
}

/* ==========================================================================
 * Utilities
 * ========================================================================== */

size_t shard_index_cert_path(const shard_index_t *idx,
                              shard_algo_t algo,
                              uint8_t shard_id,
                              uint32_t cert_id,
                              char *buf,
                              size_t buf_len) {
    if (!idx || !buf || buf_len == 0 || algo >= SHARD_ALG_MAX) {
        return 0;
    }

    return (size_t)snprintf(buf, buf_len,
                            "%s/%s/certs/%02x/cert_%08x.pem",
                            idx->pem_dir,
                            shard_algo_name(algo),
                            shard_id,
                            cert_id);
}

shard_index_err_t shard_index_stats(const shard_index_t *idx,
                                     shard_index_stats_t *stats) {
    if (!idx || !stats) {
        return SHARD_IDX_ERR_NOTFOUND;
    }

    memset(stats, 0, sizeof(*stats));

    for (shard_algo_t algo = 0; algo < SHARD_ALG_MAX; algo++) {
        const algo_shard_t *shard = &idx->shards[algo];
        if (!shard->mmap_base) continue;

        stats->per_algo[algo].entry_count = shard->header->entry_count;
        stats->per_algo[algo].capacity = shard->header->capacity;
        stats->per_algo[algo].lookups = atomic_load(&shard->stat_lookups);
        stats->per_algo[algo].hits = atomic_load(&shard->stat_hits);
        stats->per_algo[algo].misses = atomic_load(&shard->stat_misses);
        stats->per_algo[algo].memory_bytes = shard->mmap_size;

        stats->total_entries += shard->header->entry_count;
        stats->total_lookups += atomic_load(&shard->stat_lookups);
        stats->total_memory += shard->mmap_size;
    }

    return SHARD_IDX_OK;
}
