/* TLS-Gate NX - Certificate Cache Implementation
 * Copyright (C) 2025 Torsten Jahnke
 *
 * High-performance cache with compound key (Domain + Algorithm)
 */

#include "cert_cache.h"
#include "../crypto/keypool.h"
#include "../util/logger.h"
#include "../util/util.h"

#include <stdlib.h>
#include <string.h>
#include <pthread.h>

/* Cache structure */
struct cert_cache {
    /* Local cache (per process) */
    cert_cache_entry_t *entries;
    int capacity;
    atomic_int count;
    pthread_rwlock_t lock;  /* Read-write lock for performance */

    /* Shared memory index (cross-process) */
    certcache_shm_t *shm_cache;
    int shm_fd;
    bool using_shm;

    /* Statistics */
    cert_cache_stats_t stats;

    /* Configuration */
    crypto_alg_t default_algorithm;
};

/* Global cache instance (for legacy API) */
static cert_cache_t *g_cert_cache = NULL;

/* Compile-time checks */
_Static_assert(sizeof(cache_key_t) <= 512, "Cache key too large");
_Static_assert(sizeof(cert_cache_entry_t) % 64 == 0, "Entry not cache-line aligned");

/* Cache Lifecycle */

cert_cache_t* cert_cache_create(int local_capacity,
                                 const char *pem_dir,
                                 const char *pool_name) {
    if (local_capacity <= 0) {
        LOG_ERROR("Invalid capacity: %d", local_capacity);
        return NULL;
    }

    cert_cache_t *cache = calloc(1, sizeof(cert_cache_t));
    if (!cache) {
        LOG_ERROR("Failed to allocate cache structure");
        return NULL;
    }

    cache->capacity = local_capacity;
    cache->default_algorithm = CRYPTO_ALG_ECDSA_P256;

    /* Initialize atomics */
    atomic_init(&cache->count, 0);
    atomic_init(&cache->stats.total_hits, 0);
    atomic_init(&cache->stats.total_misses, 0);
    atomic_init(&cache->stats.total_evictions, 0);
    atomic_init(&cache->stats.current_count, 0);

    /* Initialize read-write lock */
    if (pthread_rwlock_init(&cache->lock, NULL) != 0) {
        LOG_ERROR("Failed to initialize rwlock");
        free(cache);
        return NULL;
    }

    /* Allocate entry array */
    cache->entries = calloc(local_capacity, sizeof(cert_cache_entry_t));
    if (!cache->entries) {
        LOG_ERROR("Failed to allocate cache entries (%d entries)", local_capacity);
        pthread_rwlock_destroy(&cache->lock);
        free(cache);
        return NULL;
    }

    /* Try to use shared memory index */
    if (pem_dir) {
        char shm_name[128];
        shm_error_t err = certcache_shm_init(pem_dir, pool_name,
                                              CERT_CACHE_SIZE_DEFAULT,  /* Use default capacity */
                                              &cache->shm_cache, &cache->shm_fd,
                                              shm_name, sizeof(shm_name));
        if (err == SHM_OK) {
            cache->using_shm = true;
            LOG_INFO("Using shared cert index: %s", shm_name);
        } else {
            LOG_WARN("Failed to initialize cert SHM, using local only: %d", err);
            cache->using_shm = false;
        }
    }

    LOG_INFO("Created cert cache (capacity=%d, shm=%s)",
            local_capacity, cache->using_shm ? "yes" : "no");

    /* Set global cache for legacy API */
    if (!g_cert_cache) {
        g_cert_cache = cache;
    }

    return cache;
}

void cert_cache_destroy(cert_cache_t *cache) {
    if (!cache) {
        return;
    }

    /* RACE CONDITION FIX: Clear global reference FIRST to prevent new accesses
     * This ensures no new lookups/inserts start while we're destroying */
    if (g_cert_cache == cache) {
        g_cert_cache = NULL;
    }

    /* Now acquire write lock to wait for any in-flight operations to complete
     * After this returns, we own exclusive access to the cache */
    pthread_rwlock_wrlock(&cache->lock);

    /* Free all SSL_CTX entries while holding lock */
    for (int i = 0; i < cache->capacity; i++) {
        if (cache->entries[i].valid && cache->entries[i].ssl_ctx) {
            SSL_CTX_free(cache->entries[i].ssl_ctx);
            cache->entries[i].ssl_ctx = NULL;
            cache->entries[i].valid = false;
        }
    }

    /* Cleanup SHM while still holding lock */
    if (cache->using_shm && cache->shm_cache) {
        certcache_shm_cleanup(cache->shm_cache, cache->shm_fd);
        cache->shm_cache = NULL;
    }

    /* Release lock before destroying it (required by POSIX) */
    pthread_rwlock_unlock(&cache->lock);

    /* Now safe to free - no other threads can access */
    free(cache->entries);
    pthread_rwlock_destroy(&cache->lock);
    free(cache);

    LOG_DEBUG("Destroyed cert cache");
}

/* Cache Operations */

/* Find entry by key (caller must hold lock) */
static int find_entry_locked(cert_cache_t *cache, const cache_key_t *key) {
    for (int i = 0; i < cache->capacity; i++) {
        if (cache->entries[i].valid &&
            cert_cache_key_equal(&cache->entries[i].key, key)) {
            return i;
        }
    }
    return -1;
}

/* Find LRU entry for eviction (caller must hold lock) */
static int find_lru_entry_locked(cert_cache_t *cache) {
    unsigned int oldest_time = UINT32_MAX;
    int oldest_idx = -1;

    for (int i = 0; i < cache->capacity; i++) {
        if (cache->entries[i].valid) {
            unsigned int last_use = atomic_load_explicit(&cache->entries[i].last_use, memory_order_acquire);
            if (last_use < oldest_time) {
                oldest_time = last_use;
                oldest_idx = i;
            }
        }
    }

    return oldest_idx;
}

/* Find empty slot (caller must hold lock) */
static int find_empty_slot_locked(cert_cache_t *cache) {
    for (int i = 0; i < cache->capacity; i++) {
        if (!cache->entries[i].valid) {
            return i;
        }
    }
    return -1;
}

SSL_CTX* cert_cache_get(cert_cache_t *cache, const cache_key_t *key) {
    if (!cache || !key) {
        return NULL;
    }

    pthread_rwlock_rdlock(&cache->lock);

    int idx = find_entry_locked(cache, key);
    if (idx >= 0) {
        /* Cache hit! */
        SSL_CTX *ctx = cache->entries[idx].ssl_ctx;

        /* Update statistics (atomically) */
        atomic_store(&cache->entries[idx].last_use, process_uptime());
        atomic_fetch_add(&cache->entries[idx].reuse_count, 1);
        atomic_fetch_add(&cache->stats.total_hits, 1);

        pthread_rwlock_unlock(&cache->lock);

        LOG_DEBUG("Cache hit: %s (%s) [reuse=%d]",
                 key->domain,
                 keypool_algorithm_name(key->algorithm),
                 atomic_load_explicit(&cache->entries[idx].reuse_count, memory_order_acquire));

        return ctx;
    }

    pthread_rwlock_unlock(&cache->lock);

    /* Cache miss */
    atomic_fetch_add(&cache->stats.total_misses, 1);

    LOG_DEBUG("Cache miss: %s (%s)",
             key->domain,
             keypool_algorithm_name(key->algorithm));

    return NULL;
}

cert_cache_error_t cert_cache_put(cert_cache_t *cache,
                                   const cache_key_t *key,
                                   SSL_CTX *ssl_ctx) {
    if (!cache || !key || !ssl_ctx) {
        return CERT_CACHE_ERR_INVALID;
    }

    pthread_rwlock_wrlock(&cache->lock);

    /* Check if already exists */
    int idx = find_entry_locked(cache, key);
    if (idx >= 0) {
        /* Update existing entry */
        if (cache->entries[idx].ssl_ctx != ssl_ctx) {
            SSL_CTX_free(cache->entries[idx].ssl_ctx);
            cache->entries[idx].ssl_ctx = ssl_ctx;
        }
        atomic_store(&cache->entries[idx].last_use, process_uptime());
        pthread_rwlock_unlock(&cache->lock);
        return CERT_CACHE_OK;
    }

    /* Find empty slot */
    idx = find_empty_slot_locked(cache);
    if (idx < 0) {
        /* Cache full - evict LRU entry */
        idx = find_lru_entry_locked(cache);
        if (idx < 0) {
            pthread_rwlock_unlock(&cache->lock);
            LOG_ERROR("Cache full and no LRU entry found!");
            return CERT_CACHE_ERR_FULL;
        }

        /* Evict old entry */
        LOG_DEBUG("Evicting LRU entry: %s (%s)",
                 cache->entries[idx].key.domain,
                 keypool_algorithm_name(cache->entries[idx].key.algorithm));

        SSL_CTX_free(cache->entries[idx].ssl_ctx);
        atomic_fetch_add(&cache->stats.total_evictions, 1);
    } else {
        /* New entry */
        atomic_fetch_add(&cache->count, 1);
        atomic_fetch_add(&cache->stats.current_count, 1);
    }

    /* Store entry */
    memcpy(&cache->entries[idx].key, key, sizeof(cache_key_t));
    cache->entries[idx].ssl_ctx = ssl_ctx;
    cache->entries[idx].valid = true;
    atomic_init(&cache->entries[idx].last_use, process_uptime());
    atomic_init(&cache->entries[idx].reuse_count, 0);

    pthread_rwlock_unlock(&cache->lock);

    LOG_DEBUG("Cached cert: %s (%s) [count=%d/%d]",
             key->domain,
             keypool_algorithm_name(key->algorithm),
             atomic_load_explicit(&cache->count, memory_order_acquire),
             cache->capacity);

    /* Also register in shared memory index (if available) */
    if (cache->using_shm && cache->shm_cache) {
        certcache_shm_insert(cache->shm_cache, key->domain, false);
    }

    return CERT_CACHE_OK;
}

cert_cache_error_t cert_cache_remove(cert_cache_t *cache, const cache_key_t *key) {
    if (!cache || !key) {
        return CERT_CACHE_ERR_INVALID;
    }

    pthread_rwlock_wrlock(&cache->lock);

    int idx = find_entry_locked(cache, key);
    if (idx < 0) {
        pthread_rwlock_unlock(&cache->lock);
        return CERT_CACHE_ERR_NOTFOUND;
    }

    /* Remove entry */
    SSL_CTX_free(cache->entries[idx].ssl_ctx);
    memset(&cache->entries[idx], 0, sizeof(cert_cache_entry_t));
    cache->entries[idx].valid = false;

    atomic_fetch_sub(&cache->count, 1);
    atomic_fetch_sub(&cache->stats.current_count, 1);

    pthread_rwlock_unlock(&cache->lock);

    LOG_DEBUG("Removed cert: %s (%s)",
             key->domain,
             keypool_algorithm_name(key->algorithm));

    return CERT_CACHE_OK;
}

/* Statistics */

void cert_cache_get_stats(const cert_cache_t *cache, cert_cache_stats_t *stats) {
    if (!cache || !stats) {
        return;
    }

    stats->total_hits = atomic_load_explicit(&cache->stats.total_hits, memory_order_acquire);
    stats->total_misses = atomic_load_explicit(&cache->stats.total_misses, memory_order_acquire);
    stats->total_evictions = atomic_load_explicit(&cache->stats.total_evictions, memory_order_acquire);
    stats->current_count = atomic_load_explicit(&cache->count, memory_order_acquire);
    stats->capacity = cache->capacity;

    int total = stats->total_hits + stats->total_misses;
    stats->hit_ratio = total > 0 ? (float)stats->total_hits / total : 0.0f;
}

void cert_cache_print_stats(const cert_cache_t *cache) {
    if (!cache) {
        return;
    }

    cert_cache_stats_t stats;
    cert_cache_get_stats(cache, &stats);

    LOG_INFO("Certificate Cache Statistics:");
    LOG_INFO("  Entries:    %d / %d (%.1f%% full)",
            stats.current_count, stats.capacity,
            100.0f * stats.current_count / stats.capacity);
    LOG_INFO("  Hits:       %d (%.1f%%)",
            stats.total_hits, 100.0f * stats.hit_ratio);
    LOG_INFO("  Misses:     %d (%.1f%%)",
            stats.total_misses, 100.0f * (1.0f - stats.hit_ratio));
    LOG_INFO("  Evictions:  %d", stats.total_evictions);
}

/* Maintenance */

int cert_cache_evict_expired(cert_cache_t *cache, unsigned int max_age_sec) {
    if (!cache) {
        return 0;
    }

    if (max_age_sec == 0) {
        max_age_sec = 3600;  /* Default: 1 hour */
    }

    unsigned int now = process_uptime();
    int evicted = 0;

    pthread_rwlock_wrlock(&cache->lock);

    for (int i = 0; i < cache->capacity; i++) {
        if (cache->entries[i].valid) {
            unsigned int last_use = atomic_load_explicit(&cache->entries[i].last_use, memory_order_acquire);
            unsigned int age = now - last_use;

            if (age > max_age_sec) {
                LOG_DEBUG("Evicting expired cert: %s (age=%us)",
                         cache->entries[i].key.domain, age);

                SSL_CTX_free(cache->entries[i].ssl_ctx);
                memset(&cache->entries[i], 0, sizeof(cert_cache_entry_t));
                cache->entries[i].valid = false;

                atomic_fetch_sub(&cache->count, 1);
                evicted++;
            }
        }
    }

    pthread_rwlock_unlock(&cache->lock);

    if (evicted > 0) {
        LOG_INFO("Evicted %d expired cache entries", evicted);
    }

    return evicted;
}

void cert_cache_flush(cert_cache_t *cache) {
    if (!cache) {
        return;
    }

    pthread_rwlock_wrlock(&cache->lock);

    for (int i = 0; i < cache->capacity; i++) {
        if (cache->entries[i].valid && cache->entries[i].ssl_ctx) {
            SSL_CTX_free(cache->entries[i].ssl_ctx);
        }
        memset(&cache->entries[i], 0, sizeof(cert_cache_entry_t));
    }

    atomic_store(&cache->count, 0);

    pthread_rwlock_unlock(&cache->lock);

    LOG_INFO("Flushed cert cache");
}

int cert_cache_get_count(const cert_cache_t *cache) {
    return cache ? atomic_load_explicit(&cache->count, memory_order_acquire) : 0;
}

/* Legacy API compatibility */

SSL_CTX* sslctx_tbl_get_ctx(const char *domain) {
    if (!g_cert_cache || !domain) {
        return NULL;
    }

    /* Use default algorithm (ECDSA P-256) */
    cache_key_t key = cert_cache_make_key(domain, g_cert_cache->default_algorithm);
    return cert_cache_get(g_cert_cache, &key);
}

int sslctx_tbl_get_cnt_total(void) {
    return g_cert_cache ? atomic_load_explicit(&g_cert_cache->count, memory_order_acquire) : 0;
}

int sslctx_tbl_get_cnt_hit(void) {
    return g_cert_cache ? atomic_load_explicit(&g_cert_cache->stats.total_hits, memory_order_acquire) : 0;
}

int sslctx_tbl_get_cnt_miss(void) {
    return g_cert_cache ? atomic_load_explicit(&g_cert_cache->stats.total_misses, memory_order_acquire) : 0;
}

int sslctx_tbl_get_cnt_purge(void) {
    return g_cert_cache ? atomic_load_explicit(&g_cert_cache->stats.total_evictions, memory_order_acquire) : 0;
}

/* Session cache stats (placeholders - session caching is active via OpenSSL)
 *
 * NOTE: Session caching is IMPLEMENTED and ACTIVE (see tlsgateNG.c)
 * These functions are legacy stubs for compatibility.
 * OpenSSL's built-in session cache is used (100K sessions, 5min timeout)
 * For actual stats, query OpenSSL directly via SSL_CTX_sess_* functions
 */
int sslctx_tbl_get_sess_cnt(void) { return 0; }
int sslctx_tbl_get_sess_hit(void) { return 0; }
int sslctx_tbl_get_sess_miss(void) { return 0; }
int sslctx_tbl_get_sess_purge(void) { return 0; }
