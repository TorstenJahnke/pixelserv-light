/* TLS-Gate NX - Certificate Cache
 * Copyright (C) 2025 Torsten Jahnke
 *
 * High-performance SSL_CTX cache with:
 * - Compound key: Domain + Algorithm (supports ECDSA + RSA per domain!)
 * - LRU eviction per algorithm
 * - Thread-safe with C11 atomics
 * - Shared memory index across 10 instances per IP
 * - Local SSL_CTX cache (per process)
 */

#ifndef TLSGATENG_CERT_CACHE_H
#define TLSGATENG_CERT_CACHE_H

#include "../common_types.h"
#include "../ipc/shm_manager.h"
#include <openssl/ssl.h>
#include <stdbool.h>
#include <stdatomic.h>

/* Error codes */
typedef enum {
    CERT_CACHE_OK = 0,
    CERT_CACHE_ERR_INVALID = -1,
    CERT_CACHE_ERR_NOMEM = -2,
    CERT_CACHE_ERR_NOTFOUND = -3,
    CERT_CACHE_ERR_FULL = -4
} cert_cache_error_t;

/* Cache key - Domain + Algorithm (compound key!) */
typedef struct {
    char domain[CERT_INDEX_ENTRY_NAME_LEN];
    crypto_alg_t algorithm;
} __attribute__((aligned(8))) cache_key_t;

/* Cache entry - Local SSL_CTX storage */
typedef struct {
    cache_key_t key;                 /* Domain + Algorithm */
    SSL_CTX *ssl_ctx;                /* SSL context */

    atomic_uint last_use;            /* process_uptime() for LRU */
    atomic_int reuse_count;          /* How many times reused */

    bool valid;                      /* Entry is valid */
    uint8_t reserved[7];             /* Padding */
} __attribute__((aligned(64))) cert_cache_entry_t;  /* Cache-line aligned */

/* Cache statistics */
typedef struct {
    atomic_int total_hits;           /* Cache hits */
    atomic_int total_misses;         /* Cache misses */
    atomic_int total_evictions;      /* LRU evictions */
    atomic_int current_count;        /* Current entries */
    int capacity;                    /* Max capacity */
    float hit_ratio;                 /* hits / (hits + misses) */
} cert_cache_stats_t;

/* Opaque cache handle */
typedef struct cert_cache cert_cache_t;

/* Cache Lifecycle */

/* Create certificate cache
 *
 * @param local_capacity   Local cache size (default: 100)
 * @param pem_dir         Certificate directory (for SHM name)
 * @param pool_name       Optional pool name (for multi-instance)
 * @return Cache handle or NULL on error
 */
cert_cache_t* cert_cache_create(int local_capacity,
                                 const char *pem_dir,
                                 const char *pool_name);

/* Destroy cache and free resources */
void cert_cache_destroy(cert_cache_t *cache);

/* Cache Operations */

/* Get SSL_CTX from cache
 *
 * @param cache  Cache handle
 * @param key    Lookup key (domain + algorithm)
 * @return SSL_CTX* or NULL if not found
 */
SSL_CTX* cert_cache_get(cert_cache_t *cache, const cache_key_t *key);

/* Put SSL_CTX into cache
 *
 * @param cache    Cache handle
 * @param key      Cache key (domain + algorithm)
 * @param ssl_ctx  SSL context to cache
 * @return CERT_CACHE_OK on success
 */
cert_cache_error_t cert_cache_put(cert_cache_t *cache,
                                   const cache_key_t *key,
                                   SSL_CTX *ssl_ctx);

/* Remove entry from cache
 *
 * @param cache  Cache handle
 * @param key    Key to remove
 * @return CERT_CACHE_OK if removed, CERT_CACHE_ERR_NOTFOUND otherwise
 */
cert_cache_error_t cert_cache_remove(cert_cache_t *cache, const cache_key_t *key);

/* Statistics */

/* Get cache statistics */
void cert_cache_get_stats(const cert_cache_t *cache, cert_cache_stats_t *stats);

/* Print statistics to log */
void cert_cache_print_stats(const cert_cache_t *cache);

/* Maintenance */

/* Evict expired entries (call periodically)
 *
 * @param cache       Cache handle
 * @param max_age_sec Maximum age in seconds (0 = use default)
 * @return Number of entries evicted
 */
int cert_cache_evict_expired(cert_cache_t *cache, unsigned int max_age_sec);

/* Flush all entries (for testing/debugging) */
void cert_cache_flush(cert_cache_t *cache);

/* Get current cache size */
int cert_cache_get_count(const cert_cache_t *cache);

/* Utility Functions */

/* Create cache key from domain and algorithm */
static inline cache_key_t cert_cache_make_key(const char *domain,
                                               crypto_alg_t algorithm) {
    cache_key_t key = {0};
    if (domain) {
        strncpy(key.domain, domain, sizeof(key.domain) - 1);
    }
    key.algorithm = algorithm;
    return key;
}

/* Compare cache keys */
static inline bool cert_cache_key_equal(const cache_key_t *a,
                                        const cache_key_t *b) {
    if (!a || !b) return false;
    return (strcmp(a->domain, b->domain) == 0 &&
            a->algorithm == b->algorithm);
}

/* Get algorithm from cache key */
static inline crypto_alg_t cert_cache_key_algorithm(const cache_key_t *key) {
    return key ? key->algorithm : CRYPTO_ALG_AUTO;
}

/* Legacy API compatibility */

/* Get cert by domain only (uses default algorithm) */
SSL_CTX* sslctx_tbl_get_ctx(const char *domain);

/* Statistics functions (old API) */
int sslctx_tbl_get_cnt_total(void);
int sslctx_tbl_get_cnt_hit(void);
int sslctx_tbl_get_cnt_miss(void);
int sslctx_tbl_get_cnt_purge(void);
int sslctx_tbl_get_sess_cnt(void);
int sslctx_tbl_get_sess_hit(void);
int sslctx_tbl_get_sess_miss(void);
int sslctx_tbl_get_sess_purge(void);

#endif /* TLSGATENG_CERT_CACHE_H */
