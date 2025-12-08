/*
 * cert_index_sharded.h - Per-Algorithm Sharded Certificate Index
 *
 * Maintains separate index files per algorithm (RSA, ECDSA, SM2).
 * Benefits:
 *   - Better cache locality (each worker typically uses one algo)
 *   - Parallel updates across algorithms
 *   - Smaller index files = faster binary search
 *   - Independent expiration per algorithm
 *
 * Directory Layout:
 *   pem_dir/RSA/index         (RSA certificates)
 *   pem_dir/ECDSA/index       (ECDSA certificates)
 *   pem_dir/SM2/index         (SM2 certificates)
 *   pem_dir/{algo}/certs/{shard:00-ff}/cert_{id}.pem
 */

#ifndef CERT_INDEX_SHARDED_H
#define CERT_INDEX_SHARDED_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdatomic.h>

/* Algorithm types - must match certs.h */
typedef enum {
    SHARD_ALG_RSA = 0,
    SHARD_ALG_ECDSA = 1,
    SHARD_ALG_SM2 = 2,
    SHARD_ALG_MAX = 3
} shard_algo_t;

/* Error codes */
typedef enum {
    SHARD_IDX_OK = 0,
    SHARD_IDX_ERR_NOTFOUND = -1,
    SHARD_IDX_ERR_NOMEM = -2,
    SHARD_IDX_ERR_IO = -3,
    SHARD_IDX_ERR_CORRUPT = -4,
    SHARD_IDX_ERR_FULL = -5,
    SHARD_IDX_ERR_ALGO = -6      /* Invalid algorithm */
} shard_index_err_t;

/*
 * Index Entry (16 bytes, cache-aligned)
 * Simpler than unified index - no algo in hash
 */
typedef struct {
    uint32_t domain_hash;       /* FNV-1a(domain) - lowercase */
    uint32_t cert_id;           /* Certificate ID within shard */
    uint64_t expiry;            /* Unix timestamp */
} __attribute__((packed, aligned(16))) shard_index_entry_t;

/*
 * Lookup Result
 */
typedef struct {
    shard_algo_t algo;          /* Which algorithm index */
    uint8_t shard_id;           /* Directory shard (00-ff) */
    uint32_t cert_id;           /* Certificate ID */
    uint64_t expiry;            /* Expiration timestamp */
    bool found;                 /* Entry exists */
} shard_index_result_t;

/*
 * Per-Algorithm Index Header (64 bytes)
 */
typedef struct {
    uint32_t magic;             /* "SIDn" where n = algo */
    uint32_t version;
    uint64_t entry_count;
    uint64_t capacity;
    uint64_t created_at;
    uint64_t updated_at;
    uint32_t algo_id;           /* Algorithm identifier */
    uint32_t next_cert_id;      /* Counter for new cert IDs */
    uint8_t  reserved[16];
} __attribute__((packed, aligned(64))) shard_index_header_t;

#define SHARD_INDEX_MAGIC_RSA   0x30444953  /* "SID0" */
#define SHARD_INDEX_MAGIC_ECDSA 0x31444953  /* "SID1" */
#define SHARD_INDEX_MAGIC_SM2   0x32444953  /* "SID2" */
#define SHARD_INDEX_VERSION 1

/*
 * Sharded Index Handle (opaque)
 */
typedef struct shard_index shard_index_t;

/*
 * Configuration
 */
typedef struct {
    const char *pem_dir;        /* Base directory */
    size_t max_entries_per_algo; /* Per-algorithm capacity (default: 4M) */
    bool read_only;             /* Open read-only (for workers) */
    bool use_huge_pages;        /* Use MAP_HUGETLB */
    bool prefault;              /* Use MAP_POPULATE */
    bool enable_udp;            /* Enable UDP write queue */
    uint16_t udp_port;          /* UDP port (0 for default) */
} shard_index_config_t;

/* Defaults */
#define SHARD_INDEX_DEFAULT_MAX_ENTRIES (4 * 1024 * 1024)

/* ==========================================================================
 * Lifecycle
 * ========================================================================== */

/**
 * Open sharded index
 *
 * Creates/opens index files for all enabled algorithms.
 *
 * @param config  Configuration
 * @return Handle or NULL on error
 */
shard_index_t *shard_index_open(const shard_index_config_t *config);

/**
 * Close and cleanup all shards
 */
void shard_index_close(shard_index_t *idx);

/* ==========================================================================
 * Lookups (Lock-free, Thread-safe)
 * ========================================================================== */

/**
 * Lookup certificate by domain and algorithm
 *
 * Searches only the specified algorithm's index.
 *
 * @param idx     Index handle
 * @param domain  Domain name
 * @param algo    Algorithm to search
 * @param result  Output result
 * @return SHARD_IDX_OK or error
 */
shard_index_err_t shard_index_lookup(const shard_index_t *idx,
                                      const char *domain,
                                      shard_algo_t algo,
                                      shard_index_result_t *result);

/**
 * Lookup certificate in any algorithm (priority order)
 *
 * Searches in order: requested algo first, then fallback order.
 * Order: ECDSA > RSA > SM2 (most common first)
 *
 * @param idx          Index handle
 * @param domain       Domain name
 * @param prefer_algo  Preferred algorithm (checked first)
 * @param result       Output result (includes which algo found it)
 * @return SHARD_IDX_OK if found in any, SHARD_IDX_ERR_NOTFOUND if none
 */
shard_index_err_t shard_index_lookup_any(const shard_index_t *idx,
                                          const char *domain,
                                          shard_algo_t prefer_algo,
                                          shard_index_result_t *result);

/**
 * Lookup by pre-computed hash
 */
shard_index_err_t shard_index_lookup_hash(const shard_index_t *idx,
                                           uint32_t hash,
                                           shard_algo_t algo,
                                           shard_index_result_t *result);

/* ==========================================================================
 * Updates (Master process only, or via UDP)
 * ========================================================================== */

/**
 * Insert certificate
 *
 * If UDP is enabled, this queues to UDP for async processing.
 * Otherwise, writes directly to the algorithm's index.
 *
 * @param idx       Index handle
 * @param domain    Domain name
 * @param algo      Algorithm
 * @param expiry    Expiration timestamp
 * @param cert_id   Output: assigned certificate ID (can be NULL)
 * @return SHARD_IDX_OK or error
 */
shard_index_err_t shard_index_insert(shard_index_t *idx,
                                      const char *domain,
                                      shard_algo_t algo,
                                      uint64_t expiry,
                                      uint32_t *cert_id);

/**
 * Remove certificate
 *
 * @param idx     Index handle
 * @param domain  Domain name
 * @param algo    Algorithm
 * @return SHARD_IDX_OK or SHARD_IDX_ERR_NOTFOUND
 */
shard_index_err_t shard_index_remove(shard_index_t *idx,
                                      const char *domain,
                                      shard_algo_t algo);

/**
 * Compact all shards
 */
shard_index_err_t shard_index_compact(shard_index_t *idx);

/* ==========================================================================
 * Utilities
 * ========================================================================== */

/**
 * Compute domain hash (FNV-1a, lowercase)
 */
uint32_t shard_index_hash(const char *domain);

/**
 * Get shard directory ID from hash
 */
static inline uint8_t shard_index_shard_id(uint32_t hash) {
    return (uint8_t)(hash & 0xFF);
}

/**
 * Build filesystem path for certificate
 *
 * @param idx       Index handle
 * @param algo      Algorithm
 * @param shard_id  Shard directory
 * @param cert_id   Certificate ID
 * @param buf       Output buffer
 * @param buf_len   Buffer length
 * @return Bytes written
 */
size_t shard_index_cert_path(const shard_index_t *idx,
                              shard_algo_t algo,
                              uint8_t shard_id,
                              uint32_t cert_id,
                              char *buf,
                              size_t buf_len);

/**
 * Get algorithm name string
 */
static inline const char *shard_algo_name(shard_algo_t algo) {
    static const char *names[] = {"RSA", "ECDSA", "SM2"};
    return (algo < SHARD_ALG_MAX) ? names[algo] : "UNKNOWN";
}

/**
 * Allocate next certificate ID for algorithm
 *
 * Thread-safe, monotonically increasing.
 *
 * @param idx   Index handle
 * @param algo  Algorithm
 * @return New certificate ID, or 0 on error
 */
uint32_t shard_index_alloc_cert_id(shard_index_t *idx, shard_algo_t algo);

/**
 * Get statistics
 */
typedef struct {
    uint64_t entry_count;       /* Current entries */
    uint64_t capacity;          /* Maximum capacity */
    uint64_t lookups;           /* Total lookups */
    uint64_t hits;              /* Cache hits */
    uint64_t misses;            /* Cache misses */
    size_t memory_bytes;        /* Memory usage */
} shard_index_algo_stats_t;

typedef struct {
    shard_index_algo_stats_t per_algo[SHARD_ALG_MAX];
    uint64_t total_entries;
    uint64_t total_lookups;
    size_t total_memory;
} shard_index_stats_t;

shard_index_err_t shard_index_stats(const shard_index_t *idx,
                                     shard_index_stats_t *stats);

#endif /* CERT_INDEX_SHARDED_H */
