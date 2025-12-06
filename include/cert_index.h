/*
 * cert_index.h - High-Performance Certificate Index for TLSGate
 *
 * Unified index with composite keys (domain + algorithm)
 * Scales to 12M+ certificates with O(log n) lookup (~24 comparisons)
 *
 * Performance Features:
 *   - mmap'd index file (zero-copy, kernel page cache)
 *   - Binary search with prefetch
 *   - Lock-free reads (RCU-style updates)
 *   - Cache-aligned structures
 *   - Composite key: hash(domain + algo) for single lookup
 *
 * Directory Layout:
 *   pem_dir/index              (binary index, mmap'd)
 *   pem_dir/index.log          (append-only write log)
 *   pem_dir/{RSA,ECDSA,SM2}/certs/{shard:00-ff}/cert_{id}.pem
 */

#ifndef CERT_INDEX_H
#define CERT_INDEX_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdatomic.h>

/* Algorithm types */
typedef enum {
    CERT_ALG_RSA = 0,
    CERT_ALG_ECDSA = 1,
    CERT_ALG_SM2 = 2,
    CERT_ALG_MAX = 3
} cert_algo_t;

/* Error codes */
typedef enum {
    CERT_IDX_OK = 0,
    CERT_IDX_ERR_NOTFOUND = -1,
    CERT_IDX_ERR_NOMEM = -2,
    CERT_IDX_ERR_IO = -3,
    CERT_IDX_ERR_CORRUPT = -4,
    CERT_IDX_ERR_FULL = -5
} cert_index_err_t;

/*
 * Index Entry (16 bytes, cache-friendly)
 *
 * Composite hash includes domain + algorithm for single-lookup
 * Shard ID derived from hash for directory distribution
 */
typedef struct {
    uint32_t composite_hash;    /* FNV-1a(domain + algo) */
    uint32_t cert_id;           /* Certificate ID within shard */
    uint64_t expiry;            /* Unix timestamp (seconds) */
} __attribute__((packed, aligned(16))) cert_index_entry_t;

_Static_assert(sizeof(cert_index_entry_t) == 16, "Entry must be 16 bytes");

/*
 * Lookup Result
 */
typedef struct {
    cert_algo_t algo;           /* Algorithm (extracted from composite) */
    uint8_t shard_id;           /* Shard directory (00-ff) */
    uint32_t cert_id;           /* Certificate ID */
    uint64_t expiry;            /* Expiration timestamp */
    bool found;                 /* Entry exists */
} cert_index_result_t;

/*
 * Index Header (64 bytes, one cache line)
 */
typedef struct {
    uint32_t magic;             /* CIDX */
    uint32_t version;           /* Format version */
    uint64_t entry_count;       /* Number of entries */
    uint64_t capacity;          /* Maximum entries */
    uint64_t created_at;        /* Creation timestamp */
    uint64_t updated_at;        /* Last update timestamp */
    uint8_t  reserved[24];      /* Future use */
} __attribute__((packed, aligned(64))) cert_index_header_t;

#define CERT_INDEX_MAGIC 0x58444943  /* "CIDX" */
#define CERT_INDEX_VERSION 1

/*
 * Index Handle (opaque)
 */
typedef struct cert_index cert_index_t;

/*
 * Configuration
 */
typedef struct {
    const char *pem_dir;        /* Base directory */
    size_t max_entries;         /* Maximum certificates (default: 16M) */
    bool read_only;             /* Open read-only (for workers) */
    bool use_huge_pages;        /* Use MAP_HUGETLB if available */
    bool prefault;              /* Use MAP_POPULATE to prefault pages */
} cert_index_config_t;

/* Default configuration */
#define CERT_INDEX_DEFAULT_MAX_ENTRIES (16 * 1024 * 1024)

/* ==========================================================================
 * Lifecycle
 * ========================================================================== */

/**
 * Create/Open certificate index
 *
 * @param config  Configuration (NULL for defaults)
 * @return Handle or NULL on error
 */
cert_index_t *cert_index_open(const cert_index_config_t *config);

/**
 * Close and cleanup
 */
void cert_index_close(cert_index_t *idx);

/* ==========================================================================
 * Lookups (Lock-free, Thread-safe)
 * ========================================================================== */

/**
 * Lookup certificate by domain and algorithm
 *
 * Fast path: ~1 μs for 12M entries (24 comparisons + prefetch)
 *
 * @param idx     Index handle
 * @param domain  Domain name (e.g., "example.com")
 * @param algo    Algorithm (RSA, ECDSA, SM2)
 * @param result  Output result
 * @return CERT_IDX_OK or error
 */
cert_index_err_t cert_index_lookup(const cert_index_t *idx,
                                    const char *domain,
                                    cert_algo_t algo,
                                    cert_index_result_t *result);

/**
 * Lookup by pre-computed composite hash
 *
 * Even faster if you already have the hash
 *
 * @param idx     Index handle
 * @param hash    Composite hash (from cert_index_hash)
 * @param algo    Algorithm (for result)
 * @param result  Output result
 * @return CERT_IDX_OK or error
 */
cert_index_err_t cert_index_lookup_hash(const cert_index_t *idx,
                                         uint32_t hash,
                                         cert_algo_t algo,
                                         cert_index_result_t *result);

/* ==========================================================================
 * Updates (Master process only)
 * ========================================================================== */

/**
 * Insert new certificate into index
 *
 * Thread-safe via append-only log + periodic compaction
 *
 * @param idx       Index handle
 * @param domain    Domain name
 * @param algo      Algorithm
 * @param cert_id   Certificate ID
 * @param expiry    Expiration timestamp
 * @return CERT_IDX_OK or error
 */
cert_index_err_t cert_index_insert(cert_index_t *idx,
                                    const char *domain,
                                    cert_algo_t algo,
                                    uint32_t cert_id,
                                    uint64_t expiry);

/**
 * Remove certificate from index
 *
 * @param idx     Index handle
 * @param domain  Domain name
 * @param algo    Algorithm
 * @return CERT_IDX_OK or CERT_IDX_ERR_NOTFOUND
 */
cert_index_err_t cert_index_remove(cert_index_t *idx,
                                    const char *domain,
                                    cert_algo_t algo);

/**
 * Compact append-only log into sorted index
 *
 * Call periodically (e.g., every 5 minutes or 10k inserts)
 * Uses atomic rename for lock-free reader safety
 *
 * @param idx  Index handle
 * @return CERT_IDX_OK or error
 */
cert_index_err_t cert_index_compact(cert_index_t *idx);

/* ==========================================================================
 * Utilities
 * ========================================================================== */

/**
 * Compute composite hash for domain + algorithm
 *
 * Uses FNV-1a with algorithm suffix
 *
 * @param domain  Domain name
 * @param algo    Algorithm
 * @return Composite hash
 */
uint32_t cert_index_hash(const char *domain, cert_algo_t algo);

/**
 * Extract shard ID from composite hash
 *
 * Shard = lower 8 bits of hash (256 shards)
 */
static inline uint8_t cert_index_shard(uint32_t hash) {
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
 * @return Bytes written, 0 on error
 */
size_t cert_index_path(const cert_index_t *idx,
                        cert_algo_t algo,
                        uint8_t shard_id,
                        uint32_t cert_id,
                        char *buf,
                        size_t buf_len);

/**
 * Get algorithm name string
 */
static inline const char *cert_algo_name(cert_algo_t algo) {
    static const char *names[] = {"RSA", "ECDSA", "SM2"};
    return (algo < CERT_ALG_MAX) ? names[algo] : "UNKNOWN";
}

/**
 * Get index statistics
 */
typedef struct {
    uint64_t entry_count;       /* Current entries */
    uint64_t capacity;          /* Maximum capacity */
    uint64_t lookups;           /* Total lookups */
    uint64_t hits;              /* Cache hits */
    uint64_t misses;            /* Cache misses */
    size_t memory_bytes;        /* Memory usage */
} cert_index_stats_t;

cert_index_err_t cert_index_stats(const cert_index_t *idx,
                                   cert_index_stats_t *stats);

#endif /* CERT_INDEX_H */
