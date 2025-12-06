/*
 * cert_index.h - Certificate Index System for 4-8M Certificates
 *
 * Sharded directory structure with binary-indexed lookup
 * - Scales to millions of certificates
 * - O(1) lookup with binary search
 * - Memory-mapped index for low memory footprint
 * - Lock-free reads (all-read, once-write pattern)
 *
 * Directory Layout:
 *   /certs/rsa/00/cert_000001.pem ... cert_031999.pem
 *   /certs/rsa/01/cert_000001.pem ... cert_031999.pem
 *   ...
 *   /certs/rsa/ff/...
 *   /certs/.index (binary-indexed, mmap'd)
 *
 * Index Format (18 bytes per entry):
 *   [domain_hash:4][shard_id:1][cert_id:4][expiry:8][flags:1]
 */

#ifndef CERT_INDEX_H
#define CERT_INDEX_H

#include <time.h>
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

/* Error codes */
typedef enum {
    CERT_INDEX_OK = 0,
    CERT_INDEX_ERR_INVALID = -1,
    CERT_INDEX_ERR_NOMEM = -2,
    CERT_INDEX_ERR_NOTFOUND = -3,
    CERT_INDEX_ERR_FULL = -4,
    CERT_INDEX_ERR_IO = -5,
    CERT_INDEX_ERR_CORRUPT = -6
} cert_index_error_t;

/* Index entry (18 bytes) */
typedef struct {
    uint32_t domain_hash;      /* CRC32 of domain (network byte order) */
    uint8_t shard_id;          /* Shard directory 00-ff */
    uint32_t cert_id;          /* Certificate ID within shard */
    uint64_t expiry;           /* Unix timestamp (network byte order) */
    uint8_t flags;             /* Reserved for future use */
} __attribute__((packed)) cert_index_entry_t;

/* Lookup result */
typedef struct {
    uint8_t shard_id;          /* Which shard directory (00-ff) */
    uint32_t cert_id;          /* Which cert file in shard */
    uint64_t expiry;           /* Expiration timestamp */
    bool found;                /* Entry exists in index */
} cert_index_result_t;

/* Opaque handle */
typedef struct cert_index cert_index_t;

/* Configuration */
typedef struct {
    const char *base_dir;      /* Base directory (/certs) */
    const char *ca_name;       /* Algorithm name (rsa, ecdsa, sm2) */
    size_t max_certs;          /* Maximum certificates to support (default: 2M) */
    bool create_dirs;          /* Create sharded directories if missing */
} cert_index_config_t;

/* ========== Lifecycle ========== */

/**
 * Create/Open certificate index
 *
 * @param config    Configuration
 * @return Handle or NULL on error
 */
cert_index_t* cert_index_create(const cert_index_config_t *config);

/**
 * Close and cleanup index
 */
void cert_index_destroy(cert_index_t *index);

/* ========== Lookups (Read-Only) ========== */

/**
 * Lookup certificate by domain
 *
 * Fast path: Binary search in mmap'd index (~0.1ms)
 *
 * @param index     Index handle
 * @param domain    Domain name (e.g., "example.com")
 * @param result    Output structure
 * @return CERT_INDEX_OK or error
 */
cert_index_error_t cert_index_lookup(const cert_index_t *index,
                                      const char *domain,
                                      cert_index_result_t *result);

/**
 * Lookup by domain hash (pre-computed CRC32)
 *
 * Faster if you already have hash (avoids CRC32 computation)
 *
 * @param index     Index handle
 * @param domain_hash  CRC32 hash of domain
 * @param result    Output structure
 * @return CERT_INDEX_OK or error
 */
cert_index_error_t cert_index_lookup_hash(const cert_index_t *index,
                                           uint32_t domain_hash,
                                           cert_index_result_t *result);

/**
 * Get filesystem path for certificate
 *
 * Returns path like: /certs/rsa/00/cert_000001.pem
 *
 * @param index     Index handle
 * @param shard_id  From lookup result
 * @param cert_id   From lookup result
 * @param path_buf  Output buffer (at least 256 bytes)
 * @param path_len  Buffer length
 * @return Bytes written, 0 on error
 */
size_t cert_index_get_path(const cert_index_t *index,
                            uint8_t shard_id,
                            uint32_t cert_id,
                            char *path_buf,
                            size_t path_len);

/* ========== Updates (Master Only) ========== */

/**
 * Register new certificate in index
 *
 * Called by master when writing new cert to disk.
 * Writes to append-only log; compaction is separate.
 *
 * @param index     Index handle
 * @param domain    Domain name
 * @param shard_id  Shard ID (0-255)
 * @param cert_id   Certificate ID in shard
 * @param expiry    Expiration timestamp
 * @return CERT_INDEX_OK or error
 */
cert_index_error_t cert_index_insert(cert_index_t *index,
                                      const char *domain,
                                      uint8_t shard_id,
                                      uint32_t cert_id,
                                      uint64_t expiry);

/**
 * Mark certificate as expired/revoked
 *
 * Removes from index (append deletion marker)
 *
 * @param index     Index handle
 * @param domain    Domain name
 * @return CERT_INDEX_OK or CERT_INDEX_ERR_NOTFOUND
 */
cert_index_error_t cert_index_delete(cert_index_t *index,
                                      const char *domain);

/**
 * Compact append-only log into binary index
 *
 * Called by master periodically (or after ~10k inserts)
 * Safe to run concurrently with reads (atomic rename)
 *
 * @param index     Index handle
 * @return CERT_INDEX_OK or error
 */
cert_index_error_t cert_index_compact(cert_index_t *index);

/**
 * Start background compaction thread
 *
 * Periodically compacts log every 5 minutes to ensure durability
 *
 * @param index     Index handle
 * @return CERT_INDEX_OK or error
 */
cert_index_error_t cert_index_start_compact(cert_index_t *index);

/**
 * Stop background compaction thread (graceful shutdown)
 *
 * @param index     Index handle
 */
void cert_index_stop_compact(cert_index_t *index);

/**
 * Rebuild index from existing certificates on first-time initialization
 *
 * Scans the sharded certificate directory and populates the index.
 * Called once on startup if index is empty.
 *
 * @param index     Index handle
 * @return CERT_INDEX_OK or error
 */
cert_index_error_t cert_index_rebuild(cert_index_t *index);

/* ========== Utilities ========== */

/**
 * Compute domain hash (CRC32)
 *
 * @param domain    Domain name
 * @return CRC32 hash
 */
uint32_t cert_index_domain_hash(const char *domain);

/**
 * Compute shard ID from hash
 *
 * @param domain_hash   CRC32 hash
 * @return Shard ID (0-255)
 */
static inline uint8_t cert_index_shard_id(uint32_t domain_hash) {
    return (uint8_t)(domain_hash & 0xFF);
}

/**
 * Get index statistics
 *
 * @param index     Index handle
 * @param count     Output: number of indexed certs
 * @param capacity  Output: maximum capacity
 * @return CERT_INDEX_OK or error
 */
cert_index_error_t cert_index_get_stats(const cert_index_t *index,
                                         size_t *count,
                                         size_t *capacity);

#endif /* CERT_INDEX_H */
