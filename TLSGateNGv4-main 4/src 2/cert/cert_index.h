/**
 * Certificate Index System
 *
 * High-performance certificate index for 10M+ domains with:
 * - O(1) hash table lookups
 * - Sorted expiry array for efficient renewal scans
 * - LRU eviction for SSL_CTX objects (~20GB RAM target)
 * - Disk overflow for cold entries
 * - Async persistence every 10 minutes
 * - Background renewal thread (2-4h random interval)
 *
 * RAM Budget (~20GB):
 * - Hash table metadata: ~3GB (10M x 300 bytes)
 * - Sorted expiry array: ~80MB (10M x 8 bytes pointers)
 * - LRU SSL_CTX cache: ~16GB (2M active domains x 8KB)
 * - Overhead: ~1GB
 *
 * Author: Torsten Jahnke
 * Copyright: 2025 Aviontex GmbH
 */

#ifndef CERT_INDEX_H
#define CERT_INDEX_H

#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include "../common_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
typedef struct cert_index cert_index_t;
typedef struct cert_index_entry cert_index_entry_t;

/* Configuration for certificate index */
typedef struct {
    const char *persist_dir;         /* Directory for index files (e.g., /opt/Aviontex/index/RSA) */
    const char *disk_cache_dir;      /* Directory for certificate PEM files (e.g., /opt/Aviontex/certs/RSA) */
    size_t max_entries;              /* Max domains (e.g., 10M) */
    size_t lru_cache_size;           /* Max SSL_CTX in RAM (e.g., 2M) */
    size_t hash_buckets;             /* Hash table size (should be prime, ~10M) */
    uint32_t renewal_threshold_days; /* Start renewal N days before expiry (e.g., 14) */
    uint32_t renewal_min_interval;   /* Min hours between renewal checks (e.g., 2) */
    uint32_t renewal_max_interval;   /* Max hours between renewal checks (e.g., 4) */
    uint32_t save_interval_sec;      /* Async save interval in seconds (e.g., 600 = 10min) */
    uint32_t max_renewals_per_scan;  /* Rate limit for renewals (e.g., 10000) */
    uid_t owner_uid;                 /* Expected owner UID for security */
    gid_t owner_gid;                 /* Expected owner GID for security */
    mode_t file_mode;                /* Expected file permissions (e.g., 0600) */
    bool is_master;                  /* true=Master (saves/renews), false=Worker (read-only) */
} cert_index_config_t;

/* Statistics for monitoring */
typedef struct {
    _Atomic uint64_t total_entries;      /* Total domains in index */
    _Atomic uint64_t active_entries;     /* Domains with SSL_CTX in RAM */
    _Atomic uint64_t cache_hits;         /* LRU cache hits */
    _Atomic uint64_t cache_misses;       /* LRU cache misses (disk load) */
    _Atomic uint64_t evictions;          /* SSL_CTX evictions to disk */
    _Atomic uint64_t renewals;           /* Successful renewals */
    _Atomic uint64_t renewal_errors;     /* Failed renewals */
    _Atomic uint64_t disk_saves;         /* Index saves to disk */
    _Atomic uint64_t disk_loads;         /* Index loads from disk */
    _Atomic uint64_t permission_errors;  /* Security validation failures */
} cert_index_stats_t;

/**
 * Create and initialize certificate index
 *
 * @param config Configuration parameters
 * @return Index handle or NULL on error
 *
 * NOTE: This will load existing index from disk if available.
 *       If permissions are invalid, old index is deleted and rebuilt.
 */
cert_index_t* cert_index_create(const cert_index_config_t *config);

/**
 * Destroy certificate index and free resources
 *
 * @param index Index handle
 *
 * NOTE: This triggers a final save to disk before cleanup.
 */
void cert_index_destroy(cert_index_t *index);

/**
 * Add or update certificate in index
 *
 * @param index      Index handle
 * @param domain     Domain name (will be copied)
 * @param ctx        SSL_CTX (reference count incremented)
 * @param cert       Certificate (for metadata extraction)
 * @param algorithm  Key algorithm used
 * @return true on success, false on error
 *
 * NOTE: SSL_CTX is added to LRU cache. If cache is full,
 *       least recently used entry is evicted to disk.
 */
bool cert_index_add(cert_index_t *index,
                    const char *domain,
                    SSL_CTX *ctx,
                    X509 *cert,
                    crypto_alg_t algorithm);

/**
 * Get certificate from index
 *
 * @param index     Index handle
 * @param domain    Domain name
 * @param algorithm Key algorithm
 * @return SSL_CTX or NULL if not found
 *
 * NOTE: This updates LRU timestamp. If SSL_CTX is on disk,
 *       it will be loaded and potentially evict another entry.
 */
SSL_CTX* cert_index_get(cert_index_t *index,
                        const char *domain,
                        crypto_alg_t algorithm);

/**
 * Check if certificate exists in index
 *
 * @param index     Index handle
 * @param domain    Domain name
 * @param algorithm Key algorithm
 * @return true if exists (in RAM or on disk), false otherwise
 *
 * NOTE: This is a lightweight check that doesn't load from disk.
 */
bool cert_index_exists(cert_index_t *index,
                       const char *domain,
                       crypto_alg_t algorithm);

/**
 * Remove certificate from index
 *
 * @param index     Index handle
 * @param domain    Domain name
 * @param algorithm Key algorithm
 * @return true on success, false if not found
 *
 * NOTE: This frees SSL_CTX and removes from all structures.
 */
bool cert_index_remove(cert_index_t *index,
                       const char *domain,
                       crypto_alg_t algorithm);

/**
 * Scan index for certificates expiring soon and renew them
 *
 * @param index     Index handle
 * @param gen       Certificate generator for renewals
 * @return Number of certificates renewed
 *
 * NOTE: This is called by background thread every 2-4 hours.
 *       Rate limited to max_renewals_per_scan.
 */
size_t cert_index_renewal_scan(cert_index_t *index, void *gen);

/**
 * Force immediate save of index to disk
 *
 * @param index Index handle
 * @return true on success, false on error
 *
 * NOTE: This is synchronous. Normal operation uses async saves.
 */
bool cert_index_save(cert_index_t *index);

/**
 * Get current statistics
 *
 * @param index Index handle
 * @param stats Output statistics structure
 */
void cert_index_get_stats(cert_index_t *index, cert_index_stats_t *stats);

/**
 * Start background renewal thread
 *
 * @param index Index handle
 * @param gen   Certificate generator for renewals
 * @return true on success, false on error
 *
 * NOTE: Thread runs every 2-4 hours (random) and calls cert_index_renewal_scan()
 */
bool cert_index_start_renewal_thread(cert_index_t *index, void *gen);

/**
 * Stop background renewal thread
 *
 * @param index Index handle
 *
 * NOTE: This blocks until thread exits cleanly
 */
void cert_index_stop_renewal_thread(cert_index_t *index);

/**
 * Start async save thread
 *
 * @param index Index handle
 * @return true on success, false on error
 *
 * NOTE: Thread saves index to disk every save_interval_sec seconds
 */
bool cert_index_start_save_thread(cert_index_t *index);

/**
 * Stop async save thread
 *
 * @param index Index handle
 *
 * NOTE: This blocks until thread exits cleanly and triggers final save
 */
void cert_index_stop_save_thread(cert_index_t *index);

#ifdef __cplusplus
}
#endif

#endif /* CERT_INDEX_H */
