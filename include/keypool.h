/*
 * keypool.h - Simplified Key Pool for TLS Certificate Generation
 *
 * Local pool per worker instance (no shared memory)
 * Supports 3 CAs: RSA-3072, ECDSA-P256, SM2
 *
 * Design:
 * - Pre-generated key pool (default: 7000 per CA per worker)
 * - Background refill threads
 * - Lock-free reads (with locking for writes)
 * - Thread-safe statistics
 */

#ifndef KEYPOOL_H
#define KEYPOOL_H

#include <openssl/evp.h>
#include <stdint.h>
#include <stdbool.h>

/* Key generation algorithms */
typedef enum {
    KEYPOOL_ALG_RSA_3072,      /* RSA 3072-bit (standard, for legacy clients) */
    KEYPOOL_ALG_ECDSA_P256,    /* ECDSA P-256 (modern, fast) */
    KEYPOOL_ALG_SM2,           /* SM2 (Chinese standard) */
    KEYPOOL_ALG_MAX            /* Total number of algorithms */
} keypool_alg_t;

/* Error codes */
typedef enum {
    KEYPOOL_OK = 0,
    KEYPOOL_ERR_INVALID = -1,
    KEYPOOL_ERR_NOMEM = -2,
    KEYPOOL_ERR_EMPTY = -3,
    KEYPOOL_ERR_CRYPTO = -4,
    KEYPOOL_ERR_THREAD = -5
} keypool_error_t;

/* Statistics per algorithm */
typedef struct {
    int64_t generated;         /* Total generated */
    int64_t consumed;          /* Total consumed */
    int64_t available;         /* Currently in pool */
    int capacity;              /* Max capacity */
} keypool_stats_t;

/* Opaque keypool handle */
typedef struct keypool keypool_t;

/* Configuration */
typedef struct {
    int pool_size;             /* Keys per algorithm (default: 7000) */
    int refill_threads;        /* Background threads (default: 2) */
    bool enable_rsa_3072;      /* Enable RSA-3072 */
    bool enable_ecdsa_p256;    /* Enable ECDSA-P256 */
    bool enable_sm2;           /* Enable SM2 */
} keypool_config_t;

/* ========== Lifecycle ========== */

/**
 * Create key pool with configuration
 *
 * @param config    Configuration (NULL for defaults)
 * @return Handle or NULL on error
 */
keypool_t* keypool_create(const keypool_config_t *config);

/**
 * Destroy key pool and free resources
 */
void keypool_destroy(keypool_t *pool);

/* ========== Key Operations ========== */

/**
 * Acquire key from pool
 *
 * Fast path: Get pre-generated key from pool (~1 microsecond)
 * Slow path: Generate on-demand if pool empty (~50-500ms depending on algorithm)
 *
 * Caller MUST free with EVP_PKEY_free() when done.
 *
 * @param pool      Key pool handle
 * @param algorithm Algorithm to use
 * @return EVP_PKEY* or NULL on error
 */
EVP_PKEY* keypool_acquire(keypool_t *pool, keypool_alg_t algorithm);

/* ========== Control ========== */

/**
 * Start background refill threads
 *
 * @param pool  Key pool handle
 * @return KEYPOOL_OK or error
 */
keypool_error_t keypool_start_refill(keypool_t *pool);

/**
 * Stop background refill threads (graceful shutdown)
 *
 * @param pool  Key pool handle
 */
void keypool_stop_refill(keypool_t *pool);

/* ========== Statistics ========== */

/**
 * Get statistics for specific algorithm
 *
 * @param pool      Key pool handle
 * @param algorithm Algorithm
 * @param stats     Output statistics
 * @return KEYPOOL_OK or error
 */
keypool_error_t keypool_get_stats(const keypool_t *pool,
                                  keypool_alg_t algorithm,
                                  keypool_stats_t *stats);

/**
 * Get algorithm name (for logging)
 *
 * @param algorithm Algorithm
 * @return String (e.g., "RSA-3072")
 */
const char* keypool_algorithm_name(keypool_alg_t algorithm);

/* ========== Direct Generation (no pool) ========== */

/**
 * Generate single key without using pool
 *
 * For testing or one-off generation
 *
 * @param algorithm Algorithm to use
 * @return EVP_PKEY* or NULL on error
 */
EVP_PKEY* keypool_generate_key(keypool_alg_t algorithm);

#endif /* KEYPOOL_H */
