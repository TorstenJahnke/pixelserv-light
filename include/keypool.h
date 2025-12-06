/*
 * keypool.h - High-Performance Key Pool for TLSGate
 *
 * Lock-free key acquisition for TLS certificate generation
 *
 * Architecture:
 *   - RSA-3072: Pre-computed primes (mmap'd), instant key generation
 *   - ECDSA-P256: Background agent threads refill pool
 *   - SM2: Background agent threads refill pool
 *
 * Performance:
 *   - RSA from primes: ~1 μs per key (vs 50-500 ms generating primes)
 *   - ECDSA/SM2: ~100 μs from pool, 1-5 ms if generating
 *   - Lock-free acquire via atomic operations
 *   - 2 min → 1.1M RSA-3072 keys with primes
 *
 * Directory Layout:
 *   pem_dir/primes/rsa3072_p.bin   (mmap'd P primes, 192 bytes each)
 *   pem_dir/primes/rsa3072_q.bin   (mmap'd Q primes, 192 bytes each)
 */

#ifndef KEYPOOL_H
#define KEYPOOL_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <openssl/evp.h>

/* Algorithm types */
typedef enum {
    KEYPOOL_ALG_RSA_3072 = 0,   /* RSA 3072-bit (from primes) */
    KEYPOOL_ALG_ECDSA_P256 = 1, /* ECDSA P-256 (agent generated) */
    KEYPOOL_ALG_SM2 = 2,        /* SM2 (agent generated) */
    KEYPOOL_ALG_MAX = 3
} keypool_alg_t;

/* Error codes */
typedef enum {
    KEYPOOL_OK = 0,
    KEYPOOL_ERR_EMPTY = -1,
    KEYPOOL_ERR_NOMEM = -2,
    KEYPOOL_ERR_CRYPTO = -3,
    KEYPOOL_ERR_IO = -4,
    KEYPOOL_ERR_PRIMES = -5
} keypool_err_t;

/* Opaque handle */
typedef struct keypool keypool_t;

/* Configuration */
typedef struct {
    const char *pem_dir;        /* Directory with primes/ subdirectory */

    /* Pool sizes per algorithm */
    int rsa_pool_size;          /* RSA pool size (default: 10000) */
    int ecdsa_pool_size;        /* ECDSA pool size (default: 10000) */
    int sm2_pool_size;          /* SM2 pool size (default: 5000) */

    /* Agent configuration */
    int ecdsa_agents;           /* ECDSA generator agents (default: 1) */
    int sm2_agents;             /* SM2 generator agents (default: 1) */

    /* Refill thresholds (refill when pool drops below this %) */
    int refill_threshold_pct;   /* Default: 20% */

    /* Disable algorithms */
    bool disable_rsa;
    bool disable_ecdsa;
    bool disable_sm2;
} keypool_config_t;

/* Default configuration */
#define KEYPOOL_DEFAULT_RSA_SIZE    10000
#define KEYPOOL_DEFAULT_ECDSA_SIZE  10000
#define KEYPOOL_DEFAULT_SM2_SIZE    5000
#define KEYPOOL_DEFAULT_AGENTS      1
#define KEYPOOL_DEFAULT_THRESHOLD   20

/* ==========================================================================
 * Lifecycle
 * ========================================================================== */

/**
 * Create key pool
 *
 * Loads RSA primes from pem_dir/primes/
 * Starts background agents for ECDSA/SM2
 *
 * @param config  Configuration (NULL for defaults)
 * @return Handle or NULL on error
 */
keypool_t *keypool_create(const keypool_config_t *config);

/**
 * Destroy key pool
 *
 * Stops agents, frees all keys
 */
void keypool_destroy(keypool_t *pool);

/* ==========================================================================
 * Key Acquisition (Lock-free)
 * ========================================================================== */

/**
 * Acquire key from pool
 *
 * Fast path (pool has keys): ~1 μs
 * Slow path (generate on demand): 1-500 ms depending on algorithm
 *
 * Caller MUST free returned key with EVP_PKEY_free()
 *
 * @param pool  Key pool handle
 * @param algo  Algorithm
 * @return EVP_PKEY* or NULL on error
 */
EVP_PKEY *keypool_acquire(keypool_t *pool, keypool_alg_t algo);

/**
 * Return unused key to pool
 *
 * Optional optimization - if key wasn't used, return it
 *
 * @param pool  Key pool handle
 * @param algo  Algorithm
 * @param key   Key to return (ownership transferred)
 */
void keypool_return(keypool_t *pool, keypool_alg_t algo, EVP_PKEY *key);

/* ==========================================================================
 * Control
 * ========================================================================== */

/**
 * Start background refill agents
 *
 * Called automatically by keypool_create()
 */
keypool_err_t keypool_start_agents(keypool_t *pool);

/**
 * Stop background refill agents
 *
 * Called automatically by keypool_destroy()
 */
void keypool_stop_agents(keypool_t *pool);

/**
 * Pre-warm pool to target level
 *
 * Blocks until pool reaches target % full
 * Useful for startup warming
 *
 * @param pool         Key pool handle
 * @param target_pct   Target fill percentage (1-100)
 * @param timeout_sec  Timeout in seconds (0 = no timeout)
 * @return KEYPOOL_OK or error
 */
keypool_err_t keypool_prewarm(keypool_t *pool, int target_pct, int timeout_sec);

/* ==========================================================================
 * Statistics
 * ========================================================================== */

typedef struct {
    /* Per-algorithm stats */
    struct {
        int64_t available;      /* Currently in pool */
        int64_t capacity;       /* Pool capacity */
        int64_t generated;      /* Total generated */
        int64_t acquired;       /* Total acquired */
        int64_t returned;       /* Total returned */
        int64_t slow_path;      /* On-demand generations (pool empty) */
    } alg[KEYPOOL_ALG_MAX];

    /* RSA primes stats */
    size_t primes_loaded;       /* Number of prime pairs loaded */
    size_t primes_used;         /* Prime pairs consumed */

    /* Agent stats */
    int agents_running;         /* Active agent threads */
} keypool_stats_t;

keypool_err_t keypool_stats(const keypool_t *pool, keypool_stats_t *stats);

/**
 * Get algorithm name
 */
static inline const char *keypool_alg_name(keypool_alg_t algo) {
    static const char *names[] = {"RSA-3072", "ECDSA-P256", "SM2"};
    return (algo < KEYPOOL_ALG_MAX) ? names[algo] : "UNKNOWN";
}

/* ==========================================================================
 * Direct Generation (bypass pool)
 * ========================================================================== */

/**
 * Generate single key without using pool
 *
 * For testing or when pool is unavailable
 * WARNING: Slow for RSA without primes!
 *
 * @param algo  Algorithm
 * @return EVP_PKEY* or NULL
 */
EVP_PKEY *keypool_generate_direct(keypool_alg_t algo);

/**
 * Generate RSA key from provided primes
 *
 * @param p     Prime P (192 bytes for 3072-bit)
 * @param q     Prime Q (192 bytes for 3072-bit)
 * @param len   Length of each prime in bytes
 * @return EVP_PKEY* or NULL
 */
EVP_PKEY *keypool_generate_rsa_from_primes(const unsigned char *p,
                                            const unsigned char *q,
                                            size_t len);

#endif /* KEYPOOL_H */
