/* TLS-Gate NX - Cryptographic Key Pool
 * Copyright (C) 2025 Torsten Jahnke
 *
 * High-performance key generation and pooling:
 * - RSA 3072/4096 (traditional, secure)
 * - ECDSA P-256/P-384/P-521 (10× faster than RSA!)
 * - EdDSA Ed25519 (future - fastest)
 * - Prime Pool for instant RSA generation
 * - Multi-threaded background generation
 * - Shared memory pool for 40+ instances
 */

#ifndef TLSGATENG_KEYPOOL_H
#define TLSGATENG_KEYPOOL_H

#include "../common_types.h"
#include "../ipc/shm_manager.h"
#include <openssl/evp.h>
#include <stdbool.h>

/* Error codes */
typedef enum {
    KEYPOOL_OK = 0,
    KEYPOOL_ERR_INVALID = -1,
    KEYPOOL_ERR_NOMEM = -2,
    KEYPOOL_ERR_EMPTY = -3,
    KEYPOOL_ERR_FULL = -4,
    KEYPOOL_ERR_CRYPTO = -5,
    KEYPOOL_ERR_THREAD = -6,
    KEYPOOL_ERR_IO = -7
} keypool_error_t;

/* Keypool configuration */
typedef struct {
    crypto_alg_t default_algorithm;  /* Default algorithm (primary) */

    /* Force single algorithm mode (for demos/testing)
     * If set, ONLY this algorithm will be used, ignoring enable_multi_algorithm */
    bool force_single_algorithm;     /* Enable force mode */
    crypto_alg_t forced_algorithm;   /* Forced algorithm (if force_single_algorithm=true) */

    /* Multi-Algorithm Pool Support - Enable/Disable algorithms */
    bool enable_multi_algorithm;     /* Enable multiple algorithms in pool */
    bool enable_rsa_2048;            /* RSA-2048 (legacy, requires primes) */
    bool enable_rsa_3072;            /* RSA-3072 (standard, requires primes) */
    bool enable_rsa_4096;            /* RSA-4096 (high-sec, requires primes) */
    bool enable_ecdsa_p256;          /* ECDSA P-256 (fast, modern) */
    bool enable_ecdsa_p384;          /* ECDSA P-384 (high-sec) */
    bool enable_ecdsa_p521;          /* ECDSA P-521 (very high-sec) */
    bool enable_sm2;                 /* SM2 (Chinese standard, OpenSSL 3.0+) */

    /* Pool distribution (percent of pool per algorithm, must sum to 100) */
    int rsa_2048_percent;            /* % of pool for RSA-2048 (default: 10%) */
    int rsa_3072_percent;            /* % of pool for RSA-3072 (default: 25%) */
    int rsa_4096_percent;            /* % of pool for RSA-4096 (default: 10%) */
    int ecdsa_p256_percent;          /* % of pool for ECDSA-P256 (default: 45%) */
    int ecdsa_p384_percent;          /* % of pool for ECDSA-P384 (default: 3%) */
    int ecdsa_p521_percent;          /* % of pool for ECDSA-P521 (default: 2%) */
    int sm2_percent;                 /* % of pool for SM2 (default: 5%) */

    int local_pool_size;             /* Local pool size (fallback) */
    int refill_thread_count;         /* Background threads (deprecated - now adaptive) */
    bool use_shared_memory;          /* Use SHM pool */
    bool enable_prime_pool;          /* Enable prime pool (RSA 2048/3072/4096) */
    const char *prime_pool_dir;      /* Directory with prime-{size}.bin files */

    /* Automatic backup (every 30 minutes) */
    bool enable_backup;              /* Enable automatic backup to disk */
    const char *backup_dir;          /* Directory for backup bundle file */
    bool encrypt_backup;             /* Encrypt backup with CA-key derived password */
    const char *ca_key_path;         /* Path to CA private key (for encryption) */
    uint32_t backup_curve;           /* Curve parameter for key derivation (format: LLPPXX) */
                                     /* LL=line, PP=position, XX=length */
} keypool_config_t;

/* Keypool statistics */
typedef struct {
    atomic_int total_generated;      /* Total keys generated */
    atomic_int total_consumed;       /* Total keys consumed */
    atomic_int cache_hits;           /* Keys from pool */
    atomic_int cache_misses;         /* Generated on-demand */
    atomic_int current_available;    /* Currently available */
    int pool_capacity;               /* Max capacity */
    float fill_ratio;                /* available / capacity */
} keypool_stats_t;

/* Opaque keypool handle */
typedef struct keypool keypool_t;

/* Configuration Helpers */

/* Get default multi-algorithm configuration
 *
 * Recommended distribution for mixed RSA + ECDSA:
 * - ECDSA P-256:  50% (fast generation, modern clients)
 * - RSA-3072:     25% (legacy clients, standard security) - INCREASED for high load!
 * - RSA-2048:     10% (very old clients, ATMs, Windows 3.11/95/98)
 * - RSA-4096:     10% (high-security requirements)
 * - ECDSA P-384:   3% (high-security, slower)
 * - ECDSA P-521:   2% (very high-security, slowest)
 *
 * Total: 100% = 200,000 keys distributed across algorithms
 *
 * NOTE: RSA requires prime pools! Generate with tlsgateNG-poolgen:
 *   tlsgateNG-poolgen -g 2048 -o prime-2048.bin
 *   tlsgateNG-poolgen -g 3072 -o prime-3072.bin
 *   tlsgateNG-poolgen -g 4096 -o prime-4096.bin
 */
static inline keypool_config_t keypool_config_multi_algo_default(void) {
    return (keypool_config_t){
        .default_algorithm = CRYPTO_ALG_ECDSA_P256,  /* Primary algorithm */

        /* Force mode disabled by default */
        .force_single_algorithm = false,
        .forced_algorithm = CRYPTO_ALG_AUTO,

        /* Enable only practical algorithms (RSA-3072, ECDSA-P256, SM2) */
        .enable_multi_algorithm = true,
        .enable_rsa_2048 = false,   /* Legacy only - use [legacy] section */
        .enable_rsa_3072 = true,    /* Standard RSA */
        .enable_rsa_4096 = false,   /* Overkill - RSA-3072 is sufficient */
        .enable_ecdsa_p256 = true,  /* Fast, modern, 128-bit security */
        .enable_ecdsa_p384 = false, /* Overkill - P256 is sufficient */
        .enable_ecdsa_p521 = false, /* Overkill - rarely needed */
        .enable_sm2 = true,         /* Chinese standard */

        /* Distribution: ECDSA-heavy (fast), RSA for compatibility, SM2 for China */
        .rsa_2048_percent = 0,      /* Disabled */
        .rsa_3072_percent = 30,     /* Standard RSA */
        .rsa_4096_percent = 0,      /* Disabled */
        .ecdsa_p256_percent = 60,   /* Primary (fast) */
        .ecdsa_p384_percent = 0,    /* Disabled */
        .ecdsa_p521_percent = 0,    /* Disabled */
        .sm2_percent = 10,          /* Chinese standard */

        .local_pool_size = 20000,
        .refill_thread_count = 0,  /* Auto-detect (deprecated) */
        .use_shared_memory = true,
        .enable_prime_pool = true,
        .prime_pool_dir = NULL,  /* Will use /opt/tlsgateNG/prime/primes */

        /* Backup disabled by default (enable for production) */
        .enable_backup = false,
        .backup_dir = NULL,        /* Set to enable automatic backups */
        .encrypt_backup = false,   /* Enable encryption (requires ca_key_path) */
        .ca_key_path = NULL,       /* Path to CA private key */
        .backup_curve = 0          /* Curve parameter for derivation */
    };
}

/* Keypool Lifecycle */

/* Create keypool
 *
 * @param config     Configuration
 * @param is_keygen  true for generator, false for reader
 * @return Keypool handle or NULL on error
 */
keypool_t* keypool_create(const keypool_config_t *config, bool is_keygen);

/* Destroy keypool and free resources */
void keypool_destroy(keypool_t *pool);

/* Key Operations */

/* Acquire key from pool
 *
 * Fast path: Get pre-generated key from pool (~0ms)
 * Slow path: Generate on-demand if pool empty (~1-100ms depending on algorithm)
 *
 * @param pool      Keypool handle
 * @param algorithm Algorithm to use (or CRYPTO_ALG_AUTO)
 * @return EVP_PKEY* or NULL on error
 */
EVP_PKEY* keypool_acquire(keypool_t *pool, crypto_alg_t algorithm);

/* Release key back to pool (for reuse - NOT RECOMMENDED for production)
 *
 * @param pool  Keypool handle
 * @param key   Key to release
 */
void keypool_release(keypool_t *pool, EVP_PKEY *key);

/* Statistics */

/* Get keypool statistics */
void keypool_get_stats(const keypool_t *pool, keypool_stats_t *stats);

/* Print statistics to log */
void keypool_print_stats(const keypool_t *pool);

/* Background Refill */

/* Start background refill threads
 *
 * @param pool         Keypool handle
 * @param num_threads  Number of threads (0 = auto-detect)
 * @return KEYPOOL_OK on success
 */
keypool_error_t keypool_start_refill(keypool_t *pool, int num_threads);

/* Stop background refill threads */
void keypool_stop_refill(keypool_t *pool);

/* Persistence (Save/Load) */

/* Save keypool to disk bundle
 *
 * Useful for faster restarts - pre-generated keys loaded on startup
 *
 * @param pool     Keypool handle
 * @param bundle_path  Path to bundle file (e.g., /var/cache/tlsgateNG/keypool.bundle.gz)
 * @return KEYPOOL_OK on success
 */
keypool_error_t keypool_save_bundle(const keypool_t *pool, const char *bundle_path);

/* Load keypool from disk bundle
 *
 * @param pool         Keypool handle
 * @param bundle_path  Path to bundle file
 * @return KEYPOOL_OK on success, KEYPOOL_ERR_* on failure
 */
keypool_error_t keypool_load_bundle(keypool_t *pool, const char *bundle_path);

/* Load multiple keypool bundles from directory
 *
 * Loads all matching bundles from directory:
 *   RSA:   keys.rsa.{1024,2048,3072,4096,8192}[.NNN].bundle.gz
 *   ECDSA: keys.ec.{256,384,521}[.NNN].bundle.gz
 *   EdDSA: keys.ed.25519[.NNN].bundle.gz
 * Where [.NNN] is optional sequence number (001-999) for multi-bundle sets
 *
 * Designed for production scale: millions of pre-generated keys for zero-downtime reboots
 *
 * @param pool       Keypool handle
 * @param bundle_dir Path to directory containing bundles
 * @return KEYPOOL_OK on success, KEYPOOL_ERR_* on failure
 */
keypool_error_t keypool_load_bundles_from_dir(keypool_t *pool, const char *bundle_dir);

/* Prime Pool Loading (for fast RSA generation) */

/* Load pre-generated prime pools from directory
 *
 * Loads prime-{keysize}.bin files from directory. Supports up to 8 RSA key sizes.
 * Prime pools accelerate RSA key generation by 20-200× by skipping prime generation.
 *
 * Supported RSA key sizes (all optional):
 *   prime-1024.bin  - RSA-1024 primes (512-bit p+q)   [Legacy]
 *   prime-1536.bin  - RSA-1536 primes (768-bit p+q)   [Intermediate]
 *   prime-2048.bin  - RSA-2048 primes (1024-bit p+q)  [Standard]
 *   prime-2560.bin  - RSA-2560 primes (1280-bit p+q)  [Intermediate]
 *   prime-3072.bin  - RSA-3072 primes (1536-bit p+q)  [Recommended]
 *   prime-3584.bin  - RSA-3584 primes (1792-bit p+q)  [Intermediate]
 *   prime-4096.bin  - RSA-4096 primes (2048-bit p+q)  [Very Secure]
 *   prime-8192.bin  - RSA-8192 primes (4096-bit p+q)  [Maximum Security]
 *
 * Generate prime pools using tlsgateNG-poolgen tool before server startup.
 * Missing files are silently ignored (RSA falls back to slow generation).
 *
 * Multi-instance support: All TLSGateNX instances on same hardware can share
 * the same prime pool directory (read-only, OS page cache automatically shared).
 *
 * @param pool       Keypool handle
 * @param prime_dir  Directory containing prime-*.bin files
 * @return KEYPOOL_OK on success
 */
keypool_error_t keypool_load_prime_pools(keypool_t *pool, const char *prime_dir);

/* Direct Key Generation (without pool) */

/* Generate single key of specified algorithm
 *
 * Bypasses pool - use for one-off generation or testing
 *
 * @param algorithm  Algorithm to use
 * @return EVP_PKEY* or NULL on error
 */
EVP_PKEY* keypool_generate_key(crypto_alg_t algorithm);

/* Get algorithm name (for logging) */
const char* keypool_algorithm_name(crypto_alg_t algorithm);

/* Get recommended algorithm for performance */
crypto_alg_t keypool_auto_select_algorithm(void);

/* Get SHM pool pointer (for backup/restore)
 *
 * @param pool  Keypool handle
 * @return keypool_shm_t* or NULL if not using SHM
 */
keypool_shm_t* keypool_get_shm_pool(const keypool_t *pool);

/* Restore lock types - one for each restore operation */
typedef enum {
    RESTORE_LOCK_SHM_BACKUP = 0,  /* SHM backup restore (keys.shm.bundle.gz) */
    RESTORE_LOCK_KEYBUNDLE = 1,   /* Keybundle loading (from bundle_dir) */
    RESTORE_LOCK_PRIME = 2        /* Prime pool loading (from prime_dir) */
} restore_lock_t;

/* Clear a specific restore lock
 *
 * Call after respective operation completes (or is skipped because no file exists).
 * The refill manager waits for ALL 3 locks to be false before generating keys.
 *
 * @param pool  Keypool handle
 * @param lock  Which lock to clear
 */
void keypool_clear_restore_lock(keypool_t *pool, restore_lock_t lock);

/* Check if all restore locks are cleared (refill can start)
 *
 * @param pool  Keypool handle
 * @return true if all locks are cleared, false if any lock is still set
 */
bool keypool_restore_locks_cleared(const keypool_t *pool);

#endif /* TLSGATENG_KEYPOOL_H */
