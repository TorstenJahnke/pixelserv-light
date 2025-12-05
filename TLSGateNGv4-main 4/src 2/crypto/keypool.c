/* TLS-Gate NX - Cryptographic Key Pool Implementation
 * Copyright (C) 2025 Torsten Jahnke
 *
 * Modern crypto with OpenSSL 3.0 Provider API
 */

#define _GNU_SOURCE  /* For memmem() */

#include "keypool.h"
#include "../ipc/shm_manager.h"
#include "../util/logger.h"
#include "../util/util.h"

#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/ec.h>
#include <openssl/param_build.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/rand.h>

#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/sysinfo.h>
#include <sys/file.h>
#include <fcntl.h>
#include <openssl/bn.h>
#include <errno.h>

#ifdef __FreeBSD__
#include <sys/types.h>
#include <sys/sysctl.h>
#endif

/* Prime pool header (compatible with tlsgateNG-poolgen) */
#define PRIME_POOL_MAGIC 0x5052494D  /* "PRIM" */
#define PRIME_POOL_VERSION 1

typedef struct {
    uint32_t magic;           /* 0x5052494D "PRIM" */
    uint32_t version;         /* Prime pool format version */
    uint32_t count;           /* Number of primes per pool (p and q each) */
    uint32_t prime_bits;      /* Bits per prime */
    uint64_t timestamp;       /* Generation timestamp */
    uint8_t  reserved[8];
} __attribute__((packed)) prime_pool_header_t;

/* Prime pool in memory */
typedef struct {
    uint32_t pool_size;       /* Number of primes per pool */
    uint32_t prime_bits;      /* Bits per prime */
    uint32_t prime_bytes;     /* Bytes per prime */
    unsigned char *p_pool;    /* p primes: pool_size * prime_bytes */
    unsigned char *q_pool;    /* q primes: pool_size * prime_bytes */
    atomic_uint next_p_idx;   /* Thread-safe index for p selection */
    atomic_uint next_q_idx;   /* Thread-safe index for q selection */
} prime_pool_t;

/* RSA key sizes we support (up to 9 different sizes) */
#define RSA_KEYSIZES 9
static const int rsa_keysizes[RSA_KEYSIZES] = {
    1024,  /* Legacy support */
    1536,  /* Intermediate */
    2048,  /* Standard (most common) */
    2560,  /* Intermediate */
    3072,  /* Recommended (high security) */
    3584,  /* Intermediate */
    4096,  /* Very secure */
    8192,  /* Maximum security */
    16384  /* Ultra-high security (very slow - demo/testing only) */
};

/* Keypool structure */
struct keypool {
    keypool_config_t config;

    /* Local pool (fallback when SHM unavailable) */
    EVP_PKEY **local_keys;
    atomic_int local_available;
    pthread_mutex_t local_lock;

    /* Shared memory pool */
    keypool_shm_t *shm_pool;
    int shm_fd;
    bool using_shm;

    /* Prime pools (optional - for fast RSA generation) */
    /* Indexed by key size: prime_pools[0]=1024, [1]=2048, [2]=3072, [3]=4096, [4]=8192 */
    prime_pool_t *prime_pools[RSA_KEYSIZES];
    char *prime_pool_dir;  /* Directory containing prime-{size}.bin files */

    /* Background refill threads */
    pthread_t *refill_threads;
    int num_refill_threads;
    atomic_bool refill_shutdown;
    _Atomic bool refill_in_progress;  /* Prevent concurrent refills */

    /* Background backup thread (30 minute interval) */
    pthread_t backup_thread;
    atomic_bool backup_shutdown;
    char *backup_path;  /* Path to backup bundle file */

    /* Statistics */
    keypool_stats_t stats;

    /* Role */
    bool is_keygen;
};

/* Thread limits */
#define MIN_REFILL_THREADS 1         /* Minimum for any system size */
#define MAX_REFILL_THREADS_LIMIT 30  /* Absolute max (for 32+ core systems) */

/* Algorithm names */
static const char* algorithm_names[] = {
    [CRYPTO_ALG_RSA_3072] = "RSA-3072",
    [CRYPTO_ALG_RSA_4096] = "RSA-4096",
    [CRYPTO_ALG_RSA_8192] = "RSA-8192",
    [CRYPTO_ALG_RSA_16384] = "RSA-16384 (DEMO)",
    [CRYPTO_ALG_ECDSA_P256] = "ECDSA-P256",
    [CRYPTO_ALG_ECDSA_P384] = "ECDSA-P384",
    [CRYPTO_ALG_ECDSA_P521] = "ECDSA-P521",
    [CRYPTO_ALG_SM2] = "SM2",
    [CRYPTO_ALG_ED25519] = "Ed25519",
    [CRYPTO_ALG_AUTO] = "AUTO",
    /* Legacy/Weak algorithms */
    [CRYPTO_ALG_RSA_1024] = "RSA-1024 (LEGACY)",
    [CRYPTO_ALG_RSA_2048] = "RSA-2048 (LEGACY)"
};

/* Detect algorithm from EVP_PKEY (for backup restore) */
static crypto_alg_t detect_key_algorithm(EVP_PKEY *pkey) {
    if (!pkey) return CRYPTO_ALG_AUTO;

    int key_type = EVP_PKEY_base_id(pkey);
    int pkey_id = EVP_PKEY_id(pkey);  /* Also try EVP_PKEY_id() */

    /* Debug: Log all key type detection attempts */
    LOG_DEBUG("detect_key_algorithm: base_id=%d, pkey_id=%d (RSA=%d, EC=%d, SM2=%d, Ed25519=%d)",
              key_type, pkey_id, EVP_PKEY_RSA, EVP_PKEY_EC, EVP_PKEY_SM2, EVP_PKEY_ED25519);

    /* Direct SM2 detection via EVP_PKEY_id() (higher priority than base_id)
     * Some OpenSSL/Tongsuo versions report SM2 via id but EC via base_id */
    if (pkey_id == EVP_PKEY_SM2) {
        LOG_DEBUG("detect_key_algorithm: Detected SM2 via EVP_PKEY_id()");
        return CRYPTO_ALG_SM2;
    }

    switch (key_type) {
        case EVP_PKEY_RSA:
        case EVP_PKEY_RSA_PSS: {  /* Also handle RSA-PSS keys */
            int bits = EVP_PKEY_bits(pkey);
            if (bits <= 1024) return CRYPTO_ALG_RSA_1024;
            if (bits <= 2048) return CRYPTO_ALG_RSA_2048;
            if (bits <= 3072) return CRYPTO_ALG_RSA_3072;
            if (bits <= 4096) return CRYPTO_ALG_RSA_4096;
            if (bits <= 8192) return CRYPTO_ALG_RSA_8192;
            return CRYPTO_ALG_RSA_16384;
        }

        case EVP_PKEY_EC: {
            /* Check for SM2 first (uses same key type but different OID) */
            char curve_name[64] = {0};
            size_t len = sizeof(curve_name);
            if (EVP_PKEY_get_utf8_string_param(pkey, OSSL_PKEY_PARAM_GROUP_NAME,
                                               curve_name, len, &len)) {
                LOG_DEBUG("detect_key_algorithm: EC curve_name='%s'", curve_name);
                /* SM2 curve detection - check multiple possible names
                 * Tongsuo may use different names than standard OpenSSL */
                if (strcmp(curve_name, "SM2") == 0 ||
                    strcmp(curve_name, "sm2") == 0 ||
                    strcmp(curve_name, "sm2p256v1") == 0 ||
                    strcmp(curve_name, "curveSM2") == 0 ||           /* Tongsuo variant */
                    strcmp(curve_name, "wapip192v1") == 0 ||         /* Chinese standard alias */
                    strstr(curve_name, "sm2") != NULL ||             /* Any curve containing "sm2" */
                    strstr(curve_name, "SM2") != NULL ||             /* Any curve containing "SM2" */
                    strcmp(curve_name, "1.2.156.10197.1.301") == 0) {  /* SM2 OID */
                    LOG_DEBUG("detect_key_algorithm: Detected SM2 curve: %s", curve_name);
                    return CRYPTO_ALG_SM2;
                }
                if (strcmp(curve_name, "prime256v1") == 0 ||
                    strcmp(curve_name, "P-256") == 0 ||
                    strcmp(curve_name, "secp256r1") == 0) {
                    return CRYPTO_ALG_ECDSA_P256;
                }
                if (strcmp(curve_name, "secp384r1") == 0 ||
                    strcmp(curve_name, "P-384") == 0) {
                    return CRYPTO_ALG_ECDSA_P384;
                }
                if (strcmp(curve_name, "secp521r1") == 0 ||
                    strcmp(curve_name, "P-521") == 0) {
                    return CRYPTO_ALG_ECDSA_P521;
                }
                /* Log unknown curve for debugging */
                LOG_WARN("Unknown EC curve: %s - defaulting to P-256", curve_name);
            } else {
                LOG_WARN("Failed to get EC curve name for key type %d", key_type);
            }
            /* Default to P-256 for unknown EC curves */
            return CRYPTO_ALG_ECDSA_P256;
        }

        case EVP_PKEY_SM2:
            return CRYPTO_ALG_SM2;

        case EVP_PKEY_ED25519:
            return CRYPTO_ALG_ED25519;

        default:
            LOG_WARN("Unknown key type: %d (EVP_PKEY_SM2=%d) - marking as AUTO", key_type, EVP_PKEY_SM2);
            return CRYPTO_ALG_AUTO;
    }
}

/* CPU and Load Detection */

/* Get number of CPU cores */
static int get_cpu_cores(void) {
#ifdef __linux__
    long nprocs = sysconf(_SC_NPROCESSORS_ONLN);
    return (nprocs > 0) ? (int)nprocs : 2;
#elif defined(__FreeBSD__)
    int ncpu;
    size_t len = sizeof(ncpu);
    if (sysctlbyname("hw.ncpu", &ncpu, &len, NULL, 0) == 0) {
        return ncpu;
    }
    return 2;
#else
    return 2;  /* Fallback */
#endif
}

/* Get system load average (Linux and FreeBSD) */
static float get_system_load(void) {
#if defined(__linux__) || defined(__FreeBSD__)
    double loadavg[3];
    if (getloadavg(loadavg, 1) > 0) {
        return (float)loadavg[0];
    }
#endif
    return 0.0f;
}

/* Get adaptive thread count based on pool fill level and CPU load
 * Returns: Number of refill threads to use
 *
 * Percent-based calculation:
 *   8 cores (FreeBSD): <25% → 4 threads (50%), 25-50% → 2 threads (25%), >75% → 1 thread
 *  32 cores (Debian):  <25% → 16 threads (50%), 25-50% → 8 threads (25%), >75% → 1 thread
 *
 * Auto-scales from 50% of cores down to 1 thread based on fill level
 * CPU load aware: reduces threads when system is busy
 */
static int get_adaptive_thread_count(int fill_percent) {
    int cores = get_cpu_cores();
    float load = get_system_load();
    int base_threads;

    /* Adaptive thread count based on fill level */
    if (fill_percent < REFILL_AGGRESSIVE_PCT) {
        /* <25% full: AGGRESSIVE - use 50% of cores */
        base_threads = cores / 2;
    } else if (fill_percent < REFILL_FAST_PCT) {
        /* 25-50% full: FAST - use 25% of cores */
        base_threads = cores / 4;
    } else if (fill_percent < REFILL_SLOW_PCT) {
        /* 50-75% full: NORMAL - use 12.5% of cores */
        base_threads = cores / 8;
    } else {
        /* >75% full: SLOW - use minimal threads */
        base_threads = MIN_REFILL_THREADS;
    }

    /* CPU load adjustment: reduce threads if system is busy */
    if (load > 0.0f) {
        float load_per_core = load / cores;
        if (load_per_core > 0.8f) {
            /* System >80% busy: halve threads */
            base_threads = base_threads / 2;
        } else if (load_per_core > 0.5f) {
            /* System >50% busy: reduce by 25% */
            base_threads = (base_threads * 3) / 4;
        }
    }

    /* Clamp between MIN and MAX */
    if (base_threads < MIN_REFILL_THREADS) {
        base_threads = MIN_REFILL_THREADS;
    }
    if (base_threads > MAX_REFILL_THREADS_LIMIT) {
        base_threads = MAX_REFILL_THREADS_LIMIT;
    }

    return base_threads;
}

const char* keypool_algorithm_name(crypto_alg_t algorithm) {
    if (algorithm >= 0 && algorithm < sizeof(algorithm_names)/sizeof(algorithm_names[0])) {
        return algorithm_names[algorithm];
    }
    return "UNKNOWN";
}

/* Auto-select best algorithm based on platform capabilities */
crypto_alg_t keypool_auto_select_algorithm(void) {
    /* ECDSA P-256 is generally 10× faster than RSA 3072
     * and provides equivalent security (~128-bit)
     *
     * Future: Check CPU capabilities and select Ed25519 if available
     */
    return CRYPTO_ALG_ECDSA_P256;
}

/* Get SHM pool pointer for backup/restore */
keypool_shm_t* keypool_get_shm_pool(const keypool_t *pool) {
    if (!pool || !pool->using_shm) {
        return NULL;
    }
    return pool->shm_pool;
}

/* Clear a specific restore lock
 * Called after each restore operation completes (or is skipped if no file exists).
 * Refill waits for ALL 3 locks to be cleared before generating keys.
 */
void keypool_clear_restore_lock(keypool_t *pool, restore_lock_t lock) {
    if (!pool || !pool->using_shm || !pool->shm_pool) {
        return;
    }

    const char *lock_name = NULL;
    switch (lock) {
        case RESTORE_LOCK_SHM_BACKUP:
            atomic_store_explicit(&pool->shm_pool->restore_lock_shm_backup, false, memory_order_release);
            lock_name = "shm-backup";
            break;
        case RESTORE_LOCK_KEYBUNDLE:
            atomic_store_explicit(&pool->shm_pool->restore_lock_keybundle, false, memory_order_release);
            lock_name = "keybundle";
            break;
        case RESTORE_LOCK_PRIME:
            atomic_store_explicit(&pool->shm_pool->restore_lock_prime, false, memory_order_release);
            lock_name = "prime";
            break;
        default:
            LOG_WARN("Unknown restore lock type: %d", lock);
            return;
    }

    LOG_INFO("Restore lock '%s' cleared", lock_name);
    fprintf(stderr, "[KEYPOOL] Restore lock '%s' cleared\n", lock_name);

    /* Check if all locks are now cleared */
    if (keypool_restore_locks_cleared(pool)) {
        LOG_INFO("All restore locks cleared - refill can start");
        fprintf(stderr, "[KEYPOOL] All restore locks cleared - refill unlocked\n");
    }
}

/* Check if all restore locks are cleared (refill can start) */
bool keypool_restore_locks_cleared(const keypool_t *pool) {
    if (!pool || !pool->using_shm || !pool->shm_pool) {
        return true;  /* No SHM = no locks to wait for */
    }

    bool shm_backup = atomic_load_explicit(&pool->shm_pool->restore_lock_shm_backup, memory_order_acquire);
    bool keybundle = atomic_load_explicit(&pool->shm_pool->restore_lock_keybundle, memory_order_acquire);
    bool prime = atomic_load_explicit(&pool->shm_pool->restore_lock_prime, memory_order_acquire);

    /* All locks must be false (cleared) for refill to start */
    return !shm_backup && !keybundle && !prime;
}

/* Key Generation - OpenSSL 3.0 Provider API */

/* Generate RSA key with specified bits */
static EVP_PKEY* generate_rsa_key(int bits) {
    LOG_DEBUG_FAST("Generating RSA-%d key", bits);

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
    if (!ctx) {
        LOG_ERROR("Failed to create RSA context");
        return NULL;
    }

    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        LOG_ERROR("Failed to initialize RSA keygen");
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    /* Set RSA parameters */
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits) <= 0) {
        LOG_ERROR("Failed to set RSA key bits");
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    /* Generate key */
    EVP_PKEY *pkey = NULL;
    if (EVP_PKEY_generate(ctx, &pkey) <= 0) {
        LOG_ERROR("Failed to generate RSA key");
        unsigned long err = ERR_get_error();
        char err_buf[256];
        ERR_error_string_n(err, err_buf, sizeof(err_buf));
        LOG_ERROR("OpenSSL error: %s", err_buf);
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    EVP_PKEY_CTX_free(ctx);
    LOG_TRACE_FAST("Generated RSA-%d key successfully", bits);
    return pkey;
}

/* Prime Pool Functions */

/* Get prime pool index for RSA key size */
static int get_prime_pool_index(int keysize) {
    for (int i = 0; i < RSA_KEYSIZES; i++) {
        if (rsa_keysizes[i] == keysize) {
            return i;
        }
    }
    return -1;
}

/* Get prime pool for RSA key size */
static prime_pool_t* get_prime_pool_for_keysize(keypool_t *pool, int keysize) {
    if (!pool) return NULL;
    int idx = get_prime_pool_index(keysize);
    if (idx < 0) return NULL;
    return pool->prime_pools[idx];
}

/* Load prime pool from file (tlsgateNG-poolgen compatible) */
static prime_pool_t* load_prime_pool(const char *path, int expected_bits) {
    if (!path) return NULL;

    LOG_INFO("Loading prime pool from: %s", path);

    FILE *fp = fopen(path, "rb");
    if (!fp) {
        LOG_WARN("Prime pool not found: %s", path);
        return NULL;
    }

    /* Read header */
    prime_pool_header_t header;
    if (fread(&header, sizeof(header), 1, fp) != 1) {
        LOG_ERROR("Failed to read prime pool header");
        fclose(fp);
        return NULL;
    }

    /* Validate magic */
    if (header.magic != PRIME_POOL_MAGIC) {
        LOG_ERROR("Invalid prime pool magic: 0x%08x", header.magic);
        fclose(fp);
        return NULL;
    }

    /* Validate version */
    if (header.version != PRIME_POOL_VERSION) {
        LOG_ERROR("Unsupported prime pool version: %u", header.version);
        fclose(fp);
        return NULL;
    }

    /* Check if prime bits match expected */
    if (header.prime_bits != (uint32_t)expected_bits) {
        LOG_WARN("Prime pool bit size mismatch (file:%u, expected:%d) - ignoring",
                 header.prime_bits, expected_bits);
        fclose(fp);
        return NULL;
    }

    /* Validate count (must be > 0 and reasonable) */
    if (header.count == 0 || header.count > 10000000) {  /* Max 10M primes */
        LOG_ERROR("Invalid prime pool count: %u (must be 1-10000000)", header.count);
        fclose(fp);
        return NULL;
    }

    /* Calculate expected file size and verify (with overflow checks) */
    /* Check for overflow in prime_bits calculation */
    if (header.prime_bits > UINT32_MAX - 7) {
        LOG_ERROR("Prime bits value too large: %u", header.prime_bits);
        fclose(fp);
        return NULL;
    }
    uint32_t prime_bytes = (header.prime_bits + 7) / 8;  /* Bits to bytes */

    /* Check for overflow in size calculation: 2 * count * prime_bytes */
    if (header.count > SIZE_MAX / prime_bytes / 2) {
        LOG_ERROR("Prime pool size calculation overflow (count=%u, prime_bytes=%u)",
                 header.count, prime_bytes);
        fclose(fp);
        return NULL;
    }
    size_t pool_data_size = 2 * (size_t)header.count * (size_t)prime_bytes;

    /* Check for overflow when adding header size */
    if (pool_data_size > SIZE_MAX - sizeof(prime_pool_header_t)) {
        LOG_ERROR("Total pool size overflow");
        fclose(fp);
        return NULL;
    }
    size_t expected_size = sizeof(prime_pool_header_t) + pool_data_size;

    /* Get actual file size */
    fseek(fp, 0, SEEK_END);
    long file_size = ftell(fp);
    fseek(fp, sizeof(prime_pool_header_t), SEEK_SET);  /* Rewind to data */

    if (file_size < 0 || (size_t)file_size != expected_size) {
        LOG_ERROR("Prime pool file size mismatch (file:%ld, expected:%zu bytes)",
                 file_size, expected_size);
        fclose(fp);
        return NULL;
    }

    /* Allocate prime pool */
    prime_pool_t *pool = calloc(1, sizeof(prime_pool_t));
    if (!pool) {
        LOG_ERROR("Failed to allocate prime pool structure");
        fclose(fp);
        return NULL;
    }

    pool->pool_size = header.count;
    pool->prime_bits = header.prime_bits;
    pool->prime_bytes = (header.prime_bits + 7) / 8;
    pool->p_pool = calloc(pool->pool_size, pool->prime_bytes);
    pool->q_pool = calloc(pool->pool_size, pool->prime_bytes);

    if (!pool->p_pool || !pool->q_pool) {
        LOG_ERROR("Failed to allocate prime pool memory");
        free(pool->p_pool);
        free(pool->q_pool);
        free(pool);
        fclose(fp);
        return NULL;
    }

    /* Read p pool */
    if (fread(pool->p_pool, pool->prime_bytes, pool->pool_size, fp) != pool->pool_size) {
        LOG_ERROR("Failed to read p-prime pool");
        free(pool->p_pool);
        free(pool->q_pool);
        free(pool);
        fclose(fp);
        return NULL;
    }

    /* Read q pool */
    if (fread(pool->q_pool, pool->prime_bytes, pool->pool_size, fp) != pool->pool_size) {
        LOG_ERROR("Failed to read q-prime pool");
        free(pool->p_pool);
        free(pool->q_pool);
        free(pool);
        fclose(fp);
        return NULL;
    }

    fclose(fp);

    /* Initialize atomic indices */
    atomic_init(&pool->next_p_idx, 0);
    atomic_init(&pool->next_q_idx, 0);

    LOG_INFO("Loaded prime pool: %u primes (%u-bit) per pool (p+q)",
             pool->pool_size, pool->prime_bits);

    return pool;
}

/* Free prime pool */
static void free_prime_pool(prime_pool_t *pool) {
    if (pool) {
        free(pool->p_pool);
        free(pool->q_pool);
        free(pool);
    }
}

/* Load prime pool from separate RAW p and q files (no header, just prime data)
 *
 * Loads two separate files with raw prime data:
 *   - prime-{keysize}-p.bin (p primes, no header)
 *   - prime-{keysize}-q.bin (q primes, no header)
 *
 * Prime size is calculated from keysize: prime_bits = keysize / 2
 * Prime count is calculated from file size: count = file_size / prime_bytes
 */
static prime_pool_t* load_prime_pool_separate_raw(const char *dir_path, int keysize, int expected_bits) {
    if (!dir_path) return NULL;

    char path_p[1024], path_q[1024];
    snprintf(path_p, sizeof(path_p), "%s/prime-%d-p.bin", dir_path, keysize);
    snprintf(path_q, sizeof(path_q), "%s/prime-%d-q.bin", dir_path, keysize);

    LOG_INFO("Trying RAW prime pool format: %s + %s", path_p, path_q);

    /* Get file sizes */
    struct stat st_p, st_q;
    if (stat(path_p, &st_p) != 0 || stat(path_q, &st_q) != 0) {
        return NULL;  /* Files don't exist */
    }

    /* Calculate prime parameters from keysize */
    int prime_bits = keysize / 2;  /* RSA-3072 → 1536-bit primes */
    int prime_bytes = (prime_bits + 7) / 8;  /* 1536 bits → 192 bytes */

    /* Verify expected bits match */
    if (prime_bits != expected_bits) {
        LOG_WARN("Prime bits mismatch: keysize %d → %d bits, expected %d bits",
                 keysize, prime_bits, expected_bits);
        return NULL;
    }

    /* Calculate prime count from file size */
    if (st_p.st_size != st_q.st_size) {
        LOG_ERROR("RAW prime files have different sizes: p=%ld, q=%ld",
                  (long)st_p.st_size, (long)st_q.st_size);
        return NULL;
    }

    if (st_p.st_size % prime_bytes != 0) {
        LOG_ERROR("RAW prime file size not divisible by prime size: %ld / %d",
                  (long)st_p.st_size, prime_bytes);
        return NULL;
    }

    uint32_t prime_count = st_p.st_size / prime_bytes;
    if (prime_count == 0 || prime_count > 10000000) {
        LOG_ERROR("Invalid prime count calculated: %u", prime_count);
        return NULL;
    }

    LOG_INFO("RAW prime format detected: %u primes × %d bytes = %ld bytes",
             prime_count, prime_bytes, (long)st_p.st_size);

    /* Open both files */
    FILE *fp_p = fopen(path_p, "rb");
    FILE *fp_q = fopen(path_q, "rb");

    if (!fp_p || !fp_q) {
        if (fp_p) fclose(fp_p);
        if (fp_q) fclose(fp_q);
        return NULL;
    }

    /* Allocate prime pool */
    prime_pool_t *pool = calloc(1, sizeof(prime_pool_t));
    if (!pool) {
        LOG_ERROR("Failed to allocate prime pool structure");
        fclose(fp_p);
        fclose(fp_q);
        return NULL;
    }

    pool->pool_size = prime_count;
    pool->prime_bits = prime_bits;
    pool->prime_bytes = prime_bytes;
    pool->p_pool = calloc(pool->pool_size, pool->prime_bytes);
    pool->q_pool = calloc(pool->pool_size, pool->prime_bytes);

    if (!pool->p_pool || !pool->q_pool) {
        LOG_ERROR("Failed to allocate prime pool memory (%u × %d bytes)",
                  prime_count, prime_bytes);
        free(pool->p_pool);
        free(pool->q_pool);
        free(pool);
        fclose(fp_p);
        fclose(fp_q);
        return NULL;
    }

    /* Read raw p primes */
    if (fread(pool->p_pool, pool->prime_bytes, pool->pool_size, fp_p) != pool->pool_size) {
        LOG_ERROR("Failed to read RAW p-prime pool");
        free(pool->p_pool);
        free(pool->q_pool);
        free(pool);
        fclose(fp_p);
        fclose(fp_q);
        return NULL;
    }

    /* Read raw q primes */
    if (fread(pool->q_pool, pool->prime_bytes, pool->pool_size, fp_q) != pool->pool_size) {
        LOG_ERROR("Failed to read RAW q-prime pool");
        free(pool->p_pool);
        free(pool->q_pool);
        free(pool);
        fclose(fp_p);
        fclose(fp_q);
        return NULL;
    }

    fclose(fp_p);
    fclose(fp_q);

    /* Initialize atomic indices */
    atomic_init(&pool->next_p_idx, 0);
    atomic_init(&pool->next_q_idx, 0);

    LOG_INFO("✅ Loaded RAW prime pools: %u primes (%d-bit) for RSA-%d",
             pool->pool_size, pool->prime_bits, keysize);

    return pool;
}

/* Load prime pool from separate p and q files (tlsgateNG-poolgen format)
 *
 * Loads two separate files:
 *   - prime-{keysize}-p.bin (p primes)
 *   - prime-{keysize}-q.bin (q primes)
 *
 * File format per file: [Header][Primes]
 */
static prime_pool_t* load_prime_pool_separate(const char *dir_path, int keysize, int expected_bits) {
    if (!dir_path) return NULL;

    char path_p[1024], path_q[1024];
    snprintf(path_p, sizeof(path_p), "%s/prime-%d-p.bin", dir_path, keysize);
    snprintf(path_q, sizeof(path_q), "%s/prime-%d-q.bin", dir_path, keysize);

    LOG_INFO("Loading separate prime pools: %s + %s", path_p, path_q);

    /* Open both files */
    FILE *fp_p = fopen(path_p, "rb");
    FILE *fp_q = fopen(path_q, "rb");

    if (!fp_p || !fp_q) {
        if (fp_p) fclose(fp_p);
        if (fp_q) fclose(fp_q);
        return NULL;
    }

    /* Read headers from both files */
    prime_pool_header_t header_p, header_q;
    if (fread(&header_p, sizeof(header_p), 1, fp_p) != 1 ||
        fread(&header_q, sizeof(header_q), 1, fp_q) != 1) {
        LOG_ERROR("Failed to read prime pool headers");
        fclose(fp_p);
        fclose(fp_q);
        return NULL;
    }

    /* Validate magic numbers */
    if (header_p.magic != PRIME_POOL_MAGIC || header_q.magic != PRIME_POOL_MAGIC) {
        LOG_ERROR("Invalid prime pool magic in separate files");
        fclose(fp_p);
        fclose(fp_q);
        return NULL;
    }

    /* Validate versions */
    if (header_p.version != PRIME_POOL_VERSION || header_q.version != PRIME_POOL_VERSION) {
        LOG_ERROR("Unsupported prime pool version in separate files");
        fclose(fp_p);
        fclose(fp_q);
        return NULL;
    }

    /* Verify both files have same count and prime_bits */
    if (header_p.count != header_q.count || header_p.prime_bits != header_q.prime_bits) {
        LOG_ERROR("Mismatch between p and q prime pools (count or bits differ)");
        fclose(fp_p);
        fclose(fp_q);
        return NULL;
    }

    /* Check if prime bits match expected */
    if (header_p.prime_bits != (uint32_t)expected_bits) {
        LOG_WARN("Prime pool bit size mismatch (file:%u, expected:%d) - ignoring",
                 header_p.prime_bits, expected_bits);
        fclose(fp_p);
        fclose(fp_q);
        return NULL;
    }

    /* Validate count */
    if (header_p.count == 0 || header_p.count > 10000000) {
        LOG_ERROR("Invalid prime pool count: %u", header_p.count);
        fclose(fp_p);
        fclose(fp_q);
        return NULL;
    }

    /* Allocate prime pool */
    prime_pool_t *pool = calloc(1, sizeof(prime_pool_t));
    if (!pool) {
        LOG_ERROR("Failed to allocate prime pool structure");
        fclose(fp_p);
        fclose(fp_q);
        return NULL;
    }

    pool->pool_size = header_p.count;
    pool->prime_bits = header_p.prime_bits;
    pool->prime_bytes = (header_p.prime_bits + 7) / 8;
    pool->p_pool = calloc(pool->pool_size, pool->prime_bytes);
    pool->q_pool = calloc(pool->pool_size, pool->prime_bytes);

    if (!pool->p_pool || !pool->q_pool) {
        LOG_ERROR("Failed to allocate prime pool memory");
        free(pool->p_pool);
        free(pool->q_pool);
        free(pool);
        fclose(fp_p);
        fclose(fp_q);
        return NULL;
    }

    /* Read p primes */
    if (fread(pool->p_pool, pool->prime_bytes, pool->pool_size, fp_p) != pool->pool_size) {
        LOG_ERROR("Failed to read p-prime pool");
        free(pool->p_pool);
        free(pool->q_pool);
        free(pool);
        fclose(fp_p);
        fclose(fp_q);
        return NULL;
    }

    /* Read q primes */
    if (fread(pool->q_pool, pool->prime_bytes, pool->pool_size, fp_q) != pool->pool_size) {
        LOG_ERROR("Failed to read q-prime pool");
        free(pool->p_pool);
        free(pool->q_pool);
        free(pool);
        fclose(fp_p);
        fclose(fp_q);
        return NULL;
    }

    fclose(fp_p);
    fclose(fp_q);

    /* Initialize atomic indices */
    atomic_init(&pool->next_p_idx, 0);
    atomic_init(&pool->next_q_idx, 0);

    LOG_INFO("Loaded separate prime pools: %u primes (%u-bit) from p+q files",
             pool->pool_size, pool->prime_bits);

    return pool;
}

/* Load all available prime pools from directory */
static void load_all_prime_pools(keypool_t *pool, const char *dir_path) {
    if (!pool || !dir_path) return;

    LOG_INFO("Scanning for prime pools in: %s", dir_path);

    int loaded = 0;
    for (int i = 0; i < RSA_KEYSIZES; i++) {
        int keysize = rsa_keysizes[i];
        int prime_bits = keysize / 2;

        prime_pool_t *pp = NULL;

        /* Try format 1: Combined file (prime-{keysize}.bin) */
        char path[1024];
        snprintf(path, sizeof(path), "%s/prime-%d.bin", dir_path, keysize);
        pp = load_prime_pool(path, prime_bits);

        /* Try format 2: Separate files with header (prime-{keysize}-p.bin + prime-{keysize}-q.bin) */
        if (!pp) {
            pp = load_prime_pool_separate(dir_path, keysize, prime_bits);
        }

        /* Try format 3: RAW separate files without header (external prime generator) */
        if (!pp) {
            pp = load_prime_pool_separate_raw(dir_path, keysize, prime_bits);
        }

        if (pp) {
            pool->prime_pools[i] = pp;
            loaded++;
            LOG_INFO("  [✓] RSA-%d: %u primes available (FAST PATH enabled)",
                     keysize, pp->pool_size);
        } else {
            pool->prime_pools[i] = NULL;
            LOG_DEBUG("  [ ] RSA-%d: no prime pool (will use slow generation)", keysize);
        }
    }

    if (loaded > 0) {
        LOG_INFO("Loaded %d prime pool(s) - RSA generation will be 20-200× faster!", loaded);
    } else {
        LOG_INFO("No prime pools loaded - RSA will use standard generation");
    }
}

/* Free all prime pools */
static void free_all_prime_pools(keypool_t *pool) {
    if (!pool) return;
    for (int i = 0; i < RSA_KEYSIZES; i++) {
        if (pool->prime_pools[i]) {
            free_prime_pool(pool->prime_pools[i]);
            pool->prime_pools[i] = NULL;
        }
    }
}

/* Generate RSA key from prime pool (FAST PATH - 20-200× faster!) */
static EVP_PKEY* generate_rsa_key_from_pool(prime_pool_t *pool, int bits ) {
    if (!pool) return NULL;

    /* bits parameter used in logging (may be unused in NDEBUG builds) */
    (void)bits;

    LOG_TRACE_FAST("Generating RSA key from prime pool (FAST!)");

    /* Thread-safe round-robin selection */
    uint32_t p_idx = atomic_fetch_add(&pool->next_p_idx, 1) % pool->pool_size;
    uint32_t q_idx = atomic_fetch_add(&pool->next_q_idx, 1) % pool->pool_size;

    /* Convert binary to BIGNUMs */
    BIGNUM *p = BN_bin2bn(pool->p_pool + (p_idx * pool->prime_bytes), pool->prime_bytes, NULL);
    BIGNUM *q = BN_bin2bn(pool->q_pool + (q_idx * pool->prime_bytes), pool->prime_bytes, NULL);

    if (!p || !q) {
        LOG_ERROR("Failed to convert primes to BIGNUMs");
        if (p) BN_free(p);
        if (q) BN_free(q);
        return NULL;
    }

    EVP_PKEY *key = NULL;
    BN_CTX *ctx = BN_CTX_new();
    if (!ctx) {
        BN_free(p);
        BN_free(q);
        return NULL;
    }

    /* Calculate RSA parameters */
    BIGNUM *n = BN_new();
    BIGNUM *e = BN_new();
    BIGNUM *d = BN_new();
    BIGNUM *dmp1 = BN_new();
    BIGNUM *dmq1 = BN_new();
    BIGNUM *iqmp = BN_new();

    if (!n || !e || !d || !dmp1 || !dmq1 || !iqmp) {
        goto cleanup;
    }

    /* n = p * q */
    BN_mul(n, p, q, ctx);

    /* e = 65537 (RSA_F4) */
    BN_set_word(e, 65537);

    /* phi = (p-1) * (q-1) */
    BIGNUM *p1 = BN_dup(p);
    BIGNUM *q1 = BN_dup(q);
    if (!p1 || !q1) {
        BN_free(p1);
        BN_free(q1);
        goto cleanup;
    }
    BN_sub_word(p1, 1);
    BN_sub_word(q1, 1);

    BIGNUM *phi = BN_new();
    if (!phi) {
        BN_free(p1);
        BN_free(q1);
        goto cleanup;
    }
    BN_mul(phi, p1, q1, ctx);

    /* d = e^-1 mod phi */
    if (!BN_mod_inverse(d, e, phi, ctx)) {
        BN_free(phi);
        BN_free(p1);
        BN_free(q1);
        goto cleanup;
    }

    /* dmp1 = d mod (p-1) */
    BN_mod(dmp1, d, p1, ctx);

    /* dmq1 = d mod (q-1) */
    BN_mod(dmq1, d, q1, ctx);

    /* iqmp = q^-1 mod p */
    if (!BN_mod_inverse(iqmp, q, p, ctx)) {
        BN_free(phi);
        BN_free(p1);
        BN_free(q1);
        goto cleanup;
    }

    BN_free(phi);
    BN_free(p1);
    BN_free(q1);

    /* Build OSSL_PARAM (OpenSSL 3.0) */
    OSSL_PARAM_BLD *param_bld = OSSL_PARAM_BLD_new();
    if (!param_bld) {
        goto cleanup;
    }

    /* Check all OSSL_PARAM_BLD_push operations for errors */
    if (!OSSL_PARAM_BLD_push_BN(param_bld, OSSL_PKEY_PARAM_RSA_N, n) ||
        !OSSL_PARAM_BLD_push_BN(param_bld, OSSL_PKEY_PARAM_RSA_E, e) ||
        !OSSL_PARAM_BLD_push_BN(param_bld, OSSL_PKEY_PARAM_RSA_D, d) ||
        !OSSL_PARAM_BLD_push_BN(param_bld, OSSL_PKEY_PARAM_RSA_FACTOR1, p) ||
        !OSSL_PARAM_BLD_push_BN(param_bld, OSSL_PKEY_PARAM_RSA_FACTOR2, q) ||
        !OSSL_PARAM_BLD_push_BN(param_bld, OSSL_PKEY_PARAM_RSA_EXPONENT1, dmp1) ||
        !OSSL_PARAM_BLD_push_BN(param_bld, OSSL_PKEY_PARAM_RSA_EXPONENT2, dmq1) ||
        !OSSL_PARAM_BLD_push_BN(param_bld, OSSL_PKEY_PARAM_RSA_COEFFICIENT1, iqmp)) {
        LOG_ERROR("Failed to push RSA parameters to OSSL_PARAM_BLD");
        OSSL_PARAM_BLD_free(param_bld);
        goto cleanup;
    }

    OSSL_PARAM *params = OSSL_PARAM_BLD_to_param(param_bld);
    if (!params) {
        OSSL_PARAM_BLD_free(param_bld);
        goto cleanup;
    }

    /* Create EVP_PKEY */
    EVP_PKEY_CTX *pkey_ctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
    if (pkey_ctx) {
        if (EVP_PKEY_fromdata_init(pkey_ctx) > 0 &&
            EVP_PKEY_fromdata(pkey_ctx, &key, EVP_PKEY_KEYPAIR, params) > 0) {
            /* Success! */
        }
        EVP_PKEY_CTX_free(pkey_ctx);
    }

    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(param_bld);

cleanup:
    BN_free(n);
    BN_free(e);
    BN_free(d);
    BN_free(dmp1);
    BN_free(dmq1);
    BN_free(iqmp);
    BN_free(p);
    BN_free(q);
    BN_CTX_free(ctx);

    if (key) {
        LOG_TRACE_FAST("Generated RSA-%d key from prime pool successfully", bits);
    }

    return key;
}

/* Generate RSA key with automatic prime pool selection (SMART) */
static EVP_PKEY* generate_rsa_key_smart(keypool_t *pool, int bits) {
    /* Try fast path first (if prime pool available) */
    prime_pool_t *primes = get_prime_pool_for_keysize(pool, bits);
    if (primes) {
        EVP_PKEY *key = generate_rsa_key_from_pool(primes, bits);
        if (key) {
            return key;
        }
        /* Fall through to slow path if fast path fails */
        LOG_WARN("Prime pool generation failed for RSA-%d, falling back to slow generation", bits);
    }

    /* Slow path (standard OpenSSL generation) */
    return generate_rsa_key(bits);
}

/* Generate ECDSA key with specified curve */
static EVP_PKEY* generate_ecdsa_key(int nid) {
    const char *curve_name ;
    switch (nid) {
        case NID_X9_62_prime256v1: curve_name = "prime256v1"; break;
        case NID_secp384r1: curve_name = "secp384r1"; break;
        case NID_secp521r1: curve_name = "secp521r1"; break;
        default:
            LOG_ERROR("Unknown ECDSA curve NID: %d", nid);
            return NULL;
    }

    /* curve_name used in logging (may be unused in NDEBUG builds) */
    (void)curve_name;

    LOG_DEBUG_FAST("Generating ECDSA key (curve=%s)", curve_name);

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
    if (!ctx) {
        LOG_ERROR("Failed to create EC context");
        return NULL;
    }

    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        LOG_ERROR("Failed to initialize EC keygen");
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    /* Set curve */
    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, nid) <= 0) {
        LOG_ERROR("Failed to set EC curve");
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    /* Generate key */
    EVP_PKEY *pkey = NULL;
    if (EVP_PKEY_generate(ctx, &pkey) <= 0) {
        LOG_ERROR("Failed to generate EC key");
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    EVP_PKEY_CTX_free(ctx);
    LOG_TRACE_FAST("Generated ECDSA key successfully (curve=%s)", curve_name);
    return pkey;
}

/* Generate SM2 key (Chinese standard elliptic curve)
 *
 * SM2 is a 256-bit elliptic curve cryptography standard used in China.
 * Performance: ~2-5ms per key (faster than RSA, slightly slower than P-256)
 * No logging - optimized for high throughput (millions of keys/second)
 *
 * @return EVP_PKEY* SM2 key pair or NULL on error
 */
static EVP_PKEY* generate_sm2_key(void) {
    /* Create SM2 context using new provider API (OpenSSL 3.0+)
     * With hardware acceleration hints for AMD EPYC (AVX2, AES-NI available) */
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, "SM2", NULL);
    if (!ctx) {
        return NULL;
    }

    /* Initialize keygen */
    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    /* Enable hardware acceleration if available
     * Modern Intel/AMD processors support AVX2 for parallel operations
     * On AMD EPYC: 32-core platform, these optimizations compound */
    OSSL_PARAM params[2] = {OSSL_PARAM_END, OSSL_PARAM_END};
    EVP_PKEY_CTX_set_params(ctx, params);

    /* Generate key */
    EVP_PKEY *pkey = NULL;
    if (EVP_PKEY_generate(ctx, &pkey) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

/* Internal: Generate key with prime pool support */
static EVP_PKEY* generate_key_internal(keypool_t *pool, crypto_alg_t algorithm) {
    EVP_PKEY *key = NULL;

    switch (algorithm) {
        case CRYPTO_ALG_RSA_3072:
            key = pool ? generate_rsa_key_smart(pool, 3072) : generate_rsa_key(3072);
            break;

        case CRYPTO_ALG_RSA_4096:
            key = pool ? generate_rsa_key_smart(pool, 4096) : generate_rsa_key(4096);
            break;

        case CRYPTO_ALG_RSA_8192:
            key = pool ? generate_rsa_key_smart(pool, 8192) : generate_rsa_key(8192);
            break;

        case CRYPTO_ALG_RSA_16384:
            /* WARNING: Very slow! 30-60s without prime pool, 3-10s with prime pool */
            LOG_WARN("Generating RSA-16384 key - this will take 30-60 seconds!");
            key = pool ? generate_rsa_key_smart(pool, 16384) : generate_rsa_key(16384);
            break;

        case CRYPTO_ALG_ECDSA_P256:
            key = generate_ecdsa_key(NID_X9_62_prime256v1);
            break;

        case CRYPTO_ALG_ECDSA_P384:
            key = generate_ecdsa_key(NID_secp384r1);
            break;

        case CRYPTO_ALG_ECDSA_P521:
            key = generate_ecdsa_key(NID_secp521r1);
            break;

        case CRYPTO_ALG_SM2:
            key = generate_sm2_key();
            break;

        case CRYPTO_ALG_ED25519:
            LOG_WARN("Ed25519 not yet implemented, falling back to ECDSA P-256");
            key = generate_ecdsa_key(NID_X9_62_prime256v1);
            break;

        case CRYPTO_ALG_AUTO:
            /* Auto-select best algorithm */
            key = generate_ecdsa_key(NID_X9_62_prime256v1);  /* ECDSA P-256 is fastest */
            break;

        /* Legacy/Weak algorithms - require --legacy-crypto flag */
        case CRYPTO_ALG_RSA_1024:
            key = pool ? generate_rsa_key_smart(pool, 1024) : generate_rsa_key(1024);
            break;

        case CRYPTO_ALG_RSA_2048:
            key = pool ? generate_rsa_key_smart(pool, 2048) : generate_rsa_key(2048);
            break;

        default:
            LOG_ERROR("Unknown algorithm: %d", algorithm);
            return NULL;
    }

    return key;
}

/* Generate key of specified algorithm (public API) */
EVP_PKEY* keypool_generate_key(crypto_alg_t algorithm) {
    EVP_PKEY *key = generate_key_internal(NULL, algorithm);
    return key;
}

/* ============================================================================
 * BACKUP ENCRYPTION
 * ============================================================================
 * Encrypts backup bundles using password derived from CA private key
 * Format: Secret number LLPPXX where LL=line, PP=position, XX=length
 * Example: 30916 = Line 3, Position 09, Length 16 characters
 */

#include <openssl/kdf.h>

#define BACKUP_HEADER_MAGIC "TLSGATENG_BACKUP_V1"
#define BACKUP_HEADER_MAGIC_V2 "TLSGATENG_BACKUP_V2"  /* v2: includes algorithm info */
#define BACKUP_HEADER_SIZE 32
#define BACKUP_SALT_SIZE 32
#define BACKUP_IV_SIZE 12
#define BACKUP_TAG_SIZE 16
#define BACKUP_KEY_SIZE 32  /* AES-256 */
#define BACKUP_V2_RECORD_MAGIC 0x4B455932  /* "KEY2" in little-endian */

/* Parse backup curve parameter (format: LLPPXX) */
static bool parse_backup_curve(uint32_t curve, int *line, int *position, int *length) {
    if (curve == 0) {
        return false;  /* Invalid curve parameter */
    }

    /* Extract components */
    *length = curve % 100;              /* Last 2 digits */
    *position = (curve / 100) % 100;    /* Middle 2 digits */
    *line = curve / 10000;              /* First 1-2 digits */

    /* Validate ranges */
    if (*line < 1 || *line > 99) return false;
    if (*position < 1 || *position > 99) return false;
    if (*length < 10 || *length > 40) return false;

    return true;
}

/* Extract password from CA private key using curve parameter */
static bool extract_password_from_ca_key(const char *ca_key_path, uint32_t curve,
                                         char *password, size_t password_size) {
    int target_line, position, length;
    if (!parse_backup_curve(curve, &target_line, &position, &length)) {
        LOG_ERROR("Invalid backup curve parameter: %u", curve);
        return false;
    }

    /* Read CA key file */
    FILE *f = fopen(ca_key_path, "r");
    if (!f) {
        LOG_ERROR("Failed to open CA key: %s", ca_key_path);
        return false;
    }

    /* Count total lines first */
    int total_lines = 0;
    char line_buffer[512];
    while (fgets(line_buffer, sizeof(line_buffer), f) != NULL) {
        total_lines++;
    }

    /* SECURITY FIX: Check for I/O errors during line counting */
    if (ferror(f)) {
        LOG_ERROR("I/O error reading CA key file: %s", ca_key_path);
        fclose(f);
        return false;
    }

    rewind(f);

    if (total_lines == 0) {
        fclose(f);
        LOG_ERROR("CA key file is empty");
        return false;
    }

    /* Wrap line number if needed (circular) */
    int actual_line = ((target_line - 1) % total_lines) + 1;

    /* Read to target line */
    int current_line = 0;
    char target_line_data[512] = {0};
    while (fgets(line_buffer, sizeof(line_buffer), f) != NULL) {
        current_line++;
        if (current_line == actual_line) {
            size_t len = strlen(line_buffer);
            if (len >= sizeof(target_line_data)) {
                len = sizeof(target_line_data) - 1;
            }
            memcpy(target_line_data, line_buffer, len);
            target_line_data[len] = '\0';  /* Ensure null termination */
            break;
        }
    }

    /* SECURITY FIX: Check for I/O errors during line reading */
    if (ferror(f)) {
        LOG_ERROR("I/O error reading CA key file line: %s", ca_key_path);
        fclose(f);
        return false;
    }

    fclose(f);

    if (current_line != actual_line) {
        LOG_ERROR("Failed to read line %d from CA key", actual_line);
        return false;
    }

    /* Remove newline/whitespace */
    size_t line_len = strlen(target_line_data);
    while (line_len > 0 && (target_line_data[line_len-1] == '\n' ||
                            target_line_data[line_len-1] == '\r')) {
        target_line_data[--line_len] = '\0';
    }

    /* Check if position+length fits in line */
    if (position < 0 || (size_t)(position + length) > line_len) {
        LOG_ERROR("Password extraction out of bounds (line=%d, pos=%d, len=%d, available=%zu)",
                  actual_line, position, length, line_len);
        return false;
    }

    /* Extract password substring */
    if ((size_t)length >= password_size) {
        LOG_ERROR("Password buffer too small");
        return false;
    }

    memcpy(password, target_line_data + position, length);
    password[length] = '\0';

    /* Security: clear line buffer */
    explicit_bzero(target_line_data, sizeof(target_line_data));
    explicit_bzero(line_buffer, sizeof(line_buffer));

    LOG_DEBUG("Extracted password from CA key (line=%d, pos=%d, len=%d)",
              actual_line, position, length);
    return true;
}

/* Derive encryption key from password using PBKDF2 */
static bool derive_encryption_key(const char *password, const unsigned char *salt,
                                   unsigned char *key) {
    EVP_KDF *kdf = EVP_KDF_fetch(NULL, "PBKDF2", NULL);
    if (!kdf) {
        LOG_ERROR("Failed to fetch PBKDF2 KDF");
        return false;
    }

    EVP_KDF_CTX *ctx = EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf);
    if (!ctx) {
        LOG_ERROR("Failed to create KDF context");
        return false;
    }

    /* PBKDF2 parameters */
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string("pass", (char*)password, strlen(password)),
        OSSL_PARAM_construct_octet_string("salt", (void*)salt, BACKUP_SALT_SIZE),
        OSSL_PARAM_construct_uint("iter", &(unsigned int){100000}),  /* 100K iterations */
        OSSL_PARAM_construct_utf8_string("digest", "SHA256", 0),
        OSSL_PARAM_construct_end()
    };

    bool success = (EVP_KDF_derive(ctx, key, BACKUP_KEY_SIZE, params) > 0);
    EVP_KDF_CTX_free(ctx);

    if (!success) {
        LOG_ERROR("PBKDF2 key derivation failed");
    }

    return success;
}

/* Encrypt data with AES-256-GCM */
static bool encrypt_backup_data(const unsigned char *plaintext, size_t plaintext_len,
                                 const unsigned char *key,
                                 unsigned char *ciphertext, size_t *ciphertext_len,
                                 unsigned char *iv, unsigned char *tag) {
    /* Generate random IV */
    if (RAND_bytes(iv, BACKUP_IV_SIZE) != 1) {
        LOG_ERROR("Failed to generate IV");
        return false;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        LOG_ERROR("Failed to create cipher context");
        return false;
    }

    bool success = false;
    int len;

    /* Initialize encryption */
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv) != 1) {
        LOG_ERROR("Failed to initialize encryption");
        goto cleanup;
    }

    /* Encrypt data */
    if (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len) != 1) {
        LOG_ERROR("Failed to encrypt data");
        goto cleanup;
    }
    *ciphertext_len = len;

    /* Finalize */
    if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1) {
        LOG_ERROR("Failed to finalize encryption");
        goto cleanup;
    }
    *ciphertext_len += len;

    /* Get authentication tag */
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, BACKUP_TAG_SIZE, tag) != 1) {
        LOG_ERROR("Failed to get auth tag");
        goto cleanup;
    }

    success = true;

cleanup:
    EVP_CIPHER_CTX_free(ctx);
    return success;
}

/* Decrypt data with AES-256-GCM */
static bool decrypt_backup_data(const unsigned char *ciphertext, size_t ciphertext_len,
                                 const unsigned char *key, const unsigned char *iv,
                                 const unsigned char *tag,
                                 unsigned char *plaintext, size_t *plaintext_len) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        LOG_ERROR("Failed to create cipher context");
        return false;
    }

    bool success = false;
    int len;

    /* Initialize decryption */
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv) != 1) {
        LOG_ERROR("Failed to initialize decryption");
        goto cleanup;
    }

    /* Decrypt data */
    if (EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len) != 1) {
        LOG_ERROR("Failed to decrypt data");
        goto cleanup;
    }
    *plaintext_len = len;

    /* Set expected tag */
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, BACKUP_TAG_SIZE, (void*)tag) != 1) {
        LOG_ERROR("Failed to set auth tag");
        goto cleanup;
    }

    /* Finalize and verify tag */
    if (EVP_DecryptFinal_ex(ctx, plaintext + len, &len) != 1) {
        LOG_ERROR("Decryption failed - authentication tag mismatch (corrupted or wrong key)");
        goto cleanup;
    }
    *plaintext_len += len;

    success = true;

cleanup:
    EVP_CIPHER_CTX_free(ctx);
    return success;
}

/* ============================================================================
 * AUTOMATIC BACKUP THREAD
 * ============================================================================
 * Saves keypool to disk every 30 minutes (overwrites single file)
 * Prevents key loss on unexpected shutdown/crash
 * Optional AES-256-GCM encryption with CA-key derived password
 */

/* Forward declarations */
static keypool_error_t save_backup_bundle(keypool_t *pool, const char *bundle_path);
static int load_single_bundle(keypool_t *pool, const char *bundle_path);

/* Backup interval in seconds */
#define BACKUP_INTERVAL_SECONDS (60 * 60)  /* 60 minutes for production */

/* Backup thread function */
static void* backup_thread_func(void *arg) {
    keypool_t *pool = (keypool_t*)arg;

    LOG_INFO("Backup thread started (backup every %d seconds)", BACKUP_INTERVAL_SECONDS);

    while (!atomic_load_explicit(&pool->backup_shutdown, memory_order_acquire)) {
        /* Sleep for backup interval (check shutdown every second) */
        for (int i = 0; i < BACKUP_INTERVAL_SECONDS; i++) {
            if (atomic_load_explicit(&pool->backup_shutdown, memory_order_acquire)) {
                break;
            }
            sleep(1);
        }

        if (atomic_load_explicit(&pool->backup_shutdown, memory_order_acquire)) {
            break;
        }

        /* Perform backup */
        LOG_INFO("Scheduled backup starting...");
        keypool_error_t err = save_backup_bundle(pool, pool->backup_path);
        if (err == KEYPOOL_OK) {
            LOG_INFO("Scheduled backup completed successfully");
        } else {
            LOG_WARN("Scheduled backup failed: %d", err);
        }
    }

    /* Final backup on shutdown */
    LOG_INFO("Backup thread stopping - performing final backup...");
    keypool_error_t err = save_backup_bundle(pool, pool->backup_path);
    if (err != KEYPOOL_OK) {
        LOG_WARN("Final backup failed: %d", err);
    }

    LOG_INFO("Backup thread stopped");
    return NULL;
}

/* Start backup thread */
static bool start_backup_thread(keypool_t *pool, const char *backup_dir) {
    if (!pool || !backup_dir) {
        return false;
    }

    /* Build backup path: {backup_dir}/keys.shm.bundle.gz */
    size_t backup_dir_len = strlen(backup_dir);
    /* Check for overflow: backup_dir_len + 64 should not overflow */
    if (backup_dir_len > SIZE_MAX - 64) {
        LOG_ERROR("Backup directory path too long");
        return false;
    }
    size_t path_len = backup_dir_len + 64;
    pool->backup_path = malloc(path_len);
    if (!pool->backup_path) {
        LOG_ERROR("Failed to allocate backup path");
        return false;
    }
    snprintf(pool->backup_path, path_len, "%s/keys.shm.bundle.gz", backup_dir);

    /* Create backup directory if needed */
    struct stat st;
    if (stat(backup_dir, &st) != 0) {
        if (mkdir(backup_dir, 0700) != 0) {
            LOG_ERROR("Failed to create backup directory: %s", backup_dir);
            free(pool->backup_path);
            pool->backup_path = NULL;
            return false;
        }
    }

    /* Auto-restore from backup on reboot (SHM empty = fresh after reboot)
     * Service restart: SHM still has keys → don't reload
     * System reboot:   SHM is empty     → restore from backup
     */
    if (pool->using_shm && pool->shm_pool) {
        /* SECURITY FIX: Prevent race condition where multiple processes restore backup simultaneously.
         * Use atomic CAS to ensure only ONE process restores from backup. */
        bool already_restored = atomic_load_explicit(&pool->shm_pool->backup_restored, memory_order_acquire);

        if (!already_restored) {
            /* Try to atomically claim the backup restore operation */
            bool expected = false;
            if (atomic_compare_exchange_strong_explicit(&pool->shm_pool->backup_restored,
                                                        &expected,
                                                        true,
                                                        memory_order_acq_rel,
                                                        memory_order_acquire)) {
                /* We won the race - we are responsible for restoring backup */
                int shm_available = atomic_load_explicit(&pool->shm_pool->available, memory_order_acquire);

                if (shm_available == 0) {
                    /* SHM is empty - check if backup exists */
                    if (stat(pool->backup_path, &st) == 0 && S_ISREG(st.st_mode)) {
                        LOG_INFO("Reboot detected (SHM empty) - restoring from backup: %s", pool->backup_path);

                        /* Open with shared read lock (allows other readers, blocks writers) */
                        int lock_fd = open(pool->backup_path, O_RDONLY);
                        if (lock_fd >= 0) {
                            if (flock(lock_fd, LOCK_SH) == 0) {
                                /* Load bundle with lock held */
                                int loaded = load_single_bundle(pool, pool->backup_path);
                                flock(lock_fd, LOCK_UN);

                                if (loaded > 0) {
                                    LOG_INFO("✅ Restored %d keys from backup after reboot", loaded);
                                } else {
                                    LOG_WARN("Failed to restore keys from backup (will regenerate)");
                                }
                            } else {
                                LOG_WARN("Failed to acquire read lock on backup: %s", strerror(errno));
                            }
                            close(lock_fd);
                        } else {
                            LOG_WARN("Failed to open backup for locking: %s", strerror(errno));
                        }
                    } else {
                        LOG_INFO("No backup file found - keys will be generated fresh");
                    }
                } else {
                    LOG_INFO("Service restart detected (SHM has %d keys) - not reloading backup", shm_available);
                }
            } else {
                /* Another process won the race - they are handling backup restore */
                LOG_DEBUG("Another process is restoring backup, skipping");
            }
        } else {
            LOG_INFO("Backup already restored on this SHM instance");
        }

        /* Clear SHM backup restore lock (regardless of success/failure/skip)
         * This allows refill to proceed once all 3 locks are cleared */
        keypool_clear_restore_lock(pool, RESTORE_LOCK_SHM_BACKUP);
    }

    /* Start thread */
    atomic_store(&pool->backup_shutdown, false);
    if (pthread_create(&pool->backup_thread, NULL, backup_thread_func, pool) != 0) {
        LOG_ERROR("Failed to create backup thread");
        free(pool->backup_path);
        pool->backup_path = NULL;
        return false;
    }

    LOG_INFO("Started automatic backup (every 60 minutes): %s", pool->backup_path);
    return true;
}

/* Stop backup thread */
static void stop_backup_thread(keypool_t *pool) {
    if (!pool || !pool->backup_path) {
        return;  /* Backup not enabled */
    }

    /* Signal shutdown */
    atomic_store(&pool->backup_shutdown, true);

    /* Wait for thread to finish (includes final backup) */
    pthread_join(pool->backup_thread, NULL);

    /* Cleanup */
    free(pool->backup_path);
    pool->backup_path = NULL;
}

/* Keypool Lifecycle */

keypool_t* keypool_create(const keypool_config_t *config, bool is_keygen) {
    if (!config) {
        LOG_ERROR("Invalid config");
        return NULL;
    }

    keypool_t *pool = calloc(1, sizeof(keypool_t));
    if (!pool) {
        LOG_ERROR("Failed to allocate keypool");
        return NULL;
    }

    /* Copy config */
    memcpy(&pool->config, config, sizeof(keypool_config_t));
    pool->is_keygen = is_keygen;

    /* Initialize atomics */
    atomic_init(&pool->local_available, 0);
    atomic_init(&pool->refill_shutdown, false);
    pool->refill_in_progress = false;  /* C11 atomic initialization */
    atomic_init(&pool->stats.total_generated, 0);
    atomic_init(&pool->stats.total_consumed, 0);
    atomic_init(&pool->stats.cache_hits, 0);
    atomic_init(&pool->stats.cache_misses, 0);

    pthread_mutex_init(&pool->local_lock, NULL);

    /* Try to use shared memory if enabled */
    if (config->use_shared_memory) {
        shm_error_t err = keypool_shm_init(is_keygen, &pool->shm_pool, &pool->shm_fd);
        if (err == SHM_OK) {
            pool->using_shm = true;
            LOG_INFO("Using shared memory keypool (capacity=%d)",
                    pool->shm_pool->capacity);
        } else {
            LOG_WARN("Failed to initialize SHM, using local pool: %d", err);
            pool->using_shm = false;
        }
    }

    /* Initialize local pool (fallback or primary) */
    if (!pool->using_shm || is_keygen) {
        pool->local_keys = calloc(config->local_pool_size, sizeof(EVP_PKEY*));
        if (!pool->local_keys) {
            LOG_ERROR("Failed to allocate local key array");
            keypool_destroy(pool);
            return NULL;
        }
        LOG_INFO("Initialized local keypool (capacity=%d)", config->local_pool_size);
    }

    /* Initialize prime pools (all NULL initially) */
    for (int i = 0; i < RSA_KEYSIZES; i++) {
        pool->prime_pools[i] = NULL;
    }
    pool->prime_pool_dir = NULL;

    /* Initialize backup fields */
    pool->backup_path = NULL;
    atomic_init(&pool->backup_shutdown, false);

    LOG_INFO("Created keypool (algorithm=%s, shm=%s, keygen=%s, backup=%s)",
            keypool_algorithm_name(config->default_algorithm),
            pool->using_shm ? "yes" : "no",
            is_keygen ? "yes" : "no",
            config->enable_backup ? "enabled" : "disabled");

    /* Start automatic backup thread (if enabled) */
    if (config->enable_backup && config->backup_dir) {
        if (!start_backup_thread(pool, config->backup_dir)) {
            LOG_WARN("Failed to start backup thread (continuing without backups)");
        }
    }

    return pool;
}

void keypool_destroy(keypool_t *pool) {
    if (!pool) {
        return;
    }

    /* Stop backup thread first (performs final backup) */
    stop_backup_thread(pool);

    /* Stop refill threads */
    keypool_stop_refill(pool);

    /* Free local keys */
    if (pool->local_keys) {
        pthread_mutex_lock(&pool->local_lock);
        for (int i = 0; i < pool->config.local_pool_size; i++) {
            if (pool->local_keys[i]) {
                EVP_PKEY_free(pool->local_keys[i]);
            }
        }
        pthread_mutex_unlock(&pool->local_lock);
        free(pool->local_keys);
    }

    /* Cleanup SHM */
    if (pool->using_shm && pool->shm_pool) {
        keypool_shm_cleanup(pool->shm_pool, pool->shm_fd);
    }

    /* Free prime pools */
    free_all_prime_pools(pool);
    free(pool->prime_pool_dir);

    pthread_mutex_destroy(&pool->local_lock);
    free(pool);

    LOG_DEBUG("Destroyed keypool");
}

/* Key Acquisition */

/* Try to get key from local pool */
static EVP_PKEY* try_acquire_local(keypool_t *pool) {
    if (!pool->local_keys) {
        return NULL;
    }

    pthread_mutex_lock(&pool->local_lock);

    int available = atomic_load_explicit(&pool->local_available, memory_order_acquire);
    if (available == 0) {
        pthread_mutex_unlock(&pool->local_lock);
        return NULL;
    }

    /* Find first available key */
    EVP_PKEY *key = NULL;
    for (int i = 0; i < pool->config.local_pool_size; i++) {
        if (pool->local_keys[i]) {
            key = pool->local_keys[i];
            pool->local_keys[i] = NULL;
            atomic_fetch_sub(&pool->local_available, 1);
            break;
        }
    }

    pthread_mutex_unlock(&pool->local_lock);

    if (key) {
        LOG_TRACE_FAST("Acquired key from local pool");
    }

    return key;
}

/* Try to get key from shared memory pool (filtered by algorithm) */
static EVP_PKEY* try_acquire_shm(keypool_t *pool, crypto_alg_t wanted_algorithm) {
    if (!pool->using_shm || !pool->shm_pool) {
        return NULL;
    }

    keypool_shm_t *shm = pool->shm_pool;
    EVP_PKEY *key = NULL;

    /* Lock SHM for exclusive access (robust: recovers from dead owner) */
    if (robust_mutex_lock(&shm->lock) != 0) {
        LOG_ERROR("Failed to lock SHM pool");
        return NULL;
    }

    /* Find first available key with matching algorithm */
    int available_count = atomic_load_explicit(&shm->available, memory_order_acquire);
    if (available_count <= 0) {
        pthread_mutex_unlock(&shm->lock);
        return NULL;  /* Pool empty */
    }

    int found_index = -1;
    for (int i = 0; i < shm->capacity; i++) {
        int offset = atomic_load_explicit(&shm->key_offsets[i], memory_order_acquire);
        if (offset != -1) {
            /* Check if algorithm matches (or wanted_algorithm is AUTO) */
            int key_alg = atomic_load_explicit(&shm->key_algorithms[i], memory_order_acquire);
            if (wanted_algorithm == CRYPTO_ALG_AUTO || key_alg == (int)wanted_algorithm) {
                found_index = i;
                break;
            }
        }
    }

    if (found_index == -1) {
        /* No key with matching algorithm found */
        LOG_DEBUG("No key with algorithm %d in SHM pool (available=%d)",
                  (int)wanted_algorithm, available_count);
        pthread_mutex_unlock(&shm->lock);
        return NULL;
    }

    /* Extract PEM data from shared memory */
    int offset = atomic_load_explicit(&shm->key_offsets[found_index], memory_order_acquire);
    unsigned int pem_len = atomic_load_explicit(&shm->key_lengths[found_index], memory_order_acquire);

    if (offset < 0 || offset + pem_len > sizeof(shm->pem_storage)) {
        LOG_ERROR("SHM pool corrupted: invalid offset=%d or length=%u", offset, pem_len);
        pthread_mutex_unlock(&shm->lock);
        return NULL;
    }

    /* Copy PEM data to local buffer (avoid holding lock during deserialization) */
    char *pem_data = malloc(pem_len + 1);
    if (!pem_data) {
        LOG_ERROR("Failed to allocate PEM buffer (%u bytes)", pem_len);
        pthread_mutex_unlock(&shm->lock);
        return NULL;
    }

    memcpy(pem_data, &shm->pem_storage[offset], pem_len);
    pem_data[pem_len] = '\0';  /* Null-terminate for PEM parser */

    /* Mark slot as consumed BEFORE unlocking */
    atomic_store(&shm->key_offsets[found_index], -1);
    atomic_store(&shm->key_lengths[found_index], 0);
    atomic_store(&shm->key_algorithms[found_index], 0);
    atomic_fetch_sub(&shm->available, 1);

    /* Unlock - deserialization can happen without lock */
    pthread_mutex_unlock(&shm->lock);

    /* Deserialize PEM to EVP_PKEY */
    BIO *bio = BIO_new_mem_buf(pem_data, (int)pem_len);
    if (!bio) {
        LOG_ERROR("Failed to create BIO for PEM deserialization");
        free(pem_data);
        return NULL;
    }

    key = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    BIO_free(bio);
    free(pem_data);

    if (!key) {
        LOG_ERROR("Failed to deserialize PEM key from SHM pool");
        ERR_clear_error();
        return NULL;
    }

    LOG_TRACE_FAST("Acquired key from SHM pool (slot %d, %u bytes)", found_index, pem_len);
    return key;
}

EVP_PKEY* keypool_acquire(keypool_t *pool, crypto_alg_t algorithm) {
    if (!pool) {
        return NULL;
    }

    /* Force single algorithm mode (overrides all other settings) */
    if (pool->config.force_single_algorithm) {
        algorithm = pool->config.forced_algorithm;
        LOG_TRACE("Force mode active: using %s", keypool_algorithm_name(algorithm));
    }

    /* If AUTO, use configured default */
    if (algorithm == CRYPTO_ALG_AUTO) {
        algorithm = pool->config.default_algorithm;
    }

    /* Try local pool first (fast path) */
    EVP_PKEY *key = try_acquire_local(pool);
    if (key) {
        atomic_fetch_add(&pool->stats.cache_hits, 1);
        atomic_fetch_add(&pool->stats.total_consumed, 1);
        return key;
    }

    /* Try SHM pool (if available) - filtered by algorithm */
    if (pool->using_shm) {
        key = try_acquire_shm(pool, algorithm);
        if (key) {
            atomic_fetch_add(&pool->stats.cache_hits, 1);
            atomic_fetch_add(&pool->stats.total_consumed, 1);
            return key;
        }
    }

    /* Pool empty - generate on demand (slow path) */
    LOG_WARN("Keypool empty, generating on-demand (performance degraded)");
    key = generate_key_internal(pool, algorithm);

    if (key) {
        atomic_fetch_add(&pool->stats.cache_misses, 1);
        atomic_fetch_add(&pool->stats.total_consumed, 1);
        atomic_fetch_add(&pool->stats.total_generated, 1);
    }

    return key;
}

/* Background Refill Thread - Adaptive Multi-threaded Refill */

/* Refill worker context */
typedef struct {
    keypool_t *pool;
    int num_keys_to_generate;
    atomic_int *keys_generated;
} refill_worker_ctx_t;

/* Add key to shared memory pool (for poolkeygen mode) */
static bool add_key_to_shm(keypool_shm_t *shm, EVP_PKEY *pkey, crypto_alg_t algorithm) {
    if (!shm || !pkey) {
        return false;
    }

    /* Serialize key to PEM in memory */
    BIO *mem_bio = BIO_new(BIO_s_mem());
    if (!mem_bio) {
        LOG_ERROR("Failed to create memory BIO for SHM key");
        return false;
    }

    if (!PEM_write_bio_PrivateKey(mem_bio, pkey, NULL, NULL, 0, NULL, NULL)) {
        BIO_free(mem_bio);
        LOG_ERROR("Failed to serialize key to PEM for SHM");
        return false;
    }

    /* Get PEM data */
    char *pem_data = NULL;
    long pem_len = BIO_get_mem_data(mem_bio, &pem_data);
    if (!pem_data || pem_len == 0 || pem_len > 2500) {
        BIO_free(mem_bio);
        LOG_ERROR("Invalid PEM length: %ld", pem_len);
        return false;
    }

    /* Thread-safe insertion into SHM (robust: recovers from dead owner) */
    if (robust_mutex_lock(&shm->lock) != 0) {
        BIO_free(mem_bio);
        LOG_ERROR("Failed to lock SHM pool for insertion");
        return false;
    }

    /* Check if pool is full */
    int current_available = atomic_load_explicit(&shm->available, memory_order_acquire);
    if (current_available >= shm->capacity) {
        pthread_mutex_unlock(&shm->lock);
        BIO_free(mem_bio);
        return false;  /* Pool full */
    }

    /* Find next empty slot (circular search from write cursor) */
    int write_cursor = atomic_load_explicit(&shm->pem_write_cursor, memory_order_acquire);
    int slot = -1;
    for (int i = 0; i < shm->capacity; i++) {
        int idx = (write_cursor + i) % shm->capacity;
        if (atomic_load_explicit(&shm->key_offsets[idx], memory_order_acquire) == -1) {
            slot = idx;
            break;
        }
    }

    if (slot == -1) {
        pthread_mutex_unlock(&shm->lock);
        BIO_free(mem_bio);
        LOG_ERROR("No empty slot found in SHM pool");
        return false;
    }

    /* Calculate offset in pem_storage - each slot has exactly 2500 bytes
     * BUG FIX: Use 'slot' not 'write_cursor' - they can differ!
     * The slot is the actual empty slot found, write_cursor is just a hint.
     * Using write_cursor would write PEM data to wrong location. */
    int offset = slot * 2500;  /* Fixed 2500 bytes per slot, no overlap possible */

    /* Write PEM data to storage */
    memcpy(&shm->pem_storage[offset], pem_data, pem_len);

    /* Update slot metadata */
    atomic_store(&shm->key_lengths[slot], (unsigned int)pem_len);
    atomic_store(&shm->key_algorithms[slot], (int)algorithm);
    atomic_store(&shm->key_offsets[slot], offset);  /* Set offset LAST (signals slot is ready) */

    /* Increment counters */
    atomic_fetch_add(&shm->available, 1);
    atomic_store(&shm->pem_write_cursor, (write_cursor + 1) % shm->capacity);

    pthread_mutex_unlock(&shm->lock);
    BIO_free(mem_bio);

    return true;
}

/* Select algorithm based on weighted distribution (percent values from config)
 *
 * Uses the configured percentages to randomly select an algorithm.
 * This ensures the pool has the right mix of RSA, ECDSA, and SM2 keys.
 *
 * @param pool  Keypool with config percentages
 * @return Selected algorithm, or default if multi-algorithm disabled
 */
static crypto_alg_t select_algorithm_weighted(const keypool_t *pool) {
    const keypool_config_t *cfg = &pool->config;

    /* If multi-algorithm disabled or forced mode, use default/forced */
    if (!cfg->enable_multi_algorithm) {
        return cfg->default_algorithm;
    }
    if (cfg->force_single_algorithm) {
        return cfg->forced_algorithm;
    }

    /* Build cumulative distribution from enabled algorithms */
    int cumulative[8];  /* Max 7 algorithms + sentinel */
    crypto_alg_t algorithms[8];
    int num_algos = 0;
    int total = 0;

    if (cfg->enable_rsa_2048 && cfg->rsa_2048_percent > 0) {
        total += cfg->rsa_2048_percent;
        cumulative[num_algos] = total;
        algorithms[num_algos] = CRYPTO_ALG_RSA_2048;
        num_algos++;
    }
    if (cfg->enable_rsa_3072 && cfg->rsa_3072_percent > 0) {
        total += cfg->rsa_3072_percent;
        cumulative[num_algos] = total;
        algorithms[num_algos] = CRYPTO_ALG_RSA_3072;
        num_algos++;
    }
    if (cfg->enable_rsa_4096 && cfg->rsa_4096_percent > 0) {
        total += cfg->rsa_4096_percent;
        cumulative[num_algos] = total;
        algorithms[num_algos] = CRYPTO_ALG_RSA_4096;
        num_algos++;
    }
    if (cfg->enable_ecdsa_p256 && cfg->ecdsa_p256_percent > 0) {
        total += cfg->ecdsa_p256_percent;
        cumulative[num_algos] = total;
        algorithms[num_algos] = CRYPTO_ALG_ECDSA_P256;
        num_algos++;
    }
    if (cfg->enable_ecdsa_p384 && cfg->ecdsa_p384_percent > 0) {
        total += cfg->ecdsa_p384_percent;
        cumulative[num_algos] = total;
        algorithms[num_algos] = CRYPTO_ALG_ECDSA_P384;
        num_algos++;
    }
    if (cfg->enable_ecdsa_p521 && cfg->ecdsa_p521_percent > 0) {
        total += cfg->ecdsa_p521_percent;
        cumulative[num_algos] = total;
        algorithms[num_algos] = CRYPTO_ALG_ECDSA_P521;
        num_algos++;
    }
    if (cfg->enable_sm2 && cfg->sm2_percent > 0) {
        total += cfg->sm2_percent;
        cumulative[num_algos] = total;
        algorithms[num_algos] = CRYPTO_ALG_SM2;
        num_algos++;
    }

    /* Fallback if nothing enabled */
    if (num_algos == 0 || total == 0) {
        return cfg->default_algorithm;
    }

    /* Random selection based on distribution */
    int r = rand() % total;
    for (int i = 0; i < num_algos; i++) {
        if (r < cumulative[i]) {
            return algorithms[i];
        }
    }

    /* Should not reach here, but fallback to default */
    return cfg->default_algorithm;
}

/* Worker thread that generates keys */
static void* refill_worker(void *arg) {
    refill_worker_ctx_t *ctx = (refill_worker_ctx_t*)arg;
    keypool_t *pool = ctx->pool;

    for (int i = 0; i < ctx->num_keys_to_generate; i++) {
        if (atomic_load_explicit(&pool->refill_shutdown, memory_order_acquire)) {
            break;
        }

        /* Generate key with weighted algorithm selection */
        crypto_alg_t alg = select_algorithm_weighted(pool);
        EVP_PKEY *key = generate_key_internal(pool, alg);

        if (key) {
            bool added = false;

            /* Poolkeygen mode: write to shared memory */
            if (pool->is_keygen && pool->using_shm && pool->shm_pool) {
                added = add_key_to_shm(pool->shm_pool, key, alg);
                if (added) {
                    atomic_fetch_add(&pool->stats.total_generated, 1);
                    atomic_fetch_add(ctx->keys_generated, 1);
                }
                /* Key is copied to SHM, free original */
                EVP_PKEY_free(key);
            } else {
                /* Reader mode: write to local pool */
                pthread_mutex_lock(&pool->local_lock);

                /* Find empty slot */
                for (int j = 0; j < pool->config.local_pool_size; j++) {
                    if (!pool->local_keys[j]) {
                        pool->local_keys[j] = key;
                        atomic_fetch_add(&pool->local_available, 1);
                        atomic_fetch_add(&pool->stats.total_generated, 1);
                        atomic_fetch_add(ctx->keys_generated, 1);
                        added = true;
                        break;
                    }
                }

                pthread_mutex_unlock(&pool->local_lock);

                if (!added) {
                    /* Pool filled up while we were generating */
                    EVP_PKEY_free(key);
                }
            }

            if (!added) {
                break;  /* Stop generating if pool is full */
            }
        }
    }

    return NULL;
}

/* Main refill thread - monitors pool and spawns adaptive workers */
static void* refill_manager_thread(void *arg) {
    keypool_t *pool = (keypool_t*)arg;

    fprintf(stderr, "[REFILL] Manager thread started (is_keygen=%d, using_shm=%d, shm_pool=%p)\n",
            pool->is_keygen, pool->using_shm, (void*)pool->shm_pool);
    LOG_INFO("Keypool adaptive refill manager started");

    /* Wait for ALL restore locks to be cleared before starting refill
     * This prevents race conditions between backup/bundle/prime restore and key generation.
     * Each lock is set on SHM creation and cleared after its respective operation:
     * - restore_lock_shm_backup: cleared after SHM backup restore
     * - restore_lock_keybundle:  cleared after keybundle loading
     * - restore_lock_prime:      cleared after prime pool loading
     */
    if (pool->using_shm && pool->shm_pool) {
        while (!keypool_restore_locks_cleared(pool)) {
            /* Show which locks are still pending */
            bool shm_backup = atomic_load_explicit(&pool->shm_pool->restore_lock_shm_backup, memory_order_acquire);
            bool keybundle = atomic_load_explicit(&pool->shm_pool->restore_lock_keybundle, memory_order_acquire);
            bool prime = atomic_load_explicit(&pool->shm_pool->restore_lock_prime, memory_order_acquire);

            fprintf(stderr, "[REFILL] Waiting for restore locks: shm-backup=%d, keybundle=%d, prime=%d\n",
                    shm_backup, keybundle, prime);
            LOG_INFO("Refill waiting for restore locks: shm-backup=%d, keybundle=%d, prime=%d",
                     shm_backup, keybundle, prime);
            sleep(1);

            /* Check for shutdown while waiting */
            if (atomic_load_explicit(&pool->refill_shutdown, memory_order_acquire)) {
                LOG_INFO("Shutdown requested while waiting for restore");
                return NULL;
            }
        }
        fprintf(stderr, "[REFILL] All restore locks cleared, starting refill\n");
        LOG_INFO("All restore locks cleared, refill manager starting");
    }

    while (!atomic_load_explicit(&pool->refill_shutdown, memory_order_acquire)) {
        /* HA SAFETY CHECK: Verify we are still the keygen owner
         * BUG FIX: If another poolgen took over (HA failover), stop generating
         * to prevent race conditions with two writers in SHM.
         */
        if (pool->is_keygen && pool->using_shm && pool->shm_pool) {
            pid_t current_owner = atomic_load_explicit(&pool->shm_pool->keygen_pid, memory_order_acquire);
            if (current_owner != getpid()) {
                LOG_WARN("HA takeover detected: PID %d took over, stopping refill", current_owner);
                fprintf(stderr, "[REFILL] HA takeover detected: PID %d is now keygen, we should exit\n", current_owner);
                break;  /* Stop generating, let the main loop handle shutdown */
            }
        }

        /* Check if a refill is already in progress - skip if so */
        bool expected = false;
        if (!atomic_compare_exchange_strong(&pool->refill_in_progress, &expected, true)) {
            /* Another refill is in progress - wait and retry */
            sleep(5);
            continue;
        }

        /* BUG FIX: Check correct pool counter based on mode
         * SHM mode: use shm_pool->available and shm_pool->capacity
         * Local mode: use local_available and local_pool_size
         */
        int available;
        int pool_size;
        if (pool->using_shm && pool->shm_pool) {
            available = atomic_load_explicit(&pool->shm_pool->available, memory_order_acquire);
            pool_size = pool->shm_pool->capacity;
        } else {
            available = atomic_load_explicit(&pool->local_available, memory_order_acquire);
            pool_size = pool->config.local_pool_size;
        }
        int fill_percent = (pool_size > 0) ? (available * 100) / pool_size : 100;

        /* Calculate how many keys we need */
        int target = (pool_size * 90) / 100;  /* Fill to 90% */
        int needed = target - available;

        fprintf(stderr, "[REFILL] available=%d, pool_size=%d, needed=%d\n", available, pool_size, needed);

        if (needed > 0) {
            /* Determine adaptive thread count based on fill level */
            int num_threads = get_adaptive_thread_count(fill_percent);

            fprintf(stderr, "[REFILL] Spawning %d workers to generate %d keys\n", num_threads, needed);
            LOG_DEBUG("Keypool refill: %d/%d keys (%.1f%%), spawning %d workers for %d keys",
                     available, pool_size, (float)fill_percent, num_threads, needed);

            /* Allocate worker contexts and threads */
            pthread_t *threads = calloc(num_threads, sizeof(pthread_t));
            refill_worker_ctx_t *workers = calloc(num_threads, sizeof(refill_worker_ctx_t));

            if (!threads || !workers) {
                LOG_ERROR("Failed to allocate refill worker arrays");
                free(threads);
                free(workers);
                atomic_store(&pool->refill_in_progress, false);
                continue;
            }

            atomic_int keys_generated;
            atomic_init(&keys_generated, 0);

            if (threads && workers) {
                int keys_per_thread = needed / num_threads;
                int remainder = needed % num_threads;

                /* Start refill worker threads
                 * BUG FIX: Track which threads were successfully created to avoid
                 * pthread_join on uninitialized pthread_t (undefined behavior) */
                int threads_started = 0;
                for (int t = 0; t < num_threads; t++) {
                    workers[t].pool = pool;
                    workers[t].num_keys_to_generate = keys_per_thread + (t < remainder ? 1 : 0);
                    workers[t].keys_generated = &keys_generated;
                    if (pthread_create(&threads[t], NULL, refill_worker, &workers[t]) == 0) {
                        threads_started++;
                    } else {
                        LOG_WARN("Failed to create refill worker thread %d/%d", t + 1, num_threads);
                        break;  /* Stop trying to create more threads */
                    }
                }

                /* Wait for successfully created workers to complete
                 * BUG FIX: Use polling instead of blocking join to update heartbeat
                 * while waiting. Otherwise heartbeat goes stale during long generations.
                 */
                int threads_remaining = threads_started;
                while (threads_remaining > 0) {
                    for (int t = 0; t < threads_started; t++) {
                        if (threads[t] != 0) {
                            /* Try non-blocking join */
                            int ret = pthread_tryjoin_np(threads[t], NULL);
                            if (ret == 0) {
                                /* Thread finished */
                                threads[t] = 0;
                                threads_remaining--;
                            }
                            /* EBUSY = still running, keep waiting */
                        }
                    }

                    if (threads_remaining > 0) {
                        /* Update heartbeat while waiting for workers */
                        if (pool->is_keygen && pool->using_shm && pool->shm_pool) {
                            atomic_store_explicit(&pool->shm_pool->last_keygen_heartbeat,
                                                  (long long)time(NULL), memory_order_release);
                        }
                        sleep(1);  /* Check every second */
                    }
                }

                int generated = atomic_load_explicit(&keys_generated, memory_order_acquire);
                if (generated > 0) {
                    /* Use correct counter for logging */
                    int current_available = (pool->using_shm && pool->shm_pool)
                        ? atomic_load_explicit(&pool->shm_pool->available, memory_order_acquire)
                        : atomic_load_explicit(&pool->local_available, memory_order_acquire);
                    LOG_INFO("Generated %d keys with %d threads (pool now %d/%d, %.1f%%)",
                            generated, num_threads,
                            current_available, pool_size,
                            (pool_size > 0) ? (float)(current_available * 100) / pool_size : 0.0f);
                }
            }

            free(threads);
            free(workers);
        }

        /* Release refill-in-progress flag */
        atomic_store(&pool->refill_in_progress, false);

        /* Update keygen heartbeat in SHM (for HA failover detection)
         * BUG FIX: This was missing - heartbeat was only set at init,
         * causing HA backup to wrongly think primary was dead.
         */
        if (pool->is_keygen && pool->using_shm && pool->shm_pool) {
            atomic_store_explicit(&pool->shm_pool->last_keygen_heartbeat,
                                  (long long)time(NULL), memory_order_release);
        }

        /* Adaptive sleep based on fill level */
        if (fill_percent < REFILL_AGGRESSIVE_PCT) {
            sleep(5);   /* <25% full: check every 5 seconds */
        } else if (fill_percent < REFILL_FAST_PCT) {
            sleep(10);  /* 25-50% full: check every 10 seconds */
        } else if (fill_percent < REFILL_SLOW_PCT) {
            sleep(30);  /* 50-75% full: check every 30 seconds */
        } else {
            sleep(60);  /* >75% full: check every minute */
        }
    }

    LOG_INFO("Keypool adaptive refill manager stopped");
    return NULL;
}

keypool_error_t keypool_start_refill(keypool_t *pool, int num_threads) {
    if (!pool) {
        return KEYPOOL_ERR_INVALID;
    }

    /* Ignore num_threads parameter - adaptive threading handles this now */
    (void)num_threads;

    LOG_INFO("Starting adaptive keypool refill manager (auto-scales: 8 cores=1-4 threads, 32 cores=1-16 threads)");

    /* Allocate single manager thread */
    pool->refill_threads = calloc(1, sizeof(pthread_t));
    if (!pool->refill_threads) {
        LOG_ERROR("Failed to allocate refill manager thread");
        return KEYPOOL_ERR_NOMEM;
    }

    pool->num_refill_threads = 1;
    atomic_store(&pool->refill_shutdown, false);

    /* Start manager thread (it will spawn adaptive workers as needed) */
    if (pthread_create(&pool->refill_threads[0], NULL, refill_manager_thread, pool) != 0) {
        LOG_ERROR("Failed to create refill manager thread");
        free(pool->refill_threads);
        pool->refill_threads = NULL;
        pool->num_refill_threads = 0;
        return KEYPOOL_ERR_THREAD;
    }

    LOG_INFO("Adaptive keypool refill manager started successfully");
    return KEYPOOL_OK;
}

void keypool_stop_refill(keypool_t *pool) {
    if (!pool || !pool->refill_threads) {
        return;
    }

    LOG_INFO("Stopping keypool refill threads");

    atomic_store(&pool->refill_shutdown, true);

    /* Join all threads */
    for (int i = 0; i < pool->num_refill_threads; i++) {
        pthread_join(pool->refill_threads[i], NULL);
    }

    free(pool->refill_threads);
    pool->refill_threads = NULL;
    pool->num_refill_threads = 0;

    LOG_INFO("Keypool refill threads stopped");
}

/* Statistics */

void keypool_get_stats(const keypool_t *pool, keypool_stats_t *stats) {
    if (!pool || !stats) {
        return;
    }

    stats->total_generated = atomic_load_explicit(&pool->stats.total_generated, memory_order_acquire);
    stats->total_consumed = atomic_load_explicit(&pool->stats.total_consumed, memory_order_acquire);
    stats->cache_hits = atomic_load_explicit(&pool->stats.cache_hits, memory_order_acquire);
    stats->cache_misses = atomic_load_explicit(&pool->stats.cache_misses, memory_order_acquire);

    int available;
    if (pool->using_shm && pool->shm_pool) {
        available = atomic_load_explicit(&pool->shm_pool->available, memory_order_acquire);
        stats->pool_capacity = pool->shm_pool->capacity;
    } else {
        available = atomic_load_explicit(&pool->local_available, memory_order_acquire);
        stats->pool_capacity = pool->config.local_pool_size;
    }

    stats->current_available = available;
    stats->fill_ratio = (float)available / stats->pool_capacity;
}

void keypool_print_stats(const keypool_t *pool) {
    if (!pool) {
        return;
    }

    keypool_stats_t stats;
    keypool_get_stats(pool, &stats);

    LOG_INFO("Keypool Statistics:");
    LOG_INFO("  Generated:  %d keys", stats.total_generated);
    LOG_INFO("  Consumed:   %d keys", stats.total_consumed);
    LOG_INFO("  Cache hits: %d (%.1f%%)",
            stats.cache_hits,
            stats.total_consumed > 0 ?
                100.0f * stats.cache_hits / stats.total_consumed : 0.0f);
    LOG_INFO("  Cache miss: %d (%.1f%%)",
            stats.cache_misses,
            stats.total_consumed > 0 ?
                100.0f * stats.cache_misses / stats.total_consumed : 0.0f);
    LOG_INFO("  Available:  %d / %d (%.1f%%)",
            stats.current_available,
            stats.pool_capacity,
            100.0f * stats.fill_ratio);
}

/* ============================================================================
 * BUNDLE PERSISTENCE
 * ============================================================================
 * Multi-bundle system for pre-generated keys:
 *   keys.rsa.001.bundle.gz ... keys.rsa.999.bundle.gz
 *   keys.ec.001.bundle.gz  ... keys.ec.999.bundle.gz
 *
 * Critical for production with millions of users - zero downtime on reboot!
 */

#include <dirent.h>
#include <zlib.h>

/* Add pregenerated key to pool with known algorithm (for v2 backup restore)
 * Skips algorithm detection since we already know it from the backup */
static keypool_error_t keypool_add_pregenerated_with_alg(keypool_t *pool, EVP_PKEY *pkey, crypto_alg_t alg) {
    if (!pool || !pkey) {
        return KEYPOOL_ERR_INVALID;
    }

    /* SHM mode: Add to shared memory so all workers can use the key */
    if (pool->using_shm && pool->shm_pool) {
        if (add_key_to_shm(pool->shm_pool, pkey, alg)) {
            atomic_fetch_add(&pool->stats.total_generated, 1);
            EVP_PKEY_free(pkey);  /* add_key_to_shm serializes to PEM, original not needed */
            return KEYPOOL_OK;
        }
        /* SHM full - try local fallback below */
    }

    /* Local mode fallback (thread-safe insertion) */
    pthread_mutex_lock(&pool->local_lock);

    /* Find empty slot */
    for (size_t i = 0; i < (size_t)pool->config.local_pool_size; i++) {
        if (!pool->local_keys[i]) {
            pool->local_keys[i] = pkey;
            atomic_fetch_add(&pool->local_available, 1);
            atomic_fetch_add(&pool->stats.total_generated, 1);
            pthread_mutex_unlock(&pool->local_lock);
            return KEYPOOL_OK;
        }
    }

    pthread_mutex_unlock(&pool->local_lock);

    /* Pool full */
    LOG_WARN("Keypool full, cannot add pregenerated key");
    return KEYPOOL_ERR_FULL;
}

/* Add pregenerated key to pool (internal)
 * BUG FIX: Now properly adds to SHM when in SHM mode (for backup restore) */
static keypool_error_t keypool_add_pregenerated(keypool_t *pool, EVP_PKEY *pkey) {
    if (!pool || !pkey) {
        return KEYPOOL_ERR_INVALID;
    }

    /* Detect algorithm and add */
    crypto_alg_t alg = detect_key_algorithm(pkey);
    return keypool_add_pregenerated_with_alg(pool, pkey, alg);
}

/* Load single bundle file (gzip-compressed PEM or encrypted)
 *
 * Supports two formats:
 * 1. Legacy/unencrypted: Gzip-compressed PEM (opens with gzopen)
 * 2. Encrypted: Header + Salt + IV + AES-256-GCM encrypted gzip + Tag
 */
static int load_single_bundle(keypool_t *pool, const char *bundle_path) {
    if (!pool || !bundle_path) {
        return -1;
    }

    LOG_INFO("Loading key bundle: %s", bundle_path);

    /* Read file to check format */
    FILE *f = fopen(bundle_path, "rb");
    if (!f) {
        LOG_ERROR("Failed to open bundle: %s", bundle_path);
        return -1;
    }

    /* Check for encryption header */
    char header[BACKUP_HEADER_SIZE];
    size_t read_bytes = fread(header, 1, BACKUP_HEADER_SIZE, f);
    if (read_bytes < BACKUP_HEADER_SIZE) {
        /* File too small - try as legacy gzip */
        fclose(f);
        goto legacy_format;
    }

    bool is_encrypted_v1 = (memcmp(header, BACKUP_HEADER_MAGIC, strlen(BACKUP_HEADER_MAGIC)) == 0);
    bool is_encrypted_v2 = (memcmp(header, BACKUP_HEADER_MAGIC_V2, strlen(BACKUP_HEADER_MAGIC_V2)) == 0);
    bool is_encrypted = is_encrypted_v1 || is_encrypted_v2;
    bool is_v2_format = is_encrypted_v2;  /* v2 format has algorithm info */

    unsigned char *pem_data = NULL;
    size_t pem_len = 0;

    if (is_encrypted) {
        LOG_INFO("Detected encrypted backup format");

        /* Check if we have decryption keys */
        if (!pool->config.encrypt_backup || !pool->config.ca_key_path || !pool->config.backup_curve) {
            fclose(f);
            LOG_ERROR("Backup is encrypted but decryption not configured");
            return -1;
        }

        /* Read salt, IV, ciphertext, tag */
        fseek(f, BACKUP_HEADER_SIZE, SEEK_SET);

        unsigned char salt[BACKUP_SALT_SIZE];
        unsigned char iv[BACKUP_IV_SIZE];
        unsigned char tag[BACKUP_TAG_SIZE];

        if (fread(salt, 1, BACKUP_SALT_SIZE, f) != BACKUP_SALT_SIZE ||
            fread(iv, 1, BACKUP_IV_SIZE, f) != BACKUP_IV_SIZE) {
            fclose(f);
            LOG_ERROR("Failed to read salt/IV from encrypted backup");
            return -1;
        }

        /* Read rest of file (ciphertext + tag) */
        fseek(f, 0, SEEK_END);
        long file_size = ftell(f);
        size_t ciphertext_size = file_size - BACKUP_HEADER_SIZE - BACKUP_SALT_SIZE - BACKUP_IV_SIZE - BACKUP_TAG_SIZE;

        fseek(f, BACKUP_HEADER_SIZE + BACKUP_SALT_SIZE + BACKUP_IV_SIZE, SEEK_SET);
        unsigned char *ciphertext = malloc(ciphertext_size);
        if (!ciphertext) {
            fclose(f);
            LOG_ERROR("Failed to allocate ciphertext buffer");
            return -1;
        }

        if (fread(ciphertext, 1, ciphertext_size, f) != ciphertext_size ||
            fread(tag, 1, BACKUP_TAG_SIZE, f) != BACKUP_TAG_SIZE) {
            free(ciphertext);
            fclose(f);
            LOG_ERROR("Failed to read ciphertext/tag from encrypted backup");
            return -1;
        }
        fclose(f);

        /* Extract password from CA key */
        char password[128] = {0};
        if (!extract_password_from_ca_key(pool->config.ca_key_path,
                                         pool->config.backup_curve,
                                         password, sizeof(password))) {
            free(ciphertext);
            LOG_ERROR("Failed to extract password for decryption");
            return -1;
        }

        /* Derive decryption key */
        unsigned char dec_key[BACKUP_KEY_SIZE];
        if (!derive_encryption_key(password, salt, dec_key)) {
            explicit_bzero(password, sizeof(password));
            free(ciphertext);
            return -1;
        }
        explicit_bzero(password, sizeof(password));

        /* Decrypt */
        unsigned char *plaintext = malloc(ciphertext_size + 32);
        size_t plaintext_len = 0;

        if (!decrypt_backup_data(ciphertext, ciphertext_size, dec_key, iv, tag,
                                 plaintext, &plaintext_len)) {
            explicit_bzero(dec_key, sizeof(dec_key));
            free(plaintext);
            free(ciphertext);
            LOG_ERROR("Failed to decrypt backup (wrong key or corrupted file)");
            return -1;
        }
        explicit_bzero(dec_key, sizeof(dec_key));
        free(ciphertext);

        /* Decompress gzip data */
        size_t decomp_size = plaintext_len * 10;  /* Estimate */
        pem_data = malloc(decomp_size);
        if (!pem_data) {
            free(plaintext);
            LOG_ERROR("Failed to allocate decompression buffer");
            return -1;
        }

        z_stream stream = {0};
        stream.next_in = plaintext;
        stream.avail_in = plaintext_len;
        stream.next_out = pem_data;
        stream.avail_out = decomp_size;

        if (inflateInit2(&stream, 15+16) != Z_OK) {  /* +16 for gzip */
            free(pem_data);
            free(plaintext);
            LOG_ERROR("Failed to initialize gzip decompression");
            return -1;
        }

        int ret = inflate(&stream, Z_FINISH);
        pem_len = stream.total_out;
        inflateEnd(&stream);
        free(plaintext);

        if (ret != Z_STREAM_END) {
            free(pem_data);
            LOG_ERROR("Failed to decompress backup data");
            return -1;
        }

        LOG_INFO("Successfully decrypted and decompressed backup (%zu bytes PEM)", pem_len);
    } else {
        /* Legacy unencrypted gzip format */
        fclose(f);

legacy_format:
        LOG_INFO("Detected legacy unencrypted format");

        gzFile gz = gzopen(bundle_path, "rb");
        if (!gz) {
            LOG_ERROR("Failed to open gzip bundle: %s", bundle_path);
            return -1;
        }

        /* Read entire gzip file into memory */
        size_t buffer_size = 1024 * 1024;  /* 1MB initial */
        pem_data = malloc(buffer_size);
        if (!pem_data) {
            gzclose(gz);
            LOG_ERROR("Failed to allocate buffer");
            return -1;
        }

        pem_len = 0;
        int bytes_read;
        while ((bytes_read = gzread(gz, pem_data + pem_len, buffer_size - pem_len)) > 0) {
            pem_len += bytes_read;
            if (pem_len >= buffer_size - 4096) {
                /* Check for overflow before doubling buffer_size */
                if (buffer_size > SIZE_MAX / 2) {
                    free(pem_data);
                    gzclose(gz);
                    LOG_ERROR("Buffer size would overflow during resize");
                    return -1;
                }
                buffer_size *= 2;
                unsigned char *new_buf = realloc(pem_data, buffer_size);
                if (!new_buf) {
                    free(pem_data);
                    gzclose(gz);
                    LOG_ERROR("Failed to resize buffer");
                    return -1;
                }
                pem_data = new_buf;
            }
        }
        gzclose(gz);
    }

    /* Parse data - v2 format has algorithm info, v1/legacy uses detection */
    int keys_loaded = 0;
    size_t offset = 0;

    if (is_v2_format) {
        /* V2 FORMAT: [ALG_ID:4][PEM_LEN:4][PEM_DATA]... */
        LOG_INFO("Parsing v2 backup format (with algorithm info)");

        while (offset + 8 <= pem_len) {  /* Need at least 8 bytes for header */
            uint32_t alg_id, block_len;
            memcpy(&alg_id, pem_data + offset, sizeof(alg_id));
            memcpy(&block_len, pem_data + offset + 4, sizeof(block_len));
            offset += 8;

            /* Validate */
            if (block_len == 0 || block_len > 4096 || offset + block_len > pem_len) {
                LOG_WARN("load_single_bundle: Invalid v2 record (len=%u, offset=%zu)", block_len, offset);
                break;
            }

            /* Parse PEM block */
            BIO *bio = BIO_new_mem_buf(pem_data + offset, (int)block_len);
            if (bio) {
                EVP_PKEY *pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
                if (pkey) {
                    /* Debug: Log first 10 keys being loaded */
                    if (keys_loaded < 10) {
                        LOG_DEBUG("load_single_bundle: v2 key %d alg=%d", keys_loaded, alg_id);
                    }
                    /* Use known algorithm from backup, skip detection */
                    if (keypool_add_pregenerated_with_alg(pool, pkey, (crypto_alg_t)alg_id) == KEYPOOL_OK) {
                        keys_loaded++;
                    } else {
                        EVP_PKEY_free(pkey);
                    }
                } else {
                    LOG_WARN("load_single_bundle: Failed to parse v2 PEM block (OpenSSL error)");
                }
                BIO_free(bio);
            }

            offset += block_len;
        }
    } else {
        /* V1/LEGACY FORMAT: PEM blocks only, need algorithm detection */
        LOG_INFO("Parsing v1/legacy backup format (algorithm detection required)");

        while (offset < pem_len) {
            /* Find BEGIN marker */
            const char *begin = "-----BEGIN";
            const char *end = "-----END";

            char *begin_pos = memmem(pem_data + offset, pem_len - offset, begin, strlen(begin));
            if (!begin_pos) break;

            char *end_pos = memmem(begin_pos, pem_len - (begin_pos - (char*)pem_data), end, strlen(end));
            if (!end_pos) break;

            /* Find end of END line */
            char *end_line = memchr(end_pos, '\n', pem_len - (end_pos - (char*)pem_data));
            if (!end_line) end_line = (char*)pem_data + pem_len;
            else end_line++;  /* Include newline */

            size_t pem_block_len = end_line - begin_pos;

            /* Parse this PEM block */
            BIO *bio = BIO_new_mem_buf(begin_pos, pem_block_len);
            if (bio) {
                EVP_PKEY *pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
                if (pkey) {
                    /* Debug: Log first 10 keys being loaded */
                    if (keys_loaded < 10) {
                        LOG_DEBUG("load_single_bundle: legacy key %d type=%d", keys_loaded, EVP_PKEY_base_id(pkey));
                    }
                    if (keypool_add_pregenerated(pool, pkey) == KEYPOOL_OK) {
                        keys_loaded++;
                    } else {
                        EVP_PKEY_free(pkey);
                    }
                } else {
                    LOG_WARN("load_single_bundle: Failed to parse PEM block (OpenSSL error)");
                }
                BIO_free(bio);
            }

            offset = end_line - (char*)pem_data;
        }
    }

    free(pem_data);

    LOG_INFO("Loaded %d keys from bundle: %s", keys_loaded, bundle_path);
    return keys_loaded;
}

/* Load all bundles from directory matching pattern */
keypool_error_t keypool_load_bundles_from_dir(keypool_t *pool, const char *bundle_dir) {
    if (!pool || !bundle_dir) {
        return KEYPOOL_ERR_INVALID;
    }

    LOG_INFO("Loading key bundles from: %s", bundle_dir);

    DIR *dir = opendir(bundle_dir);
    if (!dir) {
        LOG_ERROR("Failed to open bundle directory: %s", bundle_dir);
        return KEYPOOL_ERR_IO;
    }

    int total_keys = 0;
    int bundles_loaded = 0;
    struct dirent *entry;

    while ((entry = readdir(dir)) != NULL) {
        /* Skip . and .. */
        if (entry->d_name[0] == '.') continue;

        /* Match patterns:
         * RSA:   keys.rsa.{1024,2048,3072,4096,8192}[.NNN].bundle.gz
         * ECDSA: keys.ec.{256,384,521}[.NNN].bundle.gz
         * EdDSA: keys.ed.25519[.NNN].bundle.gz
         * Where [.NNN] is optional sequence number (001-999)
         */
        bool is_rsa = (strstr(entry->d_name, "keys.rsa.") == entry->d_name);
        bool is_ec = (strstr(entry->d_name, "keys.ec.") == entry->d_name);
        bool is_ed = (strstr(entry->d_name, "keys.ed.") == entry->d_name);
        bool ends_with_bundle_gz = (strstr(entry->d_name, ".bundle.gz") != NULL);

        if ((is_rsa || is_ec || is_ed) && ends_with_bundle_gz) {
            /* Build full path */
            char full_path[1024];
            snprintf(full_path, sizeof(full_path), "%s/%s", bundle_dir, entry->d_name);

            /* Load bundle */
            int keys = load_single_bundle(pool, full_path);
            if (keys > 0) {
                total_keys += keys;
                bundles_loaded++;
            }
        }
    }

    closedir(dir);

    LOG_INFO("Loaded %d bundles (%d keys total) from %s", bundles_loaded, total_keys, bundle_dir);

    return (bundles_loaded > 0) ? KEYPOOL_OK : KEYPOOL_ERR_INVALID;
}

/* Save all keys from local pool to backup bundle
 *
 * Writes all keys from local_keys[] to a gzip-compressed PEM file.
 * This is used for automatic backup (every 30 minutes).
 *
 * WARNING: May produce duplicate keys after restart (by design - acceptable)
 *
 * Format (unencrypted): Gzip-compressed concatenated PEM private keys
 * Format (encrypted):
 *   [Header: 32 bytes "TLSGATENG_BACKUP_V1" + padding]
 *   [Salt: 32 bytes random]
 *   [IV: 12 bytes random]
 *   [Ciphertext: gzip PEM data encrypted with AES-256-GCM]
 *   [Auth Tag: 16 bytes]
 */
static keypool_error_t save_backup_bundle(keypool_t *pool, const char *bundle_path) {
    if (!pool || !bundle_path) {
        return KEYPOOL_ERR_INVALID;
    }

    /* Step 1: Collect all keys as PEM in memory buffer */
    BIO *mem_bio = BIO_new(BIO_s_mem());
    if (!mem_bio) {
        LOG_ERROR("Failed to create memory BIO");
        return KEYPOOL_ERR_NOMEM;
    }

    int keys_saved = 0;

    /* BUG FIX: Support both SHM and local key storage
     * In keygen mode with SHM, keys are stored as PEM strings in shm_pool->pem_storage
     * In reader mode or without SHM, keys are stored as EVP_PKEY* in local_keys
     *
     * V2 FORMAT: [ALG_ID:4][PEM_LEN:4][PEM_DATA]... for each key
     * This preserves algorithm info and avoids detection issues (especially SM2)
     */
    bool use_v2_format = false;  /* Use v2 format when algorithm info is available */

    if (pool->using_shm && pool->shm_pool) {
        /* SHM mode: Read PEM strings directly from shared memory with algorithm info */
        keypool_shm_t *shm = pool->shm_pool;
        if (robust_mutex_lock(&shm->lock) != 0) {
            LOG_ERROR("Failed to lock SHM pool for backup");
            BIO_free(mem_bio);
            return KEYPOOL_ERR_NOMEM;
        }

        use_v2_format = true;  /* SHM has algorithm info, use v2 format */

        for (int i = 0; i < shm->capacity; i++) {
            int offset = atomic_load_explicit(&shm->key_offsets[i], memory_order_acquire);
            if (offset < 0) continue;  /* Empty slot */

            unsigned int len = atomic_load_explicit(&shm->key_lengths[i], memory_order_acquire);
            if (len == 0 || len > 4096) continue;  /* Invalid length */

            int alg = atomic_load_explicit(&shm->key_algorithms[i], memory_order_acquire);

            /* V2 format: [ALG_ID:4][PEM_LEN:4][PEM_DATA] */
            uint32_t alg_id = (uint32_t)alg;
            uint32_t pem_len = (uint32_t)len;

            if (BIO_write(mem_bio, &alg_id, sizeof(alg_id)) == sizeof(alg_id) &&
                BIO_write(mem_bio, &pem_len, sizeof(pem_len)) == sizeof(pem_len) &&
                BIO_write(mem_bio, &shm->pem_storage[offset], (int)len) == (int)len) {
                keys_saved++;
            }
        }

        pthread_mutex_unlock((pthread_mutex_t*)&shm->lock);
    } else if (pool->local_keys) {
        /* Local mode: Convert EVP_PKEY* to PEM */
        pthread_mutex_lock(&pool->local_lock);

        for (int i = 0; i < pool->config.local_pool_size; i++) {
            EVP_PKEY *key = pool->local_keys[i];
            if (!key) continue;

            if (PEM_write_bio_PrivateKey(mem_bio, key, NULL, NULL, 0, NULL, NULL)) {
                keys_saved++;
            }
        }

        pthread_mutex_unlock(&pool->local_lock);
    }

    if (keys_saved == 0) {
        BIO_free(mem_bio);
        LOG_WARN("No keys to save in backup bundle");
        return KEYPOOL_ERR_INVALID;
    }

    /* Get PEM data from BIO */
    char *pem_data = NULL;
    long pem_len = BIO_get_mem_data(mem_bio, &pem_data);
    if (!pem_data || pem_len == 0) {
        BIO_free(mem_bio);
        LOG_ERROR("Failed to get PEM data from BIO");
        return KEYPOOL_ERR_CRYPTO;
    }

    /* Step 2: Gzip compress PEM data in memory */
    size_t gz_buf_size = pem_len + 1024;  /* Extra space for gzip header */
    unsigned char *gz_data = malloc(gz_buf_size);
    if (!gz_data) {
        BIO_free(mem_bio);
        LOG_ERROR("Failed to allocate gzip buffer");
        return KEYPOOL_ERR_NOMEM;
    }

    z_stream stream = {0};
    stream.next_in = (unsigned char*)pem_data;
    stream.avail_in = pem_len;
    stream.next_out = gz_data;
    stream.avail_out = gz_buf_size;

    if (deflateInit2(&stream, 9, Z_DEFLATED, 15+16, 8, Z_DEFAULT_STRATEGY) != Z_OK) {
        free(gz_data);
        BIO_free(mem_bio);
        LOG_ERROR("Failed to initialize gzip compression");
        return KEYPOOL_ERR_CRYPTO;
    }

    if (deflate(&stream, Z_FINISH) != Z_STREAM_END) {
        deflateEnd(&stream);
        free(gz_data);
        BIO_free(mem_bio);
        LOG_ERROR("Failed to compress PEM data");
        return KEYPOOL_ERR_CRYPTO;
    }

    size_t gz_len = stream.total_out;
    deflateEnd(&stream);
    BIO_free(mem_bio);  /* Done with PEM data */

    /* Step 3: Encrypt if enabled */
    unsigned char *final_data = NULL;
    size_t final_len = 0;
    bool encrypted = false;

    if (pool->config.encrypt_backup && pool->config.ca_key_path && pool->config.backup_curve) {
        /* Extract password from CA key */
        char password[128] = {0};
        if (!extract_password_from_ca_key(pool->config.ca_key_path,
                                         pool->config.backup_curve,
                                         password, sizeof(password))) {
            free(gz_data);
            LOG_ERROR("Failed to extract password from CA key");
            return KEYPOOL_ERR_CRYPTO;
        }

        /* Generate random salt and IV */
        unsigned char salt[BACKUP_SALT_SIZE];
        unsigned char iv[BACKUP_IV_SIZE];
        unsigned char tag[BACKUP_TAG_SIZE];

        if (RAND_bytes(salt, BACKUP_SALT_SIZE) != 1) {
            explicit_bzero(password, sizeof(password));
            free(gz_data);
            LOG_ERROR("Failed to generate salt");
            return KEYPOOL_ERR_CRYPTO;
        }

        /* Derive encryption key */
        unsigned char enc_key[BACKUP_KEY_SIZE];
        if (!derive_encryption_key(password, salt, enc_key)) {
            explicit_bzero(password, sizeof(password));
            free(gz_data);
            return KEYPOOL_ERR_CRYPTO;
        }
        explicit_bzero(password, sizeof(password));  /* Clear password */

        /* Encrypt gzip data */
        unsigned char *ciphertext = malloc(gz_len + 32);  /* Extra for GCM */
        size_t ciphertext_len = 0;

        if (!encrypt_backup_data(gz_data, gz_len, enc_key, ciphertext, &ciphertext_len, iv, tag)) {
            explicit_bzero(enc_key, sizeof(enc_key));
            free(ciphertext);
            free(gz_data);
            return KEYPOOL_ERR_CRYPTO;
        }
        explicit_bzero(enc_key, sizeof(enc_key));  /* Clear key */
        free(gz_data);  /* Done with plaintext gzip data */

        /* Build encrypted file format: Header + Salt + IV + Ciphertext + Tag */
        final_len = BACKUP_HEADER_SIZE + BACKUP_SALT_SIZE + BACKUP_IV_SIZE + ciphertext_len + BACKUP_TAG_SIZE;
        final_data = malloc(final_len);
        if (!final_data) {
            free(ciphertext);
            LOG_ERROR("Failed to allocate final buffer");
            return KEYPOOL_ERR_NOMEM;
        }

        size_t offset = 0;

        /* Header - use V2 magic if v2 format (includes algorithm info) */
        memset(final_data, 0, BACKUP_HEADER_SIZE);
        const char *magic = use_v2_format ? BACKUP_HEADER_MAGIC_V2 : BACKUP_HEADER_MAGIC;
        memcpy(final_data, magic, strlen(magic));
        offset += BACKUP_HEADER_SIZE;

        /* Salt */
        memcpy(final_data + offset, salt, BACKUP_SALT_SIZE);
        offset += BACKUP_SALT_SIZE;

        /* IV */
        memcpy(final_data + offset, iv, BACKUP_IV_SIZE);
        offset += BACKUP_IV_SIZE;

        /* Ciphertext */
        memcpy(final_data + offset, ciphertext, ciphertext_len);
        offset += ciphertext_len;

        /* Tag */
        memcpy(final_data + offset, tag, BACKUP_TAG_SIZE);

        free(ciphertext);
        encrypted = true;
    } else {
        /* No encryption - use gzip data as-is */
        final_data = gz_data;
        final_len = gz_len;
    }

    /* Step 4: Write to file (atomic via temp + rename) */
    char temp_path[1024];
    snprintf(temp_path, sizeof(temp_path), "%s.tmp", bundle_path);

    FILE *f = fopen(temp_path, "wb");
    if (!f) {
        free(final_data);
        LOG_ERROR("Failed to create backup file: %s", temp_path);
        return KEYPOOL_ERR_IO;
    }

    if (fwrite(final_data, 1, final_len, f) != final_len) {
        fclose(f);
        unlink(temp_path);
        free(final_data);
        LOG_ERROR("Failed to write backup data");
        return KEYPOOL_ERR_IO;
    }

    fclose(f);
    free(final_data);

    /* Atomic rename */
    if (rename(temp_path, bundle_path) != 0) {
        unlink(temp_path);
        LOG_ERROR("Failed to rename backup bundle: %s", strerror(errno));
        return KEYPOOL_ERR_IO;
    }

    LOG_INFO("Saved %d keys to backup bundle: %s (encrypted=%s)", keys_saved, bundle_path,
             encrypted ? "yes" : "no");
    return KEYPOOL_OK;
}

/* Legacy stub for keygen tool compatibility */
keypool_error_t keypool_save_bundle(const keypool_t *pool ,
                                    const char *bundle_path ) {
    return save_backup_bundle((keypool_t*)pool, bundle_path);
}

/* Load prime pools from directory (for fast RSA generation) */
keypool_error_t keypool_load_prime_pools(keypool_t *pool, const char *prime_dir) {
    if (!pool || !prime_dir) {
        return KEYPOOL_ERR_INVALID;
    }

    /* Store directory path */
    if (pool->prime_pool_dir) {
        free(pool->prime_pool_dir);
    }
    pool->prime_pool_dir = strdup(prime_dir);

    /* Load all available prime pools */
    load_all_prime_pools(pool, prime_dir);

    return KEYPOOL_OK;
}

/* Legacy single-bundle loader (deprecated - use keypool_load_bundles_from_dir) */
keypool_error_t keypool_load_bundle(keypool_t *pool, const char *bundle_path) {
    if (load_single_bundle(pool, bundle_path) > 0) {
        return KEYPOOL_OK;
    }
    return KEYPOOL_ERR_INVALID;
}
