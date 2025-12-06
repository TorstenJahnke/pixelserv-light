/*
 * keypool.c - Simplified Key Pool Implementation
 * Local pool per worker for fast key acquisition
 */

#include "../include/keypool.h"
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <openssl/rsa.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <stdatomic.h>

/* Per-algorithm pool */
typedef struct {
    EVP_PKEY **keys;           /* Key array */
    int capacity;              /* Total capacity */
    atomic_int available;      /* Available keys */
    atomic_int consumed;       /* Total consumed */
    atomic_int generated;      /* Total generated */
    pthread_mutex_t lock;      /* Protect key array */
    int refill_idx;            /* Next index to refill */
} alg_pool_t;

/* Key pool structure */
struct keypool {
    keypool_config_t config;
    alg_pool_t pools[KEYPOOL_ALG_MAX];

    /* Background refill */
    pthread_t *refill_threads;
    int num_refill_threads;
    atomic_bool refill_shutdown;

    /* Statistics */
    atomic_long total_generated;
    atomic_long total_consumed;
};

/* Algorithm names */
static const char* alg_names[] = {
    [KEYPOOL_ALG_RSA_3072] = "RSA-3072",
    [KEYPOOL_ALG_ECDSA_P256] = "ECDSA-P256",
    [KEYPOOL_ALG_SM2] = "SM2"
};

/* Generate RSA-3072 key */
static EVP_PKEY* generate_rsa_3072(void) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!ctx) return NULL;

    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 3072) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    EVP_PKEY *key = NULL;
    if (EVP_PKEY_keygen(ctx, &key) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    EVP_PKEY_CTX_free(ctx);
    return key;
}

/* Generate ECDSA P-256 key */
static EVP_PKEY* generate_ecdsa_p256(void) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (!ctx) return NULL;

    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, NID_X9_62_prime256v1) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    EVP_PKEY *key = NULL;
    if (EVP_PKEY_keygen(ctx, &key) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    EVP_PKEY_CTX_free(ctx);
    return key;
}

/* Generate SM2 key */
static EVP_PKEY* generate_sm2(void) {
    /* SM2 is similar to ECDSA but with Chinese standard curve */
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (!ctx) return NULL;

    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    /* SM2 uses sm2p256v1 curve (if available) */
    int nid = OBJ_txt2nid("SM2");
    if (nid == NID_undef) {
        /* Fallback to P-256 if SM2 not available */
        nid = NID_X9_62_prime256v1;
    }

    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, nid) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    EVP_PKEY *key = NULL;
    if (EVP_PKEY_keygen(ctx, &key) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    EVP_PKEY_CTX_free(ctx);
    return key;
}

/* Generate key for algorithm */
EVP_PKEY* keypool_generate_key(keypool_alg_t algorithm) {
    switch (algorithm) {
        case KEYPOOL_ALG_RSA_3072:
            return generate_rsa_3072();
        case KEYPOOL_ALG_ECDSA_P256:
            return generate_ecdsa_p256();
        case KEYPOOL_ALG_SM2:
            return generate_sm2();
        default:
            return NULL;
    }
}

/* Background refill thread function */
static void* refill_thread_func(void *arg) {
    keypool_t *pool = (keypool_t *)arg;

    while (!atomic_load(&pool->refill_shutdown)) {
        /* Refill all algorithms in round-robin */
        for (int alg = 0; alg < KEYPOOL_ALG_MAX; alg++) {
            alg_pool_t *ap = &pool->pools[alg];

            /* Check if refill is needed */
            int avail = atomic_load(&ap->available);
            int target = ap->capacity / 2;  /* Keep at least 50% filled */

            if (avail < target) {
                pthread_mutex_lock(&ap->lock);

                /* Double-check after lock */
                avail = atomic_load(&ap->available);
                while (avail < target && ap->refill_idx < ap->capacity) {
                    EVP_PKEY *key = keypool_generate_key(alg);
                    if (key) {
                        ap->keys[ap->refill_idx++] = key;
                        atomic_fetch_add(&ap->available, 1);
                        atomic_fetch_add(&ap->generated, 1);
                        atomic_fetch_add(&pool->total_generated, 1);
                    } else {
                        break;  /* Generation failed, try again later */
                    }
                    avail = atomic_load(&ap->available);
                }

                pthread_mutex_unlock(&ap->lock);
            }
        }

        /* Sleep briefly before next refill cycle */
        sleep(1);
    }

    return NULL;
}

/* Create key pool */
keypool_t* keypool_create(const keypool_config_t *config) {
    keypool_t *pool = malloc(sizeof(keypool_t));
    if (!pool) return NULL;

    /* Set configuration */
    if (config) {
        memcpy(&pool->config, config, sizeof(*config));
    } else {
        /* Defaults */
        pool->config.pool_size = 7000;
        pool->config.refill_threads = 2;
        pool->config.enable_rsa_3072 = true;
        pool->config.enable_ecdsa_p256 = true;
        pool->config.enable_sm2 = true;
    }

    /* Initialize pools */
    for (int alg = 0; alg < KEYPOOL_ALG_MAX; alg++) {
        alg_pool_t *ap = &pool->pools[alg];
        ap->capacity = pool->config.pool_size;
        ap->keys = malloc(ap->capacity * sizeof(EVP_PKEY *));
        if (!ap->keys) {
            keypool_destroy(pool);
            return NULL;
        }
        memset(ap->keys, 0, ap->capacity * sizeof(EVP_PKEY *));
        pthread_mutex_init(&ap->lock, NULL);
        atomic_init(&ap->available, 0);
        atomic_init(&ap->consumed, 0);
        atomic_init(&ap->generated, 0);
        ap->refill_idx = 0;
    }

    atomic_init(&pool->total_generated, 0);
    atomic_init(&pool->total_consumed, 0);
    atomic_init(&pool->refill_shutdown, false);
    pool->num_refill_threads = 0;

    return pool;
}

/* Destroy key pool */
void keypool_destroy(keypool_t *pool) {
    if (!pool) return;

    /* Stop refill threads */
    keypool_stop_refill(pool);

    /* Free keys */
    for (int alg = 0; alg < KEYPOOL_ALG_MAX; alg++) {
        alg_pool_t *ap = &pool->pools[alg];
        if (ap->keys) {
            for (int i = 0; i < ap->capacity; i++) {
                if (ap->keys[i]) {
                    EVP_PKEY_free(ap->keys[i]);
                }
            }
            free(ap->keys);
        }
        pthread_mutex_destroy(&ap->lock);
    }

    free(pool);
}

/* Acquire key from pool */
EVP_PKEY* keypool_acquire(keypool_t *pool, keypool_alg_t algorithm) {
    if (!pool || algorithm >= KEYPOOL_ALG_MAX) return NULL;

    alg_pool_t *ap = &pool->pools[algorithm];

    pthread_mutex_lock(&ap->lock);

    EVP_PKEY *key = NULL;

    /* Try to get key from pool */
    for (int i = ap->capacity - 1; i >= 0; i--) {
        if (ap->keys[i]) {
            key = ap->keys[i];
            ap->keys[i] = NULL;
            atomic_fetch_sub(&ap->available, 1);
            atomic_fetch_add(&ap->consumed, 1);
            atomic_fetch_add(&pool->total_consumed, 1);
            break;
        }
    }

    pthread_mutex_unlock(&ap->lock);

    /* If pool empty, generate on-demand */
    if (!key) {
        key = keypool_generate_key(algorithm);
        if (key) {
            atomic_fetch_add(&ap->consumed, 1);
            atomic_fetch_add(&pool->total_consumed, 1);
        }
    }

    return key;
}

/* Start refill threads */
keypool_error_t keypool_start_refill(keypool_t *pool) {
    if (!pool) return KEYPOOL_ERR_INVALID;

    int num_threads = pool->config.refill_threads ? pool->config.refill_threads : 2;
    pool->refill_threads = malloc(num_threads * sizeof(pthread_t));
    if (!pool->refill_threads) return KEYPOOL_ERR_NOMEM;

    atomic_store(&pool->refill_shutdown, false);

    for (int i = 0; i < num_threads; i++) {
        if (pthread_create(&pool->refill_threads[i], NULL,
                          refill_thread_func, pool) != 0) {
            free(pool->refill_threads);
            return KEYPOOL_ERR_THREAD;
        }
    }

    pool->num_refill_threads = num_threads;
    return KEYPOOL_OK;
}

/* Stop refill threads */
void keypool_stop_refill(keypool_t *pool) {
    if (!pool || pool->num_refill_threads == 0) return;

    atomic_store(&pool->refill_shutdown, true);

    for (int i = 0; i < pool->num_refill_threads; i++) {
        pthread_join(pool->refill_threads[i], NULL);
    }

    free(pool->refill_threads);
    pool->refill_threads = NULL;
    pool->num_refill_threads = 0;
}

/* Get statistics */
keypool_error_t keypool_get_stats(const keypool_t *pool,
                                  keypool_alg_t algorithm,
                                  keypool_stats_t *stats) {
    if (!pool || !stats || algorithm >= KEYPOOL_ALG_MAX) {
        return KEYPOOL_ERR_INVALID;
    }

    const alg_pool_t *ap = &pool->pools[algorithm];
    stats->generated = atomic_load(&ap->generated);
    stats->consumed = atomic_load(&ap->consumed);
    stats->available = atomic_load(&ap->available);
    stats->capacity = ap->capacity;

    return KEYPOOL_OK;
}

/* Get algorithm name */
const char* keypool_algorithm_name(keypool_alg_t algorithm) {
    if (algorithm >= KEYPOOL_ALG_MAX) return "UNKNOWN";
    return alg_names[algorithm];
}
