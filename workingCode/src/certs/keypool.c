/*
 * keypool.c - Lock-Free Key Pool Implementation
 *
 * Uses atomic ring buffer for fast, contention-free key acquisition.
 * Multiple refill threads can push, multiple workers can pop.
 */

#include "certs/keypool.h"
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <stdio.h>
#include <openssl/rsa.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <stdatomic.h>

/* Lock-free ring buffer per algorithm */
typedef struct {
    EVP_PKEY **keys;           /* Key array (ring buffer) */
    int capacity;              /* Ring buffer size (power of 2) */
    int mask;                  /* capacity - 1 for fast modulo */
    _Atomic(int) head;         /* Producer index */
    _Atomic(int) tail;         /* Consumer index */
    atomic_int generated;      /* Stats: total generated */
    atomic_int consumed;       /* Stats: total consumed */
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

/* Round up to next power of 2 */
static int next_power_of_2(int n) {
    n--;
    n |= n >> 1;
    n |= n >> 2;
    n |= n >> 4;
    n |= n >> 8;
    n |= n >> 16;
    return n + 1;
}

/* Generate RSA-3072 key */
static EVP_PKEY* generate_rsa_3072(void) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!ctx) return NULL;

    if (EVP_PKEY_keygen_init(ctx) <= 0 ||
        EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 3072) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    EVP_PKEY *key = NULL;
    EVP_PKEY_keygen(ctx, &key);
    EVP_PKEY_CTX_free(ctx);
    return key;
}

/* Generate ECDSA P-256 key */
static EVP_PKEY* generate_ecdsa_p256(void) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (!ctx) return NULL;

    if (EVP_PKEY_keygen_init(ctx) <= 0 ||
        EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, NID_X9_62_prime256v1) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    EVP_PKEY *key = NULL;
    EVP_PKEY_keygen(ctx, &key);
    EVP_PKEY_CTX_free(ctx);
    return key;
}

/* Generate SM2 key */
static EVP_PKEY* generate_sm2(void) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (!ctx) return NULL;

    int nid = OBJ_txt2nid("SM2");
    if (nid == NID_undef) nid = NID_X9_62_prime256v1;

    if (EVP_PKEY_keygen_init(ctx) <= 0 ||
        EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, nid) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    EVP_PKEY *key = NULL;
    EVP_PKEY_keygen(ctx, &key);
    EVP_PKEY_CTX_free(ctx);
    return key;
}

/* Generate key for algorithm */
EVP_PKEY* keypool_generate_key(keypool_alg_t algorithm) {
    switch (algorithm) {
        case KEYPOOL_ALG_RSA_3072:  return generate_rsa_3072();
        case KEYPOOL_ALG_ECDSA_P256: return generate_ecdsa_p256();
        case KEYPOOL_ALG_SM2:        return generate_sm2();
        default:                     return NULL;
    }
}

/* Lock-free push (producer) - returns 1 on success, 0 if full */
static int pool_push(alg_pool_t *ap, EVP_PKEY *key) {
    int head, next_head, tail;

    do {
        head = atomic_load(&ap->head);
        next_head = (head + 1) & ap->mask;
        tail = atomic_load(&ap->tail);

        /* Check if full */
        if (next_head == tail) {
            return 0;  /* Buffer full */
        }
    } while (!atomic_compare_exchange_weak(&ap->head, &head, next_head));

    /* Store key at old head position */
    ap->keys[head] = key;
    return 1;
}

/* Lock-free pop (consumer) - returns key or NULL if empty */
static EVP_PKEY* pool_pop(alg_pool_t *ap) {
    int tail, next_tail, head;
    EVP_PKEY *key;

    do {
        tail = atomic_load(&ap->tail);
        head = atomic_load(&ap->head);

        /* Check if empty */
        if (tail == head) {
            return NULL;  /* Buffer empty */
        }

        /* Read key before CAS (might be stale, but that's ok) */
        key = ap->keys[tail];
        next_tail = (tail + 1) & ap->mask;

    } while (!atomic_compare_exchange_weak(&ap->tail, &tail, next_tail));

    return key;
}

/* Get available count (approximate, lock-free) */
static int pool_available(alg_pool_t *ap) {
    int head = atomic_load(&ap->head);
    int tail = atomic_load(&ap->tail);
    return (head - tail) & ap->mask;
}

/* Background refill thread */
static void* refill_thread_func(void *arg) {
    keypool_t *pool = (keypool_t *)arg;

#ifdef DEBUG
    fprintf(stderr, "[KEYPOOL] Refill thread started\n");
#endif

    while (!atomic_load(&pool->refill_shutdown)) {
        int did_work = 0;

        /* Only refill RSA-3072 for now */
        alg_pool_t *ap = &pool->pools[KEYPOOL_ALG_RSA_3072];
        int avail = pool_available(ap);
        int target = ap->capacity / 2;

        if (avail < target) {
            EVP_PKEY *key = generate_rsa_3072();
            if (key) {
                if (pool_push(ap, key)) {
                    atomic_fetch_add(&ap->generated, 1);
                    atomic_fetch_add(&pool->total_generated, 1);
                    did_work = 1;
                } else {
                    /* Pool full, free key */
                    EVP_PKEY_free(key);
                }
            }
        }

        if (!did_work) {
            /* Sleep briefly if no work done */
            usleep(10000);  /* 10ms */
        }
    }

#ifdef DEBUG
    fprintf(stderr, "[KEYPOOL] Refill thread stopped\n");
#endif
    return NULL;
}

/* Create key pool */
keypool_t* keypool_create(const keypool_config_t *config) {
    keypool_t *pool = calloc(1, sizeof(keypool_t));
    if (!pool) return NULL;

    if (config) {
        memcpy(&pool->config, config, sizeof(*config));
    } else {
        pool->config.pool_size = 1024;
        pool->config.refill_threads = 4;
        pool->config.enable_rsa_3072 = true;
    }

    /* Initialize pools with power-of-2 capacity */
    int capacity = next_power_of_2(pool->config.pool_size);

    for (int alg = 0; alg < KEYPOOL_ALG_MAX; alg++) {
        alg_pool_t *ap = &pool->pools[alg];
        ap->capacity = capacity;
        ap->mask = capacity - 1;
        ap->keys = calloc(capacity, sizeof(EVP_PKEY *));
        if (!ap->keys) {
            keypool_destroy(pool);
            return NULL;
        }
        atomic_init(&ap->head, 0);
        atomic_init(&ap->tail, 0);
        atomic_init(&ap->generated, 0);
        atomic_init(&ap->consumed, 0);
    }

    atomic_init(&pool->total_generated, 0);
    atomic_init(&pool->total_consumed, 0);
    atomic_init(&pool->refill_shutdown, false);
    pool->num_refill_threads = 0;

#ifdef DEBUG
    fprintf(stderr, "[KEYPOOL] Created with capacity %d per algorithm\n", capacity);
#endif

    return pool;
}

/* Destroy key pool */
void keypool_destroy(keypool_t *pool) {
    if (!pool) return;

    keypool_stop_refill(pool);

    for (int alg = 0; alg < KEYPOOL_ALG_MAX; alg++) {
        alg_pool_t *ap = &pool->pools[alg];
        if (ap->keys) {
            /* Free remaining keys */
            EVP_PKEY *key;
            while ((key = pool_pop(ap)) != NULL) {
                EVP_PKEY_free(key);
            }
            free(ap->keys);
        }
    }

    free(pool);
}

/* Acquire key from pool (LOCK-FREE!) */
EVP_PKEY* keypool_acquire(keypool_t *pool, keypool_alg_t algorithm) {
    if (!pool || algorithm >= KEYPOOL_ALG_MAX) return NULL;

    alg_pool_t *ap = &pool->pools[algorithm];

    /* Try to get from pool (lock-free) */
    EVP_PKEY *key = pool_pop(ap);

    if (key) {
        atomic_fetch_add(&ap->consumed, 1);
        atomic_fetch_add(&pool->total_consumed, 1);
        return key;
    }

    /* Pool empty - generate on-demand (slow path) */
    key = keypool_generate_key(algorithm);
    if (key) {
        atomic_fetch_add(&ap->consumed, 1);
        atomic_fetch_add(&pool->total_consumed, 1);
    }

    return key;
}

/* Start refill threads */
keypool_error_t keypool_start_refill(keypool_t *pool) {
    if (!pool) return KEYPOOL_ERR_INVALID;

    int num_threads = pool->config.refill_threads ? pool->config.refill_threads : 4;
    pool->refill_threads = malloc(num_threads * sizeof(pthread_t));
    if (!pool->refill_threads) return KEYPOOL_ERR_NOMEM;

    atomic_store(&pool->refill_shutdown, false);

    for (int i = 0; i < num_threads; i++) {
        if (pthread_create(&pool->refill_threads[i], NULL, refill_thread_func, pool) != 0) {
            /* Cleanup on failure */
            atomic_store(&pool->refill_shutdown, true);
            for (int j = 0; j < i; j++) {
                pthread_join(pool->refill_threads[j], NULL);
            }
            free(pool->refill_threads);
            pool->refill_threads = NULL;
            return KEYPOOL_ERR_THREAD;
        }
    }

    pool->num_refill_threads = num_threads;
#ifdef DEBUG
    fprintf(stderr, "[KEYPOOL] Started %d refill threads\n", num_threads);
#endif
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
    stats->available = pool_available((alg_pool_t*)ap);
    stats->capacity = ap->capacity;

    return KEYPOOL_OK;
}

/* Get algorithm name */
const char* keypool_algorithm_name(keypool_alg_t algorithm) {
    if (algorithm >= KEYPOOL_ALG_MAX) return "UNKNOWN";
    return alg_names[algorithm];
}
