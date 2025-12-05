/* _GNU_SOURCE is defined by Makefile on Linux */
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <netdb.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/ec.h>
#include <openssl/x509v3.h>

#include "certs.h"
#include "logger.h"
#include "util.h"

#if defined(__GLIBC__) && !defined(__UCLIBC__)
#  include <malloc.h>
#endif

/* OpenSSL >= 1.1.0 handles threading internally - no locks needed.
 * Legacy OpenSSL < 1.1.0 requires explicit locking callbacks (blocking).
 * For modern OpenSSL, this codebase is 100% lock-free. */
#if OPENSSL_VERSION_NUMBER < 0x10100000L
static pthread_mutex_t *legacy_openssl_locks;
#endif

static SSL_CTX *g_sslctx;

/* =============================================================================
 * LOCK-FREE HASH TABLE FOR SSL CONTEXT CACHE
 * - FNV-1a hash for strings
 * - Open addressing with linear probing
 * - Atomic CAS for lock-free parallel inserts
 * - Readers and writers can work concurrently on different buckets
 * ============================================================================= */

/* Hash entry states */
#define HASH_EMPTY     0   /* Slot available */
#define HASH_INSERTING 1   /* Slot being filled (CAS in progress) */
#define HASH_OCCUPIED  2   /* Slot contains valid data */
#define HASH_DELETED   3   /* Tombstone - was occupied, now deleted */

/* Hash table entry - each entry is independently atomic */
typedef struct {
    _Atomic uint32_t state;      /* EMPTY, INSERTING, OCCUPIED, DELETED */
    char *cert_name;             /* Immutable once state becomes OCCUPIED */
    _Atomic(SSL_CTX *) sslctx;   /* Can be atomically swapped for updates */
    _Atomic uint32_t last_use;   /* Seconds since process start */
    _Atomic uint32_t reuse_count;
} sslctx_hash_entry_t;

static sslctx_hash_entry_t *sslctx_hash_tbl;
static int sslctx_hash_size;        /* Total capacity (power of 2) */
static _Atomic int sslctx_hash_count;  /* Current number of OCCUPIED entries */
static _Atomic int sslctx_tbl_cnt_hit, sslctx_tbl_cnt_miss, sslctx_tbl_cnt_purge;
static _Atomic unsigned int sslctx_tbl_last_flush;

/* FNV-1a hash function - fast and good distribution for strings */
static inline uint32_t fnv1a_hash(const char *str) {
    uint32_t hash = 2166136261u;  /* FNV offset basis */
    while (*str) {
        hash ^= (uint8_t)*str++;
        hash *= 16777619u;        /* FNV prime */
    }
    return hash;
}

/* Lock-free Treiber stack for connection storage pool
 * Uses atomic compare-and-swap for push/pop operations */
typedef struct conn_stor_node {
    conn_tlstor_struct *data;
    struct conn_stor_node *next;
} conn_stor_node_t;

static _Atomic(conn_stor_node_t *) conn_stor_head;
static _Atomic int conn_stor_count;
static int conn_stor_max;

/* Backward-compatible accessors */
inline int sslctx_tbl_get_cnt_total() { return atomic_load(&sslctx_hash_count); }
inline int sslctx_tbl_get_cnt_hit() { return atomic_load(&sslctx_tbl_cnt_hit); }
inline int sslctx_tbl_get_cnt_miss() { return atomic_load(&sslctx_tbl_cnt_miss); }
inline int sslctx_tbl_get_cnt_purge() { return atomic_load(&sslctx_tbl_cnt_purge); }
inline int sslctx_tbl_get_sess_cnt() { return SSL_CTX_sess_number(g_sslctx); }
inline int sslctx_tbl_get_sess_hit() { return SSL_CTX_sess_hits(g_sslctx); }
inline int sslctx_tbl_get_sess_miss() { return SSL_CTX_sess_misses(g_sslctx); }
inline int sslctx_tbl_get_sess_purge() { return SSL_CTX_sess_cache_full(g_sslctx); }

static SSL_CTX* create_child_sslctx(const char* full_pem_path, const STACK_OF(X509_INFO) *cachain);

/* Forward declarations for certificate index management */
static int cert_index_init(const char *pem_dir);
static int cert_index_add(const char *pem_dir, const char *domain, time_t created,
                          int validity_days, int key_type);
static int cert_index_mem_lookup(const char *domain);
static void cert_index_mem_insert(const char *domain, time_t expires);

/* =============================================================================
 * LOCK-FREE CONNECTION STORAGE (Treiber Stack)
 * Uses atomic compare-and-swap for thread-safe push/pop without blocking
 * ============================================================================= */

void conn_stor_init(int slots) {
    if (slots < 0) {
        log_msg(LGG_ERR, "%s invalid slots %d", __FUNCTION__, slots);
        return;
    }
    atomic_store(&conn_stor_head, NULL);
    atomic_store(&conn_stor_count, 0);
    conn_stor_max = slots;
}

void conn_stor_flush() {
    int count = atomic_load_explicit(&conn_stor_count, memory_order_relaxed);
    if (conn_stor_max < 0 || count <= conn_stor_max / 2)
        return;

    int threshold = conn_stor_max / 2;

    /* Pop and free nodes until we're at threshold - lock-free */
    while (atomic_load_explicit(&conn_stor_count, memory_order_relaxed) > threshold) {
        conn_stor_node_t *old_head = atomic_load_explicit(&conn_stor_head, memory_order_acquire);
        if (old_head == NULL)
            break;

        if (atomic_compare_exchange_weak_explicit(&conn_stor_head, &old_head, old_head->next,
                                                   memory_order_release, memory_order_relaxed)) {
            atomic_fetch_sub_explicit(&conn_stor_count, 1, memory_order_relaxed);
            if (old_head->data)
                free(old_head->data);
            free(old_head);
        }
        /* If CAS failed, another thread modified head - retry */
    }
}

void conn_stor_relinq(conn_tlstor_struct *p) {
    if (atomic_load_explicit(&conn_stor_count, memory_order_relaxed) >= conn_stor_max) {
        /* Pool full - just free instead of blocking */
        free(p);
        return;
    }

    conn_stor_node_t *node = malloc(sizeof(conn_stor_node_t));
    if (!node) {
        free(p);
        return;
    }
    node->data = p;

    /* Lock-free push using CAS loop */
    conn_stor_node_t *old_head;
    do {
        old_head = atomic_load_explicit(&conn_stor_head, memory_order_acquire);
        node->next = old_head;
    } while (!atomic_compare_exchange_weak_explicit(&conn_stor_head, &old_head, node,
                                                     memory_order_release, memory_order_relaxed));
    atomic_fetch_add_explicit(&conn_stor_count, 1, memory_order_relaxed);
}

conn_tlstor_struct* conn_stor_acquire() {
    /* Lock-free pop using CAS loop */
    conn_stor_node_t *old_head;
    do {
        old_head = atomic_load_explicit(&conn_stor_head, memory_order_acquire);
        if (old_head == NULL) {
            /* Stack empty - allocate new */
            conn_tlstor_struct *ret = malloc(sizeof(conn_tlstor_struct));
            if (ret != NULL) {
                memset(ret, 0, sizeof(conn_tlstor_struct));
                ret->tlsext_cb_arg = &ret->v;
            }
            return ret;
        }
    } while (!atomic_compare_exchange_weak_explicit(&conn_stor_head, &old_head, old_head->next,
                                                     memory_order_release, memory_order_relaxed));

    atomic_fetch_sub_explicit(&conn_stor_count, 1, memory_order_relaxed);
    conn_tlstor_struct *data = old_head->data;
    free(old_head);
    return data;
}

/* =============================================================================
 * LOCK-FREE SSL CONTEXT HASH TABLE
 * - 100% lock-free: readers AND writers work in parallel
 * - Atomic CAS for inserts on same bucket (one wins, others retry)
 * - Open addressing with linear probing
 * - Load factor ~75% for good performance
 * ============================================================================= */

/* Round up to next power of 2 for efficient modulo via bitmask */
static inline int next_power_of_2(int n) {
    n--;
    n |= n >> 1;
    n |= n >> 2;
    n |= n >> 4;
    n |= n >> 8;
    n |= n >> 16;
    return n + 1;
}

void sslctx_tbl_init(int tbl_size)
{
    if (tbl_size <= 0)
        return;

    /* Use 200% of requested size for low load factor (better performance at scale)
     * For 100K entries, this creates 256K slots (~39% load factor)
     * Lower load factor = fewer collisions = faster lookups */
    int actual_size = next_power_of_2(tbl_size * 2);
    if (actual_size < 1024) actual_size = 1024;  /* Minimum 1K slots */

    sslctx_hash_tbl = calloc(actual_size, sizeof(sslctx_hash_entry_t));
    if (!sslctx_hash_tbl) {
        sslctx_hash_size = 0;
        log_msg(LGG_ERR, "Failed to allocate sslctx hash table of size %d", actual_size);
        return;
    }

    sslctx_hash_size = actual_size;
    atomic_store(&sslctx_hash_count, 0);
    atomic_store(&sslctx_tbl_cnt_hit, 0);
    atomic_store(&sslctx_tbl_cnt_miss, 0);
    atomic_store(&sslctx_tbl_cnt_purge, 0);
    atomic_store(&sslctx_tbl_last_flush, 0);

    log_msg(LGG_NOTICE, "SSL context hash table initialized: %d slots (requested %d)",
            actual_size, tbl_size);
}

void sslctx_tbl_cleanup()
{
    if (!sslctx_hash_tbl)
        return;

    /* Cleanup at shutdown - no concurrent access */
    for (int i = 0; i < sslctx_hash_size; i++) {
        uint32_t state = atomic_load(&sslctx_hash_tbl[i].state);
        if (state == HASH_OCCUPIED || state == HASH_DELETED) {
            free(sslctx_hash_tbl[i].cert_name);
            SSL_CTX *ctx = atomic_load(&sslctx_hash_tbl[i].sslctx);
            if (ctx) SSL_CTX_free(ctx);
        }
    }
    free(sslctx_hash_tbl);
    sslctx_hash_tbl = NULL;
}

/* Lock-free lookup - returns SSL_CTX* or NULL
 * Multiple readers can execute concurrently */
static SSL_CTX* sslctx_hash_lookup(const char *cert_name) {
    if (!sslctx_hash_tbl || !cert_name)
        return NULL;

    uint32_t hash = fnv1a_hash(cert_name);
    uint32_t mask = sslctx_hash_size - 1;  /* Power of 2, so mask works */
    uint32_t idx = hash & mask;

    /* Linear probing - check up to table size slots */
    for (int probe = 0; probe < sslctx_hash_size; probe++) {
        uint32_t state = atomic_load_explicit(&sslctx_hash_tbl[idx].state, memory_order_acquire);

        if (state == HASH_EMPTY) {
            /* Empty slot - key doesn't exist */
            return NULL;
        }

        if (state == HASH_OCCUPIED) {
            /* Check if this is our key */
            if (strcmp(sslctx_hash_tbl[idx].cert_name, cert_name) == 0) {
                /* Found it! Update stats atomically */
                atomic_fetch_add_explicit(&sslctx_tbl_cnt_hit, 1, memory_order_relaxed);
                atomic_fetch_add_explicit(&sslctx_hash_tbl[idx].reuse_count, 1, memory_order_relaxed);
                atomic_store_explicit(&sslctx_hash_tbl[idx].last_use, process_uptime(), memory_order_relaxed);
                return atomic_load_explicit(&sslctx_hash_tbl[idx].sslctx, memory_order_acquire);
            }
        }
        /* DELETED or different key - continue probing */
        idx = (idx + 1) & mask;
    }

    return NULL;  /* Table full, key not found */
}

/* Lock-free insert - multiple writers can work in parallel on different buckets
 * Returns: 0 = success, 1 = already exists (updated), -1 = table full */
static int sslctx_hash_insert(const char *cert_name, SSL_CTX *sslctx) {
    if (!sslctx_hash_tbl || !cert_name || !sslctx)
        return -1;

    /* Check load factor - warn at 50% to give time for operator action */
    int count = atomic_load(&sslctx_hash_count);
    if (count >= sslctx_hash_size / 2) {
        static _Atomic int warned = 0;
        if (!atomic_exchange(&warned, 1)) {
            log_msg(LGG_WARNING, "SSL context hash table at %d%% capacity (%d/%d) - consider increasing -c",
                    (count * 100) / sslctx_hash_size, count, sslctx_hash_size);
        }
    }

    uint32_t hash = fnv1a_hash(cert_name);
    uint32_t mask = sslctx_hash_size - 1;
    uint32_t idx = hash & mask;
    int first_deleted = -1;  /* Track first tombstone for reuse */

    /* Linear probing */
    for (int probe = 0; probe < sslctx_hash_size; probe++) {
        uint32_t state = atomic_load_explicit(&sslctx_hash_tbl[idx].state, memory_order_acquire);

        if (state == HASH_EMPTY) {
            /* Try to claim this slot with CAS */
            uint32_t expected = HASH_EMPTY;
            if (atomic_compare_exchange_strong_explicit(&sslctx_hash_tbl[idx].state,
                    &expected, HASH_INSERTING, memory_order_acq_rel, memory_order_acquire)) {
                /* We own this slot - fill it */
                sslctx_hash_tbl[idx].cert_name = strdup(cert_name);
                if (!sslctx_hash_tbl[idx].cert_name) {
                    atomic_store(&sslctx_hash_tbl[idx].state, HASH_EMPTY);
                    return -1;
                }
                atomic_store(&sslctx_hash_tbl[idx].sslctx, sslctx);
                atomic_store(&sslctx_hash_tbl[idx].last_use, process_uptime());
                atomic_store(&sslctx_hash_tbl[idx].reuse_count, 0);

                /* Publish - make visible to readers */
                atomic_store_explicit(&sslctx_hash_tbl[idx].state, HASH_OCCUPIED, memory_order_release);
                atomic_fetch_add(&sslctx_hash_count, 1);
                atomic_fetch_add(&sslctx_tbl_cnt_miss, 1);
                return 0;
            }
            /* CAS failed - another thread claimed it, re-read state and continue */
            state = atomic_load_explicit(&sslctx_hash_tbl[idx].state, memory_order_acquire);
        }

        if (state == HASH_OCCUPIED) {
            /* Check if already exists */
            if (strcmp(sslctx_hash_tbl[idx].cert_name, cert_name) == 0) {
                /* Already cached - update SSL_CTX atomically (for cert refresh) */
                SSL_CTX *old = atomic_exchange(&sslctx_hash_tbl[idx].sslctx, sslctx);
                atomic_store(&sslctx_hash_tbl[idx].last_use, process_uptime());
                atomic_fetch_add(&sslctx_hash_tbl[idx].reuse_count, 1);
                if (old && old != sslctx) SSL_CTX_free(old);
                return 1;  /* Updated existing */
            }
        }

        if (state == HASH_DELETED && first_deleted < 0) {
            first_deleted = idx;  /* Remember for potential reuse */
        }

        idx = (idx + 1) & mask;
    }

    /* Table full - try to reuse tombstone if found */
    if (first_deleted >= 0) {
        idx = first_deleted;
        uint32_t expected = HASH_DELETED;
        if (atomic_compare_exchange_strong_explicit(&sslctx_hash_tbl[idx].state,
                &expected, HASH_INSERTING, memory_order_acq_rel, memory_order_acquire)) {
            /* Reusing deleted slot */
            free(sslctx_hash_tbl[idx].cert_name);
            sslctx_hash_tbl[idx].cert_name = strdup(cert_name);
            if (!sslctx_hash_tbl[idx].cert_name) {
                atomic_store(&sslctx_hash_tbl[idx].state, HASH_DELETED);
                return -1;
            }
            SSL_CTX *old = atomic_exchange(&sslctx_hash_tbl[idx].sslctx, sslctx);
            if (old) SSL_CTX_free(old);
            atomic_store(&sslctx_hash_tbl[idx].last_use, process_uptime());
            atomic_store(&sslctx_hash_tbl[idx].reuse_count, 0);
            atomic_store_explicit(&sslctx_hash_tbl[idx].state, HASH_OCCUPIED, memory_order_release);
            atomic_fetch_add(&sslctx_tbl_cnt_miss, 1);
            atomic_fetch_add(&sslctx_tbl_cnt_purge, 1);
            return 0;
        }
    }

    log_msg(LGG_ERR, "SSL context hash table full - cannot insert %s", cert_name);
    return -1;
}

/* Lock-free delete (marks as tombstone) */
static int sslctx_hash_delete(const char *cert_name) {
    if (!sslctx_hash_tbl || !cert_name)
        return -1;

    uint32_t hash = fnv1a_hash(cert_name);
    uint32_t mask = sslctx_hash_size - 1;
    uint32_t idx = hash & mask;

    for (int probe = 0; probe < sslctx_hash_size; probe++) {
        uint32_t state = atomic_load_explicit(&sslctx_hash_tbl[idx].state, memory_order_acquire);

        if (state == HASH_EMPTY)
            return -1;  /* Not found */

        if (state == HASH_OCCUPIED && strcmp(sslctx_hash_tbl[idx].cert_name, cert_name) == 0) {
            /* Found - mark as deleted (tombstone) */
            uint32_t expected = HASH_OCCUPIED;
            if (atomic_compare_exchange_strong(&sslctx_hash_tbl[idx].state, &expected, HASH_DELETED)) {
                SSL_CTX *old = atomic_exchange(&sslctx_hash_tbl[idx].sslctx, NULL);
                if (old) SSL_CTX_free(old);
                atomic_fetch_sub(&sslctx_hash_count, 1);
                atomic_fetch_add(&sslctx_tbl_cnt_purge, 1);
                return 0;
            }
            /* CAS failed - another thread deleted it */
            return -1;
        }

        idx = (idx + 1) & mask;
    }

    return -1;  /* Not found */
}

/* Helper struct for sorting during save */
typedef struct {
    char *cert_name;
    int reuse_count;
} save_entry_t;

static int cmp_save_entry(const void *a, const void *b) {
    return ((save_entry_t*)b)->reuse_count - ((save_entry_t*)a)->reuse_count;
}

/* NOTE: Called during single-threaded startup only */
void sslctx_tbl_load(const char* pem_dir, const STACK_OF(X509_INFO) *cachain)
{
    FILE *fp;
    char *fname = NULL, *line = NULL;
    int loaded = 0;

    if ((line = malloc(PIXELSERV_MAX_PATH)) == NULL || (fname = malloc(PIXELSERV_MAX_PATH)) == NULL) {
        log_msg(LGG_ERR, "%s: failed to allocate memory", __FUNCTION__);
        goto quit_load;
    }

    (void)snprintf(fname, PIXELSERV_MAX_PATH, "%s/prefetch", pem_dir);
    if ((fp = fopen(fname, "r")) == NULL) {
        log_msg(LGG_WARNING, "%s: %s doesn't exist.", __FUNCTION__, fname);
        goto quit_load;
    }

    while (getline(&line, &(size_t){ PIXELSERV_MAX_PATH }, fp) != -1) {
        char *cert_name = strtok(line, " \n\t");
        if (!cert_name) continue;

        (void)snprintf(fname, PIXELSERV_MAX_PATH, "%s/%s", pem_dir, cert_name);

        SSL_CTX *sslctx = create_child_sslctx(fname, cachain);
        if (sslctx) {
            if (sslctx_hash_insert(cert_name, sslctx) >= 0) {
                log_msg(LGG_NOTICE, "%s: %s", __FUNCTION__, cert_name);
                loaded++;
            } else {
                SSL_CTX_free(sslctx);
            }
        }

        /* Stop if hash table is getting full */
        if (atomic_load(&sslctx_hash_count) >= (sslctx_hash_size * 3) / 4)
            break;
    }
    fclose(fp);
    atomic_store(&sslctx_tbl_cnt_miss, 0);  /* Reset after prefetch */
    log_msg(LGG_NOTICE, "Prefetched %d SSL contexts from cache", loaded);

quit_load:
    free(fname);
    free(line);
}

/* NOTE: Called at shutdown - collects entries and saves most-used */
void sslctx_tbl_save(const char* pem_dir)
{
    if (!sslctx_hash_tbl)
        return;

    char *fname = NULL;
    FILE *fp = NULL;
    save_entry_t *entries = NULL;
    int entry_count = 0;

    if ((fname = malloc(PIXELSERV_MAX_PATH)) == NULL) {
        log_msg(LGG_ERR, "%s: failed to allocate memory", __FUNCTION__);
        goto quit_save;
    }

    /* Collect all occupied entries */
    int count = atomic_load(&sslctx_hash_count);
    entries = malloc(count * sizeof(save_entry_t));
    if (!entries) {
        log_msg(LGG_ERR, "%s: failed to allocate entries", __FUNCTION__);
        goto quit_save;
    }

    for (int i = 0; i < sslctx_hash_size && entry_count < count; i++) {
        if (atomic_load(&sslctx_hash_tbl[i].state) == HASH_OCCUPIED) {
            entries[entry_count].cert_name = sslctx_hash_tbl[i].cert_name;
            entries[entry_count].reuse_count = atomic_load(&sslctx_hash_tbl[i].reuse_count);
            entry_count++;
        }
    }

    /* Sort by reuse count (most used first) */
    qsort(entries, entry_count, sizeof(save_entry_t), cmp_save_entry);

    (void)snprintf(fname, PIXELSERV_MAX_PATH, "%s/prefetch", pem_dir);
    if ((fp = fopen(fname, "w")) == NULL) {
        log_msg(LGG_ERR, "%s: failed to open %s", __FUNCTION__, fname);
        goto quit_save;
    }

    /* Save up to 75% of table capacity */
    int max_save = (sslctx_hash_size * 3) / 4;
    for (int i = 0; i < entry_count && i < max_save; i++) {
        fprintf(fp, "%s\t%d\n", entries[i].cert_name, entries[i].reuse_count);
    }
    fclose(fp);
    log_msg(LGG_NOTICE, "Saved %d SSL contexts to prefetch cache",
            entry_count < max_save ? entry_count : max_save);

quit_save:
    free(entries);
    free(fname);
}

static int sslctx_tbl_check_and_flush(void)
{
    int pixel_now = process_uptime(), rv = -1;
    unsigned int last_flush = atomic_load_explicit(&sslctx_tbl_last_flush, memory_order_relaxed);
#ifdef DEBUG
    printf("%s: now %d last_flush %d", __FUNCTION__, pixel_now, last_flush);
#endif

    /* flush at most every half of session timeout */
    int do_flush = pixel_now - last_flush - PIXEL_SSL_SESS_TIMEOUT / 2;
    if (do_flush < 0) {
        rv = -1;
    } else {
#if OPENSSL_VERSION_NUMBER >= 0x30400000L && !defined(ENABLE_TONGCHOU)
        /* OpenSSL 3.4+ has Y2038-safe version */
        SSL_CTX_flush_sessions_ex(g_sslctx, time(NULL));
#else
        SSL_CTX_flush_sessions(g_sslctx, time(NULL));
#endif
        atomic_store_explicit(&sslctx_tbl_last_flush, pixel_now, memory_order_relaxed);
        rv = 1;
    }
    return rv;
}

/* =============================================================================
 * LEGACY OPENSSL THREAD SUPPORT (< 1.1.0 only)
 * OpenSSL 1.1.0+ handles threading internally - these are not needed
 * For OpenSSL >= 1.1.0, this codebase is 100% lock-free and block-free.
 * ============================================================================= */

#if OPENSSL_VERSION_NUMBER < 0x10100000L
static void ssl_lock_cb(int mode, int type, const char *file, int line)
{
    if (mode & CRYPTO_LOCK)
        pthread_mutex_lock(&(legacy_openssl_locks[type]));
    else
        pthread_mutex_unlock(&(legacy_openssl_locks[type]));
}

static void ssl_thread_id(CRYPTO_THREADID *id)
{
    CRYPTO_THREADID_set_numeric(id, (unsigned long) pthread_self());
}
#endif

void ssl_init_locks()
{
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    int i;
    legacy_openssl_locks = (pthread_mutex_t *)OPENSSL_malloc(CRYPTO_num_locks()*sizeof(pthread_mutex_t));
    for (i = 0; i < CRYPTO_num_locks(); i++)
        pthread_mutex_init(&(legacy_openssl_locks[i]), NULL);

    CRYPTO_THREADID_set_callback((void (*)(CRYPTO_THREADID *)) ssl_thread_id);
    CRYPTO_set_locking_callback((void (*)(int, int, const char *, int)) ssl_lock_cb);
#endif
    /* OpenSSL >= 1.1.0: nothing to do - handles threading internally */
}

void ssl_free_locks()
{
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    int i;
    CRYPTO_set_locking_callback(NULL);
    for (i = 0; i < CRYPTO_num_locks(); i++)
        pthread_mutex_destroy(&(legacy_openssl_locks[i]));
    OPENSSL_free(legacy_openssl_locks);
#endif
    /* OpenSSL >= 1.1.0: nothing to do */
}

static void generate_cert(char* pem_fn, const char *pem_dir, X509_NAME *issuer, EVP_PKEY *privkey)
{
    char fname[PIXELSERV_MAX_PATH];
    EVP_PKEY *key = NULL;
    X509 *x509 = NULL;
    X509_EXTENSION *ext = NULL;
#define SAN_STR_SIZE PIXELSERV_MAX_SERVER_NAME + 4 /* max("IP:", "DNS:") = 4 */
    char san_str[SAN_STR_SIZE];
    char *tld = NULL, *tld_tmp = NULL;
    int dot_count = 0;
    EVP_MD_CTX *p_ctx = NULL;

    p_ctx = EVP_MD_CTX_create();
    if(EVP_DigestSignInit(p_ctx, NULL, EVP_sha256(), NULL, privkey) != 1)
        log_msg(LGG_ERR, "%s: failed to init sign context", __FUNCTION__);

    if(pem_fn[0] == '_') pem_fn[0] = '*';

    // -- generate key based on cert_key_type
    // 0=RSA2048, 1=RSA4096, 2=ECDSA-P256, 3=ECDSA-P384
    BIGNUM *e = BN_new();
    BN_set_word(e, RSA_F4);

    switch (cert_key_type) {
    case 1: // RSA 4096
#if OPENSSL_VERSION_MAJOR >= 3
        key = EVP_RSA_gen(4096);
#else
        {
            RSA *rsa = RSA_new();
            if (RSA_generate_key_ex(rsa, 4096, e, NULL) < 0) {
                RSA_free(rsa);
                goto free_all;
            }
            key = EVP_PKEY_new();
            EVP_PKEY_assign_RSA(key, rsa);
        }
#endif
        break;
    case 2: // ECDSA P-256
#if OPENSSL_VERSION_MAJOR >= 3
        key = EVP_EC_gen("P-256");
#else
        {
            EC_KEY *ec = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
            if (!ec || !EC_KEY_generate_key(ec)) {
                if (ec) EC_KEY_free(ec);
                goto free_all;
            }
            key = EVP_PKEY_new();
            EVP_PKEY_assign_EC_KEY(key, ec);
        }
#endif
        break;
    case 3: // ECDSA P-384
#if OPENSSL_VERSION_MAJOR >= 3
        key = EVP_EC_gen("P-384");
#else
        {
            EC_KEY *ec = EC_KEY_new_by_curve_name(NID_secp384r1);
            if (!ec || !EC_KEY_generate_key(ec)) {
                if (ec) EC_KEY_free(ec);
                goto free_all;
            }
            key = EVP_PKEY_new();
            EVP_PKEY_assign_EC_KEY(key, ec);
        }
#endif
        break;
    case 0: // RSA 2048 (default)
    default:
#if OPENSSL_VERSION_MAJOR >= 3
        key = EVP_RSA_gen(2048);
#else
        {
            RSA *rsa = RSA_new();
            if (RSA_generate_key_ex(rsa, 2048, e, NULL) < 0) {
                RSA_free(rsa);
                goto free_all;
            }
            key = EVP_PKEY_new();
            EVP_PKEY_assign_RSA(key, rsa);
        }
#endif
        break;
    }

    if (!key)
        goto free_all;

#ifdef DEBUG
    printf("%s: key (type %d) generated for [%s]\n", __FUNCTION__, cert_key_type, pem_fn);
#endif
    if((x509 = X509_new()) == NULL)
        goto free_all;
    ASN1_INTEGER_set(X509_get_serialNumber(x509),rand());
    X509_set_version(x509, 2); // X509 v3
    X509_gmtime_adj(X509_get_notBefore(x509), 0);
    X509_gmtime_adj(X509_get_notAfter(x509), 3600*24*(long)cert_validity_days); // cert validity from config
    X509_set_issuer_name(x509, issuer);
    X509_NAME *name = X509_get_subject_name(x509);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char *)pem_fn, -1, -1, 0);

    tld_tmp = strchr(pem_fn, '.');
    while(tld_tmp != NULL) {
        dot_count++;
        tld = tld_tmp + 1;
        tld_tmp = strchr(tld, '.');
    }
    tld_tmp = (dot_count == 3 && (atoi(tld) > 0 || (atoi(tld) == 0 && strlen(tld) == 1))) ? "IP" : "DNS";
    snprintf(san_str, SAN_STR_SIZE, "%s:%s", tld_tmp, pem_fn);
    if ((ext = X509V3_EXT_conf_nid(NULL, NULL, NID_subject_alt_name, san_str)) == NULL)
        goto free_all;
    if (X509_add_ext(x509, ext, -1) == 0) {
        X509_EXTENSION_free(ext);
        ext = NULL;
        goto free_all;
    }
    X509_EXTENSION_free(ext);
    ext = NULL;  /* Prevent double-free at free_all */

    if ((ext = X509V3_EXT_conf_nid(NULL, NULL, NID_ext_key_usage, "TLS Web Server Authentication")) == NULL)
        goto free_all;
    if (X509_add_ext(x509, ext, -1) == 0) {
        X509_EXTENSION_free(ext);
        ext = NULL;
        goto free_all;
    }
    X509_EXTENSION_free(ext);
    ext = NULL;  /* Prevent double-free at free_all */

    X509_set_pubkey(x509, key);
    X509_sign_ctx(x509, p_ctx);
#ifdef DEBUG
    printf("%s: x509 cert created\n", __FUNCTION__);
#endif

    // -- save cert
    if(pem_fn[0] == '*')
        pem_fn[0] = '_';
    snprintf(fname, PIXELSERV_MAX_PATH, "%s/%s", pem_dir, pem_fn);
    FILE *fp = fopen(fname, "wb");
    if(fp == NULL) {
        log_msg(LGG_ERR, "%s: failed to open file for write: %s", __FUNCTION__, fname);
        goto free_all;
    }
    PEM_write_PrivateKey(fp, key, NULL, NULL, 0, NULL, NULL);
    PEM_write_X509(fp, x509);
    fclose(fp);

    /* Add to sharded index (lock-free append to shard file) */
    cert_index_add(pem_dir, pem_fn, time(NULL), cert_validity_days, cert_key_type);

    log_msg(LGG_NOTICE, "cert generated to disk: %s", pem_fn);

free_all:
    BN_free(e);
    EVP_MD_CTX_destroy(p_ctx);
    EVP_PKEY_free(key);
    X509_EXTENSION_free(ext);
    X509_free(x509);
}


/* Passphrase callback structure */
typedef struct {
    const char *pem_dir;
    const char *key_name;  /* "rootca" or "subca" */
} passwd_cb_arg_t;

static int pem_passwd_cb(char *buf, int size, int rwflag, void *u) {
    int rv = 0, fp;
    char *fname = NULL;
    passwd_cb_arg_t *arg = (passwd_cb_arg_t *)u;

    /* Try pem_dir/rootCA/<key_name>.key.passphrase first */
    if (asprintf(&fname, "%s/rootCA/%s.key.passphrase", arg->pem_dir, arg->key_name) < 0)
        goto quit_cb;

    if ((fp = open(fname, O_RDONLY)) < 0) {
        /* Try legacy pem_dir/rootCA/ca.key.passphrase */
        free(fname);
        if (asprintf(&fname, "%s/rootCA/ca.key.passphrase", arg->pem_dir) < 0)
            goto quit_cb;
        if ((fp = open(fname, O_RDONLY)) < 0)
            log_msg(LGG_DEBUG, "%s: no passphrase file found", __FUNCTION__);
        else {
            rv = read(fp, buf, size);
            close(fp);
        }
    } else {
        rv = read(fp, buf, size);
        close(fp);
#ifdef DEBUG
        buf[rv] = '\0';
        printf("%s: %d, %d\n", buf, size, rv);
#endif
    }

quit_cb:
    free(fname);
    return (rv > 0) ? --rv : 0; // trim \n at the end
}

/* Helper to load a certificate file into a chain */
static int load_cert_to_chain(STACK_OF(X509_INFO) **chain, const char *cert_path) {
    FILE *fp = fopen(cert_path, "r");
    if (!fp)
        return 0;

    BIO *bioin = BIO_new_fp(fp, BIO_CLOSE);
    if (!bioin) {
        fclose(fp);
        return 0;
    }

    STACK_OF(X509_INFO) *certs = PEM_X509_INFO_read_bio(bioin, NULL, NULL, NULL);
    BIO_free(bioin);

    if (!certs)
        return 0;

    if (*chain == NULL) {
        *chain = certs;
    } else {
        /* Append certs to existing chain */
        int i;
        for (i = 0; i < sk_X509_INFO_num(certs); i++) {
            X509_INFO *inf = sk_X509_INFO_value(certs, i);
            if (inf && inf->x509) {
                X509_INFO *dup = X509_INFO_new();
                if (dup) {
                    dup->x509 = X509_dup(inf->x509);
                    sk_X509_INFO_push(*chain, dup);
                }
            }
        }
        sk_X509_INFO_pop_free(certs, X509_INFO_free);
    }
    return 1;
}

void cert_tlstor_init(const char *pem_dir, cert_tlstor_t *ct)
{
    FILE *fp = NULL;
    char cert_file[PIXELSERV_MAX_PATH];
    X509 *issuer_cert = NULL;
    int use_subca = 0;
    passwd_cb_arg_t passwd_arg;

    memset(ct, 0, sizeof(cert_tlstor_t));
    ct->pem_dir = pem_dir;
    passwd_arg.pem_dir = pem_dir;

    /* Initialize sharded certificate index */
    cert_index_init(pem_dir);

    /*
     * New CA hierarchy (all files under pem_dir/rootCA/):
     * - rootCA/rootca.crt + rootCA/rootca.key (required, at least one CA)
     * - rootCA/subca.crt + rootCA/subca.key (optional, used for signing if present)
     * - rootCA/subca.cs.crt (optional, cross-signed certificate for chain)
     *
     * Fallback to legacy rootCA/ca.crt + rootCA/ca.key if new files not found
     */

    /* Try to load SubCA first (if exists, this is the signing CA) */
    snprintf(cert_file, PIXELSERV_MAX_PATH, "%s/rootCA/subca.crt", pem_dir);
    fp = fopen(cert_file, "r");
    if (fp) {
        issuer_cert = X509_new();
        if (PEM_read_X509(fp, &issuer_cert, NULL, NULL)) {
            log_msg(LGG_NOTICE, "Using SubCA for certificate signing");
            use_subca = 1;
        } else {
            X509_free(issuer_cert);
            issuer_cert = NULL;
        }
        fclose(fp);
        fp = NULL;
    }

    /* If no SubCA, try RootCA */
    if (!use_subca) {
        snprintf(cert_file, PIXELSERV_MAX_PATH, "%s/rootCA/rootca.crt", pem_dir);
        fp = fopen(cert_file, "r");
        if (fp) {
            issuer_cert = X509_new();
            if (PEM_read_X509(fp, &issuer_cert, NULL, NULL)) {
                log_msg(LGG_NOTICE, "Using RootCA for certificate signing");
            } else {
                X509_free(issuer_cert);
                issuer_cert = NULL;
            }
            fclose(fp);
            fp = NULL;
        }
    }

    /* Fallback to legacy ca.crt */
    if (!issuer_cert) {
        snprintf(cert_file, PIXELSERV_MAX_PATH, "%s/rootCA/ca.crt", pem_dir);
        fp = fopen(cert_file, "r");
        if (fp) {
            issuer_cert = X509_new();
            if (PEM_read_X509(fp, &issuer_cert, NULL, NULL)) {
                log_msg(LGG_NOTICE, "Using legacy ca.crt for certificate signing");
            } else {
                X509_free(issuer_cert);
                issuer_cert = NULL;
            }
            fclose(fp);
            fp = NULL;
        }
    }

    if (!issuer_cert) {
        log_msg(LGG_ERR, "%s: no CA certificate found in %s/rootCA/ (tried subca.crt, rootca.crt, ca.crt)", __FUNCTION__, pem_dir);
        return;
    }

    ct->issuer = X509_NAME_dup(X509_get_subject_name(issuer_cert));
    X509_free(issuer_cert);

    /* Build CA chain: SubCA (or SubCA cross-signed) + RootCA */
    if (use_subca) {
        /* Try cross-signed SubCA first, fall back to regular SubCA */
        snprintf(cert_file, PIXELSERV_MAX_PATH, "%s/rootCA/subca.cs.crt", pem_dir);
        if (!load_cert_to_chain(&ct->cachain, cert_file)) {
            snprintf(cert_file, PIXELSERV_MAX_PATH, "%s/rootCA/subca.crt", pem_dir);
            load_cert_to_chain(&ct->cachain, cert_file);
        }
        /* Add RootCA to chain */
        snprintf(cert_file, PIXELSERV_MAX_PATH, "%s/rootCA/rootca.crt", pem_dir);
        load_cert_to_chain(&ct->cachain, cert_file);
    } else {
        /* Just RootCA or legacy ca.crt */
        snprintf(cert_file, PIXELSERV_MAX_PATH, "%s/rootCA/rootca.crt", pem_dir);
        if (!load_cert_to_chain(&ct->cachain, cert_file)) {
            snprintf(cert_file, PIXELSERV_MAX_PATH, "%s/rootCA/ca.crt", pem_dir);
            load_cert_to_chain(&ct->cachain, cert_file);
        }
    }

    if (ct->cachain == NULL)
        log_msg(LGG_ERR, "%s: failed to build CA chain", __FUNCTION__);

    /* Load private key - must match the signing certificate */
    if (use_subca) {
        /* SubCA mode: MUST have subca.key */
        snprintf(cert_file, PIXELSERV_MAX_PATH, "%s/rootCA/subca.key", pem_dir);
        passwd_arg.key_name = "subca";
        fp = fopen(cert_file, "r");
        if (fp && PEM_read_PrivateKey(fp, &ct->privkey, pem_passwd_cb, &passwd_arg)) {
            fclose(fp);
            log_msg(LGG_NOTICE, "Loaded SubCA private key");
            return;
        }
        if (fp) fclose(fp);
        log_msg(LGG_ERR, "%s: SubCA mode requires subca.key but it's missing or unreadable", __FUNCTION__);
        /* Clear issuer since we can't sign anything */
        X509_NAME_free(ct->issuer);
        ct->issuer = NULL;
        return;
    }

    /* RootCA mode: try rootca.key first */
    snprintf(cert_file, PIXELSERV_MAX_PATH, "%s/rootCA/rootca.key", pem_dir);
    passwd_arg.key_name = "rootca";
    fp = fopen(cert_file, "r");
    if (fp && PEM_read_PrivateKey(fp, &ct->privkey, pem_passwd_cb, &passwd_arg)) {
        fclose(fp);
        log_msg(LGG_NOTICE, "Loaded RootCA private key");
        return;
    }
    if (fp) fclose(fp);

    /* Fallback to legacy ca.key */
    snprintf(cert_file, PIXELSERV_MAX_PATH, "%s/rootCA/ca.key", pem_dir);
    passwd_arg.key_name = "ca";
    fp = fopen(cert_file, "r");
    if (!fp || !PEM_read_PrivateKey(fp, &ct->privkey, pem_passwd_cb, &passwd_arg))
        log_msg(LGG_ERR, "%s: failed to load any private key (tried rootca.key, ca.key)", __FUNCTION__);
    else
        log_msg(LGG_NOTICE, "Loaded private key from ca.key (legacy)");
    if (fp) fclose(fp);
}

void cert_tlstor_cleanup(cert_tlstor_t *c)
{
    sk_X509_INFO_pop_free(c->cachain, X509_INFO_free);
    X509_NAME_free(c->issuer);
    EVP_PKEY_free(c->privkey);
}

/* =============================================================================
 * SHARDED CERTIFICATE INDEX MANAGEMENT (pem_dir/index/)
 * - Scales to 5-10 million certificates
 * - Hash-based sharding: 256 shards (configurable)
 * - Lock-free parallel access to different shards
 * - Each shard is an independent file: index/00.idx ... index/ff.idx
 * ============================================================================= */

#define CERT_INDEX_DIR "index"
#define CERT_INDEX_SHARDS 256       /* Number of shards (256 = 0x00-0xff) */
#define CERT_INDEX_SHARD_BITS 8     /* log2(CERT_INDEX_SHARDS) */
#define CERT_INDEX_VERSION 2

/* Index entry - stored in shard files (tab-separated) */
typedef struct {
    char domain[PIXELSERV_MAX_SERVER_NAME + 1];
    time_t created;
    time_t expires;
    int key_type;  /* 0=RSA2048, 1=RSA4096, 2=ECDSA-P256, 3=ECDSA-P384 */
} cert_index_entry_t;

/* Forward declarations for index functions */
static cert_index_entry_t* cert_index_load_shard(const char *pem_dir, int shard, int *count);
static int cert_index_rebuild(const char *pem_dir);

/* Shard statistics (atomic) */
static _Atomic uint64_t cert_index_total_entries = 0;
static char *cert_index_base_path = NULL;

/* Get shard number from domain name using FNV-1a hash */
static inline int cert_index_shard(const char *domain) {
    uint32_t hash = fnv1a_hash(domain);
    return hash & (CERT_INDEX_SHARDS - 1);  /* Use low bits for shard */
}

/* Get shard file path */
static void cert_index_shard_path(const char *pem_dir, int shard, char *path, size_t path_size) {
    snprintf(path, path_size, "%s/%s/%02x.idx", pem_dir, CERT_INDEX_DIR, shard);
}

/* =============================================================================
 * IN-MEMORY CERTIFICATE INDEX (Lock-Free Hash Table)
 * - O(1) lookup for certificate existence
 * - Scales to 10+ million entries (~200-300MB RAM)
 * - Lock-free concurrent access
 * ============================================================================= */

#define CERT_MEM_INDEX_INITIAL_SIZE (1 << 20)  /* 1M slots initially */
#define CERT_MEM_INDEX_MAX_SIZE     (1 << 24)  /* 16M slots max */

typedef struct {
    _Atomic uint32_t state;        /* HASH_EMPTY, HASH_INSERTING, HASH_OCCUPIED */
    char domain[PIXELSERV_MAX_SERVER_NAME + 1];
    time_t expires;
} cert_mem_entry_t;

static cert_mem_entry_t *cert_mem_index = NULL;
static _Atomic int cert_mem_index_size = 0;
static _Atomic int cert_mem_index_count = 0;

/* Initialize in-memory index */
static int cert_index_mem_init(int initial_size) {
    if (initial_size <= 0)
        initial_size = CERT_MEM_INDEX_INITIAL_SIZE;

    /* Round up to power of 2 */
    int size = next_power_of_2(initial_size);
    if (size > CERT_MEM_INDEX_MAX_SIZE)
        size = CERT_MEM_INDEX_MAX_SIZE;

    cert_mem_index = calloc(size, sizeof(cert_mem_entry_t));
    if (!cert_mem_index) {
        log_msg(LGG_ERR, "Failed to allocate cert memory index (%d entries, %lu MB)",
                size, (unsigned long)(size * sizeof(cert_mem_entry_t) / (1024*1024)));
        return -1;
    }

    atomic_store(&cert_mem_index_size, size);
    atomic_store(&cert_mem_index_count, 0);

    log_msg(LGG_NOTICE, "Certificate memory index initialized: %d slots (%lu MB)",
            size, (unsigned long)(size * sizeof(cert_mem_entry_t) / (1024*1024)));
    return 0;
}

/* Lock-free lookup - returns 1 if exists, 0 if not */
static int cert_index_mem_lookup(const char *domain) {
    if (!cert_mem_index || !domain)
        return 0;

    int size = atomic_load(&cert_mem_index_size);
    uint32_t hash = fnv1a_hash(domain);
    uint32_t mask = size - 1;
    uint32_t idx = hash & mask;

    for (int probe = 0; probe < size; probe++) {
        uint32_t state = atomic_load_explicit(&cert_mem_index[idx].state, memory_order_acquire);

        if (state == HASH_EMPTY) {
            return 0;  /* Not found */
        }

        if (state == HASH_OCCUPIED) {
            if (strcmp(cert_mem_index[idx].domain, domain) == 0) {
                /* Check if expired */
                if (cert_mem_index[idx].expires > 0 &&
                    cert_mem_index[idx].expires < time(NULL)) {
                    return 0;  /* Expired */
                }
                return 1;  /* Found and valid */
            }
        }

        idx = (idx + 1) & mask;
    }

    return 0;
}

/* Lock-free insert */
static void cert_index_mem_insert(const char *domain, time_t expires) {
    if (!cert_mem_index || !domain)
        return;

    int size = atomic_load(&cert_mem_index_size);
    int count = atomic_load(&cert_mem_index_count);

    /* Check load factor - warn at 75% */
    if (count >= (size * 3) / 4) {
        static _Atomic int warned = 0;
        if (!atomic_exchange(&warned, 1)) {
            log_msg(LGG_WARNING, "Certificate memory index at %d%% capacity (%d/%d)",
                    (count * 100) / size, count, size);
        }
        if (count >= size - 1)
            return;  /* Table full */
    }

    uint32_t hash = fnv1a_hash(domain);
    uint32_t mask = size - 1;
    uint32_t idx = hash & mask;

    for (int probe = 0; probe < size; probe++) {
        uint32_t state = atomic_load_explicit(&cert_mem_index[idx].state, memory_order_acquire);

        if (state == HASH_EMPTY) {
            uint32_t expected = HASH_EMPTY;
            if (atomic_compare_exchange_strong_explicit(&cert_mem_index[idx].state,
                    &expected, HASH_INSERTING, memory_order_acq_rel, memory_order_acquire)) {
                /* We own this slot */
                strncpy(cert_mem_index[idx].domain, domain, PIXELSERV_MAX_SERVER_NAME);
                cert_mem_index[idx].domain[PIXELSERV_MAX_SERVER_NAME] = '\0';
                cert_mem_index[idx].expires = expires;

                atomic_store_explicit(&cert_mem_index[idx].state, HASH_OCCUPIED, memory_order_release);
                atomic_fetch_add(&cert_mem_index_count, 1);
                return;
            }
            /* CAS failed - retry */
            state = atomic_load_explicit(&cert_mem_index[idx].state, memory_order_acquire);
        }

        if (state == HASH_OCCUPIED) {
            if (strcmp(cert_mem_index[idx].domain, domain) == 0) {
                /* Already exists - update expiry */
                cert_mem_index[idx].expires = expires;
                return;
            }
        }

        idx = (idx + 1) & mask;
    }
}

/* Get count of entries in memory index */
static inline int cert_index_mem_count(void) {
    return atomic_load(&cert_mem_index_count);
}

/* Check if domain exists in index - uses in-memory lookup */
static int cert_index_exists(const char *pem_dir, const char *domain) {
    (void)pem_dir;  /* No longer needed - using memory index */
    return cert_index_mem_lookup(domain);
}

/* Ensure index directory and shard structure exists, load into memory */
static int cert_index_init(const char *pem_dir) {
    char path[PIXELSERV_MAX_PATH];
    struct stat st;

    /* Create main index directory */
    snprintf(path, PIXELSERV_MAX_PATH, "%s/%s", pem_dir, CERT_INDEX_DIR);

    int need_rebuild = 0;
    if (stat(path, &st) != 0) {
        if (mkdir(path, 0755) != 0) {
            log_msg(LGG_ERR, "%s: failed to create index dir %s: %s",
                    __FUNCTION__, path, strerror(errno));
            return -1;
        }
        log_msg(LGG_NOTICE, "Created sharded certificate index: %s (%d shards)",
                path, CERT_INDEX_SHARDS);
        need_rebuild = 1;
    } else if (!S_ISDIR(st.st_mode)) {
        log_msg(LGG_ERR, "%s: %s exists but is not a directory", __FUNCTION__, path);
        return -1;
    }

    /* Store base path for later use */
    if (cert_index_base_path == NULL) {
        cert_index_base_path = strdup(pem_dir);
    }

    /* Rebuild index from existing certificates if needed */
    if (need_rebuild) {
        cert_index_rebuild(pem_dir);
    }

    /* First pass: count total entries to size memory index appropriately */
    uint64_t total = 0;
    for (int s = 0; s < CERT_INDEX_SHARDS; s++) {
        cert_index_shard_path(pem_dir, s, path, PIXELSERV_MAX_PATH);
        FILE *fp = fopen(path, "r");
        if (fp) {
            char line[PIXELSERV_MAX_SERVER_NAME + 64];
            while (fgets(line, sizeof(line), fp))
                total++;
            fclose(fp);
        }
    }

    /* Initialize in-memory index with 2x capacity for good load factor */
    int mem_size = (total > 0) ? (int)(total * 2) : CERT_MEM_INDEX_INITIAL_SIZE;
    if (cert_index_mem_init(mem_size) < 0) {
        log_msg(LGG_ERR, "%s: failed to initialize memory index", __FUNCTION__);
        return -1;
    }

    /* Second pass: load all entries into memory index using cert_index_load_shard */
    if (total > 0) {
        log_msg(LGG_NOTICE, "Loading %lu certificates into memory index...", (unsigned long)total);

        for (int s = 0; s < CERT_INDEX_SHARDS; s++) {
            int shard_count = 0;
            cert_index_entry_t *entries = cert_index_load_shard(pem_dir, s, &shard_count);
            if (entries) {
                for (int i = 0; i < shard_count; i++) {
                    cert_index_mem_insert(entries[i].domain, entries[i].expires);
                }
                free(entries);
            }
        }

        log_msg(LGG_NOTICE, "Certificate index loaded: %d entries in memory (%d on disk)",
                cert_index_mem_count(), (int)total);
    }

    atomic_store(&cert_index_total_entries, total);
    return 0;
}

/* Add certificate to appropriate shard - lock-free (append is atomic on POSIX) */
static int cert_index_add(const char *pem_dir, const char *domain, time_t created,
                          int validity_days, int key_type) {
    char path[PIXELSERV_MAX_PATH];
    int shard = cert_index_shard(domain);

    cert_index_shard_path(pem_dir, shard, path, PIXELSERV_MAX_PATH);

    /* Open for append - atomic on POSIX systems */
    FILE *fp = fopen(path, "a");
    if (!fp) {
        log_msg(LGG_WARNING, "%s: cannot open shard %02x: %s",
                __FUNCTION__, shard, strerror(errno));
        return -1;
    }

    time_t expires = created + (validity_days * 24 * 3600);
    fprintf(fp, "%s\t%ld\t%ld\t%d\n", domain, (long)created, (long)expires, key_type);
    fclose(fp);

    atomic_fetch_add(&cert_index_total_entries, 1);

    /* Also add to in-memory index */
    cert_index_mem_insert(domain, expires);

    return 0;
}

/* Load a single shard into memory */
static cert_index_entry_t* cert_index_load_shard(const char *pem_dir, int shard, int *count) {
    char path[PIXELSERV_MAX_PATH];
    FILE *fp;
    char line[PIXELSERV_MAX_SERVER_NAME + 64];
    cert_index_entry_t *entries = NULL;
    int capacity = 0, n = 0;

    *count = 0;

    cert_index_shard_path(pem_dir, shard, path, PIXELSERV_MAX_PATH);
    fp = fopen(path, "r");
    if (!fp)
        return NULL;

    capacity = 1024;
    entries = malloc(capacity * sizeof(cert_index_entry_t));
    if (!entries) {
        fclose(fp);
        return NULL;
    }

    while (fgets(line, sizeof(line), fp)) {
        char domain[PIXELSERV_MAX_SERVER_NAME + 1];
        long created, expires;
        int key_type;

        if (sscanf(line, "%255s\t%ld\t%ld\t%d", domain, &created, &expires, &key_type) == 4) {
            if (n >= capacity) {
                capacity *= 2;
                cert_index_entry_t *new_entries = realloc(entries, capacity * sizeof(cert_index_entry_t));
                if (!new_entries) {
                    free(entries);
                    fclose(fp);
                    return NULL;
                }
                entries = new_entries;
            }
            strncpy(entries[n].domain, domain, PIXELSERV_MAX_SERVER_NAME);
            entries[n].domain[PIXELSERV_MAX_SERVER_NAME] = '\0';
            entries[n].created = (time_t)created;
            entries[n].expires = (time_t)expires;
            entries[n].key_type = key_type;
            n++;
        }
    }
    fclose(fp);
    *count = n;
    return entries;
}

/* Rebuild single shard from disk scan - can run in parallel for different shards */
static int cert_index_rebuild_shard(const char *pem_dir, int shard) {
    char path[PIXELSERV_MAX_PATH];
    DIR *dir;
    struct dirent *entry;
    FILE *fp;
    int count = 0;

    dir = opendir(pem_dir);
    if (!dir)
        return -1;

    cert_index_shard_path(pem_dir, shard, path, PIXELSERV_MAX_PATH);
    fp = fopen(path, "w");
    if (!fp) {
        closedir(dir);
        return -1;
    }

    while ((entry = readdir(dir)) != NULL) {
        struct stat st;
        char cert_path[PIXELSERV_MAX_PATH];

        /* Skip directories and special files */
        if (entry->d_name[0] == '.')
            continue;
        if (strcmp(entry->d_name, "rootCA") == 0 || strcmp(entry->d_name, CERT_INDEX_DIR) == 0)
            continue;
        if (strcmp(entry->d_name, "prefetch") == 0)
            continue;

        /* Only process entries belonging to this shard */
        if (cert_index_shard(entry->d_name) != shard)
            continue;

        snprintf(cert_path, PIXELSERV_MAX_PATH, "%s/%s", pem_dir, entry->d_name);
        if (stat(cert_path, &st) != 0 || !S_ISREG(st.st_mode))
            continue;

        /* Check file is a PEM certificate */
        FILE *cert_fp = fopen(cert_path, "r");
        if (cert_fp) {
            char header[32];
            if (fgets(header, sizeof(header), cert_fp) &&
                strstr(header, "-----BEGIN")) {
                fprintf(fp, "%s\t%ld\t%ld\t%d\n",
                        entry->d_name,
                        (long)st.st_mtime,
                        (long)(st.st_mtime + cert_validity_days * 24 * 3600),
                        cert_key_type);
                count++;
            }
            fclose(cert_fp);
        }
    }
    closedir(dir);
    fclose(fp);

    return count;
}

/* Full index rebuild - parallelizable across shards */
static int cert_index_rebuild(const char *pem_dir) {
    int total = 0;

    log_msg(LGG_NOTICE, "Rebuilding certificate index (%d shards)...", CERT_INDEX_SHARDS);

    for (int s = 0; s < CERT_INDEX_SHARDS; s++) {
        int count = cert_index_rebuild_shard(pem_dir, s);
        if (count > 0)
            total += count;
    }

    atomic_store(&cert_index_total_entries, total);
    log_msg(LGG_NOTICE, "Certificate index rebuilt: %d entries", total);
    return total;
}

/* Get total certificate count (lock-free read) */
static inline uint64_t cert_index_count(void) {
    return atomic_load(&cert_index_total_entries);
}

/* =============================================================================
 * LOCK-FREE THREAD POOL FOR CERTIFICATE GENERATION
 * - Multiple worker threads generate certs in parallel
 * - Lock-free MPMC queue for work distribution
 * - Scales to millions of concurrent users
 * ============================================================================= */

#define CERTGEN_QUEUE_SIZE 8192   /* Must be power of 2 - handles burst of 8K requests */
#define CERTGEN_POOL_SIZE 16      /* Number of worker threads - adjust based on CPU cores */

typedef struct {
    char domain[PIXELSERV_MAX_SERVER_NAME + 1];
} certgen_work_item_t;

/* Lock-free bounded queue using atomic indexes */
static certgen_work_item_t certgen_queue[CERTGEN_QUEUE_SIZE];
static _Atomic uint32_t certgen_queue_head = 0;  /* Producer writes here */
static _Atomic uint32_t certgen_queue_tail = 0;  /* Consumers read from here */
static _Atomic int certgen_shutdown = 0;
static pthread_t certgen_workers[CERTGEN_POOL_SIZE];
static cert_tlstor_t *certgen_ctx = NULL;

/* Enqueue work item - called by reader thread */
static int certgen_enqueue(const char *domain) {
    uint32_t head = atomic_load_explicit(&certgen_queue_head, memory_order_relaxed);
    uint32_t next_head = (head + 1) & (CERTGEN_QUEUE_SIZE - 1);
    uint32_t tail = atomic_load_explicit(&certgen_queue_tail, memory_order_acquire);

    if (next_head == tail) {
        /* Queue full - drop this request (will be retried by client) */
        return -1;
    }

    strncpy(certgen_queue[head].domain, domain, PIXELSERV_MAX_SERVER_NAME);
    certgen_queue[head].domain[PIXELSERV_MAX_SERVER_NAME] = '\0';

    /* Publish - make visible to consumers */
    atomic_store_explicit(&certgen_queue_head, next_head, memory_order_release);
    return 0;
}

/* Dequeue work item - called by worker threads, returns NULL if empty */
static const char* certgen_dequeue(void) {
    uint32_t tail, head, next_tail;

    do {
        tail = atomic_load_explicit(&certgen_queue_tail, memory_order_relaxed);
        head = atomic_load_explicit(&certgen_queue_head, memory_order_acquire);

        if (tail == head) {
            /* Queue empty */
            return NULL;
        }

        next_tail = (tail + 1) & (CERTGEN_QUEUE_SIZE - 1);
    } while (!atomic_compare_exchange_weak_explicit(&certgen_queue_tail,
                &tail, next_tail, memory_order_acq_rel, memory_order_relaxed));

    return certgen_queue[tail].domain;
}

/* Worker thread function - processes cert generation requests */
static void *certgen_worker(void *arg) {
    int worker_id = (int)(intptr_t)arg;
    (void)worker_id;  /* Silence unused warning in non-debug builds */

#ifdef DEBUG
    printf("certgen_worker[%d]: started\n", worker_id);
#endif

    while (!atomic_load_explicit(&certgen_shutdown, memory_order_acquire)) {
        const char *domain = certgen_dequeue();

        if (domain == NULL) {
            /* Queue empty - sleep briefly to avoid busy-waiting */
            struct timespec ts = {0, 10000000};  /* 10ms */
            nanosleep(&ts, NULL);
            continue;
        }

        if (certgen_ctx == NULL || certgen_ctx->privkey == NULL || certgen_ctx->issuer == NULL) {
            continue;
        }

        /* Check if cert already exists - O(1) memory lookup */
        if (!cert_index_exists(certgen_ctx->pem_dir, domain)) {
            /* Cert doesn't exist in index - generate it */
            char domain_copy[PIXELSERV_MAX_SERVER_NAME + 1];
            strncpy(domain_copy, domain, PIXELSERV_MAX_SERVER_NAME);
            domain_copy[PIXELSERV_MAX_SERVER_NAME] = '\0';
            generate_cert(domain_copy, certgen_ctx->pem_dir, certgen_ctx->issuer, certgen_ctx->privkey);
        }
    }

#ifdef DEBUG
    printf("certgen_worker[%d]: shutting down\n", worker_id);
#endif
    return NULL;
}

/* Initialize thread pool */
static void certgen_pool_init(cert_tlstor_t *ct) {
    certgen_ctx = ct;
    atomic_store(&certgen_shutdown, 0);
    atomic_store(&certgen_queue_head, 0);
    atomic_store(&certgen_queue_tail, 0);

    for (int i = 0; i < CERTGEN_POOL_SIZE; i++) {
        if (pthread_create(&certgen_workers[i], NULL, certgen_worker, (void*)(intptr_t)i) != 0) {
            log_msg(LGG_ERR, "Failed to create certgen worker thread %d", i);
        }
    }
    log_msg(LGG_NOTICE, "Certificate generation thread pool started: %d workers", CERTGEN_POOL_SIZE);
}

/* Shutdown thread pool - called from main on SIGTERM */
void certgen_pool_shutdown(void) {
    atomic_store_explicit(&certgen_shutdown, 1, memory_order_release);

    for (int i = 0; i < CERTGEN_POOL_SIZE; i++) {
        pthread_join(certgen_workers[i], NULL);
    }
    log_msg(LGG_NOTICE, "Certificate generation thread pool stopped");
}

void *cert_generator(void *ptr) {
#ifdef DEBUG
    printf("%s: thread up and running\n", __FUNCTION__);
#endif
    int idle = 0;
    cert_tlstor_t *ct = (cert_tlstor_t *) ptr;

    char buf[PIXELSERV_MAX_SERVER_NAME * 4 + 1];
    char *half_token = buf + PIXELSERV_MAX_SERVER_NAME * 4;
    buf[PIXELSERV_MAX_SERVER_NAME * 4] = '\0';

    /* Initialize thread pool for parallel certificate generation */
    certgen_pool_init(ct);

    /* non block required. otherwise blocked until other side opens */
    int fd = open(PIXEL_CERT_PIPE, O_RDONLY | O_NONBLOCK);
    srand((unsigned int)time(NULL));

    for (;;) {
        int ret;
        if(fd == -1)
            log_msg(LGG_ERR, "%s: failed to open %s: %s", __FUNCTION__, PIXEL_CERT_PIPE, strerror(errno));
        strcpy(buf, half_token);
        struct pollfd pfd = { fd, POLLIN, POLLIN };
        ret = poll(&pfd, 1, 1000 * PIXEL_SSL_SESS_TIMEOUT / 4);
        if (ret <= 0) {
            /* timeout */
            sslctx_tbl_check_and_flush();
            if (kcc == 0) {
                if (++idle >= (3600 / (PIXEL_SSL_SESS_TIMEOUT / 4))) {
                    /* flush conn_stor after 3600 seconds */
                    conn_stor_flush();
                    idle = 0;
                }
#if defined(__GLIBC__) && !defined(__UCLIBC__)
                malloc_trim(0);
#endif
            }
            continue;
        }
        ssize_t cnt;
        size_t half_len = (size_t)(half_token - buf);
        size_t remaining = (PIXELSERV_MAX_SERVER_NAME * 4) - half_len;
        if((cnt = read(fd, buf + half_len, remaining)) == 0) {
#ifdef DEBUG
             printf("%s: pipe EOF\n", __FUNCTION__);
#endif
            close(fd);
            fd = open(PIXEL_CERT_PIPE, O_RDONLY | O_NONBLOCK); /* non block required */
            continue;
        }
        if (!cnt) continue;
        if ((size_t)cnt < remaining) {
            buf[cnt + half_len] = '\0';
            half_token = buf + PIXELSERV_MAX_SERVER_NAME * 4;
        } else {
            size_t i = 0;
            for (i=1; buf[PIXELSERV_MAX_SERVER_NAME * 4 - i]!=':' && i < strlen(buf); i++);
            half_token = buf + PIXELSERV_MAX_SERVER_NAME * 4 - i + 1;
            buf[PIXELSERV_MAX_SERVER_NAME * 4 - i + 1] = '\0';
        }
        if (ct->privkey == NULL || ct->issuer == NULL)
            continue;
        char *p_buf, *p_buf_sav = NULL;
        p_buf = strtok_r(buf, ":", &p_buf_sav);
        while (p_buf != NULL) {
            /* Enqueue to thread pool for parallel generation */
            if (certgen_enqueue(p_buf) < 0) {
                /* Queue full - generate synchronously as fallback */
                char cert_file[PIXELSERV_MAX_PATH];
                struct stat st;
                snprintf(cert_file, PIXELSERV_MAX_PATH, "%s/%s", ct->pem_dir, p_buf);
                if(stat(cert_file, &st) != 0) /* doesn't exist */
                    generate_cert(p_buf, ct->pem_dir, ct->issuer, ct->privkey);
            }
            p_buf = strtok_r(NULL, ":", &p_buf_sav);
        }
        /* quick check and flush if time due */
        sslctx_tbl_check_and_flush();
    }
    /* Note: certgen_pool_shutdown() would be called here if we ever exit the loop */
    return NULL;
}

#ifdef TLS1_3_VERSION
static char* get_server_name(SSL *s)
{
    const unsigned char *p;
    size_t len, remaining;

    /*
     * The server_name extension was given too much extensibility when it
     * was written, so parsing the normal case is a bit complex.
     */
    if (!SSL_client_hello_get0_ext(s, TLSEXT_TYPE_server_name, &p,
                                   &remaining) ||
        remaining <= 2)
        return NULL;
    /* Extract the length of the supplied list of names. */
    len = (*(p++) << 8);
    len += *(p++);
    if (len + 2 != remaining)
        return NULL;
    remaining = len;
    /*
     * The list in practice only has a single element, so we only consider
     * the first one.
     */
    if (remaining == 0 || *p++ != TLSEXT_NAMETYPE_host_name)
        return NULL;
    remaining--;
    /* Now we can finally pull out the byte array with the actual hostname. */
    if (remaining <= 2)
        return NULL;
    len = (*(p++) << 8);
    len += *(p++);
    if (len + 2 > remaining)
        return NULL;
    return (char *)p;
}

int tls_clienthello_cb(SSL *ssl, int *ad, void *arg) {
# define    CB_OK   1
# define    CB_ERR  0
#else
static int tls_servername_cb(SSL *ssl, int *ad, void *arg) {
# define    CB_OK   0
# define    CB_ERR  SSL_TLSEXT_ERR_ALERT_FATAL
#endif
    int rv = CB_OK;
    tlsext_cb_arg_struct *cbarg = (tlsext_cb_arg_struct *)arg;
    char full_pem_path[PIXELSERV_MAX_PATH + 1 + 1]; /* worst case ':\0' */
    int len;

    len = strlen(cbarg->tls_pem);
    full_pem_path[PIXELSERV_MAX_PATH] = '\0';
    strncpy(full_pem_path, cbarg->tls_pem, PIXELSERV_MAX_PATH);
    full_pem_path[len++] = '/';
    full_pem_path[len] = '\0';

    char *srv_name = NULL;
#ifdef TLS1_3_VERSION
    srv_name = (char*)get_server_name(ssl);
#else
    srv_name = (char*)(char*)SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
#endif
    if (srv_name)
        strncpy(cbarg->servername, srv_name, sizeof(cbarg->servername) - 1);
    else if (strlen(cbarg->servername))
        srv_name = cbarg->servername;
    else {
#ifdef DEBUG
        log_msg(LGG_WARNING, "SNI failed. server name and ip empty.");
#endif
        rv = CB_ERR;
        goto quit_cb;
    }
#ifdef DEBUG
    printf("SNI servername: %s\n", srv_name);
#endif

    int dot_count = 0;
    char *tld = NULL;
    char *pem_file = strchr(srv_name, '.');
    while(pem_file){
        dot_count++;
        tld = pem_file + 1;
        pem_file = strchr(tld, '.');
    }
    if (dot_count <= 1 || (dot_count == 2 && strlen(tld) == 2) || (dot_count == 3 && atoi(tld) > 0)) {
        pem_file = srv_name;
        strncat(full_pem_path, srv_name, PIXELSERV_MAX_PATH - len);
        len += strlen(srv_name);
    } else {
        pem_file = full_pem_path + strlen(full_pem_path);
        strncat(full_pem_path, "_", PIXELSERV_MAX_PATH - len);
        len += 1;
        strncat(full_pem_path, strchr(srv_name, '.'), PIXELSERV_MAX_PATH - len);
        len += strlen(strchr(srv_name, '.'));
    }
#ifdef DEBUG
    printf("PEM filename: %s\n",full_pem_path);
#endif
    if (len > PIXELSERV_MAX_PATH) {
#ifdef DEBUG
        log_msg(LGG_ERR, "%s: buffer overflow. %s", __FUNCTION__, full_pem_path);
#endif
        rv = CB_ERR;
        goto quit_cb;
    }

    /* Lock-free hash table lookup - multiple threads can lookup concurrently */
    SSL_CTX *cached_ctx = sslctx_hash_lookup(pem_file);
#ifdef DEBUG
    printf("%s: cached_ctx %p for %s\n", __FUNCTION__, (void*)cached_ctx, pem_file);
#endif

    if (cached_ctx != NULL) {
        SSL_set_SSL_CTX(ssl, cached_ctx);
        if (X509_cmp_time(X509_get_notAfter(SSL_get_certificate(ssl)), NULL) > 0) {
            cbarg->status = SSL_HIT;
            goto quit_cb;
        }
        /* Certificate expired - delete from cache and regenerate */
        cbarg->status = SSL_ERR;
#ifdef DEBUG
        log_msg(LGG_WARNING, "Expired certificate %s", pem_file);
#endif
        sslctx_hash_delete(pem_file);
        remove(full_pem_path);
        goto submit_missing_cert;
    }

    struct stat st;
    if (stat(full_pem_path, &st) != 0) {
        int fd;
        cbarg->status = SSL_MISS;
#ifdef DEBUG
        log_msg(LGG_WARNING, "%s %s missing", srv_name, pem_file);
#endif

submit_missing_cert:

        if ((fd = open(PIXEL_CERT_PIPE, O_WRONLY)) < 0) {
#ifdef DEBUG
            log_msg(LGG_ERR, "%s: failed to open pipe: %s", __FUNCTION__, strerror(errno));
#endif
        } else {
            size_t i = 0;
            for(i=0; i< strlen(pem_file); i++)
                *(full_pem_path + i) = *(pem_file + i);
            *(full_pem_path + i) = ':';
            *(full_pem_path + i + 1) = '\0';

            if (write(fd, full_pem_path, strlen(full_pem_path)) < 0) {
#ifdef DEBUG
                log_msg(LGG_ERR, "%s: failed to write pipe: %s", __FUNCTION__, strerror(errno));
#endif
            }
            close(fd);
        }

        rv = CB_ERR;
        goto quit_cb;
    }

    /* Load cert from disk - lock-free, multiple threads can do this */
    SSL_CTX *sslctx = create_child_sslctx(full_pem_path, cbarg->cachain);
    if (sslctx == NULL) {
#ifdef DEBUG
        log_msg(LGG_ERR, "%s: fail to create sslctx for %s", __FUNCTION__, pem_file);
#endif
        cbarg->status = SSL_ERR;
        rv = CB_ERR;
        goto quit_cb;
    }

    SSL_set_SSL_CTX(ssl, sslctx);
    if (X509_cmp_time(X509_get_notAfter(SSL_get_certificate(ssl)), NULL) < 0) {
        /* Certificate expired - regenerate */
        cbarg->status = SSL_ERR;
#ifdef DEBUG
        log_msg(LGG_WARNING, "Expired certificate %s", pem_file);
#endif
        SSL_CTX_free(sslctx);
        remove(full_pem_path);
        goto submit_missing_cert;
    }

    /* Lock-free insert - multiple threads can insert to different buckets concurrently
     * If same cert, hash_insert handles deduplication (returns 1 = already exists) */
    int insert_rv = sslctx_hash_insert(pem_file, sslctx);
    if (insert_rv < 0) {
#ifdef DEBUG
        log_msg(LGG_WARNING, "%s: hash table full, using uncached sslctx for %s", __FUNCTION__, pem_file);
#endif
        /* Continue anyway - sslctx is valid, just not cached */
    }
    cbarg->status = SSL_HIT;

quit_cb:
    return rv;
}

/*
static int new_session(SSL *ssl, SSL_SESSION *sess) {
    return 1; // keep internal session
}

static void remove_session(SSL_CTX *sslctx, SSL_SESSION *sess) {
}

static SSL_SESSION *get_session(SSL *ssl, unsigned char *id, int idlen, int *do_copy) {
    return NULL;
}
*/

static SSL_CTX* create_child_sslctx(const char* full_pem_path, const STACK_OF(X509_INFO) *cachain)
{
    SSL_CTX *sslctx = SSL_CTX_new(SSLv23_server_method());
#if OPENSSL_VERSION_NUMBER < 0x10101000L
    EC_KEY *ecdh = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (!ecdh)
        log_msg(LGG_ERR, "%s: cannot get ECDH curve", __FUNCTION__);
    SSL_CTX_set_tmp_ecdh(sslctx, ecdh);
    EC_KEY_free(ecdh);
#else
    /* Try to set groups with SM2 support, fall back to legacy if not available */
    if (SSL_CTX_set1_groups_list(sslctx, PIXELSERV_GROUPS) <= 0) {
        log_msg(LGG_DEBUG, "%s: SM2 groups not available, using legacy groups", __FUNCTION__);
        SSL_CTX_set1_groups_list(sslctx, PIXELSERV_GROUPS_LEGACY);
    }
#endif

    SSL_CTX_set_options(sslctx,
          SSL_OP_SINGLE_DH_USE |
          SSL_MODE_RELEASE_BUFFERS |
          SSL_OP_NO_COMPRESSION | SSL_OP_NO_TICKET |
          SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1_1 |
          SSL_OP_CIPHER_SERVER_PREFERENCE);
    /* server-side caching */
    SSL_CTX_set_session_cache_mode(sslctx, SSL_SESS_CACHE_NO_AUTO_CLEAR | SSL_SESS_CACHE_SERVER);
    SSL_CTX_set_timeout(sslctx, PIXEL_SSL_SESS_TIMEOUT);
    SSL_CTX_sess_set_cache_size(sslctx, 1);
    /* Try full cipher list with SM support, fall back to standard if not available
       BSI_STRICT_MODE uses only BSI TR-02102-2 compliant ciphers */
    if (SSL_CTX_set_cipher_list(sslctx, PIXELSERV_CIPHER_LIST_FULL) <= 0) {
        log_msg(LGG_DEBUG, "%s: SM ciphers not available, using standard cipher list", __FUNCTION__);
        if (SSL_CTX_set_cipher_list(sslctx, PIXELSERV_CIPHER_LIST_ACTIVE) <= 0)
            log_msg(LGG_DEBUG, "%s: failed to set cipher list", __FUNCTION__);
    }
#ifdef TLS1_3_VERSION
    SSL_CTX_set_min_proto_version(sslctx, TLS1_VERSION);
    SSL_CTX_set_max_proto_version(sslctx, TLS1_3_VERSION);
    /* Try TLS 1.3 ciphers with SM4 support, fall back if not available */
    if (SSL_CTX_set_ciphersuites(sslctx, PIXELSERV_TLSV1_3_CIPHERS_FULL) <= 0) {
        log_msg(LGG_DEBUG, "%s: SM4 TLS 1.3 ciphers not available, using standard suites", __FUNCTION__);
        if (SSL_CTX_set_ciphersuites(sslctx, PIXELSERV_TLSV1_3_CIPHERS) <= 0)
            log_msg(LGG_DEBUG, "%s: failed to set TLSv1.3 ciphersuites", __FUNCTION__);
    }
#endif
    if(SSL_CTX_use_certificate_file(sslctx, full_pem_path, SSL_FILETYPE_PEM) <= 0
       || SSL_CTX_use_PrivateKey_file(sslctx, full_pem_path, SSL_FILETYPE_PEM) <= 0)
    {
        SSL_CTX_free(sslctx);
        log_msg(LGG_ERR, "%s: cannot find or use %s\n", __FUNCTION__, full_pem_path);
        return NULL;
    }
    if (cachain) {
        X509_INFO *inf; int i;
        for (i=sk_X509_INFO_num(cachain)-1; i >= 0; i--) {
            if ((inf = sk_X509_INFO_value(cachain, i)) && inf->x509 &&
                    !SSL_CTX_add_extra_chain_cert(sslctx, X509_dup(inf->x509)))
            {
                SSL_CTX_free(sslctx);
                log_msg(LGG_ERR, "%s: cannot add CA cert %d\n", i, __FUNCTION__);  /* X509_ref_up requires >= v1.1 */
                return NULL;
            }
        }
    }
    return sslctx;
}

SSL_CTX* create_default_sslctx(const char *pem_dir)
{
    if (g_sslctx)
        return g_sslctx;

    g_sslctx = SSL_CTX_new(SSLv23_server_method());
    SSL_CTX_set_options(g_sslctx,
          SSL_MODE_RELEASE_BUFFERS |
          SSL_OP_NO_COMPRESSION |
          SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1_1 |
          SSL_OP_CIPHER_SERVER_PREFERENCE);
    SSL_CTX_sess_set_cache_size(g_sslctx, PIXEL_SSL_SESS_CACHE_SIZE);
    SSL_CTX_set_session_cache_mode(g_sslctx, SSL_SESS_CACHE_SERVER);
    SSL_CTX_set_timeout(g_sslctx, PIXEL_SSL_SESS_TIMEOUT);
/*    // cb for server-side caching
    SSL_CTX_sess_set_new_cb(g_sslctx, new_session);
    SSL_CTX_sess_set_remove_cb(g_sslctx, remove_session); */
    /* Try full cipher list with SM support, fall back to standard if not available
       BSI_STRICT_MODE uses only BSI TR-02102-2 compliant ciphers */
    if (SSL_CTX_set_cipher_list(g_sslctx, PIXELSERV_CIPHER_LIST_FULL) <= 0) {
        log_msg(LGG_DEBUG, "SM ciphers not available, using standard cipher list");
        if (SSL_CTX_set_cipher_list(g_sslctx, PIXELSERV_CIPHER_LIST_ACTIVE) <= 0)
            log_msg(LGG_DEBUG, "cipher_list cannot be set");
    }
#ifndef TLS1_3_VERSION
    SSL_CTX_set_tlsext_servername_callback(g_sslctx, tls_servername_cb);
#else
    SSL_CTX_set_max_early_data(g_sslctx, PIXEL_TLS_EARLYDATA_SIZE);
    /* Set TLS 1.3 ciphers with SM4 support */
    if (SSL_CTX_set_ciphersuites(g_sslctx, PIXELSERV_TLSV1_3_CIPHERS_FULL) <= 0) {
        log_msg(LGG_DEBUG, "SM4 TLS 1.3 ciphers not available, using standard suites");
        SSL_CTX_set_ciphersuites(g_sslctx, PIXELSERV_TLSV1_3_CIPHERS);
    }
#endif
    return g_sslctx;
}

int is_ssl_conn(int fd, char *srv_ip, int srv_ip_len, const int *ssl_ports, int num_ssl_ports) {

    char server_ip[INET6_ADDRSTRLEN] = {'\0'};
    struct sockaddr_storage sin_addr;
    socklen_t sin_addr_len = sizeof(sin_addr);
    char port[NI_MAXSERV] = {'\0'};
    int rv = 0, i;
    errno = 0;
    getsockname(fd, (struct sockaddr*)&sin_addr, &sin_addr_len);
    if(getnameinfo((struct sockaddr *)&sin_addr, sin_addr_len,
                   server_ip, sizeof server_ip,
                   port, sizeof port,
                   NI_NUMERICHOST | NI_NUMERICSERV) != 0)
        log_msg(LGG_ERR, "getnameinfo: %s", strerror(errno));
    if (srv_ip)
        strncpy(srv_ip, server_ip, srv_ip_len);
    for(i=0; i<num_ssl_ports; i++)
        if(atoi(port) == ssl_ports[i])
            rv = ssl_ports[i];
#ifdef DEBUG
    char client_ip[INET6_ADDRSTRLEN]= {'\0'};
    getpeername(fd, (struct sockaddr*)&sin_addr, &sin_addr_len);
    if(getnameinfo((struct sockaddr *)&sin_addr, sin_addr_len, client_ip, \
            sizeof client_ip, NULL, 0, NI_NUMERICHOST) != 0)
        perror("getnameinfo");
    printf("** NEW CONNECTION ** %s:%s\n", client_ip, port);
#endif

    return rv;
}

#ifdef TLS1_3_VERSION
char* read_tls_early_data(SSL *ssl, int *err)
{
    ssize_t buf_siz = PIXEL_TLS_EARLYDATA_SIZE;
    char *buf, *pbuf;
    int count = 0;

    *err = SSL_ERROR_NONE;
    buf = malloc(PIXEL_TLS_EARLYDATA_SIZE + 1);
    if (!buf) {
        log_msg(LGG_DEBUG, "%s out of memory\n", __FUNCTION__);
        goto err_quit;
    }
    pbuf = buf;
    for (;;) {
        size_t readbytes = 0;
        ERR_clear_error();
        int rv = SSL_read_early_data(ssl, pbuf, buf_siz, &readbytes);
        if (rv == SSL_READ_EARLY_DATA_FINISH) {
            if (buf == pbuf && readbytes == 0)
                goto err_quit;
            else {
                pbuf += readbytes;
                *pbuf = '\0';
            }
            break;
        } else if (rv == SSL_READ_EARLY_DATA_SUCCESS) {
            pbuf += readbytes;
            buf_siz -= readbytes;
            if (buf_siz < 0) {
                log_msg(LGG_DEBUG, "%s API error\n", __FUNCTION__);
                goto err_quit;
            }
            continue;
        }
        /* SSL_READ_EARLY_DATA_ERROR */
        switch (SSL_get_error(ssl, 0)) {
        case SSL_ERROR_WANT_WRITE:
        case SSL_ERROR_WANT_READ:
        case SSL_ERROR_WANT_ASYNC:
            if (count++ < 10) /* 600ms total */
              continue;
              /* fall through */
        default:
            *err = SSL_get_error(ssl, 0);
            log_msg(LGG_DEBUG, "%s error: %d count: %d\n", __FUNCTION__, *err, count);
            goto err_quit;
        }
    }
#ifdef DEBUG
    printf("%s buf: %s\n", __FUNCTION__, buf);
#endif

    return buf;

err_quit:
    free(buf);
    return NULL;
}
#endif

void run_benchmark(const cert_tlstor_t *ct, const char *cert)
{
    int c, d;
    char *cert_file = NULL, *domain;
    struct stat st;
    struct timespec tm;
    float r_tm0, g_tm0, tm1;
    SSL_CTX *sslctx = NULL;

    printf("CERT_PATH: %s\n", ct->pem_dir);
    if (ct->cachain == NULL)
        goto quit;

    printf("CERT_FILE: ");
    if (cert) {
        if (asprintf(&cert_file, "%s/%s", ct->pem_dir, cert) < 0 \
            || stat(cert_file, &st) != 0)
        {
            printf("%s not found\n", cert);
            goto quit;
        }
    } else
        cert = "_.bing.com";
    if (asprintf(&cert_file, "%s/%s", ct->pem_dir, cert) > 0)
      printf("%s\n", cert);

    if (asprintf(&domain, "%s", cert) > 0 && domain[0] == '_')
      domain[0] = '*';

    r_tm0 = 0; g_tm0 = 0;
    for (c=1; c<=10; c++) {
        get_time(&tm);
        for (d=0; d<5; d++)
            generate_cert(domain, ct->pem_dir, ct->issuer, ct->privkey);
        tm1 = elapsed_time_msec(tm) / 5.0;
        printf("%2d. generate cert to disk: %.3f ms\t", c, tm1);
        g_tm0 += tm1;

        get_time(&tm);
        for (d=0; d<5; d++) {
            stat(cert_file, &st);
            sslctx = create_child_sslctx(cert_file, ct->cachain);
            sslctx_hash_insert(cert, sslctx);
        }
        tm1 = elapsed_time_msec(tm) / 5.0;
        printf("load from disk: %.3f ms\n", tm1);
        r_tm0 += tm1;

    }
    printf("generate to disk average: %.3f ms\n", g_tm0 / 10.0);
    printf("  load from disk average: %.3f ms\n", r_tm0 / 10.0);

    free(domain);
quit:
    free(cert_file);
}
