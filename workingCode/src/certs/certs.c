#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <dirent.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/ec.h>
#include <openssl/x509v3.h>
#include <openssl/opensslv.h>
#include <openssl/objects.h>

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <openssl/param_build.h>
#include <openssl/core_names.h>
#endif
#include "core/util.h"

#include "certs/certs.h"
#include "certs/cert_index.h"
#include "certs/certs_cache.h"
#include "certs/certs_queue.h"
#include "certs/certs_stats.h"
#include "certs/certs_conn.h"
#include "certs/keypool.h"
#include "core/logger.h"
#include "core/util.h"
#include "index/index_client.h"
#include "index/second_level_tlds.h"

#if defined(__GLIBC__) && !defined(__UCLIBC__)
#  include <malloc.h>
#endif

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
#define OPENSSL_API_1_1 1
#else
#define OPENSSL_API_1_1 0
#endif

#if !OPENSSL_API_1_1
static pthread_mutex_t *locks;
#endif

static SSL_CTX *g_sslctx;

/* Universal IP SSL context - lock-free with atomic CAS */
static _Atomic(SSL_CTX *) g_universal_ip_sslctx = NULL;

/* Global keypool for fast key generation */
static keypool_t *g_keypool = NULL;

/* Global certificate index for sharded storage */
static cert_index_t *g_cert_index = NULL;

/* Global cert_tlstor for SNI callback access */
static cert_tlstor_t *g_cert_tlstor = NULL;

/* Global 2nd-level TLD set for correct wildcard detection */
static tld_set_t *g_tld_set = NULL;

/* Global primes for ultrafast RSA key generation (~1ms vs ~50ms) */
static unsigned char *g_primes_p = NULL;
static unsigned char *g_primes_q = NULL;
static size_t g_primes_count = 0;
static int g_use_external_primes = 0;

/* Worker mode: use index_client instead of local cert_index */
static int g_worker_mode = 0;
static char g_master_socket[256] = "";

/* Helper function to generate cert path without needing cert_index */
static size_t get_cert_path_direct(const char *pem_dir, uint8_t shard_id,
                                    uint32_t cert_id, char *path_buf, size_t path_len) {
    if (!pem_dir || !path_buf || path_len == 0) return 0;
    return snprintf(path_buf, path_len, "%s/RSA/certs/%02x/cert_%06u.pem",
                    pem_dir, shard_id, cert_id);
}

/*
 * Index Writer Queue - MPSC queue for index updates
 * Multiple workers push, single index writer consumes
 */
typedef struct index_job {
    _Atomic(struct index_job *) next;
    char cert_name[256];
    uint8_t shard_id;
    uint32_t cert_id;
    uint64_t expiry;
} index_job_t;

static _Atomic(index_job_t *) idx_queue_head;
static _Atomic(index_job_t *) idx_queue_tail;
static index_job_t idx_queue_stub;
static _Atomic int idx_writer_shutdown;
static pthread_t idx_writer_thread;

static void index_queue_init(void) {
    atomic_store(&idx_queue_stub.next, NULL);
    atomic_store(&idx_queue_head, &idx_queue_stub);
    atomic_store(&idx_queue_tail, &idx_queue_stub);
    atomic_store(&idx_writer_shutdown, 0);
}

static void index_queue_push(const char *cert_name, uint8_t shard_id, uint32_t cert_id, uint64_t expiry) {
    index_job_t *job = malloc(sizeof(index_job_t));
    if (!job) return;

    strncpy(job->cert_name, cert_name, sizeof(job->cert_name) - 1);
    job->cert_name[sizeof(job->cert_name) - 1] = '\0';
    job->shard_id = shard_id;
    job->cert_id = cert_id;
    job->expiry = expiry;
    atomic_store(&job->next, NULL);

    index_job_t *prev = atomic_exchange(&idx_queue_head, job);
    atomic_store(&prev->next, job);
}

static index_job_t *index_queue_pop(void) {
    index_job_t *tail = atomic_load(&idx_queue_tail);
    index_job_t *next = atomic_load(&tail->next);

    if (tail == &idx_queue_stub) {
        if (!next) return NULL;
        atomic_store(&idx_queue_tail, next);
        tail = next;
        next = atomic_load(&tail->next);
    }

    if (next) {
        atomic_store(&idx_queue_tail, next);
        return tail;
    }

    index_job_t *head = atomic_load(&idx_queue_head);
    if (tail != head) return NULL;

    atomic_store(&idx_queue_stub.next, NULL);
    index_job_t *prev = atomic_exchange(&idx_queue_head, &idx_queue_stub);
    atomic_store(&prev->next, &idx_queue_stub);

    next = atomic_load(&tail->next);
    if (next) {
        atomic_store(&idx_queue_tail, next);
        return tail;
    }
    return NULL;
}

/* Index Writer Thread - single consumer for all index updates */
static void *index_writer_thread_func(void *arg) {
    (void)arg;
    int backoff = 0;

    while (!atomic_load(&idx_writer_shutdown)) {
        index_job_t *job = index_queue_pop();

        if (job) {
            backoff = 0;
            if (job->cert_name[0] != '\0') {
                if (g_worker_mode) {
                    /* Worker mode: notify master */
                    index_client_insert(job->cert_name, job->shard_id, job->cert_id, job->expiry);
                } else if (g_cert_index) {
                    /* Standalone mode: local index */
                    cert_index_insert(g_cert_index, job->cert_name, job->shard_id, job->cert_id, job->expiry);
                }
            }
            if (job != &idx_queue_stub) free(job);
        } else {
            atomic_backoff(&backoff);
            if (backoff > 15) backoff = 10;
        }
    }

    /* Drain remaining jobs on shutdown to prevent memory leak */
    index_job_t *job;
    while ((job = index_queue_pop()) != NULL) {
        if (job != &idx_queue_stub) free(job);
    }

    return NULL;
}

/*
 * NOTE: sslctx_tbl replaced by lock-free certs_cache module
 * NOTE: conn_stor replaced by lock-free certs_conn module
 * NOTE: cert_job queue replaced by lock-free certs_queue module
 * NOTE: statistics replaced by lock-free certs_stats module
 */

/* Legacy compatibility variables - kept for getter functions */
static volatile unsigned int sslctx_tbl_last_flush;

static void generate_cert(const char *cert_name,
                          const char *pem_dir,
                          X509_NAME *issuer,
                          EVP_PKEY *privkey,
                          const STACK_OF(X509_INFO) *cachain);

/* Forward declarations for prime loading/unloading */
int cert_load_primes(cert_tlstor_t *ct);
void cert_unload_primes(cert_tlstor_t *ct);

static int is_ip_address(const char *addr) {
    struct sockaddr_in sa4;
    struct sockaddr_in6 sa6;
    
    if (inet_pton(AF_INET, addr, &(sa4.sin_addr)) == 1) return 4;
    if (inet_pton(AF_INET6, addr, &(sa6.sin6_addr)) == 1) return 6;
    return 0;
}

static void generate_universal_ip_cert(const char *pem_dir,
                                      X509_NAME *issuer,
                                      EVP_PKEY *privkey,
                                      const STACK_OF(X509_INFO) *cachain)
{
    char fname[PIXELSERV_MAX_PATH];
    EVP_PKEY *key = NULL;
    X509 *x509 = NULL;
    X509_EXTENSION *ext = NULL;
    EVP_MD_CTX *p_ctx = NULL;

    char mega_san[2048];
    strcpy(mega_san,
        "IP:127.0.0.1,IP:127.0.0.254,"
        "IP:10.0.0.1,IP:10.255.255.254,"
        "IP:192.168.0.1,IP:192.168.255.254,"
        "IP:172.16.0.1,IP:172.31.255.254,"
        "IP:192.168.1.1,IP:192.168.0.1,IP:10.0.0.1,"
        "DNS:localhost,DNS:*.local,DNS:*.lan"
    );

#if OPENSSL_API_1_1
    p_ctx = EVP_MD_CTX_new();
#else
    p_ctx = EVP_MD_CTX_create();
#endif
    if (!p_ctx || EVP_DigestSignInit(p_ctx, NULL, EVP_sha256(), NULL, privkey) != 1) {
        goto free_all;
    }

/* Skip keypool for universal_ip_cert to avoid deadlock during init */
    /* Fallback to direct generation */
    {
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
        key = EVP_RSA_gen(3072);
#elif OPENSSL_API_1_1
        EVP_PKEY_CTX *pkey_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
        if (pkey_ctx) {
            if (EVP_PKEY_keygen_init(pkey_ctx) > 0 &&
                EVP_PKEY_CTX_set_rsa_keygen_bits(pkey_ctx, 3072) > 0) {
                EVP_PKEY_keygen(pkey_ctx, &key);
            }
            EVP_PKEY_CTX_free(pkey_ctx);
        }
#else
        BIGNUM *e = BN_new();
        if (e) {
            BN_set_word(e, RSA_F4);
            RSA *rsa = RSA_new();
            if (rsa && RSA_generate_key_ex(rsa, 3072, e, NULL) >= 0) {
                key = EVP_PKEY_new();
                if (!key || !EVP_PKEY_assign_RSA(key, rsa)) {
                    RSA_free(rsa);
                    key = NULL;
                }
            } else {
                RSA_free(rsa);
            }
            BN_free(e);
        }
#endif
    }
    if (!key) {
        goto free_all;
    }

    x509 = X509_new();
    if (!x509) goto free_all;
    
    ASN1_INTEGER_set(X509_get_serialNumber(x509), rand());
    X509_set_version(x509, 2);
    
    int offset = -(rand() % (864000 - 172800 + 1) + 172800);
    X509_gmtime_adj(X509_get_notBefore(x509), offset);
    X509_gmtime_adj(X509_get_notAfter(x509), 3600*24*390L);
    
    X509_set_issuer_name(x509, issuer);
    X509_NAME *name = X509_get_subject_name(x509);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char *)"*.universal.ip", -1, -1, 0);

    ext = X509V3_EXT_conf_nid(NULL, NULL, NID_subject_alt_name, mega_san);
    if (!ext) goto free_all;
    X509_add_ext(x509, ext, -1);
    X509_EXTENSION_free(ext);
    ext = NULL;
    
    ext = X509V3_EXT_conf_nid(NULL, NULL, NID_ext_key_usage, "TLS Web Server Authentication");
    if (!ext) goto free_all;
    X509_add_ext(x509, ext, -1);
    
    X509_set_pubkey(x509, key);
    X509_sign_ctx(x509, p_ctx);

    snprintf(fname, PIXELSERV_MAX_PATH, "%s/universal_ips.pem", pem_dir);
    
    FILE *fp = fopen(fname, "wb");
    if (!fp) {
        goto free_all;
    }

    /* Write order: Private Key -> Certificate -> CA Chain */
    PEM_write_PrivateKey(fp, key, NULL, NULL, 0, NULL, NULL);

    PEM_write_X509(fp, x509);

    if (cachain) {
        for (int i = 0; i < sk_X509_INFO_num(cachain); i++) {
            X509_INFO *xi = sk_X509_INFO_value(cachain, i);
            if (xi && xi->x509) {
                PEM_write_X509(fp, xi->x509);
            }
        }
    }

    fclose(fp);

free_all:
    EVP_PKEY_free(key);
    X509_EXTENSION_free(ext);
    X509_free(x509);
    if (p_ctx) {
#if OPENSSL_API_1_1
        EVP_MD_CTX_free(p_ctx);
#else
        EVP_MD_CTX_destroy(p_ctx);
#endif
    }
}

/*
 * Lock-free certificate worker thread
 * Uses spin-wait with exponential backoff instead of pthread_cond_wait
 */
static void *cert_worker(void *arg) {
    cert_tlstor_t *ct = (cert_tlstor_t *)arg;
    int backoff = 0;

    while (!cert_queue_is_shutdown()) {
        cert_job_t *job = cert_queue_pop();

        if (job) {
            backoff = 0;  /* Reset backoff on successful pop */
            /* Validate cert_name before processing */
            if (job->cert_name[0] != '\0') {
                generate_cert(job->cert_name, ct->pem_dir, ct->issuer, ct->privkey, ct->cachain);
                stats_inc_gen();
            }
            cert_job_free(job);
        } else {
            /* No job available - use exponential backoff */
            atomic_backoff(&backoff);
            if (backoff > 15) {
                backoff = 10;  /* Cap the backoff */
            }
        }
    }
    return NULL;
}

static void shutdown_cert_workers(void) {
    cert_queue_shutdown();

    /* Give workers time to exit via spin-wait */
    struct timespec delay = {0, 100 * 1000000}; /* 100ms */
    nanosleep(&delay, NULL);
}

/*
 * Lock-free job enqueue - simply delegates to certs_queue
 */
static void enqueue_cert_job(const char *cert_name) {
    cert_queue_push(cert_name);
}

/*
 * Statistics getters - now using lock-free certs_stats module
 */
inline int sslctx_tbl_get_cnt_total() { return stats_get_total(); }
inline int sslctx_tbl_get_cnt_hit() { return stats_get_hit(); }
inline int sslctx_tbl_get_cnt_miss() { return stats_get_miss(); }
inline int sslctx_tbl_get_cnt_purge() { return stats_get_purge(); }
inline int sslctx_tbl_get_sess_cnt() { return SSL_CTX_sess_number(g_sslctx); }
inline int sslctx_tbl_get_sess_hit() { return SSL_CTX_sess_hits(g_sslctx); }
inline int sslctx_tbl_get_sess_miss() { return SSL_CTX_sess_misses(g_sslctx); }
inline int sslctx_tbl_get_sess_purge() { return SSL_CTX_sess_cache_full(g_sslctx); }

static SSL_CTX* create_child_sslctx(const char* full_pem_path, const STACK_OF(X509_INFO) *cachain);

/*
 * Connection storage - now using lock-free certs_conn module
 * These are thin wrappers that delegate to the lock-free implementation
 */
void conn_stor_init(int slots) {
    conn_stor_init_lockfree(slots);
}

void conn_stor_flush() {
    conn_stor_flush_lockfree();
}

void conn_stor_relinq(conn_tlstor_struct *p) {
    conn_stor_relinq_lockfree(p);
}

conn_tlstor_struct* conn_stor_acquire() {
    conn_tlstor_struct *ret = conn_stor_acquire_lockfree();
    if (ret) {
        ret->tlsext_cb_arg = &ret->v;
    }
    return ret;
}

/*
 * SSL context table - now using lock-free certs_cache module
 */
void sslctx_tbl_init(int tbl_size)
{
    if (tbl_size <= 0)
        return;

    /* Initialize lock-free cache */
    cache_init(tbl_size);

    /* Initialize lock-free statistics */
    certs_stats_init();

    /* Initialize lock-free job queue */
    cert_queue_init();

    sslctx_tbl_last_flush = 0;
}

void sslctx_tbl_cleanup()
{
    shutdown_cert_workers();

    /* Clean up universal IP SSL_CTX - lock-free with atomic exchange */
    SSL_CTX *old_ip_ctx = atomic_exchange(&g_universal_ip_sslctx, NULL);
    if (old_ip_ctx) {
        SSL_CTX_free(old_ip_ctx);
    }

    /* Clean up lock-free cache */
    cache_cleanup();

    /* Clean up lock-free connection storage */
    conn_stor_cleanup_lockfree();
}

/*
 * SSL context table load/save - now using lock-free certs_cache module
 */
void sslctx_tbl_load(const char* pem_dir, const STACK_OF(X509_INFO) *cachain)
{
    /* Load cache index from disk - this prewarms the cache */
    cache_load_from_disk(pem_dir, cachain);
}

void sslctx_tbl_save(const char* pem_dir)
{
    /* Save cache index to disk for next startup */
    cache_save_index(pem_dir);
}

/*
 * Lock/unlock are no-ops in lock-free implementation
 * The cache uses atomic CAS operations instead
 */
void sslctx_tbl_lock(int idx)
{
    (void)idx;  /* No-op in lock-free implementation */
}

void sslctx_tbl_unlock(int idx)
{
    (void)idx;  /* No-op in lock-free implementation */
}

static int sslctx_tbl_check_and_flush(void)
{
    int pixel_now = process_uptime();

    int do_flush = pixel_now - sslctx_tbl_last_flush - PIXEL_SSL_SESS_TIMEOUT / 2;
    if (do_flush < 0) {
        return -1;
    }

    /* Use Y2038-safe version on OpenSSL 3.4+ */
#if OPENSSL_VERSION_NUMBER >= 0x30400000L
    SSL_CTX_flush_sessions_ex(g_sslctx, (time_t)time(NULL));
#else
    SSL_CTX_flush_sessions(g_sslctx, (long)time(NULL));
#endif

    /* Also expire old cache entries and reclaim those past grace period */
    cache_expire_old(PIXEL_SSL_SESS_TIMEOUT);
    cache_reclaim_expired();

    sslctx_tbl_last_flush = pixel_now;
    return 1;
}

/*
 * Lock-free cache lookup
 * Returns SSL_CTX directly, sets found_idx to 0 on hit, -1 on miss
 */
static SSL_CTX *sslctx_cache_lookup_lockfree(const char *cert_name) {
    return cache_lookup(cert_name);
}

/*
 * Lock-free cache insert
 */
static int sslctx_cache_insert_lockfree(const char *cert_name, SSL_CTX *sslctx) {
    return cache_insert(cert_name, sslctx);
}

#ifdef DEBUG
static void sslctx_tbl_dump(int idx, const char * func)
{
    (void)idx;
    (void)func;
    /* Lock-free cache - no per-entry debug dump needed */
}
#endif

#if !OPENSSL_API_1_1
static void ssl_lock_cb(int mode, int type, const char *file, int line)
{
    if (mode & CRYPTO_LOCK)
        pthread_mutex_lock(&(locks[type]));
    else
        pthread_mutex_unlock(&(locks[type]));
}

static void ssl_thread_id(CRYPTO_THREADID *id)
{
    CRYPTO_THREADID_set_numeric(id, (unsigned long) pthread_self());
}
#endif

void ssl_init_locks()
{
#if !OPENSSL_API_1_1
    int num_locks = CRYPTO_num_locks();
#ifdef DEBUG
#endif
    locks = OPENSSL_malloc(num_locks * sizeof(pthread_mutex_t));
    if (!locks) {
        return;
    }
    
    for (int i = 0; i < num_locks; i++) {
        pthread_mutex_init(&(locks[i]), NULL);
    }

    CRYPTO_THREADID_set_callback(ssl_thread_id);
    CRYPTO_set_locking_callback(ssl_lock_cb);
#else
#endif
}

void ssl_free_locks()
{
#if !OPENSSL_API_1_1
    if (!locks) return;
    
    CRYPTO_set_locking_callback(NULL);
    int num_locks = CRYPTO_num_locks();
    for (int i = 0; i < num_locks; i++) {
        pthread_mutex_destroy(&(locks[i]));
    }
    OPENSSL_free(locks);
    locks = NULL;
#endif
}

/* Generate RSA key from global external primes (ultrafast ~1ms) */
static EVP_PKEY *rsa_from_global_primes(void) {
    if (!g_use_external_primes || !g_primes_p || !g_primes_q || g_primes_count == 0) {
        return NULL;
    }

    EVP_PKEY *key = NULL;
    BIGNUM *n = NULL, *e = NULL, *d = NULL;
    BIGNUM *p = NULL, *q = NULL;
    BIGNUM *dmp1 = NULL, *dmq1 = NULL, *iqmp = NULL;
    BIGNUM *p1 = NULL, *q1 = NULL, *phi = NULL;
    BN_CTX *bn_ctx = NULL;

    /* Select random prime indices */
    size_t idx_p = rand() % g_primes_count;
    size_t idx_q = rand() % g_primes_count;
    if (idx_p == idx_q) idx_q = (idx_q + 1) % g_primes_count;

    /* Get pointers to the primes */
    const unsigned char *prime_p_data = g_primes_p + (idx_p * PRIME_SIZE_3072);
    const unsigned char *prime_q_data = g_primes_q + (idx_q * PRIME_SIZE_3072);

    /* Create BIGNUMs from the raw prime data */
    p = BN_bin2bn(prime_p_data, PRIME_SIZE_3072, NULL);
    q = BN_bin2bn(prime_q_data, PRIME_SIZE_3072, NULL);
    if (!p || !q) goto cleanup;

    /* Ensure p > q */
    if (BN_cmp(p, q) < 0) { BIGNUM *tmp = p; p = q; q = tmp; }

    /* Allocate remaining BIGNUMs */
    n = BN_new(); e = BN_new(); d = BN_new();
    dmp1 = BN_new(); dmq1 = BN_new(); iqmp = BN_new();
    p1 = BN_new(); q1 = BN_new(); phi = BN_new();
    bn_ctx = BN_CTX_new();
    if (!n || !e || !d || !dmp1 || !dmq1 || !iqmp || !p1 || !q1 || !phi || !bn_ctx) goto cleanup;

    BN_set_word(e, RSA_F4);
    if (!BN_mul(n, p, q, bn_ctx)) goto cleanup;
    if (!BN_sub(p1, p, BN_value_one())) goto cleanup;
    if (!BN_sub(q1, q, BN_value_one())) goto cleanup;
    if (!BN_mul(phi, p1, q1, bn_ctx)) goto cleanup;
    if (!BN_mod_inverse(d, e, phi, bn_ctx)) goto cleanup;
    if (!BN_mod(dmp1, d, p1, bn_ctx)) goto cleanup;
    if (!BN_mod(dmq1, d, q1, bn_ctx)) goto cleanup;
    if (!BN_mod_inverse(iqmp, q, p, bn_ctx)) goto cleanup;

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    {
        OSSL_PARAM_BLD *bld = OSSL_PARAM_BLD_new();
        if (bld) {
            OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_N, n);
            OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_E, e);
            OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_D, d);
            OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_FACTOR1, p);
            OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_FACTOR2, q);
            OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_EXPONENT1, dmp1);
            OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_EXPONENT2, dmq1);
            OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_COEFFICIENT1, iqmp);
            OSSL_PARAM *params = OSSL_PARAM_BLD_to_param(bld);
            if (params) {
                EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
                if (ctx && EVP_PKEY_fromdata_init(ctx) > 0) {
                    EVP_PKEY_fromdata(ctx, &key, EVP_PKEY_KEYPAIR, params);
                }
                EVP_PKEY_CTX_free(ctx);
                OSSL_PARAM_free(params);
            }
            OSSL_PARAM_BLD_free(bld);
        }
    }
#else
    {
        RSA *rsa = RSA_new();
        if (rsa && RSA_set0_key(rsa, BN_dup(n), BN_dup(e), BN_dup(d)) &&
            RSA_set0_factors(rsa, BN_dup(p), BN_dup(q)) &&
            RSA_set0_crt_params(rsa, BN_dup(dmp1), BN_dup(dmq1), BN_dup(iqmp))) {
            key = EVP_PKEY_new();
            if (!key || !EVP_PKEY_assign_RSA(key, rsa)) {
                RSA_free(rsa);
                key = NULL;
            }
        } else {
            RSA_free(rsa);
        }
    }
#endif

cleanup:
    BN_free(n); BN_free(e); BN_free(d);
    BN_free(p); BN_free(q);
    BN_free(dmp1); BN_free(dmq1); BN_free(iqmp);
    BN_free(p1); BN_free(q1); BN_free(phi);
    BN_CTX_free(bn_ctx);
    return key;
}

static void generate_cert(const char* cert_name,
                          const char *pem_dir,
                          X509_NAME *issuer,
                          EVP_PKEY *privkey,
                          const STACK_OF(X509_INFO) *cachain)
{
    char fname[PIXELSERV_MAX_PATH];
    EVP_PKEY *key = NULL;
    X509 *x509 = NULL;
    X509_EXTENSION *ext = NULL;
    char san_str[PIXELSERV_MAX_SERVER_NAME + 4];
    EVP_MD_CTX *p_ctx = NULL;
    char *pem_fn = NULL;
    
    pem_fn = strdup(cert_name);
    if (!pem_fn) {
        log_msg(LGG_ERR, "[GENERATE_CERT] strdup failed for %s", cert_name);
        return;
    }

#if OPENSSL_API_1_1
    p_ctx = EVP_MD_CTX_new();
#else
    p_ctx = EVP_MD_CTX_create();
#endif
    if (!p_ctx || EVP_DigestSignInit(p_ctx, NULL, EVP_sha256(), NULL, privkey) != 1) {
        log_msg(LGG_ERR, "[GENERATE_CERT] EVP_DigestSignInit failed for %s (privkey=%p)", cert_name, (void*)privkey);
        goto free_all;
    }

    if (pem_fn[0] == '_') pem_fn[0] = '*';

#ifdef DEBUG
    fprintf(stderr, "[DEBUG] generate_cert: %s\n", cert_name);
#endif

    /* Ultrafast path: use external primes (~1ms) */
    if (g_use_external_primes) {
#ifdef DEBUG
        fprintf(stderr, "[DEBUG] Using external primes for RSA generation...\n");
#endif
        key = rsa_from_global_primes();
#ifdef DEBUG
        if (key) {
            fprintf(stderr, "[DEBUG] RSA key from primes OK\n");
        }
#endif
    }

    /* Slow fallback: direct RSA generation (~50-500ms) */
    if (!key) {
#ifdef DEBUG
        fprintf(stderr, "[DEBUG] Starting slow RSA-3072 generation...\n");
#endif
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
        key = EVP_RSA_gen(3072);
#elif OPENSSL_API_1_1
        EVP_PKEY_CTX *pkey_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
        if (pkey_ctx) {
            if (EVP_PKEY_keygen_init(pkey_ctx) > 0 &&
                EVP_PKEY_CTX_set_rsa_keygen_bits(pkey_ctx, 3072) > 0) {
                EVP_PKEY_keygen(pkey_ctx, &key);
            }
            EVP_PKEY_CTX_free(pkey_ctx);
        }
#else
        BIGNUM *e = BN_new();
        if (e) {
            BN_set_word(e, RSA_F4);
            RSA *rsa = RSA_new();
            if (rsa && RSA_generate_key_ex(rsa, 3072, e, NULL) >= 0) {
                key = EVP_PKEY_new();
                if (!key || !EVP_PKEY_assign_RSA(key, rsa)) {
                    RSA_free(rsa);
                    key = NULL;
                }
            } else {
                RSA_free(rsa);
            }
            BN_free(e);
        }
#endif
    }
    if (!key) {
#ifdef DEBUG
        fprintf(stderr, "[DEBUG] RSA key generation FAILED\n");
#endif
        goto free_all;
    }

#ifdef DEBUG
    fprintf(stderr, "[DEBUG] RSA key generated OK\n");
#endif
    x509 = X509_new();
    if (!x509) goto free_all;
    
    ASN1_INTEGER_set(X509_get_serialNumber(x509), rand());
    X509_set_version(x509, 2);
    
    int offset = -(rand() % (864000 - 172800 + 1) + 172800);
    X509_gmtime_adj(X509_get_notBefore(x509), offset);
    X509_gmtime_adj(X509_get_notAfter(x509), 3600*24*390L);
    
    X509_set_issuer_name(x509, issuer);
    X509_NAME *name = X509_get_subject_name(x509);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char *)pem_fn, -1, -1, 0);

    int ip_version = is_ip_address(pem_fn);
    if (ip_version > 0) {
        snprintf(san_str, sizeof(san_str), "IP:%s", pem_fn);
    } else if (pem_fn[0] == '*' && pem_fn[1] == '.') {
        /* Wildcard cert: include both base domain AND wildcard in SAN
         * e.g., *.quelle.de -> DNS:quelle.de,DNS:*.quelle.de */
        const char *base_domain = pem_fn + 2;  /* Skip "*." */
        snprintf(san_str, sizeof(san_str), "DNS:%s,DNS:%s", base_domain, pem_fn);
    } else {
        snprintf(san_str, sizeof(san_str), "DNS:%s", pem_fn);
    }
    
    ext = X509V3_EXT_conf_nid(NULL, NULL, NID_subject_alt_name, san_str);
    if (!ext) goto free_all;
    X509_add_ext(x509, ext, -1);
    X509_EXTENSION_free(ext);
    ext = NULL;
    
    ext = X509V3_EXT_conf_nid(NULL, NULL, NID_ext_key_usage, "TLS Web Server Authentication");
    if (!ext) goto free_all;
    X509_add_ext(x509, ext, -1);
    
    X509_set_pubkey(x509, key);
    X509_sign_ctx(x509, p_ctx);

#ifdef DEBUG
#endif

    if (pem_fn[0] == '*') pem_fn[0] = '_';

    /* Get expiry time for index registration */
    const ASN1_TIME *not_after = X509_get0_notAfter(x509);
    time_t expiry_time = 0;
    if (not_after) {
        struct tm tm_exp;
        ASN1_TIME_to_tm(not_after, &tm_exp);
        expiry_time = mktime(&tm_exp);
    }

    /* Sharded storage requires cert_index */
    if (!g_cert_index) {
        log_msg(LGG_ERR, "[GENERATE_CERT] g_cert_index is NULL!");
        goto free_all;
    }

    /* Compute shard from domain hash */
    uint32_t domain_hash = cert_index_domain_hash(pem_fn);
    uint8_t shard_id = cert_index_shard_id(domain_hash);

    /* Allocate unique cert_id */
    uint32_t cert_id = cert_index_alloc_cert_id(g_cert_index, shard_id);
    if (cert_id == 0) {
        goto free_all;
    }

    /* Get sharded path */
    if (cert_index_get_path(g_cert_index, shard_id, cert_id, fname, sizeof(fname)) == 0) {
        goto free_all;
    }

    FILE *fp = fopen(fname, "wb");
    if (!fp) {
        /* Try creating parent directory */
        char dir_path[PIXELSERV_MAX_PATH];
        snprintf(dir_path, sizeof(dir_path), "%s/RSA/certs/%02x", pem_dir, shard_id);
        mkdir(dir_path, 0755);
        fp = fopen(fname, "wb");
        if (!fp) {
            goto free_all;
        }
    }

    /* Write order: Private Key -> Certificate -> CA Chain */
    PEM_write_PrivateKey(fp, key, NULL, NULL, 0, NULL, NULL);

    PEM_write_X509(fp, x509);

    if (cachain) {
        for (int i = 0; i < sk_X509_INFO_num(cachain); i++) {
            X509_INFO *xi = sk_X509_INFO_value(cachain, i);
            if (xi && xi->x509) {
                PEM_write_X509(fp, xi->x509);
            }
        }
    }

    fclose(fp);

    /* Queue index update for dedicated writer thread */
#ifdef DEBUG
    fprintf(stderr, "[DEBUG] Generated cert %s -> %s, queuing index update\n", pem_fn, fname);
#endif
    index_queue_push(pem_fn, shard_id, cert_id, (uint64_t)expiry_time);

free_all:
    free(pem_fn);
    EVP_PKEY_free(key);
    X509_EXTENSION_free(ext);
    X509_free(x509);
    if (p_ctx) {
#if OPENSSL_API_1_1
        EVP_MD_CTX_free(p_ctx);
#else
        EVP_MD_CTX_destroy(p_ctx);
#endif
    }
}

static int pem_passwd_cb(char *buf, int size, int rwflag, void *u) {
    int rv = 0, fp;
    char *fname = NULL;
    
    if (asprintf(&fname, "%s/rootCA/rootca.key.passphrase", (char*)u) < 0)
        goto quit_cb;

    if ((fp = open(fname, O_RDONLY)) < 0) {
    } else {
        rv = read(fp, buf, size - 1);
        close(fp);
        if (rv > 0 && buf[rv-1] == '\n') {
            rv--;
        }
        if (rv > 0) buf[rv] = '\0';
#ifdef DEBUG
#endif
    }

quit_cb:
    free(fname);
    return rv;
}

/* Helper function to find certificate file in various locations */
static FILE* find_cert_file(const char *pem_dir, const char *filename, char *found_path, size_t path_size)
{
    FILE *fp = NULL;
    /* Search order: RSA, ECDSA, SM2, LEGACY, then direct rootCA */
    const char *subdirs[] = { "RSA", "ECDSA", "SM2", "LEGACY", NULL };

    /* First try subdirectories */
    for (int i = 0; subdirs[i] != NULL; i++) {
        snprintf(found_path, path_size, "%s/%s/rootCA/%s", pem_dir, subdirs[i], filename);
        fp = fopen(found_path, "r");
        if (fp) return fp;
    }

    /* Then try LEGACY directly (without rootCA subdirectory) */
    snprintf(found_path, path_size, "%s/LEGACY/%s", pem_dir, filename);
    fp = fopen(found_path, "r");
    if (fp) return fp;

    /* Finally try direct rootCA path */
    snprintf(found_path, path_size, "%s/rootCA/%s", pem_dir, filename);
    fp = fopen(found_path, "r");
    return fp;
}

void cert_tlstor_init(const char *pem_dir, cert_tlstor_t *ct)
{
    FILE *fp = NULL;
    char cert_file[PIXELSERV_MAX_PATH];
    X509 *x509 = NULL;

    memset(ct, 0, sizeof(cert_tlstor_t));

    /* Set global reference for SNI callback */
    g_cert_tlstor = ct;

    fp = find_cert_file(pem_dir, "rootca.crt", cert_file, PIXELSERV_MAX_PATH);
    x509 = X509_new();

    if (!fp || !x509 || !PEM_read_X509(fp, &x509, NULL, NULL)) {
        goto cleanup_ca;
    }

    char *cafile = NULL;
    long fsz;
    
    if (fseek(fp, 0L, SEEK_END) < 0 || (fsz = ftell(fp)) < 0 || fseek(fp, 0L, SEEK_SET) < 0) {
        goto cleanup_ca;
    }

    cafile = malloc(fsz + 1);
    if (!cafile || fread(cafile, 1, fsz, fp) != (size_t)fsz) {
        free(cafile);
        goto cleanup_ca;
    }

    BIO *bioin = BIO_new_mem_buf(cafile, fsz);
    if (!bioin) {
        free(cafile);
        goto cleanup_ca;
    }

    ct->pem_dir = pem_dir;
    ct->cachain = PEM_X509_INFO_read_bio(bioin, NULL, NULL, NULL);
    ct->issuer = X509_NAME_dup(X509_get_subject_name(x509));

    if (!ct->cachain) {
    }

    BIO_free(bioin);
    free(cafile);

cleanup_ca:
    if (fp) fclose(fp);
    X509_free(x509);

    /* Try to find subca.key first (preferred), then rootca.key */
    fp = find_cert_file(pem_dir, "subca.key", cert_file, PIXELSERV_MAX_PATH);
    if (!fp) {
        fp = find_cert_file(pem_dir, "rootca.key", cert_file, PIXELSERV_MAX_PATH);
    }
    if (!fp || !PEM_read_PrivateKey(fp, &ct->privkey, pem_passwd_cb, (void*)pem_dir)) {
    }
    if (fp) fclose(fp);

    /* Try to load external primes for fast RSA key generation */
    if (cert_load_primes(ct)) {
        /* External primes loaded successfully */
    }

    /* Initialize keypool for fast key generation */
    if (!g_keypool) {
        keypool_config_t kp_cfg = {
            .pool_size = 20000,         /* Pre-generated keys for fast cert generation */
            .refill_threads = 2,        /* 2 background refill threads */
            .enable_rsa_3072 = true,
            .enable_ecdsa_p256 = true,
            .enable_sm2 = false         /* SM2 only on demand */
        };
        g_keypool = keypool_create(&kp_cfg);
        if (g_keypool) {
            keypool_start_refill(g_keypool);
        }
    }

    /* Load 2nd-level TLD list for correct wildcard detection */
    if (!g_tld_set) {
        g_tld_set = tld_set_create();
        if (g_tld_set) {
            char tld_file[PIXELSERV_MAX_PATH];
            snprintf(tld_file, sizeof(tld_file), "%s/config/second-level-tlds.conf", pem_dir);
            int loaded = tld_set_load_from_file(g_tld_set, tld_file);
            if (loaded > 0) {
                log_msg(LGG_NOTICE, "Loaded %d 2nd-level TLDs from %s", loaded, tld_file);
            } else {
                log_msg(LGG_INFO, "No TLD file found at %s, using heuristic for wildcard detection", tld_file);
            }
        }
    }

    /* Initialize certificate index for RSA (sharded storage) */
    if (!g_cert_index) {
        cert_index_config_t idx_cfg = {
            .base_dir = pem_dir,
            .ca_name = "RSA",
            .max_certs = 8000000,       /* Support up to 8M certificates */
            .create_dirs = true         /* Create shard directories if missing */
        };
        g_cert_index = cert_index_create(&idx_cfg);
        if (g_cert_index) {
            cert_index_start_compact(g_cert_index);
        }
    }

    char universal_ip_file[PIXELSERV_MAX_PATH];
    snprintf(universal_ip_file, sizeof(universal_ip_file), "%s/universal_ips.pem", pem_dir);
    struct stat st;
    if (stat(universal_ip_file, &st) != 0 && ct->privkey && ct->issuer) {
        generate_universal_ip_cert(pem_dir, ct->issuer, ct->privkey, ct->cachain);
    }

    /* Initialize queues before starting workers */
    cert_queue_init();
    index_queue_init();

    /* Start index writer thread (single consumer for index updates) */
    pthread_create(&idx_writer_thread, NULL, index_writer_thread_func, NULL);

    /* Start multiple worker threads (they only generate certs, don't write index) */
    for (int i = 0; i < 4; i++) {
        pthread_t tid;
        if (pthread_create(&tid, NULL, cert_worker, ct) == 0) {
            pthread_detach(tid);
        }
    }
}

void cert_tlstor_cleanup(cert_tlstor_t *c)
{
    if (!c) return;

    shutdown_cert_workers();

    /* Shutdown index writer thread */
    atomic_store(&idx_writer_shutdown, 1);
    pthread_join(idx_writer_thread, NULL);

    /* Cleanup keypool */
    if (g_keypool) {
        keypool_destroy(g_keypool);
        g_keypool = NULL;
    }

    /* Cleanup TLD set */
    if (g_tld_set) {
        tld_set_destroy(g_tld_set);
        g_tld_set = NULL;
    }

    /* Cleanup certificate index */
    if (g_cert_index) {
        cert_index_stop_compact(g_cert_index);
        cert_index_destroy(g_cert_index);
        g_cert_index = NULL;
    }

    /* Unload external primes if loaded */
    cert_unload_primes(c);

    sk_X509_INFO_pop_free(c->cachain, X509_INFO_free);
    X509_NAME_free(c->issuer);
    EVP_PKEY_free(c->privkey);

    memset(c, 0, sizeof(*c));
}

void *cert_generator(void *ptr) {
#ifdef DEBUG
#endif
    int idle = 0;
    cert_tlstor_t *ct = (cert_tlstor_t *) ptr;

    char buf[PIXELSERV_MAX_SERVER_NAME * 4 + 1];
    char *half_token = buf + PIXELSERV_MAX_SERVER_NAME * 4;
    buf[PIXELSERV_MAX_SERVER_NAME * 4] = '\0';

    int fd = open(pixel_cert_pipe, O_RDONLY | O_NONBLOCK);
    srand((unsigned int)time(NULL));

    while (!cert_queue_is_shutdown()) {
        if (fd == -1) {
            sleep(1);
            fd = open(pixel_cert_pipe, O_RDONLY | O_NONBLOCK);
            continue;
        }
        
        strcpy(buf, half_token);
        struct pollfd pfd = { fd, POLLIN, 0 };
        int ret = poll(&pfd, 1, 1000 * PIXEL_SSL_SESS_TIMEOUT / 4);
        
        if (ret <= 0) {
            sslctx_tbl_check_and_flush();
            if (kcc == 0) {
                if (++idle >= (3600 / (PIXEL_SSL_SESS_TIMEOUT / 4))) {
                    conn_stor_flush();
                    idle = 0;
                }
#if defined(__GLIBC__) && !defined(__UCLIBC__)
                malloc_trim(0);
#endif
            }
            continue;
        }
        
        size_t half_len = strlen(half_token);
        size_t read_size = (half_len < PIXELSERV_MAX_SERVER_NAME * 4) ?
                           (PIXELSERV_MAX_SERVER_NAME * 4 - half_len) : 0;
        ssize_t cnt = (read_size > 0) ? read(fd, buf + half_len, read_size) : 0;
        if (cnt == 0) {
#ifdef DEBUG
#endif
            close(fd);
            fd = open(pixel_cert_pipe, O_RDONLY | O_NONBLOCK);
            continue;
        }
        
        if (cnt < 0) continue;

        if ((size_t)cnt < read_size) {
            buf[cnt + half_len] = '\0';
            half_token = buf + PIXELSERV_MAX_SERVER_NAME * 4;
        } else {
            size_t i = 1;
            for (i = 1; buf[PIXELSERV_MAX_SERVER_NAME * 4 - i] != ':' && i < strlen(buf); i++);
            half_token = buf + PIXELSERV_MAX_SERVER_NAME * 4 - i + 1;
            buf[PIXELSERV_MAX_SERVER_NAME * 4 - i + 1] = '\0';
        }
        
        if (!ct->privkey || !ct->issuer) continue;
        
        char *p_buf, *p_buf_sav = NULL;
        p_buf = strtok_r(buf, ":", &p_buf_sav);
        while (p_buf != NULL) {
            int cert_exists = 0;

            /* Check cert_index (sharded storage) */
            if (g_cert_index) {
                cert_index_result_t idx_result;
                if (cert_index_lookup(g_cert_index, p_buf, &idx_result) == CERT_INDEX_OK && idx_result.found) {
                    time_t now = time(NULL);
                    if (idx_result.expiry > (uint64_t)now) {
                        cert_exists = 1;
                    }
                }
            }

            if (!cert_exists) {
                enqueue_cert_job(p_buf);
            }
            p_buf = strtok_r(NULL, ":", &p_buf_sav);
        }
        
        sslctx_tbl_check_and_flush();
    }
    
    if (fd >= 0) close(fd);
    return NULL;
}

#ifdef TLS1_3_VERSION
static const unsigned char *get_server_name(SSL *s, size_t *len)
{
    const unsigned char *p;
    size_t remaining;

    if (!SSL_client_hello_get0_ext(s, TLSEXT_TYPE_server_name, &p, &remaining) ||
        remaining <= 2)
        return NULL;
        
    size_t list_len = (*(p++) << 8);
    list_len += *(p++);
    if (list_len + 2 != remaining)
        return NULL;
        
    remaining = list_len;
    if (remaining == 0 || *p++ != TLSEXT_NAMETYPE_host_name)
        return NULL;
        
    remaining--;
    if (remaining <= 2)
        return NULL;
        
    *len = (*(p++) << 8);
    *len += *(p++);
    if (*len + 2 > remaining)
        return NULL;
        
    return p;
}

int tls_clienthello_cb(SSL *ssl, int *ad, void *arg) {
# define CB_OK   1
# define CB_ERR  0
#else
static int tls_servername_cb(SSL *ssl, int *ad, void *arg) {
# define CB_OK   0
# define CB_ERR  SSL_TLSEXT_ERR_ALERT_FATAL
#endif
    int rv = CB_OK;
    tlsext_cb_arg_struct *cbarg = (tlsext_cb_arg_struct *)arg;
    char full_pem_path[PIXELSERV_MAX_PATH + 2];
    int len;

    if (!cbarg || !cbarg->tls_pem) {
        rv = CB_ERR;
        goto quit_cb;
    }

    len = strlen(cbarg->tls_pem);
    if (len >= PIXELSERV_MAX_PATH) {
        rv = CB_ERR;
        goto quit_cb;
    }
    
    strncpy(full_pem_path, cbarg->tls_pem, PIXELSERV_MAX_PATH);
    full_pem_path[len++] = '/';
    full_pem_path[len] = '\0';

    const char *srv_name = NULL;
#ifdef TLS1_3_VERSION
    size_t name_len = 0;
    const unsigned char *name_data = get_server_name(ssl, &name_len);
    if (name_data && name_len > 0 && name_len < sizeof(cbarg->servername)) {
        memcpy(cbarg->servername, name_data, name_len);
        cbarg->servername[name_len] = '\0';
        srv_name = cbarg->servername;
    }
#else
    srv_name = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
    if (srv_name) {
        strncpy(cbarg->servername, srv_name, sizeof(cbarg->servername) - 1);
        cbarg->servername[sizeof(cbarg->servername) - 1] = '\0';
    }
#endif

    if (!srv_name) {
        if (strlen(cbarg->servername) > 0) {
            srv_name = cbarg->servername;
        } else if (strlen(cbarg->server_ip) > 0) {
            /* Use server IP as fallback when no SNI is provided */
            srv_name = cbarg->server_ip;
        } else {
            rv = CB_ERR;
            goto quit_cb;
        }
    }

#ifdef DEBUG
#endif

    if (is_ip_address(srv_name)) {
        char universal_ip_path[PIXELSERV_MAX_PATH];
        snprintf(universal_ip_path, sizeof(universal_ip_path), "%s/universal_ips.pem", cbarg->tls_pem);

        struct stat st;
        if (stat(universal_ip_path, &st) == 0) {
            /* Lock-free lazy initialization using CAS */
            SSL_CTX *ip_ctx = atomic_load(&g_universal_ip_sslctx);
            if (!ip_ctx) {
                SSL_CTX *new_ctx = create_child_sslctx(universal_ip_path, cbarg->cachain);
                if (new_ctx) {
                    SSL_CTX *expected = NULL;
                    if (!atomic_compare_exchange_strong(&g_universal_ip_sslctx, &expected, new_ctx)) {
                        /* Another thread won the race - use their context */
                        SSL_CTX_free(new_ctx);
                        ip_ctx = expected;
                    } else {
                        ip_ctx = new_ctx;
                    }
                }
            }

            if (ip_ctx) {
                SSL_set_SSL_CTX(ssl, ip_ctx);
                cbarg->status = SSL_HIT;
                goto quit_cb;
            }
        }
    }

    /* Determine certificate name (wildcard logic) */
    int dot_count = 0;
    const char *tld = NULL;
    const char *dot_pos = strchr(srv_name, '.');
    while (dot_pos) {
        dot_count++;
        tld = dot_pos + 1;
        dot_pos = strchr(tld, '.');
    }

    char cert_name[PIXELSERV_MAX_SERVER_NAME + 2];

    /* Check if we should use direct domain or wildcard */
    int use_direct = 0;

    if (dot_count <= 1) {
        /* Single label or just TLD - use as-is */
        use_direct = 1;
    } else if (dot_count == 2 && strlen(tld) == 2) {
        /* Two dots with 2-char TLD (e.g., example.co.uk) - use as-is */
        use_direct = 1;
    } else if (dot_count == 3 && atoi(tld) > 0) {
        /* IP address pattern - use as-is */
        use_direct = 1;
    } else if (g_tld_set && tld_set_count(g_tld_set) > 0) {
        /* Use TLD set for accurate 2nd-level TLD detection */
        /* For www.amazon.co.uk: check if "co.uk" is a 2nd-level TLD */
        const char *remainder = strchr(srv_name, '.');
        if (remainder) {
            remainder++;  /* Skip the dot */
            /* Check if remainder (e.g., "amazon.co.uk") has a 2nd-level TLD suffix */
            const char *second_dot = strchr(remainder, '.');
            if (second_dot && tld_set_contains(g_tld_set, second_dot + 1)) {
                /* The suffix after remainder's first dot is a 2nd-level TLD */
                /* www.amazon.co.uk -> remainder = amazon.co.uk -> suffix = co.uk (is TLD) */
                /* So use "_amazon.co.uk" not "_co.uk" */
                use_direct = 0;  /* Will use remainder as wildcard base */
            }
        }
    }

    if (use_direct) {
        /* Direct domain: use as-is */
        strncpy(cert_name, srv_name, sizeof(cert_name) - 1);
        cert_name[sizeof(cert_name) - 1] = '\0';
    } else {
        /* Wildcard domain: www.quelle.de -> _quelle.de */
        const char *wildcard_domain = strchr(srv_name, '.');
        if (wildcard_domain) {
            snprintf(cert_name, sizeof(cert_name), "_%s", wildcard_domain + 1);
        } else {
            strncpy(cert_name, srv_name, sizeof(cert_name) - 1);
            cert_name[sizeof(cert_name) - 1] = '\0';
        }
    }

    /* Check SSL context cache first - lock-free lookup */
    SSL_CTX *cached_ctx = sslctx_cache_lookup_lockfree(cert_name);
    if (cached_ctx) {
        SSL_set_SSL_CTX(ssl, cached_ctx);

        X509 *cert = SSL_get_certificate(ssl);
        if (cert && X509_cmp_time(X509_get_notAfter(cert), NULL) > 0) {
            cbarg->status = SSL_HIT;
            goto quit_cb;
        }

        cbarg->status = SSL_ERR;
        goto submit_missing_cert;
    }

    /* Lookup certificate in index (sharded storage) */
    cert_index_result_t idx_result;
    memset(&idx_result, 0, sizeof(idx_result));

    if (g_worker_mode) {
        /* Worker mode: use index_client to query master */
        uint8_t shard_id;
        uint32_t cert_id;
        uint64_t expiry;
        if (index_client_lookup(cert_name, &shard_id, &cert_id, &expiry) == 0) {
            idx_result.found = 1;
            idx_result.shard_id = shard_id;
            idx_result.cert_id = cert_id;
            idx_result.expiry = expiry;
        }
    } else {
        /* Standalone mode: use local cert_index */
        if (!g_cert_index) {
            rv = CB_ERR;
            goto quit_cb;
        }
        cert_index_lookup(g_cert_index, cert_name, &idx_result);
    }

    if (idx_result.found) {
        /* Certificate exists in index - get sharded path */
        size_t path_len = 0;
        if (g_cert_index) {
            path_len = cert_index_get_path(g_cert_index, idx_result.shard_id, idx_result.cert_id,
                                           full_pem_path, sizeof(full_pem_path));
        } else if (g_cert_tlstor && g_cert_tlstor->pem_dir) {
            path_len = get_cert_path_direct(g_cert_tlstor->pem_dir, idx_result.shard_id,
                                            idx_result.cert_id, full_pem_path, sizeof(full_pem_path));
        }
        if (path_len > 0) {
            /* Check if certificate is still valid (not expired) */
            time_t now = time(NULL);
            if (idx_result.expiry > (uint64_t)now) {
                goto load_cert_from_path;
            }
            /* Expired - remove and regenerate */
            remove(full_pem_path);
            if (!g_worker_mode && g_cert_index) {
                cert_index_delete(g_cert_index, cert_name);
            }
        }
    }

    /* Certificate not found - generate SYNCHRONOUSLY */
    cbarg->status = SSL_MISS;

    if (!g_cert_tlstor || !g_cert_tlstor->pem_dir) {
        rv = CB_ERR;
        goto quit_cb;
    }

    /* Generate certificate directly (not via queue) */
#ifdef DEBUG
    fprintf(stderr, "[DEBUG] SNI: generating cert synchronously for %s\n", cert_name);
#endif
    generate_cert(cert_name, g_cert_tlstor->pem_dir, g_cert_tlstor->issuer,
                  g_cert_tlstor->privkey, g_cert_tlstor->cachain);

    /* Now check if it was created - look up in index */
    struct timespec delay = {0, 10 * 1000000};  /* 10ms */
    for (int retry = 0; retry < 20; retry++) {
        int found = 0;
        memset(&idx_result, 0, sizeof(idx_result));

        if (g_worker_mode) {
            uint8_t shard_id;
            uint32_t cert_id;
            uint64_t expiry;
            if (index_client_lookup(cert_name, &shard_id, &cert_id, &expiry) == 0) {
                idx_result.found = 1;
                idx_result.shard_id = shard_id;
                idx_result.cert_id = cert_id;
                idx_result.expiry = expiry;
                found = 1;
            }
        } else if (g_cert_index) {
            if (cert_index_lookup(g_cert_index, cert_name, &idx_result) == CERT_INDEX_OK && idx_result.found) {
                found = 1;
            }
        }

        if (found) {
            size_t plen = 0;
            if (g_cert_index) {
                plen = cert_index_get_path(g_cert_index, idx_result.shard_id, idx_result.cert_id,
                                           full_pem_path, sizeof(full_pem_path));
            } else if (g_cert_tlstor && g_cert_tlstor->pem_dir) {
                plen = get_cert_path_direct(g_cert_tlstor->pem_dir, idx_result.shard_id,
                                            idx_result.cert_id, full_pem_path, sizeof(full_pem_path));
            }
            if (plen > 0) {
                cbarg->status = SSL_HIT;
                goto load_cert_from_path;
            }
        }
        nanosleep(&delay, NULL);
    }

    /* Index not updated yet - try to find the cert file directly */
    {
        uint32_t domain_hash = cert_index_domain_hash(cert_name);
        uint8_t shard_id = cert_index_shard_id(domain_hash);

        /* Scan shard directory for newest cert file */
        char shard_dir[512];
        snprintf(shard_dir, sizeof(shard_dir), "%s/RSA/certs/%02x", g_cert_tlstor->pem_dir, shard_id);

        DIR *dir = opendir(shard_dir);
        if (dir) {
            struct dirent *entry;
            time_t newest_time = 0;
            char newest_file[1024] = {0};

            while ((entry = readdir(dir)) != NULL) {
                if (strncmp(entry->d_name, "cert_", 5) == 0) {
                    char filepath[1024];
                    snprintf(filepath, sizeof(filepath), "%s/%.255s", shard_dir, entry->d_name);
                    struct stat st;
                    if (stat(filepath, &st) == 0 && st.st_mtime > newest_time) {
                        newest_time = st.st_mtime;
                        snprintf(newest_file, sizeof(newest_file), "%s", filepath);
                    }
                }
            }
            closedir(dir);

            if (newest_file[0] && newest_time > time(NULL) - 5) {
                strncpy(full_pem_path, newest_file, sizeof(full_pem_path) - 1);
                cbarg->status = SSL_HIT;
                goto load_cert_from_path;
            }
        }
    }

    rv = CB_ERR;
    goto quit_cb;

submit_missing_cert:
    rv = CB_ERR;
    goto quit_cb;

load_cert_from_path:

    SSL_CTX *sslctx = create_child_sslctx(full_pem_path, cbarg->cachain);
    if (!sslctx) {
        cbarg->status = SSL_ERR;
        rv = CB_ERR;
        goto quit_cb;
    }

    SSL_set_SSL_CTX(ssl, sslctx);
    
    X509 *cert = SSL_get_certificate(ssl);
    if (cert && X509_cmp_time(X509_get_notAfter(cert), NULL) < 0) {
        cbarg->status = SSL_ERR;
        remove(full_pem_path);
        goto submit_missing_cert;
    }

    /* Insert into lock-free cache */
    if (sslctx_cache_insert_lockfree(cert_name, sslctx) < 0) {
        /* Cache full - release our ownership, SSL object keeps its reference.
         * When SSL connection closes, SSL_free() will decrement refcount to 0
         * and the sslctx will be automatically freed (single-use). */
        log_msg(LGG_DEBUG, "Cache insert failed for %s (cache full, single-use)", cert_name);
        SSL_CTX_free(sslctx);  /* Decrement refcount from 2 to 1 */
    }
    
    cbarg->status = SSL_HIT;

quit_cb:
    return rv;
}

static SSL_CTX* create_child_sslctx(const char* full_pem_path, const STACK_OF(X509_INFO) *cachain)
{
    SSL_CTX *sslctx = SSL_CTX_new(TLS_server_method());
    if (!sslctx) {
        return NULL;
    }

#if OPENSSL_VERSION_NUMBER >= 0x10101000L
    int groups[] = { NID_X9_62_prime256v1, NID_secp384r1 };
    SSL_CTX_set1_groups(sslctx, groups, sizeof(groups)/sizeof(groups[0]));
#elif OPENSSL_VERSION_NUMBER >= 0x10100000L
    SSL_CTX_set_ecdh_auto(sslctx, 1);
#else
    EC_KEY *ecdh = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (ecdh) {
        SSL_CTX_set_tmp_ecdh(sslctx, ecdh);
        EC_KEY_free(ecdh);
    }
#endif

    long options = SSL_OP_SINGLE_DH_USE |
                   SSL_OP_NO_COMPRESSION |
                   SSL_OP_NO_TICKET |
                   SSL_OP_NO_SSLv2 |
                   SSL_OP_NO_SSLv3 |
                   SSL_OP_CIPHER_SERVER_PREFERENCE;

#ifdef SSL_MODE_RELEASE_BUFFERS
    options |= SSL_MODE_RELEASE_BUFFERS;
#endif

#ifdef SSL_OP_NO_TLSv1_1
    options |= SSL_OP_NO_TLSv1_1;
#endif

    SSL_CTX_set_options(sslctx, options);

    SSL_CTX_set_session_cache_mode(sslctx, SSL_SESS_CACHE_NO_AUTO_CLEAR | SSL_SESS_CACHE_SERVER);
    SSL_CTX_set_timeout(sslctx, PIXEL_SSL_SESS_TIMEOUT);
    SSL_CTX_sess_set_cache_size(sslctx, 1);

    if (SSL_CTX_set_cipher_list(sslctx, PIXELSERV_CIPHER_LIST) <= 0) {
    }

#ifdef TLS1_3_VERSION
    SSL_CTX_set_min_proto_version(sslctx, TLS1_VERSION);
    SSL_CTX_set_max_proto_version(sslctx, TLS1_3_VERSION);
    if (SSL_CTX_set_ciphersuites(sslctx, PIXELSERV_TLSV1_3_CIPHERS) <= 0) {
    }
#endif

    if (SSL_CTX_use_certificate_file(sslctx, full_pem_path, SSL_FILETYPE_PEM) <= 0 ||
        SSL_CTX_use_PrivateKey_file(sslctx, full_pem_path, SSL_FILETYPE_PEM) <= 0) {
        SSL_CTX_free(sslctx);
        return NULL;
    }

    if (cachain) {
        for (int i = sk_X509_INFO_num(cachain) - 1; i >= 0; i--) {
            X509_INFO *inf = sk_X509_INFO_value(cachain, i);
            if (inf && inf->x509) {
                X509 *cert_copy = X509_dup(inf->x509);
                if (!cert_copy || !SSL_CTX_add_extra_chain_cert(sslctx, cert_copy)) {
                    X509_free(cert_copy);
                    SSL_CTX_free(sslctx);
                    return NULL;
                }
            }
        }
    }

    return sslctx;
}

SSL_CTX* create_default_sslctx(const char *pem_dir)
{
    if (g_sslctx) return g_sslctx;

    g_sslctx = SSL_CTX_new(TLS_server_method());
    if (!g_sslctx) {
        return NULL;
    }

    long options = SSL_OP_NO_COMPRESSION |
                   SSL_OP_NO_SSLv2 |
                   SSL_OP_NO_SSLv3 |
                   SSL_OP_CIPHER_SERVER_PREFERENCE;

#ifdef SSL_MODE_RELEASE_BUFFERS
    options |= SSL_MODE_RELEASE_BUFFERS;
#endif

#ifdef SSL_OP_NO_TLSv1_1
    options |= SSL_OP_NO_TLSv1_1;
#endif

    SSL_CTX_set_options(g_sslctx, options);
    SSL_CTX_sess_set_cache_size(g_sslctx, PIXEL_SSL_SESS_CACHE_SIZE);
    SSL_CTX_set_session_cache_mode(g_sslctx, SSL_SESS_CACHE_SERVER);
    SSL_CTX_set_timeout(g_sslctx, PIXEL_SSL_SESS_TIMEOUT);

    if (SSL_CTX_set_cipher_list(g_sslctx, PIXELSERV_CIPHER_LIST) <= 0) {
    }

#ifdef TLS1_3_VERSION
    SSL_CTX_set_max_early_data(g_sslctx, PIXEL_TLS_EARLYDATA_SIZE);
    SSL_CTX_set_client_hello_cb(g_sslctx, tls_clienthello_cb, NULL);
#else
    SSL_CTX_set_tlsext_servername_callback(g_sslctx, tls_servername_cb);
#endif

    return g_sslctx;
}

int is_ssl_conn(int fd, char *srv_ip, int srv_ip_len, const int *ssl_ports, int num_ssl_ports) {
    char server_ip[INET6_ADDRSTRLEN] = {'\0'};
    struct sockaddr_storage sin_addr;
    socklen_t sin_addr_len = sizeof(sin_addr);
    char port[NI_MAXSERV] = {'\0'};
    int rv = 0;

    if (getsockname(fd, (struct sockaddr*)&sin_addr, &sin_addr_len) != 0 ||
        getnameinfo((struct sockaddr *)&sin_addr, sin_addr_len,
                   server_ip, sizeof server_ip,
                   port, sizeof port,
                   NI_NUMERICHOST | NI_NUMERICSERV) != 0) {
        return 0;
    }
    
    if (srv_ip && srv_ip_len > 0) {
        strncpy(srv_ip, server_ip, srv_ip_len - 1);
        srv_ip[srv_ip_len - 1] = '\0';
    }
    
    int port_num = atoi(port);
    for (int i = 0; i < num_ssl_ports; i++) {
        if (port_num == ssl_ports[i]) {
            rv = ssl_ports[i];
            break;
        }
    }

#ifdef DEBUG
    char client_ip[INET6_ADDRSTRLEN] = {'\0'};
    getpeername(fd, (struct sockaddr*)&sin_addr, &sin_addr_len);
    if (getnameinfo((struct sockaddr *)&sin_addr, sin_addr_len, client_ip,
                   sizeof client_ip, NULL, 0, NI_NUMERICHOST) == 0) {
    }
#endif

    return rv;
}

#ifdef TLS1_3_VERSION
char* read_tls_early_data(SSL *ssl, int *err)
{
    size_t buf_siz = PIXEL_TLS_EARLYDATA_SIZE;
    char *buf = malloc(PIXEL_TLS_EARLYDATA_SIZE + 1);
    if (!buf) {
        *err = SSL_ERROR_SYSCALL;
        return NULL;
    }

    char *pbuf = buf;
    int count = 0;
    *err = SSL_ERROR_NONE;

    for (;;) {
        size_t readbytes = 0;
        ERR_clear_error();
        int rv = SSL_read_early_data(ssl, pbuf, buf_siz, &readbytes);

        if (rv == SSL_READ_EARLY_DATA_FINISH) {
            if (buf == pbuf && readbytes == 0) {
                goto err_quit;
            } else {
                pbuf += readbytes;
                *pbuf = '\0';
            }
            break;
        } else if (rv == SSL_READ_EARLY_DATA_SUCCESS) {
            pbuf += readbytes;
            buf_siz -= readbytes;
            if (buf_siz <= 0) {
                goto err_quit;
            }
            continue;
        }

        switch (SSL_get_error(ssl, 0)) {
        case SSL_ERROR_WANT_WRITE:
        case SSL_ERROR_WANT_READ:
        case SSL_ERROR_WANT_ASYNC:
            if (count++ < 10) {
                struct timespec delay = {0, 60000000};
                nanosleep(&delay, NULL);
                continue;
            }
            __attribute__((fallthrough));
        default:
            *err = SSL_get_error(ssl, 0);
            goto err_quit;
        }
    }

#ifdef DEBUG
#endif

    return buf;

err_quit:
    free(buf);
    return NULL;
}
#endif

/* ============== External Primes Support ============== */

int cert_load_primes(cert_tlstor_t *ct) {
    char path_p[PIXELSERV_MAX_PATH];
    char path_q[PIXELSERV_MAX_PATH];
    struct stat st;
    int fd_p = -1, fd_q = -1;

    if (!ct || !ct->pem_dir) return 0;

    /* Try new format first: primes/03072/p.prime */
    snprintf(path_p, sizeof(path_p), "%s/primes/03072/p.prime", ct->pem_dir);
    snprintf(path_q, sizeof(path_q), "%s/primes/03072/q.prime", ct->pem_dir);

    /* Fallback to old format: primes/prime-3072-p.bin */
    if (stat(path_p, &st) != 0) {
        snprintf(path_p, sizeof(path_p), "%s/primes/prime-3072-p.bin", ct->pem_dir);
        snprintf(path_q, sizeof(path_q), "%s/primes/prime-3072-q.bin", ct->pem_dir);
    }

    /* Check if both files exist */
    if (stat(path_p, &st) != 0) {
        return 0;  /* External primes not available */
    }
    ct->primes_file_size = st.st_size;

    if (stat(path_q, &st) != 0 || (size_t)st.st_size != ct->primes_file_size) {
        return 0;
    }

    ct->primes_count = ct->primes_file_size / PRIME_SIZE_3072;
    if (ct->primes_count == 0) {
        return 0;
    }

    /* Memory-map prime P file */
    fd_p = open(path_p, O_RDONLY);
    if (fd_p < 0) {
        return 0;
    }

    ct->primes_p = mmap(NULL, ct->primes_file_size, PROT_READ, MAP_PRIVATE, fd_p, 0);
    close(fd_p);

    if (ct->primes_p == MAP_FAILED) {
        ct->primes_p = NULL;
        return 0;
    }

    /* Memory-map prime Q file */
    fd_q = open(path_q, O_RDONLY);
    if (fd_q < 0) {
        munmap(ct->primes_p, ct->primes_file_size);
        ct->primes_p = NULL;
        return 0;
    }

    ct->primes_q = mmap(NULL, ct->primes_file_size, PROT_READ, MAP_PRIVATE, fd_q, 0);
    close(fd_q);

    if (ct->primes_q == MAP_FAILED) {
        munmap(ct->primes_p, ct->primes_file_size);
        ct->primes_p = NULL;
        ct->primes_q = NULL;
        return 0;
    }

    ct->use_external_primes = 1;

    /* Also set global pointers for use in generate_cert() */
    g_primes_p = ct->primes_p;
    g_primes_q = ct->primes_q;
    g_primes_count = ct->primes_count;
    g_use_external_primes = 1;

#ifdef DEBUG
    fprintf(stderr, "[DEBUG] External primes loaded: count=%zu\n", g_primes_count);
#endif

    return 1;
}

void cert_unload_primes(cert_tlstor_t *ct) {
    if (!ct) return;

    if (ct->primes_p && ct->primes_file_size > 0) {
        munmap(ct->primes_p, ct->primes_file_size);
        ct->primes_p = NULL;
    }
    if (ct->primes_q && ct->primes_file_size > 0) {
        munmap(ct->primes_q, ct->primes_file_size);
        ct->primes_q = NULL;
    }
    ct->use_external_primes = 0;

    /* Clear global pointers */
    g_primes_p = NULL;
    g_primes_q = NULL;
    g_primes_count = 0;
    g_use_external_primes = 0;
}

EVP_PKEY *cert_rsa_from_primes(cert_tlstor_t *ct) {
    if (!ct || !ct->use_external_primes || !ct->primes_p || !ct->primes_q) {
        return NULL;
    }

    EVP_PKEY *key = NULL;
    BIGNUM *n = NULL, *e = NULL, *d = NULL;
    BIGNUM *p = NULL, *q = NULL;
    BIGNUM *dmp1 = NULL, *dmq1 = NULL, *iqmp = NULL;
    BIGNUM *p1 = NULL, *q1 = NULL, *phi = NULL;
    BN_CTX *bn_ctx = NULL;

    /* Select random prime indices */
    size_t idx_p = rand() % ct->primes_count;
    size_t idx_q = rand() % ct->primes_count;

    /* Ensure p != q by using different indices */
    if (idx_p == idx_q) {
        idx_q = (idx_q + 1) % ct->primes_count;
    }

    /* Get pointers to the primes */
    const unsigned char *prime_p_data = ct->primes_p + (idx_p * PRIME_SIZE_3072);
    const unsigned char *prime_q_data = ct->primes_q + (idx_q * PRIME_SIZE_3072);

    /* Create BIGNUMs from the raw prime data */
    p = BN_bin2bn(prime_p_data, PRIME_SIZE_3072, NULL);
    q = BN_bin2bn(prime_q_data, PRIME_SIZE_3072, NULL);
    if (!p || !q) goto cleanup;

    /* Ensure p > q (swap if necessary) */
    if (BN_cmp(p, q) < 0) {
        BIGNUM *tmp = p;
        p = q;
        q = tmp;
    }

    /* Allocate remaining BIGNUMs */
    n = BN_new();
    e = BN_new();
    d = BN_new();
    dmp1 = BN_new();
    dmq1 = BN_new();
    iqmp = BN_new();
    p1 = BN_new();
    q1 = BN_new();
    phi = BN_new();
    bn_ctx = BN_CTX_new();

    if (!n || !e || !d || !dmp1 || !dmq1 || !iqmp || !p1 || !q1 || !phi || !bn_ctx) {
        goto cleanup;
    }

    /* Set public exponent e = 65537 (RSA_F4) */
    BN_set_word(e, RSA_F4);

    /* Calculate n = p * q */
    if (!BN_mul(n, p, q, bn_ctx)) goto cleanup;

    /* Calculate phi = (p-1) * (q-1) */
    if (!BN_sub(p1, p, BN_value_one())) goto cleanup;
    if (!BN_sub(q1, q, BN_value_one())) goto cleanup;
    if (!BN_mul(phi, p1, q1, bn_ctx)) goto cleanup;

    /* Calculate d = e^(-1) mod phi */
    if (!BN_mod_inverse(d, e, phi, bn_ctx)) goto cleanup;

    /* Calculate CRT parameters */
    if (!BN_mod(dmp1, d, p1, bn_ctx)) goto cleanup;  /* d mod (p-1) */
    if (!BN_mod(dmq1, d, q1, bn_ctx)) goto cleanup;  /* d mod (q-1) */
    if (!BN_mod_inverse(iqmp, q, p, bn_ctx)) goto cleanup;  /* q^(-1) mod p */

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    /* OpenSSL 3.0+ API using EVP_PKEY_fromdata */
    {
        OSSL_PARAM_BLD *bld = OSSL_PARAM_BLD_new();
        OSSL_PARAM *params = NULL;
        EVP_PKEY_CTX *ctx = NULL;

        if (!bld) goto cleanup;

        /* Build RSA key parameters */
        if (!OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_N, n) ||
            !OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_E, e) ||
            !OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_D, d) ||
            !OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_FACTOR1, p) ||
            !OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_FACTOR2, q) ||
            !OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_EXPONENT1, dmp1) ||
            !OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_EXPONENT2, dmq1) ||
            !OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_COEFFICIENT1, iqmp)) {
            OSSL_PARAM_BLD_free(bld);
            goto cleanup;
        }

        params = OSSL_PARAM_BLD_to_param(bld);
        OSSL_PARAM_BLD_free(bld);

        if (!params) goto cleanup;

        ctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
        if (!ctx) {
            OSSL_PARAM_free(params);
            goto cleanup;
        }

        if (EVP_PKEY_fromdata_init(ctx) <= 0 ||
            EVP_PKEY_fromdata(ctx, &key, EVP_PKEY_KEYPAIR, params) <= 0) {
            key = NULL;
        }

        EVP_PKEY_CTX_free(ctx);
        OSSL_PARAM_free(params);
    }
#elif OPENSSL_API_1_1
    /* OpenSSL 1.1.x API */
    {
        RSA *rsa = RSA_new();
        if (!rsa) goto cleanup;

        /* Transfer ownership of BIGNUMs to RSA structure */
        if (!RSA_set0_key(rsa, n, e, d)) {
            RSA_free(rsa);
            goto cleanup;
        }
        n = e = d = NULL;  /* Ownership transferred */

        if (!RSA_set0_factors(rsa, p, q)) {
            RSA_free(rsa);
            goto cleanup;
        }
        p = q = NULL;  /* Ownership transferred */

        if (!RSA_set0_crt_params(rsa, dmp1, dmq1, iqmp)) {
            RSA_free(rsa);
            goto cleanup;
        }
        dmp1 = dmq1 = iqmp = NULL;  /* Ownership transferred */

        key = EVP_PKEY_new();
        if (!key || !EVP_PKEY_assign_RSA(key, rsa)) {
            RSA_free(rsa);
            EVP_PKEY_free(key);
            key = NULL;
            goto cleanup;
        }
    }
#else
    /* OpenSSL 1.0.x API */
    {
        RSA *rsa = RSA_new();
        if (!rsa) goto cleanup;

        rsa->n = n; rsa->e = e; rsa->d = d;
        rsa->p = p; rsa->q = q;
        rsa->dmp1 = dmp1; rsa->dmq1 = dmq1; rsa->iqmp = iqmp;
        n = e = d = p = q = dmp1 = dmq1 = iqmp = NULL;

        key = EVP_PKEY_new();
        if (!key || !EVP_PKEY_assign_RSA(key, rsa)) {
            RSA_free(rsa);
            EVP_PKEY_free(key);
            key = NULL;
            goto cleanup;
        }
    }
#endif

cleanup:
    BN_free(n);
    BN_free(e);
    BN_free(d);
    BN_free(p);
    BN_free(q);
    BN_free(dmp1);
    BN_free(dmq1);
    BN_free(iqmp);
    BN_free(p1);
    BN_free(q1);
    BN_free(phi);
    BN_CTX_free(bn_ctx);

    return key;
}

/* ============== Key Generation Functions ============== */

/* Generate RSA-3072 key with external primes fallback to standard generation */
EVP_PKEY *generate_rsa_key_fast(cert_tlstor_t *ct) {
    EVP_PKEY *key = NULL;

    /* Try external primes first (fast path: ~1ms vs ~50ms) */
    if (ct && ct->use_external_primes) {
        key = cert_rsa_from_primes(ct);
        if (key) return key;
    }

    /* Fallback to standard RSA generation */
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    key = EVP_RSA_gen(3072);
#elif OPENSSL_API_1_1
    EVP_PKEY_CTX *pkey_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (pkey_ctx) {
        if (EVP_PKEY_keygen_init(pkey_ctx) > 0 &&
            EVP_PKEY_CTX_set_rsa_keygen_bits(pkey_ctx, 3072) > 0) {
            EVP_PKEY_keygen(pkey_ctx, &key);
        }
        EVP_PKEY_CTX_free(pkey_ctx);
    }
#else
    BIGNUM *exp = BN_new();
    if (exp) {
        BN_set_word(exp, RSA_F4);
        RSA *rsa = RSA_new();
        if (rsa && RSA_generate_key_ex(rsa, 3072, exp, NULL) >= 0) {
            key = EVP_PKEY_new();
            if (!key || !EVP_PKEY_assign_RSA(key, rsa)) {
                RSA_free(rsa);
                EVP_PKEY_free(key);
                key = NULL;
            }
        } else {
            RSA_free(rsa);
        }
        BN_free(exp);
    }
#endif

    return key;
}

/* Generate ECDSA P-256 key */
EVP_PKEY *generate_ecdsa_p256_key(void) {
    EVP_PKEY *key = NULL;

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    key = EVP_EC_gen("P-256");
#else
    EVP_PKEY_CTX *pkey_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (pkey_ctx) {
        if (EVP_PKEY_keygen_init(pkey_ctx) > 0 &&
            EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pkey_ctx, NID_X9_62_prime256v1) > 0) {
            EVP_PKEY_keygen(pkey_ctx, &key);
        }
        EVP_PKEY_CTX_free(pkey_ctx);
    }
#endif

    return key;
}

/* Generate SM2 key (Chinese standard elliptic curve) */
EVP_PKEY *generate_sm2_key(void) {
    EVP_PKEY *key = NULL;

    EVP_PKEY_CTX *pkey_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (pkey_ctx) {
        if (EVP_PKEY_keygen_init(pkey_ctx) > 0) {
            /* Try SM2 curve first, fallback to P-256 if not available */
            int nid = OBJ_txt2nid("SM2");
            if (nid == NID_undef) {
                nid = NID_X9_62_prime256v1;
            }

            if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pkey_ctx, nid) > 0) {
                EVP_PKEY_keygen(pkey_ctx, &key);
            }
        }
        EVP_PKEY_CTX_free(pkey_ctx);
    }

    return key;
}

void run_benchmark(const cert_tlstor_t *ct, const char *cert)
{
    if (!ct || !ct->pem_dir) {
        return;
    }

    char *cert_file = NULL, *domain = NULL;
    struct stat st;
    struct timespec tm;
    float r_tm0 = 0.0, g_tm0 = 0.0, tm1;
    SSL_CTX *sslctx = NULL;

    printf("CERT_PATH: %s\n", ct->pem_dir);
    if (!ct->cachain) {
        printf("CA chain not loaded\n");
        goto quit;
    }

    const char *test_cert = cert ? cert : "_.bing.com";
    printf("CERT_FILE: ");
    
    if (asprintf(&cert_file, "%s/%s", ct->pem_dir, test_cert) < 0) {
        printf("Memory allocation failed\n");
        goto quit;
    }

    if (cert && stat(cert_file, &st) != 0) {
        printf("%s not found\n", cert);
        goto quit;
    }
    printf("%s\n", test_cert);

    if (asprintf(&domain, "%s", test_cert) < 0) {
        printf("Memory allocation failed for domain\n");
        goto quit;
    }
    
    if (domain[0] == '_') domain[0] = '*';

    for (int c = 1; c <= 10; c++) {
        get_time(&tm);
        for (int d = 0; d < 5; d++) {
            generate_cert(domain, ct->pem_dir, ct->issuer, ct->privkey, ct->cachain);
        }
        tm1 = elapsed_time_msec(tm) / 5.0;
        printf("%2d. generate cert to disk: %.3f ms\t", c, tm1);
        g_tm0 += tm1;

        get_time(&tm);
        for (int d = 0; d < 5; d++) {
            if (stat(cert_file, &st) == 0) {
                sslctx = create_child_sslctx(cert_file, ct->cachain);
                if (sslctx) {
                    if (sslctx_cache_insert_lockfree(test_cert, sslctx) < 0) {
                        SSL_CTX_free(sslctx);  /* Don't leak on cache full */
                    }
                }
            }
        }
        tm1 = elapsed_time_msec(tm) / 5.0;
        printf("load from disk: %.3f ms\n", tm1);
        r_tm0 += tm1;
    }
    
    printf("generate to disk average: %.3f ms\n", g_tm0 / 10.0);
    printf("  load from disk average: %.3f ms\n", r_tm0 / 10.0);

quit:
    free(cert_file);
    free(domain);
}

SSL_CTX* sslctx_tbl_get_ctx(const char *cert_name) {
    if (!cert_name) return NULL;
    return sslctx_cache_lookup_lockfree(cert_name);
}

int check_cert_expiration(const char *cert_path, time_t *expires_at) {
    FILE *fp = fopen(cert_path, "r");
    if (!fp) return -1;
    
    X509 *cert = PEM_read_X509(fp, NULL, NULL, NULL);
    fclose(fp);
    
    if (!cert) return -1;
    
    ASN1_TIME *not_after = X509_get_notAfter(cert);
    if (!not_after) {
        X509_free(cert);
        return -1;
    }
    
    int days, seconds;
    if (ASN1_TIME_diff(&days, &seconds, NULL, not_after)) {
        if (expires_at) {
            *expires_at = time(NULL) + days * 86400 + seconds;
        }
        X509_free(cert);
        return (days > 0 || (days == 0 && seconds > 0)) ? 1 : 0;
    }
    
    X509_free(cert);
    return -1;
}

void log_ssl_errors(const char *operation) {
    unsigned long err;
    char err_buf[256];
    
    while ((err = ERR_get_error()) != 0) {
        ERR_error_string_n(err, err_buf, sizeof(err_buf));
    }
}

void sslctx_tbl_cleanup_expired(void) {
    /* Use lock-free cache expiration with 24 hour timeout */
    cache_expire_old(86400);  /* 24 hours in seconds */
    cache_reclaim_expired();  /* Free entries past grace period */
}

size_t sslctx_tbl_memory_usage(void) {
    size_t total = 0;

    /* Estimate based on cache size */
    int cache_size = cache_get_size();
    int cache_used = cache_get_used();

    /* Each cache entry uses roughly sizeof(cache_entry_t) + name + SSL_CTX overhead */
    total += cache_size * sizeof(cache_entry_t);
    total += cache_used * (256 + 64 * 1024);  /* Avg name len + SSL_CTX estimate */

    return total;
}

void pregenerate_common_certs(cert_tlstor_t *ct) {
    const char *common_domains[] = {
        "google.com", "facebook.com", "amazon.com", "microsoft.com",
        "apple.com", "netflix.com", "youtube.com", "twitter.com",
        "instagram.com", "linkedin.com", "github.com", "stackoverflow.com",
        NULL
    };
    
    if (!ct || !ct->privkey || !ct->issuer) {
        return;
    }
    
    int i;
    for (i = 0; common_domains[i]; i++) {
        enqueue_cert_job(common_domains[i]);
    }
}

void print_cert_statistics(void) {
    printf("\n=== Certificate Statistics (Lock-Free) ===\n");
    printf("Cache entries: %d/%d\n", cache_get_used(), cache_get_size());
    printf("Cache hits: %d\n", stats_get_hit());
    printf("Cache misses: %d\n", stats_get_miss());
    printf("Cache purges: %d\n", stats_get_purge());
    printf("Certs generated: %d\n", stats_get_gen());
    printf("SSL sessions: %d\n", sslctx_tbl_get_sess_cnt());
    printf("SSL session hits: %d\n", sslctx_tbl_get_sess_hit());
    printf("SSL session misses: %d\n", sslctx_tbl_get_sess_miss());
    printf("Memory usage: %.2f MB\n", sslctx_tbl_memory_usage() / (1024.0 * 1024.0));
    printf("===========================================\n");
}

/*
 * Worker mode functions - use index_client instead of local cert_index
 */

int cert_enable_worker_mode(const char *master_socket) {
    if (!master_socket || strlen(master_socket) == 0) {
        log_msg(LGG_ERR, "[WORKER] Invalid master socket path");
        return -1;
    }

    strncpy(g_master_socket, master_socket, sizeof(g_master_socket) - 1);

    if (index_client_init(master_socket) < 0) {
        log_msg(LGG_ERR, "[WORKER] Failed to connect to index master at %s", master_socket);
        return -1;
    }

    g_worker_mode = 1;
    log_msg(LGG_INFO, "[WORKER] Worker mode enabled, connected to master at %s", master_socket);
    return 0;
}

void cert_disable_worker_mode(void) {
    if (g_worker_mode) {
        index_client_close();
        g_worker_mode = 0;
        g_master_socket[0] = '\0';
        log_msg(LGG_INFO, "[WORKER] Worker mode disabled");
    }
}

int cert_is_worker_mode(void) {
    return g_worker_mode;
}

/* Worker mode lookup - uses index_client */
int cert_worker_lookup(const char *domain, uint8_t *shard_id,
                       uint32_t *cert_id, uint64_t *expiry) {
    if (!g_worker_mode) {
        return -1;  /* Not in worker mode */
    }
    return index_client_lookup(domain, shard_id, cert_id, expiry);
}

/* Worker mode insert - uses index_client */
int cert_worker_insert(const char *domain, uint8_t shard_id,
                       uint32_t cert_id, uint64_t expiry) {
    if (!g_worker_mode) {
        return -1;  /* Not in worker mode */
    }
    return index_client_insert(domain, shard_id, cert_id, expiry);
}
