/* certs.c - SSL/TLS certificate management (refactored for lock-free operation) */

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>
#include <openssl/opensslv.h>

#include "../include/certs.h"
#include "../include/certs_cache.h"
#include "../include/certs_conn.h"
#include "../include/certs_gen.h"
#include "../include/certs_queue.h"
#include "../include/io_engine.h"
#include "../include/certs_stats.h"
#include "../include/logger.h"
#include "../include/util.h"
#include "../include/second_level_tlds.h"

#if defined(__GLIBC__) && !defined(__UCLIBC__)
#  include <malloc.h>
#endif

#if !OPENSSL_API_1_1
static pthread_mutex_t *locks;
#endif

static SSL_CTX *g_sslctx;
static tld_set_t *g_tld_set = NULL;  /* 2nd-level TLD set for wildcard detection */
extern char pixel_cert_pipe[PIXELSERV_MAX_PATH];  /* Defined in util.c */

/* Statistics functions using lock-free module */
inline int sslctx_tbl_get_cnt_total(void) { return cache_get_used(); }
inline int sslctx_tbl_get_cnt_hit(void) { return stats_get_hit(); }
inline int sslctx_tbl_get_cnt_miss(void) { return stats_get_miss(); }
inline int sslctx_tbl_get_cnt_purge(void) { return stats_get_purge(); }

inline int sslctx_tbl_get_sess_cnt(void) { return g_sslctx ? SSL_CTX_sess_number(g_sslctx) : 0; }
inline int sslctx_tbl_get_sess_hit(void) { return g_sslctx ? SSL_CTX_sess_hits(g_sslctx) : 0; }
inline int sslctx_tbl_get_sess_miss(void) { return g_sslctx ? SSL_CTX_sess_misses(g_sslctx) : 0; }
inline int sslctx_tbl_get_sess_purge(void) { return g_sslctx ? SSL_CTX_sess_cache_full(g_sslctx) : 0; }

/* Delegate to lock-free connection storage */
void conn_stor_init(int slots) {
    conn_stor_init_lockfree(slots);
}

conn_tlstor_struct *conn_stor_acquire(void) {
    conn_tlstor_struct *ret = conn_stor_acquire_lockfree();
    if (ret) {
        ret->tlsext_cb_arg = &ret->v;
    }
    return ret;
}

void conn_stor_relinq(conn_tlstor_struct *p) {
    conn_stor_relinq_lockfree(p);
}

void conn_stor_flush(void) {
    conn_stor_flush_lockfree();
}

/* SSL context table - delegates to lock-free cache */
void sslctx_tbl_init(int tbl_size) {
    if (tbl_size <= 0) return;
    cache_init(tbl_size);
    certs_stats_init();
}

void sslctx_tbl_cleanup(void) {
    /* Save cache state before shutdown for faster startup */
    /* NOTE: pem_dir is passed from caller - would need to be stored in global for access here
     * For now, this is handled at the pixelserv.c shutdown level */

    cert_gen_shutdown();
    cache_cleanup();
    conn_stor_cleanup_lockfree();
}

static SSL_CTX *create_child_sslctx(const char *full_pem_path, const STACK_OF(X509_INFO) *cachain);

/* Load SSL contexts from prefetch file */
void sslctx_tbl_load(const char *pem_dir, const STACK_OF(X509_INFO) *cachain) {
    char *fname = NULL, *line = NULL;
    size_t line_len = PIXELSERV_MAX_PATH;
    FILE *fp = NULL;

    if (!(line = malloc(line_len)) || !(fname = malloc(PIXELSERV_MAX_PATH))) {
        goto quit_load;
    }

    snprintf(fname, PIXELSERV_MAX_PATH, "%s/certs/prefetch", pem_dir);
    fp = fopen(fname, "r");
    if (!fp) {
        goto quit_load;  // FIX: fopen failed, fp is NULL - skip to cleanup
    }

    while (getline(&line, &line_len, fp) != -1) {
        char *cert_name = strtok(line, " \n\t");
        if (!cert_name) continue;

        snprintf(fname, PIXELSERV_MAX_PATH, "%s/certs/%s", pem_dir, cert_name);

        SSL_CTX *sslctx = create_child_sslctx(fname, cachain);
        if (sslctx) {
            cache_insert(cert_name, sslctx);
        }
    }

quit_load:
    // FIX: Proper cleanup - close file only if it was opened
    if (fp) {
        fclose(fp);
        fp = NULL;
    }
    if (fname) free(fname);
    if (line) free(line);

    /* Attempt to load cache index from previous session
     * This restores knowledge of which domains were recently cached,
     * allowing faster cache warm-up on startup */
    cache_load_from_disk(pem_dir, cachain);
}

SSL_CTX *sslctx_tbl_get_ctx(const char *cert_name) {
    return cache_lookup(cert_name);
}

#if !OPENSSL_API_1_1
static void ssl_lock_cb(int mode, int type, const char *file, int line) {
    (void)file;
    (void)line;
    if (mode & CRYPTO_LOCK)
        pthread_mutex_lock(&(locks[type]));
    else
        pthread_mutex_unlock(&(locks[type]));
}

static void ssl_thread_id(CRYPTO_THREADID *id) {
    CRYPTO_THREADID_set_numeric(id, (unsigned long)pthread_self());
}
#endif

void ssl_init_locks(void) {
#if !OPENSSL_API_1_1
    int num_locks = CRYPTO_num_locks();
    locks = OPENSSL_malloc(num_locks * sizeof(pthread_mutex_t));
    if (!locks) return;

    for (int i = 0; i < num_locks; i++) {
        pthread_mutex_init(&(locks[i]), NULL);
    }

    CRYPTO_THREADID_set_callback(ssl_thread_id);
    CRYPTO_set_locking_callback(ssl_lock_cb);
#endif
}

void ssl_free_locks(void) {
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

/* Password callback for encrypted private keys */
static int pem_passwd_cb(char *buf, int size, int rwflag, void *u) {
    (void)rwflag;
    int rv = 0, fp;
    char *fname = NULL;

    if (asprintf(&fname, "%s/rootCA/ca.key.passphrase", (char *)u) < 0)
        goto quit_cb;

    if ((fp = open(fname, O_RDONLY)) < 0) {
        /* No passphrase file */
    } else {
        rv = read(fp, buf, size - 1);
        close(fp);
        if (rv > 0 && buf[rv - 1] == '\n') {
            rv--;
        }
        if (rv > 0) buf[rv] = '\0';
    }

quit_cb:
    free(fname);
    return rv;
}

/* Helper: load certificate from file */
static X509 *load_cert_from_file(const char *filepath) {
    FILE *fp = fopen(filepath, "r");
    if (!fp) return NULL;

    X509 *cert = PEM_read_X509(fp, NULL, NULL, NULL);
    fclose(fp);
    return cert;
}

/* Helper: load private key from file */
static EVP_PKEY *load_key_from_file(const char *filepath, const char *pem_dir) {
    FILE *fp = fopen(filepath, "r");
    if (!fp) return NULL;

    EVP_PKEY *key = PEM_read_PrivateKey(fp, NULL, pem_passwd_cb, (void *)pem_dir);
    fclose(fp);
    return key;
}

/* Helper: build certificate chain from file */
static STACK_OF(X509_INFO) *build_chain_from_file(const char *filepath) {
    FILE *fp = fopen(filepath, "r");
    if (!fp) return NULL;

    if (fseek(fp, 0L, SEEK_END) < 0) {
        fclose(fp);
        return NULL;
    }

    long fsz = ftell(fp);
    if (fsz < 0 || fseek(fp, 0L, SEEK_SET) < 0) {
        fclose(fp);
        return NULL;
    }

    char *cafile = malloc(fsz + 1);
    if (!cafile) {
        fclose(fp);
        return NULL;
    }

    if (fread(cafile, 1, fsz, fp) != (size_t)fsz) {
        free(cafile);
        fclose(fp);
        return NULL;
    }
    fclose(fp);

    BIO *bioin = BIO_new_mem_buf(cafile, fsz);
    if (!bioin) {
        free(cafile);
        return NULL;
    }

    STACK_OF(X509_INFO) *chain = PEM_X509_INFO_read_bio(bioin, NULL, NULL, NULL);
    BIO_free(bioin);
    free(cafile);

    return chain;
}

void cert_tlstor_init(const char *pem_dir, cert_tlstor_t *ct) {
    char cert_file[PIXELSERV_MAX_PATH];
    char key_file[PIXELSERV_MAX_PATH];
    struct stat st;

    memset(ct, 0, sizeof(cert_tlstor_t));
    ct->pem_dir = pem_dir;
    ct->ca_type = CA_TYPE_ROOT;
    ct->use_subca_for_signing = 0;

    /*
     * Directory structure:
     *   pem_dir/rootCA/root/rootca.crt           - Root CA certificate (required)
     *   pem_dir/rootCA/root/rootca.key           - Root CA private key (optional if SubCA used)
     *   pem_dir/rootCA/subCA-RSA/subca.crt       - RSA SubCA certificate (optional)
     *   pem_dir/rootCA/subCA-RSA/subca.key       - RSA SubCA private key
     *   pem_dir/rootCA/subCA-RSA/subca.cs.crt    - RSA CrossSigned cert (optional)
     *   pem_dir/rootCA/subCA-ECDSA/subca.crt     - ECDSA SubCA certificate (optional)
     *   pem_dir/rootCA/subCA-ECDSA/subca.key     - ECDSA SubCA private key
     *   pem_dir/rootCA/subCA-ECDSA/subca.cs.crt  - ECDSA CrossSigned cert (optional)
     *   pem_dir/rootCA/subCA-SM2/subca.crt       - SM2 SubCA certificate (optional)
     *   pem_dir/rootCA/subCA-SM2/subca.key       - SM2 SubCA private key
     *   pem_dir/rootCA/subCA-SM2/subca.cs.crt    - SM2 CrossSigned cert (optional)
     *   pem_dir/certs/                           - Generated domain certificates
     *   pem_dir/primes/03072/                    - External RSA-3072 primes
     *   pem_dir/config/                          - Config files (TLD list etc.)
     *
     * SubCA Priority: RSA > ECDSA > SM2 (first found with valid key is used)
     */

    /* Step 1: Load Root CA certificate */
    snprintf(cert_file, PIXELSERV_MAX_PATH, "%s/rootCA/root/rootca.crt", pem_dir);
    X509 *root_cert = load_cert_from_file(cert_file);
    if (!root_cert) {
        return;
    }

    /* Step 2: Load Root CA private key (may be NULL for Offline RootCA setup) */
    snprintf(key_file, PIXELSERV_MAX_PATH, "%s/rootCA/root/rootca.key", pem_dir);
    EVP_PKEY *root_key = load_key_from_file(key_file, pem_dir);
    int offline_rootca = (root_key == NULL);

    if (offline_rootca) {
        log_msg(LGG_INFO, "RootCA private key not found - operating in Offline RootCA mode");
    }

    /* Step 3: Check for SubCA (try RSA, ECDSA, SM2 in order) */
    const char *subca_types[] = {"subCA-RSA", "subCA-ECDSA", "subCA-SM2", NULL};
    for (int i = 0; subca_types[i] != NULL && !ct->use_subca_for_signing; i++) {
        snprintf(cert_file, PIXELSERV_MAX_PATH, "%s/rootCA/%s/subca.crt", pem_dir, subca_types[i]);
        snprintf(key_file, PIXELSERV_MAX_PATH, "%s/rootCA/%s/subca.key", pem_dir, subca_types[i]);

        if (stat(cert_file, &st) == 0) {
            X509 *subca_cert = load_cert_from_file(cert_file);
            EVP_PKEY *subca_key = load_key_from_file(key_file, pem_dir);

            if (subca_cert && subca_key) {
                ct->subca_cert = subca_cert;
                ct->subca_privkey = subca_key;
                ct->subca_issuer = X509_NAME_dup(X509_get_subject_name(ct->subca_cert));
                ct->ca_type = CA_TYPE_SUBCA;
                ct->use_subca_for_signing = 1;

                if (offline_rootca) {
                    log_msg(LGG_NOTICE, "Using %s for certificate signing (RootCA key offline)", subca_types[i]);
                } else {
                    log_msg(LGG_INFO, "Using %s for certificate signing", subca_types[i]);
                }

                /* Check for CrossSigned cert in same folder */
                char cs_file[PIXELSERV_MAX_PATH];
                snprintf(cs_file, PIXELSERV_MAX_PATH, "%s/rootCA/%s/subca.cs.crt", pem_dir, subca_types[i]);
                if (stat(cs_file, &st) == 0) {
                    ct->crosssigned_cert = load_cert_from_file(cs_file);
                    if (ct->crosssigned_cert) {
                        ct->ca_type = CA_TYPE_SUBCA_CROSSSIGNED;
                        ct->crosssigned_chain = build_chain_from_file(cs_file);
                        log_msg(LGG_INFO, "CrossSigned certificate loaded for %s", subca_types[i]);
                    }
                }
            } else {
                if (subca_cert) {
                    log_msg(LGG_DEBUG, "%s certificate found but private key missing or invalid", subca_types[i]);
                    X509_free(subca_cert);
                }
                if (subca_key) {
                    EVP_PKEY_free(subca_key);
                }
            }
        }
    }

    /* Step 4: If no SubCA found and RootCA key available, use RootCA directly */
    if (!ct->use_subca_for_signing && !offline_rootca) {
        log_msg(LGG_ERR, "Offline RootCA mode requires SubCA private key for signing");
        log_msg(LGG_ERR, "  Checked: subCA-RSA, subCA-ECDSA, subCA-SM2");
    }

    /* Step 5: Set issuer and signing key based on configuration */
    if (ct->use_subca_for_signing && ct->subca_cert && ct->subca_privkey) {
        ct->issuer = X509_NAME_dup(X509_get_subject_name(ct->subca_cert));
        ct->privkey = ct->subca_privkey;
    } else {
        ct->issuer = X509_NAME_dup(X509_get_subject_name(root_cert));
        ct->privkey = root_key;
    }

    /* Step 5b: Validate that we have a signing key */
    if (!ct->privkey) {
        log_msg(LGG_ERR, "FATAL: No signing key available - certificate generation disabled");
        log_msg(LGG_ERR, "  For Offline RootCA mode, ensure rootCA/subCA-*/subca.key is present");
        log_msg(LGG_ERR, "  For normal mode, ensure rootCA/root/rootca.key is present");
    }

    /* Step 6: Build the certificate chain */
    snprintf(cert_file, PIXELSERV_MAX_PATH, "%s/rootCA/root/rootca.crt", pem_dir);

    if (ct->ca_type >= CA_TYPE_SUBCA && ct->subca_cert) {
        ct->cachain = sk_X509_INFO_new_null();
        if (ct->cachain) {
            X509_INFO *subca_info = X509_INFO_new();
            if (subca_info) {
                subca_info->x509 = X509_dup(ct->subca_cert);
                sk_X509_INFO_push(ct->cachain, subca_info);
            }

            X509_INFO *root_info = X509_INFO_new();
            if (root_info) {
                root_info->x509 = X509_dup(root_cert);
                sk_X509_INFO_push(ct->cachain, root_info);
            }
        }
    } else {
        ct->cachain = build_chain_from_file(cert_file);
    }

    X509_free(root_cert);
    if (ct->use_subca_for_signing && root_key) {
        EVP_PKEY_free(root_key);
    }

    /* Step 7: Load external primes */
    cert_gen_load_primes(ct);

    /* Step 8: Initialize certificate generator */
    cert_gen_init(ct);

    /* Step 9: Generate universal IP certificate if needed */
    char universal_ip_file[PIXELSERV_MAX_PATH];
    snprintf(universal_ip_file, sizeof(universal_ip_file), "%s/certs/universal_ips.pem", pem_dir);
    if (stat(universal_ip_file, &st) != 0 && ct->privkey && ct->issuer) {
        cert_gen_universal_ip(pem_dir, ct->issuer, ct->privkey, ct->cachain);
    }

    /* Step 10: Load 2nd-level TLD list for correct wildcard detection */
    if (!g_tld_set) {
        g_tld_set = tld_set_create();
        if (g_tld_set) {
            char tld_file[PIXELSERV_MAX_PATH];
            snprintf(tld_file, sizeof(tld_file), "%s/config/second-level-tlds.conf", pem_dir);
            int loaded = tld_set_load_from_file(g_tld_set, tld_file);
            if (loaded <= 0) {
                log_msg(LGG_INFO, "No TLD file loaded, using heuristic for wildcard detection");
            }
        }
    }

    /* Step 11: Start certificate worker threads (lock-free) */
    /* NOTE: Store thread IDs instead of detaching - allows proper cleanup on shutdown */
    ct->worker_threads = malloc(4 * sizeof(pthread_t));
    if (ct->worker_threads) {
        ct->num_workers = 0;
        for (int i = 0; i < 4; i++) {
            if (pthread_create(&ct->worker_threads[i], NULL, cert_gen_worker, ct) == 0) {
                ct->num_workers++;
            }
        }
    }
}

void cert_tlstor_cleanup(cert_tlstor_t *c) {
    if (!c) return;

    cert_gen_shutdown();

    /* FIX: Wait for all worker threads to finish (instead of letting them detached) */
    if (c->worker_threads && c->num_workers > 0) {
        for (int i = 0; i < c->num_workers; i++) {
            pthread_join(c->worker_threads[i], NULL);
        }
        free(c->worker_threads);
        c->worker_threads = NULL;
        c->num_workers = 0;
    }

    if (c->cachain) {
        sk_X509_INFO_pop_free(c->cachain, X509_INFO_free);
        c->cachain = NULL;
    }

    if (c->issuer) {
        X509_NAME_free(c->issuer);
        c->issuer = NULL;
    }

    if (c->privkey && c->privkey != c->subca_privkey) {
        EVP_PKEY_free(c->privkey);
    }
    c->privkey = NULL;

    if (c->subca_cert) {
        X509_free(c->subca_cert);
        c->subca_cert = NULL;
    }

    if (c->subca_privkey) {
        EVP_PKEY_free(c->subca_privkey);
        c->subca_privkey = NULL;
    }

    if (c->subca_issuer) {
        X509_NAME_free(c->subca_issuer);
        c->subca_issuer = NULL;
    }

    if (c->crosssigned_cert) {
        X509_free(c->crosssigned_cert);
        c->crosssigned_cert = NULL;
    }

    if (c->crosssigned_chain) {
        sk_X509_INFO_pop_free(c->crosssigned_chain, X509_INFO_free);
        c->crosssigned_chain = NULL;
    }

    cert_gen_unload_primes(c);

    /* Cleanup TLD set */
    if (g_tld_set) {
        tld_set_destroy(g_tld_set);
        g_tld_set = NULL;
    }

    memset(c, 0, sizeof(*c));
}

/* Certificate generator main thread - reads from named pipe */
void *cert_generator(void *ptr) {
    int idle = 0;
    cert_tlstor_t *ct = (cert_tlstor_t *)ptr;

    char buf[PIXELSERV_MAX_SERVER_NAME * 4 + 1];
    char *half_token = buf + PIXELSERV_MAX_SERVER_NAME * 4;
    buf[PIXELSERV_MAX_SERVER_NAME * 4] = '\0';

    int fd = open(pixel_cert_pipe, O_RDONLY | O_NONBLOCK);
    srand((unsigned int)time(NULL));

    /* Create I/O engine for monitoring named pipe */
    io_engine_t *io_engine = io_engine_create(8, 1024);
    io_result_t io_results[8];

    while (!cert_queue_is_shutdown()) {
        if (fd == -1) {
            sleep(1);
            fd = open(pixel_cert_pipe, O_RDONLY | O_NONBLOCK);
            continue;
        }

        memset(buf, 0, sizeof(buf));

        /* Register pipe with I/O engine if not already registered */
        static _Atomic int fd_registered = -1;
        int old_fd = atomic_load(&fd_registered);
        if (fd != old_fd) {
            io_event_t event = {.fd = fd, .events = IO_IN, .user_data = 0};
            if (io_engine_add(io_engine, &event) < 0) {
                close(fd);
                fd = -1;
                continue;
            }
            atomic_store(&fd_registered, fd);
        }

        /* Wait for data on pipe with same timeout as poll (1000 * PIXEL_SSL_SESS_TIMEOUT / 4) */
        int timeout_ms = 1000 * PIXEL_SSL_SESS_TIMEOUT / 4;
        int ret = io_engine_wait(io_engine, io_results, timeout_ms);

        if (ret <= 0) {
#if OPENSSL_VERSION_NUMBER >= 0x30400000L
            SSL_CTX_flush_sessions_ex(g_sslctx, time(NULL));
#else
            SSL_CTX_flush_sessions(g_sslctx, time(NULL));
#endif
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
        size_t buf_remaining = (half_len < PIXELSERV_MAX_SERVER_NAME * 4)
                             ? (PIXELSERV_MAX_SERVER_NAME * 4 - half_len) : 0;
        ssize_t cnt = (buf_remaining > 0) ? read(fd, buf + half_len, buf_remaining) : 0;
        if (cnt == 0) {
            close(fd);
            fd = open(pixel_cert_pipe, O_RDONLY | O_NONBLOCK);
            continue;
        }

        if (cnt < 0) continue;

        if ((size_t)cnt < buf_remaining) {
            buf[cnt + half_len] = '\0';
            half_token = buf + PIXELSERV_MAX_SERVER_NAME * 4;
        } else {
            size_t i = 1;
            for (i = 1; buf[PIXELSERV_MAX_SERVER_NAME * 4 - i] != ':' && i < strlen(buf); i++)
                ;
            half_token = buf + PIXELSERV_MAX_SERVER_NAME * 4 - i + 1;
            buf[PIXELSERV_MAX_SERVER_NAME * 4 - i + 1] = '\0';
        }

        if (!ct->privkey || !ct->issuer) continue;

        char *p_buf, *p_buf_sav = NULL;
        p_buf = strtok_r(buf, ":", &p_buf_sav);
        while (p_buf != NULL) {
            char cert_file[PIXELSERV_MAX_PATH];
            struct stat st;

            // SECURITY: Validate cert name - reject path traversal attempts
            // Only allow alphanumeric, dots, hyphens, underscores (no slashes, no ..)
            int valid_name = 1;
            for (const char *c = p_buf; *c && valid_name; ++c) {
                if (!(isalnum((unsigned char)*c) || *c == '.' || *c == '-' || *c == '_')) {
                    valid_name = 0;  // Reject invalid characters
                }
            }

            // Also reject names starting with dot (hidden files)
            if (valid_name && p_buf[0] == '.') {
                valid_name = 0;
            }

            // Reject if contains ".." (path traversal)
            if (valid_name && strstr(p_buf, "..")) {
                valid_name = 0;
            }

            if (valid_name) {
                snprintf(cert_file, PIXELSERV_MAX_PATH, "%s/certs/%s", ct->pem_dir, p_buf);
                if (stat(cert_file, &st) != 0) {
                    cert_gen_enqueue(p_buf);
                }
            }

            p_buf = strtok_r(NULL, ":", &p_buf_sav);
        }

#if OPENSSL_VERSION_NUMBER >= 0x30400000L
        SSL_CTX_flush_sessions_ex(g_sslctx, time(NULL));
#else
        SSL_CTX_flush_sessions(g_sslctx, time(NULL));
#endif
    }

    /* Cleanup I/O engine */
    if (io_engine) {
        io_engine_destroy(io_engine);
    }

    if (fd >= 0) close(fd);
    return NULL;
}

/* TLS callbacks */
#ifdef TLS1_3_VERSION
static const unsigned char *get_server_name(SSL *s, size_t *len) {
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
#define CB_OK 1
#define CB_ERR 0
#else
static int tls_servername_cb(SSL *ssl, int *ad, void *arg) {
#define CB_OK 0
#define CB_ERR SSL_TLSEXT_ERR_ALERT_FATAL
#endif
    (void)ad;
    int rv = CB_OK;
    tlsext_cb_arg_struct *cbarg = (tlsext_cb_arg_struct *)arg;
    char full_pem_path[PIXELSERV_MAX_PATH + 16];  /* Extra space for "/certs/" suffix */
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

    snprintf(full_pem_path, sizeof(full_pem_path), "%s/certs/", cbarg->tls_pem);
    len = strlen(full_pem_path);

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
        } else {
            rv = CB_ERR;
            goto quit_cb;
        }
    }

    /* Check for IP address - use universal IP cert */
    if (cert_gen_is_ip(srv_name)) {
        char universal_ip_path[PIXELSERV_MAX_PATH];
        snprintf(universal_ip_path, sizeof(universal_ip_path), "%s/certs/universal_ips.pem", cbarg->tls_pem);

        struct stat st;
        if (stat(universal_ip_path, &st) == 0) {
            SSL_CTX *ip_ctx = create_child_sslctx(universal_ip_path, cbarg->cachain);
            if (ip_ctx) {
                SSL_set_SSL_CTX(ssl, ip_ctx);
                cbarg->status = SSL_HIT;
                goto quit_cb;
            }
        }
    }

    /* Determine certificate name
     * Wildcard logic:
     * - example.com (1 dot) → exact match
     * - example.co.uk (2 dots, ccTLD) → wildcard _.example.co.uk
     * - www.quelle.de (2 dots) → wildcard _.quelle.de
     * - www.example.co.uk (3 dots) → wildcard _.example.co.uk
     * - mysite.github.io (2 dots, 2nd-level TLD) → wildcard _.mysite.github.io
     * - 192.168.1.1 (IP address) → exact match (handled earlier)
     *
     * For wildcards: strip first subdomain, but don't strip if it would leave just a TLD
     * Uses TLD set if loaded, otherwise falls back to heuristic
     */
    int dot_count = 0;
    const char *dot_pos = strchr(srv_name, '.');
    while (dot_pos) {
        dot_count++;
        dot_pos = strchr(dot_pos + 1, '.');
    }

    const char *pem_file;
    if (dot_count <= 1) {
        /* Exact match: localhost, example.com */
        pem_file = srv_name;
        strncat(full_pem_path, srv_name, PIXELSERV_MAX_PATH - len);
        len += strlen(srv_name);
    } else {
        /* Wildcard mode for 2+ dots */
        const char *first_dot = strchr(srv_name, '.');
        const char *remainder = first_dot + 1;  /* e.g., "quelle.de" or "github.io" */

        /* Check if remainder is a 2nd-level TLD (e.g., "co.uk", "github.io", "blogspot.com")
         * Priority: TLD set lookup > heuristic fallback */
        int remainder_is_tld = 0;

        if (g_tld_set && tld_set_count(g_tld_set) > 0) {
            /* Use TLD set for accurate detection */
            remainder_is_tld = tld_set_contains(g_tld_set, remainder);
        } else {
            /* Heuristic fallback: short first part (≤3 chars) + 2-char suffix */
            const char *remainder_dot = strchr(remainder, '.');
            if (remainder_dot) {
                size_t first_part_len = (size_t)(remainder_dot - remainder);
                size_t suffix_len = strlen(remainder_dot + 1);
                remainder_is_tld = (first_part_len <= 3 && suffix_len == 2);
            }
        }

        pem_file = full_pem_path + strlen(full_pem_path);
        strncat(full_pem_path, "_", PIXELSERV_MAX_PATH - len);
        len += 1;

        if (remainder_is_tld) {
            /* Remainder is a 2nd-level TLD, use full domain as wildcard base
             * example.co.uk → _.example.co.uk
             * mysite.github.io → _.mysite.github.io */
            strncat(full_pem_path, ".", PIXELSERV_MAX_PATH - len);
            len += 1;
            strncat(full_pem_path, srv_name, PIXELSERV_MAX_PATH - len);
            len += strlen(srv_name);
        } else {
            /* Normal case: strip first subdomain
             * www.quelle.de → _.quelle.de
             * www.example.co.uk → _.example.co.uk */
            strncat(full_pem_path, first_dot, PIXELSERV_MAX_PATH - len);
            len += strlen(first_dot);
        }
    }

    if (len > PIXELSERV_MAX_PATH) {
        rv = CB_ERR;
        goto quit_cb;
    }

    /* Try cache lookup first */
    SSL_CTX *cached_ctx = cache_lookup(pem_file);
    if (cached_ctx) {
        SSL_set_SSL_CTX(ssl, cached_ctx);

        X509 *cert = SSL_get_certificate(ssl);
        if (cert && X509_cmp_time(X509_get_notAfter(cert), NULL) > 0) {
            cbarg->status = SSL_HIT;
            goto quit_cb;
        }

        /* Expired - regenerate */
        cbarg->status = SSL_ERR;
        remove(full_pem_path);
        goto submit_missing_cert;
    }

    /* Check if certificate file exists */
    struct stat st;
    if (stat(full_pem_path, &st) != 0) {
        cbarg->status = SSL_MISS;

        struct timespec delay = {0, 300 * 1000000};
        nanosleep(&delay, NULL);

    submit_missing_cert:
        cert_gen_enqueue(pem_file);
        rv = CB_ERR;
        goto quit_cb;
    }

    /* Load and cache the certificate */
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
        SSL_CTX_free(sslctx);
        remove(full_pem_path);
        goto submit_missing_cert;
    }

    if (cache_insert(pem_file, sslctx) < 0) {
        /* Cache full, but still serve the cert */
    }

    cbarg->status = SSL_HIT;

quit_cb:
    return rv;
}

static SSL_CTX *create_child_sslctx(const char *full_pem_path, const STACK_OF(X509_INFO) *cachain) {
    SSL_CTX *sslctx = SSL_CTX_new(TLS_server_method());
    if (!sslctx) {
        return NULL;
    }

#if OPENSSL_VERSION_NUMBER >= 0x10101000L
    int groups[] = {NID_X9_62_prime256v1, NID_secp384r1};
    SSL_CTX_set1_groups(sslctx, groups, sizeof(groups) / sizeof(groups[0]));
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

#ifdef SSL_OP_NO_TLSv1
    options |= SSL_OP_NO_TLSv1;
#endif

    SSL_CTX_set_options(sslctx, options);

    SSL_CTX_set_session_cache_mode(sslctx, SSL_SESS_CACHE_NO_AUTO_CLEAR | SSL_SESS_CACHE_SERVER);
    SSL_CTX_set_timeout(sslctx, PIXEL_SSL_SESS_TIMEOUT);
    SSL_CTX_sess_set_cache_size(sslctx, 1);

    if (SSL_CTX_set_cipher_list(sslctx, PIXELSERV_CIPHER_LIST) <= 0) {
        /* Log error */
    }

#ifdef TLS1_3_VERSION
    SSL_CTX_set_min_proto_version(sslctx, TLS1_1_VERSION);
    SSL_CTX_set_max_proto_version(sslctx, TLS1_3_VERSION);
    if (SSL_CTX_set_ciphersuites(sslctx, PIXELSERV_TLSV1_3_CIPHERS) <= 0) {
        /* Log error */
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

SSL_CTX *create_default_sslctx(const char *pem_dir) {
    (void)pem_dir;
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

#ifdef SSL_OP_NO_TLSv1
    options |= SSL_OP_NO_TLSv1;
#endif

    SSL_CTX_set_options(g_sslctx, options);
    SSL_CTX_sess_set_cache_size(g_sslctx, PIXEL_SSL_SESS_CACHE_SIZE);
    SSL_CTX_set_session_cache_mode(g_sslctx, SSL_SESS_CACHE_SERVER);
    SSL_CTX_set_timeout(g_sslctx, PIXEL_SSL_SESS_TIMEOUT);

    if (SSL_CTX_set_cipher_list(g_sslctx, PIXELSERV_CIPHER_LIST) <= 0) {
        /* Log error */
    }

#ifdef TLS1_3_VERSION
    SSL_CTX_set_min_proto_version(g_sslctx, TLS1_1_VERSION);
    SSL_CTX_set_max_proto_version(g_sslctx, TLS1_3_VERSION);
    SSL_CTX_set_max_early_data(g_sslctx, PIXEL_TLS_EARLYDATA_SIZE);
    SSL_CTX_set_client_hello_cb(g_sslctx, tls_clienthello_cb, NULL);
    if (SSL_CTX_set_ciphersuites(g_sslctx, PIXELSERV_TLSV1_3_CIPHERS) <= 0) {
        /* Log error */
    }
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

    if (getsockname(fd, (struct sockaddr *)&sin_addr, &sin_addr_len) != 0 ||
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

    return rv;
}

#ifdef TLS1_3_VERSION
char *read_tls_early_data(SSL *ssl, int *err) {
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

    return buf;

err_quit:
    free(buf);
    return NULL;
}
#endif

void run_benchmark(const cert_tlstor_t *ct, const char *cert) {
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

    if (asprintf(&cert_file, "%s/certs/%s", ct->pem_dir, test_cert) < 0) {
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
            cert_gen_create(domain, ct->pem_dir, ct->issuer, ct->privkey, ct->cachain);
        }
        tm1 = elapsed_time_msec(tm) / 5.0;
        printf("%2d. generate cert to disk: %.3f ms\t", c, tm1);
        g_tm0 += tm1;

        get_time(&tm);
        for (int d = 0; d < 5; d++) {
            if (stat(cert_file, &st) == 0) {
                sslctx = create_child_sslctx(cert_file, ct->cachain);
                if (sslctx) {
                    cache_insert(test_cert, sslctx);
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

int validate_certificate_chain(SSL_CTX *ctx) {
    if (!ctx) return 0;
    X509_STORE *store = SSL_CTX_get_cert_store(ctx);
    if (!store) return 0;
    return 1;
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
    (void)operation;
    unsigned long err;
    char err_buf[256];

    while ((err = ERR_get_error()) != 0) {
        ERR_error_string_n(err, err_buf, sizeof(err_buf));
    }
}

void sslctx_tbl_cleanup_expired(void) {
    cache_expire_old(3600 * 24 * 200);  /* 200 days */
}

size_t sslctx_tbl_memory_usage(void) {
    return cache_get_size() * sizeof(void *) * 4;
}

void pregenerate_common_certs(cert_tlstor_t *ct) {
    const char *common_domains[] = {
        "google.com", "facebook.com", "amazon.com", "microsoft.com",
        "apple.com", "netflix.com", "youtube.com", "twitter.com",
        "instagram.com", "linkedin.com", "github.com", "stackoverflow.com",
        NULL};

    if (!ct || !ct->privkey || !ct->issuer) {
        return;
    }

    for (int i = 0; common_domains[i]; i++) {
        cert_gen_enqueue(common_domains[i]);
    }
}

void print_cert_statistics(void) {
    printf("\n=== Certificate Statistics ===\n");
    printf("Cache entries: %d/%d\n", cache_get_used(), cache_get_size());
    printf("Cache hits: %d\n", stats_get_hit());
    printf("Cache misses: %d\n", stats_get_miss());
    printf("Cache purges: %d\n", stats_get_purge());
    printf("Certs generated: %d\n", stats_get_gen());
    printf("SSL sessions: %d\n", sslctx_tbl_get_sess_cnt());
    printf("SSL session hits: %d\n", sslctx_tbl_get_sess_hit());
    printf("SSL session misses: %d\n", sslctx_tbl_get_sess_miss());
    printf("Memory usage: %.2f MB\n", sslctx_tbl_memory_usage() / (1024.0 * 1024.0));
    printf("===============================\n");
}
