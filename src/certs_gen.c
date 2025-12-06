/*
 * certs_gen.c - Lock-free certificate generation
 *
 * Certificate generation using external RSA primes for fast key generation.
 * Uses lock-free MPSC queue for job dispatch.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sched.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <arpa/inet.h>

#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/x509v3.h>
#include <openssl/opensslv.h>

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <openssl/param_build.h>
#include <openssl/core_names.h>
#endif

#include "../include/certs_gen.h"
#include "../include/certs_queue.h"
#include "../include/certs_stats.h"
#include "../include/logger.h"
#include "../include/keypool.h"

/* Global pointer to cert_tlstor for worker threads */
static cert_tlstor_t *g_cert_tlstor = NULL;

/* Global keypool for fast key acquisition (set by main thread) */
static keypool_t *g_keypool = NULL;

int cert_gen_is_ip(const char *addr) {
    struct sockaddr_in sa4;
    struct sockaddr_in6 sa6;

    if (inet_pton(AF_INET, addr, &(sa4.sin_addr)) == 1) return 4;
    if (inet_pton(AF_INET6, addr, &(sa6.sin6_addr)) == 1) return 6;
    return 0;
}

int cert_gen_load_primes(cert_tlstor_t *ct) {
    char path_p[PIXELSERV_MAX_PATH];
    char path_q[PIXELSERV_MAX_PATH];
    struct stat st;
    int fd_p = -1, fd_q = -1;

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
        log_msg(LGG_INFO, "External primes not found (tried 03072/ and prime-3072-*.bin)");
        return 0;
    }
    ct->primes_file_size = st.st_size;

    if (stat(path_q, &st) != 0 || (size_t)st.st_size != ct->primes_file_size) {
        log_msg(LGG_WARNING, "Prime Q file missing or size mismatch");
        return 0;
    }

    ct->primes_count = ct->primes_file_size / PRIME_SIZE_3072;
    if (ct->primes_count == 0) {
        log_msg(LGG_WARNING, "Prime files empty");
        return 0;
    }

    /* Memory-map prime P file */
    fd_p = open(path_p, O_RDONLY);
    if (fd_p < 0) {
        log_msg(LGG_ERR, "Cannot open prime P file: %s", strerror(errno));
        return 0;
    }

    ct->primes_p = mmap(NULL, ct->primes_file_size, PROT_READ, MAP_PRIVATE, fd_p, 0);
    close(fd_p);

    if (ct->primes_p == MAP_FAILED) {
        log_msg(LGG_ERR, "Cannot mmap prime P file: %s", strerror(errno));
        ct->primes_p = NULL;
        return 0;
    }

    /* Memory-map prime Q file */
    fd_q = open(path_q, O_RDONLY);
    if (fd_q < 0) {
        log_msg(LGG_ERR, "Cannot open prime Q file: %s", strerror(errno));
        munmap(ct->primes_p, ct->primes_file_size);
        ct->primes_p = NULL;
        return 0;
    }

    ct->primes_q = mmap(NULL, ct->primes_file_size, PROT_READ, MAP_PRIVATE, fd_q, 0);
    close(fd_q);

    if (ct->primes_q == MAP_FAILED) {
        log_msg(LGG_ERR, "Cannot mmap prime Q file: %s", strerror(errno));
        munmap(ct->primes_p, ct->primes_file_size);
        ct->primes_p = NULL;
        ct->primes_q = NULL;
        return 0;
    }

    ct->use_external_primes = 1;
    log_msg(LGG_NOTICE, "Loaded %zu external primes for fast RSA key generation", ct->primes_count);
    return 1;
}

void cert_gen_unload_primes(cert_tlstor_t *ct) {
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
}

EVP_PKEY *cert_gen_rsa_from_primes(cert_tlstor_t *ct) {
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
#elif OPENSSL_VERSION_NUMBER >= 0x10100000L
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

/* Generate RSA key with fallback to standard generation */
static EVP_PKEY *generate_rsa_key(void) {
    EVP_PKEY *key = NULL;

    /* Try keypool first (ultra-fast path: ~1µs, for worker mode) */
    if (g_keypool) {
        key = keypool_acquire(g_keypool, KEYPOOL_ALG_RSA_3072);
        if (key) {
            return key;  /* Fast path: acquired from pre-generated pool */
        }
    }

    /* Try external primes second (medium-fast path) */
    if (g_cert_tlstor && g_cert_tlstor->use_external_primes) {
        key = cert_gen_rsa_from_primes(g_cert_tlstor);
    }

    /* Fallback to standard RSA generation */
    if (!key) {
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
        key = EVP_RSA_gen(3072);
#elif OPENSSL_VERSION_NUMBER >= 0x10100000L
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
                    EVP_PKEY_free(key);
                    key = NULL;
                }
            } else {
                RSA_free(rsa);
            }
            BN_free(e);
        }
#endif
    }

    return key;
}

/* Generate ECDSA P-256 key with keypool support */
static EVP_PKEY *generate_ecdsa_key(void) {
    EVP_PKEY *key = NULL;

    /* Try keypool first (ultra-fast path: ~1µs) */
    if (g_keypool) {
        key = keypool_acquire(g_keypool, KEYPOOL_ALG_ECDSA_P256);
        if (key) {
            return key;  /* Fast path: acquired from pre-generated pool */
        }
    }

    /* Generate ECDSA P-256 key on-demand */
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

/* Generate SM2 key with keypool support */
static EVP_PKEY *generate_sm2_key(void) {
    EVP_PKEY *key = NULL;

    /* Try keypool first (ultra-fast path: ~1µs) */
    if (g_keypool) {
        key = keypool_acquire(g_keypool, KEYPOOL_ALG_SM2);
        if (key) {
            return key;  /* Fast path: acquired from pre-generated pool */
        }
    }

    /* Generate SM2 key on-demand (SM2 is EC-based with sm2p256v1 curve) */
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

void cert_gen_create(const char *cert_name,
                     const char *pem_dir,
                     X509_NAME *issuer,
                     EVP_PKEY *privkey,
                     const STACK_OF(X509_INFO) *cachain)
{
    char fname[PIXELSERV_MAX_PATH];
    EVP_PKEY *key = NULL;
    X509 *x509 = NULL;
    X509_EXTENSION *ext = NULL;
    char san_str[PIXELSERV_MAX_SERVER_NAME + 8];
    EVP_MD_CTX *p_ctx = NULL;
    char *pem_fn = NULL;

    pem_fn = strdup(cert_name);
    if (!pem_fn) {
        return;
    }

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
    p_ctx = EVP_MD_CTX_new();
#else
    p_ctx = EVP_MD_CTX_create();
#endif
    if (!p_ctx || EVP_DigestSignInit(p_ctx, NULL, EVP_sha256(), NULL, privkey) != 1) {
        goto free_all;
    }

    if (pem_fn[0] == '_') pem_fn[0] = '*';

    key = generate_rsa_key();
    if (!key) goto free_all;

    x509 = X509_new();
    if (!x509) goto free_all;

    ASN1_INTEGER_set(X509_get_serialNumber(x509), rand());
    X509_set_version(x509, 2);

    int offset = -(rand() % (864000 - 172800 + 1) + 172800);
    X509_gmtime_adj(X509_get_notBefore(x509), offset);
    X509_gmtime_adj(X509_get_notAfter(x509), 3600*24*200L);

    X509_set_issuer_name(x509, issuer);
    X509_NAME *name = X509_get_subject_name(x509);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char *)pem_fn, -1, -1, 0);

    int ip_version = cert_gen_is_ip(pem_fn);
    if (ip_version > 0) {
        snprintf(san_str, sizeof(san_str), "IP:%s", pem_fn);
    } else if (pem_fn[0] == '*' && pem_fn[1] == '.') {
        /* Wildcard cert: include both base domain AND wildcard in SAN
         * e.g., *.example.co.uk → DNS:example.co.uk,DNS:*.example.co.uk */
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

    if (pem_fn[0] == '*') pem_fn[0] = '_';
    snprintf(fname, PIXELSERV_MAX_PATH, "%s/certs/%s", pem_dir, pem_fn);

    FILE *fp = fopen(fname, "wb");
    if (!fp) {
        goto free_all;
    }

    PEM_write_X509(fp, x509);

    if (cachain) {
        for (int i = 0; i < sk_X509_INFO_num(cachain); i++) {
            X509_INFO *xi = sk_X509_INFO_value(cachain, i);
            if (xi && xi->x509) {
                PEM_write_X509(fp, xi->x509);
            }
        }
    }

    PEM_write_PrivateKey(fp, key, NULL, NULL, 0, NULL, NULL);
    fclose(fp);

    stats_inc_gen();

free_all:
    free(pem_fn);
    EVP_PKEY_free(key);
    X509_EXTENSION_free(ext);
    X509_free(x509);
    if (p_ctx) {
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
        EVP_MD_CTX_free(p_ctx);
#else
        EVP_MD_CTX_destroy(p_ctx);
#endif
    }
}

/* Internal generic certificate creation function */
static void _cert_gen_create_impl(const char *cert_name,
                                   const char *pem_dir,
                                   X509_NAME *issuer,
                                   EVP_PKEY *privkey,
                                   const STACK_OF(X509_INFO) *cachain,
                                   EVP_PKEY* (*key_generator)(void))
{
    char fname[PIXELSERV_MAX_PATH];
    EVP_PKEY *key = NULL;
    X509 *x509 = NULL;
    X509_EXTENSION *ext = NULL;
    char san_str[PIXELSERV_MAX_SERVER_NAME + 8];
    EVP_MD_CTX *p_ctx = NULL;
    char *pem_fn = NULL;

    pem_fn = strdup(cert_name);
    if (!pem_fn) {
        return;
    }

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
    p_ctx = EVP_MD_CTX_new();
#else
    p_ctx = EVP_MD_CTX_create();
#endif
    if (!p_ctx || EVP_DigestSignInit(p_ctx, NULL, EVP_sha256(), NULL, privkey) != 1) {
        goto free_all;
    }

    if (pem_fn[0] == '_') pem_fn[0] = '*';

    key = key_generator();
    if (!key) goto free_all;

    x509 = X509_new();
    if (!x509) goto free_all;

    ASN1_INTEGER_set(X509_get_serialNumber(x509), rand());
    X509_set_version(x509, 2);

    int offset = -(rand() % (864000 - 172800 + 1) + 172800);
    X509_gmtime_adj(X509_get_notBefore(x509), offset);
    X509_gmtime_adj(X509_get_notAfter(x509), 3600*24*200L);

    X509_set_issuer_name(x509, issuer);
    X509_NAME *name = X509_get_subject_name(x509);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char *)pem_fn, -1, -1, 0);

    int ip_version = cert_gen_is_ip(pem_fn);
    if (ip_version > 0) {
        snprintf(san_str, sizeof(san_str), "IP:%s", pem_fn);
    } else if (pem_fn[0] == '*' && pem_fn[1] == '.') {
        /* Wildcard cert: include both base domain AND wildcard in SAN
         * e.g., *.example.co.uk → DNS:example.co.uk,DNS:*.example.co.uk */
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

    if (pem_fn[0] == '*') pem_fn[0] = '_';
    snprintf(fname, PIXELSERV_MAX_PATH, "%s/certs/%s", pem_dir, pem_fn);

    FILE *fp = fopen(fname, "wb");
    if (!fp) {
        goto free_all;
    }

    PEM_write_X509(fp, x509);

    if (cachain) {
        for (int i = 0; i < sk_X509_INFO_num(cachain); i++) {
            X509_INFO *xi = sk_X509_INFO_value(cachain, i);
            if (xi && xi->x509) {
                PEM_write_X509(fp, xi->x509);
            }
        }
    }

    PEM_write_PrivateKey(fp, key, NULL, NULL, 0, NULL, NULL);
    fclose(fp);

    stats_inc_gen();

free_all:
    free(pem_fn);
    EVP_PKEY_free(key);
    X509_EXTENSION_free(ext);
    X509_free(x509);
    if (p_ctx) {
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
        EVP_MD_CTX_free(p_ctx);
#else
        EVP_MD_CTX_destroy(p_ctx);
#endif
    }
}

/* ECDSA P-256 certificate generation */
void cert_gen_create_ecdsa(const char *cert_name,
                           const char *pem_dir,
                           X509_NAME *issuer,
                           EVP_PKEY *privkey,
                           const STACK_OF(X509_INFO) *cachain)
{
    _cert_gen_create_impl(cert_name, pem_dir, issuer, privkey, cachain, generate_ecdsa_key);
}

/* SM2 certificate generation */
void cert_gen_create_sm2(const char *cert_name,
                         const char *pem_dir,
                         X509_NAME *issuer,
                         EVP_PKEY *privkey,
                         const STACK_OF(X509_INFO) *cachain)
{
    _cert_gen_create_impl(cert_name, pem_dir, issuer, privkey, cachain, generate_sm2_key);
}

void cert_gen_universal_ip(const char *pem_dir,
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
    snprintf(mega_san, sizeof(mega_san), "%s",
        "IP:127.0.0.1,IP:127.0.0.254,"
        "IP:10.0.0.1,IP:10.255.255.254,"
        "IP:192.168.0.1,IP:192.168.255.254,"
        "IP:172.16.0.1,IP:172.31.255.254,"
        "IP:192.168.1.1,IP:192.168.0.1,IP:10.0.0.1,"
        "DNS:localhost,DNS:*.local,DNS:*.lan"
    );

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
    p_ctx = EVP_MD_CTX_new();
#else
    p_ctx = EVP_MD_CTX_create();
#endif
    if (!p_ctx || EVP_DigestSignInit(p_ctx, NULL, EVP_sha256(), NULL, privkey) != 1) {
        goto free_all;
    }

    key = generate_rsa_key();
    if (!key) goto free_all;

    x509 = X509_new();
    if (!x509) goto free_all;

    ASN1_INTEGER_set(X509_get_serialNumber(x509), rand());
    X509_set_version(x509, 2);

    int offset = -(rand() % (864000 - 172800 + 1) + 172800);
    X509_gmtime_adj(X509_get_notBefore(x509), offset);
    X509_gmtime_adj(X509_get_notAfter(x509), 3600*24*200L);

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

    snprintf(fname, PIXELSERV_MAX_PATH, "%s/certs/universal_ips.pem", pem_dir);

    FILE *fp = fopen(fname, "wb");
    if (!fp) {
        goto free_all;
    }

    PEM_write_X509(fp, x509);

    if (cachain) {
        for (int i = 0; i < sk_X509_INFO_num(cachain); i++) {
            X509_INFO *xi = sk_X509_INFO_value(cachain, i);
            if (xi && xi->x509) {
                PEM_write_X509(fp, xi->x509);
            }
        }
    }

    PEM_write_PrivateKey(fp, key, NULL, NULL, 0, NULL, NULL);
    fclose(fp);

free_all:
    EVP_PKEY_free(key);
    X509_EXTENSION_free(ext);
    X509_free(x509);
    if (p_ctx) {
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
        EVP_MD_CTX_free(p_ctx);
#else
        EVP_MD_CTX_destroy(p_ctx);
#endif
    }
}

void cert_gen_init(cert_tlstor_t *ct) {
    g_cert_tlstor = ct;
    cert_queue_init();
}

void cert_gen_shutdown(void) {
    cert_queue_shutdown();
    g_cert_tlstor = NULL;
    g_keypool = NULL;
}

void cert_gen_set_keypool(keypool_t *kp) {
    g_keypool = kp;
}

void cert_gen_enqueue(const char *cert_name) {
    cert_queue_push(cert_name);
}

void *cert_gen_worker(void *arg) {
    cert_tlstor_t *ct = (cert_tlstor_t *)arg;
    int backoff = 0;

    while (!cert_queue_is_shutdown()) {
        cert_job_t *job = cert_queue_pop();

        if (!job) {
            /* No work available - exponential backoff */
            if (backoff < 10) {
                for (int i = 0; i < (1 << backoff); i++) {
#if defined(__x86_64__) || defined(__i386__)
                    __asm__ volatile("pause" ::: "memory");
#else
                    __asm__ volatile("" ::: "memory");
#endif
                }
                backoff++;
            } else {
                /* Yield to scheduler after many spins */
                sched_yield();
            }
            continue;
        }

        /* Reset backoff when we have work */
        backoff = 0;

        /* Generate the certificate */
        if (ct->privkey && ct->issuer) {
            cert_gen_create(job->cert_name, ct->pem_dir,
                           ct->issuer, ct->privkey, ct->cachain);
        }

        cert_job_free(job);
    }

    return NULL;
}
