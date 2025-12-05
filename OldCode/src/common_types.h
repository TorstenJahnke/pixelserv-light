/* TLS-Gate NX - Common Type Definitions
 * Copyright (C) 2025 Torsten Jahnke
 *
 * Shared types and constants used across multiple modules.
 */

#ifndef TLSGATENG_COMMON_TYPES_H
#define TLSGATENG_COMMON_TYPES_H

#include <stdbool.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/opensslv.h>
#include <pthread.h>

/* OpenSSL version compatibility */
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
#define OPENSSL_API_1_1 1
#else
#define OPENSSL_API_1_1 0
#endif

/* Global security configuration */
extern bool g_legacy_crypto_enabled;

/* TLS configuration */
#define TLSGATENG_SSL_SESS_CACHE_SIZE 100000       /* 100k sessions (~50MB RAM) - optimized for high load */
#define TLSGATENG_SSL_SESS_TIMEOUT 300             /* 5 minutes - TLS Session Resumption saves ~50ms/reconnect */
#define TLSGATENG_TLS_EARLYDATA_SIZE 16384

/* Default paths */
#ifndef DEFAULT_PEM_PATH
#define DEFAULT_PEM_PATH "/opt/var/cache/tlsgateNG"
#endif

/* Cipher suites - Modern TLS configuration
 * Includes SM2/SM4/SM3 for Chinese market support (OpenSSL 3.0+)
 */
#define TLSGATENG_CIPHER_LIST \
  "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:" \
  "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:" \
  "ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:" \
  "ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:" \
  "DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES128-SHA256:" \
  "DHE-RSA-AES128-SHA:AES128-GCM-SHA256:AES128-SHA256:AES128-SHA"

#define TLSGATENG_TLSV1_3_CIPHERS \
  "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256"

/* SM2/SM3/SM4 cipher suites for OpenSSL 3.0+ with Tongsuo support
 * These are optional and only active if OpenSSL is compiled with SM support */
#define TLSGATENG_SM_CIPHERS \
  "SM2-WITH-SM4-SM3"

/* SSL/TLS status enumeration */
typedef enum {
    SSL_NOT_TLS,
    SSL_ERR,
    SSL_MISS,
    SSL_HIT,
    SSL_HIT_CLS,
    SSL_HIT_RTT0,
    SSL_UNKNOWN
} ssl_enum;

/* Cryptographic algorithm type */
typedef enum {
    CRYPTO_ALG_RSA_3072,      /* RSA 3072-bit */
    CRYPTO_ALG_RSA_4096,      /* RSA 4096-bit */
    CRYPTO_ALG_RSA_8192,      /* RSA 8192-bit (very high security) */
    CRYPTO_ALG_RSA_16384,     /* RSA 16384-bit (ultra-high security - DEMO/TESTING only, very slow!) */
    CRYPTO_ALG_ECDSA_P256,    /* ECDSA P-256 (prime256v1) */
    CRYPTO_ALG_ECDSA_P384,    /* ECDSA P-384 (secp384r1) */
    CRYPTO_ALG_ECDSA_P521,    /* ECDSA P-521 (secp521r1) */
    CRYPTO_ALG_SM2,           /* SM2 (Chinese standard elliptic curve) */
    CRYPTO_ALG_ED25519,       /* EdDSA Ed25519 (future) */
    CRYPTO_ALG_AUTO,          /* Auto-select based on performance */

    /* LEGACY/WEAK ALGORITHMS - Only available with --legacy-crypto flag
     * WARNING: These are cryptographically weak and should only be used for:
     * - Testing legacy clients
     * - Honeypot/research purposes
     * - Intentionally weak certificates
     * DO NOT use in production without understanding security implications! */
    CRYPTO_ALG_RSA_1024,      /* RSA 1024-bit (WEAK - requires --legacy-crypto) */
    CRYPTO_ALG_RSA_2048       /* RSA 2048-bit (WEAK - requires --legacy-crypto) */
} crypto_alg_t;

/* Certificate/TLS storage (PKI Manager) */
typedef struct {
    const char* pem_dir;
    STACK_OF(X509_INFO) *cachain;
    X509_NAME *issuer;
    EVP_PKEY *privkey;
    crypto_alg_t default_alg;  /* Default algorithm for new certs */
} cert_tlstor_t;

/* TLS extension callback argument */
typedef struct {
    const char *tls_pem;
    const STACK_OF(X509_INFO) *cachain;
    char servername[65];
    char server_ip[INET6_ADDRSTRLEN];
    ssl_enum status;
    int sslctx_idx;
} tlsext_cb_arg_struct;

/* Connection TLS storage */
typedef struct {
    int new_fd;
    SSL *ssl;
    double init_time;
    tlsext_cb_arg_struct *tlsext_cb_arg;
    char *early_data;
    tlsext_cb_arg_struct v;
} conn_tlstor_struct;

#define CONN_TLSTOR(p, e) ((conn_tlstor_struct*)p)->e

/* SSL context cache entry */
typedef struct {
    int alloc_len;
    char *cert_name;
    unsigned int last_use;  /* Seconds since process start */
    int reuse_count;        /* Number of times reused */
    SSL_CTX *sslctx;
    crypto_alg_t algorithm; /* Algorithm used for this cert */
    pthread_mutex_t lock;   /* Per-entry lock for thread safety */
} sslctx_cache_struct;

#endif /* TLSGATENG_COMMON_TYPES_H */
