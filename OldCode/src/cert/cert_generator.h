/* TLS-Gate NX - Certificate Generator
 * Copyright (C) 2025 Torsten Jahnke
 *
 * On-demand X.509 certificate generation with:
 * - Client-aware algorithm selection (ECDSA for modern, RSA for legacy)
 * - Multi-algorithm support (ECDSA P-256/P-384, RSA 3072/4096)
 * - Integration with keypool and cert_cache
 * - TLS ClientHello signature algorithm detection
 * - Wildcard and SAN support
 * - Performance tracking and statistics
 */

#ifndef TLSGATENG_CERT_GENERATOR_H
#define TLSGATENG_CERT_GENERATOR_H

#include "../common_types.h"
#include "../crypto/keypool.h"
#include "cert_cache.h"
#include "ca_loader.h"

#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <stdbool.h>
#include <stdatomic.h>

/* Error codes */
typedef enum {
    CERT_GEN_OK = 0,
    CERT_GEN_ERR_INVALID = -1,
    CERT_GEN_ERR_NOMEM = -2,
    CERT_GEN_ERR_OPENSSL = -3,
    CERT_GEN_ERR_NO_KEY = -4,
    CERT_GEN_ERR_CACHE_FULL = -5
} cert_gen_error_t;

/* Algorithm selection mode */
typedef enum {
    CERT_GEN_MODE_AUTO,      /* Auto-select based on client (recommended) */
    CERT_GEN_MODE_ECDSA,     /* Force ECDSA (best performance) */
    CERT_GEN_MODE_RSA,       /* Force RSA (best compatibility) */
    CERT_GEN_MODE_PREFER_ECDSA /* Prefer ECDSA, fallback to RSA */
} cert_gen_mode_t;

/* Certificate generation configuration */
typedef struct {
    /* Algorithm selection */
    cert_gen_mode_t mode;
    crypto_alg_t default_algorithm;      /* Default for auto mode */
    crypto_alg_t fallback_algorithm;     /* Fallback for legacy clients */

    /* Certificate parameters */
    int validity_days;                   /* Certificate validity (default: 3650) */
    bool enable_wildcards;               /* Generate wildcard certs */
    bool enable_san;                     /* Add Subject Alternative Names */
    const char *second_level_tld_file;   /* Optional: Path to 2nd-level TLD file (e.g., /etc/tlsgateNG/second-level-tlds.dat) */

    /* CA certificate (single CA mode) */
    X509 *ca_cert;                       /* CA certificate (signing cert) */
    EVP_PKEY *ca_key;                    /* CA private key */
    STACK_OF(X509) *ca_chain;            /* Full CA chain (for multi-level PKI) */

    /* Multi-SubCA configuration (RSA/ECDSA/SM2)
     * If set, cert_generator will use this instead of single ca_cert/ca_key
     * and automatically select the correct SubCA based on algorithm type */
    multi_ca_config_t *multi_ca;         /* Multi-SubCA config (optional, NULL = single CA mode) */

    /* Performance tuning */
    bool detect_client_capabilities;     /* Parse ClientHello (default: true) */
    bool cache_certificates;             /* Use cert_cache (default: true) */

    /* Integration */
    keypool_t *keypool;                  /* Key pool for key acquisition */
    cert_cache_t *cert_cache;            /* Certificate cache (legacy - for compatibility) */
    void *cert_index;                    /* Certificate index (cert_index_t* - high-scale with 5-min persistence) */
    void *shm_certcache;                 /* Shared memory cert index (certcache_shm_t* - central multi-instance) */
    const char *certs_dir;               /* Directory for cert PEM files (for SHM mode disk loading) */
} cert_gen_config_t;

/* Certificate generation statistics */
typedef struct {
    atomic_llong total_generated;        /* Total certificates generated */
    atomic_llong generated_ecdsa;        /* ECDSA certificates */
    atomic_llong generated_rsa;          /* RSA certificates */
    atomic_llong generated_sm2;          /* SM2 certificates */
    atomic_llong cache_hits;             /* Cache hits */
    atomic_llong cache_misses;           /* Cache misses */
    atomic_llong client_auto_ecdsa;      /* Clients that got ECDSA (auto mode) */
    atomic_llong client_auto_rsa;        /* Clients that got RSA (auto mode) */
    atomic_llong client_auto_sm2;        /* Clients that got SM2 (auto mode) */
    atomic_llong generation_errors;      /* Generation failures */

    /* Timing statistics (microseconds) */
    atomic_llong total_generation_time_us;
    atomic_llong fastest_generation_us;
    atomic_llong slowest_generation_us;
} cert_gen_stats_t;

/* Opaque generator handle */
typedef struct cert_generator cert_generator_t;

/* Lifecycle */

/* Create certificate generator
 *
 * @param config  Configuration structure
 * @return Generator handle or NULL on error
 */
cert_generator_t* cert_generator_create(const cert_gen_config_t *config);

/* Destroy generator and free resources */
void cert_generator_destroy(cert_generator_t *gen);

/* Certificate Generation */

/* Generate certificate for domain (main entry point)
 *
 * This is the high-level API that:
 * 1. Checks cache first
 * 2. Detects client capabilities (if SSL connection provided)
 * 3. Selects appropriate algorithm
 * 4. Generates certificate if not cached
 * 5. Stores in cache for future use
 *
 * @param gen     Generator handle
 * @param domain  Domain name (SNI)
 * @param ssl     SSL connection for client detection (can be NULL)
 * @return SSL_CTX* or NULL on error
 */
SSL_CTX* cert_generator_get_ctx(cert_generator_t *gen,
                                 const char *domain,
                                 SSL *ssl);

/* Generate X.509 certificate (low-level API)
 *
 * @param gen       Generator handle
 * @param domain    Domain name
 * @param algorithm Crypto algorithm to use
 * @param pkey_out  Output: generated private key
 * @return X.509* certificate or NULL on error
 */
X509* cert_generator_generate_cert(cert_generator_t *gen,
                                    const char *domain,
                                    crypto_alg_t algorithm,
                                    EVP_PKEY **pkey_out);

/* Create SSL_CTX from certificate and key
 *
 * @param cert      X.509 certificate (server certificate)
 * @param pkey      Private key
 * @param ca_chain  CA certificate chain (optional, can be NULL)
 * @return SSL_CTX* or NULL on error
 *
 * NOTE: If ca_chain is provided, the chain will be added to SSL_CTX so that
 *       clients receive the full certificate chain for validation.
 *       Chain should be: [Sub-CA cert, Root CA cert, ...]
 */
SSL_CTX* cert_generator_create_ssl_ctx(X509 *cert, EVP_PKEY *pkey,
                                        STACK_OF(X509) *ca_chain);

/* Renew certificate with existing key (for auto-renewal)
 *
 * Re-signs an expired certificate using the same private key.
 * This is much faster than generating a new key pair.
 *
 * @param gen           Generator handle
 * @param domain        Domain name
 * @param existing_key  Existing private key to reuse
 * @return X.509* certificate or NULL on error
 *
 * NOTE: This is used for on-demand certificate renewal when an expired
 *       certificate is detected in the cache. The existing key is reused
 *       for performance - only the X.509 certificate is re-generated.
 */
X509* cert_generator_renew_cert(cert_generator_t *gen,
                                const char *domain,
                                EVP_PKEY *existing_key);

/* Client Capability Detection */

/* Detect if client supports ECDSA
 *
 * Analyzes TLS ClientHello signature_algorithms extension to determine
 * if the client supports ECDSA certificates.
 *
 * @param ssl  SSL connection (during handshake)
 * @return true if client supports ECDSA, false otherwise
 */
bool cert_generator_client_supports_ecdsa(SSL *ssl);

/* Select algorithm based on client and configuration
 *
 * @param gen  Generator handle
 * @param ssl  SSL connection (can be NULL)
 * @return Selected algorithm
 */
crypto_alg_t cert_generator_select_algorithm(cert_generator_t *gen, SSL *ssl);

/* Configuration */

/* Set algorithm selection mode
 *
 * @param gen   Generator handle
 * @param mode  Selection mode
 */
void cert_generator_set_mode(cert_generator_t *gen, cert_gen_mode_t mode);

/* Set default and fallback algorithms
 *
 * @param gen       Generator handle
 * @param default_alg  Default algorithm (for auto mode with modern clients)
 * @param fallback_alg Fallback algorithm (for legacy clients)
 */
void cert_generator_set_algorithms(cert_generator_t *gen,
                                    crypto_alg_t default_alg,
                                    crypto_alg_t fallback_alg);

/* Set CA certificate and key (single CA mode)
 *
 * @param gen      Generator handle
 * @param ca_cert  CA certificate
 * @param ca_key   CA private key
 * @return CERT_GEN_OK on success
 */
cert_gen_error_t cert_generator_set_ca(cert_generator_t *gen,
                                        X509 *ca_cert,
                                        EVP_PKEY *ca_key);

/* Set multi-SubCA configuration (RSA/ECDSA/SM2)
 *
 * Enables multi-SubCA mode where different SubCAs are used based on
 * algorithm type (RSA, ECDSA, SM2).
 *
 * @param gen       Generator handle
 * @param multi_ca  Multi-SubCA configuration
 * @return CERT_GEN_OK on success
 */
cert_gen_error_t cert_generator_set_multi_ca(cert_generator_t *gen,
                                             multi_ca_config_t *multi_ca);

/* Detect if client supports SM2
 *
 * Analyzes TLS ClientHello signature_algorithms extension to determine
 * if the client supports SM2 certificates.
 *
 * @param ssl  SSL connection (during handshake)
 * @return true if client supports SM2, false otherwise
 */
bool cert_generator_client_supports_sm2(SSL *ssl);

/* Statistics */

/* Get generation statistics */
void cert_generator_get_stats(const cert_generator_t *gen,
                               cert_gen_stats_t *stats);

/* Print statistics to log */
void cert_generator_print_stats(const cert_generator_t *gen);

/* Reset statistics counters */
void cert_generator_reset_stats(cert_generator_t *gen);

/* Utility Functions */

/* Get mode name as string */
const char* cert_gen_mode_name(cert_gen_mode_t mode);

/* Get error message for error code */
const char* cert_gen_error_string(cert_gen_error_t err);

/* Create default configuration */
static inline cert_gen_config_t cert_gen_config_default(void) {
    return (cert_gen_config_t){
        .mode = CERT_GEN_MODE_AUTO,
        .default_algorithm = CRYPTO_ALG_ECDSA_P256,
        .fallback_algorithm = CRYPTO_ALG_RSA_3072,
        .validity_days = 200,  /* 200 days (Browser max: 398 days since 2020) */
        .enable_wildcards = true,
        .enable_san = true,
        .ca_cert = NULL,
        .ca_key = NULL,
        .ca_chain = NULL,
        .detect_client_capabilities = true,
        .cache_certificates = true,
        .keypool = NULL,
        .cert_cache = NULL,
        .cert_index = NULL,
        .shm_certcache = NULL,
        .certs_dir = NULL
    };
}

#endif /* TLSGATENG_CERT_GENERATOR_H */
