/* TLS-Gate NX - Certificate Generator Implementation
 * Copyright (C) 2025 Torsten Jahnke
 *
 * On-demand X.509 certificate generation with client-aware algorithm selection
 */

#include "cert_generator.h"
#include "cert_index.h"
#include "second_level_tlds.h"
#include "../ipc/shm_manager.h"
#include "../util/logger.h"
#include "../util/util.h"

#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <ctype.h>
#include <time.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <errno.h>
#include <openssl/x509v3.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <openssl/core_names.h>
#endif

/* Forward declaration to access cert_index internals */
struct cert_index {
    cert_index_config_t config;
    char index_file[512];
    char disk_cache_dir[512];
    /* ... rest not needed here ... */
};

/* Generator structure */
struct cert_generator {
    cert_gen_config_t config;
    cert_gen_stats_t stats;
    pthread_mutex_t lock;  /* For non-atomic operations */
    tld_set_t *tld_set;    /* 2nd-level TLD set (NULL if not loaded) */
};

/* Compile-time checks */
_Static_assert(sizeof(cert_gen_config_t) <= 256, "Config structure too large");

/* Utility: Get current time in microseconds */
static inline long long get_time_us(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (long long)tv.tv_sec * 1000000LL + tv.tv_usec;
}

/* Generate random certificate creation backdate (2-14 days ago)
 *
 * Anti-Detection: Real certificates are never created "today"
 * - Random age between 2-14 days looks natural
 * - Prevents detection by "all certs same date"
 * - Each cert gets unique creation timestamp
 *
 * Returns: Negative offset in seconds (to subtract from current time)
 */
static long get_cert_backdate_offset(void) {
    /* SECURITY FIX: Use cryptographically secure random from OpenSSL
     * instead of predictable rand() to prevent fingerprinting attacks */

    /* 2 days = 172800 seconds, 14 days = 1209600 seconds */
    const long min_days = 2;
    const long max_days = 14;
    const long seconds_per_day = 24L * 60L * 60L;

    /* Generate cryptographically secure random bytes */
    unsigned char random_bytes[8];
    if (RAND_bytes(random_bytes, sizeof(random_bytes)) != 1) {
        /* Fallback to time-based offset if RAND_bytes fails */
        LOG_WARN("RAND_bytes failed, using time-based fallback");
        return -(7L * seconds_per_day);  /* Default to 7 days */
    }

    /* Convert random bytes to long (using first 4 bytes for days, next 4 for hours) */
    unsigned int days_rand = (random_bytes[0] << 24) | (random_bytes[1] << 16) |
                             (random_bytes[2] << 8) | random_bytes[3];
    unsigned int hours_rand = (random_bytes[4] << 24) | (random_bytes[5] << 16) |
                              (random_bytes[6] << 8) | random_bytes[7];

    /* Generate random offset between min and max days */
    long days = min_days + (days_rand % (max_days - min_days + 1));
    long offset = days * seconds_per_day;

    /* Add random hours (0-23) for more variance */
    long random_hours = hours_rand % 24;
    offset += random_hours * 60L * 60L;

    /* Return negative offset (backdate) */
    return -offset;
}

/* Utility: Get OpenSSL error string */
static const char* get_openssl_error(void) {
    unsigned long err = ERR_get_error();
    return err ? ERR_error_string(err, NULL) : "Unknown OpenSSL error";
}

/* Select message digest for certificate signing
 *
 * Returns appropriate hash algorithm based on:
 * - SM2: SM3 (Chinese standard hash)
 * - RSA-1024/2048: SHA1 (legacy compatibility)
 * - All other algorithms: SHA-256 (modern standard)
 *
 * @param algorithm  Crypto algorithm type
 * @return          EVP_MD pointer (SM3, SHA1, or SHA256)
 */
static const EVP_MD* select_signature_digest(crypto_alg_t algorithm) {
    switch (algorithm) {
        case CRYPTO_ALG_SM2:
            /* SM2 uses SM3 hash algorithm (Chinese standard) */
            return EVP_sm3();

        case CRYPTO_ALG_RSA_1024:
        case CRYPTO_ALG_RSA_2048:
            /* Legacy algorithms use SHA1 for maximum compatibility */
            return EVP_sha1();

        default:
            /* Modern algorithms use SHA-256 */
            return EVP_sha256();
    }
}

/* Check if string is an IP address (IPv4 or IPv6) */
static bool is_ip_address(const char *domain) {
    if (!domain) return false;

    /* Quick check for IPv4: contains only digits and dots */
    bool has_non_numeric = false;
    bool has_colon = false;

    for (const char *p = domain; *p; p++) {
        if (*p == ':') {
            has_colon = true;
            break;
        }
        if (!isdigit(*p) && *p != '.') {
            has_non_numeric = true;
            break;
        }
    }

    /* IPv6 detection: contains colon */
    if (has_colon) {
        return true;  /* Likely IPv6 (e.g., 2001:db8::1) */
    }

    /* IPv4 detection: all numeric with dots */
    if (!has_non_numeric) {
        int dots = 0;
        for (const char *p = domain; *p; p++) {
            if (*p == '.') dots++;
        }
        if (dots == 3) {
            return true;  /* Likely IPv4 (e.g., 192.168.1.1) */
        }
    }

    return false;
}

/* Determine if domain should use wildcard certificate
 *
 * Enhanced version with 2nd-level TLD support:
 * - Count dots to determine domain levels
 * - Use exact domain for:
 *   1. Single-level domains (example.com)
 *   2. 2nd-level TLD domains (example.co.uk) - if TLD set is loaded
 *   3. IP addresses (192.168.1.1, 2001:db8::1)
 * - Use wildcard for deeper subdomains (www.example.com → *.example.com)
 *
 * @param domain     Domain name to analyze
 * @param tld_set    Optional 2nd-level TLD set for accurate detection (NULL = use heuristic)
 * @return          Pointer to wildcard base domain, or NULL to use exact domain
 */
static const char* get_wildcard_base_domain(const char *domain, const tld_set_t *tld_set) {
    if (!domain || strlen(domain) == 0) {
        return NULL;
    }

    /* Check if domain is an IP address */
    if (is_ip_address(domain)) {
        return NULL;  /* Use exact for IP addresses */
    }

    /* Count dots and track TLD (last part after final dot) */
    int dot_count = 0;
    const char *tld = NULL;
    const char *dot_pos = strchr(domain, '.');

    while (dot_pos) {
        dot_count++;
        tld = dot_pos + 1;
        dot_pos = strchr(tld, '.');
    }

    /* Single-level domain: example.com → use exact */
    if (dot_count <= 1) {
        return NULL;
    }

    /* If TLD set is loaded, check for 2nd-level TLDs (e.g., co.uk, com.au) */
    if (tld_set && dot_count == 2) {
        if (tld_set_is_second_level_domain(tld_set, domain)) {
            return NULL;  /* example.co.uk → use exact */
        }
    }

    /* Fallback heuristic for 2nd-level TLDs (if no TLD set loaded):
     * - 2-char TLD: example.co.uk → use exact
     * - 3-char TLD: example.com.au → use exact
     */
    if (dot_count == 2 && tld && !tld_set) {
        size_t tld_len = strlen(tld);
        if (tld_len >= 2 && tld_len <= 3) {
            return NULL;  /* Likely 2nd-level TLD */
        }
    }

    /* Use wildcard: skip first subdomain
     * www.example.com → .example.com → *.example.com
     * api.example.com → .example.com → *.example.com
     * mail.example.co.uk → .example.co.uk → *.example.co.uk
     * myblog.blogspot.com → .blogspot.com → *.blogspot.com (good for malware protection!)
     */
    const char *wildcard_base = strchr(domain, '.');
    return wildcard_base ? (wildcard_base + 1) : NULL;  /* Skip the dot */
}

/* Detect algorithm type from private key
 *
 * Used for certificate renewal with multi-SubCA:
 * - Examines key type and parameters
 * - Returns appropriate algorithm for SubCA selection
 * - Falls back to default if detection fails
 */
static crypto_alg_t detect_algorithm_from_key(EVP_PKEY *key) {
    if (!key) {
        return CRYPTO_ALG_RSA_3072;  /* Safe default */
    }

    int key_type = EVP_PKEY_id(key);

    switch (key_type) {
        case EVP_PKEY_RSA: {
            /* RSA: Check key size to distinguish 3072 vs 4096 */
            int key_bits = EVP_PKEY_bits(key);
            if (key_bits >= 4096) {
                return CRYPTO_ALG_RSA_4096;
            }
            return CRYPTO_ALG_RSA_3072;
        }

        case EVP_PKEY_EC: {
            /* ECDSA: Detect curve (P-256, P-384, P-521) */
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
            /* OpenSSL 3.0+: Use new EVP API */
            char group_name[80];
            if (EVP_PKEY_get_utf8_string_param(key, OSSL_PKEY_PARAM_GROUP_NAME,
                                               group_name, sizeof(group_name), NULL)) {
                if (strcmp(group_name, "P-384") == 0 || strcmp(group_name, "secp384r1") == 0) {
                    return CRYPTO_ALG_ECDSA_P384;
                }
                if (strcmp(group_name, "P-521") == 0 || strcmp(group_name, "secp521r1") == 0) {
                    return CRYPTO_ALG_ECDSA_P521;
                }
                /* Default to P-256 for prime256v1 and others */
                return CRYPTO_ALG_ECDSA_P256;
            }
#else
            /* OpenSSL 1.1.x: Use legacy EC_KEY API */
            const EC_KEY *ec = EVP_PKEY_get0_EC_KEY(key);
            if (ec) {
                const EC_GROUP *group = EC_KEY_get0_group(ec);
                int curve_nid = EC_GROUP_get_curve_name(group);

                if (curve_nid == NID_secp384r1) {
                    return CRYPTO_ALG_ECDSA_P384;
                }
                if (curve_nid == NID_secp521r1) {
                    return CRYPTO_ALG_ECDSA_P521;
                }
                /* Default to P-256 for prime256v1 and others */
                return CRYPTO_ALG_ECDSA_P256;
            }
#endif
            return CRYPTO_ALG_ECDSA_P256;  /* Safe default for ECDSA */
        }

        case EVP_PKEY_SM2: {
            /* SM2: Chinese standard elliptic curve */
            return CRYPTO_ALG_SM2;
        }

        default:
            /* Unknown key type: default to RSA */
            LOG_WARN("Unknown key type %d, defaulting to RSA 3072", key_type);
            return CRYPTO_ALG_RSA_3072;
    }
}

/* Lifecycle */

cert_generator_t* cert_generator_create(const cert_gen_config_t *config) {
    if (!config) {
        LOG_ERROR("Invalid config");
        return NULL;
    }

    /* Support either single CA (ca_cert/ca_key) or multi-SubCA mode (multi_ca) */
    if (!config->ca_cert && !config->ca_key && !config->multi_ca) {
        LOG_ERROR("Either (ca_cert + ca_key) or multi_ca configuration is required");
        return NULL;
    }

    /* If multi_ca is set, single CA should be NULL */
    if (config->multi_ca && (config->ca_cert || config->ca_key)) {
        LOG_WARN("Multi-SubCA mode: ignoring single CA cert/key, using multi_ca instead");
    }

    cert_generator_t *gen = calloc(1, sizeof(cert_generator_t));
    if (!gen) {
        LOG_ERROR("Failed to allocate generator");
        return NULL;
    }

    /* Copy configuration */
    memcpy(&gen->config, config, sizeof(cert_gen_config_t));

    /* Initialize statistics */
    atomic_init(&gen->stats.total_generated, 0);
    atomic_init(&gen->stats.generated_ecdsa, 0);
    atomic_init(&gen->stats.generated_rsa, 0);
    atomic_init(&gen->stats.cache_hits, 0);
    atomic_init(&gen->stats.cache_misses, 0);
    atomic_init(&gen->stats.client_auto_ecdsa, 0);
    atomic_init(&gen->stats.client_auto_rsa, 0);
    atomic_init(&gen->stats.generation_errors, 0);
    atomic_init(&gen->stats.total_generation_time_us, 0);
    atomic_init(&gen->stats.fastest_generation_us, LLONG_MAX);
    atomic_init(&gen->stats.slowest_generation_us, 0);

    /* Initialize lock */
    if (pthread_mutex_init(&gen->lock, NULL) != 0) {
        LOG_ERROR("Failed to initialize mutex");
        free(gen);
        return NULL;
    }

    /* Load 2nd-level TLDs from file (optional) */
    gen->tld_set = NULL;
    if (config->second_level_tld_file) {
        gen->tld_set = tld_set_create(2048);  /* Initial capacity for ~2000 TLDs */
        if (gen->tld_set) {
            int loaded = tld_set_load_from_file(gen->tld_set, config->second_level_tld_file);
            if (loaded < 0) {
                LOG_WARN("Failed to load 2nd-level TLDs from %s, using heuristic only",
                        config->second_level_tld_file);
                tld_set_destroy(gen->tld_set);
                gen->tld_set = NULL;
            } else {
                LOG_INFO("Loaded %d 2nd-level TLDs from %s", loaded, config->second_level_tld_file);
            }
        }
    }

    LOG_INFO("Created certificate generator (mode=%s, default=%s, fallback=%s)",
            cert_gen_mode_name(gen->config.mode),
            keypool_algorithm_name(gen->config.default_algorithm),
            keypool_algorithm_name(gen->config.fallback_algorithm));

    return gen;
}

void cert_generator_destroy(cert_generator_t *gen) {
    if (!gen) {
        return;
    }

    /* Cleanup TLD set if loaded */
    if (gen->tld_set) {
        tld_set_destroy(gen->tld_set);
    }

    pthread_mutex_destroy(&gen->lock);
    free(gen);

    LOG_DEBUG("Destroyed certificate generator");
}

/* Client Capability Detection */

bool cert_generator_client_supports_ecdsa(SSL *ssl) {
    if (!ssl) {
        LOG_TRACE("No SSL connection, cannot detect client capabilities");
        return false;
    }

    /* Method 1: Check signature algorithms extension (TLS 1.3+) */
    int num_sigalgs = SSL_get_sigalgs(ssl, 0, NULL, NULL, NULL, NULL, NULL);
    if (num_sigalgs > 0) {
        for (int i = 0; i < num_sigalgs; i++) {
            int sign_nid, hash_nid, pkey_nid;

            if (SSL_get_sigalgs(ssl, i, &sign_nid, &hash_nid, &pkey_nid, NULL, NULL) > 0) {
                /* Check for ECDSA support */
                if (pkey_nid == EVP_PKEY_EC) {
                    LOG_TRACE("Client supports ECDSA (signature algorithm extension)");
                    return true;
                }
            }
        }

        LOG_TRACE("Client does not advertise ECDSA in signature algorithms");
        return false;
    }

    /* Method 2: Check cipher suites (TLS 1.2) */
    STACK_OF(SSL_CIPHER) *client_ciphers = SSL_get_client_ciphers(ssl);
    if (client_ciphers) {
        int num_ciphers = sk_SSL_CIPHER_num(client_ciphers);
        for (int i = 0; i < num_ciphers; i++) {
            const SSL_CIPHER *cipher = sk_SSL_CIPHER_value(client_ciphers, i);
            const char *name = SSL_CIPHER_get_name(cipher);

            /* Check for ECDSA cipher suites */
            if (name && strstr(name, "ECDSA") != NULL) {
                LOG_TRACE("Client supports ECDSA (cipher suite: %s)", name);
                return true;
            }
        }
    }

    LOG_TRACE("Client does not support ECDSA, fallback to RSA");
    return false;
}

crypto_alg_t cert_generator_select_algorithm(cert_generator_t *gen, SSL *ssl) {
    if (!gen) {
        return CRYPTO_ALG_RSA_3072;  /* Safe default */
    }

    switch (gen->config.mode) {
        case CERT_GEN_MODE_ECDSA:
            /* Force ECDSA */
            LOG_TRACE("Mode ECDSA: using %s",
                     keypool_algorithm_name(gen->config.default_algorithm));
            return gen->config.default_algorithm;

        case CERT_GEN_MODE_RSA:
            /* Force RSA */
            LOG_TRACE("Mode RSA: using %s",
                     keypool_algorithm_name(gen->config.fallback_algorithm));
            return gen->config.fallback_algorithm;

        case CERT_GEN_MODE_PREFER_ECDSA:
            /* Prefer ECDSA, but allow fallback */
            LOG_TRACE("Mode PREFER_ECDSA: using %s",
                     keypool_algorithm_name(gen->config.default_algorithm));
            return gen->config.default_algorithm;

        case CERT_GEN_MODE_AUTO:
        default:
            /* Auto-detect based on client */
            if (gen->config.detect_client_capabilities && ssl) {
                /* Priority: SM2 > ECDSA > RSA */
                bool supports_sm2 = cert_generator_client_supports_sm2(ssl);
                bool supports_ecdsa = cert_generator_client_supports_ecdsa(ssl);

                if (supports_sm2) {
                    atomic_fetch_add(&gen->stats.client_auto_sm2, 1);
                    LOG_DEBUG("Auto-selected SM2 for client");
                    return CRYPTO_ALG_SM2;
                } else if (supports_ecdsa) {
                    atomic_fetch_add(&gen->stats.client_auto_ecdsa, 1);
                    LOG_DEBUG("Auto-selected ECDSA for client");
                    return gen->config.default_algorithm;
                } else {
                    atomic_fetch_add(&gen->stats.client_auto_rsa, 1);
                    LOG_DEBUG("Auto-selected RSA for legacy client");
                    return gen->config.fallback_algorithm;
                }
            }

            /* No SSL connection or detection disabled, use default */
            LOG_TRACE("No client detection, using default %s",
                     keypool_algorithm_name(gen->config.default_algorithm));
            return gen->config.default_algorithm;
    }
}

/* X.509 Certificate Generation */

/* Add X509v3 extension */
static bool add_ext(X509 *cert, int nid, const char *value) {
    X509_EXTENSION *ex = NULL;
    X509V3_CTX ctx;

    /* Setup context */
    X509V3_set_ctx_nodb(&ctx);
    X509V3_set_ctx(&ctx, cert, cert, NULL, NULL, 0);

    /* Create extension */
    ex = X509V3_EXT_conf_nid(NULL, &ctx, nid, value);
    if (!ex) {
        LOG_ERROR("Failed to create extension (nid=%d): %s", nid, get_openssl_error());
        return false;
    }

    /* Add to certificate */
    if (!X509_add_ext(cert, ex, -1)) {
        LOG_ERROR("Failed to add extension (nid=%d): %s", nid, get_openssl_error());
        X509_EXTENSION_free(ex);
        return false;
    }

    X509_EXTENSION_free(ex);
    return true;
}

/* Save certificate + chain + key to PEM file for KI analysis and restart recovery */
static bool save_cert_chain_to_pem(const char *disk_cache_dir,
                                    const char *domain,
                                    X509 *cert,
                                    EVP_PKEY *pkey,
                                    STACK_OF(X509) *ca_chain,
                                    crypto_alg_t algorithm) {
    (void)algorithm; /* Unused - algorithm is implicit in disk_cache_dir path */

    if (!disk_cache_dir || !domain || !cert || !pkey) {
        return false;
    }

    /* Build filename: {disk_cache_dir}/{domain}.pem
     * Note: disk_cache_dir is already algorithm-specific (e.g., /opt/Aviontex/certs/RSA) */
    char filepath[1024];
    snprintf(filepath, sizeof(filepath), "%s/%s.pem",
             disk_cache_dir, domain);

    /* Open file for writing */
    FILE *fp = fopen(filepath, "wb");
    if (!fp) {
        LOG_ERROR("Failed to open PEM file for writing: %s (%s)",
                  filepath, strerror(errno));
        return false;
    }

    /* Correct order: Key → TLS Cert → SubCA → RootCA */

    /* 1. Write private key first (unencrypted - file permissions protect it) */
    if (!PEM_write_PrivateKey(fp, pkey, NULL, NULL, 0, NULL, NULL)) {
        LOG_ERROR("Failed to write private key to PEM: %s", filepath);
        fclose(fp);
        return false;
    }

    /* 2. Write TLS certificate (end-entity) */
    if (!PEM_write_X509(fp, cert)) {
        LOG_ERROR("Failed to write certificate to PEM: %s", filepath);
        fclose(fp);
        return false;
    }

    /* 3. Write CA chain: SubCA → RootCA (if provided) */
    if (ca_chain) {
        int chain_len = sk_X509_num(ca_chain);
        for (int i = 0; i < chain_len; i++) {
            X509 *ca_cert = sk_X509_value(ca_chain, i);
            if (ca_cert && !PEM_write_X509(fp, ca_cert)) {
                LOG_ERROR("Failed to write CA chain cert %d to PEM: %s", i, filepath);
                fclose(fp);
                return false;
            }
        }
    }

    fclose(fp);

    /* Set secure file permissions (owner read/write only) */
    chmod(filepath, 0600);

    LOG_INFO("Saved certificate chain to PEM: %s", filepath);
    return true;
}

X509* cert_generator_generate_cert(cert_generator_t *gen,
                                    const char *domain,
                                    crypto_alg_t algorithm,
                                    EVP_PKEY **pkey_out) {
    if (!gen || !domain || !pkey_out) {
        LOG_ERROR("Invalid parameters for cert generation");
        return NULL;
    }

    /* Check if legacy crypto is requested but not enabled */
    if ((algorithm == CRYPTO_ALG_RSA_1024 || algorithm == CRYPTO_ALG_RSA_2048) &&
        !g_legacy_crypto_enabled) {
        LOG_ERROR("Legacy crypto algorithm %d requested but not enabled (set legacy_crypto=true in config)",
                 algorithm);
        return NULL;
    }

    long long start_time = get_time_us();
    X509 *cert = NULL;
    EVP_PKEY *pkey = NULL;
    bool success = false;

    /* Multi-SubCA Support: Select correct SubCA based on algorithm */
    X509 *ca_cert = gen->config.ca_cert;  /* Default: single CA */
    EVP_PKEY *ca_key = gen->config.ca_key;

    if (gen->config.multi_ca) {
        /* Multi-SubCA mode: select SubCA based on algorithm */
        ca_config_t *subca = multi_ca_get_subca_for_algorithm(gen->config.multi_ca, algorithm);
        if (!subca) {
            LOG_ERROR("No SubCA available for algorithm %s", keypool_algorithm_name(algorithm));
            atomic_fetch_add(&gen->stats.generation_errors, 1);
            return NULL;
        }
        ca_cert = ca_get_signing_cert(subca);
        ca_key = ca_get_private_key(subca);

        if (!ca_cert || !ca_key) {
            LOG_ERROR("Failed to get SubCA for algorithm %s", keypool_algorithm_name(algorithm));
            atomic_fetch_add(&gen->stats.generation_errors, 1);
            return NULL;
        }
    }

    /* Verify we have CA cert and key */
    if (!ca_cert || !ca_key) {
        LOG_ERROR("No CA certificate or key configured");
        atomic_fetch_add(&gen->stats.generation_errors, 1);
        return NULL;
    }

    LOG_DEBUG("Generating certificate: domain=%s, algorithm=%s",
             domain, keypool_algorithm_name(algorithm));

    /* Acquire private key from pool */
    if (gen->config.keypool) {
        pkey = keypool_acquire(gen->config.keypool, algorithm);
        if (!pkey) {
            LOG_ERROR("Failed to acquire key from pool");
            atomic_fetch_add(&gen->stats.generation_errors, 1);
            return NULL;
        }
    } else {
        LOG_ERROR("No keypool configured");
        atomic_fetch_add(&gen->stats.generation_errors, 1);
        return NULL;
    }

    /* Create X509 certificate */
    cert = X509_new();
    if (!cert) {
        LOG_ERROR("Failed to create X509 structure: %s", get_openssl_error());
        goto cleanup;
    }

    /* Set version (X509v3) */
    if (!X509_set_version(cert, 2)) {  /* Version 3 = value 2 */
        LOG_ERROR("Failed to set certificate version: %s", get_openssl_error());
        goto cleanup;
    }

    /* Set serial number (random) */
    BIGNUM *bn = BN_new();
    if (bn && BN_rand(bn, 128, 0, 0)) {
        ASN1_INTEGER *serial = X509_get_serialNumber(cert);
        if (!BN_to_ASN1_INTEGER(bn, serial)) {
            LOG_ERROR("Failed to convert BIGNUM to ASN1_INTEGER: %s", get_openssl_error());
            BN_free(bn);
            goto cleanup;
        }
        BN_free(bn);
    } else {
        LOG_WARN("Failed to generate random serial, using timestamp");
        ASN1_INTEGER_set(X509_get_serialNumber(cert), (long)time(NULL));
        if (bn) BN_free(bn);
    }

    /* Set validity period with backdated creation time
     *
     * Anti-Detection: Backdate certificate creation by 2-14 days (random)
     * - Real certificates are never created "today"
     * - Each cert gets unique age (prevents fingerprinting)
     * - Looks natural to inspection tools
     */
    long backdate_offset = get_cert_backdate_offset();

    /* SECURITY FIX: Ensure validity period is always positive
     * Calculate the validity duration first, validate it's positive */
    long validity_seconds = (long)gen->config.validity_days * 24L * 60L * 60L;
    if (validity_seconds <= 0) {
        LOG_ERROR("Invalid certificate validity period: %d days", gen->config.validity_days);
        goto cleanup;
    }

    X509_gmtime_adj(X509_get_notBefore(cert), backdate_offset);
    X509_gmtime_adj(X509_get_notAfter(cert), backdate_offset + validity_seconds);

    /* SECURITY FIX: Verify notAfter > notBefore after setting times
     * This catches any potential issues with time calculations */
    const ASN1_TIME *not_before = X509_getm_notBefore(cert);
    const ASN1_TIME *not_after = X509_getm_notAfter(cert);

    if (!not_before || !not_after) {
        LOG_ERROR("Failed to retrieve certificate time fields");
        goto cleanup;
    }

    /* Set subject (CN = domain or wildcard base)
     * CRITICAL FIX: For wildcard certificates, use base domain as CN, not the subdomain
     * Problem: If CN=www.example.com and SAN=*.example.com, browsers reject quelle.de
     * Solution: When wildcard is enabled, set CN to the wildcard base domain
     * Examples:
     *   - Request: www.example.com  → CN: example.com (wildcard base), SAN: *.example.com
     *   - Request: api.example.com  → CN: example.com (wildcard base), SAN: *.example.com
     *   - Request: example.com      → CN: example.com (exact match, no wildcard)
     */
    const char *cn_domain = domain;  /* Default: use requested domain */

    /* Determine CN based on wildcard eligibility */
    if (gen->config.enable_wildcards && domain[0] != '*' &&
        algorithm != CRYPTO_ALG_RSA_1024 && algorithm != CRYPTO_ALG_RSA_2048) {
        const char *wildcard_base = get_wildcard_base_domain(domain, gen->tld_set);
        if (wildcard_base) {
            /* Use wildcard base as CN for consistency with SAN */
            cn_domain = wildcard_base;
            LOG_DEBUG("Using wildcard base domain for CN: %s (requested: %s)", cn_domain, domain);
        }
    }

    X509_NAME *subject = X509_get_subject_name(cert);
    /* ERROR CHECK FIX: Check if X509_NAME_add_entry_by_txt succeeded */
    if (!X509_NAME_add_entry_by_txt(subject, "CN", MBSTRING_ASC,
                               (const unsigned char*)cn_domain, -1, -1, 0)) {
        LOG_ERROR("Failed to set CN=%s: %s", cn_domain, get_openssl_error());
        goto cleanup;
    }

    /* Set issuer (copy from CA cert) */
    X509_NAME *issuer = X509_get_subject_name(ca_cert);
    /* ERROR CHECK FIX: Check if X509_set_issuer_name succeeded */
    if (!X509_set_issuer_name(cert, issuer)) {
        LOG_ERROR("Failed to set issuer name: %s", get_openssl_error());
        goto cleanup;
    }

    /* Set public key */
    if (!X509_set_pubkey(cert, pkey)) {
        LOG_ERROR("Failed to set public key: %s", get_openssl_error());
        goto cleanup;
    }

    /* Add extensions
     *
     * ULTRA-LEGACY MODE (16-Bit DOS, MS-DOS, Win 3.11, OS/2, AS/400):
     * For RSA-1024/2048, skip ALL extensions for maximum compatibility.
     * Many 16-bit DOS SSL stacks cannot parse X.509v3 extensions properly.
     * This creates a minimal "v1-style" certificate that works with ancient clients.
     *
     * Only add extensions for modern algorithms (RSA-3072+, ECDSA, etc.)
     */
    bool is_ultra_legacy = (algorithm == CRYPTO_ALG_RSA_1024 || algorithm == CRYPTO_ALG_RSA_2048);

    if (!is_ultra_legacy) {
        /* Modern certificates: Add standard extensions */

        /* Basic Constraints: CA=FALSE */
        if (!add_ext(cert, NID_basic_constraints, "CA:FALSE")) {
            goto cleanup;
        }

        /* Key Usage: Digital Signature, Key Encipherment */
        if (!add_ext(cert, NID_key_usage, "digitalSignature,keyEncipherment")) {
            goto cleanup;
        }

        /* Extended Key Usage: TLS Web Server + Client Authentication (mTLS support) */
        if (!add_ext(cert, NID_ext_key_usage, "serverAuth,clientAuth")) {
            goto cleanup;
        }

        /* DEMO: Subject Key Identifier - Contains public key hash for certificate matching */
        if (!add_ext(cert, NID_subject_key_identifier, "hash")) {
            goto cleanup;
        }

        /* DEMO: Authority Key Identifier - Links to signing CA's public key identifier */
        if (!add_ext(cert, NID_authority_key_identifier, "keyid:always")) {
            goto cleanup;
        }
    } else {
        LOG_DEBUG("Ultra-legacy mode: Skipping extensions for %s (16-bit DOS compatibility)",
                 keypool_algorithm_name(algorithm));
    }

    /* Subject Alternative Name (SAN)
     * Skip for ultra-legacy (DOS cannot parse SAN) */
    if (!is_ultra_legacy && gen->config.enable_san) {
        /* SECURITY FIX: Dynamically allocate SAN value to prevent buffer overflow */
        size_t domain_len = strlen(domain);

        /* Determine if wildcard should be used (enhanced with 2nd-level TLD support)
         *
         * LEGACY MODE: KEINE Wildcards NUR BEI Legacy Algorithmen (RSA-1024/2048)!
         *
         * Gilt NUR wenn --legacy-crypto Flag gesetzt ist:
         * - RSA-1024/2048 generiert Zertifikate OHNE Wildcard SAN
         * - CN muss EXAKT den kompletten Hostnamen enthalten
         * - www.example.com MUSS im CN stehen (nicht *.example.com)
         * - Pre-SNI Era Clients (MS-DOS, Win3.11, Win95/98) prüfen nur CN
         * - Diese Clients verstehen Wildcard Matching NICHT
         *
         * Normal (RSA-3072+, ECDSA): www.example.com → CN=www.example.com, SAN=DNS:www.example.com,DNS:*.example.com
         * Legacy (RSA-1024/2048):    www.example.com → CN=www.example.com, SAN=DNS:www.example.com (kein Wildcard!)
         */
        const char *wildcard_base = NULL;
        if (gen->config.enable_wildcards && domain[0] != '*' &&
            algorithm != CRYPTO_ALG_RSA_1024 && algorithm != CRYPTO_ALG_RSA_2048) {
            wildcard_base = get_wildcard_base_domain(domain, gen->tld_set);
        }

        size_t san_size;
        if (wildcard_base) {
            size_t wildcard_len = strlen(wildcard_base);
            /* SECURITY FIX: Explicit SAN size calculation for clarity
             * Format: "DNS:domain,DNS:*.wildcard_base\0"
             * Breakdown: "DNS:" (4) + domain (domain_len) + "," (1) + "DNS:*." (6) + wildcard (wildcard_len) + "\0" (1)
             * Total: 4 + domain_len + 1 + 6 + wildcard_len + 1 = 12 + domain_len + wildcard_len */
            const size_t SAFE_SAN_MAX = 8192;

            /* Check for integer overflow before calculating san_size */
            if (domain_len > SAFE_SAN_MAX - 12 || wildcard_len > SAFE_SAN_MAX - 12) {
                LOG_ERROR("Domain name too long for SAN extension: domain=%zu, wildcard=%zu",
                         domain_len, wildcard_len);
                goto cleanup;
            }

            san_size = 4 + domain_len + 1 + 6 + wildcard_len + 1;  /* Explicit: DNS: + domain + , + DNS:*. + base + \0 */
        } else {
            /* SECURITY FIX: Explicit SAN size calculation for non-wildcard case
             * Format: "DNS:domain\0"
             * Breakdown: "DNS:" (4) + domain (domain_len) + "\0" (1) */
            const size_t SAFE_SAN_MAX = 8192;

            if (domain_len > SAFE_SAN_MAX - 5) {  /* 4 for "DNS:" + 1 for null terminator */
                LOG_ERROR("Domain name too long for SAN extension: %zu bytes", domain_len);
                goto cleanup;
            }
            san_size = 4 + domain_len + 1;  /* Explicit: DNS: + domain + \0 */
        }

        if (san_size > 8192) {
            LOG_ERROR("SAN size check failed: %zu bytes (should not happen)", san_size);
            goto cleanup;
        }

        char *san_value = malloc(san_size);
        if (!san_value) {
            LOG_ERROR("Failed to allocate memory for SAN value");
            goto cleanup;
        }

        if (wildcard_base) {
            /* Add wildcard SAN for subdomains (OldCodeBase logic)
             * Examples:
             *   1.html-load.com    → DNS:1.html-load.com,DNS:*.html-load.com
             *   www.example.com    → DNS:www.example.com,DNS:*.example.com
             *   api.example.co.uk  → DNS:api.example.co.uk,DNS:*.example.co.uk
             *   example.com        → DNS:example.com (no wildcard)
             *   example.co.uk      → DNS:example.co.uk (no wildcard)
             */
            snprintf(san_value, san_size, "DNS:%s,DNS:*.%s", domain, wildcard_base);
        } else {
            snprintf(san_value, san_size, "DNS:%s", domain);
        }

        bool add_ext_result = add_ext(cert, NID_subject_alt_name, san_value);
        free(san_value);

        if (!add_ext_result) {
            goto cleanup;
        }
    }

    /* DEMO: Add public key information extension before signing
     * This allows browsers to display key algorithm and size (e.g., "RSA-3072", "ECDSA-P256", "RSA-1024")
     * Shows which key was actually used to sign - critical for verification
     * Uses private OID 1.3.6.1.4.1.tlsgate.1 for key information */
    int key_bits = EVP_PKEY_bits(pkey);
    int key_type = EVP_PKEY_id(pkey);
    const char *alg_name = NULL;

    switch (key_type) {
        case EVP_PKEY_RSA:
            alg_name = "RSA";
            break;
        case EVP_PKEY_EC:
            alg_name = "ECDSA";
            break;
        case EVP_PKEY_SM2:
            alg_name = "SM2";
            break;
        default:
            alg_name = "Unknown";
    }

    char key_info_value[256];
    snprintf(key_info_value, sizeof(key_info_value), "%s-%d", alg_name, key_bits);

    /* Register private OID for key information if not already registered */
    int key_info_nid = OBJ_txt2nid("1.3.6.1.4.1.tlsgate.1");
    if (key_info_nid == NID_undef) {
        key_info_nid = OBJ_create("1.3.6.1.4.1.tlsgate.1", "keyInfo", "TLSGate Key Information");
    }

    if (key_info_nid != NID_undef) {
        if (!add_ext(cert, key_info_nid, key_info_value)) {
            LOG_WARN("Failed to add key information extension (non-fatal, continuing)");
        } else {
            LOG_DEBUG("Added key information extension: %s", key_info_value);
        }
    }

    /* Sign certificate with CA key
     * Message digest selection:
     * - Legacy algorithms (RSA-1024/2048): SHA1 for maximum compatibility
     * - Modern algorithms: SHA-256 (standard)
     */
    const EVP_MD *md = select_signature_digest(algorithm);

    if (!X509_sign(cert, ca_key, md)) {
        LOG_ERROR("Failed to sign certificate: %s", get_openssl_error());
        goto cleanup;
    }

    success = true;

    /* Update statistics */
    long long end_time = get_time_us();
    long long duration = end_time - start_time;

    atomic_fetch_add(&gen->stats.total_generated, 1);
    atomic_fetch_add(&gen->stats.total_generation_time_us, duration);

    /* Update fastest/slowest */
    long long current_fastest = atomic_load_explicit(&gen->stats.fastest_generation_us, memory_order_acquire);
    if (duration < current_fastest) {
        atomic_store(&gen->stats.fastest_generation_us, duration);
    }

    long long current_slowest = atomic_load_explicit(&gen->stats.slowest_generation_us, memory_order_acquire);
    if (duration > current_slowest) {
        atomic_store(&gen->stats.slowest_generation_us, duration);
    }

    /* Track by algorithm */
    if (algorithm == CRYPTO_ALG_ECDSA_P256 ||
        algorithm == CRYPTO_ALG_ECDSA_P384 ||
        algorithm == CRYPTO_ALG_ECDSA_P521) {
        atomic_fetch_add(&gen->stats.generated_ecdsa, 1);
    } else {
        atomic_fetch_add(&gen->stats.generated_rsa, 1);
    }

    LOG_INFO("Generated certificate: %s (%s) in %lld μs",
            domain, keypool_algorithm_name(algorithm), duration);

cleanup:
    if (!success) {
        if (cert) {
            X509_free(cert);
            cert = NULL;
        }
        if (pkey) {
            EVP_PKEY_free(pkey);
            pkey = NULL;
        }
        atomic_fetch_add(&gen->stats.generation_errors, 1);
    } else {
        *pkey_out = pkey;
    }

    return cert;
}

X509* cert_generator_renew_cert(cert_generator_t *gen,
                                const char *domain,
                                EVP_PKEY *existing_key) {
    if (!gen || !domain || !existing_key) {
        LOG_ERROR("Invalid parameters for cert renewal");
        return NULL;
    }

    long long start_time = get_time_us();
    X509 *cert = NULL;
    bool success = false;

    /* Multi-SubCA Support for Certificate Renewal
     *
     * When renewing: Detect which SubCA originally signed this key
     * by examining the key type and parameters.
     * This ensures renewals use the same algorithm (SM2→SM2, RSA→RSA, etc.)
     */
    X509 *ca_cert = gen->config.ca_cert;
    EVP_PKEY *ca_key = gen->config.ca_key;

    /* Detect algorithm from the existing key being renewed */
    crypto_alg_t renewal_algorithm = detect_algorithm_from_key(existing_key);

    if (gen->config.multi_ca) {

        /* Get the SubCA that originally signed this key type */
        ca_config_t *subca = multi_ca_get_subca_for_algorithm(gen->config.multi_ca, renewal_algorithm);
        if (!subca) {
            LOG_ERROR("No SubCA available for renewal algorithm %s (key type mismatch?)",
                     keypool_algorithm_name(renewal_algorithm));
            atomic_fetch_add(&gen->stats.generation_errors, 1);
            return NULL;
        }

        ca_cert = ca_get_signing_cert(subca);
        ca_key = ca_get_private_key(subca);

        LOG_DEBUG("Certificate renewal: Using %s SubCA for key type %s",
                 keypool_algorithm_name(renewal_algorithm),
                 keypool_algorithm_name(renewal_algorithm));
    }

    if (!ca_cert || !ca_key) {
        LOG_ERROR("No CA certificate or key configured for renewal");
        atomic_fetch_add(&gen->stats.generation_errors, 1);
        return NULL;
    }

    LOG_DEBUG("Renewing certificate (with key reuse): domain=%s", domain);

    /* Create X509 certificate */
    cert = X509_new();
    if (!cert) {
        LOG_ERROR("Failed to create X509 structure: %s", get_openssl_error());
        goto cleanup;
    }

    /* Set version (X509v3) */
    if (!X509_set_version(cert, 2)) {  /* Version 3 = value 2 */
        LOG_ERROR("Failed to set certificate version: %s", get_openssl_error());
        goto cleanup;
    }

    /* Set serial number (random) */
    BIGNUM *bn = BN_new();
    if (bn && BN_rand(bn, 128, 0, 0)) {
        ASN1_INTEGER *serial = X509_get_serialNumber(cert);
        if (!BN_to_ASN1_INTEGER(bn, serial)) {
            LOG_ERROR("Failed to convert BIGNUM to ASN1_INTEGER: %s", get_openssl_error());
            BN_free(bn);
            goto cleanup;
        }
        BN_free(bn);
    } else {
        LOG_WARN("Failed to generate random serial, using timestamp");
        ASN1_INTEGER_set(X509_get_serialNumber(cert), (long)time(NULL));
        if (bn) BN_free(bn);
    }

    /* Set validity period (NEW dates) with backdated creation time
     *
     * Anti-Detection + Compatibility:
     * - Backdate by 2-14 days (random) prevents "future cert" errors
     * - Some clients/devices run 1-2 weeks behind (security, timezones)
     * - Cert created "today" would be rejected by these clients
     * - Backdating ensures compatibility even with clock-skewed devices
     */
    long backdate_offset = get_cert_backdate_offset();

    /* SECURITY FIX: Ensure validity period is always positive
     * Calculate the validity duration first, validate it's positive */
    long validity_seconds = (long)gen->config.validity_days * 24L * 60L * 60L;
    if (validity_seconds <= 0) {
        LOG_ERROR("Invalid certificate validity period: %d days", gen->config.validity_days);
        goto cleanup;
    }

    X509_gmtime_adj(X509_get_notBefore(cert), backdate_offset);
    X509_gmtime_adj(X509_get_notAfter(cert), backdate_offset + validity_seconds);

    /* SECURITY FIX: Verify notAfter > notBefore after setting times
     * This catches any potential issues with time calculations */
    const ASN1_TIME *not_before = X509_getm_notBefore(cert);
    const ASN1_TIME *not_after = X509_getm_notAfter(cert);

    if (!not_before || !not_after) {
        LOG_ERROR("Failed to retrieve certificate time fields");
        goto cleanup;
    }

    /* Set subject (CN = domain or wildcard base)
     * CRITICAL FIX: For wildcard certificates, use base domain as CN, not the subdomain
     * Problem: If CN=www.example.com and SAN=*.example.com, browsers reject quelle.de
     * Solution: When wildcard is enabled, set CN to the wildcard base domain
     * Examples:
     *   - Request: www.example.com  → CN: example.com (wildcard base), SAN: *.example.com
     *   - Request: api.example.com  → CN: example.com (wildcard base), SAN: *.example.com
     *   - Request: example.com      → CN: example.com (exact match, no wildcard)
     */
    const char *cn_domain = domain;  /* Default: use requested domain */

    /* Determine CN based on wildcard eligibility (use renewal_algorithm, not algorithm) */
    if (gen->config.enable_wildcards && domain[0] != '*' &&
        renewal_algorithm != CRYPTO_ALG_RSA_1024 && renewal_algorithm != CRYPTO_ALG_RSA_2048) {
        const char *wildcard_base = get_wildcard_base_domain(domain, gen->tld_set);
        if (wildcard_base) {
            /* Use wildcard base as CN for consistency with SAN */
            cn_domain = wildcard_base;
            LOG_DEBUG("Using wildcard base domain for CN: %s (requested: %s)", cn_domain, domain);
        }
    }

    X509_NAME *subject = X509_get_subject_name(cert);
    /* ERROR CHECK FIX: Check if X509_NAME_add_entry_by_txt succeeded */
    if (!X509_NAME_add_entry_by_txt(subject, "CN", MBSTRING_ASC,
                               (const unsigned char*)cn_domain, -1, -1, 0)) {
        LOG_ERROR("Failed to set CN=%s: %s", cn_domain, get_openssl_error());
        goto cleanup;
    }

    /* Set issuer (copy from CA cert) */
    X509_NAME *issuer = X509_get_subject_name(ca_cert);
    /* ERROR CHECK FIX: Check if X509_set_issuer_name succeeded */
    if (!X509_set_issuer_name(cert, issuer)) {
        LOG_ERROR("Failed to set issuer name: %s", get_openssl_error());
        goto cleanup;
    }

    /* Set public key (REUSE existing key) */
    if (!X509_set_pubkey(cert, existing_key)) {
        LOG_ERROR("Failed to set public key: %s", get_openssl_error());
        goto cleanup;
    }

    /* Add extensions
     *
     * ULTRA-LEGACY MODE (16-Bit DOS, MS-DOS, Win 3.11, OS/2, AS/400):
     * For RSA-1024/2048, skip ALL extensions for maximum compatibility.
     * Many 16-bit DOS SSL stacks cannot parse X.509v3 extensions properly.
     * This creates a minimal "v1-style" certificate that works with ancient clients.
     *
     * Only add extensions for modern algorithms (RSA-3072+, ECDSA, etc.)
     */
    bool is_ultra_legacy_renewal = (renewal_algorithm == CRYPTO_ALG_RSA_1024 ||
                                     renewal_algorithm == CRYPTO_ALG_RSA_2048);

    if (!is_ultra_legacy_renewal) {
        /* Modern certificates: Add standard extensions */

        /* Basic Constraints: CA=FALSE */
        if (!add_ext(cert, NID_basic_constraints, "CA:FALSE")) {
            goto cleanup;
        }

        /* Key Usage: Digital Signature, Key Encipherment */
        if (!add_ext(cert, NID_key_usage, "digitalSignature,keyEncipherment")) {
            goto cleanup;
        }

        /* Extended Key Usage: TLS Web Server + Client Authentication (mTLS support) */
        if (!add_ext(cert, NID_ext_key_usage, "serverAuth,clientAuth")) {
            goto cleanup;
        }

        /* DEMO: Subject Key Identifier - Contains public key hash for certificate matching */
        if (!add_ext(cert, NID_subject_key_identifier, "hash")) {
            goto cleanup;
        }

        /* DEMO: Authority Key Identifier - Links to signing CA's public key identifier */
        if (!add_ext(cert, NID_authority_key_identifier, "keyid:always")) {
            goto cleanup;
        }
    } else {
        LOG_DEBUG("Ultra-legacy renewal: Skipping extensions for %s (16-bit DOS compatibility)",
                 keypool_algorithm_name(renewal_algorithm));
    }

    /* Subject Alternative Name (SAN)
     * Skip for ultra-legacy (DOS cannot parse SAN) */
    if (!is_ultra_legacy_renewal && gen->config.enable_san) {
        /* SECURITY FIX: Dynamically allocate SAN value to prevent buffer overflow */
        size_t domain_len = strlen(domain);

        /* Determine if wildcard should be used (enhanced with 2nd-level TLD support)
         *
         * LEGACY MODE: KEINE Wildcards NUR BEI Legacy Algorithmen (RSA-1024/2048)!
         * (siehe Dokumentation in cert_generator_generate_cert() oben - gleiches Prinzip)
         */
        const char *wildcard_base = NULL;
        if (gen->config.enable_wildcards && domain[0] != '*' &&
            renewal_algorithm != CRYPTO_ALG_RSA_1024 && renewal_algorithm != CRYPTO_ALG_RSA_2048) {
            wildcard_base = get_wildcard_base_domain(domain, gen->tld_set);
        }

        size_t san_size;
        if (wildcard_base) {
            size_t wildcard_len = strlen(wildcard_base);
            /* SECURITY FIX: Explicit SAN size calculation for clarity
             * Format: "DNS:domain,DNS:*.wildcard_base\0"
             * Breakdown: "DNS:" (4) + domain (domain_len) + "," (1) + "DNS:*." (6) + wildcard (wildcard_len) + "\0" (1)
             * Total: 4 + domain_len + 1 + 6 + wildcard_len + 1 = 12 + domain_len + wildcard_len */
            const size_t SAFE_SAN_MAX = 8192;

            /* Check for integer overflow before calculating san_size */
            if (domain_len > SAFE_SAN_MAX - 12 || wildcard_len > SAFE_SAN_MAX - 12) {
                LOG_ERROR("Domain name too long for SAN extension: domain=%zu, wildcard=%zu",
                         domain_len, wildcard_len);
                goto cleanup;
            }

            san_size = 4 + domain_len + 1 + 6 + wildcard_len + 1;  /* Explicit: DNS: + domain + , + DNS:*. + base + \0 */
        } else {
            /* SECURITY FIX: Explicit SAN size calculation for non-wildcard case
             * Format: "DNS:domain\0"
             * Breakdown: "DNS:" (4) + domain (domain_len) + "\0" (1) */
            const size_t SAFE_SAN_MAX = 8192;

            if (domain_len > SAFE_SAN_MAX - 5) {  /* 4 for "DNS:" + 1 for null terminator */
                LOG_ERROR("Domain name too long for SAN extension: %zu bytes", domain_len);
                goto cleanup;
            }
            san_size = 4 + domain_len + 1;  /* Explicit: DNS: + domain + \0 */
        }

        if (san_size > 8192) {
            LOG_ERROR("SAN size check failed: %zu bytes (should not happen)", san_size);
            goto cleanup;
        }

        char *san_value = malloc(san_size);
        if (!san_value) {
            LOG_ERROR("Failed to allocate memory for SAN value");
            goto cleanup;
        }

        if (wildcard_base) {
            /* Add wildcard SAN for subdomains (OldCodeBase logic)
             * Examples:
             *   1.html-load.com    → DNS:1.html-load.com,DNS:*.html-load.com
             *   www.example.com    → DNS:www.example.com,DNS:*.example.com
             *   api.example.co.uk  → DNS:api.example.co.uk,DNS:*.example.co.uk
             *   example.com        → DNS:example.com (no wildcard)
             *   example.co.uk      → DNS:example.co.uk (no wildcard)
             */
            snprintf(san_value, san_size, "DNS:%s,DNS:*.%s", domain, wildcard_base);
        } else {
            snprintf(san_value, san_size, "DNS:%s", domain);
        }

        bool add_ext_result = add_ext(cert, NID_subject_alt_name, san_value);
        free(san_value);

        if (!add_ext_result) {
            goto cleanup;
        }
    }

    /* DEMO: Add public key information extension before signing (renewal)
     * This allows browsers to display key algorithm and size (e.g., "RSA-3072", "ECDSA-P256", "RSA-1024")
     * Shows which key was actually used to sign - critical for verification
     * Uses private OID 1.3.6.1.4.1.tlsgate.1 for key information */
    int renewal_key_bits = EVP_PKEY_bits(existing_key);
    int renewal_key_type = EVP_PKEY_id(existing_key);
    const char *renewal_alg_name = NULL;

    switch (renewal_key_type) {
        case EVP_PKEY_RSA:
            renewal_alg_name = "RSA";
            break;
        case EVP_PKEY_EC:
            renewal_alg_name = "ECDSA";
            break;
        case EVP_PKEY_SM2:
            renewal_alg_name = "SM2";
            break;
        default:
            renewal_alg_name = "Unknown";
    }

    char renewal_key_info_value[256];
    snprintf(renewal_key_info_value, sizeof(renewal_key_info_value), "%s-%d", renewal_alg_name, renewal_key_bits);

    /* Register private OID for key information if not already registered */
    int renewal_key_info_nid = OBJ_txt2nid("1.3.6.1.4.1.tlsgate.1");
    if (renewal_key_info_nid == NID_undef) {
        renewal_key_info_nid = OBJ_create("1.3.6.1.4.1.tlsgate.1", "keyInfo", "TLSGate Key Information");
    }

    if (renewal_key_info_nid != NID_undef) {
        if (!add_ext(cert, renewal_key_info_nid, renewal_key_info_value)) {
            LOG_WARN("Failed to add key information extension (non-fatal, continuing)");
        } else {
            LOG_DEBUG("Added key information extension: %s", renewal_key_info_value);
        }
    }

    /* Sign certificate with CA key
     * Message digest selection:
     * - Legacy algorithms (RSA-1024/2048): SHA1 for maximum compatibility
     * - Modern algorithms: SHA-256 (standard)
     */
    const EVP_MD *md = select_signature_digest(renewal_algorithm);

    if (!X509_sign(cert, ca_key, md)) {
        LOG_ERROR("Failed to sign certificate: %s", get_openssl_error());
        goto cleanup;
    }

    success = true;

    /* Update statistics */
    long long end_time = get_time_us();
    long long duration = end_time - start_time;

    LOG_INFO("Renewed certificate (key reused): %s in %lld μs", domain, duration);

cleanup:
    if (!success) {
        if (cert) {
            X509_free(cert);
            cert = NULL;
        }
        atomic_fetch_add(&gen->stats.generation_errors, 1);
    }

    return cert;
}

SSL_CTX* cert_generator_create_ssl_ctx(X509 *cert, EVP_PKEY *pkey,
                                        STACK_OF(X509) *ca_chain) {
    if (!cert || !pkey) {
        LOG_ERROR("Invalid certificate or key for SSL_CTX creation");
        return NULL;
    }

    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) {
        LOG_ERROR("Failed to create SSL_CTX: %s", get_openssl_error());
        return NULL;
    }

    /* Set certificate */
    if (SSL_CTX_use_certificate(ctx, cert) <= 0) {
        LOG_ERROR("Failed to set certificate: %s", get_openssl_error());
        SSL_CTX_free(ctx);
        return NULL;
    }

    /* Set private key */
    if (SSL_CTX_use_PrivateKey(ctx, pkey) <= 0) {
        LOG_ERROR("Failed to set private key: %s", get_openssl_error());
        SSL_CTX_free(ctx);
        return NULL;
    }

    /* Verify private key matches certificate */
    if (!SSL_CTX_check_private_key(ctx)) {
        LOG_ERROR("Private key does not match certificate: %s", get_openssl_error());
        SSL_CTX_free(ctx);
        return NULL;
    }

    /* Add CA certificate chain (if provided)
     * This ensures clients receive the full chain for validation.
     * Send ALL certificates so clients can build trust path to Root CA.
     */
    if (ca_chain && sk_X509_num(ca_chain) > 0) {
        int num_chain = sk_X509_num(ca_chain);
        LOG_DEBUG("Adding CA certificate chain to SSL_CTX (%d certs)", num_chain);

        /* Add ALL certificates from the chain (Root CA, Intermediate CAs) */
        for (int i = 0; i < num_chain; i++) {
            X509 *chain_cert = sk_X509_value(ca_chain, i);
            if (chain_cert) {
                /* SSL_CTX_add_extra_chain_cert takes ownership, so we need to dup */
                X509 *cert_dup = X509_dup(chain_cert);
                if (!cert_dup) {
                    LOG_ERROR("Failed to duplicate chain certificate");
                    SSL_CTX_free(ctx);
                    return NULL;
                }

                if (!SSL_CTX_add_extra_chain_cert(ctx, cert_dup)) {
                    LOG_ERROR("Failed to add chain certificate: %s",
                             get_openssl_error());
                    X509_free(cert_dup);
                    SSL_CTX_free(ctx);
                    return NULL;
                }

                LOG_TRACE("Added chain certificate %d to SSL_CTX", i);
            }
        }

        LOG_DEBUG("Successfully added full CA chain to SSL_CTX (%d certs)", num_chain);
    } else {
        LOG_WARN("No CA chain provided - clients may not trust certificates!");
    }

    /* Set secure options */
    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);
    SSL_CTX_set_options(ctx, SSL_OP_SINGLE_DH_USE | SSL_OP_SINGLE_ECDH_USE);

    /* Set cipher preferences */
    SSL_CTX_set_cipher_list(ctx, "HIGH:!aNULL:!MD5:!RC4");

    LOG_TRACE("Created SSL_CTX");
    return ctx;
}

/* High-Level API */

/* Load SSL_CTX from PEM file on disk
 *
 * @param pem_path  Path to PEM file (cert + key + chain)
 * @param ca_chain  CA chain to add if not in PEM
 * @return SSL_CTX or NULL if file doesn't exist or is invalid
 */
static SSL_CTX* load_ssl_ctx_from_pem(const char *pem_path, STACK_OF(X509) *ca_chain) {
    FILE *fp = fopen(pem_path, "rb");
    if (!fp) {
        return NULL;  /* File doesn't exist - not an error */
    }

    /* Read server certificate */
    X509 *cert = PEM_read_X509(fp, NULL, NULL, NULL);
    if (!cert) {
        fclose(fp);
        return NULL;
    }

    /* Read CA chain from PEM (all certs until private key) */
    STACK_OF(X509) *pem_chain = sk_X509_new_null();
    if (pem_chain) {
        X509 *chain_cert = NULL;
        while ((chain_cert = PEM_read_X509(fp, NULL, NULL, NULL)) != NULL) {
            sk_X509_push(pem_chain, chain_cert);
        }
        /* Clear error from failed read (expected at end of certs) */
        ERR_clear_error();
    }

    /* Read private key */
    EVP_PKEY *pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);

    if (!pkey) {
        X509_free(cert);
        sk_X509_pop_free(pem_chain, X509_free);
        return NULL;
    }

    /* Create SSL_CTX */
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) {
        X509_free(cert);
        EVP_PKEY_free(pkey);
        sk_X509_pop_free(pem_chain, X509_free);
        return NULL;
    }

    /* Set certificate and key */
    if (SSL_CTX_use_certificate(ctx, cert) != 1 ||
        SSL_CTX_use_PrivateKey(ctx, pkey) != 1) {
        SSL_CTX_free(ctx);
        X509_free(cert);
        EVP_PKEY_free(pkey);
        sk_X509_pop_free(pem_chain, X509_free);
        return NULL;
    }

    /* Add chain from PEM file first (if present) */
    if (pem_chain && sk_X509_num(pem_chain) > 0) {
        for (int i = 0; i < sk_X509_num(pem_chain); i++) {
            X509 *cc = sk_X509_value(pem_chain, i);
            SSL_CTX_add_extra_chain_cert(ctx, X509_dup(cc));
        }
    }
    /* Otherwise use provided CA chain */
    else if (ca_chain && sk_X509_num(ca_chain) > 0) {
        for (int i = 0; i < sk_X509_num(ca_chain); i++) {
            X509 *cc = sk_X509_value(ca_chain, i);
            SSL_CTX_add_extra_chain_cert(ctx, X509_dup(cc));
        }
    }

    /* Cleanup */
    X509_free(cert);
    EVP_PKEY_free(pkey);
    sk_X509_pop_free(pem_chain, X509_free);

    /* Set secure options */
    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);

    return ctx;
}

/* Get algorithm subdirectory name */
static const char* get_algorithm_subdir(crypto_alg_t algorithm) {
    switch (algorithm) {
        case CRYPTO_ALG_RSA_1024:
        case CRYPTO_ALG_RSA_2048:
        case CRYPTO_ALG_RSA_3072:
        case CRYPTO_ALG_RSA_4096:
        case CRYPTO_ALG_RSA_8192:
            return "RSA";
        case CRYPTO_ALG_ECDSA_P256:
        case CRYPTO_ALG_ECDSA_P384:
        case CRYPTO_ALG_ECDSA_P521:
            return "ECDSA";
        case CRYPTO_ALG_SM2:
            return "SM2";
        case CRYPTO_ALG_ED25519:
            return "ED25519";
        default:
            return "OTHER";
    }
}

SSL_CTX* cert_generator_get_ctx(cert_generator_t *gen,
                                 const char *domain,
                                 SSL *ssl) {
    if (!gen || !domain) {
        LOG_ERROR("Invalid parameters");
        return NULL;
    }

    LOG_DEBUG("Getting SSL_CTX for domain: %s", domain);

    /* Step 1: Select algorithm based on client */
    crypto_alg_t algorithm = cert_generator_select_algorithm(gen, ssl);

    /* Step 2: Check cache (prefer SHM certcache > cert_index > legacy cert_cache) */
    if (gen->config.cache_certificates) {
        SSL_CTX *cached_ctx = NULL;

        /* Step 2a: Try SHM certcache first (multi-instance shared mode) */
        if (gen->config.shm_certcache && gen->config.certs_dir) {
            certcache_shm_t *shm = (certcache_shm_t*)gen->config.shm_certcache;
            certindex_entry_t entry;

            if (certcache_shm_lookup_full(shm, domain, (int)algorithm, &entry)) {
                /* Found in SHM index */
                if (atomic_load_explicit(&entry.generation_in_progress, memory_order_acquire)) {
                    /* Another process is generating - skip to avoid duplicate work */
                    LOG_DEBUG("SHM: Generation in progress for %s, waiting...", domain);
                    /* Could add a short wait here, but for now just proceed to generate */
                }
                else if (atomic_load_explicit(&entry.on_disk, memory_order_acquire)) {
                    /* Cert exists on disk - load it */
                    char pem_path[512];
                    snprintf(pem_path, sizeof(pem_path), "%s/%s/%s.pem",
                             gen->config.certs_dir, get_algorithm_subdir(algorithm), domain);

                    cached_ctx = load_ssl_ctx_from_pem(pem_path, gen->config.ca_chain);
                    if (cached_ctx) {
                        /* Check certificate expiry */
                        X509 *cert = SSL_CTX_get0_certificate(cached_ctx);
                        time_t expiry = atomic_load_explicit(&entry.expiry_time, memory_order_acquire);
                        if (cert && expiry > 0 && expiry < time(NULL)) {
                            /* Expired - will regenerate below */
                            LOG_WARN("SHM: Certificate expired for %s - will regenerate", domain);
                            SSL_CTX_free(cached_ctx);
                            cached_ctx = NULL;
                        } else {
                            atomic_fetch_add(&gen->stats.cache_hits, 1);
                            LOG_DEBUG("SHM HIT (disk): %s (%s)", domain, keypool_algorithm_name(algorithm));
                            return cached_ctx;
                        }
                    }
                }
            }
            /* Not in SHM - try direct disk load as fallback */
            else if (gen->config.certs_dir) {
                char pem_path[512];
                snprintf(pem_path, sizeof(pem_path), "%s/%s/%s.pem",
                         gen->config.certs_dir, get_algorithm_subdir(algorithm), domain);

                cached_ctx = load_ssl_ctx_from_pem(pem_path, gen->config.ca_chain);
                if (cached_ctx) {
                    /* Found on disk but not in SHM - add to SHM */
                    X509 *cert = SSL_CTX_get0_certificate(cached_ctx);
                    time_t expiry = 0;
                    if (cert) {
                        const ASN1_TIME *not_after = X509_get0_notAfter(cert);
                        if (not_after) {
                            struct tm tm = {0};
                            ASN1_TIME_to_tm(not_after, &tm);
                            expiry = mktime(&tm);
                        }
                    }

                    /* Check if expired */
                    if (expiry > 0 && expiry < time(NULL)) {
                        LOG_WARN("Disk: Certificate expired for %s - will regenerate", domain);
                        SSL_CTX_free(cached_ctx);
                        cached_ctx = NULL;
                    } else {
                        /* Add to SHM for future lookups */
                        certcache_shm_insert_full(shm, domain, (int)algorithm, expiry, true);
                        atomic_fetch_add(&gen->stats.cache_hits, 1);
                        LOG_DEBUG("Disk HIT (added to SHM): %s (%s)", domain, keypool_algorithm_name(algorithm));
                        return cached_ctx;
                    }
                }
            }

            atomic_fetch_add(&gen->stats.cache_misses, 1);
            LOG_DEBUG("SHM/Disk MISS: %s (%s)", domain, keypool_algorithm_name(algorithm));
        }

        /* Step 2b: Try cert_index (high-scale mode with local SSL_CTX cache) */
        if (gen->config.cert_index) {
            cert_index_t *index = (cert_index_t*)gen->config.cert_index;
            cached_ctx = cert_index_get(index, domain, algorithm);

            if (cached_ctx) {
                /* Check certificate expiry (auto-renewal with key reuse) */
                X509 *cert = SSL_CTX_get0_certificate(cached_ctx);
                if (cert && X509_cmp_time(X509_get_notAfter(cert), NULL) < 0) {
                    /* Certificate EXPIRED - renew with existing key (fast!) */
                    LOG_WARN("Certificate expired for %s - auto-renewing", domain);

                    EVP_PKEY *old_key = SSL_CTX_get0_privatekey(cached_ctx);
                    if (old_key) {
                        /* Generate new certificate with existing key */
                        X509 *new_cert = cert_generator_renew_cert(gen, domain, old_key);
                        if (new_cert) {
                            /* Create new SSL_CTX with renewed certificate */
                            SSL_CTX *new_ctx = cert_generator_create_ssl_ctx(new_cert, old_key,
                                                                              gen->config.ca_chain);
                            if (new_ctx) {
                                /* Replace in index (atomic update) */
                                cert_index_add(index, domain, new_ctx, new_cert, algorithm);
                                LOG_INFO("Auto-renewed certificate: %s (key reused)", domain);
                                atomic_fetch_add(&gen->stats.cache_hits, 1);
                                X509_free(new_cert);
                                return new_ctx;
                            }
                            X509_free(new_cert);
                        }
                    }

                    /* Fallback: Use expired cert (better than nothing) */
                    LOG_WARN("Failed to renew cert for %s - using expired cert", domain);
                }

                atomic_fetch_add(&gen->stats.cache_hits, 1);
                LOG_DEBUG("Index HIT: %s (%s)", domain, keypool_algorithm_name(algorithm));
                return cached_ctx;
            }

            atomic_fetch_add(&gen->stats.cache_misses, 1);
            LOG_DEBUG("Index MISS: %s (%s)", domain, keypool_algorithm_name(algorithm));
        }
        /* Fall back to legacy cert_cache if no cert_index */
        else if (gen->config.cert_cache) {
            cache_key_t key = cert_cache_make_key(domain, algorithm);
            cached_ctx = cert_cache_get(gen->config.cert_cache, &key);

            if (cached_ctx) {
                /* Check certificate expiry (auto-renewal with key reuse) */
                X509 *cert = SSL_CTX_get0_certificate(cached_ctx);
                if (cert && X509_cmp_time(X509_get_notAfter(cert), NULL) < 0) {
                    /* Certificate EXPIRED - renew with existing key (fast!) */
                    LOG_WARN("Certificate expired for %s - auto-renewing", domain);

                    EVP_PKEY *old_key = SSL_CTX_get0_privatekey(cached_ctx);
                    if (old_key) {
                        /* Generate new certificate with existing key */
                        X509 *new_cert = cert_generator_renew_cert(gen, domain, old_key);
                        if (new_cert) {
                            /* Create new SSL_CTX with renewed certificate */
                            SSL_CTX *new_ctx = cert_generator_create_ssl_ctx(new_cert, old_key,
                                                                              gen->config.ca_chain);
                            if (new_ctx) {
                                /* Replace in cache (NEVER delete - just overwrite!) */
                                cert_cache_put(gen->config.cert_cache, &key, new_ctx);
                                LOG_INFO("Auto-renewed certificate: %s (key reused)", domain);
                                atomic_fetch_add(&gen->stats.cache_hits, 1);
                                X509_free(new_cert);
                                return new_ctx;
                            }
                            X509_free(new_cert);
                        }
                    }

                    /* Fallback: Use expired cert (better than nothing) */
                    LOG_WARN("Failed to renew cert for %s - using expired cert", domain);
                }

                atomic_fetch_add(&gen->stats.cache_hits, 1);
                LOG_DEBUG("Cache HIT: %s (%s)", domain, keypool_algorithm_name(algorithm));
                return cached_ctx;
            }

            atomic_fetch_add(&gen->stats.cache_misses, 1);
            LOG_DEBUG("Cache MISS: %s (%s)", domain, keypool_algorithm_name(algorithm));
        }
    }

    /* Step 2.5: Check for existing wildcard certificate (optimization!)
     * If wildcards are enabled and a wildcard base domain exists, try to reuse
     * an existing wildcard certificate instead of generating a new one.
     *
     * Example: api.example.com → Check if *.example.com already exists
     *          If yes, reuse it! (saves 80-95% of cert generations)
     *
     * LEGACY MODE FIX: No wildcard reuse for legacy algorithms (RSA-1024/2048)
     * Legacy mode requires exact CN match only
     */
    if (gen->config.enable_wildcards && domain[0] != '*' &&
        algorithm != CRYPTO_ALG_RSA_1024 && algorithm != CRYPTO_ALG_RSA_2048) {
        const char *wildcard_base = get_wildcard_base_domain(domain, gen->tld_set);
        if (wildcard_base) {
            /* Try to find existing wildcard certificate for base domain */
            if (gen->config.cert_index) {
                cert_index_t *index = (cert_index_t*)gen->config.cert_index;
                SSL_CTX *wildcard_ctx = cert_index_get(index, wildcard_base, algorithm);

                if (wildcard_ctx) {
                    /* Check if certificate is still valid (not expired) */
                    X509 *wildcard_cert = SSL_CTX_get0_certificate(wildcard_ctx);
                    if (wildcard_cert && X509_cmp_time(X509_get_notAfter(wildcard_cert), NULL) > 0) {
                        /* Found valid wildcard certificate! Reuse it */
                        LOG_INFO("♻️  Reusing wildcard cert *.%s for %s (avoided generation!)",
                                wildcard_base, domain);
                        atomic_fetch_add(&gen->stats.cache_hits, 1);
                        return wildcard_ctx;
                    }
                }
            }
            /* Also check legacy cert_cache */
            else if (gen->config.cert_cache) {
                cache_key_t wc_key = cert_cache_make_key(wildcard_base, algorithm);
                SSL_CTX *wildcard_ctx = cert_cache_get(gen->config.cert_cache, &wc_key);

                if (wildcard_ctx) {
                    /* Check if certificate is still valid (not expired) */
                    X509 *wildcard_cert = SSL_CTX_get0_certificate(wildcard_ctx);
                    if (wildcard_cert && X509_cmp_time(X509_get_notAfter(wildcard_cert), NULL) > 0) {
                        /* Found valid wildcard certificate! Reuse it */
                        LOG_INFO("♻️  Reusing wildcard cert *.%s for %s (avoided generation!)",
                                wildcard_base, domain);
                        atomic_fetch_add(&gen->stats.cache_hits, 1);
                        return wildcard_ctx;
                    }
                }
            }
        }
    }

    /* Step 3: Generate certificate (fallback if no wildcard cert found) */
    EVP_PKEY *pkey = NULL;
    X509 *cert = cert_generator_generate_cert(gen, domain, algorithm, &pkey);
    if (!cert || !pkey) {
        LOG_ERROR("Failed to generate certificate for %s", domain);
        return NULL;
    }

    /* Step 4: Create SSL_CTX with full certificate chain
     * If CA chain is provided (multi-level PKI), clients will receive
     * the full chain for proper validation */
    SSL_CTX *ctx = cert_generator_create_ssl_ctx(cert, pkey, gen->config.ca_chain);

    /* Note: X509 and EVP_PKEY are now owned by SSL_CTX, don't free them */

    if (!ctx) {
        LOG_ERROR("Failed to create SSL_CTX for %s", domain);
        X509_free(cert);
        EVP_PKEY_free(pkey);
        return NULL;
    }

    /* Step 4.5: Save certificate + chain + key to PEM file (for KI analysis and restart) */
    const char *disk_cache_dir = NULL;
    if (gen->config.certs_dir) {
        /* Use explicit certs_dir (preferred for SHM mode) */
        disk_cache_dir = gen->config.certs_dir;
    } else if (gen->config.cert_index) {
        /* Get disk_cache_dir from cert_index (legacy mode) */
        disk_cache_dir = ((struct cert_index*)gen->config.cert_index)->disk_cache_dir;
    }

    bool saved_to_disk = false;
    if (disk_cache_dir) {
        saved_to_disk = save_cert_chain_to_pem(disk_cache_dir, domain, cert, pkey,
                                                gen->config.ca_chain, algorithm);
        if (!saved_to_disk) {
            LOG_WARN("Failed to save PEM file for %s (non-fatal, continuing)", domain);
            /* Continue anyway - PEM save is for recovery/KI, not critical for operation */
        }
    }

    /* Extract expiry time for SHM */
    time_t expiry_time = 0;
    const ASN1_TIME *not_after = X509_get0_notAfter(cert);
    if (not_after) {
        struct tm tm = {0};
        ASN1_TIME_to_tm(not_after, &tm);
        expiry_time = mktime(&tm);
    }

    /* Step 5: Store in SHM certcache (multi-instance shared index) */
    if (gen->config.shm_certcache) {
        certcache_shm_t *shm = (certcache_shm_t*)gen->config.shm_certcache;
        if (certcache_shm_insert_full(shm, domain, (int)algorithm, expiry_time, saved_to_disk) != SHM_OK) {
            LOG_WARN("Failed to add certificate to SHM index: %s", domain);
        }
    }

    /* Step 5b: Store in local cache or index */
    if (gen->config.cache_certificates) {
        if (gen->config.cert_index) {
            /* Store in cert_index (local SSL_CTX cache) */
            cert_index_t *index = (cert_index_t*)gen->config.cert_index;
            if (!cert_index_add(index, domain, ctx, cert, algorithm)) {
                LOG_WARN("Failed to add certificate to local index: %s", domain);
                /* Continue anyway, ctx is still valid */
            }
        } else if (gen->config.cert_cache) {
            /* Store in legacy cert_cache */
            cache_key_t key = cert_cache_make_key(domain, algorithm);
            cert_cache_error_t err = cert_cache_put(gen->config.cert_cache, &key, ctx);

            if (err != CERT_CACHE_OK) {
                LOG_WARN("Failed to cache certificate for %s: %d", domain, err);
                /* Continue anyway, ctx is still valid */
            }
        }
    }

    LOG_INFO("Generated and cached SSL_CTX: %s (%s)",
            domain, keypool_algorithm_name(algorithm));

    return ctx;
}

/* Configuration */

void cert_generator_set_mode(cert_generator_t *gen, cert_gen_mode_t mode) {
    if (!gen) {
        return;
    }

    gen->config.mode = mode;
    LOG_INFO("Set certificate generation mode: %s", cert_gen_mode_name(mode));
}

void cert_generator_set_algorithms(cert_generator_t *gen,
                                    crypto_alg_t default_alg,
                                    crypto_alg_t fallback_alg) {
    if (!gen) {
        return;
    }

    gen->config.default_algorithm = default_alg;
    gen->config.fallback_algorithm = fallback_alg;

    LOG_INFO("Set algorithms: default=%s, fallback=%s",
            keypool_algorithm_name(default_alg),
            keypool_algorithm_name(fallback_alg));
}

cert_gen_error_t cert_generator_set_ca(cert_generator_t *gen,
                                        X509 *ca_cert,
                                        EVP_PKEY *ca_key) {
    if (!gen || !ca_cert || !ca_key) {
        return CERT_GEN_ERR_INVALID;
    }

    gen->config.ca_cert = ca_cert;
    gen->config.ca_key = ca_key;

    LOG_INFO("Set CA certificate and key");
    return CERT_GEN_OK;
}

/* Set multi-SubCA configuration */
cert_gen_error_t cert_generator_set_multi_ca(cert_generator_t *gen,
                                             multi_ca_config_t *multi_ca) {
    if (!gen || !multi_ca) {
        return CERT_GEN_ERR_INVALID;
    }

    gen->config.multi_ca = multi_ca;

    LOG_INFO("Set multi-SubCA configuration (RSA/ECDSA/SM2)");
    return CERT_GEN_OK;
}

/* Detect if client supports SM2 signature algorithm
 *
 * SM2 support indicated by:
 * - EVP_PKEY_SM2 in signature algorithms (TLS 1.3+)
 * - SM2/SM3 signature algorithm pairs in signature_algorithms extension
 * - SM2 in cipher suite names (legacy clients)
 *
 * Returns: true if client explicitly advertises SM2 support
 */
bool cert_generator_client_supports_sm2(SSL *ssl) {
    if (!ssl) {
        LOG_TRACE("No SSL connection, cannot detect SM2 client capabilities");
        return false;
    }

    /* Method 1: Check signature algorithms extension (TLS 1.3+)
     * SM2 uses EVP_PKEY_SM2 key type (if OpenSSL supports it)
     * SM2 with SM3 hash is typical algorithm pair */
    int num_sigalgs = SSL_get_sigalgs(ssl, 0, NULL, NULL, NULL, NULL, NULL);
    if (num_sigalgs > 0) {
        for (int i = 0; i < num_sigalgs; i++) {
            int sign_nid, hash_nid, pkey_nid;

            if (SSL_get_sigalgs(ssl, i, &sign_nid, &hash_nid, &pkey_nid, NULL, NULL) > 0) {
                /* Check for SM2 support
                 * EVP_PKEY_SM2 = 0x111 (1265 in decimal) on systems with SM2 support
                 * SM2 with SM3: sign_nid would be SM2, hash_nid would be SM3 */

                /* Direct check for SM2 key type */
                if (pkey_nid == EVP_PKEY_SM2) {
                    LOG_DEBUG("Client supports SM2 (pkey_nid: EVP_PKEY_SM2)");
                    return true;
                }

                /* Check by OID names: sm2_sm3 (0x0708 in IANA registry) */
                if (sign_nid == NID_sm2 && hash_nid == NID_sm3) {
                    LOG_DEBUG("Client supports SM2 (sm2 + sm3 signature algorithm)");
                    return true;
                }

                /* Also check by string names if OpenSSL provides OBJ names */
                const char *sign_name = OBJ_nid2ln(sign_nid);
                const char *hash_name = OBJ_nid2ln(hash_nid);
                if ((sign_name && strstr(sign_name, "sm2")) ||
                    (hash_name && strstr(hash_name, "sm3"))) {
                    LOG_DEBUG("Client supports SM2 (signature: %s, hash: %s)",
                             sign_name ? sign_name : "unknown",
                             hash_name ? hash_name : "unknown");
                    return true;
                }
            }
        }

        LOG_TRACE("Client does not advertise SM2 in signature algorithms");
        return false;
    }

    /* Method 2: Check cipher suites (TLS 1.2 and below)
     * Chinese clients may use SM2-enabled cipher suites */
    STACK_OF(SSL_CIPHER) *client_ciphers = SSL_get_client_ciphers(ssl);
    if (client_ciphers) {
        int num_ciphers = sk_SSL_CIPHER_num(client_ciphers);
        for (int i = 0; i < num_ciphers; i++) {
            const SSL_CIPHER *cipher = sk_SSL_CIPHER_value(client_ciphers, i);
            const char *name = SSL_CIPHER_get_name(cipher);

            /* Check for SM2/SM4 cipher suites (used by Chinese clients) */
            if (name && (strstr(name, "SM2") != NULL || strstr(name, "SM4") != NULL)) {
                LOG_DEBUG("Client supports SM2 (cipher suite: %s)", name);
                return true;
            }
        }
    }

    LOG_TRACE("Client does not advertise SM2 support");
    return false;
}

/* Statistics */

void cert_generator_get_stats(const cert_generator_t *gen,
                               cert_gen_stats_t *stats) {
    if (!gen || !stats) {
        return;
    }

    stats->total_generated = atomic_load_explicit(&gen->stats.total_generated, memory_order_acquire);
    stats->generated_ecdsa = atomic_load_explicit(&gen->stats.generated_ecdsa, memory_order_acquire);
    stats->generated_rsa = atomic_load_explicit(&gen->stats.generated_rsa, memory_order_acquire);
    stats->cache_hits = atomic_load_explicit(&gen->stats.cache_hits, memory_order_acquire);
    stats->cache_misses = atomic_load_explicit(&gen->stats.cache_misses, memory_order_acquire);
    stats->client_auto_ecdsa = atomic_load_explicit(&gen->stats.client_auto_ecdsa, memory_order_acquire);
    stats->client_auto_rsa = atomic_load_explicit(&gen->stats.client_auto_rsa, memory_order_acquire);
    stats->generation_errors = atomic_load_explicit(&gen->stats.generation_errors, memory_order_acquire);
    stats->total_generation_time_us = atomic_load_explicit(&gen->stats.total_generation_time_us, memory_order_acquire);
    stats->fastest_generation_us = atomic_load_explicit(&gen->stats.fastest_generation_us, memory_order_acquire);
    stats->slowest_generation_us = atomic_load_explicit(&gen->stats.slowest_generation_us, memory_order_acquire);
}

void cert_generator_print_stats(const cert_generator_t *gen) {
    if (!gen) {
        return;
    }

    cert_gen_stats_t stats;
    cert_generator_get_stats(gen, &stats);

    long long total_requests = stats.cache_hits + stats.cache_misses;
    float cache_hit_ratio = total_requests > 0 ?
        (float)stats.cache_hits / total_requests : 0.0f;

    long long avg_time_us = stats.total_generated > 0 ?
        stats.total_generation_time_us / stats.total_generated : 0;

    LOG_INFO("Certificate Generator Statistics:");
    LOG_INFO("  Total Requests:    %lld", total_requests);
    LOG_INFO("  Cache Hits:        %lld (%.1f%%)",
            stats.cache_hits, 100.0f * cache_hit_ratio);
    LOG_INFO("  Cache Misses:      %lld (%.1f%%)",
            stats.cache_misses, 100.0f * (1.0f - cache_hit_ratio));
    LOG_INFO("  Generated Total:   %lld", stats.total_generated);
    LOG_INFO("    ECDSA:           %lld (%.1f%%)",
            stats.generated_ecdsa,
            stats.total_generated > 0 ?
                100.0f * stats.generated_ecdsa / stats.total_generated : 0.0f);
    LOG_INFO("    RSA:             %lld (%.1f%%)",
            stats.generated_rsa,
            stats.total_generated > 0 ?
                100.0f * stats.generated_rsa / stats.total_generated : 0.0f);
    LOG_INFO("  Client Detection:");
    LOG_INFO("    Auto-ECDSA:      %lld", stats.client_auto_ecdsa);
    LOG_INFO("    Auto-RSA:        %lld", stats.client_auto_rsa);
    LOG_INFO("  Generation Time:");
    LOG_INFO("    Average:         %lld μs (%.2f ms)",
            avg_time_us, avg_time_us / 1000.0f);
    LOG_INFO("    Fastest:         %lld μs (%.2f ms)",
            stats.fastest_generation_us, stats.fastest_generation_us / 1000.0f);
    LOG_INFO("    Slowest:         %lld μs (%.2f ms)",
            stats.slowest_generation_us, stats.slowest_generation_us / 1000.0f);
    LOG_INFO("  Errors:            %lld", stats.generation_errors);
}

void cert_generator_reset_stats(cert_generator_t *gen) {
    if (!gen) {
        return;
    }

    atomic_store(&gen->stats.total_generated, 0);
    atomic_store(&gen->stats.generated_ecdsa, 0);
    atomic_store(&gen->stats.generated_rsa, 0);
    atomic_store(&gen->stats.cache_hits, 0);
    atomic_store(&gen->stats.cache_misses, 0);
    atomic_store(&gen->stats.client_auto_ecdsa, 0);
    atomic_store(&gen->stats.client_auto_rsa, 0);
    atomic_store(&gen->stats.generation_errors, 0);
    atomic_store(&gen->stats.total_generation_time_us, 0);
    atomic_store(&gen->stats.fastest_generation_us, LLONG_MAX);
    atomic_store(&gen->stats.slowest_generation_us, 0);

    LOG_INFO("Reset certificate generator statistics");
}

/* Utility Functions */

const char* cert_gen_mode_name(cert_gen_mode_t mode) {
    switch (mode) {
        case CERT_GEN_MODE_AUTO:         return "AUTO";
        case CERT_GEN_MODE_ECDSA:        return "ECDSA";
        case CERT_GEN_MODE_RSA:          return "RSA";
        case CERT_GEN_MODE_PREFER_ECDSA: return "PREFER_ECDSA";
        default:                         return "UNKNOWN";
    }
}

const char* cert_gen_error_string(cert_gen_error_t err) {
    switch (err) {
        case CERT_GEN_OK:            return "Success";
        case CERT_GEN_ERR_INVALID:   return "Invalid parameters";
        case CERT_GEN_ERR_NOMEM:     return "Out of memory";
        case CERT_GEN_ERR_OPENSSL:   return "OpenSSL error";
        case CERT_GEN_ERR_NO_KEY:    return "No key available";
        case CERT_GEN_ERR_CACHE_FULL: return "Cache full";
        default:                     return "Unknown error";
    }
}
