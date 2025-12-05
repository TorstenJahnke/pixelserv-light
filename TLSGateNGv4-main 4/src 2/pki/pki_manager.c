/* TLS-Gate NX - PKI Manager Implementation
 * Copyright (C) 2025 Torsten Jahnke
 *
 * CA certificate and key management with secure storage
 */

#include "pki_manager.h"
#include "../util/logger.h"
#include "../util/util.h"
#include "../crypto/keypool.h"

#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>
#include <openssl/bn.h>
#include <openssl/err.h>

/* PKI manager structure */
struct pki_manager {
    X509 *ca_cert;              /* CA certificate (signing cert) */
    EVP_PKEY *ca_key;           /* CA private key */
    STACK_OF(X509) *ca_chain;   /* Full certificate chain (incl. signing cert) */
    pthread_mutex_t lock;       /* Thread safety */
    bool has_ca;                /* CA loaded flag */
    int chain_depth;            /* Chain depth (1 = simple CA, 2+ = sub-CA) */
};

/* Utility: Get OpenSSL error string */
static const char* get_openssl_error(void) {
    unsigned long err = ERR_get_error();
    return err ? ERR_error_string(err, NULL) : "Unknown OpenSSL error";
}

/* Utility: Read file to memory */
static char* read_file(const char *path, size_t *len_out) {
    FILE *fp = fopen(path, "rb");
    if (!fp) {
        LOG_ERROR("Failed to open file: %s", path);
        return NULL;
    }

    /* Get file size */
    fseek(fp, 0, SEEK_END);
    long size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    if (size <= 0 || size > 10*1024*1024) {  /* Max 10 MB */
        LOG_ERROR("Invalid file size: %ld", size);
        fclose(fp);
        return NULL;
    }

    /* Allocate buffer */
    char *buffer = malloc(size + 1);
    if (!buffer) {
        LOG_ERROR("Failed to allocate buffer for file");
        fclose(fp);
        return NULL;
    }

    /* Read file */
    size_t bytes_read = fread(buffer, 1, size, fp);
    fclose(fp);

    if ((long)bytes_read != size) {
        LOG_ERROR("Failed to read file completely");
        free(buffer);
        return NULL;
    }

    buffer[size] = '\0';
    if (len_out) {
        *len_out = size;
    }

    return buffer;
}

/* Lifecycle */

pki_manager_t* pki_manager_create(void) {
    pki_manager_t *pki = calloc(1, sizeof(pki_manager_t));
    if (!pki) {
        LOG_ERROR("Failed to allocate PKI manager");
        return NULL;
    }

    if (pthread_mutex_init(&pki->lock, NULL) != 0) {
        LOG_ERROR("Failed to initialize PKI mutex");
        free(pki);
        return NULL;
    }

    /* Initialize certificate chain stack */
    pki->ca_chain = sk_X509_new_null();
    if (!pki->ca_chain) {
        LOG_ERROR("Failed to create certificate chain stack");
        pthread_mutex_destroy(&pki->lock);
        free(pki);
        return NULL;
    }

    pki->has_ca = false;
    pki->chain_depth = 0;

    LOG_DEBUG("Created PKI manager");
    return pki;
}

void pki_manager_destroy(pki_manager_t *pki) {
    if (!pki) {
        return;
    }

    pthread_mutex_lock(&pki->lock);

    /* Securely erase and free CA key */
    if (pki->ca_key) {
        EVP_PKEY_free(pki->ca_key);
        pki->ca_key = NULL;
    }

    /* Free CA certificate */
    if (pki->ca_cert) {
        X509_free(pki->ca_cert);
        pki->ca_cert = NULL;
    }

    /* Free certificate chain */
    if (pki->ca_chain) {
        sk_X509_pop_free(pki->ca_chain, X509_free);
        pki->ca_chain = NULL;
    }

    pki->has_ca = false;
    pki->chain_depth = 0;

    pthread_mutex_unlock(&pki->lock);
    pthread_mutex_destroy(&pki->lock);

    free(pki);

    LOG_DEBUG("Destroyed PKI manager (securely wiped keys)");
}

/* CA Certificate Loading */

pki_error_t pki_manager_load_ca_mem(pki_manager_t *pki,
                                     const char *cert_pem, size_t cert_len,
                                     const char *key_pem, size_t key_len,
                                     const char *passphrase) {
    if (!pki || !cert_pem || !key_pem) {
        return PKI_ERR_INVALID;
    }

    pthread_mutex_lock(&pki->lock);

    X509 *cert = NULL;
    EVP_PKEY *pkey = NULL;
    BIO *bio = NULL;
    pki_error_t result = PKI_OK;

    LOG_DEBUG("Loading CA certificate(s) and key from memory");

    /* Load CA certificate(s) - may be a chain! */
    bio = BIO_new_mem_buf(cert_pem, (int)cert_len);
    if (!bio) {
        LOG_ERROR("Failed to create BIO for certificate");
        result = PKI_ERR_NOMEM;
        goto cleanup;
    }

    /* Load first certificate (signing certificate) */
    cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    if (!cert) {
        LOG_ERROR("Failed to parse CA certificate: %s", get_openssl_error());
        result = PKI_ERR_INVALID_CERT;
        goto cleanup;
    }

    /* Clear old chain */
    if (pki->ca_chain) {
        sk_X509_pop_free(pki->ca_chain, X509_free);
        pki->ca_chain = sk_X509_new_null();
    }

    /* Add signing certificate to chain */
    if (!sk_X509_push(pki->ca_chain, cert)) {
        LOG_ERROR("Failed to add signing cert to chain");
        result = PKI_ERR_NOMEM;
        goto cleanup;
    }
    X509_up_ref(cert);  /* Increment ref count since we store it separately */

    pki->chain_depth = 1;

    /* Load additional certificates (intermediate/root CAs) */
    X509 *chain_cert;
    while ((chain_cert = PEM_read_bio_X509(bio, NULL, NULL, NULL)) != NULL) {
        if (!sk_X509_push(pki->ca_chain, chain_cert)) {
            LOG_ERROR("Failed to add chain certificate");
            X509_free(chain_cert);
            result = PKI_ERR_NOMEM;
            goto cleanup;
        }
        pki->chain_depth++;
        LOG_DEBUG("Loaded chain certificate %d", pki->chain_depth);
    }

    /* Clear any OpenSSL errors from the failed PEM_read (expected at end of file) */
    ERR_clear_error();

    LOG_INFO("Loaded CA certificate chain (depth=%d)", pki->chain_depth);
    if (pki->chain_depth == 1) {
        LOG_INFO("  Mode: Simple CA (direct signing)");
    } else {
        LOG_INFO("  Mode: Sub-CA chain (Root CA → Sub-CA → Server)");
    }

    BIO_free(bio);
    bio = NULL;

    /* Load CA private key */
    bio = BIO_new_mem_buf(key_pem, (int)key_len);
    if (!bio) {
        LOG_ERROR("Failed to create BIO for private key");
        result = PKI_ERR_NOMEM;
        goto cleanup;
    }

    pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, (void*)passphrase);
    if (!pkey) {
        LOG_ERROR("Failed to parse CA private key: %s", get_openssl_error());
        result = passphrase ? PKI_ERR_PASSPHRASE : PKI_ERR_INVALID_KEY;
        goto cleanup;
    }

    BIO_free(bio);
    bio = NULL;

    /* Verify that certificate is a CA certificate */
    if (!pki_is_ca_certificate(cert)) {
        LOG_ERROR("Certificate is not a CA certificate (missing basicConstraints CA:TRUE)");
        result = PKI_ERR_NOT_CA;
        goto cleanup;
    }

    /* Verify that key matches certificate */
    if (!pki_verify_key_match(cert, pkey)) {
        LOG_ERROR("Private key does not match CA certificate");
        result = PKI_ERR_KEY_MISMATCH;
        goto cleanup;
    }

    /* Free old CA if exists */
    if (pki->ca_cert) {
        X509_free(pki->ca_cert);
    }
    if (pki->ca_key) {
        EVP_PKEY_free(pki->ca_key);
    }

    /* Store new CA */
    pki->ca_cert = cert;
    pki->ca_key = pkey;
    pki->has_ca = true;

    LOG_INFO("Loaded CA certificate and key successfully");

    /* Print CA info */
    pki_ca_info_t info;
    if (pki_manager_get_ca_info(pki, &info) == PKI_OK) {
        LOG_INFO("  Subject: %s", info.subject);
        LOG_INFO("  Algorithm: %s (%d bits)",
                keypool_algorithm_name(info.algorithm), info.key_bits);
        LOG_INFO("  Valid: %s to %s",
                format_time(info.not_before), format_time(info.not_after));
    }

    pthread_mutex_unlock(&pki->lock);
    return PKI_OK;

cleanup:
    if (bio) BIO_free(bio);
    if (cert) X509_free(cert);
    if (pkey) EVP_PKEY_free(pkey);

    pthread_mutex_unlock(&pki->lock);
    return result;
}

pki_error_t pki_manager_load_ca(pki_manager_t *pki,
                                 const char *cert_path,
                                 const char *key_path,
                                 const char *passphrase) {
    if (!pki || !cert_path || !key_path) {
        return PKI_ERR_INVALID;
    }

    LOG_INFO("Loading CA certificate: %s", cert_path);
    LOG_INFO("Loading CA private key: %s", key_path);

    /* Read certificate file */
    size_t cert_len;
    char *cert_pem = read_file(cert_path, &cert_len);
    if (!cert_pem) {
        return PKI_ERR_FILE_READ;
    }

    /* Read key file */
    size_t key_len;
    char *key_pem = read_file(key_path, &key_len);
    if (!key_pem) {
        free(cert_pem);
        return PKI_ERR_FILE_READ;
    }

    /* Load from memory */
    pki_error_t err = pki_manager_load_ca_mem(pki,
                                               cert_pem, cert_len,
                                               key_pem, key_len,
                                               passphrase);

    /* Securely erase key from memory */
    OPENSSL_cleanse(key_pem, key_len);
    free(key_pem);
    free(cert_pem);

    return err;
}

/* CA Certificate Generation */

pki_error_t pki_manager_generate_ca(pki_manager_t *pki,
                                     const char *subject_cn,
                                     int validity_days,
                                     crypto_alg_t algorithm) {
    if (!pki || !subject_cn) {
        return PKI_ERR_INVALID;
    }

    pthread_mutex_lock(&pki->lock);

    LOG_INFO("Generating self-signed CA certificate: %s (%s)",
            subject_cn, keypool_algorithm_name(algorithm));

    X509 *cert = NULL;
    EVP_PKEY *pkey = NULL;
    pki_error_t result = PKI_OK;

    /* Generate key pair */
    pkey = keypool_generate_key(algorithm);
    if (!pkey) {
        LOG_ERROR("Failed to generate CA key");
        result = PKI_ERR_INVALID_KEY;
        goto cleanup;
    }

    /* Create X509 certificate */
    cert = X509_new();
    if (!cert) {
        LOG_ERROR("Failed to create X509 structure: %s", get_openssl_error());
        result = PKI_ERR_NOMEM;
        goto cleanup;
    }

    /* Set version (X509v3) */
    X509_set_version(cert, 2);

    /* Set serial number (random) */
    BIGNUM *bn = BN_new();
    if (bn && BN_rand(bn, 128, 0, 0)) {
        ASN1_INTEGER *serial = X509_get_serialNumber(cert);
        BN_to_ASN1_INTEGER(bn, serial);
        BN_free(bn);
    } else {
        ASN1_INTEGER_set(X509_get_serialNumber(cert), 1);
        if (bn) BN_free(bn);
    }

    /* Set validity period */
    X509_gmtime_adj(X509_get_notBefore(cert), 0);
    X509_gmtime_adj(X509_get_notAfter(cert),
                    (long)validity_days * 24L * 60L * 60L);

    /* Set subject and issuer (same for self-signed) */
    X509_NAME *name = X509_get_subject_name(cert);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                               (const unsigned char*)subject_cn, -1, -1, 0);
    X509_set_issuer_name(cert, name);

    /* Set public key */
    X509_set_pubkey(cert, pkey);

    /* Add CA extensions */
    X509V3_CTX ctx;
    X509V3_set_ctx_nodb(&ctx);
    X509V3_set_ctx(&ctx, cert, cert, NULL, NULL, 0);

    /* Basic Constraints: CA=TRUE */
    X509_EXTENSION *ext = X509V3_EXT_conf_nid(NULL, &ctx,
                                               NID_basic_constraints, "CA:TRUE");
    if (ext) {
        X509_add_ext(cert, ext, -1);
        X509_EXTENSION_free(ext);
    }

    /* Key Usage: Certificate Sign, CRL Sign */
    ext = X509V3_EXT_conf_nid(NULL, &ctx, NID_key_usage,
                              "keyCertSign,cRLSign");
    if (ext) {
        X509_add_ext(cert, ext, -1);
        X509_EXTENSION_free(ext);
    }

    /* Subject Key Identifier */
    ext = X509V3_EXT_conf_nid(NULL, &ctx, NID_subject_key_identifier, "hash");
    if (ext) {
        X509_add_ext(cert, ext, -1);
        X509_EXTENSION_free(ext);
    }

    /* Sign certificate (self-signed) */
    const EVP_MD *md = EVP_sha256();
    if (!X509_sign(cert, pkey, md)) {
        LOG_ERROR("Failed to sign CA certificate: %s", get_openssl_error());
        result = PKI_ERR_INVALID_CERT;
        goto cleanup;
    }

    /* Free old CA if exists */
    if (pki->ca_cert) {
        X509_free(pki->ca_cert);
    }
    if (pki->ca_key) {
        EVP_PKEY_free(pki->ca_key);
    }

    /* Store new CA */
    pki->ca_cert = cert;
    pki->ca_key = pkey;
    pki->has_ca = true;

    LOG_INFO("Generated self-signed CA certificate successfully");

    pthread_mutex_unlock(&pki->lock);
    return PKI_OK;

cleanup:
    if (cert) X509_free(cert);
    if (pkey) EVP_PKEY_free(pkey);

    pthread_mutex_unlock(&pki->lock);
    return result;
}

/* Save CA Certificate and Key */

pki_error_t pki_manager_save_ca(pki_manager_t *pki,
                                 const char *cert_path,
                                 const char *key_path,
                                 const char *passphrase) {
    if (!pki || !cert_path || !key_path) {
        return PKI_ERR_INVALID;
    }

    pthread_mutex_lock(&pki->lock);

    if (!pki->has_ca) {
        pthread_mutex_unlock(&pki->lock);
        return PKI_ERR_INVALID;
    }

    LOG_INFO("Saving CA certificate to: %s", cert_path);
    LOG_INFO("Saving CA private key to: %s", key_path);

    pki_error_t result = PKI_OK;

    /* Save certificate */
    FILE *fp = fopen(cert_path, "wb");
    if (!fp) {
        LOG_ERROR("Failed to open certificate file for writing: %s", cert_path);
        result = PKI_ERR_FILE_READ;
        goto cleanup;
    }

    if (!PEM_write_X509(fp, pki->ca_cert)) {
        LOG_ERROR("Failed to write CA certificate: %s", get_openssl_error());
        fclose(fp);
        result = PKI_ERR_FILE_READ;
        goto cleanup;
    }

    fclose(fp);

    /* Save private key */
    fp = fopen(key_path, "wb");
    if (!fp) {
        LOG_ERROR("Failed to open private key file for writing: %s", key_path);
        result = PKI_ERR_FILE_READ;
        goto cleanup;
    }

    /* Write key with optional encryption */
    const EVP_CIPHER *cipher = passphrase ? EVP_aes_256_cbc() : NULL;

    if (!PEM_write_PrivateKey(fp, pki->ca_key, cipher,
                               NULL, 0, NULL, (void*)passphrase)) {
        LOG_ERROR("Failed to write CA private key: %s", get_openssl_error());
        fclose(fp);
        result = PKI_ERR_FILE_READ;
        goto cleanup;
    }

    fclose(fp);

    LOG_INFO("Saved CA certificate and key successfully");

cleanup:
    pthread_mutex_unlock(&pki->lock);
    return result;
}

/* Access CA Certificate and Key */

X509* pki_manager_get_ca_cert(const pki_manager_t *pki) {
    return pki ? pki->ca_cert : NULL;
}

EVP_PKEY* pki_manager_get_ca_key(const pki_manager_t *pki) {
    return pki ? pki->ca_key : NULL;
}

STACK_OF(X509)* pki_manager_get_ca_chain(const pki_manager_t *pki) {
    return pki ? pki->ca_chain : NULL;
}

pki_error_t pki_manager_set_ca_chain(pki_manager_t *pki, STACK_OF(X509) *chain) {
    if (!pki) {
        return PKI_ERR_INVALID;
    }

    /* ATOMICITY FIX: Build new chain completely BEFORE replacing old chain
     * This ensures we don't leave PKI manager in inconsistent state on failure */

    /* Create new chain first (outside lock to minimize critical section) */
    STACK_OF(X509) *new_chain = sk_X509_new_null();
    if (!new_chain) {
        LOG_ERROR("Failed to create certificate chain stack");
        return PKI_ERR_NOMEM;
    }

    /* Copy chain if provided (NULL or empty chain is valid for RootCA-only mode) */
    if (chain) {
        int num_certs = sk_X509_num(chain);
        for (int i = 0; i < num_certs; i++) {
            X509 *cert = sk_X509_value(chain, i);
            if (cert) {
                X509_up_ref(cert);  /* Increment reference count */
                if (!sk_X509_push(new_chain, cert)) {
                    LOG_ERROR("Failed to add certificate to chain");
                    X509_free(cert);  /* Undo up_ref */
                    /* Clean up the partially built new chain */
                    sk_X509_pop_free(new_chain, X509_free);
                    return PKI_ERR_NOMEM;
                }
            }
        }
        LOG_DEBUG("Built new CA chain (%d certificates)", num_certs);
    } else {
        LOG_DEBUG("Built empty CA chain (RootCA-only mode)");
    }

    /* Now atomically replace old chain with new chain (under lock) */
    pthread_mutex_lock(&pki->lock);

    STACK_OF(X509) *old_chain = pki->ca_chain;
    pki->ca_chain = new_chain;
    pki->chain_depth = sk_X509_num(new_chain);

    pthread_mutex_unlock(&pki->lock);

    /* Free old chain after releasing lock (minimize critical section) */
    if (old_chain) {
        sk_X509_pop_free(old_chain, X509_free);
    }

    LOG_DEBUG("CA chain updated successfully");
    return PKI_OK;
}

bool pki_manager_has_ca(const pki_manager_t *pki) {
    return pki && pki->has_ca;
}

/* Validation and Information */

bool pki_manager_validate_ca(const pki_manager_t *pki) {
    if (!pki || !pki->has_ca) {
        return false;
    }

    /* Check certificate is not expired */
    time_t now = time(NULL);
    const ASN1_TIME *not_before = X509_get0_notBefore(pki->ca_cert);
    const ASN1_TIME *not_after = X509_get0_notAfter(pki->ca_cert);

    if (X509_cmp_time(not_before, &now) > 0) {
        LOG_WARN("CA certificate not yet valid");
        return false;
    }

    if (X509_cmp_time(not_after, &now) < 0) {
        LOG_WARN("CA certificate expired");
        return false;
    }

    /* Check basicConstraints CA:TRUE */
    if (!pki_is_ca_certificate(pki->ca_cert)) {
        LOG_ERROR("Certificate is not a CA certificate");
        return false;
    }

    /* Verify key matches certificate */
    if (!pki_verify_key_match(pki->ca_cert, pki->ca_key)) {
        LOG_ERROR("Private key does not match CA certificate");
        return false;
    }

    LOG_DEBUG("CA certificate validation passed");
    return true;
}

pki_error_t pki_manager_get_ca_info(const pki_manager_t *pki,
                                     pki_ca_info_t *info) {
    if (!pki || !info || !pki->has_ca) {
        return PKI_ERR_INVALID;
    }

    memset(info, 0, sizeof(pki_ca_info_t));

    /* Get subject */
    X509_NAME *subject = X509_get_subject_name(pki->ca_cert);
    X509_NAME_oneline(subject, info->subject, sizeof(info->subject));

    /* Get issuer */
    X509_NAME *issuer = X509_get_issuer_name(pki->ca_cert);
    X509_NAME_oneline(issuer, info->issuer, sizeof(info->issuer));

    /* Get serial number */
    const ASN1_INTEGER *serial = X509_get0_serialNumber(pki->ca_cert);
    BIGNUM *bn = ASN1_INTEGER_to_BN(serial, NULL);
    if (bn) {
        char *hex = BN_bn2hex(bn);
        if (hex) {
            snprintf(info->serial, sizeof(info->serial), "%s", hex);
            OPENSSL_free(hex);
        }
        BN_free(bn);
    }

    /* Get validity */
    const ASN1_TIME *not_before = X509_get0_notBefore(pki->ca_cert);
    const ASN1_TIME *not_after = X509_get0_notAfter(pki->ca_cert);

    struct tm tm_before = {0};
    struct tm tm_after = {0};

    ASN1_TIME_to_tm(not_before, &tm_before);
    info->not_before = timegm(&tm_before);  /* Use timegm() for UTC */

    ASN1_TIME_to_tm(not_after, &tm_after);
    info->not_after = timegm(&tm_after);    /* Use timegm() for UTC */

    /* Get key info */
    info->key_bits = EVP_PKEY_bits(pki->ca_key);
    info->algorithm = pki_get_key_algorithm(pki->ca_key);

    /* Check if self-signed */
    info->is_self_signed = (X509_check_issued(pki->ca_cert, pki->ca_cert) == X509_V_OK);

    /* Check if CA */
    info->is_ca = pki_is_ca_certificate(pki->ca_cert);

    return PKI_OK;
}

void pki_manager_print_ca_info(const pki_manager_t *pki) {
    if (!pki || !pki->has_ca) {
        LOG_WARN("No CA certificate loaded");
        return;
    }

    pki_ca_info_t info;
    if (pki_manager_get_ca_info(pki, &info) != PKI_OK) {
        LOG_ERROR("Failed to get CA info");
        return;
    }

    LOG_INFO("CA Certificate Information:");
    LOG_INFO("  Subject:     %s", info.subject);
    LOG_INFO("  Issuer:      %s", info.issuer);
    LOG_INFO("  Serial:      %s", info.serial);
    LOG_INFO("  Algorithm:   %s (%d bits)",
            keypool_algorithm_name(info.algorithm), info.key_bits);
    LOG_INFO("  Valid From:  %s", format_time(info.not_before));
    LOG_INFO("  Valid Until: %s", format_time(info.not_after));
    LOG_INFO("  Self-Signed: %s", info.is_self_signed ? "Yes" : "No");
    LOG_INFO("  Is CA:       %s", info.is_ca ? "Yes" : "No");
}

/* Utility Functions */

const char* pki_error_string(pki_error_t err) {
    switch (err) {
        case PKI_OK:                 return "Success";
        case PKI_ERR_INVALID:        return "Invalid parameters";
        case PKI_ERR_NOMEM:          return "Out of memory";
        case PKI_ERR_FILE_NOT_FOUND: return "File not found";
        case PKI_ERR_FILE_READ:      return "File read error";
        case PKI_ERR_INVALID_FORMAT: return "Invalid file format";
        case PKI_ERR_INVALID_CERT:   return "Invalid certificate";
        case PKI_ERR_INVALID_KEY:    return "Invalid private key";
        case PKI_ERR_KEY_MISMATCH:   return "Key does not match certificate";
        case PKI_ERR_PASSPHRASE:     return "Invalid passphrase";
        case PKI_ERR_NOT_CA:         return "Not a CA certificate";
        default:                     return "Unknown error";
    }
}

bool pki_verify_key_match(X509 *cert, EVP_PKEY *pkey) {
    if (!cert || !pkey) {
        return false;
    }

    /* Get public key from certificate */
    EVP_PKEY *cert_pkey = X509_get0_pubkey(cert);
    if (!cert_pkey) {
        return false;
    }

    /* Compare public keys */
    return EVP_PKEY_eq(cert_pkey, pkey) == 1;
}

bool pki_is_ca_certificate(X509 *cert) {
    if (!cert) {
        return false;
    }

    /* Check basicConstraints extension */
    BASIC_CONSTRAINTS *bc = X509_get_ext_d2i(cert, NID_basic_constraints, NULL, NULL);
    if (!bc) {
        return false;
    }

    bool is_ca = (bc->ca != 0);
    BASIC_CONSTRAINTS_free(bc);

    return is_ca;
}

crypto_alg_t pki_get_key_algorithm(EVP_PKEY *pkey) {
    if (!pkey) {
        return CRYPTO_ALG_AUTO;
    }

    int pkey_type = EVP_PKEY_id(pkey);
    int key_bits = EVP_PKEY_bits(pkey);

    if (pkey_type == EVP_PKEY_RSA || pkey_type == EVP_PKEY_RSA_PSS) {
        if (key_bits >= 4096) {
            return CRYPTO_ALG_RSA_4096;
        } else {
            return CRYPTO_ALG_RSA_3072;
        }
    } else if (pkey_type == EVP_PKEY_SM2) {
        return CRYPTO_ALG_SM2;
    } else if (pkey_type == EVP_PKEY_EC) {
        if (key_bits >= 521) {
            return CRYPTO_ALG_ECDSA_P521;
        } else if (key_bits >= 384) {
            return CRYPTO_ALG_ECDSA_P384;
        } else {
            return CRYPTO_ALG_ECDSA_P256;
        }
    } else if (pkey_type == EVP_PKEY_ED25519) {
        return CRYPTO_ALG_ED25519;
    }

    return CRYPTO_ALG_AUTO;
}
