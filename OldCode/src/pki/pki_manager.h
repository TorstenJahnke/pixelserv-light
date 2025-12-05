/* TLS-Gate NX - PKI Manager
 * Copyright (C) 2025 Torsten Jahnke
 *
 * Certificate Authority (CA) management:
 * - Load CA certificates and keys from PEM files
 * - Validate CA certificates
 * - Secure key storage with memory protection
 * - Support for multiple CA certificates
 * - Passphrase-protected private keys
 */

#ifndef TLSGATENG_PKI_MANAGER_H
#define TLSGATENG_PKI_MANAGER_H

#include "../common_types.h"
#include <openssl/x509.h>
#include <openssl/evp.h>
#include <stdbool.h>

/* Error codes */
typedef enum {
    PKI_OK = 0,
    PKI_ERR_INVALID = -1,
    PKI_ERR_NOMEM = -2,
    PKI_ERR_FILE_NOT_FOUND = -3,
    PKI_ERR_FILE_READ = -4,
    PKI_ERR_INVALID_FORMAT = -5,
    PKI_ERR_INVALID_CERT = -6,
    PKI_ERR_INVALID_KEY = -7,
    PKI_ERR_KEY_MISMATCH = -8,
    PKI_ERR_PASSPHRASE = -9,
    PKI_ERR_NOT_CA = -10
} pki_error_t;

/* CA certificate info */
typedef struct {
    char subject[256];          /* Certificate subject DN */
    char issuer[256];           /* Issuer DN */
    char serial[64];            /* Serial number (hex) */
    time_t not_before;          /* Validity start */
    time_t not_after;           /* Validity end */
    int key_bits;               /* Key size in bits */
    crypto_alg_t algorithm;     /* Algorithm type */
    bool is_self_signed;        /* Self-signed certificate */
    bool is_ca;                 /* CA certificate (basicConstraints CA:TRUE) */
} pki_ca_info_t;

/* Opaque PKI manager handle */
typedef struct pki_manager pki_manager_t;

/* Lifecycle */

/* Create PKI manager
 *
 * @return PKI manager handle or NULL on error
 */
pki_manager_t* pki_manager_create(void);

/* Destroy PKI manager and securely erase keys
 *
 * SECURITY: Private keys are securely wiped from memory using OPENSSL_cleanse()
 */
void pki_manager_destroy(pki_manager_t *pki);

/* CA Certificate Loading */

/* Load CA certificate and key from PEM files
 *
 * IMPORTANT: Supports both scenarios:
 * 1. Simple CA:  CA → Server Certificate (direct signing)
 * 2. Chain:      Root CA → Sub-CA → Server Certificate
 *
 * The cert_path can contain:
 * - Single certificate (simple CA)
 * - Certificate chain (Sub-CA + Root CA in one PEM file)
 *
 * The signing certificate (first cert in chain) is used for signing.
 * The full chain is stored for SSL_CTX creation.
 *
 * @param pki           PKI manager handle
 * @param cert_path     Path to CA certificate (or chain) PEM file
 * @param key_path      Path to CA private key PEM file
 * @param passphrase    Optional passphrase for encrypted key (can be NULL)
 * @return PKI_OK on success, error code otherwise
 *
 * Example (Simple CA):
 *   pki_error_t err = pki_manager_load_ca(pki,
 *                                          "/etc/tlsgateNG/ca.pem",
 *                                          "/etc/tlsgateNG/ca-key.pem",
 *                                          NULL);
 *
 * Example (Sub-CA with chain):
 *   # ca-chain.pem contains:
 *   #   1. Sub-CA certificate (signing cert)
 *   #   2. Root CA certificate
 *
 *   pki_error_t err = pki_manager_load_ca(pki,
 *                                          "/etc/tlsgateNG/ca-chain.pem",
 *                                          "/etc/tlsgateNG/sub-ca-key.pem",
 *                                          NULL);
 */
pki_error_t pki_manager_load_ca(pki_manager_t *pki,
                                 const char *cert_path,
                                 const char *key_path,
                                 const char *passphrase);

/* Load CA certificate and key from memory (PEM format)
 *
 * @param pki           PKI manager handle
 * @param cert_pem      CA certificate PEM data
 * @param cert_len      Certificate length
 * @param key_pem       CA private key PEM data
 * @param key_len       Key length
 * @param passphrase    Optional passphrase (can be NULL)
 * @return PKI_OK on success, error code otherwise
 */
pki_error_t pki_manager_load_ca_mem(pki_manager_t *pki,
                                     const char *cert_pem, size_t cert_len,
                                     const char *key_pem, size_t key_len,
                                     const char *passphrase);

/* Generate new self-signed CA certificate
 *
 * This is useful for initial setup or testing. The generated CA can be used
 * to sign server certificates.
 *
 * @param pki          PKI manager handle
 * @param subject_cn   Common Name for CA certificate (e.g., "TLS-Gate NX CA")
 * @param validity_days Certificate validity in days (e.g., 3650 = 10 years)
 * @param algorithm    Key algorithm (ECDSA P-256 or RSA 3072 recommended)
 * @return PKI_OK on success, error code otherwise
 */
pki_error_t pki_manager_generate_ca(pki_manager_t *pki,
                                     const char *subject_cn,
                                     int validity_days,
                                     crypto_alg_t algorithm);

/* Save CA certificate and key to PEM files
 *
 * @param pki           PKI manager handle
 * @param cert_path     Output path for CA certificate
 * @param key_path      Output path for CA private key
 * @param passphrase    Optional passphrase to encrypt key (can be NULL)
 * @return PKI_OK on success, error code otherwise
 *
 * SECURITY: If passphrase is provided, the private key is encrypted with AES-256-CBC
 */
pki_error_t pki_manager_save_ca(pki_manager_t *pki,
                                 const char *cert_path,
                                 const char *key_path,
                                 const char *passphrase);

/* Access CA Certificate and Key */

/* Get CA certificate
 *
 * @param pki  PKI manager handle
 * @return X509* certificate or NULL if not loaded
 *
 * NOTE: The returned certificate is still owned by PKI manager, do NOT free it!
 */
X509* pki_manager_get_ca_cert(const pki_manager_t *pki);

/* Get CA private key
 *
 * @param pki  PKI manager handle
 * @return EVP_PKEY* private key or NULL if not loaded
 *
 * NOTE: The returned key is still owned by PKI manager, do NOT free it!
 */
EVP_PKEY* pki_manager_get_ca_key(const pki_manager_t *pki);

/* Get CA certificate chain
 *
 * Returns the full certificate chain (if loaded), or just the signing cert.
 *
 * @param pki  PKI manager handle
 * @return STACK_OF(X509)* certificate chain or NULL if not loaded
 *
 * NOTE: The returned chain is still owned by PKI manager, do NOT free it!
 *
 * Chain order (OpenSSL convention):
 *   [0] = Signing certificate (Sub-CA or Root CA)
 *   [1] = Intermediate CA (if present)
 *   [2] = Root CA (if intermediate present)
 *   ...
 */
STACK_OF(X509)* pki_manager_get_ca_chain(const pki_manager_t *pki);

/* Set CA certificate chain
 *
 * Replaces the PKI manager's chain with a copy of the provided chain.
 * Useful when loading CA via ca_loader which builds the chain separately.
 *
 * @param pki    PKI manager handle
 * @param chain  Certificate chain to set (will be duplicated)
 * @return PKI_OK on success, error code otherwise
 */
pki_error_t pki_manager_set_ca_chain(pki_manager_t *pki,
                                      STACK_OF(X509) *chain);

/* Validation and Information */

/* Validate CA certificate
 *
 * Checks:
 * - Certificate is valid (not expired)
 * - basicConstraints CA:TRUE is set
 * - keyUsage includes keyCertSign
 * - Private key matches certificate
 *
 * @param pki  PKI manager handle
 * @return true if valid, false otherwise
 */
bool pki_manager_validate_ca(const pki_manager_t *pki);

/* Get CA certificate information
 *
 * @param pki   PKI manager handle
 * @param info  Output: CA certificate info
 * @return PKI_OK on success, error code otherwise
 */
pki_error_t pki_manager_get_ca_info(const pki_manager_t *pki,
                                     pki_ca_info_t *info);

/* Print CA certificate information to log */
void pki_manager_print_ca_info(const pki_manager_t *pki);

/* Check if CA certificate is loaded
 *
 * @param pki  PKI manager handle
 * @return true if CA cert and key are loaded, false otherwise
 */
bool pki_manager_has_ca(const pki_manager_t *pki);

/* Utility Functions */

/* Get error message for error code */
const char* pki_error_string(pki_error_t err);

/* Verify that private key matches certificate
 *
 * @param cert  X509 certificate
 * @param pkey  Private key
 * @return true if key matches certificate, false otherwise
 */
bool pki_verify_key_match(X509 *cert, EVP_PKEY *pkey);

/* Check if certificate is a CA certificate
 *
 * @param cert  X509 certificate
 * @return true if certificate has basicConstraints CA:TRUE
 */
bool pki_is_ca_certificate(X509 *cert);

/* Get algorithm type from EVP_PKEY
 *
 * @param pkey  Private key
 * @return Algorithm type
 */
crypto_alg_t pki_get_key_algorithm(EVP_PKEY *pkey);

#endif /* TLSGATENG_PKI_MANAGER_H */
