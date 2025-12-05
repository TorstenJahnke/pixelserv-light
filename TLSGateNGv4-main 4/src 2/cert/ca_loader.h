/* TLSGateNX - CA Certificate Auto-Detection and Loader
 * Copyright (C) 2025 Torsten Jahnke
 *
 * Automatically detects and loads CA certificates from directory:
 * - 2-Tier: rootca.crt + ca.crt + ca.key (RootCA + SubCA)
 * - 1-Tier: ca.crt + ca.key (single CA)
 * - Multi-SubCA: One RootCA + multiple SubCAs (RSA/ECDSA/SM2)
 * - Supports .crt and .pem extensions
 */

#ifndef CA_LOADER_H
#define CA_LOADER_H

#include <openssl/x509.h>
#include <openssl/evp.h>
#include <stdbool.h>
#include "../common_types.h"

/* CA Structure Type */
typedef enum {
    CA_TYPE_UNKNOWN = 0,
    CA_TYPE_SINGLE,      /* 1-Tier: ca.crt + ca.key */
    CA_TYPE_TWO_TIER     /* 2-Tier: rootca.crt + ca.crt + ca.key */
} ca_type_t;

/* CA Configuration (loaded from directory) */
typedef struct {
    ca_type_t type;                  /* Detected CA type */
    char base_dir[4096];             /* Base directory (e.g., /opt/TLSGateNX) */
    char ca_dir[4096];               /* CA directory (e.g., /opt/TLSGateNX/rootCA/RSA) */
    char certs_dir[4096];            /* Generated certs directory (e.g., /opt/TLSGateNX/certs/RSA) */
    char index_dir[4096];            /* Index directory (e.g., /opt/TLSGateNX/index/RSA) */
    char root_cert_path[4096];       /* Path to root CA cert (if 2-tier) */
    char sub_cert_path[4096];        /* Path to SubCA cert (or main CA if 1-tier) */
    char cs_cert_path[4096];         /* Path to cross-signed SubCA cert (optional) */
    char key_path[4096];             /* Path to CA private key */

    /* Loaded certificates and key */
    X509 *root_cert;                 /* RootCA certificate (NULL if 1-tier) */
    X509 *sub_cert;                  /* SubCA certificate (or main CA if 1-tier) */
    X509 *cs_cert;                   /* Cross-signed SubCA certificate (optional) */
    EVP_PKEY *private_key;           /* CA private key */

    /* Certificate chain for signing */
    STACK_OF(X509) *chain;           /* Full chain: SubCA + CS-SubCA (optional) + RootCA (or just CA) */
} ca_config_t;

/* Initialize CA configuration from base directory
 *
 * Directory structure:
 *   base_dir/              (e.g., /opt/TLSGateNX/)
 *     ├── rootCA/          (CA certificates & key - auto-detected)
 *     │   ├── rootca.crt   (optional, for 2-Tier)
 *     │   ├── ca.crt       (SubCA or main CA)
 *     │   ├── ca.cs.crt    (optional, cross-signed SubCA)
 *     │   └── ca.key       (private key)
 *     └── [certs]/         (generated certificates stored here)
 *
 * Automatically detects:
 * - 2-Tier: rootca.crt + ca.crt + ca.key in rootCA/ subdirectory
 * - 1-Tier: ca.crt + ca.key in rootCA/ subdirectory
 * - Cross-Signed: ca.cs.crt (optional, added to chain if present)
 * - Supports both .crt and .pem extensions
 *
 * Arguments:
 *   base_dir: Base directory path (e.g., /opt/TLSGateNX)
 *             CA files expected in base_dir/rootCA/
 *
 * Returns:
 *   CA configuration on success, NULL on failure
 */
ca_config_t* ca_load_from_directory(const char *base_dir);

/* Free CA configuration */
void ca_config_free(ca_config_t *config);

/* Get CA type name (for logging) */
const char* ca_type_name(ca_type_t type);

/* Get issuer name (SubCA for 2-tier, CA for 1-tier) */
X509_NAME* ca_get_issuer_name(const ca_config_t *config);

/* Get signing certificate (SubCA for 2-tier, CA for 1-tier) */
X509* ca_get_signing_cert(const ca_config_t *config);

/* Get private key */
EVP_PKEY* ca_get_private_key(const ca_config_t *config);

/* Get certificate chain for signing */
STACK_OF(X509)* ca_get_chain(const ca_config_t *config);

/* Get base directory (for storing generated certificates)
 * Returns: base_dir path (e.g., /opt/TLSGateNX) */
const char* ca_get_base_dir(const ca_config_t *config);

/* Get CA directory (where CA certs and keys are stored)
 * Returns: ca_dir path (e.g., /opt/TLSGateNX/rootCA) */
const char* ca_get_ca_dir(const ca_config_t *config);

/* ========== MULTI-SUBCA SUPPORT (RSA/ECDSA/SM2) ========== */

/* Multi-SubCA Configuration: One RootCA + multiple SubCAs by algorithm
 *
 * Directory structure:
 *   base_dir/              (e.g., /opt/Aviontex/)
 *     ├── rootCA/          (CA certificates & keys - PROTECTED root:root 0600)
 *     │   ├── RSA/
 *     │   │   ├── rootca.crt   (Shared RootCA)
 *     │   │   ├── subca.crt    (RSA SubCA)
 *     │   │   ├── subca.cs.crt (optional, cross-signed)
 *     │   │   └── subca.key
 *     │   ├── ECDSA/
 *     │   │   ├── rootca.crt   (Shared RootCA)
 *     │   │   ├── subca.crt    (ECDSA SubCA)
 *     │   │   └── subca.key
 *     │   └── SM2/
 *     │       ├── rootca.crt   (Shared RootCA)
 *     │       ├── subca.crt    (SM2 SubCA)
 *     │       └── subca.key
 *     ├── certs/           (Generated certificates - writable after drop-root)
 *     │   ├── RSA/
 *     │   ├── ECDSA/
 *     │   └── SM2/
 *     └── index/           (Certificate index - writable after drop-root)
 *         ├── RSA/
 *         ├── ECDSA/
 *         └── SM2/
 */
typedef struct {
    X509 *root_cert;              /* Shared RootCA for all SubCAs */
    ca_config_t *subca[3];        /* SubCA configs: [RSA, ECDSA, SM2] */
    char base_dir[4096];          /* Base directory */
} multi_ca_config_t;

/* Load multiple SubCAs from base directory
 *
 * Loads RootCA from RSA/, ECDSA/, or SM2/ directory (all should have same root).
 * Then loads each SubCA (RSA/ECDSA/SM2) from respective directories.
 *
 * Returns: Multi-CA configuration on success, NULL on failure
 */
multi_ca_config_t* multi_ca_load_from_directory(const char *base_dir);

/* Free multi-CA configuration */
void multi_ca_free(multi_ca_config_t *config);

/* Get SubCA for specific algorithm
 *
 * Arguments:
 *   config: Multi-CA configuration
 *   algorithm: CRYPTO_ALG_RSA_3072/4096, ECDSA_P256/384/521, SM2
 *
 * Returns: ca_config_t pointer or NULL if algorithm not available
 */
ca_config_t* multi_ca_get_subca_for_algorithm(const multi_ca_config_t *config,
                                              crypto_alg_t algorithm);

/* Get RootCA from multi-CA config */
X509* multi_ca_get_root_cert(const multi_ca_config_t *config);

#endif /* CA_LOADER_H */
