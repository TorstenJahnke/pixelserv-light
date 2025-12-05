/* TLSGateNX - CA Certificate Auto-Detection and Loader
 * Copyright (C) 2025 Torsten Jahnke
 */

#include "ca_loader.h"
#include "../util/logger.h"
#include "../config/config_file.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <dirent.h>
#include <openssl/pem.h>
#include <openssl/err.h>

/* External global for legacy crypto mode */
extern bool g_legacy_crypto_enabled;

/* Try to read CA paths from tlsgateNG.conf in the CA base directory
 *
 * Config format (algorithm-specific sections):
 * [ca-RSA]
 * sub_cert_path = /path/to/subca.crt
 * sub_key_path = /path/to/subca.key
 * root_cert_path = /path/to/rootca.crt
 * sub_cs_cert_path = /path/to/subca.cs.crt (optional - cross-signed SubCA)
 *
 * For Single Mode (RootCA only):
 * [ca-keweon]
 * root_cert_path = /path/to/rootca.crt
 * root_key_path = /path/to/rootca.key
 *
 * [ca-ECDSA]
 * [ca-SM2]
 * [ca-LEGACY]  (for legacy RootCA mode)
 *
 * Legacy format (backward compatible):
 * [ca]
 * sub_cert_path = /path/to/subca.crt
 * sub_key_path = /path/to/subca.key
 * root_cert_path = /path/to/rootca.crt
 * sub_cs_cert_path = /path/to/subca.cs.crt (optional)
 *
 * Arguments:
 *   base_dir: Base configuration directory
 *   algorithm: Algorithm name (e.g., "RSA", "ECDSA", "SM2", "LEGACY") or NULL for generic [ca]
 *   sub_cert_out, sub_key_out, root_cert_out, cs_cert_out: Output buffers for paths
 *   root_key_out: Output buffer for root key path (for Single Mode)
 *
 * Returns: true if paths were successfully loaded from config, false otherwise
 */
static bool read_ca_config_from_file(const char *base_dir,
                                     const char *algorithm,
                                     char *sub_cert_out, size_t sub_cert_size,
                                     char *sub_key_out, size_t sub_key_size,
                                     char *root_cert_out, size_t root_cert_size,
                                     char *cs_cert_out, size_t cs_cert_size,
                                     char *root_key_out, size_t root_key_size) {
    if (!base_dir) return false;

    char config_path[4096];
    snprintf(config_path, sizeof(config_path), "%s/tlsgateNG.conf", base_dir);

    FILE *fp = fopen(config_path, "r");
    if (!fp) {
        /* Config file not found - that's OK, will use auto-detection */
        return false;
    }

    char line[4096];
    bool in_ca_section = false;
    bool found_paths = false;

    /* Build section name to look for */
    char section_name[64];

    if (algorithm && algorithm[0]) {
        snprintf(section_name, sizeof(section_name), "[ca-%s]", algorithm);
    } else {
        /* For generic CA mode, use [ca] section */
        snprintf(section_name, sizeof(section_name), "[ca]");
    }

    /* Parse appropriate CA section */
    while (fgets(line, sizeof(line), fp)) {
        /* Remove newline */
        char *nl = strchr(line, '\n');
        if (nl) *nl = '\0';

        /* Skip comments and empty lines */
        if (line[0] == ';' || line[0] == '#' || line[0] == '\0') continue;

        /* Check for section headers */
        if (line[0] == '[') {
            in_ca_section = (strcmp(line, section_name) == 0);
            continue;
        }

        if (!in_ca_section) continue;

        /* Parse key=value pairs */
        char *eq = strchr(line, '=');
        if (!eq) continue;

        /* Extract key and value */
        *eq = '\0';
        char *key = line;
        char *value = eq + 1;

        /* Trim whitespace from key */
        while (*key && (*key == ' ' || *key == '\t')) key++;
        size_t key_len = strlen(key);
        while (key_len > 0 && (key[key_len-1] == ' ' || key[key_len-1] == '\t')) {
            key[key_len-1] = '\0';
            key_len--;
        }
        while (*value && (*value == ' ' || *value == '\t')) value++;

        /* Parse CA paths (accept both underscore and hyphen variants) */
        if ((strcmp(key, "sub_cert_path") == 0 || strcmp(key, "sub-cert-path") == 0) && *value) {
            strncpy(sub_cert_out, value, sub_cert_size - 1);
            sub_cert_out[sub_cert_size - 1] = '\0';
            found_paths = true;
            LOG_DEBUG("CA Config [%s]: sub_cert_path = %s", algorithm ? algorithm : "ca", value);
        } else if ((strcmp(key, "sub_key_path") == 0 || strcmp(key, "sub-key-path") == 0) && *value) {
            strncpy(sub_key_out, value, sub_key_size - 1);
            sub_key_out[sub_key_size - 1] = '\0';
            found_paths = true;
            LOG_DEBUG("CA Config [%s]: sub_key_path = %s", algorithm ? algorithm : "ca", value);
        } else if ((strcmp(key, "root_cert_path") == 0 || strcmp(key, "root-cert-path") == 0) && *value) {
            strncpy(root_cert_out, value, root_cert_size - 1);
            root_cert_out[root_cert_size - 1] = '\0';
            found_paths = true;
            LOG_DEBUG("CA Config [%s]: root_cert_path = %s", algorithm ? algorithm : "ca", value);
        } else if ((strcmp(key, "root_key_path") == 0 || strcmp(key, "root-key-path") == 0) && *value) {
            /* Root key path (for Single Mode: RootCA signs directly) */
            strncpy(root_key_out, value, root_key_size - 1);
            root_key_out[root_key_size - 1] = '\0';
            found_paths = true;
            LOG_DEBUG("CA Config [%s]: root_key_path = %s", algorithm ? algorithm : "ca", value);
        } else if ((strcmp(key, "sub_cs_cert_path") == 0 || strcmp(key, "sub-cs-cert-path") == 0) && *value) {
            /* Optional cross-signed SubCA certificate */
            strncpy(cs_cert_out, value, cs_cert_size - 1);
            cs_cert_out[cs_cert_size - 1] = '\0';
            LOG_DEBUG("CA Config [%s]: sub_cs_cert_path = %s", algorithm ? algorithm : "ca", value);
        }
    }

    fclose(fp);

    if (found_paths) {
        LOG_INFO("CA paths loaded from config [%s]: %s", algorithm ? algorithm : "ca", config_path);
        return true;
    }

    /* If algorithm-specific section not found, try generic [ca] section as fallback */
    if (algorithm && algorithm[0]) {
        LOG_DEBUG("Section [ca-%s] not found in config, trying fallback [ca] section", algorithm);
        return read_ca_config_from_file(base_dir, NULL,
                                       sub_cert_out, sub_cert_size,
                                       sub_key_out, sub_key_size,
                                       root_cert_out, root_cert_size,
                                       cs_cert_out, cs_cert_size,
                                       root_key_out, root_key_size);
    }

    return false;
}

/* Check if file exists */
static bool file_exists(const char *path) {
    struct stat st;
    return (stat(path, &st) == 0 && S_ISREG(st.st_mode));
}

/* Try to find a certificate file with given names */
static bool find_cert_file(const char *dir, const char **names, char *out_path, size_t out_size) {
    for (int i = 0; names[i] != NULL; i++) {
        snprintf(out_path, out_size, "%s/%s", dir, names[i]);
        if (file_exists(out_path)) {
            return true;
        }
    }
    return false;
}

/* Load X.509 certificate from file */
static X509* load_cert_file(const char *path) {
    FILE *fp = fopen(path, "r");
    if (!fp) {
        LOG_ERROR("Failed to open certificate file: %s", path);
        return NULL;
    }

    X509 *cert = PEM_read_X509(fp, NULL, NULL, NULL);
    fclose(fp);

    if (!cert) {
        LOG_ERROR("Failed to parse certificate: %s", path);
        unsigned long err = ERR_get_error();
        if (err) {
            char err_buf[256];
            ERR_error_string_n(err, err_buf, sizeof(err_buf));
            LOG_ERROR("OpenSSL error: %s", err_buf);
        }
    }

    return cert;
}

/* Passphrase callback (reads from ca.key.passphrase file)
 * Based on Old/certs.c:2248-2270 */
static int pem_passphrase_cb(char *buf, int size, int rwflag , void *userdata) {
    (void)rwflag;  /* Unused but required by OpenSSL callback signature */
    const char *ca_dir = (const char *)userdata;
    char passphrase_file[4096];
    int fd;
    ssize_t bytes_read = -1;

    /* Validate input from OpenSSL - size should be reasonable */
    if (size < 2 || !buf) {
        return 0;  /* Invalid parameters from caller */
    }

    /* Build path to passphrase file */
    snprintf(passphrase_file, sizeof(passphrase_file), "%s/ca.key.passphrase", ca_dir);

    /* Try to open passphrase file */
    fd = open(passphrase_file, O_RDONLY);
    if (fd < 0) {
        /* No passphrase file - return 0 (no passphrase) */
        return 0;
    }

    /* Read passphrase */
    bytes_read = read(fd, buf, size - 1);
    close(fd);

    /* Handle read errors - return -1 to signal error to OpenSSL
     * SECURITY FIX: Previously returned 0 (no passphrase) on I/O errors,
     * which could allow CA key to be loaded without passphrase on failures */
    if (bytes_read < 0) {
        LOG_ERROR("Failed to read passphrase file: %s", passphrase_file);
        return -1;
    }

    if (bytes_read > 0) {
        /* Remove trailing newline if present */
        if (buf[bytes_read - 1] == '\n') {
            bytes_read--;
        }
        buf[bytes_read] = '\0';
    }

    return (int)bytes_read;
}

/* Load private key from file (supports passphrase via callback) */
static EVP_PKEY* load_key_file(const char *path, const char *ca_dir) {
    FILE *fp = fopen(path, "r");
    if (!fp) {
        LOG_ERROR("Failed to open private key file: %s", path);
        return NULL;
    }

    /* Load key with passphrase callback (reads ca.key.passphrase if exists) */
    EVP_PKEY *key = PEM_read_PrivateKey(fp, NULL, pem_passphrase_cb, (void*)ca_dir);
    fclose(fp);

    if (!key) {
        LOG_ERROR("Failed to parse private key: %s", path);
        unsigned long err = ERR_get_error();
        if (err) {
            char err_buf[256];
            ERR_error_string_n(err, err_buf, sizeof(err_buf));
            LOG_ERROR("OpenSSL error: %s", err_buf);
        }
    }

    return key;
}

/* Auto-detect and load CA configuration from base directory */
ca_config_t* ca_load_from_directory(const char *base_dir) {
    if (!base_dir || strlen(base_dir) == 0) {
        LOG_ERROR("Invalid base directory path");
        return NULL;
    }

    /* Check if base directory exists */
    struct stat st;
    if (stat(base_dir, &st) != 0 || !S_ISDIR(st.st_mode)) {
        LOG_ERROR("Base directory does not exist: %s", base_dir);
        return NULL;
    }

    ca_config_t *config = calloc(1, sizeof(ca_config_t));
    if (!config) {
        LOG_ERROR("Failed to allocate CA configuration");
        return NULL;
    }

    /* Store base directory path */
    strncpy(config->base_dir, base_dir, sizeof(config->base_dir) - 1);

    /* Try to read CA paths from main config file first (if it exists)
     * Uses system config path (usually /etc/tlsgateNG/tlsgateNG.conf)
     * This gives users explicit control over CA path configuration
     * Pass NULL for algorithm to use generic [ca] section for single-CA mode */
    char config_sub_cert[4096] = "";
    char config_sub_key[4096] = "";
    char config_root_cert[4096] = "";
    char config_cs_cert[4096] = "";

    char config_root_key[4096] = "";

    /* Read from main config location (/etc/tlsgateNG/tlsgateNG.conf) */
    const char *config_dir = config_get_dir();
    bool config_loaded = read_ca_config_from_file(config_dir, NULL,
                                                  config_sub_cert, sizeof(config_sub_cert),
                                                  config_sub_key, sizeof(config_sub_key),
                                                  config_root_cert, sizeof(config_root_cert),
                                                  config_cs_cert, sizeof(config_cs_cert),
                                                  config_root_key, sizeof(config_root_key));

    /* Check if we have Multi Mode config (sub_cert + sub_key) */
    if (config_loaded && config_sub_cert[0] != '\0' && config_sub_key[0] != '\0') {
        /* CA paths provided in config - use them directly */
        LOG_INFO("Using CA paths from tlsgateNG.conf:");
        LOG_INFO("  SubCA Cert: %s", config_sub_cert);
        LOG_INFO("  SubCA Key:  %s", config_sub_key);
        LOG_INFO("  RootCA Cert: %s", config_root_cert);

        snprintf(config->sub_cert_path, sizeof(config->sub_cert_path), "%s", config_sub_cert);
        snprintf(config->key_path, sizeof(config->key_path), "%s", config_sub_key);
        if (config_root_cert[0] != '\0') {
            snprintf(config->root_cert_path, sizeof(config->root_cert_path), "%s", config_root_cert);
        }
        if (config_cs_cert[0] != '\0') {
            snprintf(config->cs_cert_path, sizeof(config->cs_cert_path), "%s", config_cs_cert);
            LOG_INFO("  Cross-Signed SubCA: %s", config_cs_cert);
        }

        /* Set CA dir to the directory containing the cert file (for consistency) */
        char ca_dir_from_cert[4096];
        snprintf(ca_dir_from_cert, sizeof(ca_dir_from_cert), "%s", config_sub_cert);
        /* Find last '/' and truncate there */
        char *last_slash = strrchr(ca_dir_from_cert, '/');
        if (last_slash) {
            *last_slash = '\0';
            snprintf(config->ca_dir, sizeof(config->ca_dir), "%s", ca_dir_from_cert);
        } else {
            snprintf(config->ca_dir, sizeof(config->ca_dir), "%s", base_dir);
        }
        snprintf(config->certs_dir, sizeof(config->certs_dir), "%s/certs", base_dir);
        snprintf(config->index_dir, sizeof(config->index_dir), "%s/index", base_dir);
    } else if (config_loaded && config_root_cert[0] != '\0' && config_root_key[0] != '\0') {
        /* Single Mode config: Only RootCA cert and key (no SubCA) */
        LOG_INFO("Using Single Mode CA paths from tlsgateNG.conf:");
        LOG_INFO("  RootCA Cert: %s", config_root_cert);
        LOG_INFO("  RootCA Key:  %s", config_root_key);

        snprintf(config->root_cert_path, sizeof(config->root_cert_path), "%s", config_root_cert);
        snprintf(config->key_path, sizeof(config->key_path), "%s", config_root_key);
        config->sub_cert_path[0] = '\0';  /* No SubCA in Single Mode */
        config->cs_cert_path[0] = '\0';   /* No Cross-Signed cert in Single Mode */

        /* Set CA dir to the directory containing the cert file */
        char ca_dir_from_cert[4096];
        snprintf(ca_dir_from_cert, sizeof(ca_dir_from_cert), "%s", config_root_cert);
        char *last_slash = strrchr(ca_dir_from_cert, '/');
        if (last_slash) {
            *last_slash = '\0';
            snprintf(config->ca_dir, sizeof(config->ca_dir), "%s", ca_dir_from_cert);
        } else {
            snprintf(config->ca_dir, sizeof(config->ca_dir), "%s", base_dir);
        }
        snprintf(config->certs_dir, sizeof(config->certs_dir), "%s/certs", base_dir);
        snprintf(config->index_dir, sizeof(config->index_dir), "%s/index", base_dir);
    } else {
        /* No config paths - use auto-detection
         * Priority: OLD structure first (for Single Mode), then NEW structure (for Multi Mode) */

        char old_struct_dir[4096];
        snprintf(old_struct_dir, sizeof(old_struct_dir), "%s/rootCA", base_dir);

        /* Check OLD structure first: base_dir/rootCA/ (Single Mode or legacy Multi Mode) */
        if (stat(old_struct_dir, &st) == 0 && S_ISDIR(st.st_mode)) {
            /* Old structure exists - use it (priority for Single Mode) */
            snprintf(config->ca_dir, sizeof(config->ca_dir), "%s/rootCA", base_dir);
            snprintf(config->certs_dir, sizeof(config->certs_dir), "%s/certs", base_dir);
            snprintf(config->index_dir, sizeof(config->index_dir), "%s/index", base_dir);
            LOG_INFO("Using standard directory structure: /rootCA/");
        } else {
            /* Old structure doesn't exist - try NEW structure: base_dir/RSA/rootCA/ (Multi Mode with algorithms) */
            char new_struct_test[4096];
            char new_struct_rootca_dir[4096];
            snprintf(new_struct_test, sizeof(new_struct_test), "%s/RSA", base_dir);
            snprintf(new_struct_rootca_dir, sizeof(new_struct_rootca_dir), "%s/RSA/rootCA", base_dir);

            bool use_new_structure = false;
            if (stat(new_struct_test, &st) == 0 && S_ISDIR(st.st_mode)) {
                /* RSA directory exists - check if rootCA directory also exists and has certificates */
                if (stat(new_struct_rootca_dir, &st) == 0 && S_ISDIR(st.st_mode)) {
                    /* Check if there are any certificate files in the new structure */
                    DIR *dir = opendir(new_struct_rootca_dir);
                    if (dir) {
                        struct dirent *entry;
                        while ((entry = readdir(dir)) != NULL) {
                            size_t name_len = strlen(entry->d_name);
                            if (name_len > 4) {
                                const char *ext = entry->d_name + name_len - 4;
                                if (strcmp(ext, ".crt") == 0 || strcmp(ext, ".pem") == 0 || strcmp(ext, ".key") == 0) {
                                    use_new_structure = true;
                                    break;
                                }
                            }
                            /* No files without extension are supported anymore */
                        }
                        closedir(dir);
                    }
                }
            }

            if (use_new_structure) {
                /* New structure validated: /RSA/rootCA/ (Multi Mode with multiple algorithms) */
                snprintf(config->ca_dir, sizeof(config->ca_dir), "%s/RSA/rootCA", base_dir);
                snprintf(config->certs_dir, sizeof(config->certs_dir), "%s/RSA/certs", base_dir);
                snprintf(config->index_dir, sizeof(config->index_dir), "%s/RSA/index", base_dir);
                LOG_INFO("Using multi-algorithm directory structure: /RSA/rootCA/");
            } else {
                /* Neither old nor new structure found */
                LOG_ERROR("No valid CA directory structure found in %s", base_dir);
                LOG_INFO("Expected: %s/rootCA/ (Single/Multi Mode) or %s/RSA/rootCA/ (Multi Mode)", base_dir, base_dir);
                free(config);
                return NULL;
            }
        }  /* Close auto-detection if/else */
    }  /* Close config_loaded if/else */

    /* Certificate file name patterns
     *
     * Valid constellations:
     *   1. Single Mode:  rootca.crt + rootca.key (RootCA signs directly, no multi-algorithm)
     *   2. Multi Mode:   rootca.crt + subca.crt + subca.key (SubCA signs, supports RSA/ECDSA/SM2)
     *   3. Multi + CS:   rootca.crt + subca.crt + subca.cs.crt + subca.key (with Cross-Signed cert)
     */
    const char *rootca_names[] = { "rootca.crt", "rootca.pem", "RootCA.crt", "RootCA.pem", NULL };
    const char *rootca_key_names[] = { "rootca.key", "RootCA.key", NULL };
    const char *ca_names[] = { "subca.crt", "subca.pem", "SubCA.crt", "SubCA.pem", NULL };
    const char *subca_key_names[] = { "subca.key", "SubCA.key", NULL };
    const char *cs_names[] = { "subca.cs.crt", "subca.cs.pem", "SubCA.cs.crt", "SubCA.cs.pem", NULL };

    /* Step 1: KEY-BASED MODE DETECTION - Determine CA mode by which key exists
     * - If subca.key exists: Multi Mode (Constellations 2 or 3)
     * - If only rootca.key exists: Single Mode (Constellation 1)
     * SKIP this if CA paths were loaded from config */
    bool has_subca_key;
    bool has_rootca_key = false;
    char rootca_key_path[4096] = "";

    if (config_loaded && config->key_path[0] != '\0') {
        /* Paths already loaded from config - determine mode based on what's set */
        if (config->sub_cert_path[0] != '\0') {
            /* SubCA mode: Both sub_cert and key_path are set */
            has_subca_key = true;
            LOG_INFO("Using CA configuration from config file (SubCA/Multi Mode)");
        } else {
            /* Single Mode: Only root cert and key_path are set, sub_cert is empty */
            has_rootca_key = true;
            /* For consistency, copy rootca key path to rootca_key_path variable */
            snprintf(rootca_key_path, sizeof(rootca_key_path), "%s", config->key_path);
            LOG_INFO("Using CA configuration from config file (Single Mode)");
        }
    } else {
        /* Auto-detect keys */
        has_subca_key = find_cert_file(config->ca_dir, subca_key_names, config->key_path, sizeof(config->key_path));

        if (!has_subca_key) {
            /* No SubCA key found - check for RootCA key (Single Mode) */
            has_rootca_key = find_cert_file(config->ca_dir, rootca_key_names, rootca_key_path, sizeof(rootca_key_path));
        }
    }

    /* Determine CA mode based on found key */
    if (has_subca_key) {
        /* Multi Mode (Constellations 2/3) - SubCA signs certificates
         * Supports multiple algorithms (RSA, ECDSA, SM2) */
        LOG_INFO("Found SubCA private key: %s (Multi Mode)", config->key_path);

        /* Step 2a: Load SubCA certificate (REQUIRED for SubCA mode) */
        /* If paths were loaded from config, they're already set - just validate they exist */
        if (!config_loaded || config->sub_cert_path[0] == '\0') {
            if (!find_cert_file(config->ca_dir, ca_names, config->sub_cert_path, sizeof(config->sub_cert_path))) {
                LOG_ERROR("SubCA certificate not found in %s", config->ca_dir);
                LOG_ERROR("Tried: subca.crt, subca.pem, SubCA.crt, SubCA.pem");
                free(config);
                return NULL;
            }
        }
        LOG_INFO("Found SubCA certificate: %s", config->sub_cert_path);

        /* Step 2b: Check for RootCA certificate (optional for 2-tier) */
        bool has_root = false;
        if (!config_loaded || config->root_cert_path[0] == '\0') {
            has_root = find_cert_file(config->ca_dir, rootca_names, config->root_cert_path,
                                            sizeof(config->root_cert_path));
        } else {
            /* Paths already loaded from config, just check they exist */
            struct stat st;
            has_root = (stat(config->root_cert_path, &st) == 0);
        }

        if (has_root) {
            LOG_INFO("Found RootCA certificate: %s (2-tier setup)", config->root_cert_path);
            config->type = CA_TYPE_TWO_TIER;
        } else {
            LOG_INFO("RootCA not found - using single-tier SubCA");
            config->type = CA_TYPE_SINGLE;
        }

        /* Step 2c: Check for Cross-Signed SubCA certificate (optional) */
        bool has_cs = false;
        if (!config_loaded || config->cs_cert_path[0] == '\0') {
            has_cs = find_cert_file(config->ca_dir, cs_names, config->cs_cert_path,
                                          sizeof(config->cs_cert_path));
        } else {
            /* Paths already loaded from config, just check they exist */
            struct stat st;
            has_cs = (stat(config->cs_cert_path, &st) == 0);
        }

        if (has_cs) {
            LOG_INFO("Found Cross-Signed SubCA certificate: %s", config->cs_cert_path);
        } else {
            LOG_DEBUG("Cross-Signed SubCA not found (optional)");
            config->cs_cert_path[0] = '\0';  /* Mark as not present */
        }

    } else if (has_rootca_key) {
        /* Single Mode - RootCA signs certificates directly
         * Constellation 1: rootca.crt + rootca.key (no SubCA)
         * This is a normal mode, NOT legacy-only! */

        LOG_INFO("Found RootCA private key: %s (Single Mode - RootCA signs directly)", rootca_key_path);
        snprintf(config->key_path, sizeof(config->key_path), "%s", rootca_key_path);

        /* Step 2d: Load RootCA certificate (REQUIRED for Single Mode) */
        if (!find_cert_file(config->ca_dir, rootca_names, config->root_cert_path, sizeof(config->root_cert_path))) {
            LOG_ERROR("RootCA certificate not found in %s", config->ca_dir);
            LOG_ERROR("Tried: rootca.crt, rootca.pem, RootCA.crt, RootCA.pem");
            LOG_INFO("Single Mode requires: rootca.crt + rootca.key");
            free(config);
            return NULL;
        }
        LOG_INFO("Found RootCA certificate: %s", config->root_cert_path);

        /* In Single Mode, RootCA acts as the signing cert */
        config->type = CA_TYPE_SINGLE;
        config->sub_cert_path[0] = '\0';  /* No SubCA in Single Mode */
        config->cs_cert_path[0] = '\0';   /* No cross-signed cert in Single Mode */

    } else {
        /* No valid key found */
        LOG_ERROR("No CA private key found in %s", config->ca_dir);
        LOG_ERROR("Tried SubCA keys: subca.key, SubCA.key");
        LOG_ERROR("Tried RootCA keys: rootca.key, RootCA.key");
        LOG_INFO("Valid constellations:");
        LOG_INFO("  1. Single Mode:  rootca.crt + rootca.key");
        LOG_INFO("  2. Multi Mode:   rootca.crt + subca.crt + subca.key");
        LOG_INFO("  3. Multi + CS:   rootca.crt + subca.crt + subca.cs.crt + subca.key");
        free(config);
        return NULL;
    }

    /* Step 3: Load certificates based on mode */
    if (has_subca_key) {
        /* SubCA mode - load SubCA certificate */
        config->sub_cert = load_cert_file(config->sub_cert_path);
        if (!config->sub_cert) {
            LOG_ERROR("Failed to load SubCA certificate: %s", config->sub_cert_path);
            ca_config_free(config);
            return NULL;
        }

        /* Load RootCA certificate (if 2-tier) */
        if (config->type == CA_TYPE_TWO_TIER) {
            config->root_cert = load_cert_file(config->root_cert_path);
            if (!config->root_cert) {
                LOG_ERROR("Failed to load RootCA certificate: %s", config->root_cert_path);
                ca_config_free(config);
                return NULL;
            }
        }

        /* Load Cross-Signed SubCA certificate (if present) */
        if (config->cs_cert_path[0] != '\0') {
            config->cs_cert = load_cert_file(config->cs_cert_path);
            if (!config->cs_cert) {
                LOG_WARN("Failed to load Cross-Signed SubCA certificate: %s (continuing without it)",
                         config->cs_cert_path);
                config->cs_cert = NULL;
                config->cs_cert_path[0] = '\0';
            }
        } else {
            config->cs_cert = NULL;
        }

    } else if (has_rootca_key) {
        /* RootCA-only mode - load only RootCA certificate */
        config->root_cert = load_cert_file(config->root_cert_path);
        if (!config->root_cert) {
            LOG_ERROR("Failed to load RootCA certificate: %s", config->root_cert_path);
            ca_config_free(config);
            return NULL;
        }

        /* In RootCA-only mode, use root_cert as signing cert (sub_cert stays NULL) */
        config->sub_cert = NULL;
        config->cs_cert = NULL;
    }

    /* Step 6: Load private key */
    config->private_key = load_key_file(config->key_path, config->ca_dir);
    if (!config->private_key) {
        LOG_ERROR("Failed to load CA private key: %s", config->key_path);
        ca_config_free(config);
        return NULL;
    }

    /* Step 7: Build certificate chain based on mode */
    config->chain = sk_X509_new_null();
    if (!config->chain) {
        LOG_ERROR("Failed to create certificate chain");
        ca_config_free(config);
        return NULL;
    }

    if (has_subca_key) {
        /* SubCA mode - add SubCA and optionally cross-signed cert to chain
         * RootCA is NOT included (browsers already have it in trust store) */

        /* Add SubCA to chain (signing certificate/intermediate) */
        X509_up_ref(config->sub_cert);  /* Increment reference count */

        /* CRITICAL BUG FIX: Check sk_X509_push return value
         * sk_X509_push() can fail if memory allocation fails in the stack */
        if (!sk_X509_push(config->chain, config->sub_cert)) {
            LOG_ERROR("Failed to push SubCA certificate to chain (memory error)");
            /* Undo the up_ref from above */
            #ifdef X509_down_ref
            X509_down_ref(config->sub_cert);
            #else
            /* Older OpenSSL versions don't have X509_down_ref - use X509_free instead
             * CRITICAL FIX: Must call X509_free to undo X509_up_ref and prevent memory leak */
            X509_free(config->sub_cert);
            config->sub_cert = NULL;  /* Prevent double-free in ca_config_free */
            #endif
            ca_config_free(config);
            return NULL;
        }

        /* Add Cross-Signed SubCA to chain (if present)
         * This allows clients with different root CAs to validate the certificate chain */
        if (config->cs_cert) {
            X509_up_ref(config->cs_cert);  /* Increment reference count */

            if (!sk_X509_push(config->chain, config->cs_cert)) {
                LOG_WARN("Failed to push Cross-Signed SubCA certificate to chain (memory error) - continuing without it");
                X509_free(config->cs_cert);  /* Free since push failed */
                config->cs_cert = NULL;
            } else {
                LOG_INFO("Added Cross-Signed SubCA to certificate chain");
            }
        }

        LOG_INFO("CA configuration loaded successfully (SubCA mode, chain: %d certs)", sk_X509_num(config->chain));

    } else if (has_rootca_key) {
        /* RootCA-only mode - empty chain (RootCA signs directly, no intermediates)
         * Legacy clients must have RootCA in their trust store */
        LOG_INFO("CA configuration loaded successfully (RootCA-only mode for legacy clients, empty chain)");
    }


    return config;
}

/* Free CA configuration */
void ca_config_free(ca_config_t *config) {
    if (!config) {
        return;
    }

    if (config->root_cert) {
        X509_free(config->root_cert);
    }

    if (config->sub_cert) {
        X509_free(config->sub_cert);
    }

    if (config->cs_cert) {
        X509_free(config->cs_cert);
    }

    if (config->private_key) {
        EVP_PKEY_free(config->private_key);
    }

    if (config->chain) {
        sk_X509_pop_free(config->chain, X509_free);
    }

    free(config);
}

/* Get CA type name */
const char* ca_type_name(ca_type_t type) {
    switch (type) {
        case CA_TYPE_SINGLE:   return "Single-Tier";
        case CA_TYPE_TWO_TIER: return "Two-Tier (RootCA + SubCA)";
        default:               return "Unknown";
    }
}

/* Get issuer name (SubCA for 2-tier, CA for 1-tier, RootCA for legacy) */
X509_NAME* ca_get_issuer_name(const ca_config_t *config) {
    if (!config) {
        return NULL;
    }

    /* In RootCA-only mode (legacy), use RootCA as issuer */
    if (config->sub_cert) {
        return X509_get_subject_name(config->sub_cert);
    } else if (config->root_cert) {
        return X509_get_subject_name(config->root_cert);
    }

    return NULL;
}

/* Get signing certificate (SubCA for 2-tier, CA for 1-tier, RootCA for legacy) */
X509* ca_get_signing_cert(const ca_config_t *config) {
    if (!config) {
        return NULL;
    }

    /* In RootCA-only mode (legacy), use RootCA as signing cert */
    if (config->sub_cert) {
        return config->sub_cert;
    } else if (config->root_cert) {
        return config->root_cert;
    }

    return NULL;
}

/* Get private key */
EVP_PKEY* ca_get_private_key(const ca_config_t *config) {
    if (!config) {
        return NULL;
    }
    return config->private_key;
}

/* Get certificate chain */
STACK_OF(X509)* ca_get_chain(const ca_config_t *config) {
    if (!config) {
        return NULL;
    }
    return config->chain;
}

/* Get base directory */
const char* ca_get_base_dir(const ca_config_t *config) {
    if (!config) {
        return NULL;
    }
    return config->base_dir;
}

/* Get CA directory */
const char* ca_get_ca_dir(const ca_config_t *config) {
    if (!config) {
        return NULL;
    }
    return config->ca_dir;
}

/* ========== MULTI-SUBCA IMPLEMENTATION ========== */

/* Load single SubCA from algorithm-specific directory or config */
static ca_config_t* load_subca_for_algo(const char *base_dir, const char *algo_name) {
    ca_config_t *config = calloc(1, sizeof(ca_config_t));
    if (!config) {
        LOG_ERROR("Failed to allocate SubCA configuration");
        return NULL;
    }

    snprintf(config->base_dir, sizeof(config->base_dir), "%s", base_dir);

    /* Try to read CA paths from algorithm-specific config section first
     * Format: [ca-RSA], [ca-ECDSA], [ca-SM2], [ca-LEGACY] */
    char config_sub_cert[4096] = "";
    char config_sub_key[4096] = "";
    char config_root_cert[4096] = "";
    char config_cs_cert[4096] = "";
    char config_root_key[4096] = "";

    bool config_loaded = read_ca_config_from_file(base_dir, algo_name,
                                                  config_sub_cert, sizeof(config_sub_cert),
                                                  config_sub_key, sizeof(config_sub_key),
                                                  config_root_cert, sizeof(config_root_cert),
                                                  config_cs_cert, sizeof(config_cs_cert),
                                                  config_root_key, sizeof(config_root_key));

    if (config_loaded && config_sub_cert[0] != '\0' && config_sub_key[0] != '\0') {
        /* CA paths provided in config for this algorithm */
        LOG_INFO("Using %s SubCA paths from config: %s", algo_name, config_sub_cert);
        snprintf(config->sub_cert_path, sizeof(config->sub_cert_path), "%s", config_sub_cert);
        snprintf(config->key_path, sizeof(config->key_path), "%s", config_sub_key);
        if (config_root_cert[0] != '\0') {
            snprintf(config->root_cert_path, sizeof(config->root_cert_path), "%s", config_root_cert);
        }
        if (config_cs_cert[0] != '\0') {
            snprintf(config->cs_cert_path, sizeof(config->cs_cert_path), "%s", config_cs_cert);
            LOG_INFO("Cross-Signed SubCA for %s: %s", algo_name, config_cs_cert);
        }

        /* Set CA dir from cert path for consistency */
        char ca_dir_from_cert[4096];
        snprintf(ca_dir_from_cert, sizeof(ca_dir_from_cert), "%s", config_sub_cert);
        char *last_slash = strrchr(ca_dir_from_cert, '/');
        if (last_slash) {
            *last_slash = '\0';
            snprintf(config->ca_dir, sizeof(config->ca_dir), "%s", ca_dir_from_cert);
        } else {
            snprintf(config->ca_dir, sizeof(config->ca_dir), "%s/%s", base_dir, algo_name);
        }
    } else {
        /* Fall back to auto-detection from directory structure
         * Structure: base_dir/rootCA/{RSA,ECDSA,SM2}/  - CA certificates (protected)
         *            base_dir/certs/{RSA,ECDSA,SM2}/   - Generated certificates (writable)
         *            base_dir/index/{RSA,ECDSA,SM2}/   - Index files (writable) */
        snprintf(config->ca_dir, sizeof(config->ca_dir), "%s/rootCA/%s", base_dir, algo_name);

        /* Certificate file priorities */
        const char *rootca_names[] = { "rootca.crt", "root.crt", "rootca.pem", NULL };
        const char *ca_names[] = { "subca.crt", "ca.crt", "subca.pem", "ca.pem", NULL };
        const char *key_names[] = { "subca.key", "ca.key", "ca-key.pem", NULL };

        /* Find root cert */
        if (!find_cert_file(config->ca_dir, rootca_names, config->root_cert_path,
                            sizeof(config->root_cert_path))) {
            LOG_ERROR("Root CA not found for %s in %s", algo_name, config->ca_dir);
            free(config);
            return NULL;
        }

        /* Find SubCA cert */
        if (!find_cert_file(config->ca_dir, ca_names, config->sub_cert_path,
                            sizeof(config->sub_cert_path))) {
            LOG_ERROR("SubCA certificate not found for %s in %s", algo_name, config->ca_dir);
            free(config);
            return NULL;
        }

        /* Find private key */
        if (!find_cert_file(config->ca_dir, key_names, config->key_path,
                            sizeof(config->key_path))) {
            LOG_ERROR("CA private key not found for %s in %s", algo_name, config->ca_dir);
            free(config);
            return NULL;
        }
    }

    /* Set up generated certificate directories based on algorithm
     * These must be writable after drop_privileges() */
    snprintf(config->certs_dir, sizeof(config->certs_dir), "%s/certs/%s", base_dir, algo_name);
    snprintf(config->index_dir, sizeof(config->index_dir), "%s/index/%s", base_dir, algo_name);

    /* Check for Cross-Signed SubCA certificate (optional) */
    const char *cs_names[] = { "subca.cs.crt", "ca.cs.crt", NULL };
    bool has_cs = find_cert_file(config->ca_dir, cs_names, config->cs_cert_path,
                                  sizeof(config->cs_cert_path));
    if (has_cs) {
        LOG_INFO("Found Cross-Signed SubCA certificate: %s", config->cs_cert_path);
    } else {
        LOG_DEBUG("Cross-Signed SubCA not found (optional)");
        config->cs_cert_path[0] = '\0';  /* Mark as not present */
    }

    /* Load certificates */
    config->root_cert = load_cert_file(config->root_cert_path);
    if (!config->root_cert) {
        LOG_ERROR("Failed to load root cert from %s", config->root_cert_path);
        free(config);
        return NULL;
    }

    config->sub_cert = load_cert_file(config->sub_cert_path);
    if (!config->sub_cert) {
        LOG_ERROR("Failed to load SubCA cert from %s", config->sub_cert_path);
        X509_free(config->root_cert);
        free(config);
        return NULL;
    }

    /* Load Cross-Signed SubCA certificate (if present) */
    if (config->cs_cert_path[0] != '\0') {
        config->cs_cert = load_cert_file(config->cs_cert_path);
        if (!config->cs_cert) {
            LOG_WARN("Failed to load Cross-Signed SubCA certificate: %s (continuing without it)",
                     config->cs_cert_path);
            config->cs_cert = NULL;
            config->cs_cert_path[0] = '\0';
        }
    } else {
        config->cs_cert = NULL;
    }

    /* Load private key */
    config->private_key = load_key_file(config->key_path, config->ca_dir);
    if (!config->private_key) {
        LOG_ERROR("Failed to load private key from %s", config->key_path);
        X509_free(config->root_cert);
        X509_free(config->sub_cert);
        if (config->cs_cert) X509_free(config->cs_cert);
        free(config);
        return NULL;
    }

    /* Build certificate chain (only SubCA/Intermediate, NOT RootCA)
     * RootCA is not included because browsers already have it in their trust store */
    config->chain = sk_X509_new_null();
    if (!config->chain) {
        LOG_ERROR("Failed to create certificate chain");
        X509_free(config->root_cert);
        X509_free(config->sub_cert);
        EVP_PKEY_free(config->private_key);
        free(config);
        return NULL;
    }

    /* Add SubCA to chain (intermediate certificate only) */
    X509_up_ref(config->sub_cert);

    /* CRITICAL BUG FIX: Check sk_X509_push return value
     * sk_X509_push() can fail if memory allocation fails in the stack */
    if (!sk_X509_push(config->chain, config->sub_cert)) {
        LOG_ERROR("Failed to push SubCA certificate to chain (memory error)");
        /* Undo the up_ref from above */
        #ifdef X509_down_ref
        X509_down_ref(config->sub_cert);
        #else
        /* Older OpenSSL versions don't have X509_down_ref - use X509_free instead
         * CRITICAL FIX: Must call X509_free to undo X509_up_ref and prevent memory leak */
        X509_free(config->sub_cert);
        #endif
        X509_free(config->root_cert);
        if (config->cs_cert) X509_free(config->cs_cert);
        EVP_PKEY_free(config->private_key);
        sk_X509_pop_free(config->chain, X509_free);
        free(config);
        return NULL;
    }

    /* Add Cross-Signed SubCA to chain (if present) */
    if (config->cs_cert) {
        X509_up_ref(config->cs_cert);
        if (!sk_X509_push(config->chain, config->cs_cert)) {
            LOG_ERROR("Failed to push Cross-Signed SubCA certificate to chain (memory error)");
            /* Undo the up_ref from above */
            #ifdef X509_down_ref
            X509_down_ref(config->cs_cert);
            #else
            X509_free(config->cs_cert);
            #endif
            X509_free(config->root_cert);
            X509_free(config->sub_cert);
            X509_free(config->cs_cert);
            EVP_PKEY_free(config->private_key);
            sk_X509_pop_free(config->chain, X509_free);
            free(config);
            return NULL;
        }
        LOG_INFO("Added Cross-Signed SubCA to certificate chain");
    }

    config->type = CA_TYPE_TWO_TIER;

    return config;
}

/* Load multiple SubCAs from base directory
 *
 * Configuration can be specified in algorithm-specific sections:
 * [ca-RSA], [ca-ECDSA], [ca-SM2], [ca-LEGACY]
 *
 * Falls back to directory structure if config sections not present:
 * base_dir/rootCA/RSA/{files}, base_dir/rootCA/ECDSA/{files}, base_dir/rootCA/SM2/{files}
 */
multi_ca_config_t* multi_ca_load_from_directory(const char *base_dir) {
    if (!base_dir || strlen(base_dir) == 0) {
        LOG_ERROR("Invalid base directory path");
        return NULL;
    }

    struct stat st;
    if (stat(base_dir, &st) != 0 || !S_ISDIR(st.st_mode)) {
        LOG_ERROR("Base directory does not exist: %s", base_dir);
        return NULL;
    }

    multi_ca_config_t *config = calloc(1, sizeof(multi_ca_config_t));
    if (!config) {
        LOG_ERROR("Failed to allocate multi-CA configuration");
        return NULL;
    }

    strncpy(config->base_dir, base_dir, sizeof(config->base_dir) - 1);

    /* Load SubCAs for RSA, ECDSA, SM2
     * Each can be configured with [ca-RSA], [ca-ECDSA], [ca-SM2] sections */
    const char *algo_names[] = { "RSA", "ECDSA", "SM2" };

    for (int i = 0; i < 3; i++) {
        config->subca[i] = load_subca_for_algo(base_dir, algo_names[i]);
        if (!config->subca[i]) {
            LOG_WARN("Failed to load %s SubCA (check config [ca-%s] section or directory)", algo_names[i], algo_names[i]);
            /* Continue - at least one should succeed */
        }
    }

    /* Check if at least one SubCA loaded */
    bool has_subca = false;
    for (int i = 0; i < 3; i++) {
        if (config->subca[i]) {
            has_subca = true;
            break;
        }
    }

    if (!has_subca) {
        LOG_ERROR("Failed to load any SubCA (RSA/ECDSA/SM2)");
        free(config);
        return NULL;
    }

    /* Verify all SubCAs have the same RootCA (for integrity) */
    X509 *first_root = NULL;
    for (int i = 0; i < 3; i++) {
        if (config->subca[i]) {
            if (!first_root) {
                first_root = config->subca[i]->root_cert;
                config->root_cert = first_root;  /* Store shared RootCA */
            } else {
                /* Compare RootCA names - they should match */
                if (X509_NAME_cmp(X509_get_subject_name(first_root),
                                X509_get_subject_name(config->subca[i]->root_cert)) != 0) {
                    LOG_WARN("RootCA mismatch detected - SubCAs have different root certificates!");
                }
            }
        }
    }

    LOG_INFO("Multi-CA configuration loaded successfully");
    if (config->subca[0]) LOG_INFO("  RSA SubCA: available");
    if (config->subca[1]) LOG_INFO("  ECDSA SubCA: available");
    if (config->subca[2]) LOG_INFO("  SM2 SubCA: available");

    return config;
}

/* Free multi-CA configuration */
void multi_ca_free(multi_ca_config_t *config) {
    if (!config) return;

    /* Free each SubCA config */
    for (int i = 0; i < 3; i++) {
        if (config->subca[i]) {
            ca_config_free(config->subca[i]);
        }
    }

    free(config);
}

/* Get SubCA for specific algorithm */
ca_config_t* multi_ca_get_subca_for_algorithm(const multi_ca_config_t *config,
                                              crypto_alg_t algorithm) {
    if (!config) return NULL;

    switch (algorithm) {
        case CRYPTO_ALG_RSA_3072:
        case CRYPTO_ALG_RSA_4096:
            return config->subca[0];  /* RSA SubCA */

        case CRYPTO_ALG_ECDSA_P256:
        case CRYPTO_ALG_ECDSA_P384:
        case CRYPTO_ALG_ECDSA_P521:
            return config->subca[1];  /* ECDSA SubCA */

        case CRYPTO_ALG_SM2:
            return config->subca[2];  /* SM2 SubCA */

        default:
            return NULL;
    }
}

/* Get RootCA from multi-CA config */
X509* multi_ca_get_root_cert(const multi_ca_config_t *config) {
    if (!config) return NULL;
    return config->root_cert;
}
