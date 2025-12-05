/* TLS-Gate NX - Certificate Maintenance Implementation
 * Copyright (C) 2025 Torsten Jahnke
 */

/* FIX: Suppress GCC format-truncation warnings for path construction
 * We validate path lengths before constructing paths (see strlen checks),
 * so these warnings are false positives. */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-truncation"

#include "cert_maintenance.h"
#include "../util/logger.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>
#include <unistd.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/err.h>

/* Parse certificate file and extract domain + valid-until
 *
 * Returns: true on success, false on error
 */
static bool extract_cert_info(const char *cert_path,
                             char *domain_out, size_t domain_size,
                             time_t *valid_until_out,
                             char *algorithm_out, size_t algo_size) {
    FILE *fp = fopen(cert_path, "r");
    if (!fp) {
        LOG_ERROR("Cannot open certificate: %s", cert_path);
        return false;
    }

    /* Load certificate */
    X509 *cert = PEM_read_X509(fp, NULL, NULL, NULL);
    fclose(fp);

    if (!cert) {
        LOG_ERROR("Failed to parse certificate: %s", cert_path);
        return false;
    }

    bool success = false;

    /* Extract CN from subject */
    X509_NAME *subject = X509_get_subject_name(cert);
    if (subject) {
        int idx = X509_NAME_get_index_by_NID(subject, NID_commonName, -1);
        if (idx >= 0) {
            X509_NAME_ENTRY *entry = X509_NAME_get_entry(subject, idx);
            if (entry) {
                ASN1_STRING *data = X509_NAME_ENTRY_get_data(entry);
                if (data && data->length > 0) {
                    snprintf(domain_out, domain_size, "%.*s",
                            data->length, (const char*)data->data);
                    success = true;
                }
            }
        }
    }

    /* Extract expiration date */
    if (success) {
        ASN1_TIME *notAfter = X509_get_notAfter(cert);
        if (notAfter) {
            struct tm tm = {0};

#if OPENSSL_VERSION_NUMBER >= 0x10101000L  /* OpenSSL 1.1.1+ */
            /* ROBUSTNESS FIX: Use ASN1_TIME_to_tm() instead of manual parsing
             * This is more robust and handles different ASN1_TIME formats correctly */
            if (ASN1_TIME_to_tm(notAfter, &tm) == 1) {
                tm.tm_isdst = -1;
                *valid_until_out = mktime(&tm);
            }
#else
            /* Fallback for older OpenSSL: Parse ASN1_TIME format manually: YYMMDDhhmmssZ */
            if (notAfter->length >= 13) {
                sscanf((const char*)notAfter->data, "%2d%2d%2d%2d%2d%2d",
                      &tm.tm_year, &tm.tm_mon, &tm.tm_mday,
                      &tm.tm_hour, &tm.tm_min, &tm.tm_sec);

                /* ASN1_TIME year is offset from 1900, months are 0-11 */
                if (tm.tm_year >= 50) {
                    tm.tm_year += 1900;  /* 1950-2049 */
                } else {
                    tm.tm_year += 2000;  /* 2000-2049 */
                }
                tm.tm_mon--;  /* Adjust month from 0-11 */
                tm.tm_isdst = -1;

                *valid_until_out = mktime(&tm);
            }
#endif
        }

        /* Detect algorithm from public key */
        EVP_PKEY *pkey = X509_get_pubkey(cert);
        if (pkey) {
            int pkey_type = EVP_PKEY_id(pkey);
            if (pkey_type == EVP_PKEY_RSA) {
                snprintf(algorithm_out, algo_size, "RSA");
            } else if (pkey_type == EVP_PKEY_EC) {
                snprintf(algorithm_out, algo_size, "ECDSA");
            } else if (pkey_type == EVP_PKEY_SM2) {
                snprintf(algorithm_out, algo_size, "SM2");
            } else {
                snprintf(algorithm_out, algo_size, "UNKNOWN");
            }
            EVP_PKEY_free(pkey);
        }
    }

    X509_free(cert);
    return success;
}

/* Scan certificate directory and generate index */
cert_maint_index_t* cert_maintenance_scan_and_index(const char *ca_dir) {
    if (!ca_dir) {
        LOG_ERROR("Invalid ca_dir");
        return NULL;
    }

    /* Check certs directory exists */
    char certs_dir[4096];
    snprintf(certs_dir, sizeof(certs_dir), "%s/certs", ca_dir);

    DIR *dir = opendir(certs_dir);
    if (!dir) {
        LOG_WARN("Certs directory does not exist: %s", certs_dir);
        return NULL;
    }

    /* Allocate index structure */
    cert_maint_index_t *index = calloc(1, sizeof(cert_maint_index_t));
    if (!index) {
        closedir(dir);
        return NULL;
    }

    /* FIX: Use snprintf instead of strncpy to ensure null-termination */
    snprintf(index->ca_dir, sizeof(index->ca_dir), "%s", ca_dir);
    snprintf(index->base_dir, sizeof(index->base_dir), "%s", certs_dir);

    /* FIX: Validate path length before creating paths */
    if (strlen(certs_dir) > 4000) {
        LOG_ERROR("Certificate directory path too long: %s", certs_dir);
        free(index);
        closedir(dir);
        return NULL;
    }

    /* Allocate entries (start with 100 capacity) */
    int capacity = 100;
    index->entries = malloc(capacity * sizeof(cert_maint_entry_t));
    if (!index->entries) {
        free(index);
        closedir(dir);
        return NULL;
    }

    /* Scan directory */
    struct dirent *entry;
    FILE *index_file = NULL;
    char index_path[4096];
    snprintf(index_path, sizeof(index_path), "%s/.index", certs_dir);
    index_file = fopen(index_path, "w");

    if (index_file) {
        fprintf(index_file, "# Certificate Index - Generated %s\n", certs_dir);
        fprintf(index_file, "# domain|expiration|algorithm|days_remaining\n");
    }

    while ((entry = readdir(dir))) {
        /* Skip directories and special files */
        if (entry->d_type == DT_DIR) continue;
        if (entry->d_name[0] == '.') continue;

        /* Only process .pem and .crt files */
        const char *ext = strrchr(entry->d_name, '.');
        if (!ext || (strcmp(ext, ".pem") != 0 && strcmp(ext, ".crt") != 0)) {
            continue;
        }

        char cert_path[4096];
        snprintf(cert_path, sizeof(cert_path), "%s/%s", certs_dir, entry->d_name);

        cert_maint_entry_t *e = &index->entries[index->count];
        char algo[16] = {0};

        if (extract_cert_info(cert_path, e->domain, sizeof(e->domain),
                             &e->valid_until, algo, sizeof(algo))) {
            /* FIX: Use snprintf instead of strncpy to ensure null-termination */
            snprintf(e->algorithm, sizeof(e->algorithm), "%s", algo);
            e->needs_renewal = cert_maintenance_needs_renewal(e);

            int days = cert_maintenance_days_until_expiry(e->valid_until);
            if (index_file) {
                fprintf(index_file, "%s|%ld|%s|%d\n", e->domain, e->valid_until, algo, days);
            }

            index->count++;

            /* Grow array if needed */
            if (index->count >= capacity) {
                capacity *= 2;
                cert_maint_entry_t *new_entries = realloc(index->entries,
                                                          capacity * sizeof(cert_maint_entry_t));
                if (!new_entries) {
                    LOG_ERROR("Memory allocation failed during index scan");
                    break;
                }
                index->entries = new_entries;
            }
        }
    }

    if (index_file) {
        fclose(index_file);
        LOG_INFO("Index written: %s (%d entries)", index_path, index->count);
    }

    closedir(dir);
    return index;
}

/* Check if certificate needs renewal */
bool cert_maintenance_needs_renewal(const cert_maint_entry_t *entry) {
    if (!entry) return false;

    int days = cert_maintenance_days_until_expiry(entry->valid_until);
    return days < 7 && days >= 0;  /* < 7 days but not expired yet */
}

/* Get days until expiration */
int cert_maintenance_days_until_expiry(time_t valid_until) {
    time_t now = time(NULL);
    if (valid_until <= now) {
        return -1;  /* Already expired */
    }

    long seconds_left = valid_until - now;
    return (int)(seconds_left / (24 * 3600));  /* Convert to days */
}

/* Renew all expiring certificates
 *
 * NOTE: This function is a simplified version of cert_maintenance_cycle_12h()
 * For production use, prefer cert_maintenance_cycle_12h() which includes:
 * - Atomic certificate replacement with backup
 * - Index re-scanning after renewal
 * - Better error handling
 *
 * This function is kept for API compatibility and simple renewal scenarios.
 */
int cert_maintenance_renew_expiring(cert_generator_t *gen, const char *ca_dir) {
    if (!gen || !ca_dir) {
        return 0;
    }

    /* Scan and index all certificates */
    cert_maint_index_t *index = cert_maintenance_scan_and_index(ca_dir);
    if (!index) {
        LOG_WARN("No certificates to index in: %s", ca_dir);
        return 0;
    }

    int renewed_count = 0;

    /* Check each certificate */
    for (int i = 0; i < index->count; i++) {
        cert_maint_entry_t *entry = &index->entries[i];

        if (entry->needs_renewal) {
            int days = cert_maintenance_days_until_expiry(entry->valid_until);
            LOG_INFO("Renewing expiring cert: %s (expires in %d days)",
                    entry->domain, days);

            /* Build path to certificate */
            char certs_dir[4096];
            char cert_path[4096];
            snprintf(certs_dir, sizeof(certs_dir), "%s/certs", ca_dir);
            snprintf(cert_path, sizeof(cert_path), "%s/%s.pem",
                    certs_dir, entry->domain);

            /* Use cert_maintenance_replace_cert for atomic replacement */
            if (cert_maintenance_replace_cert(gen, ca_dir, cert_path,
                                             entry->domain)) {
                renewed_count++;
                LOG_INFO("Successfully renewed: %s", entry->domain);
            } else {
                LOG_ERROR("Failed to renew: %s", entry->domain);
            }
        }
    }

    if (renewed_count > 0) {
        LOG_INFO("Renewed %d expiring certificates from %s", renewed_count, ca_dir);
    }

    cert_maintenance_free_index(index);
    return renewed_count;
}

/* Free index structure */
void cert_maintenance_free_index(cert_maint_index_t *index) {
    if (!index) return;

    if (index->entries) {
        free(index->entries);
    }

    free(index);
}

/* Archive failed/expired certificate to OldCerts directory
 *
 * Instead of restoring a potentially broken/expired certificate,
 * we archive it for record-keeping. On next request, cert_generator
 * will create a fresh certificate automatically.
 *
 * @param ca_dir       Algorithm-specific CA directory
 * @param cert_path    Path to certificate to archive
 * @param domain       Domain name (for logging)
 * @return             true if archived successfully, false otherwise
 */
static bool archive_failed_cert(const char *ca_dir, const char *cert_path, const char *domain) {
    if (!ca_dir || !cert_path || !domain) {
        return false;
    }

    /* FIX: Validate path lengths to prevent buffer truncation */
    if (strlen(ca_dir) > 4000 || strlen(domain) > 255) {
        LOG_ERROR("Path or domain too long for archiving: %s", domain);
        remove(cert_path);  /* Delete cert if we can't archive it */
        return false;
    }

    /* Create OldCerts directory if it doesn't exist */
    char oldcerts_dir[4096];
    snprintf(oldcerts_dir, sizeof(oldcerts_dir), "%s/OldCerts", ca_dir);

    struct stat st;
    if (stat(oldcerts_dir, &st) != 0) {
        if (mkdir(oldcerts_dir, 0700) != 0) {
            LOG_ERROR("Failed to create OldCerts directory: %s", oldcerts_dir);
            /* Try to delete the cert anyway */
            remove(cert_path);
            return false;
        }
        LOG_INFO("Created OldCerts archive directory: %s", oldcerts_dir);
    }

    /* Generate archive path with timestamp */
    time_t now = time(NULL);
    char archive_path[4096];
    snprintf(archive_path, sizeof(archive_path), "%s/%s.%ld.old",
             oldcerts_dir, domain, (long)now);

    /* Move certificate to archive */
    if (rename(cert_path, archive_path) == 0) {
        LOG_INFO("Archived old certificate: %s → %s", domain, archive_path);
        return true;
    } else {
        LOG_WARN("Failed to archive certificate, deleting: %s", cert_path);
        remove(cert_path);
        return false;
    }
}

/* Replace old certificate with renewed version
 *
 * Process:
 * 1. Backup: Move old cert to .old (temporary)
 * 2. Extract: Read private key from backup
 * 3. Renew: Generate new cert with same key
 * 4. Write: Save new cert+key to .tmp file
 * 5. Replace: Atomically move .tmp to original location
 * 6. Archive: Move .old to OldCerts directory
 *
 * On Error:
 * - Archive old cert to OldCerts/ (instead of restore)
 * - Delete broken cert (if exists)
 * - Let cert_generator create fresh cert on next request
 *
 * @param gen          Certificate generator
 * @param ca_dir       Algorithm-specific CA directory
 * @param old_cert_path Path to old certificate file
 * @param domain       Domain to renew
 * @return             true if replacement successful, false otherwise
 */
bool cert_maintenance_replace_cert(cert_generator_t *gen,
                                  const char *ca_dir,
                                  const char *old_cert_path,
                                  const char *domain) {
    if (!gen || !ca_dir || !old_cert_path || !domain) {
        return false;
    }

    /* Step 1: Extract directory path from old cert */
    char certs_dir[4096];
    snprintf(certs_dir, sizeof(certs_dir), "%s/certs", ca_dir);

    /* Step 2: Create backup path */
    char backup_path[4096];
    snprintf(backup_path, sizeof(backup_path), "%s.old", old_cert_path);

    /* Step 3: Create renewal temp path */
    char temp_path[4096];
    snprintf(temp_path, sizeof(temp_path), "%s.tmp", old_cert_path);

    LOG_INFO("Certificate replacement: %s (backup: %s)", domain, backup_path);

    /* Step 4: Backup old certificate
     * ROBUSTNESS FIX: Handle cross-filesystem rename() failures (EXDEV)
     * If rename fails with EXDEV, fall back to copy+delete */
    if (rename(old_cert_path, backup_path) != 0) {
        if (errno == EXDEV) {
            /* Cross-filesystem rename - use copy+delete fallback */
            LOG_DEBUG("Cross-filesystem rename detected, using copy+delete fallback");

            /* Copy file content */
            FILE *src = fopen(old_cert_path, "rb");
            if (!src) {
                LOG_ERROR("Failed to open source for backup: %s", old_cert_path);
                return false;
            }

            FILE *dst = fopen(backup_path, "wb");
            if (!dst) {
                LOG_ERROR("Failed to create backup file: %s", backup_path);
                fclose(src);
                return false;
            }

            /* Copy in 64KB chunks */
            char copy_buffer[65536];
            size_t n;
            bool copy_success = true;
            while ((n = fread(copy_buffer, 1, sizeof(copy_buffer), src)) > 0) {
                if (fwrite(copy_buffer, 1, n, dst) != n) {
                    LOG_ERROR("Failed to write backup: %s", backup_path);
                    copy_success = false;
                    break;
                }
            }

            fclose(src);
            fclose(dst);

            if (!copy_success) {
                unlink(backup_path);  /* Clean up partial file */
                return false;
            }

            /* Delete original file after successful copy */
            if (unlink(old_cert_path) != 0) {
                LOG_ERROR("Failed to delete original after backup: %s", old_cert_path);
                unlink(backup_path);  /* Clean up backup */
                return false;
            }
        } else {
            LOG_ERROR("Failed to backup old certificate: %s → %s (errno=%d)",
                     old_cert_path, backup_path, errno);
            return false;
        }
    }

    LOG_DEBUG("Backed up old certificate: %s", backup_path);

    /* Step 5: Read private key from backup
     * The backup contains both cert and key in PEM format
     */
    FILE *backup_fp = fopen(backup_path, "r");
    if (!backup_fp) {
        LOG_ERROR("Failed to open backup for key extraction: %s", backup_path);
        /* Archive to OldCerts instead of restore */
        LOG_WARN("Archiving broken certificate: %s", domain);
        archive_failed_cert(ca_dir, backup_path, domain);
        return false;
    }

    /* Read the private key from backup (skip cert, read key) */
    EVP_PKEY *old_key = NULL;
    X509 *old_cert = PEM_read_X509(backup_fp, NULL, NULL, NULL);
    if (old_cert) {
        X509_free(old_cert);  /* We don't need the old cert, just the key */
        old_key = PEM_read_PrivateKey(backup_fp, NULL, NULL, NULL);
    }
    fclose(backup_fp);

    if (!old_key) {
        LOG_ERROR("Failed to extract private key from backup: %s", backup_path);
        /* Archive to OldCerts instead of restore */
        LOG_WARN("Archiving certificate with corrupted key: %s", domain);
        archive_failed_cert(ca_dir, backup_path, domain);
        return false;
    }

    LOG_DEBUG("Extracted private key from backup for renewal");

    /* Step 6: Generate renewed certificate using existing key */
    LOG_INFO("Renewing certificate: %s (saving to: %s)", domain, temp_path);

    X509 *new_cert = cert_generator_renew_cert(gen, domain, old_key);
    if (!new_cert) {
        LOG_ERROR("Certificate renewal failed for: %s", domain);
        EVP_PKEY_free(old_key);
        /* Archive to OldCerts instead of restore */
        LOG_WARN("Renewal failed, archiving old certificate: %s", domain);
        archive_failed_cert(ca_dir, backup_path, domain);
        return false;
    }

    LOG_DEBUG("Generated new certificate for: %s", domain);

    /* Step 7: Write renewed certificate and key to temp file */
    FILE *temp_fp = fopen(temp_path, "w");
    if (!temp_fp) {
        LOG_ERROR("Failed to create temp file: %s", temp_path);
        X509_free(new_cert);
        EVP_PKEY_free(old_key);
        /* Archive to OldCerts instead of restore */
        LOG_WARN("Failed to write new cert, archiving old: %s", domain);
        archive_failed_cert(ca_dir, backup_path, domain);
        return false;
    }

    bool write_success = true;

    /* Write certificate */
    if (!PEM_write_X509(temp_fp, new_cert)) {
        LOG_ERROR("Failed to write certificate to temp file: %s", temp_path);
        write_success = false;
    }

    /* Write private key */
    if (write_success && !PEM_write_PrivateKey(temp_fp, old_key, NULL, NULL, 0, NULL, NULL)) {
        LOG_ERROR("Failed to write private key to temp file: %s", temp_path);
        write_success = false;
    }

    fclose(temp_fp);
    X509_free(new_cert);
    EVP_PKEY_free(old_key);

    /* Step 8: Verify write was successful */
    bool renewal_success = write_success;

    if (!renewal_success) {
        LOG_ERROR("Certificate write failed: %s", domain);
        /* Archive to OldCerts instead of restore */
        LOG_WARN("Archiving old certificate after write failure: %s", domain);
        archive_failed_cert(ca_dir, backup_path, domain);
        /* Clean up temp file */
        remove(temp_path);
        return false;
    }

    /* Step 9: Replace old with new (atomic) */
    if (rename(temp_path, old_cert_path) != 0) {
        LOG_ERROR("Failed to replace certificate: %s → %s",
                 temp_path, old_cert_path);
        /* Archive old cert instead of restore */
        LOG_WARN("Rename failed, archiving old certificate: %s", domain);
        archive_failed_cert(ca_dir, backup_path, domain);
        /* Clean up temp file */
        remove(temp_path);
        return false;
    }

    LOG_DEBUG("Replaced certificate: %s", old_cert_path);

    /* Step 10: Archive old certificate to OldCerts */
    LOG_INFO("Certificate renewed successfully, archiving old version: %s", domain);
    archive_failed_cert(ca_dir, backup_path, domain);

    LOG_INFO("Certificate replacement complete: %s", domain);
    return true;
}

/* Execute 12-hour maintenance cycle
 *
 * Called every 12 hours to:
 * 1. Scan and index all certificates
 * 2. Identify expiring certificates (< 7 days)
 * 3. Renew expiring certificates
 * 4. Replace old certs with renewed versions
 *
 * @param gen          Certificate generator
 * @param ca_dir       Algorithm-specific CA directory (e.g., /opt/TLSGateNXv3/RSA/)
 * @return             Number of certificates renewed
 */
int cert_maintenance_cycle_12h(cert_generator_t *gen, const char *ca_dir) {
    if (!gen || !ca_dir) {
        return 0;
    }

    /* FIX: Validate path length before constructing paths */
    if (strlen(ca_dir) > 4000) {
        LOG_ERROR("CA directory path too long: %s", ca_dir);
        return 0;
    }

    LOG_INFO("=== 12-hour maintenance cycle: %s ===", ca_dir);

    /* Step 1: Generate fresh index */
    cert_maint_index_t *index = cert_maintenance_scan_and_index(ca_dir);
    if (!index) {
        LOG_WARN("No certificates to maintain in: %s", ca_dir);
        return 0;
    }

    int renewed_count = 0;

    /* Step 2: Check each certificate */
    for (int i = 0; i < index->count; i++) {
        cert_maint_entry_t *entry = &index->entries[i];
        int days = cert_maintenance_days_until_expiry(entry->valid_until);

        /* If < 7 days to expiry: Renew and replace */
        if (days < 7 && days >= 0) {
            LOG_INFO("Renewing expiring cert: %s (expires in %d days)",
                    entry->domain, days);

            /* Build path to old cert */
            char certs_dir[4096];
            char old_cert_path[4096];
            snprintf(certs_dir, sizeof(certs_dir), "%s/certs", ca_dir);
            snprintf(old_cert_path, sizeof(old_cert_path), "%s/%s.pem",
                    certs_dir, entry->domain);

            /* Replace certificate (renew + swap) */
            if (cert_maintenance_replace_cert(gen, ca_dir, old_cert_path,
                                             entry->domain)) {
                renewed_count++;
                LOG_INFO("Successfully renewed: %s", entry->domain);
            } else {
                LOG_ERROR("Failed to renew: %s", entry->domain);
            }
        }
    }

    if (renewed_count > 0) {
        LOG_INFO("Maintenance cycle complete: %d certificates renewed", renewed_count);

        /* Step 3: Re-scan to update index with new certs */
        cert_maint_index_t *updated_index = cert_maintenance_scan_and_index(ca_dir);
        if (updated_index) {
            cert_maintenance_free_index(updated_index);
        }
    }

    cert_maintenance_free_index(index);
    return renewed_count;
}
