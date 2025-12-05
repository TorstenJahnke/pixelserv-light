/* TLS-Gate NX - Certificate Maintenance
 * Copyright (C) 2025 Torsten Jahnke
 *
 * Daily maintenance tasks:
 * - Generate certificate index (domain|valid-until)
 * - Auto-renew certificates expiring within 7 days
 * - Cleanup expired certificates
 */

#ifndef TLSGATENG_CERT_MAINTENANCE_H
#define TLSGATENG_CERT_MAINTENANCE_H

#include "cert_generator.h"
#include <time.h>
#include <stdbool.h>

typedef struct {
    char domain[256];           /* Domain name */
    time_t valid_until;         /* Certificate expiration time */
    char algorithm[16];         /* RSA/ECDSA/SM2 */
    bool needs_renewal;         /* true if < 7 days until expiry */
} cert_maint_entry_t;

typedef struct {
    cert_maint_entry_t *entries;
    int count;
    char base_dir[4096];
    char ca_dir[4096];          /* e.g., RSA/, ECDSA/, SM2/ */
} cert_maint_index_t;

/* Scan certificate directory and generate index
 *
 * Scans all .pem/.crt files in ca_dir/certs/
 * Extracts domain and valid-until from each certificate
 * Writes .index file for monitoring
 *
 * @param ca_dir       Algorithm-specific CA directory (e.g., /opt/TLSGateNXv3/RSA/)
 * @return             Parsed index on success, NULL on failure
 *
 * Index format:
 *   domain.com|2025-11-20|RSA|0 (days_until_expiry=0 means expired)
 *   api.example.com|2025-12-15|RSA|27
 */
cert_maint_index_t* cert_maintenance_scan_and_index(const char *ca_dir);

/* Check if certificate needs renewal (< 7 days until expiry)
 *
 * @param entry        Index entry to check
 * @return             true if needs renewal, false otherwise
 */
bool cert_maintenance_needs_renewal(const cert_maint_entry_t *entry);

/* Renew all certificates expiring within 7 days
 *
 * Reads index, identifies certs with < 7 days left
 * Triggers renewal for each expired certificate
 *
 * @param gen          Certificate generator
 * @param ca_dir       Algorithm-specific CA directory
 * @return             Number of certificates renewed
 */
int cert_maintenance_renew_expiring(cert_generator_t *gen, const char *ca_dir);

/* Free index structure */
void cert_maintenance_free_index(cert_maint_index_t *index);

/* Get days until certificate expiration
 *
 * @param valid_until  Certificate expiration timestamp
 * @return             Days remaining (negative = expired)
 */
int cert_maintenance_days_until_expiry(time_t valid_until);

/* Replace old certificate with renewed version
 *
 * Atomic operation:
 * 1. Backup old cert to .old
 * 2. Generate renewed cert to .tmp
 * 3. Verify new cert is valid
 * 4. Swap: move .tmp to original location
 * 5. Cleanup: remove .old
 *
 * If any step fails: Restore from backup
 *
 * @param gen             Certificate generator
 * @param ca_dir          Algorithm-specific CA directory
 * @param old_cert_path   Path to certificate file to renew
 * @param domain          Domain name for renewal
 * @return                true if successful, false otherwise
 */
bool cert_maintenance_replace_cert(cert_generator_t *gen,
                                  const char *ca_dir,
                                  const char *old_cert_path,
                                  const char *domain);

/* Execute 12-hour maintenance cycle
 *
 * Scheduled task (call every 12 hours from main loop):
 *
 * 1. Scan and index all certificates in ca_dir/certs/
 * 2. Identify certificates expiring within 7 days
 * 3. For each expiring cert:
 *    - Generate renewed certificate
 *    - Atomically replace old with new
 *    - Update certificate index
 * 4. Re-scan to generate updated index
 *
 * Usage in main loop:
 *   if (time_since_last_maintenance >= 12 * 3600) {
 *     cert_maintenance_cycle_12h(gen, "/opt/TLSGateNXv3/RSA/");
 *     cert_maintenance_cycle_12h(gen, "/opt/TLSGateNXv3/ECDSA/");
 *     cert_maintenance_cycle_12h(gen, "/opt/TLSGateNXv3/SM2/");
 *     last_maintenance = now();
 *   }
 *
 * @param gen     Certificate generator
 * @param ca_dir  Algorithm-specific CA directory
 * @return        Number of certificates renewed
 */
int cert_maintenance_cycle_12h(cert_generator_t *gen, const char *ca_dir);

#endif /* TLSGATENG_CERT_MAINTENANCE_H */
