/* TLS-Gate NX - Second-Level TLD Management
 * Copyright (C) 2025 Torsten Jahnke
 *
 * Manages 2nd-level TLDs (e.g., co.uk, com.au, org.br) for wildcard
 * certificate generation logic.
 *
 * Features:
 * - Load from external file (e.g., /etc/tlsgateNG/second-level-tlds.dat)
 * - O(1) hash-based lookup for fast domain classification
 * - Automatic reload support (caller handles file monitoring)
 */

#ifndef TLSGATENG_SECOND_LEVEL_TLDS_H
#define TLSGATENG_SECOND_LEVEL_TLDS_H

#include <stdbool.h>
#include <stddef.h>

/* Opaque TLD set handle */
typedef struct tld_set tld_set_t;

/* Lifecycle */

/* Create empty TLD set
 * @param initial_capacity  Estimated number of TLDs (for hash sizing)
 * @return                  TLD set handle, or NULL on error
 */
tld_set_t* tld_set_create(size_t initial_capacity);

/* Destroy TLD set and free all resources
 * @param set  TLD set handle
 */
void tld_set_destroy(tld_set_t *set);

/* Load TLDs from file
 *
 * File format: One TLD per line, with or without leading dot
 * Examples:
 *   co.uk
 *   .com.au
 *   org.br
 *
 * Empty lines and lines starting with # are ignored.
 *
 * @param set       TLD set handle
 * @param filepath  Path to TLD file
 * @return          Number of TLDs loaded, or -1 on error
 */
int tld_set_load_from_file(tld_set_t *set, const char *filepath);

/* Load TLDs from SHM data buffer (used with Poolgen)
 *
 * Data format: Same as file - newline-separated TLDs
 * This is used by Workers to load TLDs from shared memory
 * instead of reading the file directly.
 *
 * @param set       TLD set handle
 * @param data      Pointer to TLD data (newline-separated)
 * @param data_len  Length of data in bytes
 * @return          Number of TLDs loaded, or -1 on error
 */
int tld_set_load_from_shm(tld_set_t *set, const char *data, int data_len);

/* Add single TLD to set
 * @param set  TLD set handle
 * @param tld  TLD string (e.g., "co.uk" or ".co.uk")
 * @return     true on success, false on error
 */
bool tld_set_add(tld_set_t *set, const char *tld);

/* Lookup */

/* Check if a TLD is a 2nd-level TLD
 *
 * @param set  TLD set handle
 * @param tld  TLD string to check (e.g., "co.uk" or ".co.uk")
 * @return     true if TLD is in set, false otherwise
 */
bool tld_set_contains(const tld_set_t *set, const char *tld);

/* Extract TLD from domain and check if it's 2nd-level
 *
 * Example:
 *   example.co.uk → extracts "co.uk" → returns true (if in set)
 *   www.example.com → extracts "com" → returns false
 *
 * @param set     TLD set handle
 * @param domain  Full domain name
 * @return        true if domain has a 2nd-level TLD, false otherwise
 */
bool tld_set_is_second_level_domain(const tld_set_t *set, const char *domain);

/* Statistics */

/* Get number of TLDs in set
 * @param set  TLD set handle
 * @return     Number of TLDs loaded
 */
size_t tld_set_count(const tld_set_t *set);

#endif /* TLSGATENG_SECOND_LEVEL_TLDS_H */
