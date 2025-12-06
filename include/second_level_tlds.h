/*
 * second_level_tlds.h - 2nd-Level TLD Management for Wildcard Certificates
 *
 * Manages 2nd-level TLDs (e.g., co.uk, com.au, blogspot.com, github.io)
 * for correct wildcard certificate generation.
 *
 * Without this:
 *   mysite.github.io → *.github.io (WRONG - too broad!)
 *
 * With this:
 *   mysite.github.io → *.mysite.github.io (CORRECT)
 *
 * Features:
 * - Load from external file (e.g., /var/cache/pixelserv/second-level-tlds.conf)
 * - O(1) hash-based lookup for fast domain classification
 * - Handles 10,000+ entries efficiently
 */

#ifndef SECOND_LEVEL_TLDS_H
#define SECOND_LEVEL_TLDS_H

#include <stdbool.h>
#include <stddef.h>

/* Opaque TLD set handle */
typedef struct tld_set tld_set_t;

/* ========== Lifecycle ========== */

/**
 * Create empty TLD set
 * @return TLD set handle, or NULL on error
 */
tld_set_t* tld_set_create(void);

/**
 * Destroy TLD set and free all resources
 * @param set TLD set handle (NULL-safe)
 */
void tld_set_destroy(tld_set_t *set);

/**
 * Load TLDs from file
 *
 * File format: One TLD per line, with leading dot
 * Examples:
 *   .co.uk
 *   .com.au
 *   .blogspot.com
 *   .github.io
 *
 * Processing:
 *   1. Remove leading dot
 *   2. Only keep entries that still contain a dot (true 2nd-level TLDs)
 *   3. Empty lines and lines starting with # are ignored
 *
 * @param set      TLD set handle
 * @param filepath Path to TLD file
 * @return         Number of TLDs loaded, or -1 on error
 */
int tld_set_load_from_file(tld_set_t *set, const char *filepath);

/* ========== Lookup ========== */

/**
 * Check if a suffix is a 2nd-level TLD
 *
 * @param set TLD set handle
 * @param tld TLD string to check (e.g., "co.uk" or ".co.uk")
 * @return    true if TLD is in set, false otherwise
 */
bool tld_set_contains(const tld_set_t *set, const char *tld);

/**
 * Extract and check if domain's suffix is a 2nd-level TLD
 *
 * Example:
 *   www.example.co.uk → extracts "co.uk" → returns true
 *   www.example.com   → extracts "com" → returns false
 *   mysite.github.io  → extracts "github.io" → returns true
 *
 * @param set    TLD set handle
 * @param domain Full domain name
 * @return       true if domain has a 2nd-level TLD suffix
 */
bool tld_set_is_second_level(const tld_set_t *set, const char *domain);

/* ========== Statistics ========== */

/**
 * Get number of TLDs in set
 * @param set TLD set handle
 * @return    Number of TLDs loaded
 */
size_t tld_set_count(const tld_set_t *set);

#endif /* SECOND_LEVEL_TLDS_H */
