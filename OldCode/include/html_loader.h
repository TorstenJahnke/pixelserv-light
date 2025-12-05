/* HTML Loader - Runtime loading with fallback to compiled-in HTML
 *
 * Supports both:
 * 1. Runtime loading from file (from config default_html=/path/to/file)
 * 2. Fallback to compiled-in HTML (from html_index.h)
 *
 * This allows changing HTML without recompiling!
 */

#ifndef HTML_LOADER_H
#define HTML_LOADER_H

#include <stdint.h>
#include <stddef.h>

/* HTML content holder */
typedef struct {
    unsigned char *data;      /* HTML content (may be from file or compiled-in) */
    size_t length;            /* Length in bytes (excluding null terminator) */
    int is_from_file;         /* 1 if loaded from file, 0 if compiled-in */
    char source_path[4096];   /* Where it came from (filename or "compiled-in") */
} html_content_t;

/* Load HTML from config path or fallback to compiled-in
 *
 * Parameters:
 *   html_path - Path from config (can be NULL or empty for fallback)
 *
 * Returns:
 *   Pointer to html_content_t on success
 *   NULL on error (but should never fail - always has fallback)
 *
 * Notes:
 *   - Allocates memory that must be freed with html_content_free()
 *   - Always succeeds (worst case: uses compiled-in fallback)
 *   - Thread-safe for reading, but not for concurrent initialization
 */
html_content_t* html_content_load(const char *html_path);

/* Free HTML content (if allocated from file)
 * Safe to call on NULL pointers
 */
void html_content_free(html_content_t *html);

/* Set globally cached HTML (pre-loaded before privilege drop)
 *
 * Parameters:
 *   html - Pointer to pre-loaded html_content_t (or NULL to clear cache)
 *
 * Notes:
 *   - Call this ONCE after loading HTML but BEFORE dropping privileges
 *   - After setting, html_content_load() will return this cached version
 *   - Ownership transferred to cache - do NOT free externally
 *   - Thread-safe for reading after initial set
 */
void html_content_set_cache(html_content_t *html);

/* Get globally cached HTML (if pre-loaded)
 *
 * Returns:
 *   Pointer to cached html_content_t if set
 *   NULL if cache not set (normal operation with per-request loading)
 */
html_content_t* html_content_get_cache(void);

/* ========== Multi-Variant HTML Caching (Anti-Detection) ========== */
/* 100 pre-rendered HTML variants with different timestamps/padding
 * Each request gets a different variant → defeats pattern matching
 */

#define HTML_VARIANT_COUNT 100

/* Multi-variant cache holder */
typedef struct {
    html_content_t *variants[HTML_VARIANT_COUNT];  /* Array of variants */
    int variant_count;                             /* Actual count (≤ 100) */
    int last_variant_index;                        /* For round-robin selection */
} html_variant_cache_t;

/* Create variant cache with N pre-rendered versions
 *
 * Parameters:
 *   html_path - Path to original HTML file
 *   variant_count - Number of variants to generate (1-100)
 *
 * Returns:
 *   Pointer to html_variant_cache_t with pre-rendered variants
 *   Each variant has:
 *   - Different timestamp in HTML comment
 *   - Different padding (spaces/tabs)
 *   - Different comment positions
 *   - Size variation: 10-50 bytes different
 *
 * Notes:
 *   - Call BEFORE dropping privileges (needs file access)
 *   - Generates all variants in ~500-800ms (1GB RAM)
 *   - Must be freed with html_variant_cache_free()
 */
html_variant_cache_t* html_variant_cache_create(const char *html_path, int variant_count);

/* Get next variant (round-robin)
 *
 * Returns next variant from cache, cycling through all variants
 * Thread-safe for reading (uses atomic increment internally)
 */
html_content_t* html_variant_cache_get_next(html_variant_cache_t *cache);

/* Free variant cache
 * Safe to call on NULL pointers
 */
void html_variant_cache_free(html_variant_cache_t *cache);

/* Set globally cached variant cache
 * Call after html_variant_cache_create() but BEFORE drop_privileges()
 */
void html_variant_cache_set(html_variant_cache_t *cache);

/* Get globally cached variant cache
 */
html_variant_cache_t* html_variant_cache_get(void);

#endif /* HTML_LOADER_H */
