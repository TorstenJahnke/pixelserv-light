/* HTML Loader Implementation
 *
 * Loads HTML from runtime file or uses compiled-in fallback
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <time.h>
#include "../include/html_loader.h"
#include "logger.h"

/* Compiled-in HTML (defined in html_index.h, included by response.c) */
extern unsigned char index_html[];
extern unsigned int index_html_len;

/* Global cache for pre-loaded HTML (set before privilege drop) */
static html_content_t *g_html_cache = NULL;

html_content_t* html_content_get_cache(void) {
    return g_html_cache;
}

void html_content_set_cache(html_content_t *html) {
    g_html_cache = html;
}

html_content_t* html_content_load(const char *html_path) {
    /* If HTML was pre-loaded before privilege drop, return cached version */
    if (g_html_cache) {
        return g_html_cache;
    }

    html_content_t *html = calloc(1, sizeof(html_content_t));
    if (!html) {
        log_error("Failed to allocate html_content_t");
        return NULL;
    }

    /* CRITICAL: If a path is defined, it MUST exist and be readable!
     * This prevents misconfiguration - admin must explicitly set a valid path.
     */
    if (html_path && html_path[0] != '\0') {
        FILE *fp = fopen(html_path, "rb");

        /* If path is defined but cannot be opened → FATAL ERROR */
        if (!fp) {
            log_error("FATAL: HTML file configured but NOT FOUND: %s", html_path);
            log_error("       This is a configuration error - server cannot start!");
            log_error("       Either:");
            log_error("         1. Remove/comment 'default_html=' from config to use compiled-in HTML");
            log_error("         2. Create the HTML binary file at: %s", html_path);
            log_error("          Use: python3 tools/html2bin.py config-files/index.html %s", html_path);
            free(html);
            return NULL;  /* Caller should check for NULL and exit */
        }

        /* Get file size */
        fseek(fp, 0, SEEK_END);
        long file_size = ftell(fp);
        fseek(fp, 0, SEEK_SET);

        /* Validate file size */
        if (file_size <= 0) {
            log_error("FATAL: HTML file is empty or invalid: %s (size: %ld bytes)", html_path, file_size);
            fclose(fp);
            free(html);
            return NULL;
        }

        if (file_size >= 10 * 1024 * 1024) {  /* Limit to 10MB */
            log_error("FATAL: HTML file is too large: %s (%ld bytes, max 10MB)", html_path, file_size);
            fclose(fp);
            free(html);
            return NULL;
        }

        /* Try to read the file */
        unsigned char *file_data = malloc(file_size);
        if (!file_data) {
            log_error("FATAL: Cannot allocate memory for HTML file: %s (%ld bytes)", html_path, file_size);
            fclose(fp);
            free(html);
            return NULL;
        }

        size_t bytes_read = fread(file_data, 1, file_size, fp);
        fclose(fp);

        if (bytes_read != (size_t)file_size) {
            log_error("FATAL: Failed to read complete HTML file: %s (read %zu/%ld bytes)",
                      html_path, bytes_read, file_size);
            free(file_data);
            free(html);
            return NULL;
        }

        /* Success - file loaded */
        html->data = file_data;
        html->length = file_size;
        html->is_from_file = 1;
        strncpy(html->source_path, html_path, sizeof(html->source_path) - 1);
        html->source_path[sizeof(html->source_path) - 1] = '\0';

        log_info("✓ Loaded HTML from file: %s (%zu bytes)", html_path, html->length);
        return html;
    }

    /* No path defined → use compiled-in HTML (safe fallback) */
    log_info("✓ Using compiled-in fallback HTML (%u bytes)", index_html_len);
    html->data = (unsigned char *)index_html;
    html->length = index_html_len;
    html->is_from_file = 0;
    strncpy(html->source_path, "compiled-in", sizeof(html->source_path) - 1);
    html->source_path[sizeof(html->source_path) - 1] = '\0';

    return html;
}

void html_content_free(html_content_t *html) {
    if (!html) return;

    /* Only free if loaded from file */
    if (html->is_from_file && html->data) {
        free(html->data);
    }

    free(html);
}

/* ========== Multi-Variant HTML Caching (Anti-Detection) ========== */

/* Global variant cache */
static html_variant_cache_t *g_variant_cache = NULL;

html_variant_cache_t* html_variant_cache_get(void) {
    return g_variant_cache;
}

void html_variant_cache_set(html_variant_cache_t *cache) {
    g_variant_cache = cache;
}

/* Generate single variant with modifications
 *
 * Strategy:
 * - Add timestamp comment at different positions
 * - Add padding (spaces/tabs) based on variant number
 * - Vary comment positions to create size variation
 */
static html_content_t* html_variant_generate(const unsigned char *original_data,
                                              size_t original_size,
                                              int variant_idx) {
    html_content_t *variant = calloc(1, sizeof(html_content_t));
    if (!variant) return NULL;

    /* Generate timestamp for this variant */
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    char timestamp[64];
    snprintf(timestamp, sizeof(timestamp),
             "<!-- Generated: %04d-%02d-%02d %02d:%02d:%02d.%03d -->",
             tm_info->tm_year + 1900, tm_info->tm_mon + 1, tm_info->tm_mday,
             tm_info->tm_hour, tm_info->tm_min, tm_info->tm_sec, variant_idx * 10);

    /* Calculate padding based on variant */
    int padding_size = 10 + (variant_idx % 40);  /* 10-50 bytes variation */
    char *padding = malloc(padding_size + 1);
    if (!padding) {
        free(variant);
        return NULL;
    }

    /* Fill padding with spaces/tabs alternating */
    for (int i = 0; i < padding_size; i++) {
        padding[i] = (i % 2 == 0) ? ' ' : '\t';
    }
    padding[padding_size] = '\0';

    /* Allocate buffer for variant (original + timestamp + padding) */
    size_t variant_size = original_size + strlen(timestamp) + padding_size + 10;
    unsigned char *variant_data = malloc(variant_size);
    if (!variant_data) {
        free(padding);
        free(variant);
        return NULL;
    }

    /* Build variant:
     * - Copy original
     * - Add timestamp comment at position based on variant_idx
     * - Add padding spread throughout
     */
    size_t offset = 0;

    /* Insert first part of original */
    size_t split_pos = original_size / 3 + (variant_idx % (original_size / 4));
    if (split_pos > original_size) split_pos = original_size / 2;

    memcpy(variant_data, original_data, split_pos);
    offset = split_pos;

    /* Add timestamp comment */
    memcpy(variant_data + offset, timestamp, strlen(timestamp));
    offset += strlen(timestamp);

    /* Add padding */
    memcpy(variant_data + offset, padding, padding_size);
    offset += padding_size;

    /* Add newline */
    variant_data[offset++] = '\n';

    /* Copy rest of original */
    memcpy(variant_data + offset, original_data + split_pos, original_size - split_pos);
    offset += original_size - split_pos;

    /* Set variant fields */
    variant->data = variant_data;
    variant->length = offset;
    variant->is_from_file = 1;  /* Mark as allocated */
    snprintf(variant->source_path, sizeof(variant->source_path),
             "variant-%d", variant_idx);

    free(padding);
    return variant;
}

/* Create variant cache with N pre-rendered versions */
html_variant_cache_t* html_variant_cache_create(const char *html_path, int variant_count) {
    if (!html_path || !html_path[0]) {
        log_warn("HTML variant cache: no path configured");
        return NULL;
    }

    if (variant_count < 1 || variant_count > HTML_VARIANT_COUNT) {
        log_error("Invalid variant count: %d (must be 1-%d)", variant_count, HTML_VARIANT_COUNT);
        return NULL;
    }

    /* Load original HTML */
    html_content_t *original = html_content_load(html_path);
    if (!original) {
        log_error("Failed to load HTML for variant generation: %s", html_path);
        return NULL;
    }

    /* Create variant cache */
    html_variant_cache_t *cache = calloc(1, sizeof(html_variant_cache_t));
    if (!cache) {
        log_error("Failed to allocate variant cache");
        html_content_free(original);
        return NULL;
    }

    printf("Generating %d HTML variants (anti-detection)...\n", variant_count);

    /* Generate all variants */
    for (int i = 0; i < variant_count; i++) {
        cache->variants[i] = html_variant_generate(original->data, original->length, i);
        if (!cache->variants[i]) {
            log_error("Failed to generate variant %d", i);
            /* Free what we have so far */
            for (int j = 0; j < i; j++) {
                if (cache->variants[j]) {
                    html_content_free(cache->variants[j]);
                }
            }
            free(cache);
            html_content_free(original);
            return NULL;
        }

        if ((i + 1) % 10 == 0) {
            printf("  ✓ Generated %d/%d variants\n", i + 1, variant_count);
        }
    }

    cache->variant_count = variant_count;
    cache->last_variant_index = 0;

    printf("✓ All %d variants generated successfully (%zu bytes each)\n",
           variant_count, cache->variants[0]->length);

    /* Don't free original - variants reference its structure */
    html_content_free(original);

    return cache;
}

/* Get next variant (round-robin) */
html_content_t* html_variant_cache_get_next(html_variant_cache_t *cache) {
    if (!cache || cache->variant_count == 0) {
        return NULL;
    }

    /* Round-robin selection */
    int idx = cache->last_variant_index % cache->variant_count;
    cache->last_variant_index++;

    return cache->variants[idx];
}

/* Free variant cache */
void html_variant_cache_free(html_variant_cache_t *cache) {
    if (!cache) return;

    for (int i = 0; i < cache->variant_count; i++) {
        if (cache->variants[i]) {
            html_content_free(cache->variants[i]);
        }
    }

    free(cache);
}
