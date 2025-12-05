/* extension_lookup.c */
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdlib.h>
#include <string.h>
#include <stdatomic.h>
#include <ctype.h>
#include "extension_lookup.h"

/* Use existing extension_hash_table.h - DO NOT REPLACE */
#include "extension_hash_table.h"

/* THREAD SAFETY FIX: Use atomic_int to prevent double-checked locking bug
 * Without atomics, multiple threads could see initialized=0 simultaneously
 * and call extension_lookup_init() multiple times, causing race conditions */
static atomic_int extension_system_initialized = 0;

/* Initialize extension lookup system */
void extension_lookup_init(void) {
    /* Use atomic compare-exchange to ensure only ONE thread initializes */
    int expected = 0;
    if (!atomic_compare_exchange_strong_explicit(&extension_system_initialized,
                                                 &expected,
                                                 1,
                                                 memory_order_acq_rel,
                                                 memory_order_acquire)) {
        /* Another thread already initialized - nothing to do */
        return;
    }

    /* extension_hash_table.h is already pre-computed, no runtime init needed */
    /* We got here because we successfully CAS'd 0→1, so we're the only initializer */
}

/* Cleanup extension lookup system */
void extension_lookup_cleanup(void) {
    /* Static table, no cleanup needed */
    atomic_store_explicit(&extension_system_initialized, 0, memory_order_release);
}

/* Get extension entry using ultra-fast binary search O(log n) */
const extension_entry_t* extension_lookup_get(const char *extension) {
    if (!atomic_load_explicit(&extension_system_initialized, memory_order_acquire) ||
        !extension || *extension == '\0') {
        return NULL;
    }

    /* Use binary search - hash table has correct FNV-1a values */
    return lookup_extension(extension);
}

/* Check if extension needs content randomization for AdBlock prevention */
int extension_needs_randomization(const char *extension) {
    const extension_entry_t *entry = lookup_extension(extension);
    if (!entry) {
        return 0;
    }
    
    /* High randomization for script/style content (AdBlock targets) */
    return (entry->response_type == RESP_SCRIPT_JS || 
            entry->response_type == RESP_STYLE_CSS ||
            entry->response_type == RESP_SCRIPT_HTML ||
            entry->response_type == RESP_DATA_JSON ||
            entry->response_type == RESP_DATA_XML);
}

/* Get cache time for extension */
int extension_get_cache_time(const char *extension) {
    const extension_entry_t *entry = lookup_extension(extension);
    if (!entry) {
        return 3600;  /* Default 1 hour */
    }
    
    /* Cache times based on content type */
    switch (entry->response_type) {
        case RESP_BINARY_GIF:
        case RESP_BINARY_PNG:
        case RESP_BINARY_JPG:
        case RESP_BINARY_ICO:  /* ICO gets same cache time */
        case RESP_BINARY_SWF:
        case RESP_MEDIA_VIDEO:
        case RESP_MEDIA_AUDIO:
            return 86400;  /* 24 hours for media */
            
        case RESP_SCRIPT_JS:
        case RESP_STYLE_CSS:
        case RESP_SCRIPT_HTML:
            return 3600;   /* 1 hour for dynamic content */
            
        case RESP_DATA_JSON:
        case RESP_DATA_XML:
            return 300;    /* 5 minutes for data */
            
        case RESP_DOCUMENT_PDF:
        case RESP_TEXT_PLAIN:
        default:
            return 3600;   /* 1 hour default */
    }
}

/* Get CSP policy type for extension */
csp_policy_type_t extension_get_csp_policy(const char *extension) {
    const extension_entry_t *entry = lookup_extension(extension);
    if (!entry) {
        return CSP_NONE;
    }
    
    return entry->csp_policy;
}

/* Get content type for extension */
const char* extension_get_content_type(const char *extension) {
    const extension_entry_t *entry = lookup_extension(extension);
    if (!entry) {
        return "text/html; charset=utf-8";  /* Default */
    }
    
    return entry->content_type;
}
