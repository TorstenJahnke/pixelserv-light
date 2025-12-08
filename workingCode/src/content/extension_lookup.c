/* extension_lookup.c */
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "content/extension_lookup.h"

/* Use existing extension_hash_table.h - DO NOT REPLACE */
#include "content/extension_hash_table.h"

/* Global state */
static int extension_system_initialized = 0;

/* Initialize extension lookup system */
void extension_lookup_init(void) {
    if (extension_system_initialized) {
        return;
    }
    
    /* extension_hash_table.h is already pre-computed, no runtime init needed */
    extension_system_initialized = 1;
}

/* Cleanup extension lookup system */
void extension_lookup_cleanup(void) {
    /* Static table, no cleanup needed */
    extension_system_initialized = 0;
}

/* Get extension entry using existing ultra-fast lookup */
const extension_entry_t* extension_lookup_get(const char *extension) {
    if (!extension_system_initialized || !extension || *extension == '\0') {
        return NULL;
    }
    
    /* Use existing ultra-fast binary search from extension_hash_table.h */
    return lookup_extension(extension);
}

/* Convert to pixelserv-tls response enum - KEEP EXISTING ICO HANDLING */
response_enum extension_get_response_type(const char *extension) {
    if (!extension || *extension == '\0') {
        return SEND_NO_EXT;
    }
    
    /* Use existing lookup first */
    const extension_entry_t *entry = lookup_extension(extension);
    if (entry) {
        /* Map to pixelserv-tls response types */
        switch (entry->response_type) {
            case RESP_BINARY_GIF: return SEND_GIF;
            case RESP_BINARY_PNG: return SEND_PNG;
            case RESP_BINARY_JPG: return SEND_JPG;
            case RESP_BINARY_ICO: return SEND_ICO;  /* KEEP EXISTING ICO HANDLING */
            case RESP_BINARY_SWF: return SEND_SWF;
            case RESP_SCRIPT_HTML: return SEND_HTML;
            case RESP_SCRIPT_JS: return SEND_JS;
            case RESP_STYLE_CSS: return SEND_CSS;
            case RESP_DATA_JSON: return SEND_JSON;
            case RESP_DATA_XML: return SEND_XML;
            case RESP_MEDIA_VIDEO: return SEND_VIDEO;
            case RESP_MEDIA_AUDIO: return SEND_AUDIO;
            case RESP_DOCUMENT_PDF: return SEND_PDF;
            case RESP_TEXT_PLAIN: return SEND_TXT;
            default: return SEND_UNK_EXT;
        }
    }
    
    /* Fallback - unknown extension */
    return SEND_UNK_EXT;
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
