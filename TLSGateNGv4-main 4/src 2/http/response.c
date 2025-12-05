/*
 * response.c - HTTP Response Generation Implementation
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <strings.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>

#include "response.h"
#include "connection.h"
#include "anti_adblock.h"
#include "browser_detection.h"
#include "silent_blocker.h"
#include "reverse_proxy.h"
#include "../util/logger.h"

/* Real favicon.ico from OldCodeBase */
#include "favicon.h"

/* Ultra-fast 265+ extension MIME type system from OldCodeBase */
#include "extension_hash_table.h"

/* HTML template compiled into binary (SECURE!) */
#include "html_index.h"

/* HTML runtime loader */
#include "html_loader.h"

/* Configuration access */
#include "../config/config_file.h"
extern config_file_t *g_master_config;

/* ========== Utility Functions ========== */

/* Safe size addition - prevents integer overflow
 * Returns: sum if no overflow, SIZE_MAX on overflow
 */
static size_t safe_add_size(size_t a, size_t b) {
    if (a > SIZE_MAX - b) {
        return SIZE_MAX;  /* Overflow detected */
    }
    return a + b;
}

/* Get current time as formatted string for HTML templates
 * Format: "2025-11-08 14:23:45 UTC"
 * CRITICAL BUG FIX: gmtime() can return NULL on invalid time values
 * Must check before dereferencing! */
static void get_current_time(char *buf, size_t size) {
    time_t now = time(NULL);
    struct tm *tm_info = gmtime(&now);

    /* SAFETY CHECK: gmtime() can fail and return NULL */
    if (!tm_info || !buf || size < 25) {
        if (buf && size > 0) {
            strncpy(buf, "2025-01-01 00:00:00 UTC", size - 1);
            buf[size - 1] = '\0';
        }
        return;
    }

    strftime(buf, size, "%Y-%m-%d %H:%M:%S UTC", tm_info);
}

/* ========== Static Content ========== */

/* Minimal 1x1 ICO for other *.ico files (NOT favicon.ico!)
 * Using dynamic header generation to include all security neutralization
 * Note: This is kept for reference but will be generated dynamically
 */
static const char httpnull_ico_response[] =
  "HTTP/1.1 200 OK\r\n"
  "Content-type: image/x-icon\r\n"
  "Cache-Control: max-age=2592000\r\n"
  "Content-length: 70\r\n"
  "Connection: keep-alive\r\n"
  "Access-Control-Allow-Origin: *\r\n"
  "Access-Control-Allow-Methods: GET, POST, PUT, DELETE, PATCH, OPTIONS, HEAD, TRACE, CONNECT\r\n"
  "Access-Control-Allow-Headers: *\r\n"
  "Access-Control-Allow-Credentials: true\r\n"
  "Cross-Origin-Resource-Policy: cross-origin\r\n"
  "\r\n"
  "\x00\x00" // reserved 0
  "\x01\x00" // ico
  "\x01\x00" // 1 image
  "\x01\x01\x00" // 1 x 1 x >8bpp colour
  "\x00" // reserved 0
  "\x01\x00" // 1 colour plane
  "\x20\x00" // 32 bits per pixel
  "\x30\x00\x00\x00" // size 48 bytes
  "\x16\x00\x00\x00" // start of image 22 bytes in
  "\x28\x00\x00\x00" // size of DIB header 40 bytes
  "\x01\x00\x00\x00" // width
  "\x02\x00\x00\x00" // height
  "\x01\x00" // colour planes
  "\x20\x00" // bits per pixel
  "\x00\x00\x00\x00" // no compression
  "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
  "\x00\x00\x00\x00" // end of header
  "\x00\x00\x00\x00" // Colour table
  "\x00\x00\x00\x00" // XOR B G R
  "\x80\xF8\x9C\x41"; // AND

/* 1x1 transparent GIF */
static const unsigned char gif_1x1[] = {
    'G','I','F','8','9','a',
    0x01,0x00,0x01,0x00,
    0x80,0x00,0x00,
    0x01,0x01,0x01,
    0x00,0x00,0x00,
    0x21,0xf9,0x04,0x01,0x00,0x00,0x00,0x00,
    0x2c,0x00,0x00,0x00,0x00,0x01,0x00,0x01,0x00,0x00,
    0x02,0x01,0x44,0x00,0x3b
};

/* ========== MIME Type Lookup ========== */

const char* response_get_mime_type(const char *ext) {
    if (!ext || !*ext) {
        return "text/html; charset=utf-8";
    }

    /* Use ultra-fast O(log n) binary search - hash table has correct FNV-1a values */
    const extension_entry_t *entry = lookup_extension(ext);

    if (entry) {
        return entry->content_type;
    }

    /* Fallback for unknown extensions */
    return "application/octet-stream";
}

/* ========== Anti-AdBlock Randomization ========== */

/* Wrapper for polymorphic JS generation - uses anti_adblock 150+ variants */
size_t response_generate_random_js(char *buf, size_t size) {
    adblock_seed_t seeds = anti_adblock_generate_seeds("/", "", "");
    anti_adblock_generate_js_content(&seeds, buf, size);
    return strlen(buf);
}

/* Wrapper for polymorphic CSS generation - uses anti_adblock 150+ variants */
size_t response_generate_random_css(char *buf, size_t size) {
    adblock_seed_t seeds = anti_adblock_generate_seeds("/", "", "");
    anti_adblock_generate_css_content(&seeds, buf, size);
    return strlen(buf);
}

/* ========== HTTP Header Generation ========== */

/* Build HTTP response header with COMPLETE security neutralization + STEALTH
 * For DNS Sinkhole: Accept EVERYTHING, block NOTHING
 * With anti-detection: Randomized headers, server rotation, CF-RAY, ETag
 * Returns: header length, or -1 on error
 */
static int build_response_header_dynamic(char *header_buf, size_t header_size,
                                         const char *mime_type, size_t content_length,
                                         connection_t *conn) {
    if (!header_buf || header_size < 512) {
        LOG_ERROR("Invalid header buffer size: %zu", header_size);
        return -1;
    }

    /* Generate anti-adblock seeds from request data */
    adblock_seed_t seeds = anti_adblock_generate_seeds(
        conn->path,        /* Request path */
        conn->user_agent,  /* User-Agent header (extracted from HTTP request) */
        conn->remote_addr  /* Remote IP address (IPv4/IPv6) */
    );

    /* Generate dynamic headers (server rotation, CF-RAY, cache status, etc.) */
    dynamic_headers_t dyn_headers;
    anti_adblock_generate_headers(&seeds, &dyn_headers);

    /* SECURITY FIX: Prevent integer overflow when using len as offset
     * Ensure snprintf didn't truncate by checking return value
     * snprintf returns the number of characters that would have been written
     * If >= header_size, the output was truncated */
    int len = snprintf(header_buf, header_size,
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %zu\r\n"
        "Connection: keep-alive\r\n"
        "Cache-Control: public, max-age=3600\r\n"

        /* STEALTH: Dynamic server identification (rotates between 100+ servers) */
        "Server: %s\r\n"
        "X-Cache: %s\r\n"
        "X-Cache-Status: %s\r\n"
        "CF-RAY: %s\r\n"
        "Vary: %s\r\n",
        mime_type, content_length,
        dyn_headers.server_header,
        dyn_headers.cache_status,
        dyn_headers.cache_status,
        dyn_headers.cf_ray,
        dyn_headers.vary_header
    );

    /* Check if snprintf succeeded without truncation */
    if (len < 0 || (size_t)len >= header_size) {
        LOG_ERROR("Header buffer too small or snprintf failed: %d >= %zu", len, header_size);
        return -1;
    }

    /* Add ETag if generated (33%% probability) and buffer space available */
    if (dyn_headers.has_etag) {
        size_t remaining = header_size - (size_t)len;
        if (remaining > 100) {  /* Safe: ensure enough space for ETag + terminator */
            int etag_len = snprintf(header_buf + len, remaining,
                "ETag: %s\r\n", dyn_headers.etag);
            if (etag_len > 0 && (size_t)etag_len < remaining) {
                len += etag_len;
            }
        }
    }

    /* Add security neutralization headers */
    {
        size_t remaining = header_size - (size_t)len;
        /* Reserve 2 bytes for final \r\n */
        if (remaining > 1024 + 2) {
            int sec_len = snprintf(header_buf + len, remaining,
                /* CORS - Allow everything from everywhere */
                "Access-Control-Allow-Origin: *\r\n"
                "Access-Control-Allow-Methods: GET, POST, PUT, DELETE, PATCH, OPTIONS, HEAD, TRACE, CONNECT\r\n"
                "Access-Control-Allow-Headers: *\r\n"
                "Access-Control-Allow-Credentials: true\r\n"
                "Access-Control-Expose-Headers: *\r\n"
                "Access-Control-Max-Age: 86400\r\n"

                /* CSP - Allow all sources, inline scripts, eval */
                "Content-Security-Policy: default-src * 'unsafe-inline' 'unsafe-eval' data: blob: filesystem:; "
                "script-src * 'unsafe-inline' 'unsafe-eval'; style-src * 'unsafe-inline'; "
                "img-src * data: blob:; font-src * data:; connect-src * data: blob:; "
                "frame-src *; object-src *; media-src * data: blob:;\r\n"

                /* Disable all browser security features */
                "X-Content-Type-Options: nosniff\r\n"
                "X-Frame-Options: ALLOWALL\r\n"
                "X-XSS-Protection: 0\r\n"
                "Referrer-Policy: no-referrer\r\n"

                /* Modern security headers - neutralize */
                "Cross-Origin-Opener-Policy: unsafe-none\r\n"
                "Cross-Origin-Embedder-Policy: unsafe-none\r\n"
                "Cross-Origin-Resource-Policy: cross-origin\r\n"
                "Accept-Ranges: bytes\r\n"
                "\r\n"
            );

            if (sec_len > 0 && (size_t)sec_len < remaining) {
                len += sec_len;
            } else {
                /* Fallback: just add minimal closing headers
                 * SECURITY FIX: Use memcpy instead of strncat to avoid NULL terminator overflow
                 * strncat adds a NULL terminator which can overflow our buffer
                 * We handle the closing manually via memcpy + len increment */
                if (remaining >= 2) {
                    memcpy(header_buf + len, "\r\n", 2);
                    len += 2;
                }
            }
        } else {
            /* Buffer too small - just close with minimal header */
            if (remaining >= 2) {
                header_buf[len++] = '\r';
                header_buf[len++] = '\n';
            }
        }
    }

    return len;
}

/* ========== Response Generation Functions ========== */

/* Generate silent block response (204, 200, etc.)
 * Used by Silent Blocker pattern matching system
 */
int response_generate_silent_block(connection_t *conn, int status_code) {
    const char *status_text;
    const char *body = "";
    size_t body_len = 0;

    /* Map status code to status text */
    switch (status_code) {
        case 200: status_text = "OK"; break;
        case 204: status_text = "No Content"; break;
        case 301: status_text = "Moved Permanently"; break;
        case 302: status_text = "Found"; break;
        case 404: status_text = "Not Found"; break;
        default:  status_text = "OK"; status_code = 200; break;
    }

    /* For 200 OK, send empty body (no static signatures!) */
    if (status_code == 200) {
        body = "";
        body_len = 0;
    }

    /* Allocate response buffer */
    char *response = malloc(1024);
    if (!response) {
        return -1;
    }

    /* Build response header + body */
    int len = snprintf(response, 1024,
        "HTTP/1.1 %d %s\r\n"
        "Content-Type: text/plain; charset=utf-8\r\n"
        "Content-Length: %zu\r\n"
        "Connection: keep-alive\r\n"
        "Cache-Control: no-cache, no-store, must-revalidate\r\n"
        "\r\n"
        "%s",
        status_code, status_text, body_len, body);

    /* SECURITY FIX: Validate snprintf return value before use */
    if (len < 0 || len >= 1024) {
        LOG_ERROR("snprintf failed or response truncated (len=%d)", len);
        free(response);
        return -1;
    }

    conn->response_buf = response;
    conn->response_len = len;
    conn->response_is_static = 0;  /* Dynamically allocated, must free */

    return 0;
}

int response_generate_404(connection_t *conn) {
    /* Static 404 response - Content-Length MUST match body exactly!
     * Body: "<html><body><h1>404 Not Found</h1></body></html>" = 48 bytes
     * Verified via: printf '<html>...</html>' | wc -c
     */
    static const char response_404[] =
        "HTTP/1.1 404 Not Found\r\n"
        "Content-Type: text/html\r\n"
        "Content-Length: 48\r\n"
        "Connection: close\r\n"
        "\r\n"
        "<html><body><h1>404 Not Found</h1></body></html>";

    /* Compile-time assertion: verify Content-Length matches body */
    _Static_assert(sizeof("<html><body><h1>404 Not Found</h1></body></html>") - 1 == 48,
                   "404 response body length mismatch with Content-Length header");

    conn->response_buf = (char*)response_404;
    conn->response_len = sizeof(response_404) - 1;
    conn->response_is_static = 1;
    conn->close_after_write = 1;

    return 0;
}

int response_generate_204(connection_t *conn) {
    static const char response_204[] =
        "HTTP/1.1 204 No Content\r\n"
        "Content-Length: 0\r\n"
        "Connection: keep-alive\r\n"
        "Cache-Control: no-cache, no-store, must-revalidate\r\n"
        "\r\n";

    conn->response_buf = (char*)response_204;
    conn->response_len = sizeof(response_204) - 1;
    conn->response_is_static = 1;

    return 0;
}

int response_generate_index(connection_t *conn) {
    /* Load HTML from config if specified, otherwise empty response
     *
     * Priority:
     * 1. Runtime-loaded template (response_load_html_template_file)
     * 2. Variant cache (100 pre-rendered variants for anti-detection)
     * 3. Single cached version from config
     * 4. Empty response
     *
     * Each request gets different variant → defeats pattern matching
     */
    html_content_t *html = NULL;
    unsigned char *html_data = NULL;
    size_t html_len = 0;

    /* PRIORITY 1: Check if runtime template is loaded */
    const char *runtime_template = response_get_html_template();
    size_t runtime_len = response_get_html_template_size();

    if (runtime_template && runtime_len > 0) {
        /* Use runtime-loaded template */
        html_data = (unsigned char *)runtime_template;
        html_len = runtime_len;
    }
    /* PRIORITY 2-3: Check if external HTML is configured */
    else if (g_master_config && g_master_config->default_html_path[0] != '\0') {
        /* Try to get variant from cache first */
        html_variant_cache_t *variant_cache = html_variant_cache_get();
        if (variant_cache) {
            /* Get next variant (round-robin) - ANTI-DETECTION! */
            html = html_variant_cache_get_next(variant_cache);
        } else {
            /* Fall back to single cached version */
            html = html_content_load(g_master_config->default_html_path);
        }

        if (html) {
            html_data = html->data;
            html_len = html->length;
        }
    }
    /* PRIORITY 4: No template configured - empty response */

    /* Allocate buffer for dynamic content with timestamp substitution */
    size_t buf_size = safe_add_size(html_len + 256, 0);  /* +256 for timestamp */
    if (buf_size == SIZE_MAX) {
        return -1;
    }

    char *body_buf = malloc(buf_size);
    if (!body_buf) {
        return -1;
    }

    /* Generate body with timestamp substitution (if HTML exists) */
    int body_len = 0;
    if (html_data && html_len > 0) {
        /* Get current timestamp for %s substitution */
        char time_buf[64];
        get_current_time(time_buf, sizeof(time_buf));

        /* Use snprintf for timestamp substitution
         * If no %s in template, string is just copied as-is
         */
        body_len = snprintf(body_buf, buf_size, (const char *)html_data, time_buf);
        if (body_len < 0 || body_len >= (int)buf_size) {
            free(body_buf);
            return -1;  /* HTML too large or error */
        }
    } else {
        /* No external HTML configured - empty response */
        body_len = 0;
    }

    /* NOTE: Do NOT free html here!
     * If html is from variant cache, it's owned by html_loader
     * and should persist for all subsequent requests.
     * If html is NULL, there's nothing to free anyway.
     */

    /* Allocate buffer for header + body (with overflow check) */
    size_t total_size = safe_add_size(2048, body_len);
    if (total_size == SIZE_MAX) {
        free(body_buf);
        return -1;  /* Integer overflow detected */
    }
    char *full_response = malloc(total_size);
    if (!full_response) {
        free(body_buf);
        return -1;
    }

    /* Build header with dynamic server rotation */
    int header_len = build_response_header_dynamic(full_response, 2048,
                                          "text/html; charset=utf-8", body_len, conn);

    /* MEMORY LEAK FIX: Check if header generation failed */
    if (header_len < 0) {
        free(body_buf);
        free(full_response);
        return -1;
    }

    /* SECURITY FIX: Validate header_len and body_len fit in allocated buffer */
    if (header_len > 2048 || (size_t)body_len > (total_size - (size_t)header_len)) {
        LOG_ERROR("Index response too large: header=%d, body=%d, allocated=%zu",
                 header_len, body_len, total_size);
        free(body_buf);
        free(full_response);
        return -1;
    }

    /* Append body */
    memcpy(full_response + header_len, body_buf, body_len);
    free(body_buf);

    conn->response_buf = full_response;
    conn->response_len = header_len + body_len;
    conn->response_is_static = 0;  /* Dynamically allocated, must free */
    conn->skip_jitter = 1;         /* Skip timing jitter for index page (fast UX) */

    return 0;
}

int response_generate_favicon(connection_t *conn) {
    /* Use the real favicon.ico from OldCodeBase (9,462 bytes) */
    size_t buf_size = 2048 + favicon_ico_len;
    char *response = malloc(buf_size);
    if (!response) {
        return -1;
    }

    /* Build header with dynamic server rotation */
    int header_len = build_response_header_dynamic(response, 2048,
                                          "image/x-icon", favicon_ico_len, conn);

    /* MEMORY LEAK FIX: Check if header generation failed */
    if (header_len < 0) {
        free(response);
        return -1;
    }

    /* SECURITY FIX: Validate header_len and favicon_ico_len fit in allocated buffer
     * buf_size = 2048 + favicon_ico_len
     * We need: header_len + favicon_ico_len <= buf_size */
    if (header_len > 2048 || favicon_ico_len > (buf_size - (size_t)header_len)) {
        LOG_ERROR("Favicon response too large: header=%d, icon=%u, allocated=%zu",
                 header_len, favicon_ico_len, buf_size);
        free(response);
        return -1;
    }

    /* Append favicon data */
    memcpy(response + header_len, favicon_ico, favicon_ico_len);

    conn->response_buf = response;
    conn->response_len = header_len + favicon_ico_len;
    conn->response_is_static = 0;  /* Dynamically allocated, must free */
    conn->skip_jitter = 1;         /* Skip timing jitter for favicon (fast UX) */

    return 0;
}

int response_generate_for_extension(connection_t *conn, const char *ext) {
    if (!ext || !*ext) {
        return response_generate_index(conn);
    }

    const char *mime = response_get_mime_type(ext);

    /* JavaScript: CDN Library Simulator + Polymorphic anti-adblock */
    if (strcasecmp(ext, "js") == 0 || strcasecmp(ext, "mjs") == 0) {
        char *body_buf = malloc(8192);
        if (!body_buf) {
            return -1;
        }

        /* Check if this is a CDN library request (jQuery, Bootstrap, etc.) */
        if (is_cdn_library_request(conn->path)) {
            /* Generate CDN library stub to prevent website crashes! */
            generate_cdn_library_response(conn->path, body_buf, 8192);
        } else {
            /* Generate polymorphic JS with anti-adblock seeds */
            adblock_seed_t seeds = anti_adblock_generate_seeds(conn->path, "", "");
            anti_adblock_generate_js_content(&seeds, body_buf, 8192);
        }
        size_t body_len = strlen(body_buf);

        /* Allocate buffer for header + body (with overflow check) */
        size_t total_size = safe_add_size(4096, body_len);
        if (total_size == SIZE_MAX) {
            free(body_buf);
            return -1;  /* Integer overflow detected */
        }
        char *full_response = malloc(total_size);
        if (!full_response) {
            free(body_buf);
            return -1;
        }

        int header_len = build_response_header_dynamic(full_response, 4096, mime, body_len, conn);
        /* MEMORY LEAK FIX: Check if header generation failed */
        if (header_len < 0) {
            free(body_buf);
            free(full_response);
            return -1;
        }

        /* SECURITY FIX: Validate header_len is within allocated buffer and safe to use as offset */
        if (header_len > 4096 || body_len > (total_size - (size_t)header_len)) {
            LOG_ERROR("JS response too large: header=%d, body=%zu, total_allocated=%zu",
                     header_len, body_len, total_size);
            free(body_buf);
            free(full_response);
            return -1;
        }

        memcpy(full_response + header_len, body_buf, body_len);
        free(body_buf);

        conn->response_buf = full_response;
        conn->response_len = header_len + body_len;
        conn->response_is_static = 0;

        return 0;
    }

    /* CSS: CDN Library Simulator + Polymorphic anti-adblock */
    if (strcasecmp(ext, "css") == 0) {
        char *body_buf = malloc(8192);
        if (!body_buf) {
            return -1;
        }

        /* Check if this is a CDN library request (FontAwesome, Google Fonts, etc.) */
        if (is_cdn_library_request(conn->path)) {
            /* Generate CDN library stub to prevent website crashes! */
            generate_cdn_library_response(conn->path, body_buf, 8192);
        } else {
            /* Generate polymorphic CSS with anti-adblock seeds */
            adblock_seed_t seeds = anti_adblock_generate_seeds(conn->path, "", "");
            anti_adblock_generate_css_content(&seeds, body_buf, 8192);
        }
        size_t body_len = strlen(body_buf);

        /* Allocate buffer for header + body (with overflow check) */
        size_t total_size = safe_add_size(4096, body_len);
        if (total_size == SIZE_MAX) {
            free(body_buf);
            return -1;  /* Integer overflow detected */
        }
        char *full_response = malloc(total_size);
        if (!full_response) {
            free(body_buf);
            return -1;
        }

        int header_len = build_response_header_dynamic(full_response, 4096, mime, body_len, conn);
        /* MEMORY LEAK FIX: Check if header generation failed */
        if (header_len < 0) {
            free(body_buf);
            free(full_response);
            return -1;
        }

        /* SECURITY FIX: Validate header_len is within allocated buffer and safe to use as offset */
        if (header_len > 4096 || body_len > (total_size - (size_t)header_len)) {
            LOG_ERROR("CSS response too large: header=%d, body=%zu, total_allocated=%zu",
                     header_len, body_len, total_size);
            free(body_buf);
            free(full_response);
            return -1;
        }

        memcpy(full_response + header_len, body_buf, body_len);
        free(body_buf);

        conn->response_buf = full_response;
        conn->response_len = header_len + body_len;
        conn->response_is_static = 0;

        return 0;
    }

    /* Other .ico files (NOT /favicon.ico!) - use minimal 1x1 ICO */
    if (strcasecmp(ext, "ico") == 0) {
        conn->response_buf = (char*)httpnull_ico_response;
        conn->response_len = sizeof(httpnull_ico_response) - 1;
        conn->response_is_static = 1;
        return 0;
    }

    /* GIF: 1x1 transparent */
    if (strcasecmp(ext, "gif") == 0) {
        char *response = malloc(4096 + sizeof(gif_1x1));
        if (!response) {
            return -1;
        }

        int header_len = build_response_header_dynamic(response, 4096, mime, sizeof(gif_1x1), conn);
        /* MEMORY LEAK FIX: Check if header generation failed */
        if (header_len < 0) {
            free(response);
            return -1;
        }

        /* SECURITY FIX: Validate header_len fits in 4096-byte header space
         * and image data doesn't exceed allocated buffer */
        if (header_len > 4096 || sizeof(gif_1x1) > (4096 + sizeof(gif_1x1) - (size_t)header_len)) {
            LOG_ERROR("GIF response header too large: header=%d", header_len);
            free(response);
            return -1;
        }

        memcpy(response + header_len, gif_1x1, sizeof(gif_1x1));

        conn->response_buf = response;
        conn->response_len = header_len + sizeof(gif_1x1);
        conn->response_is_static = 0;

        return 0;
    }

    /* PNG/JPG/JPEG: Use 1x1 GIF with correct MIME */
    if (strcasecmp(ext, "png") == 0 ||
        strcasecmp(ext, "jpg") == 0 ||
        strcasecmp(ext, "jpeg") == 0) {
        char *response = malloc(4096 + sizeof(gif_1x1));
        if (!response) {
            return -1;
        }

        int header_len = build_response_header_dynamic(response, 4096, mime, sizeof(gif_1x1), conn);
        /* MEMORY LEAK FIX: Check if header generation failed */
        if (header_len < 0) {
            free(response);
            return -1;
        }

        /* SECURITY FIX: Validate header_len fits in 4096-byte header space
         * and image data doesn't exceed allocated buffer */
        if (header_len > 4096 || sizeof(gif_1x1) > (4096 + sizeof(gif_1x1) - (size_t)header_len)) {
            LOG_ERROR("Image response header too large: header=%d", header_len);
            free(response);
            return -1;
        }

        memcpy(response + header_len, gif_1x1, sizeof(gif_1x1));

        conn->response_buf = response;
        conn->response_len = header_len + sizeof(gif_1x1);
        conn->response_is_static = 0;

        return 0;
    }

    /* ========== UNIVERSAL SINKHOLE RESPONSES ========== */
    /* Generate appropriate success response for ANY content type */

    char *response = malloc(8192);  /* Increased for polymorphic content */
    if (!response) {
        return -1;
    }

    char *body_buf = NULL;
    const char *body = "";
    size_t body_len = 0;

    /* Generate anti-adblock seeds for polymorphic responses */
    adblock_seed_t seeds = anti_adblock_generate_seeds(
        conn->path, "", "");

    /* JSON responses (for APIs, tracking, analytics) - POLYMORPHIC */
    if (strcasecmp(ext, "json") == 0) {
        body_buf = malloc(4096);
        if (body_buf) {
            anti_adblock_generate_json_content(&seeds, body_buf, 4096);
            body = body_buf;
            body_len = strlen(body);
        }
    }
    /* XML responses (for SOAP, RSS, APIs) - POLYMORPHIC */
    else if (strcasecmp(ext, "xml") == 0) {
        body_buf = malloc(4096);
        if (body_buf) {
            anti_adblock_generate_xml_content(&seeds, body_buf, 4096);
            body = body_buf;
            body_len = strlen(body);
        }
    }
    /* JavaScript responses (tracking scripts, analytics) */
    else if (strcasecmp(ext, "js") == 0) {
        body = "/* Blocked by TLSGate-NX Sinkhole */\n"
               "(function(){window.__tlsgateNG_blocked=true;})();";
        body_len = strlen(body);
    }
    /* CSS responses (tracking pixels, webfonts) */
    else if (strcasecmp(ext, "css") == 0) {
        body = "/* Blocked by TLSGate-NX Sinkhole */\n"
               "body{margin:0;padding:0;}";
        body_len = strlen(body);
    }
    /* PHP/ASP/ASPX/JSP responses (simulate successful processing) */
    else if (strcasecmp(ext, "php") == 0 ||
             strcasecmp(ext, "asp") == 0 ||
             strcasecmp(ext, "aspx") == 0 ||
             strcasecmp(ext, "jsp") == 0) {
        body = "";
        body_len = 0;  /* Empty response (no static signatures!) */
        mime = "text/plain; charset=utf-8";
    }
    /* Python/Ruby/Perl responses */
    else if (strcasecmp(ext, "py") == 0 ||
             strcasecmp(ext, "rb") == 0 ||
             strcasecmp(ext, "pl") == 0) {
        body = "";
        body_len = 0;  /* Empty response (no static signatures!) */
        mime = "text/plain; charset=utf-8";
    }
    /* Text files */
    else if (strcasecmp(ext, "txt") == 0) {
        body = "";
        body_len = 0;  /* Empty response (no static signatures!) */
    }
    /* HTML fragments */
    else if (strcasecmp(ext, "html") == 0 || strcasecmp(ext, "htm") == 0) {
        body = "";
        body_len = 0;  /* Empty response (no static signatures!) */
    }
    /* All other types: return HTML index (like PixelNG) */
    else {
        free(response);
        return response_generate_index(conn);
    }

    int header_len = build_response_header_dynamic(response, 8192, mime, body_len, conn);
    /* MEMORY LEAK FIX: Check if header generation failed */
    if (header_len < 0) {
        free(response);
        if (body_buf) {
            free(body_buf);
        }
        return -1;
    }

    /* SECURITY FIX: Validate that header + body fits in allocated buffer (8192 bytes)
     * Prevent integer overflow and buffer overflow on response_len calculation */
    if (body_len > 0) {
        /* Cast header_len to size_t for safe comparison (header_len must be positive) */
        if (header_len < 0 || header_len > 8192 || body_len > (size_t)(8192 - (size_t)header_len)) {
            LOG_ERROR("Response too large: header=%d, body=%zu (max=8192)", header_len, body_len);
            free(response);
            if (body_buf) {
                free(body_buf);
            }
            return -1;
        }
        memcpy(response + header_len, body, body_len);
    }

    /* Free temporary body buffer if allocated */
    if (body_buf) {
        free(body_buf);
    }

    conn->response_buf = response;
    conn->response_len = header_len + body_len;  /* Safe: validated above */
    conn->response_is_static = 0;

    return 0;
}

/* Extract hostname from connection (SNI for HTTPS, Host header for HTTP) */
static const char* get_request_host(connection_t *conn) {
    /* HTTPS: Use SNI hostname if available */
    if (conn->is_https && conn->sni[0] != '\0') {
        return conn->sni;
    }

    /* HTTP: Parse Host header from request */
    static __thread char host_buf[256];  /* Thread-local buffer */
    host_buf[0] = '\0';

    const char *host_header = strcasestr(conn->request_buf, "\r\nHost:");
    if (!host_header) {
        host_header = strcasestr(conn->request_buf, "\nHost:");
        if (!host_header) {
            return host_buf;  /* Empty string */
        }
        host_header += 6;  /* Skip "\nHost:" */
    } else {
        host_header += 7;  /* Skip "\r\nHost:" */
    }

    /* Skip whitespace */
    while (*host_header == ' ' || *host_header == '\t') {
        host_header++;
    }

    /* Extract hostname (until \r, \n, :, or space) */
    const char *host_end = host_header;
    while (*host_end && *host_end != '\r' && *host_end != '\n' &&
           *host_end != ':' && *host_end != ' ' && *host_end != '\t') {
        host_end++;
    }

    size_t host_len = host_end - host_header;
    if (host_len >= sizeof(host_buf)) {
        host_len = sizeof(host_buf) - 1;
    }

    memcpy(host_buf, host_header, host_len);
    host_buf[host_len] = '\0';

    return host_buf;
}

int response_generate(connection_t *conn) {
    /* ========== Favicon Check (BEFORE any_responses) ========== */
    /* CRITICAL: Must check favicon BEFORE any_responses!
     * If we return HTML for favicon, browser shows loading spinner
     * Favicon must ALWAYS be the real favicon, even in anti-phishing mode
     */
    if (strcasecmp(conn->path, "/favicon.ico") == 0) {
        return response_generate_favicon(conn);
    }

    /* ========== Anti-Phishing Mode Check ========== */
    /* If any-responses=true: Return same HTML for ALL requests
     * This makes it impossible to detect the server by response patterns
     * (but favicon is already handled above)
     */
    if (g_master_config && g_master_config->any_responses) {
        return response_generate_index(conn);
    }

    /* ========== Silent Blocker Check ========== */
    /* Check if request matches silent block pattern (configured in silent-blocks.conf)
     * If matched: Return configured status code (204, 200, etc.) with optional delay
     * If not matched: Continue with normal response generation
     */

    /* Hot-reload check: Detect if Poolgen updated silent-block rules via SIGHUP */
    silent_blocker_check_and_reload_from_shm();

    if (silent_blocker_is_enabled()) {
        const char *host = get_request_host(conn);

        if (host && host[0] != '\0') {
            silent_block_result_t result = silent_blocker_check(host, conn->path);

            if (result.matched) {
                /* Check if reverse-proxy is enabled for this rule */
                if (result.reverse_proxy) {
                    /* Log origin info if specified */
                    if (result.origin_dns[0] != '\0') {
                        LOG_DEBUG("Reverse-proxy: Fetching %s%s via dynamic DNS (%s)",
                                  host, conn->path, result.origin_dns);
                    } else if (result.origin_host[0] != '\0') {
                        LOG_DEBUG("Reverse-proxy: Fetching %s%s via origin %s",
                                  host, conn->path, result.origin_host);
                    } else {
                        LOG_DEBUG("Reverse-proxy: Fetching from %s%s", host, conn->path);
                    }

                    /* Fetch real response from origin server
                     * Priority: origin-dns (dynamic) > origin (static) > local DNS */
                    reverse_proxy_response_t resp;
                    if (result.origin_dns[0] != '\0') {
                        /* Dynamic DNS resolution via external DNS server */
                        resp = reverse_proxy_fetch_with_dns(host, conn->path, result.origin_dns);
                    } else {
                        /* Static origin or local DNS */
                        resp = reverse_proxy_fetch_with_origin(
                            host, conn->path, result.origin_host[0] ? result.origin_host : NULL);
                    }

                    if (resp.status_code > 0) {
                        /* Successful fetch - build response */
                        LOG_DEBUG("Reverse-proxy: Got %d from origin, applying status %d",
                                  resp.status_code, result.status_code);

                        /* Use origin status code, not the override from config */
                        int final_status = resp.status_code;
                        const char *status_text =
                            final_status == 200 ? "OK" :
                            final_status == 201 ? "Created" :
                            final_status == 204 ? "No Content" :
                            final_status == 301 ? "Moved Permanently" :
                            final_status == 302 ? "Found" :
                            final_status == 304 ? "Not Modified" :
                            final_status == 400 ? "Bad Request" :
                            final_status == 401 ? "Unauthorized" :
                            final_status == 403 ? "Forbidden" :
                            final_status == 404 ? "Not Found" :
                            final_status == 500 ? "Internal Server Error" :
                            final_status == 502 ? "Bad Gateway" :
                            final_status == 503 ? "Service Unavailable" : "OK";

                        /* Use the actual Content-Type from origin server */
                        const char *actual_content_type = (resp.content_type[0] != '\0')
                            ? resp.content_type
                            : "application/octet-stream";

                        /* Allocate response buffer */
                        size_t total_size = 4096 + resp.body_len;
                        char *response = malloc(total_size);
                        if (!response) {
                            reverse_proxy_free_response(&resp);
                            return -1;
                        }

                        int header_len = snprintf(response, 4096,
                            "HTTP/1.1 %d %s\r\n"
                            "Content-Type: %s\r\n"
                            "Content-Length: %zu\r\n"
                            "Connection: keep-alive\r\n"
                            "Cache-Control: public, max-age=3600\r\n"
                            "Access-Control-Allow-Origin: *\r\n"
                            "\r\n",
                            final_status,
                            status_text,
                            actual_content_type,
                            resp.body_len);

                        if (header_len > 0 && header_len < 4096) {
                            /* Append body */
                            if (resp.body_len > 0 && resp.body) {
                                memcpy(response + header_len, resp.body, resp.body_len);
                            }

                            conn->response_buf = response;
                            conn->response_len = header_len + resp.body_len;
                            conn->response_is_static = 0;

                            /* Apply delay if configured */
                            if (result.delay_ms > 0) {
                                usleep(result.delay_ms * 1000);
                            }

                            reverse_proxy_free_response(&resp);
                            return 0;
                        }

                        free(response);
                        reverse_proxy_free_response(&resp);
                    } else {
                        LOG_WARN("Reverse-proxy fetch failed: %s", resp.error);
                        reverse_proxy_free_response(&resp);
                    }

                    /* Fallback: generate silent block response on fetch failure */
                    LOG_DEBUG("Falling back to silent block response");
                }

                /* Apply delay if configured (for realistic response timing) */
                if (result.delay_ms > 0) {
                    usleep(result.delay_ms * 1000);
                }

                /* Generate silent block response (normal or after proxy failure) */
                return response_generate_silent_block(conn, result.status_code);
            }
        }
    }

    /* ========== Normal Response Generation ========== */
    /* Route based on path */

    /* Special endpoints */
    if (strcasecmp(conn->path, "/generate_204") == 0 ||
        strcasecmp(conn->path, "/gen_204") == 0) {
        return response_generate_204(conn);
    }

    /* Root: html_index */
    if (strcmp(conn->path, "/") == 0 || strcmp(conn->path, "/index.html") == 0) {
        return response_generate_index(conn);
    }

    /* Extension-based response */
    if (conn->ext && *conn->ext) {
        return response_generate_for_extension(conn, conn->ext);
    }

    /* Path-based content type detection (before default PNG fallback)
     *
     * Some tracking/ad URLs have no extension but specific path patterns
     * that indicate the expected content type:
     *
     * JavaScript paths (loaded via <script src="...">):
     * - /players/... → ad/tracking scripts
     * - /player/... → video player scripts
     * - /pagead/... → Google Ads scripts
     *
     * If we return PNG for these, browser rejects with:
     * "Refused to execute script because MIME type 'image/png' is not executable"
     */
    if (strstr(conn->path, "/players/") != NULL ||
        strstr(conn->path, "/player/") != NULL ||
        strstr(conn->path, "/pagead/") != NULL) {
        /* Return minimal JavaScript stub */
        return response_generate_for_extension(conn, "js");
    }

    /* NO EXTENSION: Default to PNG (tracking pixel blocker)
     *
     * Why PNG instead of HTML?
     * Many tracking URLs have no extension:
     * - https://1.html-load.com/player/www.example.com/...
     * - https://tracking.domain.com/pixel/user123/campaign456
     *
     * These are typically:
     * 1. Tracking pixels (expect image, not HTML)
     * 2. Analytics beacons (expect image, not HTML)
     * 3. Ad impression counters (expect image, not HTML)
     *
     * Returning HTML would:
     * - Break websites expecting images in <img> tags
     * - Cause console errors: "Resource interpreted as Image but transferred with MIME type text/html"
     * - Make detection easier (real tracking servers return images!)
     *
     * Returning 1x1 transparent PNG:
     * - Silently blocks tracking
     * - No website breakage
     * - No console errors
     * - Indistinguishable from real tracking pixels
     * - STEALTH mode!
     */
    char *response = malloc(4096 + sizeof(gif_1x1));
    if (!response) {
        return -1;
    }

    int header_len = build_response_header_dynamic(response, 4096, "image/png", sizeof(gif_1x1), conn);
    /* MEMORY LEAK FIX: Check if header generation failed */
    if (header_len < 0) {
        free(response);
        return -1;
    }
    memcpy(response + header_len, gif_1x1, sizeof(gif_1x1));

    conn->response_buf = response;
    conn->response_len = header_len + sizeof(gif_1x1);
    conn->response_is_static = 0;

    return 0;
}

void response_init(void) {
    /* Initialize anti-adblock system (seeds, randomization) */
    anti_adblock_init();

    /* NOTE: Silent blocker is now initialized AFTER SHM setup in main()
     * - Poolgen: Loads rules from file into SHM (certcache_shm_load_silentblocks)
     * - Worker with SHM: Reads rules from SHM (silent_blocker_init_from_shm)
     * - Without SHM: Loads from file (silent_blocker_init)
     *
     * This allows hot-reload via SIGHUP to Poolgen.
     */
}

/* ========== HTML Template System ========== */

/* Global template buffer (thread-safe for read, protect writes with mutex) */
#define MAX_TEMPLATE_SIZE (1024 * 1024)  /* 1MB max template size */
static char g_html_template[MAX_TEMPLATE_SIZE];
static size_t g_html_template_len = 0;
static pthread_mutex_t g_template_lock = PTHREAD_MUTEX_INITIALIZER;

/* Load HTML template from disk at runtime
 * SECURITY: Validates file is in /etc/tlsgateNG/templates/ directory
 * This allows changing templates without recompiling (critical for production!)
 *
 * @param template_name: Template filename (e.g., "blocking.html")
 * @return 0 on success, -1 on error
 */
int response_load_html_template_file(const char *template_name) {
    if (!template_name) {
        LOG_ERROR("Template loading: NULL template name");
        return -1;
    }

    /* SECURITY: Check for path traversal attempts */
    if (strchr(template_name, '/') || strchr(template_name, '\\') ||
        strcmp(template_name, ".") == 0 || strcmp(template_name, "..") == 0) {
        LOG_ERROR("Template loading: Invalid template name (path traversal): %s", template_name);
        return -1;
    }

    /* Build full path in secure templates directory */
    char full_path[4096];
    snprintf(full_path, sizeof(full_path), "/etc/tlsgateNG/templates/%s", template_name);

    /* Open file */
    FILE *fp = fopen(full_path, "r");
    if (!fp) {
        LOG_ERROR("Template loading: Failed to open template %s: %s", full_path, strerror(errno));
        return -1;
    }

    /* Get file size */
    fseek(fp, 0, SEEK_END);
    long file_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    if (file_size < 0 || file_size > MAX_TEMPLATE_SIZE) {
        LOG_ERROR("Template loading: Invalid file size %ld (max: %d)", file_size, MAX_TEMPLATE_SIZE);
        fclose(fp);
        return -1;
    }

    /* Read template into buffer */
    size_t bytes_read = fread(g_html_template, 1, (size_t)file_size, fp);
    fclose(fp);

    if (bytes_read != (size_t)file_size) {
        LOG_ERROR("Template loading: Failed to read template (expected %ld, got %zu)",
                  file_size, bytes_read);
        return -1;
    }

    /* Update length atomically */
    pthread_mutex_lock(&g_template_lock);
    g_html_template_len = bytes_read;
    pthread_mutex_unlock(&g_template_lock);

    LOG_INFO("Template loaded successfully: %s (%zu bytes)", full_path, bytes_read);
    return 0;
}

/* Set template from memory buffer
 * Useful for testing or custom templates generated at runtime
 *
 * @param template_content: HTML content buffer
 * @param content_len: Length of content
 * @return 0 on success, -1 on error
 */
int response_set_html_template(const char *template_content, size_t content_len) {
    if (!template_content || content_len == 0) {
        LOG_ERROR("Template setting: NULL or empty content");
        return -1;
    }

    if (content_len > MAX_TEMPLATE_SIZE) {
        LOG_ERROR("Template setting: Content too large (%zu > %d)", content_len, MAX_TEMPLATE_SIZE);
        return -1;
    }

    pthread_mutex_lock(&g_template_lock);
    memcpy(g_html_template, template_content, content_len);
    g_html_template_len = content_len;
    pthread_mutex_unlock(&g_template_lock);

    LOG_INFO("Template set from memory (%zu bytes)", content_len);
    return 0;
}

/* Get current template content
 * @return Pointer to current template (static buffer), or NULL if not set
 */
const char* response_get_html_template(void) {
    if (g_html_template_len == 0) {
        return NULL;
    }
    return g_html_template;
}

/* Get current template size in bytes
 * @return Template size, or 0 if not set
 */
size_t response_get_html_template_size(void) {
    return g_html_template_len;
}
