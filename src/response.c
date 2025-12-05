/*
 * response.c - HTTP Response Generation for TLSGate
 *
 * Ultra-fast response generation using:
 * - Pre-computed FNV-1a hash table (273 extensions)
 * - O(log n) binary search (~8 comparisons)
 * - Zero-copy static responses
 * - Full security header neutralization
 */

#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stdio.h>

#include "../include/response.h"
#include "../include/extension_hash_table.h"
#include "../include/favicon.h"

/* Pre-built favicon response (allocated once at init) */
static char *favicon_response = NULL;
static size_t favicon_response_len = 0;

/* =============================================================================
 * Static Response Data
 * =============================================================================
 */

/* 1x1 transparent GIF (43 bytes) */
static const unsigned char gif_1x1[] = {
    'G','I','F','8','9','a',
    0x01, 0x00, 0x01, 0x00,     /* 1x1 */
    0x80, 0x00, 0x00,           /* Global color table */
    0x01, 0x01, 0x01,           /* Color 0: near-black */
    0x00, 0x00, 0x00,           /* Color 1: black */
    0x21, 0xf9, 0x04, 0x01,     /* Graphics extension */
    0x00, 0x00, 0x00, 0x00,     /* Delay, transparent */
    0x2c, 0x00, 0x00, 0x00, 0x00, /* Image descriptor */
    0x01, 0x00, 0x01, 0x00, 0x00,
    0x02, 0x01, 0x44, 0x00,     /* Image data */
    0x3b                        /* Trailer */
};

/* 1x1 transparent PNG (67 bytes) */
static const unsigned char png_1x1[] = {
    0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a,
    0x00, 0x00, 0x00, 0x0d, 0x49, 0x48, 0x44, 0x52,
    0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
    0x08, 0x06, 0x00, 0x00, 0x00, 0x1f, 0x15, 0xc4,
    0x89, 0x00, 0x00, 0x00, 0x0a, 0x49, 0x44, 0x41,
    0x54, 0x78, 0x9c, 0x63, 0x00, 0x01, 0x00, 0x00,
    0x05, 0x00, 0x01, 0x0d, 0x0a, 0x2d, 0xb4, 0x00,
    0x00, 0x00, 0x00, 0x49, 0x45, 0x4e, 0x44, 0xae,
    0x42, 0x60, 0x82
};

/* Minimal ICO (70 bytes) - for generic .ico files */
static const unsigned char ico_1x1[] = {
    0x00, 0x00,             /* Reserved */
    0x01, 0x00,             /* ICO type */
    0x01, 0x00,             /* 1 image */
    0x01, 0x01, 0x00,       /* 1x1, >8bpp */
    0x00,                   /* Reserved */
    0x01, 0x00,             /* 1 color plane */
    0x20, 0x00,             /* 32 bpp */
    0x30, 0x00, 0x00, 0x00, /* Size: 48 bytes */
    0x16, 0x00, 0x00, 0x00, /* Offset: 22 bytes */
    /* DIB header */
    0x28, 0x00, 0x00, 0x00, /* DIB size: 40 */
    0x01, 0x00, 0x00, 0x00, /* Width: 1 */
    0x02, 0x00, 0x00, 0x00, /* Height: 2 */
    0x01, 0x00,             /* Planes: 1 */
    0x20, 0x00,             /* BPP: 32 */
    0x00, 0x00, 0x00, 0x00, /* No compression */
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, /* End header */
    0x00, 0x00, 0x00, 0x00, /* Color table */
    0x00, 0x00, 0x00, 0x00, /* XOR BGRA */
    0x80, 0xf8, 0x9c, 0x41  /* AND mask */
};

/* Empty SWF (placeholder - browsers don't run Flash anymore) */
static const unsigned char swf_empty[] = {
    'F', 'W', 'S', 0x05,    /* Uncompressed Flash 5 */
    0x11, 0x00, 0x00, 0x00, /* File size */
    0x00, 0x00, 0x00, 0x00, /* Frame size */
    0x00, 0x00,             /* Frame rate */
    0x01, 0x00,             /* Frame count */
    0x00                    /* End tag */
};

/* =============================================================================
 * Static Response Headers (pre-computed for zero-copy)
 * =============================================================================
 */

/* Common header parts */
#define SECURITY_HEADERS \
    "Access-Control-Allow-Origin: *\r\n" \
    "Access-Control-Allow-Methods: GET, POST, PUT, DELETE, PATCH, OPTIONS, HEAD\r\n" \
    "Access-Control-Allow-Headers: *\r\n" \
    "Access-Control-Allow-Credentials: true\r\n" \
    "Cross-Origin-Resource-Policy: cross-origin\r\n" \
    "X-Content-Type-Options: nosniff\r\n" \
    "X-Frame-Options: ALLOWALL\r\n"

/* 204 No Content response */
static const char resp_204[] =
    "HTTP/1.1 204 No Content\r\n"
    "Content-Length: 0\r\n"
    "Connection: keep-alive\r\n"
    "Cache-Control: no-cache\r\n"
    SECURITY_HEADERS
    "\r\n";

/* OPTIONS CORS preflight response */
static const char resp_options[] =
    "HTTP/1.1 200 OK\r\n"
    "Content-Length: 0\r\n"
    "Connection: keep-alive\r\n"
    "Cache-Control: max-age=86400\r\n"
    SECURITY_HEADERS
    "Access-Control-Max-Age: 86400\r\n"
    "\r\n";

/* 404 Not Found */
static const char resp_404[] =
    "HTTP/1.1 404 Not Found\r\n"
    "Content-Type: text/plain\r\n"
    "Content-Length: 9\r\n"
    "Connection: close\r\n"
    "\r\n"
    "Not Found";

/* Pre-built response structures */
const response_t RESP_204_NO_CONTENT = {
    .data = resp_204,
    .len = sizeof(resp_204) - 1,
    .is_static = 1
};

const response_t RESP_OPTIONS_CORS = {
    .data = resp_options,
    .len = sizeof(resp_options) - 1,
    .is_static = 1
};

const response_t RESP_404_NOT_FOUND = {
    .data = resp_404,
    .len = sizeof(resp_404) - 1,
    .is_static = 1
};

/* =============================================================================
 * Response Generation
 * =============================================================================
 */

void response_init(void)
{
    /* Pre-build the favicon response (header + 288KB icon data)
     * This is allocated once and shared by all connections */
    if (favicon_response == NULL) {
        size_t header_max = 1024;
        size_t total = header_max + favicon_ico_len;

        favicon_response = malloc(total);
        if (favicon_response) {
            int header_len = snprintf(favicon_response, header_max,
                "HTTP/1.1 200 OK\r\n"
                "Content-Type: image/x-icon\r\n"
                "Content-Length: %u\r\n"
                "Connection: keep-alive\r\n"
                "Cache-Control: public, max-age=86400\r\n"
                SECURITY_HEADERS
                "\r\n",
                favicon_ico_len);

            if (header_len > 0 && (size_t)header_len < header_max) {
                memcpy(favicon_response + header_len, favicon_ico, favicon_ico_len);
                favicon_response_len = header_len + favicon_ico_len;
            }
        }
    }
}

const char *response_get_mime(const char *ext)
{
    if (!ext || !*ext)
        return "text/html; charset=utf-8";

    const extension_entry_t *entry = lookup_extension(ext);
    if (entry)
        return entry->content_type;

    return "application/octet-stream";
}

/*
 * Build HTTP response with headers and body
 * Returns dynamically allocated buffer or NULL on error
 */
static char *build_response(const char *mime, const void *body, size_t body_len,
                            size_t *out_len)
{
    /* Estimate header size */
    size_t header_max = 1024;
    size_t total = header_max + body_len;

    char *buf = malloc(total);
    if (!buf)
        return NULL;

    int header_len = snprintf(buf, header_max,
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %zu\r\n"
        "Connection: keep-alive\r\n"
        "Cache-Control: public, max-age=3600\r\n"
        SECURITY_HEADERS
        "\r\n",
        mime, body_len);

    if (header_len < 0 || (size_t)header_len >= header_max) {
        free(buf);
        return NULL;
    }

    /* Append body */
    if (body && body_len > 0)
        memcpy(buf + header_len, body, body_len);

    *out_len = header_len + body_len;
    return buf;
}

/*
 * Extract file extension from path
 * Returns pointer to extension (without dot) or NULL
 */
static const char *get_extension(const char *path)
{
    if (!path)
        return NULL;

    const char *dot = strrchr(path, '.');
    if (!dot || dot == path)
        return NULL;

    /* Skip the dot */
    return dot + 1;
}

int response_for_extension(const char *ext, response_t *resp)
{
    if (!resp)
        return -1;

    /* Default: empty response with MIME type */
    const char *mime = response_get_mime(ext);
    const extension_entry_t *entry = ext ? lookup_extension(ext) : NULL;
    response_type_t type = entry ? entry->response_type : RESP_DEFAULT;

    const void *body = NULL;
    size_t body_len = 0;

    /* Select appropriate body based on response type */
    switch (type) {
    case RESP_BINARY_GIF:
        body = gif_1x1;
        body_len = sizeof(gif_1x1);
        break;

    case RESP_BINARY_PNG:
        body = png_1x1;
        body_len = sizeof(png_1x1);
        break;

    case RESP_BINARY_JPG:
        /* Use PNG as placeholder - browsers accept it */
        body = png_1x1;
        body_len = sizeof(png_1x1);
        break;

    case RESP_BINARY_ICO:
        body = ico_1x1;
        body_len = sizeof(ico_1x1);
        break;

    case RESP_BINARY_SWF:
        body = swf_empty;
        body_len = sizeof(swf_empty);
        break;

    case RESP_SCRIPT_JS:
        /* Empty JS with no-op */
        body = "/* */";
        body_len = 5;
        break;

    case RESP_STYLE_CSS:
        /* Empty CSS */
        body = "/* */";
        body_len = 5;
        break;

    case RESP_SCRIPT_HTML:
        /* Empty HTML */
        body = "";
        body_len = 0;
        break;

    case RESP_DATA_JSON:
        /* Empty JSON object */
        body = "{}";
        body_len = 2;
        break;

    case RESP_DATA_XML:
        /* Minimal XML */
        body = "<?xml version=\"1.0\"?><r/>";
        body_len = 25;
        break;

    case RESP_MEDIA_VIDEO:
    case RESP_MEDIA_AUDIO:
    case RESP_DOCUMENT_PDF:
    case RESP_TEXT_PLAIN:
    case RESP_DEFAULT:
    default:
        /* Empty response */
        body = "";
        body_len = 0;
        break;
    }

    /* Build the response */
    resp->data = build_response(mime, body, body_len, &resp->len);
    if (!resp->data)
        return -1;

    resp->is_static = 0;
    return 0;
}

int response_generate(const char *path, const char *method, response_t *resp)
{
    if (!resp)
        return -1;

    /* Handle OPTIONS preflight */
    if (method && strcasecmp(method, "OPTIONS") == 0) {
        *resp = RESP_OPTIONS_CORS;
        return 0;
    }

    /* Extract extension from path */
    const char *ext = get_extension(path);

    /* Special case: favicon.ico */
    if (path && strcasecmp(path, "/favicon.ico") == 0) {
        return response_for_extension("ico", resp);
    }

    /* Generate response based on extension */
    if (ext) {
        return response_for_extension(ext, resp);
    }

    /* No extension: return 204 No Content */
    *resp = RESP_204_NO_CONTENT;
    return 0;
}

void response_free(response_t *resp)
{
    if (resp && !resp->is_static && resp->data) {
        free((void *)resp->data);
        resp->data = NULL;
        resp->len = 0;
    }
}
