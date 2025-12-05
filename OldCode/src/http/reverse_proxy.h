/*
 * reverse_proxy.h - Reverse Proxy with LRU Cache for Silent Blocker
 *
 * Fetches real responses from origin servers via HTTPS with SSL termination.
 * Caches responses with TTL expiration and LRU eviction.
 *
 * Features:
 *   - Browser simulation (realistic User-Agent, Accept headers)
 *   - Compression support (gzip, br, deflate)
 *   - Adaptive caching based on content type
 *   - Hash-based O(1) cache lookup
 *   - Retry logic with exponential backoff
 *
 * CacheSize: 200MB default (configurable)
 * CacheTime: Adaptive (5min-24h based on content type)
 *
 * Usage:
 *   1. reverse_proxy_init(209715200)  // 200MB cache
 *   2. reverse_proxy_fetch("domain.com", "/path") -> returns cached or fetched response
 *   3. reverse_proxy_free() on shutdown
 */

#ifndef REVERSE_PROXY_H
#define REVERSE_PROXY_H

#include <stddef.h>
#include <stdint.h>
#include <time.h>
#include <stdbool.h>

/* CacheSize: Maximum cache size (200MB) */
#define REVERSE_PROXY_MAX_CACHE (200 * 1024 * 1024)  /* 200MB default */

/* Adaptive Cache TTL based on content type (in seconds) */
#define CACHE_TTL_STATIC    86400   /* 24 hours - images, fonts, CSS, JS */
#define CACHE_TTL_DYNAMIC   300     /* 5 minutes - HTML, JSON, API responses */
#define CACHE_TTL_MEDIA     3600    /* 1 hour - video, audio */
#define CACHE_TTL_DEFAULT   1800    /* 30 minutes - unknown content */

/* Fetch configuration */
#define REVERSE_PROXY_FETCH_TIMEOUT     5000    /* 5 seconds initial timeout */
#define REVERSE_PROXY_CONNECT_TIMEOUT   3000    /* 3 seconds connection timeout */
#define REVERSE_PROXY_MAX_RETRIES       2       /* Number of retries on failure */
#define REVERSE_PROXY_RETRY_DELAY_MS    500     /* Base delay between retries */

/* Maximum URL length */
#define REVERSE_PROXY_MAX_URL 2048

/* Hash table size for O(1) cache lookup (prime number) */
#define CACHE_HASH_BUCKETS 1021

/* Content type categories for adaptive caching */
typedef enum {
    CONTENT_STATIC,     /* Images, fonts, CSS, JS - long cache */
    CONTENT_DYNAMIC,    /* HTML, JSON, XML - short cache */
    CONTENT_MEDIA,      /* Video, audio - medium cache */
    CONTENT_UNKNOWN     /* Default caching */
} content_category_t;

/* Cached response with hash-chain for O(1) lookup */
typedef struct reverse_proxy_cache_entry {
    char url[REVERSE_PROXY_MAX_URL];  /* Full URL (domain + path) */
    uint32_t url_hash;                 /* FNV-1a hash of URL */
    unsigned char *data;               /* Response body (may be compressed) */
    size_t data_len;                   /* Response size */
    int http_status;                   /* HTTP status code (200, 404, etc.) */
    time_t cached_at;                  /* Timestamp when cached */
    time_t ttl;                        /* Adaptive TTL based on content type */
    size_t cache_size;                 /* Memory used by this entry */
    content_category_t content_type;   /* Content category for TTL */
    char content_type_header[128];     /* Original Content-Type header */
    bool compressed;                   /* Response is compressed */

    /* Hash chain for O(1) lookup */
    struct reverse_proxy_cache_entry *hash_next;

    /* LRU pointers */
    struct reverse_proxy_cache_entry *lru_prev;
    struct reverse_proxy_cache_entry *lru_next;
} reverse_proxy_cache_entry_t;

/* Security headers structure for CORS/CSP passthrough */
typedef struct {
    /* CORS Headers */
    char access_control_allow_origin[256];
    char access_control_allow_methods[128];
    char access_control_allow_headers[512];
    char access_control_allow_credentials[16];
    char access_control_max_age[32];
    char access_control_expose_headers[256];

    /* CSP Headers */
    char content_security_policy[2048];
    char content_security_policy_report_only[2048];

    /* Other Security Headers */
    char x_frame_options[64];
    char x_content_type_options[32];
    char strict_transport_security[128];
    char x_xss_protection[32];
    char referrer_policy[64];
    char permissions_policy[512];

    /* Caching Headers */
    char cache_control[256];
    char expires[64];
    char etag[128];
    char last_modified[64];
    char vary[128];
} security_headers_t;

/* Fetched response structure */
typedef struct {
    int status_code;           /* HTTP status (200, 404, 500, -1 on error) */
    unsigned char *body;       /* Response body (heap allocated) */
    size_t body_len;           /* Body size in bytes */
    char error[256];           /* Error message if status < 0 */
    char content_type[128];    /* Content-Type header from response */
    bool from_cache;           /* True if response came from cache */
    int retry_count;           /* Number of retries needed */
    security_headers_t headers; /* CORS/CSP headers from origin */
} reverse_proxy_response_t;

/* Initialize reverse proxy with cache size limit
 *
 * Parameters:
 *   max_cache_size - Maximum cache size in bytes (e.g., 5242880 for 5MB)
 *                    0 = use default REVERSE_PROXY_MAX_CACHE
 *
 * Returns:
 *   0 on success
 *   -1 on error (memory allocation failed)
 */
int reverse_proxy_init(size_t max_cache_size);

/* Fetch response from origin server (with cache)
 *
 * Parameters:
 *   domain - Origin domain (e.g., "tracking.com")
 *   path   - Request path (e.g., "/pixel/user123")
 *
 * Returns:
 *   reverse_proxy_response_t with:
 *     status_code >= 0: successful fetch (200, 404, etc.)
 *     status_code < 0: error (timeout, connection failed, etc.)
 *     body: NULL-terminated response body (must free after use!)
 *
 * Note: Caller must free response.body when done!
 */
reverse_proxy_response_t reverse_proxy_fetch(const char *domain, const char *path);

/* Fetch response from specific origin server (bypasses DNS)
 *
 * Use this when the domain's DNS points to TLSGate itself.
 * The origin_host specifies where to actually connect (IP or hostname).
 * The domain is still used for SNI and Host header.
 *
 * Parameters:
 *   domain      - Domain for SNI/Host header (e.g., "html-load.com")
 *   path        - Request path (e.g., "/loader.min.js")
 *   origin_host - Origin server IP or hostname (e.g., "1.2.3.4" or "origin.example.com")
 *                 NULL = use domain for DNS (same as reverse_proxy_fetch)
 *
 * Example config:
 *   html-load.com /* 0 200 reverse-proxy=on origin=104.18.20.31
 *
 * Returns: same as reverse_proxy_fetch
 */
reverse_proxy_response_t reverse_proxy_fetch_with_origin(const char *domain, const char *path,
                                                          const char *origin_host);

/* Fetch response with dynamic DNS resolution via external DNS server
 *
 * Use this when you want to dynamically resolve the origin IP using an
 * external DNS server (e.g., 8.8.8.8) instead of local DNS or a static IP.
 * This is useful when the domain's DNS changes frequently (e.g., CDN rotation).
 *
 * Parameters:
 *   domain      - Domain for SNI/Host header and DNS resolution
 *   path        - Request path
 *   origin_dns  - External DNS server IP (e.g., "8.8.8.8", "1.1.1.1")
 *                 NULL = use local DNS (same as reverse_proxy_fetch)
 *
 * Example config:
 *   html-load.com /* 0 200 reverse-proxy=on origin-dns=8.8.8.8
 *
 * Returns: same as reverse_proxy_fetch
 */
reverse_proxy_response_t reverse_proxy_fetch_with_dns(const char *domain, const char *path,
                                                       const char *origin_dns);

/* Free response body (call this after using reverse_proxy_fetch result) */
void reverse_proxy_free_response(reverse_proxy_response_t *resp);

/* Clear cache (useful for testing) */
void reverse_proxy_clear_cache(void);

/* Get current cache usage in bytes */
size_t reverse_proxy_get_cache_size(void);

/* Get cache hit rate (for debugging) */
void reverse_proxy_get_stats(int *hits, int *misses);

/* Cleanup and free all resources */
void reverse_proxy_shutdown(void);

#endif /* REVERSE_PROXY_H */
