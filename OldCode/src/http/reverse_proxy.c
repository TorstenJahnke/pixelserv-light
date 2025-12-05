/*
 * reverse_proxy.c - Reverse Proxy Implementation with LRU Cache
 *
 * Optimized version with:
 *   - Browser simulation (realistic headers)
 *   - Compression support (Accept-Encoding: gzip, br, deflate)
 *   - Adaptive caching based on content type
 *   - Hash-based O(1) cache lookup
 *   - Retry logic with exponential backoff
 */

#include "reverse_proxy.h"
#include "../util/logger.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <pthread.h>
#include <time.h>
#include <ctype.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#ifdef HAVE_CURL
#include <curl/curl.h>
#else
/* curl not available - reverse proxy disabled */
typedef void CURL;
typedef void CURLM;
#endif

/* Browser simulation constants moved into HAVE_CURL block below */

/* ========== FNV-1a Hash for O(1) Cache Lookup ========== */

static inline uint32_t fnv1a_hash_url(const char *url) {
    uint32_t hash = 2166136261U;
    while (*url) {
        hash ^= (uint32_t)(unsigned char)*url++;
        hash *= 16777619U;
    }
    return hash;
}

/* ========== Content Type Classification ========== */

/* Classify content type for adaptive caching */
static content_category_t classify_content_type(const char *content_type) {
    if (!content_type || content_type[0] == '\0') {
        return CONTENT_UNKNOWN;
    }

    /* Static content - long cache (24h) */
    if (strstr(content_type, "image/") ||
        strstr(content_type, "font/") ||
        strstr(content_type, "text/css") ||
        strstr(content_type, "javascript") ||
        strstr(content_type, "woff") ||
        strstr(content_type, "application/octet-stream")) {
        return CONTENT_STATIC;
    }

    /* Media content - medium cache (1h) */
    if (strstr(content_type, "video/") ||
        strstr(content_type, "audio/")) {
        return CONTENT_MEDIA;
    }

    /* Dynamic content - short cache (5min) */
    if (strstr(content_type, "text/html") ||
        strstr(content_type, "application/json") ||
        strstr(content_type, "application/xml") ||
        strstr(content_type, "text/xml")) {
        return CONTENT_DYNAMIC;
    }

    return CONTENT_UNKNOWN;
}

/* Get TTL based on content category */
static time_t get_ttl_for_category(content_category_t category) {
    switch (category) {
        case CONTENT_STATIC:  return CACHE_TTL_STATIC;   /* 24 hours */
        case CONTENT_MEDIA:   return CACHE_TTL_MEDIA;    /* 1 hour */
        case CONTENT_DYNAMIC: return CACHE_TTL_DYNAMIC;  /* 5 minutes */
        default:              return CACHE_TTL_DEFAULT;  /* 30 minutes */
    }
}

/* ========== LRU Cache with Hash Table ========== */

typedef struct {
    reverse_proxy_cache_entry_t *head;      /* Most recently used */
    reverse_proxy_cache_entry_t *tail;      /* Least recently used */
    reverse_proxy_cache_entry_t *hash_table[CACHE_HASH_BUCKETS]; /* Hash buckets */
    size_t total_size;                      /* Current cache size */
    size_t max_size;                        /* Maximum cache size */
    int hits;                               /* Cache hit count */
    int misses;                             /* Cache miss count */
    int entry_count;                        /* Number of entries */
    pthread_mutex_t lock;                   /* Thread-safe access */
    unsigned int ua_index;                  /* User-Agent rotation index */
} reverse_proxy_cache_t;

static reverse_proxy_cache_t g_cache = {
    .head = NULL,
    .tail = NULL,
    .hash_table = {NULL},
    .total_size = 0,
    .max_size = REVERSE_PROXY_MAX_CACHE,
    .hits = 0,
    .misses = 0,
    .entry_count = 0,
    .lock = PTHREAD_MUTEX_INITIALIZER,
    .ua_index = 0
};

#ifdef HAVE_CURL

/* ========== Browser Simulation (CURL only) ========== */

/* Realistic User-Agent strings (rotated to avoid fingerprinting) */
static const char *USER_AGENTS[] = {
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
};
#define USER_AGENT_COUNT (sizeof(USER_AGENTS) / sizeof(USER_AGENTS[0]))

/* Standard browser Accept headers */
#define ACCEPT_HEADER "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8"
#define ACCEPT_LANGUAGE "en-US,en;q=0.9,de;q=0.8"
#define ACCEPT_ENCODING "gzip, deflate, br"

/* Get next User-Agent (thread-safe rotation) */
static const char* get_next_user_agent(void) {
    unsigned int idx = __sync_fetch_and_add(&g_cache.ua_index, 1) % USER_AGENT_COUNT;
    return USER_AGENTS[idx];
}

/* Response buffer for curl callback */
typedef struct {
    unsigned char *data;
    size_t len;
    size_t capacity;
} response_buffer_t;

/* Header buffer for capturing all relevant headers */
typedef struct {
    char content_type[128];
    security_headers_t security;  /* CORS, CSP, and other security headers */
} header_data_t;

/* Callback for libcurl to write response data */
static size_t write_callback(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;
    response_buffer_t *buf = (response_buffer_t *)userp;

    /* Grow buffer if needed */
    if (buf->len + realsize + 1 > buf->capacity) {
        size_t new_capacity = (buf->capacity == 0) ? 4096 : buf->capacity * 2;
        while (new_capacity < buf->len + realsize + 1) {
            new_capacity *= 2;
        }

        unsigned char *ptr = realloc(buf->data, new_capacity);
        if (!ptr) {
            LOG_ERROR("reverse_proxy: Memory allocation failed (%zu bytes)", new_capacity);
            return 0;
        }
        buf->data = ptr;
        buf->capacity = new_capacity;
    }

    memcpy(&(buf->data[buf->len]), contents, realsize);
    buf->len += realsize;
    buf->data[buf->len] = 0;  /* Null terminate */

    return realsize;
}

/* Helper to extract header value and copy to destination */
static void extract_header_value(const char *buffer, size_t buflen, size_t header_len,
                                  char *dest, size_t dest_size) {
    const char *value = buffer + header_len;
    while (*value == ' ' || *value == '\t') value++;

    size_t len = buflen - (value - buffer);
    while (len > 0 && (value[len-1] == '\r' || value[len-1] == '\n' || value[len-1] == ' ')) {
        len--;
    }
    if (len >= dest_size) {
        len = dest_size - 1;
    }
    memcpy(dest, value, len);
    dest[len] = '\0';
}

/* Callback for libcurl to capture headers - CORS, CSP, and all security headers */
static size_t header_callback(char *buffer, size_t size, size_t nitems, void *userp) {
    size_t realsize = size * nitems;
    header_data_t *hdr = (header_data_t *)userp;

    /* Content-Type */
    if (realsize > 14 && strncasecmp(buffer, "Content-Type:", 13) == 0) {
        extract_header_value(buffer, realsize, 13, hdr->content_type, sizeof(hdr->content_type));
    }
    /* CORS Headers */
    else if (realsize > 28 && strncasecmp(buffer, "Access-Control-Allow-Origin:", 28) == 0) {
        extract_header_value(buffer, realsize, 28,
            hdr->security.access_control_allow_origin,
            sizeof(hdr->security.access_control_allow_origin));
    }
    else if (realsize > 29 && strncasecmp(buffer, "Access-Control-Allow-Methods:", 29) == 0) {
        extract_header_value(buffer, realsize, 29,
            hdr->security.access_control_allow_methods,
            sizeof(hdr->security.access_control_allow_methods));
    }
    else if (realsize > 29 && strncasecmp(buffer, "Access-Control-Allow-Headers:", 29) == 0) {
        extract_header_value(buffer, realsize, 29,
            hdr->security.access_control_allow_headers,
            sizeof(hdr->security.access_control_allow_headers));
    }
    else if (realsize > 33 && strncasecmp(buffer, "Access-Control-Allow-Credentials:", 33) == 0) {
        extract_header_value(buffer, realsize, 33,
            hdr->security.access_control_allow_credentials,
            sizeof(hdr->security.access_control_allow_credentials));
    }
    else if (realsize > 24 && strncasecmp(buffer, "Access-Control-Max-Age:", 23) == 0) {
        extract_header_value(buffer, realsize, 23,
            hdr->security.access_control_max_age,
            sizeof(hdr->security.access_control_max_age));
    }
    else if (realsize > 30 && strncasecmp(buffer, "Access-Control-Expose-Headers:", 30) == 0) {
        extract_header_value(buffer, realsize, 30,
            hdr->security.access_control_expose_headers,
            sizeof(hdr->security.access_control_expose_headers));
    }
    /* CSP Headers */
    else if (realsize > 25 && strncasecmp(buffer, "Content-Security-Policy:", 24) == 0) {
        extract_header_value(buffer, realsize, 24,
            hdr->security.content_security_policy,
            sizeof(hdr->security.content_security_policy));
    }
    else if (realsize > 37 && strncasecmp(buffer, "Content-Security-Policy-Report-Only:", 36) == 0) {
        extract_header_value(buffer, realsize, 36,
            hdr->security.content_security_policy_report_only,
            sizeof(hdr->security.content_security_policy_report_only));
    }
    /* Other Security Headers */
    else if (realsize > 16 && strncasecmp(buffer, "X-Frame-Options:", 16) == 0) {
        extract_header_value(buffer, realsize, 16,
            hdr->security.x_frame_options,
            sizeof(hdr->security.x_frame_options));
    }
    else if (realsize > 23 && strncasecmp(buffer, "X-Content-Type-Options:", 23) == 0) {
        extract_header_value(buffer, realsize, 23,
            hdr->security.x_content_type_options,
            sizeof(hdr->security.x_content_type_options));
    }
    else if (realsize > 26 && strncasecmp(buffer, "Strict-Transport-Security:", 26) == 0) {
        extract_header_value(buffer, realsize, 26,
            hdr->security.strict_transport_security,
            sizeof(hdr->security.strict_transport_security));
    }
    else if (realsize > 18 && strncasecmp(buffer, "X-XSS-Protection:", 17) == 0) {
        extract_header_value(buffer, realsize, 17,
            hdr->security.x_xss_protection,
            sizeof(hdr->security.x_xss_protection));
    }
    else if (realsize > 16 && strncasecmp(buffer, "Referrer-Policy:", 16) == 0) {
        extract_header_value(buffer, realsize, 16,
            hdr->security.referrer_policy,
            sizeof(hdr->security.referrer_policy));
    }
    else if (realsize > 19 && strncasecmp(buffer, "Permissions-Policy:", 19) == 0) {
        extract_header_value(buffer, realsize, 19,
            hdr->security.permissions_policy,
            sizeof(hdr->security.permissions_policy));
    }
    /* Caching Headers */
    else if (realsize > 14 && strncasecmp(buffer, "Cache-Control:", 14) == 0) {
        extract_header_value(buffer, realsize, 14,
            hdr->security.cache_control,
            sizeof(hdr->security.cache_control));
    }
    else if (realsize > 8 && strncasecmp(buffer, "Expires:", 8) == 0) {
        extract_header_value(buffer, realsize, 8,
            hdr->security.expires,
            sizeof(hdr->security.expires));
    }
    else if (realsize > 5 && strncasecmp(buffer, "ETag:", 5) == 0) {
        extract_header_value(buffer, realsize, 5,
            hdr->security.etag,
            sizeof(hdr->security.etag));
    }
    else if (realsize > 14 && strncasecmp(buffer, "Last-Modified:", 14) == 0) {
        extract_header_value(buffer, realsize, 14,
            hdr->security.last_modified,
            sizeof(hdr->security.last_modified));
    }
    else if (realsize > 5 && strncasecmp(buffer, "Vary:", 5) == 0) {
        extract_header_value(buffer, realsize, 5,
            hdr->security.vary,
            sizeof(hdr->security.vary));
    }

    return realsize;
}
#endif

/* Remove entry from LRU list */
static void lru_remove(reverse_proxy_cache_entry_t *entry) {
    if (entry->lru_prev) {
        entry->lru_prev->lru_next = entry->lru_next;
    } else {
        g_cache.head = entry->lru_next;
    }

    if (entry->lru_next) {
        entry->lru_next->lru_prev = entry->lru_prev;
    } else {
        g_cache.tail = entry->lru_prev;
    }
}

/* Add entry to LRU head (most recently used) */
static void lru_add_head(reverse_proxy_cache_entry_t *entry) {
    entry->lru_prev = NULL;
    entry->lru_next = g_cache.head;

    if (g_cache.head) {
        g_cache.head->lru_prev = entry;
    } else {
        g_cache.tail = entry;
    }

    g_cache.head = entry;
}

/* Remove entry from hash table */
static void hash_remove(reverse_proxy_cache_entry_t *entry) {
    uint32_t bucket = entry->url_hash % CACHE_HASH_BUCKETS;
    reverse_proxy_cache_entry_t **pp = &g_cache.hash_table[bucket];

    while (*pp) {
        if (*pp == entry) {
            *pp = entry->hash_next;
            return;
        }
        pp = &(*pp)->hash_next;
    }
}

/* Add entry to hash table */
static void hash_add(reverse_proxy_cache_entry_t *entry) {
    uint32_t bucket = entry->url_hash % CACHE_HASH_BUCKETS;
    entry->hash_next = g_cache.hash_table[bucket];
    g_cache.hash_table[bucket] = entry;
}

/* Find entry in cache by URL - O(1) average via hash table */
static reverse_proxy_cache_entry_t* cache_find(const char *url, uint32_t url_hash) {
    uint32_t bucket = url_hash % CACHE_HASH_BUCKETS;
    reverse_proxy_cache_entry_t *entry = g_cache.hash_table[bucket];

    while (entry) {
        if (entry->url_hash == url_hash && strcmp(entry->url, url) == 0) {
            return entry;
        }
        entry = entry->hash_next;
    }
    return NULL;
}

/* Free a cache entry */
static void cache_entry_free(reverse_proxy_cache_entry_t *entry) {
    if (entry) {
        free(entry->data);
        free(entry);
    }
}

/* Evict least recently used entries to make space */
static void cache_evict_lru(size_t needed_size) {
    while (g_cache.tail && (g_cache.total_size + needed_size > g_cache.max_size)) {
        reverse_proxy_cache_entry_t *victim = g_cache.tail;

        LOG_DEBUG("Cache evicting: %s (%zu bytes, age: %lds)",
                  victim->url, victim->cache_size, (long)(time(NULL) - victim->cached_at));

        lru_remove(victim);
        hash_remove(victim);
        g_cache.total_size -= victim->cache_size;
        g_cache.entry_count--;

        cache_entry_free(victim);
    }
}

/* Add response to cache */
static void cache_add(const char *url, uint32_t url_hash, int status_code,
                      const unsigned char *data, size_t data_len,
                      const char *content_type) {
    if (data_len == 0) {
        return;  /* Don't cache empty responses */
    }

    /* Don't cache error responses */
    if (status_code >= 400) {
        return;
    }

    size_t entry_size = sizeof(reverse_proxy_cache_entry_t) + data_len;

    /* Don't cache if single entry exceeds max cache */
    if (entry_size > g_cache.max_size / 2) {
        LOG_DEBUG("Cache: Response too large to cache (%zu bytes)", data_len);
        return;
    }

    /* Evict if needed */
    cache_evict_lru(entry_size);

    /* Create new entry */
    reverse_proxy_cache_entry_t *entry = malloc(sizeof(reverse_proxy_cache_entry_t));
    if (!entry) {
        return;
    }

    entry->data = malloc(data_len);
    if (!entry->data) {
        free(entry);
        return;
    }

    snprintf(entry->url, sizeof(entry->url), "%s", url);
    entry->url_hash = url_hash;
    memcpy(entry->data, data, data_len);
    entry->data_len = data_len;
    entry->http_status = status_code;
    entry->cached_at = time(NULL);
    entry->cache_size = entry_size;

    /* Classify content and set adaptive TTL */
    entry->content_type = classify_content_type(content_type);
    entry->ttl = get_ttl_for_category(entry->content_type);

    if (content_type) {
        snprintf(entry->content_type_header, sizeof(entry->content_type_header), "%s", content_type);
    } else {
        entry->content_type_header[0] = '\0';
    }

    entry->compressed = false;
    entry->hash_next = NULL;

    /* Add to hash table and LRU list */
    hash_add(entry);
    lru_add_head(entry);
    g_cache.total_size += entry_size;
    g_cache.entry_count++;

    LOG_DEBUG("Cache added: %s (%zu bytes, TTL: %lds, entries: %d, total: %zu/%zu)",
              url, entry_size, (long)entry->ttl, g_cache.entry_count,
              g_cache.total_size, g_cache.max_size);
}

/* ========== External DNS Resolution ========== */

/* DNS query packet structure (simplified) */
typedef struct {
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
} dns_header_t;

/* Resolve domain using external DNS server (e.g., 8.8.8.8)
 *
 * This bypasses local DNS (which may point to TLSGate) and queries
 * an external DNS server directly to get the real origin IP.
 *
 * Parameters:
 *   domain     - Domain to resolve (e.g., "html-load.com")
 *   dns_server - External DNS server IP (e.g., "8.8.8.8")
 *   result_ip  - Buffer to store resolved IP (min 64 bytes)
 *   result_size - Size of result_ip buffer
 *
 * Returns:
 *   0 on success, -1 on error
 */
static int resolve_via_external_dns(const char *domain, const char *dns_server,
                                     char *result_ip, size_t result_size) {
    if (!domain || !dns_server || !result_ip || result_size < 16) {
        return -1;
    }

    /* Create UDP socket */
    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0) {
        LOG_WARN("External DNS: Failed to create socket");
        return -1;
    }

    /* Set socket timeout (2 seconds) */
    struct timeval tv = { .tv_sec = 2, .tv_usec = 0 };
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    /* DNS server address */
    struct sockaddr_in dns_addr;
    memset(&dns_addr, 0, sizeof(dns_addr));
    dns_addr.sin_family = AF_INET;
    dns_addr.sin_port = htons(53);
    if (inet_pton(AF_INET, dns_server, &dns_addr.sin_addr) != 1) {
        LOG_WARN("External DNS: Invalid DNS server IP: %s", dns_server);
        close(sock);
        return -1;
    }

    /* Build DNS query packet */
    unsigned char query[512];
    memset(query, 0, sizeof(query));

    /* Header */
    dns_header_t *hdr = (dns_header_t *)query;
    hdr->id = htons((uint16_t)(time(NULL) & 0xFFFF));  /* Random ID */
    hdr->flags = htons(0x0100);  /* Standard query with recursion desired */
    hdr->qdcount = htons(1);     /* One question */

    /* Question section - encode domain name */
    unsigned char *qname = query + sizeof(dns_header_t);
    const char *p = domain;
    unsigned char *len_pos = qname;
    qname++;

    while (*p) {
        if (*p == '.') {
            *len_pos = (unsigned char)(qname - len_pos - 1);
            len_pos = qname;
            qname++;
        } else {
            *qname++ = (unsigned char)*p;
        }
        p++;
    }
    *len_pos = (unsigned char)(qname - len_pos - 1);
    *qname++ = 0;  /* Root label */

    /* QTYPE and QCLASS */
    *qname++ = 0x00; *qname++ = 0x01;  /* Type A (IPv4) */
    *qname++ = 0x00; *qname++ = 0x01;  /* Class IN */

    size_t query_len = (size_t)(qname - query);

    /* Send query */
    if (sendto(sock, query, query_len, 0, (struct sockaddr *)&dns_addr, sizeof(dns_addr)) < 0) {
        LOG_WARN("External DNS: Failed to send query to %s", dns_server);
        close(sock);
        return -1;
    }

    /* Receive response */
    unsigned char response[512];
    ssize_t resp_len = recv(sock, response, sizeof(response), 0);
    close(sock);

    if (resp_len < (ssize_t)(sizeof(dns_header_t) + 4)) {
        LOG_WARN("External DNS: No response or response too short from %s", dns_server);
        return -1;
    }

    /* Parse response header */
    dns_header_t *resp_hdr = (dns_header_t *)response;
    uint16_t ancount = ntohs(resp_hdr->ancount);

    if (ancount == 0) {
        LOG_WARN("External DNS: No answers for %s from %s", domain, dns_server);
        return -1;
    }

    /* Skip question section - find answer section */
    unsigned char *answer = response + sizeof(dns_header_t);
    unsigned char *end = response + resp_len;

    /* Skip QNAME (encoded domain) */
    while (answer < end && *answer != 0) {
        if ((*answer & 0xC0) == 0xC0) {
            /* Compression pointer */
            answer += 2;
            break;
        }
        answer += *answer + 1;
    }
    if (*answer == 0) answer++;  /* Skip null terminator */
    answer += 4;  /* Skip QTYPE and QCLASS */

    /* Parse answer records */
    for (uint16_t i = 0; i < ancount && answer < end - 12; i++) {
        /* Skip NAME (usually compressed) */
        if ((*answer & 0xC0) == 0xC0) {
            answer += 2;
        } else {
            while (answer < end && *answer != 0) {
                answer += *answer + 1;
            }
            if (*answer == 0) answer++;
        }

        if (answer + 10 > end) break;

        uint16_t rtype = (uint16_t)((answer[0] << 8) | answer[1]);
        /* uint16_t rclass = (uint16_t)((answer[2] << 8) | answer[3]); */
        /* uint32_t ttl = (uint32_t)((answer[4] << 24) | (answer[5] << 16) | (answer[6] << 8) | answer[7]); */
        uint16_t rdlen = (uint16_t)((answer[8] << 8) | answer[9]);
        answer += 10;

        if (answer + rdlen > end) break;

        if (rtype == 1 && rdlen == 4) {
            /* A record - IPv4 address */
            snprintf(result_ip, result_size, "%d.%d.%d.%d",
                     answer[0], answer[1], answer[2], answer[3]);
            LOG_DEBUG("External DNS: Resolved %s -> %s via %s", domain, result_ip, dns_server);
            return 0;
        }

        answer += rdlen;
    }

    LOG_WARN("External DNS: No A record found for %s from %s", domain, dns_server);
    return -1;
}

/* Perform HTTPS fetch using libcurl with browser simulation
 *
 * Parameters:
 *   domain      - Domain for Host header and SNI
 *   path        - Request path
 *   origin_host - IP/hostname to connect to (NULL = use domain for DNS)
 *   retry       - Retry count for exponential backoff
 */
static reverse_proxy_response_t perform_fetch(const char *domain, const char *path,
                                               const char *origin_host, int retry) {
    reverse_proxy_response_t resp = {
        .status_code = -1,
        .body = NULL,
        .body_len = 0,
        .error = "",
        .content_type = "",
        .from_cache = false,
        .retry_count = retry
    };

    /* Determine which host to connect to */
    const char *connect_host = (origin_host && origin_host[0] != '\0') ? origin_host : domain;

#ifdef HAVE_CURL
    /* Build URL - use connect_host for actual connection */
    char url[REVERSE_PROXY_MAX_URL];
    snprintf(url, sizeof(url), "https://%s%s", connect_host, path);

    /* Initialize libcurl */
    CURL *curl = curl_easy_init();
    if (!curl) {
        snprintf(resp.error, sizeof(resp.error), "curl_easy_init failed");
        return resp;
    }

    /* Response and header buffers */
    response_buffer_t buf = { .data = NULL, .len = 0, .capacity = 0 };
    header_data_t hdr;
    memset(&hdr, 0, sizeof(hdr));  /* Zero-initialize all header fields */

    /* Build request headers */
    struct curl_slist *headers = NULL;
    struct curl_slist *tmp = NULL;

    /* Add browser-like headers
     * BUG FIX: Check curl_slist_append return values - NULL means allocation failed */
    char accept_hdr[256];
    snprintf(accept_hdr, sizeof(accept_hdr), "Accept: %s", ACCEPT_HEADER);
    tmp = curl_slist_append(headers, accept_hdr);
    if (!tmp) goto header_alloc_failed;
    headers = tmp;

    char accept_lang[128];
    snprintf(accept_lang, sizeof(accept_lang), "Accept-Language: %s", ACCEPT_LANGUAGE);
    tmp = curl_slist_append(headers, accept_lang);
    if (!tmp) goto header_alloc_failed;
    headers = tmp;

    /* Request compression */
    char accept_enc[64];
    snprintf(accept_enc, sizeof(accept_enc), "Accept-Encoding: %s", ACCEPT_ENCODING);
    tmp = curl_slist_append(headers, accept_enc);
    if (!tmp) goto header_alloc_failed;
    headers = tmp;

    /* Additional browser headers */
    tmp = curl_slist_append(headers, "Sec-Fetch-Dest: document");
    if (!tmp) goto header_alloc_failed;
    headers = tmp;

    tmp = curl_slist_append(headers, "Sec-Fetch-Mode: navigate");
    if (!tmp) goto header_alloc_failed;
    headers = tmp;

    tmp = curl_slist_append(headers, "Sec-Fetch-Site: none");
    if (!tmp) goto header_alloc_failed;
    headers = tmp;

    tmp = curl_slist_append(headers, "Sec-Fetch-User: ?1");
    if (!tmp) goto header_alloc_failed;
    headers = tmp;

    tmp = curl_slist_append(headers, "Upgrade-Insecure-Requests: 1");
    if (!tmp) goto header_alloc_failed;
    headers = tmp;

    tmp = curl_slist_append(headers, "Cache-Control: no-cache");
    if (!tmp) goto header_alloc_failed;
    headers = tmp;

    tmp = curl_slist_append(headers, "Pragma: no-cache");
    if (!tmp) goto header_alloc_failed;
    headers = tmp;

    /* Set Referer to look more legitimate */
    char referer[512];
    snprintf(referer, sizeof(referer), "Referer: https://%s/", domain);
    tmp = curl_slist_append(headers, referer);
    if (!tmp) goto header_alloc_failed;
    headers = tmp;

    /* If using origin_host, override the Host header to use original domain */
    struct curl_slist *resolve_list = NULL;
    if (origin_host && origin_host[0] != '\0') {
        char host_header[300];
        snprintf(host_header, sizeof(host_header), "Host: %s", domain);
        tmp = curl_slist_append(headers, host_header);
        if (!tmp) goto header_alloc_failed;
        headers = tmp;

        /* Use CURLOPT_RESOLVE to map domain to origin IP
         * Format: "domain:port:address" */
        char resolve_entry[512];
        snprintf(resolve_entry, sizeof(resolve_entry), "%s:443:%s", domain, origin_host);
        resolve_list = curl_slist_append(NULL, resolve_entry);

        LOG_DEBUG("Reverse-proxy (curl): Using origin %s for domain %s", origin_host, domain);
    }

    /* Configure curl with browser simulation */
    /* Build correct URL using domain (Host header will be set correctly) */
    char final_url[REVERSE_PROXY_MAX_URL];
    snprintf(final_url, sizeof(final_url), "https://%s%s", domain, path);
    curl_easy_setopt(curl, CURLOPT_URL, final_url);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, get_next_user_agent());

    /* Apply DNS override if origin_host is specified */
    if (resolve_list) {
        curl_easy_setopt(curl, CURLOPT_RESOLVE, resolve_list);
    }

    /* Timeouts with exponential backoff on retry */
    long timeout = REVERSE_PROXY_FETCH_TIMEOUT * (1 << retry);  /* Double timeout on retry */
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, timeout);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT_MS, (long)REVERSE_PROXY_CONNECT_TIMEOUT);

    /* Response handling */
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&buf);
    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, header_callback);
    curl_easy_setopt(curl, CURLOPT_HEADERDATA, (void *)&hdr);

    /* Enable automatic decompression */
    curl_easy_setopt(curl, CURLOPT_ACCEPT_ENCODING, "");  /* Accept all encodings curl supports */

    /* SSL configuration - disable verification for transparent proxying */
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);

    /* Follow redirects */
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_MAXREDIRS, 5L);

    /* HTTP/2 support if available */
#if CURL_AT_LEAST_VERSION(7, 43, 0)
    curl_easy_setopt(curl, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_2TLS);
#endif

    /* Perform fetch */
    CURLcode res = curl_easy_perform(curl);

    if (res != CURLE_OK) {
        snprintf(resp.error, sizeof(resp.error), "curl error: %s (retry %d)",
                 curl_easy_strerror(res), retry);
        LOG_WARN("Reverse-proxy fetch failed: %s", resp.error);
        free(buf.data);
        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
        return resp;
    }

    /* Get HTTP status code */
    long http_code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);

    resp.status_code = (int)http_code;
    resp.body = buf.data;
    resp.body_len = buf.len;
    snprintf(resp.content_type, sizeof(resp.content_type), "%s", hdr.content_type);

    /* Copy all security headers (CORS, CSP, etc.) */
    memcpy(&resp.headers, &hdr.security, sizeof(security_headers_t));

    LOG_DEBUG("Reverse-proxy fetch: %s -> %ld (%zu bytes, type: %s, retry: %d, CORS: %s, CSP: %s)",
              final_url, http_code, buf.len, hdr.content_type, retry,
              hdr.security.access_control_allow_origin[0] ? "yes" : "no",
              hdr.security.content_security_policy[0] ? "yes" : "no");

    curl_slist_free_all(headers);
    if (resolve_list) curl_slist_free_all(resolve_list);
    curl_easy_cleanup(curl);
    return resp;

header_alloc_failed:
    /* BUG FIX: Handle curl_slist_append allocation failure */
    snprintf(resp.error, sizeof(resp.error), "Memory allocation failed for HTTP headers");
    LOG_ERROR("Reverse-proxy: Failed to allocate HTTP headers");
    if (headers) curl_slist_free_all(headers);
    if (resolve_list) curl_slist_free_all(resolve_list);
    curl_easy_cleanup(curl);
#else
    /* ========== OpenSSL-based HTTPS fetch (no libcurl required) ========== */
    /* IMPROVED: Now with redirect following (up to 5 redirects) and origin_host support */

    char current_domain[256];   /* Domain for Host header and SNI */
    char current_path[2048];
    char current_connect[256];  /* Host to actually connect to (origin or domain) */
    int redirect_count = 0;
    const int max_redirects = 5;

    snprintf(current_domain, sizeof(current_domain), "%s", domain);
    snprintf(current_path, sizeof(current_path), "%s", path);

    /* Use origin_host for connection if specified, otherwise use domain */
    if (origin_host && origin_host[0] != '\0') {
        snprintf(current_connect, sizeof(current_connect), "%s", origin_host);
        LOG_DEBUG("Reverse-proxy (OpenSSL): Using origin %s for domain %s", origin_host, domain);
    } else {
        snprintf(current_connect, sizeof(current_connect), "%s", domain);
    }

openssl_fetch_start:
    {
        /* Build URL for logging */
        char url[REVERSE_PROXY_MAX_URL];
        snprintf(url, sizeof(url), "https://%s%s (connect: %s)", current_domain, current_path, current_connect);
        LOG_DEBUG("Reverse-proxy (OpenSSL): Fetching %s (retry %d, redirect %d)",
                  url, retry, redirect_count);

        /* DNS lookup - use current_connect (origin or domain) */
        struct hostent *he = gethostbyname(current_connect);
        if (!he) {
            snprintf(resp.error, sizeof(resp.error), "DNS lookup failed for %s", current_domain);
            LOG_WARN("Reverse-proxy: %s", resp.error);
            return resp;
        }

        /* Create TCP socket */
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) {
            snprintf(resp.error, sizeof(resp.error), "Socket creation failed");
            LOG_WARN("Reverse-proxy: %s", resp.error);
            return resp;
        }

        /* Set socket timeout */
        struct timeval tv;
        tv.tv_sec = (REVERSE_PROXY_FETCH_TIMEOUT * (1 << retry)) / 1000;
        tv.tv_usec = 0;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

        /* Connect to server */
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(443);
        memcpy(&addr.sin_addr, he->h_addr, (size_t)he->h_length);

        if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
            snprintf(resp.error, sizeof(resp.error), "TCP connect failed to %s:443", current_domain);
            LOG_WARN("Reverse-proxy: %s", resp.error);
            close(sock);
            return resp;
        }

        /* Create SSL context with browser-like settings */
        const SSL_METHOD *method = TLS_client_method();
        SSL_CTX *ctx = SSL_CTX_new(method);
        if (!ctx) {
            snprintf(resp.error, sizeof(resp.error), "SSL_CTX_new failed");
            LOG_WARN("Reverse-proxy: %s", resp.error);
            close(sock);
            return resp;
        }

        /* Browser-like TLS settings to avoid fingerprinting detection */
        SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);  /* Minimum TLS 1.2 */
        SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_COMPRESSION);

        /* Use browser-like cipher suites (Chrome order) */
        SSL_CTX_set_cipher_list(ctx,
            "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:"
            "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:"
            "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:"
            "ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305");

        /* Don't verify server certificate (we're proxying, not authenticating) */
        SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);

        /* Create SSL connection */
        SSL *ssl = SSL_new(ctx);
        SSL_set_fd(ssl, sock);

        /* CRITICAL: Set SNI (Server Name Indication) - required by most servers */
        SSL_set_tlsext_host_name(ssl, current_domain);

        /* Enable ALPN for HTTP/1.1 (helps with Cloudflare/CDN detection) */
        static const unsigned char alpn_protos[] = {
            8, 'h', 't', 't', 'p', '/', '1', '.', '1'
        };
        SSL_set_alpn_protos(ssl, alpn_protos, sizeof(alpn_protos));

        if (SSL_connect(ssl) <= 0) {
            unsigned long ssl_err = ERR_get_error();
            char err_buf[256];
            ERR_error_string_n(ssl_err, err_buf, sizeof(err_buf));
            snprintf(resp.error, sizeof(resp.error), "SSL failed with %s: %.200s", current_domain, err_buf);
            LOG_WARN("Reverse-proxy: %s", resp.error);
            SSL_free(ssl);
            SSL_CTX_free(ctx);
            close(sock);
            return resp;
        }

        /* Build HTTP request with browser-like headers */
        char request[4096];
        int req_len = snprintf(request, sizeof(request),
            "GET %s HTTP/1.1\r\n"
            "Host: %s\r\n"
            "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36\r\n"
            "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8\r\n"
            "Accept-Language: en-US,en;q=0.9\r\n"
            "Accept-Encoding: identity\r\n"
            "Connection: close\r\n"
            "Upgrade-Insecure-Requests: 1\r\n"
            "\r\n",
            current_path, current_domain);

        /* Send request */
        if (SSL_write(ssl, request, req_len) <= 0) {
            snprintf(resp.error, sizeof(resp.error), "SSL_write failed");
            LOG_WARN("Reverse-proxy: %s", resp.error);
            SSL_shutdown(ssl);
            SSL_free(ssl);
            SSL_CTX_free(ctx);
            close(sock);
            return resp;
        }

        /* Read response (max 2MB) */
        size_t max_response = 2 * 1024 * 1024;
        char *response_buf = malloc(max_response);
        if (!response_buf) {
            snprintf(resp.error, sizeof(resp.error), "Memory allocation failed");
            SSL_shutdown(ssl);
            SSL_free(ssl);
            SSL_CTX_free(ctx);
            close(sock);
            return resp;
        }

        size_t total = 0;
        int n;
        while ((n = SSL_read(ssl, response_buf + total, 4096)) > 0) {
            total += (size_t)n;
            if (total >= max_response - 4096) break;
        }
        response_buf[total] = '\0';

        /* Parse HTTP status code */
        int http_status = 0;
        if (total > 12 && strncmp(response_buf, "HTTP/", 5) == 0) {
            const char *status_start = strchr(response_buf, ' ');
            if (status_start) {
                http_status = atoi(status_start + 1);
            }
        }

        /* Handle HTTP redirects (301, 302, 303, 307, 308) */
        if ((http_status == 301 || http_status == 302 || http_status == 303 ||
             http_status == 307 || http_status == 308) && redirect_count < max_redirects) {

            /* Parse Location header */
            const char *loc = strcasestr(response_buf, "Location:");
            if (loc) {
                loc += 9;
                while (*loc == ' ' || *loc == '\t') loc++;

                char location[2048];
                size_t loc_len = 0;
                while (*loc && *loc != '\r' && *loc != '\n' && loc_len < sizeof(location) - 1) {
                    location[loc_len++] = *loc++;
                }
                location[loc_len] = '\0';

                LOG_DEBUG("Reverse-proxy (OpenSSL): Redirect %d -> %s", http_status, location);

                /* Parse the redirect URL */
                if (strncasecmp(location, "https://", 8) == 0) {
                    /* Absolute HTTPS URL */
                    const char *host_start = location + 8;
                    const char *path_start = strchr(host_start, '/');
                    if (path_start) {
                        size_t host_len = (size_t)(path_start - host_start);
                        if (host_len < sizeof(current_domain)) {
                            memcpy(current_domain, host_start, host_len);
                            current_domain[host_len] = '\0';
                            /* For redirects to new domain, use that domain for DNS */
                            snprintf(current_connect, sizeof(current_connect), "%s", current_domain);
                        }
                        snprintf(current_path, sizeof(current_path), "%s", path_start);
                    } else {
                        snprintf(current_domain, sizeof(current_domain), "%s", host_start);
                        snprintf(current_connect, sizeof(current_connect), "%s", current_domain);
                        snprintf(current_path, sizeof(current_path), "/");
                    }
                } else if (strncasecmp(location, "http://", 7) == 0) {
                    /* HTTP URL - upgrade to HTTPS */
                    const char *host_start = location + 7;
                    const char *path_start = strchr(host_start, '/');
                    if (path_start) {
                        size_t host_len = (size_t)(path_start - host_start);
                        if (host_len < sizeof(current_domain)) {
                            memcpy(current_domain, host_start, host_len);
                            current_domain[host_len] = '\0';
                            /* For redirects to new domain, use that domain for DNS */
                            snprintf(current_connect, sizeof(current_connect), "%s", current_domain);
                        }
                        snprintf(current_path, sizeof(current_path), "%s", path_start);
                    } else {
                        snprintf(current_domain, sizeof(current_domain), "%s", host_start);
                        snprintf(current_connect, sizeof(current_connect), "%s", current_domain);
                        snprintf(current_path, sizeof(current_path), "/");
                    }
                    LOG_DEBUG("Reverse-proxy (OpenSSL): Upgrading HTTP->HTTPS for %s", current_domain);
                } else if (location[0] == '/') {
                    /* Relative path - same domain, keep current_connect */
                    snprintf(current_path, sizeof(current_path), "%s", location);
                } else {
                    /* Relative path without leading slash (rare) */
                    snprintf(current_path, sizeof(current_path), "/%s", location);
                }

                /* Cleanup current connection and follow redirect */
                free(response_buf);
                SSL_shutdown(ssl);
                SSL_free(ssl);
                SSL_CTX_free(ctx);
                close(sock);

                redirect_count++;
                goto openssl_fetch_start;
            }
        }

        /* Store final status */
        resp.status_code = http_status;

        /* Parse Content-Type header */
        const char *ct = strcasestr(response_buf, "Content-Type:");
        if (ct) {
            ct += 13;
            while (*ct == ' ') ct++;
            size_t i = 0;
            while (*ct && *ct != '\r' && *ct != '\n' && i < sizeof(resp.content_type) - 1) {
                resp.content_type[i++] = *ct++;
            }
            resp.content_type[i] = '\0';
        }

        /* Find body (after \r\n\r\n) */
        const char *body = strstr(response_buf, "\r\n\r\n");
        if (body && resp.status_code > 0) {
            body += 4;
            resp.body_len = total - (size_t)(body - response_buf);
            resp.body = malloc(resp.body_len + 1);
            if (resp.body) {
                memcpy(resp.body, body, resp.body_len);
                resp.body[resp.body_len] = '\0';
            }
            LOG_DEBUG("Reverse-proxy (OpenSSL): Got %d, %zu bytes, type=%s (redirects: %d)",
                      resp.status_code, resp.body_len, resp.content_type, redirect_count);
        } else {
            snprintf(resp.error, sizeof(resp.error), "Invalid HTTP response from %s", current_domain);
            LOG_WARN("Reverse-proxy: %s", resp.error);
        }

        free(response_buf);
        SSL_shutdown(ssl);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        close(sock);
    }
#endif

    return resp;
}

/* ========== Public API ========== */

int reverse_proxy_init(size_t max_cache_size) {
    if (max_cache_size > 0) {
        g_cache.max_size = max_cache_size;
    }

    /* Initialize hash table */
    memset(g_cache.hash_table, 0, sizeof(g_cache.hash_table));

#ifdef HAVE_CURL
    /* Initialize curl (global) */
    curl_global_init(CURL_GLOBAL_DEFAULT);
    LOG_INFO("Reverse-proxy initialized: cache=%zu bytes, buckets=%d (libcurl enabled)",
             g_cache.max_size, CACHE_HASH_BUCKETS);
#else
    /* OpenSSL is always available - no extra init needed */
    LOG_INFO("Reverse-proxy initialized: cache=%zu bytes, buckets=%d (OpenSSL backend)",
             g_cache.max_size, CACHE_HASH_BUCKETS);
#endif

    return 0;
}

/* Internal fetch implementation with origin_host support */
static reverse_proxy_response_t reverse_proxy_fetch_internal(const char *domain, const char *path,
                                                              const char *origin_host) {
    if (!domain || !path) {
        reverse_proxy_response_t resp = {
            .status_code = -1,
            .body = NULL,
            .body_len = 0,
            .content_type = "",
            .from_cache = false,
            .retry_count = 0
        };
        snprintf(resp.error, sizeof(resp.error), "Invalid parameters");
        return resp;
    }

    /* Build full URL for cache lookup */
    char url[REVERSE_PROXY_MAX_URL];
    snprintf(url, sizeof(url), "https://%s%s", domain, path);
    uint32_t url_hash = fnv1a_hash_url(url);

    pthread_mutex_lock(&g_cache.lock);

    /* Check cache with O(1) hash lookup */
    reverse_proxy_cache_entry_t *cached = cache_find(url, url_hash);
    if (cached) {
        time_t now = time(NULL);
        time_t age = now - cached->cached_at;

        /* Check adaptive TTL */
        if (age > cached->ttl) {
            /* Entry expired - remove and fetch fresh */
            LOG_DEBUG("Cache EXPIRED: %s (age: %lds, ttl: %lds)", url, (long)age, (long)cached->ttl);
            lru_remove(cached);
            hash_remove(cached);
            g_cache.total_size -= cached->cache_size;
            g_cache.entry_count--;
            cache_entry_free(cached);
            g_cache.misses++;
            /* Fall through to fetch from origin */
        } else {
            /* Entry still valid */
            g_cache.hits++;
            LOG_DEBUG("Cache HIT: %s (age: %lds, ttl: %lds)", url, (long)age, (long)cached->ttl);

            /* Move to head (most recently used) */
            lru_remove(cached);
            lru_add_head(cached);

            /* Return copy
             * BUG FIX: Properly handle malloc failure - set body_len=0 if allocation fails */
            reverse_proxy_response_t resp = {
                .status_code = cached->http_status,
                .body = NULL,
                .body_len = 0,
                .from_cache = true,
                .retry_count = 0
            };

            resp.body = malloc(cached->data_len);
            if (resp.body) {
                memcpy(resp.body, cached->data, cached->data_len);
                resp.body_len = cached->data_len;
            } else {
                /* ERROR HANDLING FIX: Return error response instead of silent data loss
                 * Previous: Returned cached metadata with empty body (appeared valid but corrupt)
                 * Now: Mark as error so caller knows to handle gracefully */
                resp.status_code = -1;  /* Error indicator */
                resp.from_cache = false;
                snprintf(resp.error, sizeof(resp.error), "Memory allocation failed for cache copy (%zu bytes)", cached->data_len);
                LOG_ERROR("Cache HIT but malloc failed for %zu bytes - OOM condition", cached->data_len);
            }
            snprintf(resp.content_type, sizeof(resp.content_type), "%s", cached->content_type_header);

            pthread_mutex_unlock(&g_cache.lock);
            return resp;
        }
    } else {
        g_cache.misses++;
        LOG_DEBUG("Cache MISS: %s (entries: %d)", url, g_cache.entry_count);
    }

    pthread_mutex_unlock(&g_cache.lock);

    /* Fetch from origin with retry logic */
    reverse_proxy_response_t resp = {0};
    int retry;

    for (retry = 0; retry <= REVERSE_PROXY_MAX_RETRIES; retry++) {
        if (retry > 0) {
            /* Exponential backoff delay before retry */
            int delay_ms = REVERSE_PROXY_RETRY_DELAY_MS * (1 << (retry - 1));
            LOG_DEBUG("Retry %d after %dms delay: %s", retry, delay_ms, url);
            usleep(delay_ms * 1000);
        }

        resp = perform_fetch(domain, path, origin_host, retry);

        /* Success or non-retryable error */
        if (resp.status_code > 0) {
            break;  /* Success */
        }

        /* Check if error is retryable (timeout, connection failed) */
        if (strstr(resp.error, "Couldn't connect") ||
            strstr(resp.error, "Connection timed out") ||
            strstr(resp.error, "Operation timed out") ||
            strstr(resp.error, "SSL connect error")) {
            /* Retryable error - continue loop */
            if (retry < REVERSE_PROXY_MAX_RETRIES) {
                free(resp.body);
                resp.body = NULL;
                continue;
            }
        }

        break;  /* Non-retryable error */
    }

    resp.retry_count = retry;

    /* Cache successful response */
    if (resp.status_code > 0 && resp.status_code < 400 && resp.body) {
        pthread_mutex_lock(&g_cache.lock);
        cache_add(url, url_hash, resp.status_code, resp.body, resp.body_len, resp.content_type);
        pthread_mutex_unlock(&g_cache.lock);
    }

    return resp;
}

/* Public API: Fetch from domain (uses DNS for connection) */
reverse_proxy_response_t reverse_proxy_fetch(const char *domain, const char *path) {
    return reverse_proxy_fetch_internal(domain, path, NULL);
}

/* Public API: Fetch with specific origin (bypasses DNS) */
reverse_proxy_response_t reverse_proxy_fetch_with_origin(const char *domain, const char *path,
                                                          const char *origin_host) {
    return reverse_proxy_fetch_internal(domain, path, origin_host);
}

/* Public API: Fetch with dynamic DNS resolution via external DNS server */
reverse_proxy_response_t reverse_proxy_fetch_with_dns(const char *domain, const char *path,
                                                       const char *origin_dns) {
    if (!origin_dns || origin_dns[0] == '\0') {
        /* No external DNS specified, use local DNS */
        return reverse_proxy_fetch_internal(domain, path, NULL);
    }

    /* Resolve domain using external DNS server */
    char resolved_ip[64];
    if (resolve_via_external_dns(domain, origin_dns, resolved_ip, sizeof(resolved_ip)) == 0) {
        /* Successfully resolved - use the IP as origin */
        LOG_DEBUG("Reverse-proxy: Using dynamically resolved origin %s for %s (DNS: %s)",
                  resolved_ip, domain, origin_dns);
        return reverse_proxy_fetch_internal(domain, path, resolved_ip);
    }

    /* DNS resolution failed - fallback to local DNS */
    LOG_WARN("Reverse-proxy: External DNS resolution failed, falling back to local DNS for %s", domain);
    return reverse_proxy_fetch_internal(domain, path, NULL);
}

void reverse_proxy_free_response(reverse_proxy_response_t *resp) {
    if (resp && resp->body) {
        free(resp->body);
        resp->body = NULL;
        resp->body_len = 0;
    }
}

void reverse_proxy_clear_cache(void) {
    pthread_mutex_lock(&g_cache.lock);

    while (g_cache.head) {
        reverse_proxy_cache_entry_t *entry = g_cache.head;
        lru_remove(entry);
        hash_remove(entry);
        cache_entry_free(entry);
    }

    /* Clear hash table */
    memset(g_cache.hash_table, 0, sizeof(g_cache.hash_table));

    g_cache.total_size = 0;
    g_cache.entry_count = 0;
    g_cache.hits = 0;
    g_cache.misses = 0;

    pthread_mutex_unlock(&g_cache.lock);

    LOG_INFO("Reverse-proxy cache cleared");
}

size_t reverse_proxy_get_cache_size(void) {
    pthread_mutex_lock(&g_cache.lock);
    size_t size = g_cache.total_size;
    pthread_mutex_unlock(&g_cache.lock);
    return size;
}

void reverse_proxy_get_stats(int *hits, int *misses) {
    if (!hits || !misses) return;

    pthread_mutex_lock(&g_cache.lock);
    *hits = g_cache.hits;
    *misses = g_cache.misses;
    pthread_mutex_unlock(&g_cache.lock);
}

/* Extended stats function */
void reverse_proxy_get_extended_stats(int *hits, int *misses, int *entries, size_t *size, size_t *max_size) {
    pthread_mutex_lock(&g_cache.lock);
    if (hits) *hits = g_cache.hits;
    if (misses) *misses = g_cache.misses;
    if (entries) *entries = g_cache.entry_count;
    if (size) *size = g_cache.total_size;
    if (max_size) *max_size = g_cache.max_size;
    pthread_mutex_unlock(&g_cache.lock);
}

void reverse_proxy_shutdown(void) {
    reverse_proxy_clear_cache();
#ifdef HAVE_CURL
    curl_global_cleanup();
#endif
    LOG_INFO("Reverse-proxy shutdown");
}
