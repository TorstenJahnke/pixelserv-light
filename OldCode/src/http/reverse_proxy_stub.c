/*
 * reverse_proxy_stub.c - Stub functions for Reverse Proxy (when curl is unavailable)
 * This provides dummy implementations so the code compiles without libcurl
 */

#include "reverse_proxy.h"
#include "../util/logger.h"
#include <string.h>
#include <stdlib.h>

/* Stub implementation - reverse proxy disabled */
int reverse_proxy_init(size_t max_cache_size) {
    (void)max_cache_size;  /* Unused parameter - intentional stub */
    LOG_WARN("Reverse-proxy: libcurl not available - disabled");
    return 0;
}

reverse_proxy_response_t reverse_proxy_fetch(const char *domain, const char *path) {
    (void)domain;  /* Unused parameter - intentional stub */
    (void)path;    /* Unused parameter - intentional stub */
    reverse_proxy_response_t resp = {
        .status_code = -1,
        .body = NULL,
        .body_len = 0,
    };
    strncpy(resp.error, "reverse_proxy disabled (no curl)", sizeof(resp.error) - 1);
    return resp;
}

void reverse_proxy_free_response(reverse_proxy_response_t *resp) {
    if (resp && resp->body) {
        free(resp->body);
        resp->body = NULL;
        resp->body_len = 0;
    }
}

void reverse_proxy_clear_cache(void) {
    /* No-op */
}

void reverse_proxy_print_stats(void) {
    /* No-op */
}
