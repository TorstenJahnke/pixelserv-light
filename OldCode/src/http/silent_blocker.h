/*
 * silent_blocker.h - Silent Blocker Pattern Matching
 *
 * Based on Mokku's Hard2Block approach
 *
 * URL pattern matching with exact segment count and configurable responses.
 * Config file format: domain path-pattern delay(ms) status
 *
 * Example:
 *   html-load.com /(*)/(*)/(*) 0 204
 *   *.tracker.com /(*) 50 200
 */

#ifndef SILENT_BLOCKER_H
#define SILENT_BLOCKER_H

#include <stdbool.h>

/* Maximum number of rules supported */
#define SILENT_BLOCKER_MAX_RULES 1024

/* Single blocking rule */
typedef struct {
    char domain[256];           /* Domain: "example.com" or "*.example.com" */
    char path_pattern[512];     /* Path pattern: /(*)/(*)/(*) */
    int segment_count;          /* Number of (*) wildcards = exact segments required */
    int delay_ms;               /* Delay before response (0 = instant) */
    int status_code;            /* HTTP status code (200, 204, etc.) */
    bool wildcard_subdomain;    /* true if domain starts with "*." */
    char base_domain[256];      /* For *.example.com: stores "example.com" */
    bool reverse_proxy;         /* true if reverse-proxy=on (fetch from origin) */
    char origin_host[256];      /* Origin server IP/host for reverse proxy (bypasses DNS) */
    char origin_dns[64];        /* External DNS server for dynamic origin resolution (e.g., "8.8.8.8") */
} silent_block_rule_t;

/* Result of pattern matching */
typedef struct {
    bool matched;               /* true if pattern matched */
    int delay_ms;               /* Delay to apply (milliseconds) */
    int status_code;            /* HTTP status code to return */
    bool reverse_proxy;         /* true if reverse-proxy=on (fetch from origin) */
    char origin_host[256];      /* Origin server IP/host (bypasses DNS if set) */
    char origin_dns[64];        /* External DNS server for dynamic resolution (e.g., "8.8.8.8") */
} silent_block_result_t;

/* Global silent blocker state */
typedef struct {
    silent_block_rule_t *rules; /* Array of rules */
    int count;                  /* Number of loaded rules */
    int capacity;               /* Allocated capacity */
    char config_path[512];      /* Path to config file */
    bool enabled;               /* Is silent blocker enabled? */
} silent_blocker_t;

/* Initialize silent blocker and load config file
 *
 * Parameters:
 *   config_path - Path to silent-blocks.conf file
 *                 NULL = use default /etc/tlsgateNG/silent-blocks.conf
 *
 * Returns:
 *   0 on success
 *   -1 on error (config file not found, parse error, etc.)
 *
 * Note: If config file doesn't exist, silent blocker is disabled (not an error)
 */
int silent_blocker_init(const char *config_path);

/* Initialize silent blocker from SHM data (used with Poolgen)
 *
 * Workers use this to load rules from shared memory instead of file.
 * The data format is the same as the config file.
 *
 * Parameters:
 *   data     - Pointer to SHM data (same format as config file)
 *   data_len - Length of data in bytes
 *   version  - SHM version for hot-reload tracking
 *
 * Returns:
 *   0 on success
 *   -1 on error
 */
int silent_blocker_init_from_shm(const char *data, int data_len, int version);

/* Check if SHM version changed (for hot-reload)
 *
 * Workers call this periodically to detect if Poolgen reloaded the rules.
 * If version changed, worker should call silent_blocker_init_from_shm() again.
 *
 * Parameters:
 *   current_version - The version from last init_from_shm call
 *   new_version     - The current SHM version (from certcache_shm_silentblock_version)
 *
 * Returns:
 *   true if version changed (reload needed), false otherwise
 */
static inline bool silent_blocker_needs_reload(int current_version, int new_version) {
    return current_version != new_version;
}

/* Get last loaded SHM version (for hot-reload tracking) */
int silent_blocker_get_shm_version(void);

/* Set SHM cache pointer for hot-reload (called once after SHM init)
 *
 * Workers call this to enable automatic hot-reload when Poolgen
 * updates the silent-block rules via SIGHUP.
 *
 * Parameters:
 *   cache - Pointer to certcache_shm_t (or NULL to disable SHM-based reload)
 */
void silent_blocker_set_shm_cache(void *cache);

/* Check and reload from SHM if version changed
 *
 * Call this periodically (e.g., before each request check) to detect
 * if Poolgen has updated the rules. If version changed, rules are
 * automatically reloaded from SHM.
 *
 * Returns:
 *   true if rules were reloaded, false if no change
 */
bool silent_blocker_check_and_reload_from_shm(void);

/* Check if request matches any blocking rule
 *
 * Parameters:
 *   host - Request host/domain (e.g., "html-load.com", "sub.tracker.com")
 *   path - Request path (e.g., "/a/b/c", "/track/pixel")
 *
 * Returns:
 *   silent_block_result_t with:
 *     matched = true if rule matched, false otherwise
 *     delay_ms = delay to apply before response
 *     status_code = HTTP status code to return
 *
 * Note: First matching rule wins (order matters!)
 */
silent_block_result_t silent_blocker_check(const char *host, const char *path);

/* Reload config file at runtime
 *
 * Useful for SIGHUP handler to reload rules without restart.
 *
 * Returns:
 *   0 on success
 *   -1 on error
 */
int silent_blocker_reload(void);

/* Free all resources */
void silent_blocker_free(void);

/* Get number of loaded rules (for debugging/stats) */
int silent_blocker_get_rule_count(void);

/* Check if silent blocker is enabled */
bool silent_blocker_is_enabled(void);

#endif /* SILENT_BLOCKER_H */
