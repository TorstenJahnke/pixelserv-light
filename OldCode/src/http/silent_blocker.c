/*
 * silent_blocker.c - Silent Blocker Pattern Matching Implementation
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <strings.h>

#include "silent_blocker.h"

/* Default config path */
#define DEFAULT_CONFIG_PATH "/etc/tlsgateNG/silent-blocks.conf"

/* Global silent blocker instance */
static silent_blocker_t g_blocker = {
    .rules = NULL,
    .count = 0,
    .capacity = 0,
    .config_path = {0},
    .enabled = false
};

/* SHM version tracking for hot-reload */
static int g_shm_version = 0;

/* SHM cache pointer for automatic hot-reload (set via silent_blocker_set_shm_cache) */
static void *g_shm_cache = NULL;

/* ========== Utility Functions ========== */

/* Count path segments in a URL path
 *
 * Examples:
 *   "/"           → 0 segments
 *   "/a"          → 1 segment
 *   "/a/b"        → 2 segments
 *   "/a/b/c"      → 3 segments
 *   "/a/b/c/"     → 3 segments (trailing slash ignored)
 */
static int count_path_segments(const char *path) {
    if (!path || path[0] != '/') {
        return 0;
    }

    /* Empty path or just "/" */
    if (path[1] == '\0') {
        return 0;
    }

    int count = 0;
    const char *p = path + 1;  /* Skip leading / */

    while (*p) {
        if (*p == '/') {
            count++;
        }
        p++;
    }

    /* Add 1 for the final segment (after last /) */
    count++;

    return count;
}

/* Count (*) wildcards in path pattern
 *
 * Examples:
 *   "/(.*)"                    → 1
 *   "/(.*)/(.*)"               → 2
 *   "/(.*)/(.*)/(.*)"          → 3
 */
static int count_pattern_wildcards(const char *pattern) {
    int count = 0;
    const char *p = pattern;

    while (*p) {
        if (p[0] == '(' && p[1] == '*' && p[2] == ')') {
            count++;
            p += 3;
        } else {
            p++;
        }
    }

    return count;
}

/* Check if domain matches rule domain (exact or wildcard)
 *
 * Examples:
 *   domain="html-load.com", rule="html-load.com"           → true
 *   domain="sub.tracker.com", rule="*.tracker.com"         → true
 *   domain="tracker.com", rule="*.tracker.com"             → false (need subdomain!)
 *   domain="evil.tracker.com", rule="tracker.com"          → false
 */
static bool domain_matches(const char *domain, const silent_block_rule_t *rule) {
    if (!domain || !rule) {
        return false;
    }

    /* Exact match */
    if (!rule->wildcard_subdomain) {
        return strcasecmp(domain, rule->domain) == 0;
    }

    /* Wildcard subdomain: *.example.com
     * Domain must end with .example.com
     * But NOT be exactly example.com (must have subdomain!)
     */
    size_t domain_len = strlen(domain);
    size_t base_len = strlen(rule->base_domain);

    /* Domain must be longer than base (to have subdomain) */
    if (domain_len <= base_len) {
        return false;
    }

    /* Check if domain ends with .base_domain */
    if (domain_len < base_len + 1) {
        return false;
    }

    /* Must have a dot before base domain */
    if (domain[domain_len - base_len - 1] != '.') {
        return false;
    }

    /* Compare the base domain part (case-insensitive) */
    return strcasecmp(domain + (domain_len - base_len), rule->base_domain) == 0;
}

/* Trim whitespace from string (in-place) */
static void trim_whitespace(char *str) {
    if (!str) return;

    /* Trim leading whitespace */
    char *start = str;
    while (*start && isspace((unsigned char)*start)) {
        start++;
    }

    /* Trim trailing whitespace */
    size_t len = strlen(start);
    if (len == 0) {
        /* Empty string after leading trim - set to empty and return */
        if (start != str) {
            str[0] = '\0';
        }
        return;
    }

    char *end = start + len - 1;
    while (end > start && isspace((unsigned char)*end)) {
        *end = '\0';
        end--;
    }

    /* Move trimmed string to beginning */
    if (start != str) {
        memmove(str, start, strlen(start) + 1);
    }
}

/* ========== Config Parser ========== */

/* Parse a single rule line
 *
 * Format: domain path-pattern delay(ms) status [options...]
 * Options: reverse-proxy=on, origin=IP_OR_HOST, origin-dns=DNS_SERVER
 *
 * Examples:
 *   html-load.com /(*)/(*)/(*) 0 204
 *   html-load.com /(*)/(*)/(*) 0 200 reverse-proxy=on
 *   html-load.com /* 0 200 reverse-proxy=on origin=1.2.3.4
 *   html-load.com /* 0 200 reverse-proxy=on origin=origin.html-load.com
 *   html-load.com /* 0 200 reverse-proxy=on origin-dns=8.8.8.8
 *
 * Returns: 0 on success, -1 on parse error
 */
static int parse_rule_line(const char *line, silent_block_rule_t *rule) {
    char domain[256];
    char pattern[512];
    int delay;
    int status;
    char extra1[256] = "";
    char extra2[256] = "";
    char extra3[256] = "";

    /* Parse line (whitespace-separated) - up to 7 fields */
    int parsed = sscanf(line, "%255s %511s %d %d %255s %255s %255s",
                        domain, pattern, &delay, &status, extra1, extra2, extra3);

    if (parsed < 4) {
        return -1;  /* Invalid format */
    }

    /* Validate status code */
    if (status < 100 || status > 599) {
        return -1;
    }

    /* Validate delay */
    if (delay < 0) {
        return -1;
    }

    /* Parse domain (check for wildcard) */
    memset(rule, 0, sizeof(*rule));

    if (strncmp(domain, "*.", 2) == 0) {
        /* Wildcard subdomain: *.example.com */
        rule->wildcard_subdomain = true;
        /* FIX: Use snprintf instead of strncpy to avoid truncation warnings */
        snprintf(rule->base_domain, sizeof(rule->base_domain), "%s", domain + 2);
        snprintf(rule->domain, sizeof(rule->domain), "%s", domain);
    } else {
        /* Exact domain */
        rule->wildcard_subdomain = false;
        /* FIX: Use snprintf instead of strncpy to avoid truncation warnings */
        snprintf(rule->domain, sizeof(rule->domain), "%s", domain);
        rule->base_domain[0] = '\0';
    }

    /* Parse path pattern */
    /* FIX: Use snprintf instead of strncpy to avoid truncation warnings */
    snprintf(rule->path_pattern, sizeof(rule->path_pattern), "%s", pattern);

    /* Special case: slash-asterisk means match ALL paths (wildcard) */
    if (strcmp(pattern, "/*") == 0) {
        rule->segment_count = -1;  /* -1 = match any path */
    } else {
        rule->segment_count = count_pattern_wildcards(pattern);
    }

    /* Store delay and status */
    rule->delay_ms = delay;
    rule->status_code = status;

    /* Parse optional parameters: reverse-proxy=on, origin=xxx, origin-dns=xxx */
    rule->reverse_proxy = false;
    rule->origin_host[0] = '\0';
    rule->origin_dns[0] = '\0';

    /* Helper to parse an option field */
    const char *extras[] = { extra1, extra2, extra3 };
    for (int i = 0; i < 3; i++) {
        const char *opt = extras[i];
        if (opt[0] == '\0') continue;

        if (strcasecmp(opt, "reverse-proxy=on") == 0) {
            rule->reverse_proxy = true;
        } else if (strncasecmp(opt, "origin=", 7) == 0) {
            snprintf(rule->origin_host, sizeof(rule->origin_host), "%s", opt + 7);
        } else if (strncasecmp(opt, "origin-dns=", 11) == 0) {
            snprintf(rule->origin_dns, sizeof(rule->origin_dns), "%s", opt + 11);
        }
    }

    return 0;
}

/* Load config file and parse all rules */
static int load_config_file(const char *config_path) {
    FILE *fp = fopen(config_path, "r");
    if (!fp) {
        /* Config file doesn't exist - not an error, just disabled */
        fprintf(stderr, "Silent blocker: Config file not found (%s), disabled\n", config_path);
        g_blocker.enabled = false;
        return 0;
    }

    /* Allocate initial rule array */
    g_blocker.capacity = 128;
    g_blocker.rules = malloc(sizeof(silent_block_rule_t) * g_blocker.capacity);
    if (!g_blocker.rules) {
        fclose(fp);
        return -1;
    }

    g_blocker.count = 0;

    char line[1024];
    int line_num = 0;

    while (fgets(line, sizeof(line), fp)) {
        line_num++;

        /* Trim whitespace */
        trim_whitespace(line);

        /* Skip empty lines and comments */
        if (line[0] == '\0' || line[0] == '#') {
            continue;
        }

        /* Check capacity */
        if (g_blocker.count >= SILENT_BLOCKER_MAX_RULES) {
            fprintf(stderr, "Silent blocker: Maximum rules (%d) reached, ignoring rest\n",
                    SILENT_BLOCKER_MAX_RULES);
            break;
        }

        /* Resize array if needed */
        if (g_blocker.count >= g_blocker.capacity) {
            int new_capacity = g_blocker.capacity * 2;
            if (new_capacity > SILENT_BLOCKER_MAX_RULES) {
                new_capacity = SILENT_BLOCKER_MAX_RULES;
            }

            silent_block_rule_t *new_rules = realloc(g_blocker.rules,
                sizeof(silent_block_rule_t) * new_capacity);
            if (!new_rules) {
                fprintf(stderr, "Silent blocker: Failed to resize rule array\n");
                break;
            }

            g_blocker.rules = new_rules;
            g_blocker.capacity = new_capacity;
        }

        /* Parse rule */
        silent_block_rule_t rule;
        if (parse_rule_line(line, &rule) == 0) {
            g_blocker.rules[g_blocker.count] = rule;
            g_blocker.count++;
        } else {
            fprintf(stderr, "Silent blocker: Parse error at line %d: %s\n", line_num, line);
        }
    }

    /* SECURITY FIX: Check for I/O errors during file reading */
    if (ferror(fp)) {
        fprintf(stderr, "Silent blocker: I/O error reading config file: %s\n", config_path);
        fclose(fp);
        return -1;
    }

    fclose(fp);

    fprintf(stderr, "Silent blocker: Loaded %d rules from %s\n",
            g_blocker.count, config_path);

    g_blocker.enabled = (g_blocker.count > 0);

    return 0;
}

/* ========== Public API ========== */

int silent_blocker_init(const char *config_path) {
    /* Use default path if not specified */
    if (!config_path) {
        config_path = DEFAULT_CONFIG_PATH;
    }

    /* Store config path for reload
     * CODE QUALITY FIX: Use snprintf instead of strncpy (strncpy is deprecated pattern)
     * snprintf automatically handles NULL-termination */
    snprintf(g_blocker.config_path, sizeof(g_blocker.config_path), "%s", config_path);

    /* Load config file */
    return load_config_file(config_path);
}

silent_block_result_t silent_blocker_check(const char *host, const char *path) {
    silent_block_result_t result = {
        .matched = false,
        .delay_ms = 0,
        .status_code = 200,
        .reverse_proxy = false,
        .origin_host = "",
        .origin_dns = ""
    };

    /* Not enabled or no rules */
    if (!g_blocker.enabled || g_blocker.count == 0) {
        return result;
    }

    if (!host || !path) {
        return result;
    }

    /* Count segments in request path */
    int path_segments = count_path_segments(path);

    /* Check all rules (first match wins) */
    for (int i = 0; i < g_blocker.count; i++) {
        const silent_block_rule_t *rule = &g_blocker.rules[i];

        /* Check domain match */
        if (!domain_matches(host, rule)) {
            continue;
        }

        /* Check path segment count
         * segment_count == -1 means wildcard (match ALL paths)
         * Otherwise EXACT match required */
        if (rule->segment_count != -1 && path_segments != rule->segment_count) {
            continue;
        }

        /* MATCH! */
        result.matched = true;
        result.delay_ms = rule->delay_ms;
        result.status_code = rule->status_code;
        result.reverse_proxy = rule->reverse_proxy;

        /* Copy origin host if specified (for reverse proxy to bypass DNS) */
        if (rule->origin_host[0] != '\0') {
            snprintf(result.origin_host, sizeof(result.origin_host), "%s", rule->origin_host);
        }

        /* Copy origin DNS server if specified (for dynamic resolution via external DNS) */
        if (rule->origin_dns[0] != '\0') {
            snprintf(result.origin_dns, sizeof(result.origin_dns), "%s", rule->origin_dns);
        }

        return result;
    }

    return result;
}

int silent_blocker_reload(void) {
    /* Free old rules */
    if (g_blocker.rules) {
        free(g_blocker.rules);
        g_blocker.rules = NULL;
        g_blocker.count = 0;
        g_blocker.capacity = 0;
    }

    /* Reload config */
    return load_config_file(g_blocker.config_path);
}

void silent_blocker_free(void) {
    if (g_blocker.rules) {
        free(g_blocker.rules);
        g_blocker.rules = NULL;
    }

    g_blocker.count = 0;
    g_blocker.capacity = 0;
    g_blocker.enabled = false;
}

int silent_blocker_get_rule_count(void) {
    return g_blocker.count;
}

bool silent_blocker_is_enabled(void) {
    return g_blocker.enabled;
}

/* Load rules from SHM data buffer */
static int load_from_shm_data(const char *data, int data_len) {
    if (!data || data_len <= 0) {
        g_blocker.enabled = false;
        return 0;
    }

    /* Free old rules */
    if (g_blocker.rules) {
        free(g_blocker.rules);
        g_blocker.rules = NULL;
        g_blocker.count = 0;
        g_blocker.capacity = 0;
    }

    /* Allocate initial rule array */
    g_blocker.capacity = 128;
    g_blocker.rules = malloc(sizeof(silent_block_rule_t) * g_blocker.capacity);
    if (!g_blocker.rules) {
        return -1;
    }

    g_blocker.count = 0;

    /* Parse data line by line */
    char line[1024];
    const char *p = data;
    const char *end = data + data_len;
    int line_num = 0;

    while (p < end) {
        line_num++;

        /* Find end of line */
        const char *line_end = p;
        while (line_end < end && *line_end != '\n') {
            line_end++;
        }

        /* Copy line to buffer */
        size_t line_len = (size_t)(line_end - p);
        if (line_len >= sizeof(line)) {
            line_len = sizeof(line) - 1;
        }

        memcpy(line, p, line_len);
        line[line_len] = '\0';

        /* Move to next line */
        p = (line_end < end) ? line_end + 1 : end;

        /* Trim whitespace */
        trim_whitespace(line);

        /* Skip empty lines and comments */
        if (line[0] == '\0' || line[0] == '#') {
            continue;
        }

        /* Check capacity */
        if (g_blocker.count >= SILENT_BLOCKER_MAX_RULES) {
            fprintf(stderr, "Silent blocker (SHM): Maximum rules (%d) reached\n",
                    SILENT_BLOCKER_MAX_RULES);
            break;
        }

        /* Resize array if needed */
        if (g_blocker.count >= g_blocker.capacity) {
            int new_capacity = g_blocker.capacity * 2;
            if (new_capacity > SILENT_BLOCKER_MAX_RULES) {
                new_capacity = SILENT_BLOCKER_MAX_RULES;
            }

            silent_block_rule_t *new_rules = realloc(g_blocker.rules,
                sizeof(silent_block_rule_t) * (size_t)new_capacity);
            if (!new_rules) {
                fprintf(stderr, "Silent blocker (SHM): Failed to resize rule array\n");
                break;
            }

            g_blocker.rules = new_rules;
            g_blocker.capacity = new_capacity;
        }

        /* Parse rule */
        silent_block_rule_t rule;
        if (parse_rule_line(line, &rule) == 0) {
            g_blocker.rules[g_blocker.count] = rule;
            g_blocker.count++;
        }
    }

    fprintf(stderr, "Silent blocker: Loaded %d rules from SHM\n", g_blocker.count);
    g_blocker.enabled = (g_blocker.count > 0);

    return 0;
}

int silent_blocker_init_from_shm(const char *data, int data_len, int version) {
    int result = load_from_shm_data(data, data_len);
    if (result == 0) {
        g_shm_version = version;
    }
    return result;
}

int silent_blocker_get_shm_version(void) {
    return g_shm_version;
}

void silent_blocker_set_shm_cache(void *cache) {
    g_shm_cache = cache;
}

/* Include SHM manager for hot-reload support */
#include "../ipc/shm_manager.h"

bool silent_blocker_check_and_reload_from_shm(void) {
    /* No SHM cache configured - nothing to do */
    if (!g_shm_cache) {
        return false;
    }

    /* RACE CONDITION FIX: Get data and version atomically
     * Previous code checked version, then got data separately.
     * Poolgen could update version between these two operations.
     * Now we get data+version together, ensuring consistency. */
    int sb_len = 0, sb_version = 0;
    const char *sb_data = certcache_shm_get_silentblock_data(
        (const certcache_shm_t *)g_shm_cache, &sb_len, &sb_version);

    /* Now check if version changed (using version from get_data call) */
    if (!silent_blocker_needs_reload(g_shm_version, sb_version)) {
        return false;  /* No change */
    }

    /* Version changed - reload from SHM */
    fprintf(stderr, "Silent blocker: Hot-reload detected (version %d -> %d)\n",
            g_shm_version, sb_version);

    if (sb_data && sb_len > 0) {
        if (load_from_shm_data(sb_data, sb_len) == 0) {
            g_shm_version = sb_version;
            fprintf(stderr, "Silent blocker: Hot-reload complete (%d rules, version %d)\n",
                    g_blocker.count, sb_version);
            return true;
        } else {
            fprintf(stderr, "Silent blocker: Hot-reload failed to parse data\n");
        }
    } else {
        /* SHM data cleared - disable silent blocker */
        if (g_blocker.rules) {
            free(g_blocker.rules);
            g_blocker.rules = NULL;
            g_blocker.count = 0;
            g_blocker.capacity = 0;
        }
        g_blocker.enabled = false;
        g_shm_version = sb_version;
        fprintf(stderr, "Silent blocker: Hot-reload - disabled (no rules in SHM)\n");
        return true;
    }

    return false;
}
