/* TLSGateNX - Security Intelligence Module
 * Copyright (C) 2025 Torsten Jahnke
 *
 * Threat detection and security logging for all incoming requests:
 * - IDN/Punycode Homograph Attack Detection (mixed Unicode scripts)
 * - Suspicious TLD Detection (.tk, .ml, .xyz, etc.)
 * - URL Entropy Analysis (random strings = suspicious)
 * - Phishing Pattern Detection
 *
 * All threats logged to syslog (LOG_AUTH facility) for external analysis.
 *
 * Output format (pipe-delimited for easy parsing):
 *   THREAT|timestamp|client_ip|full_url|threat_type|score|details
 */

#ifndef SECURITY_INTEL_H
#define SECURITY_INTEL_H

#include <stdbool.h>
#include <stdint.h>
#include <time.h>

/* Threat types detected by the security module */
typedef enum {
    THREAT_NONE = 0,
    THREAT_HOMOGRAPH,           /* IDN homograph attack (mixed scripts) */
    THREAT_SUSPICIOUS_TLD,      /* Known malicious TLD (.tk, .ml, etc.) */
    THREAT_HIGH_ENTROPY,        /* Random-looking domain (DGA suspected) */
    THREAT_PHISHING_PATTERN,    /* Known phishing URL patterns */
    THREAT_PUNYCODE_SUSPICIOUS, /* Punycode that mimics ASCII domain */
    THREAT_EXCESSIVE_SUBDOMAINS,/* Too many subdomains (evasion) */
    THREAT_IP_AS_HOST,          /* Direct IP access (bypassing DNS) */
    THREAT_DATA_EXFIL_PATTERN,  /* Long subdomains (data exfiltration) */
    THREAT_TYPOSQUAT            /* Looks like typosquatting of known brand */
} threat_type_t;

/* Unicode script categories for homograph detection */
typedef enum {
    SCRIPT_LATIN = 0,
    SCRIPT_CYRILLIC,
    SCRIPT_GREEK,
    SCRIPT_ARMENIAN,
    SCRIPT_HEBREW,
    SCRIPT_ARABIC,
    SCRIPT_THAI,
    SCRIPT_CJK,
    SCRIPT_OTHER,
    SCRIPT_ASCII,       /* Pure ASCII (a-z, 0-9, hyphen) */
    SCRIPT_COUNT
} unicode_script_t;

/* Analysis result for a single request */
typedef struct {
    bool is_threat;             /* true if any threat detected */
    threat_type_t primary_threat; /* Most severe threat type */
    uint8_t threat_score;       /* 0-100, higher = more suspicious */

    /* Detected threat flags (multiple can be set) */
    bool has_mixed_scripts;     /* Different Unicode scripts in domain */
    bool has_suspicious_tld;    /* Known bad TLD */
    bool has_high_entropy;      /* Random-looking domain */
    bool has_phishing_pattern;  /* Known phishing indicators */
    bool is_punycode;           /* Domain uses IDN encoding */
    bool is_ip_address;         /* Host is IP, not domain */

    /* Analysis details */
    char decoded_domain[512];   /* Punycode decoded to Unicode */
    char detected_scripts[128]; /* List of scripts found */
    char threat_details[256];   /* Human-readable description */

    /* For logging - NO client_ip (DSGVO compliant) */
    time_t timestamp;
    char full_url[2048];
} security_analysis_t;

/* Security module configuration */
typedef struct {
    bool enabled;               /* Master enable/disable */
    bool log_all_requests;      /* Log even non-threats (for debugging) */
    bool log_to_syslog;         /* Use syslog (LOG_AUTH) */
    bool log_to_file;           /* Also log to file */
    char log_file_path[512];    /* Path for file logging */

    uint8_t min_threat_score;   /* Minimum score to log (default: 50) */

    /* Detection toggles */
    bool detect_homograph;      /* IDN homograph attacks */
    bool detect_suspicious_tld; /* Bad TLDs */
    bool detect_entropy;        /* High entropy domains */
    bool detect_phishing;       /* Phishing patterns */
} security_config_t;

/* Statistics */
typedef struct {
    uint64_t total_analyzed;
    uint64_t threats_detected;
    uint64_t homograph_attacks;
    uint64_t suspicious_tlds;
    uint64_t high_entropy;
    uint64_t phishing_patterns;
    uint64_t punycode_domains;
} security_stats_t;

/* Initialize security intelligence module
 * @param config  Configuration (NULL for defaults)
 * @return        true on success
 */
bool security_intel_init(const security_config_t *config);

/* Set log file path (call before init, or will use default)
 * @param path  Base path without extension (e.g., "/var/log/tlsgateNG/security")
 *              Files created: path.0.log, path.1.log, ...
 */
void security_intel_set_log_path(const char *path);

/* Set log rotation configuration (call before init)
 * @param max_file_size   Max size per log file in bytes (0 = use default 100MB)
 * @param max_total_size  Max total size of all logs (0 = use default 5GB)
 * @param max_files       Max number of log files (0 = calculate from total/file size)
 */
void security_intel_set_log_config(size_t max_file_size, size_t max_total_size, int max_files);

/* Setup log directory with proper ownership (call BEFORE drop_privileges!)
 * Creates log directory if it doesn't exist and sets ownership to user:group.
 * Must be called while still running as root.
 *
 * @param user   Username for ownership (NULL = don't change)
 * @param group  Group name for ownership (NULL = use user's primary group)
 * @return       0 on success, -1 on error
 */
int security_intel_setup_log_dir(const char *user, const char *group);

/* Shutdown and cleanup */
void security_intel_shutdown(void);

/* Analyze a request for security threats (DSGVO compliant - no client IP)
 * @param host       Request host/domain
 * @param path       Request path
 * @param query      Query string (can be NULL)
 * @param result     Output: Analysis results
 * @return           true if threat detected
 */
bool security_intel_analyze(const char *host,
                            const char *path,
                            const char *query,
                            security_analysis_t *result);

/* Log a security event to syslog
 * Called automatically by security_intel_analyze() if threat detected
 * @param result  Analysis result to log
 */
void security_intel_log(const security_analysis_t *result);

/* Log any request for analysis (DSGVO compliant - no client IP)
 * @param host       Request host
 * @param path       Request path
 * @param query      Query string (can be NULL)
 * @param note       Optional note/category
 */
void security_intel_log_request(const char *host, const char *path,
                                 const char *query, const char *note);

/* Get current statistics */
void security_intel_get_stats(security_stats_t *stats);

/* Reset statistics */
void security_intel_reset_stats(void);

/* Check if a domain is IDN (Punycode encoded)
 * @param domain  Domain to check
 * @return        true if contains xn-- labels
 */
bool security_is_punycode(const char *domain);

/* Decode Punycode domain to Unicode
 * @param encoded   Punycode domain (e.g., "xn--pple-43d.com")
 * @param decoded   Output buffer for decoded domain
 * @param size      Size of output buffer
 * @return          true on success
 */
bool security_decode_punycode(const char *encoded, char *decoded, size_t size);

/* Detect Unicode script of a character
 * @param codepoint  Unicode codepoint
 * @return           Script category
 */
unicode_script_t security_detect_script(uint32_t codepoint);

/* Calculate entropy of a string (bits per character)
 * @param str  String to analyze
 * @return     Entropy value (0.0 - 8.0)
 */
double security_calculate_entropy(const char *str);

/* Check if domain looks like a typosquat of known brands
 * @param domain  Domain to check
 * @return        true if suspicious
 */
bool security_check_typosquat(const char *domain);

/* Get threat type as string */
const char* security_threat_type_str(threat_type_t type);

#endif /* SECURITY_INTEL_H */
