/* TLSGateNX - Security Intelligence Implementation
 * Copyright (C) 2025 Torsten Jahnke
 */

#include "security_intel.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <math.h>
#include <stdatomic.h>
#include <syslog.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <sys/stat.h>
#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <unistd.h>
#include <pwd.h>
#include <grp.h>

/* Module state */
static security_config_t g_config;
static security_stats_t g_stats;
static _Atomic bool g_initialized = false;

/* Log rotation settings - configurable via security_intel_set_log_config() */
static size_t g_log_max_file_size = 100 * 1024 * 1024;          /* 100 MB per file (default) */
static size_t g_log_max_total_size = 5ULL * 1024 * 1024 * 1024; /* 5 GB total (default) */
static int g_log_max_files = 0;                                  /* 0 = use total_size / file_size */

static FILE *g_log_file = NULL;
#define LOG_BASE_PATH_MAX 512
#define LOG_FULL_PATH_MAX 1024  /* base + "/" + name + ".NNN.log" */
static char g_log_base_path[LOG_BASE_PATH_MAX] = "/var/log/tlsgateNG/security";
static int g_current_log_num = 0;
static size_t g_current_log_size = 0;
static pthread_mutex_t g_log_mutex = PTHREAD_MUTEX_INITIALIZER;

/* Calculate effective max files */
static int get_max_files(void) {
    if (g_log_max_files > 0) {
        return g_log_max_files;
    }
    /* Calculate from total_size / file_size */
    if (g_log_max_file_size > 0) {
        return (int)(g_log_max_total_size / g_log_max_file_size);
    }
    return 50;  /* Fallback */
}

/* ============================================================================
 * LOG ROTATION - 100MB per file, max 20GB total (200 files)
 * ============================================================================ */

/* Create log directory if needed */
static void ensure_log_dir(void) {
    char dir[LOG_FULL_PATH_MAX];
    snprintf(dir, sizeof(dir), "%s", g_log_base_path);

    char *last_slash = strrchr(dir, '/');
    if (last_slash) {
        *last_slash = '\0';
        mkdir(dir, 0755);  /* Ignore error if exists */
    }
}

/* Find next available log number */
static int find_next_log_num(void) {
    char dir[LOG_FULL_PATH_MAX];
    snprintf(dir, sizeof(dir), "%s", g_log_base_path);

    char *last_slash = strrchr(dir, '/');
    if (!last_slash) return 0;

    char *basename = last_slash + 1;
    *last_slash = '\0';

    DIR *d = opendir(dir);
    if (!d) return 0;

    int max_num = -1;
    struct dirent *entry;

    while ((entry = readdir(d))) {
        if (strncmp(entry->d_name, basename, strlen(basename)) == 0) {
            /* Parse number from filename: security.123.log */
            const char *numstart = entry->d_name + strlen(basename);
            if (*numstart == '.') {
                int num = atoi(numstart + 1);
                if (num > max_num) max_num = num;
            }
        }
    }

    closedir(d);
    return max_num + 1;
}

/* Delete oldest log files if total exceeds limit */
static void cleanup_old_logs(void) {
    char dir[LOG_FULL_PATH_MAX];
    snprintf(dir, sizeof(dir), "%s", g_log_base_path);

    char *last_slash = strrchr(dir, '/');
    if (!last_slash) return;

    char *basename = last_slash + 1;
    *last_slash = '\0';

    /* Count files and find oldest */
    DIR *d = opendir(dir);
    if (!d) return;

    int file_count = 0;
    int min_num = INT32_MAX;
    struct dirent *entry;

    while ((entry = readdir(d))) {
        if (strncmp(entry->d_name, basename, strlen(basename)) == 0) {
            const char *numstart = entry->d_name + strlen(basename);
            if (*numstart == '.') {
                file_count++;
                int num = atoi(numstart + 1);
                if (num < min_num) min_num = num;
            }
        }
    }
    closedir(d);

    /* Delete oldest files if over limit */
    int max_files = get_max_files();
    while (file_count >= max_files) {
        char old_path[LOG_FULL_PATH_MAX * 2];  /* Extra space for dir + "/" + basename + ".NNN.log" */
        snprintf(old_path, sizeof(old_path), "%s/%s.%d.log", dir, basename, min_num);
        if (unlink(old_path) == 0) {
            file_count--;
            min_num++;
        } else {
            break;  /* Can't delete, stop trying */
        }
    }
}

/* Rotate log file - MUST be called with g_log_mutex held! */
static void rotate_log_file_locked(void) {
    if (g_log_file) {
        fclose(g_log_file);
        g_log_file = NULL;
    }

    ensure_log_dir();
    cleanup_old_logs();

    g_current_log_num = find_next_log_num();

    char path[LOG_FULL_PATH_MAX];
    snprintf(path, sizeof(path), "%s.%d.log", g_log_base_path, g_current_log_num);

    g_log_file = fopen(path, "a");
    g_current_log_size = 0;

    if (g_log_file) {
        fseek(g_log_file, 0, SEEK_END);
        g_current_log_size = ftell(g_log_file);
    }
}

/* Write to log with rotation check - thread-safe */
static void log_write(const char *line) {
    pthread_mutex_lock(&g_log_mutex);

    /* Open log file if needed */
    if (!g_log_file) {
        ensure_log_dir();
        g_current_log_num = find_next_log_num();
        char path[LOG_FULL_PATH_MAX];
        snprintf(path, sizeof(path), "%s.%d.log", g_log_base_path, g_current_log_num);
        g_log_file = fopen(path, "a");
        if (g_log_file) {
            fseek(g_log_file, 0, SEEK_END);
            g_current_log_size = ftell(g_log_file);
        }
    }

    if (g_log_file) {
        size_t len = strlen(line);
        fprintf(g_log_file, "%s\n", line);
        fflush(g_log_file);
        g_current_log_size += len + 1;

        /* Rotate if size exceeded - do it inside mutex to avoid race! */
        if (g_current_log_size >= g_log_max_file_size) {
            rotate_log_file_locked();
        }
    }

    pthread_mutex_unlock(&g_log_mutex);
}

/* ============================================================================
 * THREAT DETECTION DATA
 * ============================================================================ */

/* Suspicious TLDs - known for abuse */
static const char *suspicious_tlds[] = {
    /* Free/cheap TLDs heavily abused */
    "tk", "ml", "ga", "cf", "gq",           /* Freenom free TLDs */
    "top", "xyz", "club", "online", "site", /* Cheap gTLDs */
    "icu", "buzz", "monster", "rest",
    "cam", "click", "link", "win", "loan",
    "work", "party", "date", "stream",
    "download", "racing", "review", "trade",
    "webcam", "bid", "cricket", "science",
    "accountant", "faith", "gdn",

    /* Country TLDs with weak policies */
    "ws", "cc", "pw", "su", "to",

    NULL  /* Terminator */
};

/* Known brand domains for typosquatting detection */
static const char *known_brands[] = {
    "google", "facebook", "amazon", "apple", "microsoft",
    "paypal", "netflix", "instagram", "twitter", "linkedin",
    "ebay", "yahoo", "gmail", "outlook", "dropbox",
    "chase", "wellsfargo", "bankofamerica", "citibank",
    "dhl", "fedex", "ups", "usps",
    NULL
};

/* Homograph confusables - characters that look alike across scripts */
static const struct {
    uint32_t codepoint;
    char ascii_lookalike;
    const char *script;
} confusables[] = {
    /* Cyrillic confusables */
    {0x0430, 'a', "Cyrillic"},  /* а */
    {0x0441, 'c', "Cyrillic"},  /* с */
    {0x0435, 'e', "Cyrillic"},  /* е */
    {0x043E, 'o', "Cyrillic"},  /* о */
    {0x0440, 'p', "Cyrillic"},  /* р */
    {0x0445, 'x', "Cyrillic"},  /* х */
    {0x0443, 'y', "Cyrillic"},  /* у */
    {0x0456, 'i', "Cyrillic"},  /* і */
    {0x0458, 'j', "Cyrillic"},  /* ј */
    {0x04BB, 'h', "Cyrillic"},  /* һ */

    /* Greek confusables */
    {0x03B1, 'a', "Greek"},     /* α */
    {0x03B5, 'e', "Greek"},     /* ε */
    {0x03B9, 'i', "Greek"},     /* ι */
    {0x03BF, 'o', "Greek"},     /* ο */
    {0x03C1, 'p', "Greek"},     /* ρ */
    {0x03C5, 'u', "Greek"},     /* υ */
    {0x03C9, 'w', "Greek"},     /* ω */

    {0, 0, NULL}  /* Terminator */
};

/* Punycode decoding constants */
#define PUNYCODE_BASE 36
#define PUNYCODE_TMIN 1
#define PUNYCODE_TMAX 26
#define PUNYCODE_SKEW 38
#define PUNYCODE_DAMP 700
#define PUNYCODE_INITIAL_BIAS 72
#define PUNYCODE_INITIAL_N 128

/* UTF-8 decoding helper */
static int utf8_decode(const char **str, uint32_t *codepoint) {
    const unsigned char *s = (const unsigned char *)*str;

    if (*s == 0) return 0;

    if (*s < 0x80) {
        *codepoint = *s;
        *str += 1;
        return 1;
    } else if ((*s & 0xE0) == 0xC0) {
        *codepoint = (*s & 0x1F) << 6 | (s[1] & 0x3F);
        *str += 2;
        return 2;
    } else if ((*s & 0xF0) == 0xE0) {
        *codepoint = (*s & 0x0F) << 12 | (s[1] & 0x3F) << 6 | (s[2] & 0x3F);
        *str += 3;
        return 3;
    } else if ((*s & 0xF8) == 0xF0) {
        *codepoint = (*s & 0x07) << 18 | (s[1] & 0x3F) << 12 | (s[2] & 0x3F) << 6 | (s[3] & 0x3F);
        *str += 4;
        return 4;
    }

    return 0;
}

/* Detect Unicode script of a codepoint */
unicode_script_t security_detect_script(uint32_t cp) {
    /* ASCII */
    if (cp < 0x80) return SCRIPT_ASCII;

    /* Latin Extended */
    if ((cp >= 0x0080 && cp <= 0x024F) ||  /* Latin Extended A/B */
        (cp >= 0x1E00 && cp <= 0x1EFF))    /* Latin Extended Additional */
        return SCRIPT_LATIN;

    /* Cyrillic */
    if ((cp >= 0x0400 && cp <= 0x04FF) ||  /* Cyrillic */
        (cp >= 0x0500 && cp <= 0x052F))    /* Cyrillic Supplement */
        return SCRIPT_CYRILLIC;

    /* Greek */
    if (cp >= 0x0370 && cp <= 0x03FF)
        return SCRIPT_GREEK;

    /* Armenian */
    if (cp >= 0x0530 && cp <= 0x058F)
        return SCRIPT_ARMENIAN;

    /* Hebrew */
    if (cp >= 0x0590 && cp <= 0x05FF)
        return SCRIPT_HEBREW;

    /* Arabic */
    if ((cp >= 0x0600 && cp <= 0x06FF) ||
        (cp >= 0x0750 && cp <= 0x077F))
        return SCRIPT_ARABIC;

    /* Thai */
    if (cp >= 0x0E00 && cp <= 0x0E7F)
        return SCRIPT_THAI;

    /* CJK */
    if ((cp >= 0x4E00 && cp <= 0x9FFF) ||   /* CJK Unified */
        (cp >= 0x3400 && cp <= 0x4DBF) ||   /* CJK Extension A */
        (cp >= 0x3040 && cp <= 0x309F) ||   /* Hiragana */
        (cp >= 0x30A0 && cp <= 0x30FF) ||   /* Katakana */
        (cp >= 0xAC00 && cp <= 0xD7AF))     /* Hangul */
        return SCRIPT_CJK;

    return SCRIPT_OTHER;
}

/* Check for mixed scripts (homograph attack indicator) */
static bool check_mixed_scripts(const char *domain, char *detected_scripts, size_t det_size) {
    bool scripts_found[SCRIPT_COUNT] = {false};
    int script_count = 0;
    const char *p = domain;
    uint32_t cp;

    while (utf8_decode(&p, &cp) > 0) {
        if (cp == '.' || cp == '-') continue;  /* Skip separators */

        unicode_script_t script = security_detect_script(cp);
        if (!scripts_found[script]) {
            scripts_found[script] = true;
            script_count++;
        }
    }

    /* Build detected scripts string */
    detected_scripts[0] = '\0';
    const char *script_names[] = {
        "Latin", "Cyrillic", "Greek", "Armenian", "Hebrew",
        "Arabic", "Thai", "CJK", "Other", "ASCII"
    };
    for (int i = 0; i < SCRIPT_COUNT; i++) {
        if (scripts_found[i]) {
            if (detected_scripts[0] != '\0')
                strncat(detected_scripts, ",", det_size - strlen(detected_scripts) - 1);
            strncat(detected_scripts, script_names[i], det_size - strlen(detected_scripts) - 1);
        }
    }

    /* Mixed if ASCII/Latin + another non-ASCII script */
    bool has_latin = scripts_found[SCRIPT_ASCII] || scripts_found[SCRIPT_LATIN];
    bool has_other = scripts_found[SCRIPT_CYRILLIC] || scripts_found[SCRIPT_GREEK] ||
                     scripts_found[SCRIPT_ARMENIAN] || scripts_found[SCRIPT_HEBREW] ||
                     scripts_found[SCRIPT_ARABIC];

    return has_latin && has_other;
}

/* Check for confusable characters */
static bool check_confusables(const char *domain, char *details, size_t det_size) {
    const char *p = domain;
    uint32_t cp;
    bool found = false;

    while (utf8_decode(&p, &cp) > 0) {
        for (int i = 0; confusables[i].codepoint != 0; i++) {
            if (cp == confusables[i].codepoint) {
                if (!found) {
                    snprintf(details, det_size, "Confusable: U+%04X looks like '%c' (%s)",
                             cp, confusables[i].ascii_lookalike, confusables[i].script);
                    found = true;
                }
            }
        }
    }

    return found;
}

/* Check if domain is Punycode */
bool security_is_punycode(const char *domain) {
    return strstr(domain, "xn--") != NULL;
}

/* Simple Punycode decode (single label) */
static bool punycode_decode_label(const char *encoded, uint32_t *output, size_t *out_len, size_t max_len) {
    /* Skip "xn--" prefix */
    if (strncmp(encoded, "xn--", 4) != 0) {
        /* Not punycode - copy as-is */
        size_t len = strlen(encoded);
        for (size_t i = 0; i < len && i < max_len; i++) {
            output[i] = (uint32_t)(unsigned char)encoded[i];
        }
        *out_len = len < max_len ? len : max_len;
        return true;
    }

    encoded += 4;  /* Skip prefix */

    /* Find last delimiter */
    const char *delim = strrchr(encoded, '-');
    size_t basic_len = delim ? (size_t)(delim - encoded) : 0;

    /* Copy basic characters */
    for (size_t i = 0; i < basic_len && i < max_len; i++) {
        output[i] = (uint32_t)(unsigned char)encoded[i];
    }
    *out_len = basic_len;

    /* Decode extended characters */
    const char *p = delim ? delim + 1 : encoded;
    uint32_t n = PUNYCODE_INITIAL_N;
    int bias = PUNYCODE_INITIAL_BIAS;
    uint32_t i = 0;

    while (*p) {
        uint32_t oldi = i;
        uint32_t w = 1;

        for (int k = PUNYCODE_BASE; ; k += PUNYCODE_BASE) {
            if (!*p) break;

            int digit;
            char c = *p++;
            if (c >= 'a' && c <= 'z') digit = c - 'a';
            else if (c >= '0' && c <= '9') digit = c - '0' + 26;
            else return false;

            i += digit * w;

            int t = k <= bias ? PUNYCODE_TMIN :
                    k >= bias + PUNYCODE_TMAX ? PUNYCODE_TMAX : k - bias;

            if (digit < t) break;
            w *= PUNYCODE_BASE - t;
        }

        /* Adapt bias */
        int delta = (i - oldi) / (oldi == 0 ? PUNYCODE_DAMP : 2);
        delta += delta / (*out_len + 1);
        int k = 0;
        while (delta > ((PUNYCODE_BASE - PUNYCODE_TMIN) * PUNYCODE_TMAX) / 2) {
            delta /= PUNYCODE_BASE - PUNYCODE_TMIN;
            k += PUNYCODE_BASE;
        }
        bias = k + ((PUNYCODE_BASE - PUNYCODE_TMIN + 1) * delta) / (delta + PUNYCODE_SKEW);

        n += i / (*out_len + 1);
        i %= (*out_len + 1);

        /* Insert character at position i */
        if (*out_len >= max_len - 1) return false;
        memmove(&output[i + 1], &output[i], (*out_len - i) * sizeof(uint32_t));
        output[i] = n;
        (*out_len)++;
        i++;
    }

    return true;
}

/* UTF-8 encode helper */
static int utf8_encode(uint32_t cp, char *out) {
    if (cp < 0x80) {
        out[0] = (char)cp;
        return 1;
    } else if (cp < 0x800) {
        out[0] = (char)(0xC0 | (cp >> 6));
        out[1] = (char)(0x80 | (cp & 0x3F));
        return 2;
    } else if (cp < 0x10000) {
        out[0] = (char)(0xE0 | (cp >> 12));
        out[1] = (char)(0x80 | ((cp >> 6) & 0x3F));
        out[2] = (char)(0x80 | (cp & 0x3F));
        return 3;
    } else {
        out[0] = (char)(0xF0 | (cp >> 18));
        out[1] = (char)(0x80 | ((cp >> 12) & 0x3F));
        out[2] = (char)(0x80 | ((cp >> 6) & 0x3F));
        out[3] = (char)(0x80 | (cp & 0x3F));
        return 4;
    }
}

/* Decode full Punycode domain */
bool security_decode_punycode(const char *encoded, char *decoded, size_t size) {
    char domain_copy[512];
    strncpy(domain_copy, encoded, sizeof(domain_copy) - 1);
    domain_copy[sizeof(domain_copy) - 1] = '\0';

    decoded[0] = '\0';
    size_t pos = 0;

    /* Use strtok_r for thread-safety! (strtok uses global state) */
    char *saveptr = NULL;
    char *label = strtok_r(domain_copy, ".", &saveptr);
    bool first = true;

    while (label) {
        if (!first && pos < size - 1) {
            decoded[pos++] = '.';
        }
        first = false;

        uint32_t codepoints[256];
        size_t cp_len = 0;

        if (!punycode_decode_label(label, codepoints, &cp_len, 256)) {
            /* Decode failed - copy as-is */
            size_t len = strlen(label);
            if (pos + len < size) {
                memcpy(&decoded[pos], label, len);
                pos += len;
            }
        } else {
            /* Encode to UTF-8 */
            for (size_t i = 0; i < cp_len && pos < size - 4; i++) {
                pos += utf8_encode(codepoints[i], &decoded[pos]);
            }
        }

        label = strtok_r(NULL, ".", &saveptr);
    }

    decoded[pos] = '\0';
    return true;
}

/* Calculate Shannon entropy */
double security_calculate_entropy(const char *str) {
    if (!str || !*str) return 0.0;

    int freq[256] = {0};
    size_t len = 0;

    for (const char *p = str; *p; p++) {
        freq[(unsigned char)*p]++;
        len++;
    }

    if (len == 0) return 0.0;

    double entropy = 0.0;
    for (int i = 0; i < 256; i++) {
        if (freq[i] > 0) {
            double p = (double)freq[i] / len;
            entropy -= p * log2(p);
        }
    }

    return entropy;
}

/* Check for suspicious TLD */
static bool check_suspicious_tld(const char *domain) {
    const char *dot = strrchr(domain, '.');
    if (!dot) return false;

    const char *tld = dot + 1;
    for (int i = 0; suspicious_tlds[i]; i++) {
        if (strcasecmp(tld, suspicious_tlds[i]) == 0) {
            return true;
        }
    }

    return false;
}

/* Check if host is an IP address */
static bool is_ip_address(const char *host) {
    struct in_addr addr4;
    struct in6_addr addr6;

    return inet_pton(AF_INET, host, &addr4) == 1 ||
           inet_pton(AF_INET6, host, &addr6) == 1;
}

/* Levenshtein distance for typosquat detection */
static int levenshtein(const char *s1, const char *s2) {
    size_t len1 = strlen(s1);
    size_t len2 = strlen(s2);

    if (len1 > 64 || len2 > 64) return 999;  /* Too long */

    int matrix[65][65];

    for (size_t i = 0; i <= len1; i++) matrix[i][0] = i;
    for (size_t j = 0; j <= len2; j++) matrix[0][j] = j;

    for (size_t i = 1; i <= len1; i++) {
        for (size_t j = 1; j <= len2; j++) {
            int cost = (tolower(s1[i-1]) == tolower(s2[j-1])) ? 0 : 1;
            int del = matrix[i-1][j] + 1;
            int ins = matrix[i][j-1] + 1;
            int sub = matrix[i-1][j-1] + cost;

            matrix[i][j] = del < ins ? (del < sub ? del : sub) : (ins < sub ? ins : sub);
        }
    }

    return matrix[len1][len2];
}

/* Check for typosquatting */
bool security_check_typosquat(const char *domain) {
    /* Extract base domain (without TLD) */
    char base[256];
    strncpy(base, domain, sizeof(base) - 1);
    base[sizeof(base) - 1] = '\0';

    char *dot = strchr(base, '.');
    if (dot) *dot = '\0';

    /* Check against known brands */
    for (int i = 0; known_brands[i]; i++) {
        int dist = levenshtein(base, known_brands[i]);
        size_t brand_len = strlen(known_brands[i]);

        /* Suspicious if edit distance 1-2 for short names, or contains brand */
        if ((brand_len <= 6 && dist == 1) ||
            (brand_len > 6 && dist <= 2) ||
            (strstr(base, known_brands[i]) != NULL && strcmp(base, known_brands[i]) != 0)) {
            return true;
        }
    }

    return false;
}

/* Count subdomains */
static int count_subdomains(const char *domain) {
    int count = 0;
    for (const char *p = domain; *p; p++) {
        if (*p == '.') count++;
    }
    return count;
}

/* Get threat type string */
const char* security_threat_type_str(threat_type_t type) {
    switch (type) {
        case THREAT_NONE: return "NONE";
        case THREAT_HOMOGRAPH: return "HOMOGRAPH";
        case THREAT_SUSPICIOUS_TLD: return "SUSPICIOUS_TLD";
        case THREAT_HIGH_ENTROPY: return "HIGH_ENTROPY";
        case THREAT_PHISHING_PATTERN: return "PHISHING_PATTERN";
        case THREAT_PUNYCODE_SUSPICIOUS: return "PUNYCODE_SUSPICIOUS";
        case THREAT_EXCESSIVE_SUBDOMAINS: return "EXCESSIVE_SUBDOMAINS";
        case THREAT_IP_AS_HOST: return "IP_AS_HOST";
        case THREAT_DATA_EXFIL_PATTERN: return "DATA_EXFIL_PATTERN";
        case THREAT_TYPOSQUAT: return "TYPOSQUAT";
        default: return "UNKNOWN";
    }
}

/* Set log path (call before init) */
void security_intel_set_log_path(const char *path) {
    if (path && path[0]) {
        snprintf(g_log_base_path, sizeof(g_log_base_path), "%s", path);
    }
}

/* Set log rotation configuration (call before init) */
void security_intel_set_log_config(size_t max_file_size, size_t max_total_size, int max_files) {
    if (max_file_size > 0) {
        g_log_max_file_size = max_file_size;
    }
    if (max_total_size > 0) {
        g_log_max_total_size = max_total_size;
    }
    if (max_files > 0) {
        g_log_max_files = max_files;
    }
}

/* Create directory recursively (like mkdir -p) */
static int mkdir_recursive(const char *path, mode_t mode) {
    char tmp[LOG_FULL_PATH_MAX];
    char *p = NULL;
    size_t len;

    snprintf(tmp, sizeof(tmp), "%s", path);
    len = strlen(tmp);

    /* Remove trailing slash */
    if (tmp[len - 1] == '/') {
        tmp[len - 1] = '\0';
    }

    /* Create each directory component */
    for (p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            if (mkdir(tmp, mode) != 0 && errno != EEXIST) {
                return -1;
            }
            *p = '/';
        }
    }

    /* Create final directory */
    if (mkdir(tmp, mode) != 0 && errno != EEXIST) {
        return -1;
    }

    return 0;
}

/* Setup log directory with proper ownership (call BEFORE drop_privileges!) */
int security_intel_setup_log_dir(const char *user, const char *group) {
    struct passwd *pw = NULL;
    struct group *gr = NULL;
    uid_t target_uid = 0;
    gid_t target_gid = 0;
    char dir_path[LOG_FULL_PATH_MAX];

    /* Extract directory from log base path */
    snprintf(dir_path, sizeof(dir_path), "%s", g_log_base_path);
    char *last_slash = strrchr(dir_path, '/');
    if (last_slash) {
        *last_slash = '\0';  /* Remove filename, keep directory */
    } else {
        return 0;  /* No directory component */
    }

    /* Must be root to set ownership */
    if (getuid() != 0) {
        /* Not root - just create directory without chown */
        return mkdir_recursive(dir_path, 0755);
    }

    /* Nothing to change if no user/group specified */
    if (!user && !group) {
        return mkdir_recursive(dir_path, 0755);
    }

    /* Lookup group (if specified) */
    if (group) {
        gr = getgrnam(group);
        if (!gr) {
            fprintf(stderr, "WARNING: Group '%s' not found for log directory\n", group);
            return mkdir_recursive(dir_path, 0755);
        }
        target_gid = gr->gr_gid;
    }

    /* Lookup user (if specified) */
    if (user) {
        pw = getpwnam(user);
        if (!pw) {
            fprintf(stderr, "WARNING: User '%s' not found for log directory\n", user);
            return mkdir_recursive(dir_path, 0755);
        }
        target_uid = pw->pw_uid;

        /* If no group specified, use user's primary group */
        if (!group) {
            target_gid = pw->pw_gid;
        }
    }

    /* Create directory recursively */
    if (mkdir_recursive(dir_path, 0750) != 0) {
        fprintf(stderr, "WARNING: Failed to create log directory: %s\n", dir_path);
        return -1;
    }

    /* Set ownership */
    if (chown(dir_path, target_uid, target_gid) != 0) {
        fprintf(stderr, "WARNING: Failed to chown log directory %s to %d:%d: %s\n",
                dir_path, target_uid, target_gid, strerror(errno));
        return -1;
    }

    printf("  Log directory: %s -> %d:%d (0750)\n", dir_path, target_uid, target_gid);
    return 0;
}

/* Initialize module */
bool security_intel_init(const security_config_t *config) {
    if (atomic_load_explicit(&g_initialized, memory_order_acquire)) {
        return true;  /* Already initialized */
    }

    /* Set defaults */
    memset(&g_config, 0, sizeof(g_config));
    g_config.enabled = true;
    g_config.log_to_syslog = true;
    g_config.min_threat_score = 50;
    g_config.detect_homograph = true;
    g_config.detect_suspicious_tld = true;
    g_config.detect_entropy = true;
    g_config.detect_phishing = true;

    /* Override with user config */
    if (config) {
        memcpy(&g_config, config, sizeof(g_config));
    }

    /* Initialize syslog */
    if (g_config.log_to_syslog) {
        openlog("tlsgateNG-security", LOG_PID | LOG_NDELAY, LOG_AUTH);
    }

    memset(&g_stats, 0, sizeof(g_stats));
    atomic_store(&g_initialized, true);

    return true;
}

/* Shutdown */
void security_intel_shutdown(void) {
    if (!atomic_load_explicit(&g_initialized, memory_order_acquire)) return;

    /* Close log file (LEAK FIX!) */
    pthread_mutex_lock(&g_log_mutex);
    if (g_log_file) {
        fclose(g_log_file);
        g_log_file = NULL;
    }
    pthread_mutex_unlock(&g_log_mutex);

    if (g_config.log_to_syslog) {
        closelog();
    }

    atomic_store(&g_initialized, false);
}

/* Log ALL requests (for analysis) or just threats */
void security_intel_log_request(const char *host, const char *path,
                                 const char *query, const char *note) {
    char timestamp[32];
    time_t now = time(NULL);
    struct tm *tm = gmtime(&now);
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%dT%H:%M:%SZ", tm);

    char log_line[4096];
    snprintf(log_line, sizeof(log_line),
             "REQUEST|%s|https://%s%s%s%s|%s",
             timestamp,
             host ? host : "-",
             path ? path : "/",
             query ? "?" : "",
             query ? query : "",
             note ? note : "-");

    log_write(log_line);
}

/* Log security event - NO CLIENT IP (DSGVO compliant, focus on URL/threat) */
void security_intel_log(const security_analysis_t *result) {
    if (!result) return;

    /* Log ALL IDN domains for analysis (even non-threats) */
    if (result->is_punycode && !result->is_threat) {
        char timestamp[32];
        struct tm *tm = gmtime(&result->timestamp);
        strftime(timestamp, sizeof(timestamp), "%Y-%m-%dT%H:%M:%SZ", tm);

        char log_line[4096];
        snprintf(log_line, sizeof(log_line),
                 "IDN|%s|%s|decoded=%s|scripts=%s",
                 timestamp,
                 result->full_url,
                 result->decoded_domain,
                 result->detected_scripts[0] ? result->detected_scripts : "ASCII");

        log_write(log_line);
        return;  /* Not a threat, just logged for analysis */
    }

    if (!result->is_threat) return;

    /* Format: THREAT|timestamp|full_url|threat_type|score|details
     * NO client_ip - DSGVO compliant, focus on WHAT not WHO */
    char timestamp[32];
    struct tm *tm = gmtime(&result->timestamp);
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%dT%H:%M:%SZ", tm);

    char log_line[4096];
    snprintf(log_line, sizeof(log_line),
             "THREAT|%s|%s|%s|%d|%s",
             timestamp,
             result->full_url,
             security_threat_type_str(result->primary_threat),
             result->threat_score,
             result->threat_details);

    /* Write to rotating log file (100MB per file, 20GB max total) */
    log_write(log_line);

    /* Also to syslog if enabled */
    if (g_config.log_to_syslog) {
        syslog(LOG_WARNING, "%s", log_line);
    }
}

/* Main analysis function - DSGVO compliant (no client IP logging) */
bool security_intel_analyze(const char *host,
                            const char *path,
                            const char *query,
                            security_analysis_t *result) {
    if (!atomic_load_explicit(&g_initialized, memory_order_acquire) || !g_config.enabled) {
        return false;
    }

    if (!host || !result) return false;

    /* Initialize result */
    memset(result, 0, sizeof(security_analysis_t));
    result->timestamp = time(NULL);

    /* Build full URL */
    snprintf(result->full_url, sizeof(result->full_url), "https://%s%s%s%s",
             host, path ? path : "/",
             query ? "?" : "", query ? query : "");

    atomic_fetch_add(&g_stats.total_analyzed, 1);

    uint8_t score = 0;
    threat_type_t primary = THREAT_NONE;

    /* Check if IP address */
    if (is_ip_address(host)) {
        result->is_ip_address = true;
        score += 20;
        if (primary == THREAT_NONE) primary = THREAT_IP_AS_HOST;
    }

    /* Check Punycode */
    if (security_is_punycode(host)) {
        result->is_punycode = true;
        atomic_fetch_add(&g_stats.punycode_domains, 1);

        /* Decode and analyze */
        security_decode_punycode(host, result->decoded_domain, sizeof(result->decoded_domain));

        /* Check for mixed scripts (homograph attack) */
        if (g_config.detect_homograph) {
            if (check_mixed_scripts(result->decoded_domain, result->detected_scripts,
                                    sizeof(result->detected_scripts))) {
                result->has_mixed_scripts = true;
                score += 80;
                primary = THREAT_HOMOGRAPH;
                atomic_fetch_add(&g_stats.homograph_attacks, 1);
            }

            /* Check for confusables */
            char conf_details[256];
            if (check_confusables(result->decoded_domain, conf_details, sizeof(conf_details))) {
                if (result->threat_details[0] == '\0') {
                    memcpy(result->threat_details, conf_details, sizeof(result->threat_details));
                }
                score += 40;
                if (primary == THREAT_NONE) primary = THREAT_PUNYCODE_SUSPICIOUS;
            }
        }
    } else {
        strncpy(result->decoded_domain, host, sizeof(result->decoded_domain) - 1);
    }

    /* Check suspicious TLD */
    if (g_config.detect_suspicious_tld && check_suspicious_tld(host)) {
        result->has_suspicious_tld = true;
        score += 30;
        if (primary == THREAT_NONE) primary = THREAT_SUSPICIOUS_TLD;
        atomic_fetch_add(&g_stats.suspicious_tlds, 1);
    }

    /* Check entropy (DGA detection) */
    if (g_config.detect_entropy) {
        /* Extract domain without TLD for entropy check */
        char domain_part[256];
        strncpy(domain_part, host, sizeof(domain_part) - 1);
        domain_part[sizeof(domain_part) - 1] = '\0';
        char *dot = strchr(domain_part, '.');
        if (dot) *dot = '\0';

        double entropy = security_calculate_entropy(domain_part);
        if (entropy > 4.0 && strlen(domain_part) > 10) {
            result->has_high_entropy = true;
            score += (uint8_t)((entropy - 4.0) * 20);
            if (primary == THREAT_NONE) primary = THREAT_HIGH_ENTROPY;
            atomic_fetch_add(&g_stats.high_entropy, 1);

            snprintf(result->threat_details, sizeof(result->threat_details),
                     "High entropy: %.2f bits/char", entropy);
        }
    }

    /* Check typosquatting */
    if (g_config.detect_phishing && security_check_typosquat(host)) {
        score += 50;
        if (primary == THREAT_NONE) primary = THREAT_TYPOSQUAT;
        atomic_fetch_add(&g_stats.phishing_patterns, 1);
    }

    /* Check excessive subdomains */
    int subdomain_count = count_subdomains(host);
    if (subdomain_count > 4) {
        score += subdomain_count * 5;
        if (primary == THREAT_NONE) primary = THREAT_EXCESSIVE_SUBDOMAINS;
    }

    /* Check for data exfiltration pattern (very long subdomain) */
    const char *first_dot = strchr(host, '.');
    if (first_dot) {
        size_t first_label_len = first_dot - host;
        if (first_label_len > 30) {
            score += 30;
            if (primary == THREAT_NONE) primary = THREAT_DATA_EXFIL_PATTERN;
        }
    }

    /* Cap score at 100 */
    if (score > 100) score = 100;

    result->threat_score = score;
    result->primary_threat = primary;
    result->is_threat = (score >= g_config.min_threat_score);

    /* Log if threat detected */
    if (result->is_threat) {
        atomic_fetch_add(&g_stats.threats_detected, 1);
        security_intel_log(result);
    }

    return result->is_threat;
}

/* Get statistics */
void security_intel_get_stats(security_stats_t *stats) {
    if (stats) {
        memcpy(stats, &g_stats, sizeof(security_stats_t));
    }
}

/* Reset statistics */
void security_intel_reset_stats(void) {
    memset(&g_stats, 0, sizeof(g_stats));
}
