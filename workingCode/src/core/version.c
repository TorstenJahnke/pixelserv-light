/*
 * version.c - Version utility functions
 *
 * Implementation of version-related utility functions.
 * All version information is centralized in version.h
 */

#include <stdio.h>
#include "core/version.h"
#include "core/util.h"
#include "certs/certs.h"

/* Static buffers for version strings (thread-safe, const data) */
static const char version_string[] = VERSION;
static const char version_full[] = VERSION_FULL " (compiled: " BUILD_TIMESTAMP FEATURE_FLAGS ")";
static const char copyright_string[] = COPYRIGHT_NOTICE;
static const char build_info[] = "Built: " BUILD_TIMESTAMP " with " COMPILER_NAME " " COMPILER_VERSION;

/**
 * Print full version banner to stdout
 */
void print_version_banner(void) {
    printf("\n");
    printf("  %s\n", PROJECT_NAME);
    printf("  %s\n", PROJECT_DESCRIPTION);
    printf("\n");
    printf("  Version:   %s\n", VERSION);
    printf("  Built:     %s\n", BUILD_TIMESTAMP);
    printf("  Compiler:  %s %s\n", COMPILER_NAME, COMPILER_VERSION);
    printf("  Features:  %s\n", FEATURE_FLAGS[0] ? FEATURE_FLAGS + 1 : "standard");
    printf("\n");
    printf("  %s\n", COPYRIGHT_NOTICE);
    printf("  Original:  (c) %s %s\n", ORIGINAL_YEAR, ORIGINAL_AUTHOR);
    printf("  License:   %s (%s)\n", LICENSE_TYPE, LICENSE_URL);
    printf("\n");
}

/**
 * Print short version line to stdout
 */
void print_version_short(void) {
    printf("%s %s (compiled: %s%s)\n",
           PROJECT_NAME, VERSION, BUILD_TIMESTAMP, FEATURE_FLAGS);
}

/**
 * Get version string
 */
const char *get_version_string(void) {
    return version_string;
}

/**
 * Get full version info including build date
 */
const char *get_version_full(void) {
    return version_full;
}

/**
 * Get copyright notice
 */
const char *get_copyright(void) {
    return copyright_string;
}

/**
 * Get build information
 */
const char *get_build_info(void) {
    return build_info;
}

/**
 * Print usage/help information to stdout
 */
void print_usage(void) {
    printf("\n"
           "  %s %s (compiled: %s%s)\n"
           "  %s\n"
           "\n"
           "Usage: pixelserv-tls [ip_addr] [OPTIONS]\n"
           "\n"
           "Network Options:\n"
           "    ip_addr/hostname      IP or hostname to bind (default: 0.0.0.0 = all)\n"
           "    -p  HTTP_PORT         HTTP port (default: %s)\n"
           "    -k  HTTPS_PORT        HTTPS/TLS port (default: %s)\n"
           "    -a  AUTO_PORT         Auto-detect HTTP/HTTPS on same port\n"
           "    -A  ADMIN_PORT        Admin HTTPS-only port (default: none)\n"
#ifdef IF_MODE
           "    -n  IFACE             Bind to specific interface (default: all)\n"
#endif
           "\n"
           "Master/Worker Mode (for HAProxy setups):\n"
           "    -M                    Run as index master (owns cert index)\n"
           "    -m  SOCKET_PATH       Connect to index master as worker\n"
           "\n"
           "TLS/Certificate Options:\n"
           "    -z  CERT_PATH         Certificate directory (default: %s)\n"
           "    -c  CACHE_SIZE        Certificate cache size (default: %d)\n"
           "\n"
           "Content Options:\n"
           "    -H  HTML_FILE         External HTML file for default response (max 1MB)\n"
           "    -2                    Disable HTTP 204 for generate_204 URLs\n"
           "    -R                    Enable redirect to encoded path in URLs\n"
           "\n"
           "Server Options:\n"
           "    -T  MAX_THREADS       Maximum concurrent threads (default: %d)\n"
           "    -O  KEEPALIVE_SEC     HTTP/1.1 keep-alive timeout (default: %ds)\n"
           "    -s  STATS_URL         HTML stats URL (default: %s)\n"
           "    -t  STATS_TXT_URL     Text stats URL (default: %s)\n"
#ifndef TEST
           "    -f                    Stay in foreground (don't daemonize)\n"
#endif
#ifdef DROP_ROOT
           "    -u  USER              Run as user after binding (default: %s)\n"
#endif
           "\n"
           "Logging & Debug:\n"
           "    -l  LEVEL             Log level: 0=crit 1=err 2=warn 3=notice 4=info 5=debug\n"
#ifdef DEBUG
           "    -w  MSEC              Warn when connection time exceeds value\n"
#endif
           "    -B  [CERT_FILE]       Benchmark crypto/disk, then quit\n"
           "\n"
           "Examples:\n"
           "    pixelserv-tls 192.168.1.1 -p 80 -k 443 -f\n"
           "    pixelserv-tls -M -z %s     # Index master\n"
           "    pixelserv-tls -m /path/pixelserv-index.sock    # Worker\n"
           "\n"
           "Stats:  http://<ip>:<port>%s\n"
           "\n",
           PROJECT_NAME, VERSION, BUILD_TIMESTAMP, FEATURE_FLAGS,
           PROJECT_DESCRIPTION,
           DEFAULT_PORT, SECOND_PORT,
           DEFAULT_PEM_PATH, DEFAULT_CERT_CACHE_SIZE,
           DEFAULT_THREAD_MAX, DEFAULT_KEEPALIVE,
           DEFAULT_STATS_URL, DEFAULT_STATS_TEXT_URL,
#ifdef DROP_ROOT
           DEFAULT_USER,
#endif
           DEFAULT_PEM_PATH, DEFAULT_STATS_URL);
}
