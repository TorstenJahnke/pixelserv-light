/* TLSGateNG4 - Version Information
 * Copyright (C) 2026 Torsten Jahnke
 */

#ifndef TLSGATENG_VERSION_H
#define TLSGATENG_VERSION_H

/* Version Format: MAJOR.MINOR.PATCH Rev. NNNN
 *
 * MAJOR: Breaking changes, major rewrites
 * MINOR: New features, enhancements
 * PATCH: Bug fixes, small improvements
 * REV:   Build/revision number (incremented with each build)
 */

#define TLSGATENG_VERSION_MAJOR  4
#define TLSGATENG_VERSION_MINOR  36
#define TLSGATENG_VERSION_PATCH  0
#define TLSGATENG_REVISION       1

/* Alias for compatibility with config_file.c */
#define TLSGATENG_VERSION_BUILD  TLSGATENG_REVISION

/* String representations */
#define TLSGATENG_VERSION_STRING "4.36.0"
#define TLSGATENG_VERSION_FULL   "4.36.0 GEN4 (2026) Rev. 0001 - 国密/商用密码"

/* Build information */
#define TLSGATENG_BUILD_DATE     __DATE__
#define TLSGATENG_BUILD_TIME     __TIME__

/* ============================================================================
 * About Information (for --version, --about, help screens)
 * ============================================================================ */

/* Project & Copyright */
#define TLSGATENG_PROJECT_NAME   "TLSGateNG4"
#define TLSGATENG_COPYRIGHT      "Copyright (C) 2026 Torsten Jahnke"
#define TLSGATENG_DESCRIPTION    "High-Performance Ad-Blocking HTTP/HTTPS Proxy"
#define TLSGATENG_AUTHOR         "Torsten Jahnke"
#define TLSGATENG_AUTHOR_EMAIL   "torsten@keweon.de"

/* License */
#define TLSGATENG_LICENSE        "Proprietary"
#define TLSGATENG_LICENSE_TEXT   "All rights reserved. Commercial use requires license."

/* Project URLs */
#define TLSGATENG_HOMEPAGE       "https://github.com/TorstenJahnke/TLSGateNXv2"
#define TLSGATENG_ISSUES_URL     "https://github.com/TorstenJahnke/TLSGateNXv2/issues"
#define TLSGATENG_DOCS_URL       "https://github.com/TorstenJahnke/TLSGateNXv2/wiki"

/* System Information */
#define TLSGATENG_PLATFORM       "Linux/BSD"
#define TLSGATENG_COMPILER       __VERSION__  /* GCC version */

/* Features (for about screen) */
#define TLSGATENG_FEATURES \
    "  - Multi-threaded worker architecture\n" \
    "  - Automatic TLS/HTTPS detection\n" \
    "  - On-the-fly certificate generation (SNI)\n" \
    "  - 国密/商用密码 support (SM2/SM3/SM4)\n" \
    "  - Shared memory keypool (multi-instance)\n" \
    "  - Prime pool for ultra-fast RSA\n" \
    "  - Anti-adblock fingerprinting defense\n" \
    "  - Response-based timing jitter\n" \
    "  - io_uring support for 200K+ connections\n" \
    "  - Zero-copy I/O operations\n" \
    "  - Certificate caching and indexing\n" \
    "  - Master configuration with version check"

/* Performance Targets */
#define TLSGATENG_PERF_TARGET \
    "Performance:\n" \
    "  - 500,000+ req/s HTTPS (io_uring)\n" \
    "  - 50,000+ req/s HTTPS (epoll fallback)\n" \
    "  - < 1ms latency target (p99)\n" \
    "  - 200K+ simultaneous connections\n" \
    "  - 100× faster certificate generation (ECDSA)\n" \
    "  - 16× faster HTTP parsing (SIMD)"

/* Credits */
#define TLSGATENG_CREDITS \
    "Based on:\n" \
    "  - TLSGate NX v1 by Torsten Jahnke\n" \
    "  - OpenSSL for cryptography\n" \
    "  - liburing for high-performance I/O"

/* Build Configuration String */
#define TLSGATENG_BUILD_INFO \
    "Built: " __DATE__ " " __TIME__ "\n" \
    "Compiler: " __VERSION__

/* ============================================================================
 * Function Declarations (from version.c)
 * ============================================================================ */

/**
 * Display help/usage information
 * @param prog Program name (argv[0])
 */
void print_usage(const char *prog);

/**
 * Display version information
 */
void print_version(void);

/**
 * Display about information
 */
void print_about(void);

#endif /* TLSGATENG_VERSION_H */
