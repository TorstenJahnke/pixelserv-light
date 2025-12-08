/*
 * version.h - Central version and build information
 *
 * All version numbers, copyright notices, and build metadata
 * are defined here for easy maintenance.
 */

#ifndef VERSION_H
#define VERSION_H

/* ==========================================================================
 * VERSION NUMBERS
 * ========================================================================== */

#define VERSION_MAJOR       3
#define VERSION_MINOR       0
#define VERSION_PATCH       18
#define VERSION_BUILD       25

/* Version string: "3.0.18.25" */
#define VERSION             "3.0.18.25"

/* Full version with name */
#define VERSION_FULL        "pixelserv-tls " VERSION

/* ==========================================================================
 * PROJECT INFORMATION
 * ========================================================================== */

#define PROJECT_NAME        "pixelserv-tls"
#define PROJECT_DESCRIPTION "Minimal ad-blocking pixel server with TLS/HTTPS support"

/* ==========================================================================
 * COPYRIGHT AND LICENSE
 * ========================================================================== */

#define COPYRIGHT_YEAR      "2015-2025"
#define COPYRIGHT_HOLDER    "Torsten Jahnke"
#define COPYRIGHT_NOTICE    "Copyright (c) " COPYRIGHT_YEAR " " COPYRIGHT_HOLDER

/* Original author credits */
#define ORIGINAL_AUTHOR     "Kaz (kazpgmの日記)"
#define ORIGINAL_YEAR       "2010"

/* License */
#define LICENSE_TYPE        "GPL v3"
#define LICENSE_URL         "https://www.gnu.org/licenses/gpl-3.0.html"

/* ==========================================================================
 * BUILD INFORMATION (auto-generated at compile time)
 * ========================================================================== */

/* Build date/time - use __DATE__ and __TIME__ from compiler */
#define BUILD_DATE          __DATE__
#define BUILD_TIME          __TIME__
#define BUILD_TIMESTAMP     __DATE__ " " __TIME__

/* Compiler info */
#ifdef __GNUC__
#define COMPILER_NAME       "GCC"
#define COMPILER_VERSION    __VERSION__
#elif defined(__clang__)
#define COMPILER_NAME       "Clang"
#define COMPILER_VERSION    __clang_version__
#else
#define COMPILER_NAME       "Unknown"
#define COMPILER_VERSION    "Unknown"
#endif

/* ==========================================================================
 * FEATURE FLAGS (for version display)
 * ========================================================================== */

/* Runtime/compile-time feature detection */
#ifdef linux
#include <linux/version.h>
#endif
#include <openssl/ssl.h>

/* TCP Fast Open support */
#ifdef linux
#  if defined(LINUX_VERSION_CODE) && (LINUX_VERSION_CODE >= KERNEL_VERSION(3,7,0) || defined(ENABLE_TCP_FASTOPEN))
#    define FEAT_TFO " tfo"
#  else
#    define FEAT_TFO ""
#  endif
#else
#  define FEAT_TFO ""
#endif

/* TLS 1.3 support */
#ifdef TLS1_3_VERSION
#  define FEAT_TLS1_3 " tls1_3"
#else
#  define FEAT_TLS1_3 " no_tls1_3"
#endif

/* Build options */
#ifdef DROP_ROOT
#  define FEAT_DROP_ROOT " drop_root"
#else
#  define FEAT_DROP_ROOT ""
#endif

#ifdef IF_MODE
#  define FEAT_IF_MODE " if_mode"
#else
#  define FEAT_IF_MODE ""
#endif

#ifdef DEBUG
#  define FEAT_DEBUG " debug"
#else
#  define FEAT_DEBUG ""
#endif

#ifdef TEST
#  define FEAT_TEST " test"
#else
#  define FEAT_TEST ""
#endif

/* Combined feature string */
#define FEATURE_FLAGS " flags:" FEAT_TFO FEAT_TLS1_3 FEAT_DROP_ROOT FEAT_IF_MODE FEAT_DEBUG FEAT_TEST

/* ==========================================================================
 * REPOSITORY INFORMATION
 * ========================================================================== */

#define REPO_URL            "https://github.com/user/pixelserv-tls"
#define ISSUES_URL          "https://github.com/user/pixelserv-tls/issues"

/* ==========================================================================
 * VERSION UTILITY FUNCTIONS
 * ========================================================================== */

/* Get version as integer for comparisons: 3.0.18.25 -> 30001825 */
#define VERSION_NUMBER      ((VERSION_MAJOR * 1000000) + \
                             (VERSION_MINOR * 10000) + \
                             (VERSION_PATCH * 100) + \
                             VERSION_BUILD)

/* Function declarations (implemented in version.c) */

/**
 * Print full version banner to stdout
 */
void print_version_banner(void);

/**
 * Print short version line to stdout
 */
void print_version_short(void);

/**
 * Get version string (static, do not free)
 * @return Pointer to static version string
 */
const char *get_version_string(void);

/**
 * Get full version info including build date (static, do not free)
 * @return Pointer to static full version string
 */
const char *get_version_full(void);

/**
 * Get copyright notice (static, do not free)
 * @return Pointer to static copyright string
 */
const char *get_copyright(void);

/**
 * Get build information (static, do not free)
 * @return Pointer to static build info string
 */
const char *get_build_info(void);

/**
 * Print usage/help information to stdout
 */
void print_usage(void);

#endif /* VERSION_H */
