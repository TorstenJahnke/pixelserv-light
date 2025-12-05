/* TLS-Gate NX - Logging System
 * Copyright (C) 2025 Torsten Jahnke
 *
 * High-performance logging with zero overhead in production mode.
 *
 * DESIGN PHILOSOPHY:
 *   TLS-Gate NX runs SILENT by default!
 *   - NO request logging (DNS server does that!)
 *   - NO per-connection logs
 *   - Only startup/shutdown/fatal errors
 *
 * Why? Logging overhead:
 *   - syslog() syscall:  ~10-50 μs
 *   - String formatting: ~5-20 μs
 *   - At 50,000 req/s:   50% CPU wasted!
 *
 * DNS server logs:
 *   - Domain requests
 *   - Client IPs
 *   - Block decisions
 *
 * TLS-Gate NX only:
 *   - Extracts SNI
 *   - Generates certificate
 *   - Returns response
 *   - ZERO LOGGING = MAX PERFORMANCE!
 *
 * Production mode (default): LOG_LEVEL_SILENT
 * Debug mode (--debug):      LOG_LEVEL_DEBUG (dev only!)
 */

#ifndef TLSGATENG_LOGGER_H
#define TLSGATENG_LOGGER_H

#include <stdbool.h>

/* We need syslog.h but it defines LOG_INFO and LOG_DEBUG macros that conflict
 * with our convenience macros. Solution: Include it only in the .c file where
 * we can use the numeric values directly (6 and 7). */
/* DO NOT include syslog.h here! */

/* Log levels */
typedef enum {
    LOG_LEVEL_SILENT = 0,   /* Production: Only fatal errors */
    LOG_LEVEL_ERROR  = 1,   /* Errors that affect operation */
    LOG_LEVEL_WARN   = 2,   /* Warnings (non-critical) */
    LOG_LEVEL_INFO   = 3,   /* Informational (startup, stats) */
    LOG_LEVEL_DEBUG  = 4,   /* Detailed debugging */
    LOG_LEVEL_TRACE  = 5    /* Very verbose (function entry/exit) */
} log_level_t;

/* Initialize logging system
 *
 * @param program_name  Program name for syslog
 * @param level         Initial log level
 * @param use_syslog    true to use syslog, false for stderr only
 */
void log_init(const char* program_name, log_level_t level, bool use_syslog);

/* Set log level at runtime */
void log_set_level(log_level_t level);

/* Get current log level */
log_level_t log_get_level(void);

/* Core logging functions (with printf-style format checking) */
void log_error(const char* fmt, ...) __attribute__((format(printf, 1, 2)));
void log_warn(const char* fmt, ...)  __attribute__((format(printf, 1, 2)));
void log_info(const char* fmt, ...)  __attribute__((format(printf, 1, 2)));
void log_debug(const char* fmt, ...) __attribute__((format(printf, 1, 2)));
void log_trace(const char* fmt, ...) __attribute__((format(printf, 1, 2)));

/* Convenience macros (safe now that syslog.h is not included) */
#define LOG_ERROR(...) log_error(__VA_ARGS__)
#define LOG_WARN(...)  log_warn(__VA_ARGS__)
#define LOG_INFO(...)  log_info(__VA_ARGS__)
#define LOG_DEBUG(...) log_debug(__VA_ARGS__)
#define LOG_TRACE(...) log_trace(__VA_ARGS__)

/* Performance-critical: compiled out entirely in production mode */
#if defined(PRODUCTION) || defined(NDEBUG)
    #define LOG_TRACE_FAST(...) ((void)0)
    #define LOG_DEBUG_FAST(...) ((void)0)
#else
    #define LOG_TRACE_FAST(...) log_trace(__VA_ARGS__)
    #define LOG_DEBUG_FAST(...) log_debug(__VA_ARGS__)
#endif

/* Cleanup */
void log_close(void);

#endif /* TLSGATENG_LOGGER_H */
