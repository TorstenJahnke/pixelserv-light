/* TLS-Gate NX - Logging System Implementation
 * Copyright (C) 2025 Torsten Jahnke
 */

#include "logger.h"
#include <stdio.h>
#include <stdarg.h>
#include <time.h>
#include <string.h>
#include <syslog.h>
#include <stdatomic.h>

/* syslog priority values (from sys/syslog.h) */
#define SYSLOG_LOG_INFO    6  /* LOG_INFO */
#define SYSLOG_LOG_DEBUG   7  /* LOG_DEBUG */

/* Global state - C11 atomic initialization */
static _Atomic int current_log_level = LOG_LEVEL_SILENT;
static _Atomic bool use_syslog_backend = true;
static _Atomic bool log_initialized = false;
static char program_name_buf[64] = "tlsgateNG";

void log_init(const char* program_name, log_level_t level, bool use_syslog) {
    atomic_store(&current_log_level, level);
    atomic_store(&use_syslog_backend, use_syslog);

    if (program_name) {
        snprintf(program_name_buf, sizeof(program_name_buf), "%s", program_name);
    }

    if (use_syslog) {
        openlog(program_name_buf, LOG_PID | LOG_NDELAY, LOG_DAEMON);
    }

    atomic_store(&log_initialized, true);
}

void log_set_level(log_level_t level) {
    atomic_store(&current_log_level, level);
}

log_level_t log_get_level(void) {
    return atomic_load_explicit(&current_log_level, memory_order_acquire);
}

/* Internal: Format and output log message */
static void log_message(log_level_t level, const char* level_str,
                       int syslog_priority, const char* fmt, va_list args) {
    /* Thread-safe atomic reads */
    if (!atomic_load_explicit(&log_initialized, memory_order_acquire) || level > (log_level_t)atomic_load_explicit(&current_log_level, memory_order_acquire)) {
        return;  /* Skip if not initialized or below threshold */
    }

    char buffer[4096];
    vsnprintf(buffer, sizeof(buffer), fmt, args);

    /* Output to syslog (always in production, optional in debug) */
    if (atomic_load_explicit(&use_syslog_backend, memory_order_acquire)) {
        syslog(syslog_priority, "%s", buffer);
    }

    /* Output to stderr (only in debug mode) */
    if (atomic_load_explicit(&current_log_level, memory_order_acquire) >= LOG_LEVEL_DEBUG) {
        time_t now = time(NULL);
        struct tm* tm_info = localtime(&now);
        char timestamp[32];

        /* CRITICAL BUG FIX: localtime() can return NULL on invalid time values
         * Must check before dereferencing! This prevents NULL ptr dereference in strftime() */
        if (tm_info) {
            strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm_info);
        } else {
            /* Fallback timestamp if localtime() fails */
            snprintf(timestamp, sizeof(timestamp), "time_error");
        }

        fprintf(stderr, "[%s] [%s] %s\n", timestamp, level_str, buffer);
        fflush(stderr);  /* Ensure output is visible immediately */
    }
}

void log_error(const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    log_message(LOG_LEVEL_ERROR, "ERROR", LOG_ERR, fmt, args);
    va_end(args);
}

void log_warn(const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    log_message(LOG_LEVEL_WARN, "WARN", LOG_WARNING, fmt, args);
    va_end(args);
}

void log_info(const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    log_message(LOG_LEVEL_INFO, "INFO", SYSLOG_LOG_INFO, fmt, args);
    va_end(args);
}

void log_debug(const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    log_message(LOG_LEVEL_DEBUG, "DEBUG", SYSLOG_LOG_DEBUG, fmt, args);
    va_end(args);
}

void log_trace(const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    log_message(LOG_LEVEL_TRACE, "TRACE", SYSLOG_LOG_DEBUG, fmt, args);
    va_end(args);
}

void log_close(void) {
    if (atomic_load_explicit(&use_syslog_backend, memory_order_acquire)) {
        closelog();
    }
    atomic_store(&log_initialized, false);
}
