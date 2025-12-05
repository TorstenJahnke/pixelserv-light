/*
 * compat.h - POSIX/BSD compatibility layer
 *
 * Provides portable alternatives to GNU-specific functions.
 * Supports: Linux (glibc, musl), FreeBSD, OpenBSD, NetBSD, macOS
 */

#ifndef COMPAT_H
#define COMPAT_H

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>

/* =============================================================================
 * asprintf - formatted string allocation (GNU extension)
 *
 * Available in: glibc, musl, FreeBSD, macOS
 * Not available in: Some embedded systems, older BSDs
 *
 * We provide our own implementation for maximum portability.
 * ============================================================================= */

#if !defined(HAVE_ASPRINTF) && !defined(__GLIBC__) && !defined(__FreeBSD__) && \
    !defined(__APPLE__) && !defined(__OpenBSD__) && !defined(__NetBSD__)
#define NEED_ASPRINTF 1
#endif

#ifdef NEED_ASPRINTF
static inline int
asprintf(char **strp, const char *fmt, ...)
{
    va_list ap;
    int len;
    char *buf;

    /* First pass: determine length needed */
    va_start(ap, fmt);
    len = vsnprintf(NULL, 0, fmt, ap);
    va_end(ap);

    if (len < 0) {
        *strp = NULL;
        return -1;
    }

    /* Allocate buffer */
    buf = malloc(len + 1);
    if (!buf) {
        *strp = NULL;
        return -1;
    }

    /* Second pass: format string */
    va_start(ap, fmt);
    len = vsnprintf(buf, len + 1, fmt, ap);
    va_end(ap);

    if (len < 0) {
        free(buf);
        *strp = NULL;
        return -1;
    }

    *strp = buf;
    return len;
}
#endif /* NEED_ASPRINTF */

/* =============================================================================
 * TEMP_FAILURE_RETRY - retry on EINTR (GNU extension)
 *
 * This macro retries a system call if interrupted by a signal.
 * Used by glibc, we provide it for other systems.
 * ============================================================================= */

#ifndef TEMP_FAILURE_RETRY
#define TEMP_FAILURE_RETRY(expression) \
    (__extension__ \
     ({ long int __result; \
        do __result = (long int)(expression); \
        while (__result == -1L && errno == EINTR); \
        __result; }))
#endif

/* =============================================================================
 * Safe string functions
 *
 * strlcpy/strlcat are BSD extensions, not available in glibc.
 * snprintf is POSIX and always available - prefer it for new code.
 * ============================================================================= */

/* Use strlcpy if available (BSD, macOS), otherwise use snprintf */
#if defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__) || defined(__APPLE__)
#include <string.h>
/* strlcpy and strlcat are available */
#else
/* glibc doesn't have strlcpy - use snprintf instead in code */
/* These are only for code that explicitly uses strlcpy */
#ifndef HAVE_STRLCPY
static inline size_t
strlcpy(char *dst, const char *src, size_t size)
{
    size_t srclen = strlen(src);
    if (size > 0) {
        size_t copylen = (srclen >= size) ? size - 1 : srclen;
        memcpy(dst, src, copylen);
        dst[copylen] = '\0';
    }
    return srclen;
}
#endif

#ifndef HAVE_STRLCAT
static inline size_t
strlcat(char *dst, const char *src, size_t size)
{
    size_t dstlen = strlen(dst);
    size_t srclen = strlen(src);

    if (dstlen >= size)
        return size + srclen;

    if (srclen < size - dstlen)
        memcpy(dst + dstlen, src, srclen + 1);
    else {
        memcpy(dst + dstlen, src, size - dstlen - 1);
        dst[size - 1] = '\0';
    }

    return dstlen + srclen;
}
#endif
#endif /* BSD strlcpy/strlcat */

/* =============================================================================
 * Clock functions
 *
 * CLOCK_MONOTONIC is POSIX, but some systems (old macOS) need workarounds.
 * ============================================================================= */

#include <time.h>

#ifndef CLOCK_MONOTONIC
/* Fallback for systems without CLOCK_MONOTONIC */
#ifdef __APPLE__
#include <mach/mach_time.h>
static inline int
clock_gettime_compat(int clk_id, struct timespec *tp)
{
    (void)clk_id;
    static mach_timebase_info_data_t info = {0, 0};
    if (info.denom == 0)
        mach_timebase_info(&info);

    uint64_t t = mach_absolute_time();
    t = t * info.numer / info.denom;
    tp->tv_sec = t / 1000000000ULL;
    tp->tv_nsec = t % 1000000000ULL;
    return 0;
}
#define clock_gettime clock_gettime_compat
#endif
#endif

/* =============================================================================
 * Socket options
 *
 * Some socket options have different names on different systems.
 * ============================================================================= */

#include <sys/socket.h>

/* SO_BINDTODEVICE is Linux-specific */
#ifndef SO_BINDTODEVICE
#ifdef IP_RECVIF
#define SO_BINDTODEVICE IP_RECVIF
#else
#define SO_BINDTODEVICE 0  /* Not available - will be ignored */
#endif
#endif

/* TCP_FASTOPEN queue length may need different values */
#ifndef TCP_FASTOPEN
#define TCP_FASTOPEN 0  /* Not available */
#endif

/* =============================================================================
 * Endian functions
 *
 * BSD uses <sys/endian.h>, Linux uses <endian.h>
 * ============================================================================= */

#if defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
#include <sys/endian.h>
#elif defined(__APPLE__)
#include <libkern/OSByteOrder.h>
#define htobe16(x) OSSwapHostToBigInt16(x)
#define htobe32(x) OSSwapHostToBigInt32(x)
#define htobe64(x) OSSwapHostToBigInt64(x)
#define be16toh(x) OSSwapBigToHostInt16(x)
#define be32toh(x) OSSwapBigToHostInt32(x)
#define be64toh(x) OSSwapBigToHostInt64(x)
#elif defined(__linux__)
#include <endian.h>
#endif

/* =============================================================================
 * Compiler attributes
 *
 * GCC and Clang support __attribute__, MSVC doesn't (but we don't support it)
 * ============================================================================= */

#ifndef __has_attribute
#define __has_attribute(x) 0
#endif

#if __has_attribute(unused) || defined(__GNUC__)
#define UNUSED __attribute__((unused))
#else
#define UNUSED
#endif

#if __has_attribute(format) || defined(__GNUC__)
#define PRINTF_FMT(a, b) __attribute__((format(printf, a, b)))
#else
#define PRINTF_FMT(a, b)
#endif

#endif /* COMPAT_H */
