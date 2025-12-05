/* TLS-Gate NX - Utility Functions and Common Definitions
 * Copyright (C) 2025 Torsten Jahnke
 * TLSGate NextGeneration
 */

#ifndef TLSGATENG_UTIL_H
#define TLSGATENG_UTIL_H

#include <stddef.h>
#include <stdlib.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/tcp.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
/* DO NOT include syslog.h here - it conflicts with logger.h macros */
#include <unistd.h>
#include <time.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <stdatomic.h>

#ifdef linux
#include <linux/version.h>
#endif

#include <openssl/ssl.h>

/* Version and branding */
/* VERSION is provided by Makefile via -DVERSION */
#ifndef VERSION
#define VERSION "unknown"
#endif
#define PROGRAM_NAME "tlsgateNG"

/* Network configuration */
#define BACKLOG SOMAXCONN
#define DEFAULT_IP "*"
#define DEFAULT_PORT "80"
#define DEFAULT_TIMEOUT 2              /* 2s - tolerance for slow/distant clients */
#define DEFAULT_KEEPALIVE (DEFAULT_TIMEOUT * 30)  /* 60s - balanced for high load */
#define DEFAULT_THREAD_MAX 1200
#define DEFAULT_CERT_CACHE_SIZE 500
#define SECOND_PORT "443"
#define MAX_PORTS 10
#define MAX_TLS_PORTS 9

/* Default user/group */
#ifdef DROP_ROOT
#define DEFAULT_USER "tlsgateNG"
#define DEFAULT_GROUP "tlsgateNG"
#endif

/* Stats URLs */
#define DEFAULT_STATS_URL "/servstats"
#define DEFAULT_STATS_TEXT_URL "/servstats.txt"

/* Path configuration */
#define TLSGATENG_MAX_PATH 512
#define TLSGATENG_MAX_SERVER_NAME 255

/* Feature detection */
#define FEAT_TFO
#ifdef linux
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,7,0) || defined(ENABLE_TCP_FASTOPEN)
#undef FEAT_TFO
#define FEAT_TFO " tfo"
#endif
#endif

#ifdef TLS1_3_VERSION
#define FEAT_TLS1_3 " tls1_3"
#else
#define FEAT_TLS1_3 " no_tls1_3"
#endif

#define FEATURE_FLAGS " flags:" FEAT_TFO FEAT_TLS1_3

/* TEMP_FAILURE_RETRY macro (fixes musl libc) */
#ifndef TEMP_FAILURE_RETRY
#define TEMP_FAILURE_RETRY(expression) \
  (__extension__                                                              \
    ({ long int __result;                                                     \
       do __result = (long int) (expression);                                 \
       while (__result == -1L && errno == EINTR);                             \
       __result; }))
#endif

/* Test mode */
#ifdef TEST
#define TESTPRINT printf
#else
#define TESTPRINT(x, ...) ((void)0)  /* C23 standard variadic macro */
#endif

/* Global runtime configuration */
struct Global {
    int argc;
    char** argv;
    const time_t select_timeout;
    const time_t http_keepalive;
    const int pipefd;
    const char* const stats_url;
    const char* const stats_text_url;
    const int do_204;
    const int do_redirect;
#ifdef DEBUG
    const int warning_time;
#endif
    const char* pem_dir;
};

#define GLOBAL(p,e) ((struct Global *)p)->e

/* Certificate pipe path */
extern char tlsgateNG_cert_pipe[TLSGATENG_MAX_PATH];

/* Generate random temporary path */
void generate_random_pipe_path(char *buffer, size_t buflen);

/* Thread-safe atomic statistics counters */
extern atomic_int count;    /* Total requests */
extern atomic_int avg;      /* Average request size */
extern atomic_int _act;     /* Average count */
extern atomic_int rmx;      /* Max request size */
extern atomic_int _tct;     /* Time count */
extern atomic_int tav;      /* Average time (ms) */
extern atomic_int tmx;      /* Max time (ms) */
extern atomic_int ers;      /* Errors */
extern atomic_int tmo;      /* Timeouts */
extern atomic_int cls;      /* Close */
extern atomic_int nou;      /* No URL */
extern atomic_int pth;      /* Path */
extern atomic_int nfe;      /* Not found errors */
extern atomic_int ufe;      /* Unknown format errors */
extern atomic_int gif;      /* GIF responses */
extern atomic_int bad;      /* Bad requests */
extern atomic_int txt;      /* Text responses */
extern atomic_int jpg;      /* JPEG responses */
extern atomic_int png;      /* PNG responses */
extern atomic_int swf;      /* SWF responses */
extern atomic_int ico;      /* ICO responses */
extern atomic_int sta;      /* Stats HTML */
extern atomic_int stt;      /* Stats text */
extern atomic_int noc;      /* No content */
extern atomic_int rdr;      /* Redirects */
extern atomic_int pst;      /* POST requests */
extern atomic_int hed;      /* HEAD requests */
extern atomic_int opt;      /* OPTIONS requests */
extern atomic_int cly;      /* Close waiting */
extern atomic_int slh;      /* SSL handshake */
extern atomic_int slm;      /* SSL miss */
extern atomic_int sle;      /* SSL errors */
extern atomic_int slc;      /* SSL cache hits */
extern atomic_int slu;      /* SSL unknown */
extern atomic_int uca;      /* Unknown cert algo */
extern atomic_int ucb;      /* Unknown cert b */
extern atomic_int uce;      /* Unknown cert errors */
extern atomic_int ush;      /* Unknown SSL handshake */
extern atomic_int kcc;      /* Keep-alive current connections */
extern atomic_int kmx;      /* Keep-alive max */
extern atomic_int kct;      /* Keep-alive count */
extern float kvg;           /* Keep-alive average (protected by mutex) */
extern pthread_mutex_t kvg_mutex;
extern pthread_mutex_t favg_mutex;
extern pthread_mutex_t ftav_mutex;
extern atomic_int krq;      /* Keep-alive requests */
extern atomic_int clt;      /* Clients */
extern atomic_int v13;      /* TLS 1.3 connections */
extern atomic_int v12;      /* TLS 1.2 connections */
extern atomic_int v10;      /* TLS 1.0 connections */
extern atomic_int zrt;      /* Zero RTT */

/* Utility functions */

/* Get current time (encapsulated clock_gettime) */
void get_time(struct timespec *time);

/* Get process uptime in seconds */
unsigned int process_uptime(void);

/* Generate version string (caller must free()) */
char* get_version(int argc, char* argv[]);

/* Generate stats string (caller must free())
 * sta_offset: account for in-progress HTML stats response
 * stt_offset: account for in-progress text stats response
 */
char* get_stats(const int sta_offset, const int stt_offset);

/* Exponential moving average */
float ema(float curr, int new, int *cnt);

/* Calculate elapsed time in milliseconds */
double elapsed_time_msec(const struct timespec start_time);

/* Format time_t as human-readable string
 * Returns pointer to static buffer (not thread-safe!)
 */
const char* format_time(time_t t);

/* Backtrace support */
#if defined(__GLIBC__) && defined(BACKTRACE)
void print_trace(void);
#endif

#endif /* TLSGATENG_UTIL_H */
