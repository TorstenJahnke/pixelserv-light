#ifndef UTIL_H
#define UTIL_H

// common configuration items
// _GNU_SOURCE is set by Makefile on Linux only

// system includes used by more than one source file
#include <errno.h>              // EPIPE, errno, EINTR
#include <netdb.h>              // addrinfo(), AI_PASSIVE, gai_strerror(), freeaddrinfo()
#include <netinet/tcp.h>        // SOL_TCP, TCP_NODELAY
#include <signal.h>             // sig_atomic_t
#include <stdio.h>              // printf() and variants
#include <stdlib.h>             // exit(), EXIT_FAILURE
#include <string.h>             // lots of stuff!
#include <syslog.h>             // syslog(), openlog()
#include <unistd.h>             // close(), setuid(), TEMP_FAILURE_RETRY, fork()
#include <time.h>               // struct timespec, clock_gettime(), difftime()
#include <arpa/inet.h>
#ifdef linux
#  include <linux/version.h>
#endif
#include <openssl/ssl.h>

// preprocessor defines
#define VERSION "2.5.6"

/* Listen backlog - how many pending connections queue will hold
 * For 10M+ concurrent users, increase kernel limit:
 *   sysctl -w net.core.somaxconn=65535
 *   sysctl -w net.ipv4.tcp_max_syn_backlog=65535 */
#define BACKLOG SOMAXCONN
#define DEFAULT_IP "*"          // default IP address ALL - use this in messages only
#define DEFAULT_PORT "80"       // the default port users will be connecting to
#define DEFAULT_TIMEOUT 1       // default timeout for select() calls, in seconds
#define DEFAULT_KEEPALIVE (DEFAULT_TIMEOUT * 120)
                                // default keep-alive duration for HTTP/1.1 connections, in seconds
                                // it's the time a connection will stay active
                                // until another request comes and refreshes the timer
/* Enterprise-scale defaults for 10M+ concurrent users
 *
 * Kernel tuning required for production:
 *   sysctl -w net.core.somaxconn=65535
 *   sysctl -w net.ipv4.tcp_max_syn_backlog=65535
 *   sysctl -w net.ipv4.ip_local_port_range="1024 65535"
 *   sysctl -w net.ipv4.tcp_tw_reuse=1
 *   sysctl -w fs.file-max=10000000
 *   ulimit -n 1000000
 *
 * For millions of certificates:
 *   - Use -c 5000000 or higher for cert cache (hash table)
 *   - Sharded index in pem_dir/index/ handles 5-10M certs
 *   - SSL session cache: 1M sessions (PIXEL_SSL_SESS_CACHE_SIZE)
 */
#define DEFAULT_THREAD_MAX 65536  // maximum concurrent service threads (64K)
#define DEFAULT_CERT_CACHE_SIZE 100000
                                // SSL context cache slots (100K default)
                                // For 10M+ domains, use -c 5000000
#define DEFAULT_CERT_VALIDITY_DAYS 100
                                // default certificate validity in days
#define DEFAULT_CERT_KEY_TYPE 1 // 0=RSA2048, 1=RSA3072, 2=RSA4096, 3=RSA8192, 4=RSA16384, 5=ECDSA-P256, 6=ECDSA-P384, 7=SM2
#define SECOND_PORT "443"
#define MAX_PORTS 10
#define MAX_TLS_PORTS 9         // PLEASE ENSURE MAX_TLS_PORTS < MAX_PORTS

#ifdef DROP_ROOT
# define DEFAULT_USER "nobody"  // nobody used by dnsmasq
#endif

# define DEFAULT_STATS_URL "/servstats"
# define DEFAULT_STATS_TEXT_URL "/servstats.txt"

// TEMP_FAILURE_RETRY is in compat.h
#include "compat.h"

/* Atomic operations for stats counters - lock-free increment/decrement
 * Uses GCC/Clang built-in atomics for thread safety without blocking */
#if defined(__GNUC__) || defined(__clang__)
#  define STAT_INC(x) __atomic_fetch_add(&(x), 1, __ATOMIC_RELAXED)
#  define STAT_DEC(x) __atomic_fetch_sub(&(x), 1, __ATOMIC_RELAXED)
#  define STAT_ADD(x, v) __atomic_fetch_add(&(x), (v), __ATOMIC_RELAXED)
#  define STAT_LOAD(x) __atomic_load_n(&(x), __ATOMIC_RELAXED)
#  define STAT_STORE(x, v) __atomic_store_n(&(x), (v), __ATOMIC_RELAXED)
#else
/* Fallback for non-GCC/Clang - not truly atomic but maintains volatile semantics */
#  define STAT_INC(x) (++(x))
#  define STAT_DEC(x) (--(x))
#  define STAT_ADD(x, v) ((x) += (v))
#  define STAT_LOAD(x) (x)
#  define STAT_STORE(x, v) ((x) = (v))
#endif

# define FEAT_TFO
# ifdef linux
#   if LINUX_VERSION_CODE >= KERNEL_VERSION(3,7,0) || ENABLE_TCP_FASTOPEN
#     undef FEAT_TFO
#     define FEAT_TFO " tfo"
#   endif
# endif
# ifdef TLS1_3_VERSION
#   define FEAT_TLS1_3  " tls1_3"
# else
#   define FEAT_TLS1_3  " no_tls1_3"
# endif
# define FEATURE_FLAGS " flags:" FEAT_TFO FEAT_TLS1_3

#ifdef TEST
# define TESTPRINT printf
#else
# define TESTPRINT(x,y...)
#endif

/* Cross-thread count variables - Cache-Line Aligned (64 bytes)
 * IMPORTANT: Each counter is padded to 64 bytes to prevent false-sharing
 * on multi-core systems. This ensures atomic increments on different cores
 * don't invalidate the same cache line, improving performance for 10M+ users.
 */
#define CACHELINE_SIZE 64

/* HTTP Request Counters - Group 1 */
extern volatile sig_atomic_t count __attribute__((aligned(CACHELINE_SIZE))); // req
extern volatile sig_atomic_t avg; // cumulative moving average request size
extern volatile sig_atomic_t _act; // avg count (updated at time of average calculation)
extern volatile sig_atomic_t rmx; // maximum encountered request size

/* Request Timing Counters - Group 2 */
extern volatile sig_atomic_t _tct __attribute__((aligned(CACHELINE_SIZE))); // time count
extern volatile sig_atomic_t tav; // cumulative moving average time in msec
extern volatile sig_atomic_t tmx; // max time in msec

/* Error & Failure Counters - Group 3 */
extern volatile sig_atomic_t ers __attribute__((aligned(CACHELINE_SIZE))); // errors
extern volatile sig_atomic_t tmo; // timeouts
extern volatile sig_atomic_t cls; // client closures
extern volatile sig_atomic_t nou; // no URL

/* Path Counters - Group 4 */
extern volatile sig_atomic_t pth __attribute__((aligned(CACHELINE_SIZE))); // bad path
extern volatile sig_atomic_t nfe; // no file extension
extern volatile sig_atomic_t ufe; // unknown file extension

/* Response Type Counters - Group 5 */
extern volatile sig_atomic_t gif __attribute__((aligned(CACHELINE_SIZE))); // GIF responses
extern volatile sig_atomic_t bad; // BAD responses
extern volatile sig_atomic_t txt; // TXT responses
extern volatile sig_atomic_t jpg; // JPG responses
extern volatile sig_atomic_t png; // PNG responses
extern volatile sig_atomic_t swf; // SWF responses
extern volatile sig_atomic_t ico; // ICO responses

/* Stats Page Counters - Group 6 */
extern volatile sig_atomic_t sta __attribute__((aligned(CACHELINE_SIZE))); // stats HTML
extern volatile sig_atomic_t stt; // stats text
extern volatile sig_atomic_t noc; // 204 no content
extern volatile sig_atomic_t rdr; // redirects

/* HTTP Method Counters - Group 7 */
extern volatile sig_atomic_t pst __attribute__((aligned(CACHELINE_SIZE))); // POST
extern volatile sig_atomic_t hed; // HEAD
extern volatile sig_atomic_t opt; // OPTIONS
extern volatile sig_atomic_t cly; // client closure

/* TLS/SSL Counters - Group 8 */
extern volatile sig_atomic_t slh __attribute__((aligned(CACHELINE_SIZE))); // SSL handshake hit
extern volatile sig_atomic_t slm; // SSL cache miss
extern volatile sig_atomic_t sle; // SSL error
extern volatile sig_atomic_t slc; // SSL context count
extern volatile sig_atomic_t slu; // SSL unknown
extern volatile sig_atomic_t uca; // cert update A
extern volatile sig_atomic_t ucb; // cert update B
extern volatile sig_atomic_t uce; // cert update E
extern volatile sig_atomic_t ush; // cert update SH

/* Cert Cache Counters - Group 9 */
extern volatile sig_atomic_t kcc __attribute__((aligned(CACHELINE_SIZE))); // cert cache count
extern volatile sig_atomic_t kmx; // cert cache max
extern volatile sig_atomic_t kct; // cert cache time
extern volatile float kvg; // cert avg reuse
extern volatile sig_atomic_t krq; // cert requests
extern volatile sig_atomic_t clt; // client timeout

/* TLS Version Counters - Group 10 */
extern volatile sig_atomic_t v13 __attribute__((aligned(CACHELINE_SIZE))); // TLS 1.3
extern volatile sig_atomic_t v12; // TLS 1.2
extern volatile sig_atomic_t v10; // TLS 1.0
extern volatile sig_atomic_t zrt; // 0-RTT

// Certificate configuration
extern int cert_validity_days;  // certificate validity in days
extern int cert_key_type;       // 0=RSA2048, 1=RSA4096, 2=ECDSA-P256, 3=ECDSA-P384

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

// util.c functions

// encapsulation of clock_gettime() to perform one-time degradation of source
//  when necessary
void get_time(struct timespec *time);
unsigned int process_uptime();

// generate version string
// note that caller is expected to call free()
//  on the return value when done using it
char* get_version(int argc, char* argv[]);

// stats string generator
// NOTES:
// - The return value is heap-allocated, so the caller is expected to call
//   free() on the return value when done using it in order to avoid a memory
//   leak.
// - The purpose of sta_offset is to allow accounting for an in-progess status
//   response.
// - Similarly, stt_offset is for an in-progress status.txt response.
char* get_stats(const int sta_offset, const int stt_offset);

float ema(float curr, int new, int *cnt);

double elapsed_time_msec(const struct timespec start_time);

#if defined(__GLIBC__) && defined(BACKTRACE)
void print_trace();
#endif

#endif // UTIL_H
