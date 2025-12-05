/* TLS-Gate NX - Utility Functions Implementation
 * Copyright (C) 2025 Torsten Jahnke
 * TLSGate NextGeneration
 */

#include "util.h"
#include "logger.h"
#include <fcntl.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <time.h>
#include <sys/types.h>
#include <unistd.h>

#ifdef __linux__
#include <sys/syscall.h>
#endif

#if defined(__GLIBC__) && defined(BACKTRACE)
#include <execinfo.h>
#endif

/* Global certificate pipe path */
char tlsgateNG_cert_pipe[TLSGATENG_MAX_PATH];

/* Generate random temporary path for IPC - Thread-safe using /dev/urandom */
void generate_random_pipe_path(char *buffer, size_t buflen) {
    const char charset[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    const int len = 32;
    const size_t min_size = 5 + len + 1;  /* "/tmp/" + 32 chars + '\0' */

    /* Bounds check */
    if (!buffer || buflen < min_size) {
        if (buffer && buflen > 0) buffer[0] = '\0';
        return;
    }

    unsigned char random_bytes[32];
    bool got_random = false;

    /* SECURITY FIX: Try /dev/urandom first with proper read handling */
    int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if (fd >= 0) {
        /* Read with loop to handle partial reads and signals */
        size_t bytes_read = 0;
        ssize_t n;
        while (bytes_read < sizeof(random_bytes)) {
            n = read(fd, random_bytes + bytes_read, sizeof(random_bytes) - bytes_read);
            if (n < 0) {
                /* SECURITY FIX: Retry on EINTR (signal interruption) */
                if (errno == EINTR) {
                    continue;
                }
                break;  /* Real error on read */
            }
            if (n == 0) {
                break;  /* EOF (unexpected) */
            }
            bytes_read += n;
        }
        close(fd);

        if (bytes_read == sizeof(random_bytes)) {
            got_random = true;
        }
    }

    /* Fallback to /dev/random if /dev/urandom fails (slower but acceptable) */
    if (!got_random) {
        fd = open("/dev/random", O_RDONLY | O_CLOEXEC | O_NONBLOCK);
        if (fd >= 0) {
            /* SECURITY FIX: Handle partial reads and EINTR for /dev/random too */
            size_t bytes_read = 0;
            ssize_t n;
            while (bytes_read < sizeof(random_bytes)) {
                n = read(fd, random_bytes + bytes_read, sizeof(random_bytes) - bytes_read);
                if (n < 0) {
                    if (errno == EINTR) {
                        continue;  /* Retry on signal */
                    }
                    if (errno == EAGAIN || errno == EWOULDBLOCK) {
                        break;  /* No entropy available (non-blocking) */
                    }
                    break;  /* Real error */
                }
                if (n == 0) {
                    break;  /* EOF (unexpected) */
                }
                bytes_read += n;
            }
            close(fd);

            if (bytes_read == sizeof(random_bytes)) {
                got_random = true;
            }
        }
    }

    /* Fallback to getrandom (if available on Linux 3.17+) */
    if (!got_random) {
        #ifdef SYS_getrandom
        /* SECURITY FIX: getrandom() can also be interrupted by signals */
        ssize_t result;
        do {
            result = syscall(SYS_getrandom, random_bytes, sizeof(random_bytes), 0);
        } while (result < 0 && errno == EINTR);

        if (result == sizeof(random_bytes)) {
            got_random = true;
        }
        #endif
    }

    /* SECURITY FIX: Enhanced fallback with CRITICAL warning
     * NOTE: This fallback should NEVER be used in production!
     * It's only here for ancient/broken systems where all hardware RNGs fail.
     * On any modern Linux, /dev/urandom or getrandom() will work. */
    if (!got_random) {
        LOG_ERROR("CRITICAL SECURITY WARNING: No hardware RNG available!");
        LOG_ERROR("All secure random sources failed (/dev/urandom, /dev/random, getrandom)");
        LOG_ERROR("Falling back to WEAK pseudo-random generator for temp paths");
        LOG_ERROR("This should NEVER happen on modern systems!");

        /* Use multiple entropy sources for better (but still weak!) seed */
        uint64_t seed = 0;
        seed ^= (uint64_t)time(NULL);
        seed ^= (uint64_t)getpid();
        seed ^= (uint64_t)getppid();
        seed ^= (uint64_t)getuid();
        seed ^= (uint64_t)getgid();

        /* Try to get some entropy from timing */
        struct timespec ts;
        if (clock_gettime(CLOCK_MONOTONIC, &ts) == 0) {
            seed ^= (uint64_t)ts.tv_sec;
            seed ^= (uint64_t)ts.tv_nsec;
        }
        if (clock_gettime(CLOCK_REALTIME, &ts) == 0) {
            seed ^= (uint64_t)ts.tv_sec;
            seed ^= (uint64_t)ts.tv_nsec;
        }

        /* Try to get address space randomization as entropy */
        void *stack_ptr = &seed;
        seed ^= (uint64_t)(uintptr_t)stack_ptr;

        /* Use a better PRNG if available (not cryptographically secure!) */
        #if defined(__linux__)
        unsigned int random_state = (unsigned int)seed;
        for (size_t i = 0; i < sizeof(random_bytes); i++) {
            random_bytes[i] = (unsigned char)(rand_r(&random_state) & 0xFF);
        }
        #else
        srand((unsigned int)seed);
        for (size_t i = 0; i < sizeof(random_bytes); i++) {
            random_bytes[i] = (unsigned char)(rand() & 0xFF);
        }
        #endif

        got_random = true;
    }

    /* Build path from random bytes */
    snprintf(buffer, buflen, "/tmp/");
    for (int i = 0; i < len; i++) {
        buffer[5 + i] = charset[random_bytes[i] % (sizeof(charset) - 1)];
    }
    buffer[5 + len] = '\0';
}

/* Thread-safe atomic statistics counters - using C11 atomics */
atomic_int count = 0;
atomic_int avg = 0;
atomic_int _act = 0;
atomic_int rmx = 0;
atomic_int _tct = 0;
atomic_int tav = 0;
atomic_int tmx = 0;
atomic_int ers = 0;
atomic_int tmo = 0;
atomic_int cls = 0;
atomic_int nou = 0;
atomic_int pth = 0;
atomic_int nfe = 0;
atomic_int ufe = 0;
atomic_int gif = 0;
atomic_int bad = 0;
atomic_int txt = 0;
atomic_int jpg = 0;
atomic_int png = 0;
atomic_int swf = 0;
atomic_int ico = 0;
atomic_int sta = 0;
atomic_int stt = 0;
atomic_int noc = 0;
atomic_int rdr = 0;
atomic_int pst = 0;
atomic_int hed = 0;
atomic_int opt = 0;
atomic_int cly = 0;
atomic_int slh = 0;
atomic_int slm = 0;
atomic_int sle = 0;
atomic_int slc = 0;
atomic_int slu = 0;
atomic_int uca = 0;
atomic_int ucb = 0;
atomic_int uce = 0;
atomic_int ush = 0;
atomic_int kcc = 0;  /* CRITICAL: Connection counter - must be atomic */
atomic_int kmx = 0;
atomic_int kct = 0;
float kvg = 0.0;     /* Protected by kvg_mutex (see below) */
pthread_mutex_t kvg_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t favg_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t ftav_mutex = PTHREAD_MUTEX_INITIALIZER;
atomic_int krq = 0;
atomic_int clt = 0;
atomic_int v13 = 0;
atomic_int v12 = 0;
atomic_int v10 = 0;
atomic_int zrt = 0;

/* Time tracking */
static struct timespec startup_time = {0, 0};

/* THREAD SAFETY FIX: Use atomic to prevent race condition
 * Multiple threads could simultaneously try to upgrade clock_source
 * from CLOCK_MONOTONIC to CLOCK_REALTIME, causing TOCTOU bug.
 * Using atomic compare-exchange ensures only one thread updates. */
static atomic_int clock_source = CLOCK_MONOTONIC;

void get_time(struct timespec *time) {
    clockid_t source = atomic_load_explicit(&clock_source, memory_order_acquire);

    if (clock_gettime(source, time) < 0) {
        if (errno == EINVAL && source == CLOCK_MONOTONIC) {
            /* CLOCK_MONOTONIC not supported - try to upgrade to CLOCK_REALTIME
             * Use atomic compare-exchange to ensure only ONE thread performs the upgrade */
            clockid_t expected = CLOCK_MONOTONIC;
            if (atomic_compare_exchange_strong_explicit(&clock_source,
                                                       &expected,
                                                       CLOCK_REALTIME,
                                                       memory_order_acq_rel,
                                                       memory_order_acquire)) {
                LOG_WARN("CLOCK_MONOTONIC not supported, falling back to CLOCK_REALTIME");
            }
            /* Retry with updated clock source (whether we updated it or another thread did) */
            get_time(time);
        } else {
            /* Fatal error or different errno - return zero time */
            time->tv_sec = time->tv_nsec = 0;
        }
    }
}

unsigned int process_uptime(void) {
    struct timespec now;
    get_time(&now);
    return (unsigned int) difftime(now.tv_sec, startup_time.tv_sec);
}

char* get_version(int argc, char* argv[]) {
    char* retbuf = NULL;
    char* optbuf = NULL;
    unsigned int optlen = 0, freeoptbuf = 0;

    /* CRITICAL BUG FIX: Replaced VLA (Variable Length Array) with dynamic allocation
     * VLA on stack can cause stack overflow with large argc values (argv[])
     * Example: argc=10000 → 40KB on stack, stack overflow on embedded systems
     * Solution: Use malloc instead for safe memory management */
    unsigned int *arglen = NULL;

    if (argc > 0) {
        arglen = malloc(argc * sizeof(unsigned int));
        if (!arglen) {
            /* Fallback to safe static response on malloc failure */
            return "TLS-Gate NX (memory error)";
        }
    }

    if (!startup_time.tv_sec) {
        get_time(&startup_time);
    }

    for (int i = 1; i < argc; ++i) {
        arglen[i] = strlen(argv[i]) + 1;
        optlen += arglen[i];
    }

    if (optlen > 0) {
        optbuf = malloc((optlen * sizeof(char)) + 1);
        if (optbuf) {
            freeoptbuf = 1;
            for (int i = 1, optlen = 0; i < argc; ++i) {
                optbuf[optlen] = ' ';
                strncpy(optbuf + optlen + 1, argv[i], arglen[i]);
                optlen += arglen[i];
            }
            optbuf[optlen] = '\0';
        } else {
            optbuf = " <malloc error>";
        }
    } else {
        optbuf = " <none>";
    }

    if (asprintf(&retbuf, "TLS-Gate NX %s (compiled: %s" FEATURE_FLAGS ") options:%s",
            VERSION, __DATE__ " " __TIME__, optbuf) < 1) {
        retbuf = " <asprintf error>";
    }

    if (freeoptbuf) {
        free(optbuf);
    }

    /* CLEANUP: Free arglen array (allocated with malloc in VLA fix) */
    if (arglen) {
        free(arglen);
    }

    return retbuf;
}

/* Forward declarations for cert cache functions (will be in cert_cache.c) */
extern int sslctx_tbl_get_cnt_total(void);
extern int sslctx_tbl_get_cnt_hit(void);
extern int sslctx_tbl_get_cnt_miss(void);
extern int sslctx_tbl_get_cnt_purge(void);
extern int sslctx_tbl_get_sess_cnt(void);
extern int sslctx_tbl_get_sess_hit(void);
extern int sslctx_tbl_get_sess_miss(void);
extern int sslctx_tbl_get_sess_purge(void);

char* get_stats(const int sta_offset, const int stt_offset ) {
    (void)stt_offset;  /* Reserved for future statistics table offset */
    char* retbuf = NULL;
    char* uptimeStr = NULL;
    unsigned int uptime = process_uptime();

    const char* sta_fmt = "<br><table>"
        "<tr><td>uts</td><td>%s</td><td>process uptime</td></tr>"
        "<tr><td>log</td><td>%d</td><td>log level (0=SILENT 1=ERROR 2=WARN 3=INFO 4=DEBUG 5=TRACE)</td></tr>"
        "<tr><td>kcc</td><td>%d</td><td>active service threads</td></tr>"
        "<tr><td>kmx</td><td>%d</td><td>maximum service threads</td></tr>"
        "<tr><td>kvg</td><td>%.2f</td><td>average requests per thread</td></tr>"
        "<tr><td>krq</td><td>%d</td><td>max requests by one thread</td></tr>"
        "<tr><th colspan=\"3\"></th></tr>"
        "<tr><td>req</td><td>%d</td><td>total # of requests</td></tr>"
        "<tr><td>avg</td><td>%d bytes</td><td>average request size</td></tr>"
        "<tr><td>rmx</td><td>%d bytes</td><td>largest request</td></tr>"
        "<tr><td>tav</td><td>%d ms</td><td>average processing time</td></tr>"
        "<tr><td>tmx</td><td>%d ms</td><td>longest processing time</td></tr>"
        "<tr><th colspan=\"3\"></th></tr>"
        "<tr><td>slh</td><td>%d</td><td>accepted HTTPS requests</td></tr>"
        "<tr><td>slm</td><td>%d</td><td>rejected (missing cert)</td></tr>"
        "<tr><td>sle</td><td>%d</td><td>rejected (cert not usable)</td></tr>"
        "<tr><td>slc</td><td>%d</td><td>dropped (client disconnect)</td></tr>"
        "<tr><td>slu</td><td>%d</td><td>dropped (TLS errors)</td></tr>"
        "<tr><th colspan=\"3\"></th></tr>"
        "<tr><td>v13</td><td>%d</td><td>TLS 1.3 connections</td></tr>"
        "<tr><td>v12</td><td>%d</td><td>TLS 1.2 connections</td></tr>"
        "<tr><td>v10</td><td>%d</td><td>TLS 1.0 connections</td></tr>"
        "<tr><td>zrt</td><td>%d</td><td>TLS 1.3 0-RTT</td></tr>"
        "</table>";

    const char* stt_fmt = "%d uts, %d log, %d kcc, %d kmx, %.2f kvg, %d krq, "
        "%d req, %d avg, %d rmx, %d tav, %d tmx, "
        "%d slh, %d slm, %d sle, %d slc, %d slu, "
        "%d v13, %d v12, %d v10, %d zrt";

    /* Thread-safe copy of kvg */
    float kvg_snapshot;
    pthread_mutex_lock(&kvg_mutex);
    kvg_snapshot = kvg;
    pthread_mutex_unlock(&kvg_mutex);

    if (sta_offset) {
        int ret = asprintf(&uptimeStr, "%dd %02d:%02d",
                (int)uptime/86400, (int)(uptime%86400)/3600,
                (int)((uptime%86400)%3600)/60);
        if (ret < 0) {
            uptimeStr = strdup("N/A");  /* Fallback for asprintf failure */
        }
    }

    if (asprintf(&retbuf, (sta_offset) ? sta_fmt : stt_fmt,
            (sta_offset) ? (uptimeStr ? uptimeStr : "N/A") : (char*)(long)uptime,
            log_get_level(), kcc, kmx, kvg_snapshot, krq,
            count, avg, rmx, tav, tmx,
            slh, slm, sle, slc, slu,
            v13, v12, v10, zrt) < 1) {
        retbuf = " <asprintf error>";
    }

    if (uptimeStr) {
        free(uptimeStr);
    }

    return retbuf;
}

float ema(float curr, int new, int *cnt) {
    /* Exponential moving average with overflow protection */
    if (*cnt < 500) {
        curr *= *cnt;
        curr = (curr + new) / ++(*cnt);
    } else {
        curr += 0.002 * (new - curr);
    }
    return curr;
}

double elapsed_time_msec(const struct timespec start_time) {
    struct timespec current_time = {0, 0};
    struct timespec diff_time = {0, 0};

    if (!start_time.tv_sec && !start_time.tv_nsec) {
        return -1.0;
    }

    get_time(&current_time);

    diff_time.tv_sec = difftime(current_time.tv_sec, start_time.tv_sec) + 0.5;
    diff_time.tv_nsec = current_time.tv_nsec - start_time.tv_nsec;
    if (diff_time.tv_nsec < 0) {
        diff_time.tv_sec  -= 1;
        diff_time.tv_nsec += 1000000000;
    }

    return diff_time.tv_sec * 1000 + ((double)diff_time.tv_nsec / 1000000);
}

/* Format time_t as human-readable string (thread-safe using thread-local storage) */
const char* format_time(time_t t) {
    static _Thread_local char buffer[64];
    struct tm tm;

    if (localtime_r(&t, &tm) == NULL) {
        snprintf(buffer, sizeof(buffer), "Invalid time");
        return buffer;
    }

    strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", &tm);
    return buffer;
}

#if defined(__GLIBC__) && defined(BACKTRACE)
void print_trace(void) {
    void *buf[32];
    char **strings;
    int size;

    size = backtrace(buf, 32);
    strings = backtrace_symbols(buf, size);

    LOG_ERROR("Backtrace (%d frames):", size);
    for (int i = 0; i < size; i++) {
        LOG_ERROR("  [%d] %s", i, strings[i]);
    }

    free(strings);
    exit(EXIT_FAILURE);
}
#endif
