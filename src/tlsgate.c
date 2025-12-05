/*
 * tlsgate.c - TLSGate Ultra-Scale TLS Pixel Server
 *
 * Main entry point for the event-driven architecture
 * Designed for 10M+ concurrent connections on 32-core EPYC / 256GB RAM
 *
 * Architecture:
 *   - Multi-process with SO_REUSEPORT for accept distribution
 *   - Event-driven workers (epoll) handling 100K+ connections each
 *   - Lock-free data structures throughout
 *   - Zero malloc during request handling
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <getopt.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/resource.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <pwd.h>
#include <grp.h>

#include "../include/connection.h"
#include "../include/buffer_pool.h"
#include "../include/worker.h"
#include "../include/response.h"

/* =============================================================================
 * Configuration
 * =============================================================================
 */

#define TLSGATE_VERSION "1.0.0"
#define DEFAULT_HTTP_PORT 80
#define DEFAULT_HTTPS_PORT 443
#define DEFAULT_WORKERS 0           /* 0 = auto-detect CPU cores */
#define DEFAULT_CONNS_PER_WORKER 500000
#define DEFAULT_USER "nobody"

typedef struct {
    /* Network */
    char *bind_addr;
    int http_port;
    int https_port;

    /* Scaling */
    int num_workers;
    int num_processes;
    uint32_t conns_per_worker;

    /* Paths */
    char *cert_dir;
    char *ca_cert;
    char *ca_key;

    /* Security */
    char *user;
    int daemonize;

    /* Debug */
    int verbose;
} config_t;

static config_t config = {
    .bind_addr = "0.0.0.0",
    .http_port = DEFAULT_HTTP_PORT,
    .https_port = DEFAULT_HTTPS_PORT,
    .num_workers = DEFAULT_WORKERS,
    .num_processes = 1,
    .conns_per_worker = DEFAULT_CONNS_PER_WORKER,
    .cert_dir = "/var/cache/tlsgate",
    .ca_cert = NULL,
    .ca_key = NULL,
    .user = DEFAULT_USER,
    .daemonize = 1,
    .verbose = 0
};

/* =============================================================================
 * Global State
 * =============================================================================
 */

static volatile sig_atomic_t g_running = 1;
static volatile sig_atomic_t g_reload = 0;
static worker_pool_t g_worker_pool;
static int g_listen_fds[2];  /* HTTP and HTTPS */
static int g_listen_count = 0;

/* =============================================================================
 * Signal Handling
 * =============================================================================
 */

static void signal_handler(int sig)
{
    switch (sig) {
    case SIGTERM:
    case SIGINT:
        g_running = 0;
        break;
    case SIGHUP:
        g_reload = 1;
        break;
    case SIGPIPE:
        /* Ignore */
        break;
    }
}

static void setup_signals(void)
{
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);

    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGHUP, &sa, NULL);

    sa.sa_handler = SIG_IGN;
    sigaction(SIGPIPE, &sa, NULL);
}

/* =============================================================================
 * Socket Setup
 * =============================================================================
 */

static int create_listen_socket(const char *addr, int port, int reuse_port)
{
    int fd = socket(AF_INET6, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        /* Fallback to IPv4 */
        fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
        if (fd < 0) {
            perror("socket");
            return -1;
        }
    }

    int opt = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    if (reuse_port) {
        setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));
    }

    /* Allow both IPv4 and IPv6 */
    opt = 0;
    setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &opt, sizeof(opt));

    /* TCP optimizations */
    opt = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt));

#ifdef TCP_FASTOPEN
    opt = 256;  /* Queue length */
    setsockopt(fd, IPPROTO_TCP, TCP_FASTOPEN, &opt, sizeof(opt));
#endif

#ifdef TCP_DEFER_ACCEPT
    opt = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_DEFER_ACCEPT, &opt, sizeof(opt));
#endif

    struct sockaddr_in6 addr6;
    memset(&addr6, 0, sizeof(addr6));
    addr6.sin6_family = AF_INET6;
    addr6.sin6_port = htons(port);
    addr6.sin6_addr = in6addr_any;

    if (bind(fd, (struct sockaddr *)&addr6, sizeof(addr6)) < 0) {
        /* Try IPv4 */
        struct sockaddr_in addr4;
        memset(&addr4, 0, sizeof(addr4));
        addr4.sin_family = AF_INET;
        addr4.sin_port = htons(port);
        addr4.sin_addr.s_addr = INADDR_ANY;

        if (bind(fd, (struct sockaddr *)&addr4, sizeof(addr4)) < 0) {
            perror("bind");
            close(fd);
            return -1;
        }
    }

    /* Large backlog for high connection rates */
    if (listen(fd, 65535) < 0) {
        perror("listen");
        close(fd);
        return -1;
    }

    return fd;
}

/* =============================================================================
 * Resource Limits
 * =============================================================================
 */

static void setup_rlimits(uint32_t max_connections)
{
    struct rlimit rl;

    /* File descriptors */
    rl.rlim_cur = max_connections + 1000;
    rl.rlim_max = max_connections + 1000;
    if (setrlimit(RLIMIT_NOFILE, &rl) != 0) {
        fprintf(stderr, "Warning: Cannot set RLIMIT_NOFILE to %u: %s\n",
                (unsigned)(max_connections + 1000), strerror(errno));
    }

    /* Core dumps (disable in production) */
    rl.rlim_cur = 0;
    rl.rlim_max = 0;
    setrlimit(RLIMIT_CORE, &rl);
}

/* =============================================================================
 * Privilege Dropping
 * =============================================================================
 */

static int drop_privileges(const char *username)
{
    if (getuid() != 0)
        return 0;  /* Not root, nothing to drop */

    struct passwd *pw = getpwnam(username);
    if (!pw) {
        fprintf(stderr, "User '%s' not found\n", username);
        return -1;
    }

    if (setgroups(0, NULL) != 0) {
        perror("setgroups");
        return -1;
    }

    if (setgid(pw->pw_gid) != 0) {
        perror("setgid");
        return -1;
    }

    if (setuid(pw->pw_uid) != 0) {
        perror("setuid");
        return -1;
    }

    return 0;
}

/* =============================================================================
 * Usage / Help
 * =============================================================================
 */

static void print_usage(const char *progname)
{
    printf("TLSGate %s - Ultra-Scale TLS Pixel Server\n\n", TLSGATE_VERSION);
    printf("Usage: %s [OPTIONS]\n\n", progname);
    printf("Options:\n");
    printf("  -a, --addr ADDR       Bind address (default: 0.0.0.0)\n");
    printf("  -p, --http-port PORT  HTTP port (default: 80)\n");
    printf("  -s, --https-port PORT HTTPS port (default: 443)\n");
    printf("  -w, --workers N       Worker threads per process (default: auto)\n");
    printf("  -P, --processes N     Number of processes (default: 1)\n");
    printf("  -c, --connections N   Max connections per worker (default: 500000)\n");
    printf("  -d, --cert-dir DIR    Certificate directory\n");
    printf("  -C, --ca-cert FILE    CA certificate file\n");
    printf("  -K, --ca-key FILE     CA private key file\n");
    printf("  -u, --user USER       Drop privileges to user (default: nobody)\n");
    printf("  -f, --foreground      Stay in foreground\n");
    printf("  -v, --verbose         Verbose output\n");
    printf("  -h, --help            Show this help\n");
    printf("\n");
    printf("Example:\n");
    printf("  %s -w 32 -c 1000000   # 32 workers, 1M connections each = 32M total\n", progname);
    printf("\n");
}

/* =============================================================================
 * Main
 * =============================================================================
 */

int main(int argc, char *argv[])
{
    static struct option long_options[] = {
        {"addr",        required_argument, 0, 'a'},
        {"http-port",   required_argument, 0, 'p'},
        {"https-port",  required_argument, 0, 's'},
        {"workers",     required_argument, 0, 'w'},
        {"processes",   required_argument, 0, 'P'},
        {"connections", required_argument, 0, 'c'},
        {"cert-dir",    required_argument, 0, 'd'},
        {"ca-cert",     required_argument, 0, 'C'},
        {"ca-key",      required_argument, 0, 'K'},
        {"user",        required_argument, 0, 'u'},
        {"foreground",  no_argument,       0, 'f'},
        {"verbose",     no_argument,       0, 'v'},
        {"help",        no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "a:p:s:w:P:c:d:C:K:u:fvh",
                              long_options, NULL)) != -1) {
        switch (opt) {
        case 'a': config.bind_addr = optarg; break;
        case 'p': config.http_port = atoi(optarg); break;
        case 's': config.https_port = atoi(optarg); break;
        case 'w': config.num_workers = atoi(optarg); break;
        case 'P': config.num_processes = atoi(optarg); break;
        case 'c': config.conns_per_worker = atoi(optarg); break;
        case 'd': config.cert_dir = optarg; break;
        case 'C': config.ca_cert = optarg; break;
        case 'K': config.ca_key = optarg; break;
        case 'u': config.user = optarg; break;
        case 'f': config.daemonize = 0; break;
        case 'v': config.verbose++; break;
        case 'h':
            print_usage(argv[0]);
            return 0;
        default:
            print_usage(argv[0]);
            return 1;
        }
    }

    /* Auto-detect workers from CPU count */
    if (config.num_workers <= 0) {
        config.num_workers = sysconf(_SC_NPROCESSORS_ONLN);
        if (config.num_workers <= 0)
            config.num_workers = 4;
    }

    printf("TLSGate %s starting...\n", TLSGATE_VERSION);
    printf("  Workers: %d\n", config.num_workers);
    printf("  Connections per worker: %u\n", config.conns_per_worker);
    printf("  Total capacity: %lu connections\n",
           (unsigned long)config.num_workers * config.conns_per_worker);

    /* Setup resource limits */
    uint32_t total_conns = config.num_workers * config.conns_per_worker;
    setup_rlimits(total_conns);

    /* Setup signals */
    setup_signals();

    /* Create listening sockets */
    g_listen_fds[0] = create_listen_socket(config.bind_addr, config.http_port, 1);
    if (g_listen_fds[0] >= 0) {
        g_listen_count++;
        printf("  Listening on HTTP port %d\n", config.http_port);
    }

    g_listen_fds[1] = create_listen_socket(config.bind_addr, config.https_port, 1);
    if (g_listen_fds[1] >= 0) {
        g_listen_count++;
        printf("  Listening on HTTPS port %d\n", config.https_port);
    }

    if (g_listen_count == 0) {
        fprintf(stderr, "Failed to create any listening sockets\n");
        return 1;
    }

    /* Initialize buffer pools */
    if (buffer_pools_init(total_conns) != 0) {
        fprintf(stderr, "Failed to initialize buffer pools\n");
        return 1;
    }
    printf("  Buffer pools initialized\n");

    /* Drop privileges after binding to ports */
    if (drop_privileges(config.user) != 0) {
        fprintf(stderr, "Failed to drop privileges\n");
        return 1;
    }

    /* Daemonize if requested */
    if (config.daemonize) {
        if (daemon(0, 0) != 0) {
            perror("daemon");
            return 1;
        }
    }

    /* Initialize response system (pre-build favicon, etc.) */
    response_init();

    /* Initialize worker pool */
    if (worker_pool_init(&g_worker_pool, config.num_workers,
                         config.conns_per_worker,
                         g_listen_fds, g_listen_count) != 0) {
        fprintf(stderr, "Failed to initialize worker pool\n");
        return 1;
    }

    /* Start workers */
    if (worker_pool_start(&g_worker_pool) != 0) {
        fprintf(stderr, "Failed to start workers\n");
        return 1;
    }

    printf("TLSGate running with %d workers\n", config.num_workers);

    /* Main loop - just wait for signals */
    while (g_running) {
        sleep(1);

        if (g_reload) {
            g_reload = 0;
            /* TODO: Reload configuration */
        }

        if (config.verbose) {
            uint64_t accepted, closed, requests, errors;
            worker_pool_stats(&g_worker_pool, &accepted, &closed, &requests, &errors);
            printf("Stats: accepted=%lu closed=%lu requests=%lu errors=%lu active=%lu\n",
                   accepted, closed, requests, errors, accepted - closed);
        }
    }

    printf("TLSGate shutting down...\n");

    /* Stop workers */
    worker_pool_stop(&g_worker_pool);
    worker_pool_wait(&g_worker_pool);
    worker_pool_destroy(&g_worker_pool);

    /* Cleanup */
    buffer_pools_destroy();

    for (int i = 0; i < g_listen_count; i++) {
        if (g_listen_fds[i] >= 0)
            close(g_listen_fds[i]);
    }

    printf("TLSGate stopped.\n");
    return 0;
}
