/*
 * index_udp.c - UDP Write Queue for Certificate Index
 *
 * High-performance asynchronous index updates via UDP.
 *
 * Implementation:
 *   - Lock-free SPMC ring buffer for batching
 *   - epoll-based UDP socket handling
 *   - Batch commits for efficiency
 *   - Atomic statistics
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <ctype.h>
#include <pthread.h>
#include <stdatomic.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <time.h>

#include "../include/index_udp.h"

/* FNV-1a hash function (same as cert_index) */
#define FNV_OFFSET 2166136261U
#define FNV_PRIME  16777619U

static inline uint32_t fnv1a_lower(const char *str) {
    uint32_t hash = FNV_OFFSET;
    while (*str) {
        hash ^= (uint32_t)(unsigned char)tolower(*str);
        hash *= FNV_PRIME;
        str++;
    }
    return hash;
}

/* Hash domain + algo for composite key */
static inline uint32_t hash_domain_algo(const char *domain, int algo) {
    uint32_t hash = fnv1a_lower(domain);
    hash ^= (uint32_t)':';
    hash *= FNV_PRIME;
    hash ^= (uint32_t)algo;
    hash *= FNV_PRIME;
    return hash;
}

/* ==========================================================================
 * Client Implementation
 * ========================================================================== */

static int g_client_fd = -1;
static struct sockaddr_in g_server_addr;
static _Atomic int g_client_initialized = 0;

int index_udp_client_init(const char *host, uint16_t port) {
    if (atomic_exchange(&g_client_initialized, 1)) {
        return 0;  /* Already initialized */
    }

    g_client_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (g_client_fd < 0) {
        perror("[INDEX-UDP] socket");
        atomic_store(&g_client_initialized, 0);
        return -1;
    }

    /* Set non-blocking */
    int flags = fcntl(g_client_fd, F_GETFL, 0);
    fcntl(g_client_fd, F_SETFL, flags | O_NONBLOCK);

    /* Configure server address */
    memset(&g_server_addr, 0, sizeof(g_server_addr));
    g_server_addr.sin_family = AF_INET;
    g_server_addr.sin_port = htons(port ? port : INDEX_UDP_DEFAULT_PORT);

    if (host && host[0]) {
        if (inet_pton(AF_INET, host, &g_server_addr.sin_addr) != 1) {
            /* Try hostname resolution */
            g_server_addr.sin_addr.s_addr = inet_addr(host);
        }
    } else {
        g_server_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    }

    return 0;
}

void index_udp_client_shutdown(void) {
    if (atomic_exchange(&g_client_initialized, 0)) {
        if (g_client_fd >= 0) {
            close(g_client_fd);
            g_client_fd = -1;
        }
    }
}

int index_udp_client_insert(const char *domain,
                            int algo,
                            uint32_t cert_id,
                            uint64_t expiry) {
    if (!atomic_load(&g_client_initialized) || !domain) {
        return -1;
    }

    size_t domain_len = strlen(domain);
    if (domain_len > INDEX_UDP_MAX_DOMAIN) {
        return -1;
    }

    /* Build message */
    uint8_t buf[INDEX_UDP_MAX_PAYLOAD];
    index_udp_header_t *hdr = (index_udp_header_t *)buf;
    index_udp_insert_t *payload = (index_udp_insert_t *)(buf + sizeof(*hdr));

    hdr->magic = INDEX_UDP_MAGIC;
    hdr->version = INDEX_UDP_VERSION;
    hdr->msg_type = IDX_MSG_INSERT;
    hdr->payload_len = sizeof(*payload) + domain_len;

    /* Pre-compute hash for zero server-side CPU */
    payload->composite_hash = hash_domain_algo(domain, algo);
    payload->cert_id = cert_id;
    payload->expiry = expiry;
    payload->algo = (uint8_t)algo;
    payload->domain_len = (uint8_t)domain_len;
    payload->reserved = 0;

    /* Copy domain name */
    memcpy(buf + sizeof(*hdr) + sizeof(*payload), domain, domain_len);

    /* Fire-and-forget send */
    size_t total_len = sizeof(*hdr) + sizeof(*payload) + domain_len;
    ssize_t sent = sendto(g_client_fd, buf, total_len, 0,
                          (struct sockaddr *)&g_server_addr,
                          sizeof(g_server_addr));

    return (sent == (ssize_t)total_len) ? 0 : -1;
}

int index_udp_client_remove(const char *domain, int algo) {
    if (!atomic_load(&g_client_initialized) || !domain) {
        return -1;
    }

    size_t domain_len = strlen(domain);
    if (domain_len > INDEX_UDP_MAX_DOMAIN) {
        return -1;
    }

    /* Build message */
    uint8_t buf[INDEX_UDP_MAX_PAYLOAD];
    index_udp_header_t *hdr = (index_udp_header_t *)buf;
    index_udp_insert_t *payload = (index_udp_insert_t *)(buf + sizeof(*hdr));

    hdr->magic = INDEX_UDP_MAGIC;
    hdr->version = INDEX_UDP_VERSION;
    hdr->msg_type = IDX_MSG_REMOVE;
    hdr->payload_len = sizeof(*payload) + domain_len;

    payload->composite_hash = hash_domain_algo(domain, algo);
    payload->cert_id = 0;
    payload->expiry = 0;
    payload->algo = (uint8_t)algo;
    payload->domain_len = (uint8_t)domain_len;
    payload->reserved = 0;

    memcpy(buf + sizeof(*hdr) + sizeof(*payload), domain, domain_len);

    size_t total_len = sizeof(*hdr) + sizeof(*payload) + domain_len;
    ssize_t sent = sendto(g_client_fd, buf, total_len, 0,
                          (struct sockaddr *)&g_server_addr,
                          sizeof(g_server_addr));

    return (sent == (ssize_t)total_len) ? 0 : -1;
}

int index_udp_client_sync(int timeout_ms) {
    if (!atomic_load(&g_client_initialized)) {
        return -1;
    }

    /* Build sync message */
    index_udp_header_t hdr = {
        .magic = INDEX_UDP_MAGIC,
        .version = INDEX_UDP_VERSION,
        .msg_type = IDX_MSG_SYNC,
        .payload_len = 0
    };

    sendto(g_client_fd, &hdr, sizeof(hdr), 0,
           (struct sockaddr *)&g_server_addr, sizeof(g_server_addr));

    if (timeout_ms <= 0) {
        return 0;  /* No wait */
    }

    /* Wait for response */
    struct pollfd pfd = { .fd = g_client_fd, .events = POLLIN };
    if (poll(&pfd, 1, timeout_ms) <= 0) {
        return -1;  /* Timeout */
    }

    uint8_t buf[64];
    ssize_t n = recv(g_client_fd, buf, sizeof(buf), 0);
    if (n < (ssize_t)sizeof(index_udp_header_t)) {
        return -1;
    }

    index_udp_header_t *resp = (index_udp_header_t *)buf;
    if (resp->magic != INDEX_UDP_MAGIC || resp->msg_type != IDX_MSG_SYNC) {
        return -1;
    }

    return 0;
}

int64_t index_udp_client_ping(int timeout_ms) {
    if (!atomic_load(&g_client_initialized)) {
        return -1;
    }

    struct timeval tv_start, tv_end;
    gettimeofday(&tv_start, NULL);

    /* Send ping */
    index_udp_header_t hdr = {
        .magic = INDEX_UDP_MAGIC,
        .version = INDEX_UDP_VERSION,
        .msg_type = IDX_MSG_PING,
        .payload_len = 0
    };

    sendto(g_client_fd, &hdr, sizeof(hdr), 0,
           (struct sockaddr *)&g_server_addr, sizeof(g_server_addr));

    /* Wait for pong */
    struct pollfd pfd = { .fd = g_client_fd, .events = POLLIN };
    if (poll(&pfd, 1, timeout_ms) <= 0) {
        return -1;
    }

    uint8_t buf[64];
    ssize_t n = recv(g_client_fd, buf, sizeof(buf), 0);
    if (n < (ssize_t)sizeof(index_udp_header_t)) {
        return -1;
    }

    index_udp_header_t *resp = (index_udp_header_t *)buf;
    if (resp->magic != INDEX_UDP_MAGIC || resp->msg_type != IDX_MSG_PONG) {
        return -1;
    }

    gettimeofday(&tv_end, NULL);

    int64_t latency_us = (tv_end.tv_sec - tv_start.tv_sec) * 1000000LL +
                         (tv_end.tv_usec - tv_start.tv_usec);
    return latency_us;
}

/* ==========================================================================
 * Server Implementation
 * ========================================================================== */

/* Ring buffer entry for batching */
typedef struct {
    uint32_t composite_hash;
    uint32_t cert_id;
    uint64_t expiry;
    uint8_t  algo;
    uint8_t  msg_type;
    char     domain[INDEX_UDP_MAX_DOMAIN + 1];
} queue_entry_t;

/* Server state */
static struct {
    int socket_fd;
    int epoll_fd;
    pthread_t worker_thread;
    _Atomic bool shutdown;

    /* Configuration */
    void *index;  /* cert_index_t* - opaque pointer */
    size_t batch_size;
    int batch_timeout_ms;

    /* Ring buffer (lock-free) */
    queue_entry_t *queue;
    size_t queue_size;
    _Atomic size_t queue_head;  /* Writer position */
    _Atomic size_t queue_tail;  /* Reader position */

    /* Statistics */
    _Atomic uint64_t stat_inserts;
    _Atomic uint64_t stat_removes;
    _Atomic uint64_t stat_queue_drops;
    _Atomic uint64_t stat_batches;
} g_server = {
    .socket_fd = -1,
    .epoll_fd = -1,
    .shutdown = false
};

/* Forward declarations */
static void *server_worker(void *arg);
static void process_message(const uint8_t *buf, size_t len,
                           const struct sockaddr_in *client_addr);
static void flush_batch(void);

int index_udp_server_init(const index_udp_server_config_t *config) {
    if (!config || !config->index) {
        return -1;
    }

    /* Apply configuration */
    g_server.index = config->index;
    g_server.batch_size = config->batch_size ? config->batch_size : 100;
    g_server.batch_timeout_ms = config->batch_timeout_ms ? config->batch_timeout_ms : 50;
    g_server.queue_size = config->queue_size ? config->queue_size : 10000;

    /* Allocate ring buffer */
    g_server.queue = calloc(g_server.queue_size, sizeof(queue_entry_t));
    if (!g_server.queue) {
        return -1;
    }

    atomic_store(&g_server.queue_head, 0);
    atomic_store(&g_server.queue_tail, 0);
    atomic_store(&g_server.shutdown, false);

    /* Create UDP socket */
    g_server.socket_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (g_server.socket_fd < 0) {
        perror("[INDEX-UDP] socket");
        free(g_server.queue);
        return -1;
    }

    /* Allow address reuse */
    int opt = 1;
    setsockopt(g_server.socket_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    /* Increase receive buffer for burst handling */
    int rcvbuf = 4 * 1024 * 1024;  /* 4MB */
    setsockopt(g_server.socket_fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));

    /* Set non-blocking */
    int flags = fcntl(g_server.socket_fd, F_GETFL, 0);
    fcntl(g_server.socket_fd, F_SETFL, flags | O_NONBLOCK);

    /* Bind */
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(config->port ? config->port : INDEX_UDP_DEFAULT_PORT);

    if (config->bind_addr && config->bind_addr[0]) {
        inet_pton(AF_INET, config->bind_addr, &addr.sin_addr);
    } else {
        addr.sin_addr.s_addr = htonl(INADDR_ANY);
    }

    if (bind(g_server.socket_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("[INDEX-UDP] bind");
        close(g_server.socket_fd);
        free(g_server.queue);
        return -1;
    }

    /* Create epoll */
    g_server.epoll_fd = epoll_create1(0);
    if (g_server.epoll_fd < 0) {
        perror("[INDEX-UDP] epoll_create1");
        close(g_server.socket_fd);
        free(g_server.queue);
        return -1;
    }

    struct epoll_event ev = {
        .events = EPOLLIN | EPOLLET,
        .data.fd = g_server.socket_fd
    };
    epoll_ctl(g_server.epoll_fd, EPOLL_CTL_ADD, g_server.socket_fd, &ev);

    /* Start worker thread */
    if (pthread_create(&g_server.worker_thread, NULL, server_worker, NULL) != 0) {
        perror("[INDEX-UDP] pthread_create");
        close(g_server.epoll_fd);
        close(g_server.socket_fd);
        free(g_server.queue);
        return -1;
    }

    uint16_t bound_port = ntohs(addr.sin_port);
    fprintf(stderr, "[INDEX-UDP] Server listening on port %u (batch=%zu, queue=%zu)\n",
            bound_port, g_server.batch_size, g_server.queue_size);

    return 0;
}

void index_udp_server_shutdown(void) {
    if (g_server.socket_fd < 0) {
        return;
    }

    /* Signal shutdown */
    atomic_store(&g_server.shutdown, true);

    /* Wait for worker thread */
    pthread_join(g_server.worker_thread, NULL);

    /* Final flush */
    flush_batch();

    /* Cleanup */
    close(g_server.epoll_fd);
    close(g_server.socket_fd);
    free(g_server.queue);

    g_server.socket_fd = -1;
    g_server.epoll_fd = -1;
    g_server.queue = NULL;
}

int index_udp_server_stats(index_udp_stats_t *stats) {
    if (!stats) return -1;

    /* Note: entries and capacity must be set by caller if needed,
     * as we don't have access to the cert_index API here */
    stats->entries = 0;
    stats->capacity = 0;
    stats->inserts = atomic_load(&g_server.stat_inserts);
    stats->removes = atomic_load(&g_server.stat_removes);

    size_t head = atomic_load(&g_server.queue_head);
    size_t tail = atomic_load(&g_server.queue_tail);
    stats->queue_depth = (head >= tail) ? (head - tail) : (g_server.queue_size - tail + head);
    stats->queue_drops = atomic_load(&g_server.stat_queue_drops);

    return 0;
}

size_t index_udp_server_flush(void) {
    flush_batch();
    return atomic_load(&g_server.stat_batches);
}

/* Server worker thread */
static void *server_worker(void *arg) {
    (void)arg;

    uint8_t buf[INDEX_UDP_MAX_PAYLOAD + 64];
    struct epoll_event events[32];

    while (!atomic_load(&g_server.shutdown)) {
        int nfds = epoll_wait(g_server.epoll_fd, events, 32, g_server.batch_timeout_ms);

        if (nfds < 0) {
            if (errno == EINTR) continue;
            perror("[INDEX-UDP] epoll_wait");
            break;
        }

        /* Process incoming messages */
        for (int i = 0; i < nfds; i++) {
            if (events[i].data.fd == g_server.socket_fd) {
                /* Drain socket (edge-triggered) */
                while (1) {
                    struct sockaddr_in client_addr;
                    socklen_t client_len = sizeof(client_addr);

                    ssize_t n = recvfrom(g_server.socket_fd, buf, sizeof(buf), 0,
                                         (struct sockaddr *)&client_addr, &client_len);
                    if (n <= 0) {
                        if (errno == EAGAIN || errno == EWOULDBLOCK) break;
                        break;
                    }

                    process_message(buf, n, &client_addr);
                }
            }
        }

        /* Flush batch if timeout or full */
        size_t head = atomic_load(&g_server.queue_head);
        size_t tail = atomic_load(&g_server.queue_tail);
        size_t queued = (head >= tail) ? (head - tail) : (g_server.queue_size - tail + head);

        if (queued >= g_server.batch_size || nfds == 0) {
            flush_batch();
        }
    }

    return NULL;
}

/* Process a single UDP message */
static void process_message(const uint8_t *buf, size_t len,
                           const struct sockaddr_in *client_addr) {
    if (len < sizeof(index_udp_header_t)) {
        return;
    }

    const index_udp_header_t *hdr = (const index_udp_header_t *)buf;

    /* Validate header */
    if (hdr->magic != INDEX_UDP_MAGIC || hdr->version != INDEX_UDP_VERSION) {
        return;
    }

    if (len < sizeof(*hdr) + hdr->payload_len) {
        return;
    }

    switch (hdr->msg_type) {
    case IDX_MSG_INSERT:
    case IDX_MSG_REMOVE: {
        if (hdr->payload_len < sizeof(index_udp_insert_t)) {
            return;
        }

        const index_udp_insert_t *payload =
            (const index_udp_insert_t *)(buf + sizeof(*hdr));

        if (hdr->payload_len < sizeof(*payload) + payload->domain_len) {
            return;
        }

        /* Add to queue */
        size_t head = atomic_load_explicit(&g_server.queue_head, memory_order_relaxed);
        size_t next = (head + 1) % g_server.queue_size;
        size_t tail = atomic_load_explicit(&g_server.queue_tail, memory_order_acquire);

        if (next == tail) {
            /* Queue full - drop */
            atomic_fetch_add(&g_server.stat_queue_drops, 1);
            return;
        }

        /* Copy to queue entry */
        queue_entry_t *entry = &g_server.queue[head];
        entry->composite_hash = payload->composite_hash;
        entry->cert_id = payload->cert_id;
        entry->expiry = payload->expiry;
        entry->algo = payload->algo;
        entry->msg_type = hdr->msg_type;

        memcpy(entry->domain,
               buf + sizeof(*hdr) + sizeof(*payload),
               payload->domain_len);
        entry->domain[payload->domain_len] = '\0';

        atomic_store_explicit(&g_server.queue_head, next, memory_order_release);
        break;
    }

    case IDX_MSG_PING: {
        /* Respond with PONG */
        index_udp_header_t resp = {
            .magic = INDEX_UDP_MAGIC,
            .version = INDEX_UDP_VERSION,
            .msg_type = IDX_MSG_PONG,
            .payload_len = 0
        };
        sendto(g_server.socket_fd, &resp, sizeof(resp), 0,
               (const struct sockaddr *)client_addr, sizeof(*client_addr));
        break;
    }

    case IDX_MSG_SYNC: {
        /* Flush and respond */
        flush_batch();
        index_udp_header_t resp = {
            .magic = INDEX_UDP_MAGIC,
            .version = INDEX_UDP_VERSION,
            .msg_type = IDX_MSG_SYNC,
            .payload_len = 0
        };
        sendto(g_server.socket_fd, &resp, sizeof(resp), 0,
               (const struct sockaddr *)client_addr, sizeof(*client_addr));
        break;
    }

    case IDX_MSG_STATS: {
        /* Respond with statistics */
        index_udp_header_t resp_hdr = {
            .magic = INDEX_UDP_MAGIC,
            .version = INDEX_UDP_VERSION,
            .msg_type = IDX_MSG_STATS,
            .payload_len = sizeof(index_udp_stats_t)
        };

        uint8_t resp[sizeof(resp_hdr) + sizeof(index_udp_stats_t)];
        memcpy(resp, &resp_hdr, sizeof(resp_hdr));
        index_udp_server_stats((index_udp_stats_t *)(resp + sizeof(resp_hdr)));

        sendto(g_server.socket_fd, resp, sizeof(resp), 0,
               (const struct sockaddr *)client_addr, sizeof(*client_addr));
        break;
    }

    default:
        break;
    }
}

/* Callback function pointers for index operations (set during init) */
static int (*g_index_insert_fn)(void *idx, const char *domain, int algo,
                                 uint32_t cert_id, uint64_t expiry) = NULL;
static int (*g_index_remove_fn)(void *idx, const char *domain, int algo) = NULL;

/* Set index callbacks (call before server_init) */
void index_udp_set_callbacks(
    int (*insert_fn)(void *idx, const char *domain, int algo, uint32_t cert_id, uint64_t expiry),
    int (*remove_fn)(void *idx, const char *domain, int algo)) {
    g_index_insert_fn = insert_fn;
    g_index_remove_fn = remove_fn;
}

/* Flush queued operations to index */
static void flush_batch(void) {
    size_t tail = atomic_load_explicit(&g_server.queue_tail, memory_order_relaxed);
    size_t head = atomic_load_explicit(&g_server.queue_head, memory_order_acquire);

    if (tail == head) {
        return;  /* Nothing to flush */
    }

    size_t count = 0;

    while (tail != head) {
        const queue_entry_t *entry = &g_server.queue[tail];

        if (entry->msg_type == IDX_MSG_INSERT) {
            if (g_index_insert_fn) {
                g_index_insert_fn(g_server.index,
                                  entry->domain,
                                  entry->algo,
                                  entry->cert_id,
                                  entry->expiry);
            }
            atomic_fetch_add(&g_server.stat_inserts, 1);
        } else if (entry->msg_type == IDX_MSG_REMOVE) {
            if (g_index_remove_fn) {
                g_index_remove_fn(g_server.index,
                                  entry->domain,
                                  entry->algo);
            }
            atomic_fetch_add(&g_server.stat_removes, 1);
        }

        tail = (tail + 1) % g_server.queue_size;
        count++;
    }

    atomic_store_explicit(&g_server.queue_tail, tail, memory_order_release);

    if (count > 0) {
        atomic_fetch_add(&g_server.stat_batches, 1);
        /* Index compaction done by callbacks if needed */
    }
}
