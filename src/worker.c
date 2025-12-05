/*
 * worker.c - Event Loop Worker Implementation for TLSGate
 *
 * High-performance epoll-based event loop
 * Each worker handles 100K-1M concurrent connections
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sched.h>

#include "../include/worker.h"
#include "../include/response.h"

/* =============================================================================
 * Time Utilities
 * =============================================================================
 */

static inline uint64_t get_time_us(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000 + ts.tv_nsec / 1000;
}

/* =============================================================================
 * Worker Initialization
 * =============================================================================
 */

static int worker_init(worker_t *worker, uint16_t id, uint32_t conn_capacity,
                       int *listen_fds, int listen_count)
{
    memset(worker, 0, sizeof(*worker));

    worker->id = id;
    atomic_store(&worker->state, WORKER_STATE_INIT);

    /* Create epoll instance */
    worker->epfd = epoll_create1(EPOLL_CLOEXEC);
    if (worker->epfd < 0)
        return -1;

    /* Allocate event buffer */
    worker->events = calloc(WORKER_MAX_EVENTS, sizeof(struct epoll_event));
    if (!worker->events) {
        close(worker->epfd);
        return -1;
    }

    /* Initialize connection pool */
    if (conn_pool_init(&worker->conn_pool, conn_capacity) != 0) {
        free(worker->events);
        close(worker->epfd);
        return -1;
    }

    /* Store listening socket info */
    worker->listen_fds = listen_fds;
    worker->listen_count = listen_count;

    /* Register listening sockets with epoll
     * Using EPOLLEXCLUSIVE to distribute accepts across workers
     */
    for (int i = 0; i < listen_count; i++) {
        struct epoll_event ev;
        ev.events = EPOLLIN | EPOLLEXCLUSIVE;
        ev.data.fd = listen_fds[i];  /* Use fd directly for listen sockets */

        if (epoll_ctl(worker->epfd, EPOLL_CTL_ADD, listen_fds[i], &ev) != 0) {
            /* Non-fatal: older kernels don't support EPOLLEXCLUSIVE */
            ev.events = EPOLLIN;
            epoll_ctl(worker->epfd, EPOLL_CTL_ADD, listen_fds[i], &ev);
        }
    }

    return 0;
}

static void worker_cleanup(worker_t *worker)
{
    if (worker->events) {
        free(worker->events);
        worker->events = NULL;
    }

    conn_pool_destroy(&worker->conn_pool);

    if (worker->epfd >= 0) {
        close(worker->epfd);
        worker->epfd = -1;
    }
}

/* =============================================================================
 * Worker Thread Main Loop
 * =============================================================================
 */

void *worker_thread_main(void *arg)
{
    worker_t *worker = (worker_t *)arg;
    uint64_t last_maintenance = get_time_us();

    /* Set CPU affinity for cache locality */
#ifdef __linux__
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(worker->id % sysconf(_SC_NPROCESSORS_ONLN), &cpuset);
    pthread_setaffinity_np(pthread_self(), sizeof(cpuset), &cpuset);
#endif

    atomic_store(&worker->state, WORKER_STATE_RUNNING);

    while (atomic_load(&worker->state) == WORKER_STATE_RUNNING) {
        uint64_t start = get_time_us();

        /* Wait for events */
        int nevents = epoll_wait(worker->epfd, worker->events,
                                  WORKER_MAX_EVENTS, WORKER_TIMEOUT_MS);

        uint64_t after_wait = get_time_us();
        atomic_fetch_add(&worker->idle_time_us, after_wait - start);

        if (nevents < 0) {
            if (errno == EINTR)
                continue;
            atomic_fetch_add(&worker->errors, 1);
            continue;
        }

        /* Process events */
        if (nevents > 0) {
            worker_process_events(worker, nevents);
        }

        atomic_fetch_add(&worker->loop_count, 1);

        /* Periodic maintenance every 1 second */
        uint64_t now = get_time_us();
        if (now - last_maintenance > 1000000) {
            worker_maintenance(worker);
            last_maintenance = now;
        }

        atomic_fetch_add(&worker->busy_time_us, get_time_us() - after_wait);
    }

    atomic_store(&worker->state, WORKER_STATE_STOPPED);
    return NULL;
}

/* =============================================================================
 * Event Processing
 * =============================================================================
 */

void worker_process_events(worker_t *worker, int nevents)
{
    for (int i = 0; i < nevents; i++) {
        struct epoll_event *ev = &worker->events[i];

        /* Check if this is a listening socket */
        int is_listen = 0;
        for (int j = 0; j < worker->listen_count; j++) {
            if (ev->data.fd == worker->listen_fds[j]) {
                is_listen = 1;
                worker_accept_connection(worker, ev->data.fd);
                break;
            }
        }

        if (!is_listen) {
            /* Regular connection event */
            connection_t *conn = (connection_t *)ev->data.ptr;
            if (conn)
                worker_handle_connection(worker, conn, ev->events);
        }
    }
}

/* =============================================================================
 * Accept New Connections
 * =============================================================================
 */

void worker_accept_connection(worker_t *worker, int listen_fd)
{
    struct sockaddr_storage addr;
    socklen_t addr_len = sizeof(addr);

    /* Accept multiple connections per event (edge-triggered optimization) */
    for (int i = 0; i < 16; i++) {
        int fd = accept4(listen_fd, (struct sockaddr *)&addr, &addr_len,
                         SOCK_NONBLOCK | SOCK_CLOEXEC);

        if (fd < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                break;  /* No more pending connections */
            if (errno == EINTR)
                continue;
            atomic_fetch_add(&worker->errors, 1);
            break;
        }

        /* Allocate connection from pool */
        connection_t *conn = conn_alloc(&worker->conn_pool);
        if (!conn) {
            close(fd);
            atomic_fetch_add(&worker->errors, 1);
            continue;
        }

        /* Determine if TLS based on port (443 = TLS) */
        int local_port = 0;
        struct sockaddr_storage local_addr;
        socklen_t local_len = sizeof(local_addr);
        if (getsockname(fd, (struct sockaddr *)&local_addr, &local_len) == 0) {
            if (local_addr.ss_family == AF_INET)
                local_port = ntohs(((struct sockaddr_in *)&local_addr)->sin_port);
            else if (local_addr.ss_family == AF_INET6)
                local_port = ntohs(((struct sockaddr_in6 *)&local_addr)->sin6_port);
        }
        int is_tls = (local_port == 443);

        /* Initialize connection */
        conn_init(conn, fd, worker->id, is_tls);
        conn->cold.local_port = local_port;

        /* Allocate buffers */
        conn->hot.read_buf = buf_alloc_small();
        conn->hot.write_buf = buf_alloc_small();

        if (!conn->hot.read_buf || !conn->hot.write_buf) {
            if (conn->hot.read_buf) buf_free_small(conn->hot.read_buf);
            if (conn->hot.write_buf) buf_free_small(conn->hot.write_buf);
            conn_free(&worker->conn_pool, conn);
            close(fd);
            atomic_fetch_add(&worker->errors, 1);
            continue;
        }

        /* TCP optimizations */
        int opt = 1;
        setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt));
#ifdef TCP_QUICKACK
        setsockopt(fd, IPPROTO_TCP, TCP_QUICKACK, &opt, sizeof(opt));
#endif

        /* Add to epoll */
        struct epoll_event ev;
        ev.events = EPOLLIN | EPOLLET;  /* Edge-triggered */
        ev.data.ptr = conn;

        if (epoll_ctl(worker->epfd, EPOLL_CTL_ADD, fd, &ev) != 0) {
            buf_free_small(conn->hot.read_buf);
            buf_free_small(conn->hot.write_buf);
            conn_free(&worker->conn_pool, conn);
            close(fd);
            atomic_fetch_add(&worker->errors, 1);
            continue;
        }

        atomic_fetch_add(&worker->connections_accepted, 1);

        /* Advance state machine */
        conn_advance(conn, EPOLLIN);
    }
}

/* =============================================================================
 * HTTP Request Parsing and Response Generation
 * =============================================================================
 */

/*
 * Parse HTTP request line and extract method/path
 * Input: "GET /path/file.js HTTP/1.1\r\n..."
 * Returns: 0 on success, -1 on error
 */
static int parse_http_request(const char *buf, char *method, size_t method_size,
                              char *path, size_t path_size)
{
    if (!buf || !method || !path)
        return -1;

    /* Find method (first space-delimited token) */
    const char *p = buf;
    size_t i = 0;
    while (*p && *p != ' ' && *p != '\r' && i < method_size - 1) {
        method[i++] = *p++;
    }
    method[i] = '\0';

    if (*p != ' ')
        return -1;
    p++;  /* Skip space */

    /* Find path (second space-delimited token) */
    i = 0;
    while (*p && *p != ' ' && *p != '\r' && *p != '?' && i < path_size - 1) {
        path[i++] = *p++;
    }
    path[i] = '\0';

    return 0;
}

/*
 * Check if request has Connection: keep-alive
 */
static int check_keepalive(const char *buf)
{
    /* HTTP/1.1 defaults to keep-alive */
    if (strstr(buf, "HTTP/1.1"))
        return 1;

    /* Explicit Connection: keep-alive header */
    const char *conn_hdr = strcasestr(buf, "Connection:");
    if (conn_hdr) {
        if (strcasestr(conn_hdr, "keep-alive"))
            return 1;
        if (strcasestr(conn_hdr, "close"))
            return 0;
    }

    return 0;  /* HTTP/1.0 default is close */
}

/*
 * Generate response for a connection that just finished reading
 */
static int worker_generate_response(connection_t *conn)
{
    char method[16] = {0};
    char path[512] = {0};

    /* Parse HTTP request */
    if (parse_http_request(conn->hot.read_buf, method, sizeof(method),
                           path, sizeof(path)) != 0) {
        /* Bad request - send 404 */
        response_t resp = RESP_404_NOT_FOUND;
        memcpy(conn->hot.write_buf, resp.data, resp.len);
        conn->hot.write_len = resp.len;
        conn->hot.write_pos = 0;
        return 0;
    }

    /* Check keep-alive */
    if (check_keepalive(conn->hot.read_buf)) {
        conn->hot.flags |= CONN_FLAG_KEEPALIVE;
    }

    /* Generate response based on path and method */
    response_t resp;
    if (response_generate(path, method, &resp) != 0) {
        resp = RESP_404_NOT_FOUND;
    }

    /* Copy response to write buffer (limited by buffer size) */
    size_t copy_len = resp.len;
    if (copy_len > 4096)
        copy_len = 4096;  /* Buffer size limit */

    memcpy(conn->hot.write_buf, resp.data, copy_len);
    conn->hot.write_len = copy_len;
    conn->hot.write_pos = 0;

    /* Free dynamic response */
    response_free(&resp);

    return 0;
}

/* =============================================================================
 * Handle Connection Events
 * =============================================================================
 */

void worker_handle_connection(worker_t *worker, connection_t *conn, uint32_t events)
{
    conn_state_t old_state = conn->hot.state;
    int ret = conn_advance(conn, events);

    /* Check if we just transitioned to WRITE_RESPONSE - need to generate response */
    if (old_state == CONN_STATE_READ_REQUEST &&
        conn->hot.state == CONN_STATE_WRITE_RESPONSE) {
        worker_generate_response(conn);
    }

    if (ret < 0) {
        /* Connection should be closed */
        epoll_ctl(worker->epfd, EPOLL_CTL_DEL, conn->hot.fd, NULL);

        /* Update stats */
        atomic_fetch_add(&worker->bytes_read, conn->cold.bytes_read);
        atomic_fetch_add(&worker->bytes_written, conn->cold.bytes_written);
        atomic_fetch_add(&worker->requests_handled, conn->cold.request_count);

        /* Free buffers */
        if (conn->hot.read_buf) buf_free_small(conn->hot.read_buf);
        if (conn->hot.write_buf) buf_free_small(conn->hot.write_buf);

        /* Close and free connection */
        conn_close(conn);
        conn_free(&worker->conn_pool, conn);

        atomic_fetch_add(&worker->connections_closed, 1);
    } else if (ret == 0) {
        /* State advanced, update epoll */
        conn_update_epoll(conn, worker->epfd);
    }
    /* ret == 1: would block, epoll will notify when ready */
}

/* =============================================================================
 * Periodic Maintenance
 * =============================================================================
 */

void worker_maintenance(worker_t *worker)
{
    time_t now = time(NULL);

    /* Check for timed out connections
     * This is O(n) but only runs once per second
     * For 1M connections, this takes ~10-50ms which is acceptable
     */
    for (uint32_t i = 0; i < worker->conn_pool.capacity; i++) {
        connection_t *conn = &worker->conn_pool.connections[i];

        if (conn->hot.state == CONN_STATE_NONE)
            continue;

        int timeout = (conn->hot.state == CONN_STATE_KEEPALIVE)
                      ? WORKER_KEEPALIVE_TIMEOUT
                      : WORKER_CONN_TIMEOUT;

        if (conn_check_timeout(conn, now, timeout)) {
            /* Timeout - close connection */
            epoll_ctl(worker->epfd, EPOLL_CTL_DEL, conn->hot.fd, NULL);

            if (conn->hot.read_buf) buf_free_small(conn->hot.read_buf);
            if (conn->hot.write_buf) buf_free_small(conn->hot.write_buf);

            conn_close(conn);
            conn_free(&worker->conn_pool, conn);

            atomic_fetch_add(&worker->connections_closed, 1);
        }
    }
}

/* =============================================================================
 * Worker Pool Management
 * =============================================================================
 */

int worker_pool_init(worker_pool_t *pool, uint16_t num_workers,
                     uint32_t conns_per_worker, int *listen_fds, int listen_count)
{
    memset(pool, 0, sizeof(*pool));

    pool->workers = calloc(num_workers, sizeof(worker_t));
    if (!pool->workers)
        return -1;

    pool->count = num_workers;
    pool->conns_per_worker = conns_per_worker;
    pool->listen_fds = listen_fds;
    pool->listen_count = listen_count;
    atomic_store(&pool->running, 0);

    /* Initialize each worker */
    for (uint16_t i = 0; i < num_workers; i++) {
        if (worker_init(&pool->workers[i], i, conns_per_worker,
                        listen_fds, listen_count) != 0) {
            /* Cleanup already initialized workers */
            for (uint16_t j = 0; j < i; j++)
                worker_cleanup(&pool->workers[j]);
            free(pool->workers);
            return -1;
        }
    }

    return 0;
}

int worker_pool_start(worker_pool_t *pool)
{
    atomic_store(&pool->running, 1);

    for (uint16_t i = 0; i < pool->count; i++) {
        if (pthread_create(&pool->workers[i].thread, NULL,
                           worker_thread_main, &pool->workers[i]) != 0) {
            /* Stop already started workers */
            atomic_store(&pool->running, 0);
            for (uint16_t j = 0; j < i; j++) {
                atomic_store(&pool->workers[j].state, WORKER_STATE_STOPPING);
                pthread_join(pool->workers[j].thread, NULL);
            }
            return -1;
        }
    }

    return 0;
}

void worker_pool_stop(worker_pool_t *pool)
{
    atomic_store(&pool->running, 0);

    for (uint16_t i = 0; i < pool->count; i++) {
        atomic_store(&pool->workers[i].state, WORKER_STATE_STOPPING);
    }
}

void worker_pool_wait(worker_pool_t *pool)
{
    for (uint16_t i = 0; i < pool->count; i++) {
        pthread_join(pool->workers[i].thread, NULL);
    }
}

void worker_pool_destroy(worker_pool_t *pool)
{
    if (!pool->workers)
        return;

    for (uint16_t i = 0; i < pool->count; i++) {
        worker_cleanup(&pool->workers[i]);
    }

    free(pool->workers);
    pool->workers = NULL;
    pool->count = 0;
}

void worker_pool_stats(worker_pool_t *pool,
                       uint64_t *accepted, uint64_t *closed,
                       uint64_t *requests, uint64_t *errors)
{
    uint64_t a = 0, c = 0, r = 0, e = 0;

    for (uint16_t i = 0; i < pool->count; i++) {
        a += atomic_load(&pool->workers[i].connections_accepted);
        c += atomic_load(&pool->workers[i].connections_closed);
        r += atomic_load(&pool->workers[i].requests_handled);
        e += atomic_load(&pool->workers[i].errors);
    }

    if (accepted) *accepted = a;
    if (closed) *closed = c;
    if (requests) *requests = r;
    if (errors) *errors = e;
}
