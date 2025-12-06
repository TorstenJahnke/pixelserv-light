/*
 * worker.h - Event Loop Worker for TLSGate
 *
 * Each worker handles 100K-1M connections via epoll
 * 32 workers on 32-core EPYC = 32M potential connections
 */

#ifndef WORKER_H
#define WORKER_H

#include <stdint.h>
#include <stdatomic.h>
#include <pthread.h>
#include <sys/epoll.h>

#include "connection.h"
#include "buffer_pool.h"

/* =============================================================================
 * Configuration
 * =============================================================================
 */

#define WORKER_MAX_EVENTS       4096    /* Events per epoll_wait */
#define WORKER_TIMEOUT_MS       100     /* epoll_wait timeout */
#define WORKER_CONN_TIMEOUT     120     /* Connection timeout seconds */
#define WORKER_KEEPALIVE_TIMEOUT 60     /* Keep-alive timeout seconds */

/* =============================================================================
 * Worker State
 * =============================================================================
 */

typedef enum {
    WORKER_STATE_INIT,
    WORKER_STATE_RUNNING,
    WORKER_STATE_STOPPING,
    WORKER_STATE_STOPPED
} worker_state_t;

/* =============================================================================
 * Worker Structure
 * =============================================================================
 */

typedef struct worker {
    /* Identity */
    uint16_t id;                      /* Worker ID (0 to N-1) */
    pthread_t thread;                 /* Thread handle */
    _Atomic int state;                /* worker_state_t */

    /* Event loop */
    int epfd;                         /* epoll file descriptor */
    struct epoll_event *events;       /* Event buffer */

    /* Connection pool (per-worker for cache locality) */
    conn_pool_t conn_pool;

    /* Listening sockets (shared, registered per worker) */
    int *listen_fds;                  /* Array of listening FDs */
    int listen_count;                 /* Number of listening FDs */

    /* Statistics */
    _Atomic uint64_t connections_accepted;
    _Atomic uint64_t connections_closed;
    _Atomic uint64_t requests_handled;
    _Atomic uint64_t bytes_read;
    _Atomic uint64_t bytes_written;
    _Atomic uint64_t errors;

    /* Timing */
    _Atomic uint64_t loop_count;      /* Number of event loop iterations */
    _Atomic uint64_t busy_time_us;    /* Microseconds spent processing */
    _Atomic uint64_t idle_time_us;    /* Microseconds in epoll_wait */
} worker_t;

/* =============================================================================
 * Worker Pool
 * =============================================================================
 */

typedef struct worker_pool {
    worker_t *workers;                /* Array of workers */
    uint16_t count;                   /* Number of workers */
    _Atomic int running;              /* Pool is running */

    /* Shared resources */
    int *listen_fds;                  /* Listening socket FDs */
    int listen_count;                 /* Number of listening sockets */

    /* Configuration */
    uint32_t conns_per_worker;        /* Connections per worker */
} worker_pool_t;

/* =============================================================================
 * API Functions
 * =============================================================================
 */

/*
 * Initialize worker pool
 * @param pool              Pool to initialize
 * @param num_workers       Number of worker threads
 * @param conns_per_worker  Connection pool size per worker
 * @param listen_fds        Array of listening socket FDs
 * @param listen_count      Number of listening sockets
 * @return                  0 on success, -1 on failure
 */
int worker_pool_init(worker_pool_t *pool, uint16_t num_workers,
                     uint32_t conns_per_worker, int *listen_fds, int listen_count);

/*
 * Start all workers
 */
int worker_pool_start(worker_pool_t *pool);

/*
 * Stop all workers gracefully
 */
void worker_pool_stop(worker_pool_t *pool);

/*
 * Wait for all workers to finish
 */
void worker_pool_wait(worker_pool_t *pool);

/*
 * Destroy worker pool and free resources
 */
void worker_pool_destroy(worker_pool_t *pool);

/*
 * Get aggregate statistics from all workers
 */
void worker_pool_stats(worker_pool_t *pool,
                       uint64_t *accepted, uint64_t *closed,
                       uint64_t *requests, uint64_t *errors);

/* =============================================================================
 * Internal Worker Functions (called from worker thread)
 * =============================================================================
 */

/* Main worker entry point */
void *worker_thread_main(void *arg);

/* Process events from epoll_wait */
void worker_process_events(worker_t *worker, int nevents);

/* Handle new connection on listening socket */
void worker_accept_connection(worker_t *worker, int listen_fd);

/* Handle event on existing connection */
void worker_handle_connection(worker_t *worker, connection_t *conn, uint32_t events);

/* Periodic maintenance (timeouts, cleanup) */
void worker_maintenance(worker_t *worker);

#endif /* WORKER_H */
