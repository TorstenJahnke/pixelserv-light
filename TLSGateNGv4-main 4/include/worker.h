/*
 * worker.h - Worker Thread with epoll Event Loop
 *
 * Each worker thread:
 * - Runs independent epoll event loop
 * - Handles 40K+ connections
 * - Non-blocking I/O
 * - Lock-free statistics
 */

#ifndef WORKER_H
#define WORKER_H

#include <pthread.h>
#include <stdatomic.h>
#include <sys/epoll.h>

#include "connection.h"

#define MAX_EPOLL_EVENTS 1024
#define WORKER_TIMEOUT_MS 100

/* Connection info passed through pipe from main thread to worker */
typedef struct {
    int fd;
    int socket_type;  /* 0=HTTP, 1=HTTPS, 2=AUTO (needs detection) */
    char remote_addr[64];  /* Remote IP address (IPv4/IPv6) */
} connection_pipe_msg_t;

/* Worker Statistics (atomic for lock-free updates) */
typedef struct worker_stats {
    atomic_uint_fast64_t connections_accepted;
    atomic_uint_fast64_t requests_handled;
    atomic_uint_fast64_t bytes_sent;
    atomic_uint_fast64_t bytes_received;
    atomic_uint_fast64_t errors;
    atomic_uint_fast64_t timeouts;
} worker_stats_t;

/* Worker Thread */
typedef struct worker {
    /* Thread management */
    pthread_t thread_id;
    int worker_id;
    atomic_int running;

    /* epoll */
    int epoll_fd;
    struct epoll_event events[MAX_EPOLL_EVENTS];

    /* Connection pool */
    connection_pool_t *conn_pool;

    /* Communication pipe with main thread */
    int pipe_fd[2];  /* pipe_fd[0] = read, pipe_fd[1] = write */

    /* Statistics */
    worker_stats_t stats;

} worker_t;

/* Create worker thread */
worker_t* worker_create(int worker_id, size_t conn_pool_size);

/* Destroy worker thread */
void worker_destroy(worker_t *worker);

/* Start worker thread */
int worker_start(worker_t *worker);

/* Stop worker thread */
void worker_stop(worker_t *worker);

/* Worker thread main loop */
void* worker_thread_main(void *arg);

/* Handle new connection from main thread
 *
 * IMPORTANT: On error (return < 0), caller MUST close client_fd to prevent FD leak.
 * The file descriptor has been accepted but could not be sent to worker thread.
 *
 * Returns: 0 on success, -1 on error (caller must close client_fd)
 */
int worker_add_connection(worker_t *worker, int client_fd);
int worker_add_connection_ex(worker_t *worker, int client_fd, int socket_type, const char *remote_addr);

/* epoll event handlers */
void worker_handle_pipe(worker_t *worker);
void worker_handle_connection_read(worker_t *worker, connection_t *conn);
void worker_handle_connection_write(worker_t *worker, connection_t *conn);
void worker_check_timeouts(worker_t *worker);

/* Print worker statistics */
void worker_print_stats(worker_t *worker);

#endif /* WORKER_H */
