/*
 * connection.c - Connection Pool Implementation
 */

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

#include "connection.h"

/* Create connection pool with fixed size */
connection_pool_t* connection_pool_create(size_t pool_size) {
    connection_pool_t *pool = malloc(sizeof(connection_pool_t));
    if (!pool) {
        return NULL;
    }

    /* Allocate array of connections */
    pool->connections = calloc(pool_size, sizeof(connection_t));
    if (!pool->connections) {
        free(pool);
        return NULL;
    }

    pool->pool_size = pool_size;
    /* CONSISTENCY FIX: Use relaxed ordering for initialization (no threads yet) */
    atomic_store_explicit(&pool->active_count, 0, memory_order_relaxed);

    /* CRITICAL FIX: Initialize mutex to protect free_list access from multiple worker threads */
    if (pthread_mutex_init(&pool->pool_lock, NULL) != 0) {
        free(pool->connections);
        free(pool);
        return NULL;
    }

    /* Build free list - all connections initially free */
    pool->free_list = NULL;
    for (size_t i = 0; i < pool_size; i++) {
        connection_t *conn = &pool->connections[i];
        conn->fd = -1;
        atomic_store_explicit(&conn->state, CONN_STATE_IDLE, memory_order_release);
        conn->response_buf = NULL;

        /* Add to free list */
        conn->next = pool->free_list;
        pool->free_list = conn;
    }

    return pool;
}

/* Destroy connection pool */
void connection_pool_destroy(connection_pool_t *pool) {
    if (!pool) return;

    /* Close all active connections */
    for (size_t i = 0; i < pool->pool_size; i++) {
        connection_t *conn = &pool->connections[i];
        if (conn->fd >= 0) {
            close(conn->fd);
        }
        if (conn->response_buf) {
            free(conn->response_buf);
        }
    }

    /* CRITICAL FIX: Destroy mutex before freeing pool */
    pthread_mutex_destroy(&pool->pool_lock);

    free(pool->connections);
    free(pool);
}

/* Allocate connection from free list */
connection_t* connection_alloc(connection_pool_t *pool) {
    /* CRITICAL FIX: Lock mutex to prevent race condition when multiple worker threads
     * allocate connections simultaneously. Without this lock, two threads could:
     * 1. Both read pool->free_list (same value)
     * 2. Both set pool->free_list = conn->next
     * 3. Both get the SAME connection → data corruption, crashes
     */
    pthread_mutex_lock(&pool->pool_lock);

    if (!pool->free_list) {
        /* Pool exhausted */
        pthread_mutex_unlock(&pool->pool_lock);
        return NULL;
    }

    /* Pop from free list */
    connection_t *conn = pool->free_list;
    pool->free_list = conn->next;
    conn->next = NULL;

    /* Atomically increment active count */
    atomic_fetch_add_explicit(&pool->active_count, 1, memory_order_acq_rel);

    pthread_mutex_unlock(&pool->pool_lock);

    /* Initialize connection (outside lock for better concurrency) */
    connection_reset(conn);

    return conn;
}

/* Free connection back to pool */
void connection_free(connection_pool_t *pool, connection_t *conn) {
    if (!conn) return;

    /* Free SSL connection */
    if (conn->ssl) {
        /* Attempt graceful SSL shutdown (don't wait for peer response)
         * RESOURCE FIX: Added SSL_shutdown to properly release SSL session data
         * SSL_SENT_SHUTDOWN mode means we only send our close_notify, don't wait */
        SSL_set_shutdown(conn->ssl, SSL_SENT_SHUTDOWN | SSL_RECEIVED_SHUTDOWN);
        SSL_shutdown(conn->ssl);
        SSL_free(conn->ssl);
        conn->ssl = NULL;
    }

    /* Close file descriptor */
    if (conn->fd >= 0) {
        close(conn->fd);
        conn->fd = -1;
    }

    /* Free response buffer only if dynamically allocated */
    if (conn->response_buf && !conn->response_is_static) {
        free(conn->response_buf);
    }
    conn->response_buf = NULL;
    conn->response_is_static = 0;

    /* Reset state (atomic) */
    atomic_store_explicit(&conn->state, CONN_STATE_IDLE, memory_order_release);

    /* CRITICAL FIX: Lock mutex to prevent race condition when returning connection to pool */
    pthread_mutex_lock(&pool->pool_lock);

    /* Push back to free list */
    conn->next = pool->free_list;
    pool->free_list = conn;

    /* Atomically decrement active count */
    atomic_fetch_sub_explicit(&pool->active_count, 1, memory_order_acq_rel);

    pthread_mutex_unlock(&pool->pool_lock);
}

/* Reset connection for reuse */
void connection_reset(connection_t *conn) {
    atomic_store_explicit(&conn->state, CONN_STATE_IDLE, memory_order_release);
    conn->last_activity = time(NULL);
    conn->request_len = 0;
    conn->response_sent = 0;
    conn->ext = NULL;

    /* Reset TLS fields */
    conn->ssl = NULL;  /* SSL should be freed before reset */
    conn->is_https = 0;
    conn->needs_tls_detection = 0;  /* Reset detection need flag */
    conn->tls_detected = 0;  /* Reset TLS detection flag */
    conn->handshake_complete = 0;  /* Reset handshake flag */
    conn->handshake_retries = 0;  /* Reset retry counter */
    conn->handshake_start_ts.tv_sec = 0;  /* Reset retry timestamp */
    conn->handshake_start_ts.tv_nsec = 0;
    memset(conn->sni, 0, sizeof(conn->sni));

    /* Reset HTTP header fields */
    memset(conn->user_agent, 0, sizeof(conn->user_agent));
    memset(conn->remote_addr, 0, sizeof(conn->remote_addr));

    /* Free response buffer if it was dynamically allocated */
    if (conn->response_buf) {
        if (!conn->response_is_static) {
            free(conn->response_buf);
        }
        conn->response_buf = NULL;  /* Clear pointer for both static and dynamic */
    }
    conn->response_len = 0;
    conn->response_is_static = 0;
    conn->skip_jitter = 0;

    /* keep_alive and close_after_write are set by next request parser */

    /* PERFORMANCE FIX: Only clear the used portion of request_buf, not entire 128KB buffer
     * memset(conn->request_buf, 0, 131072) was wasting CPU cycles on every connection reset.
     * SECURITY FIX: Clear the entire used region to prevent old data from being parsed
     * by string functions that might not respect request_len boundary.
     */
    if (conn->request_len > 0 && conn->request_len < sizeof(conn->request_buf)) {
        memset(conn->request_buf, 0, conn->request_len);
    } else {
        conn->request_buf[0] = '\0';  /* At minimum, null-terminate */
    }
    conn->method[0] = '\0';  /* Null-terminate instead of full memset */
    conn->path[0] = '\0';    /* Null-terminate instead of full memset */
}

/* Set file descriptor to non-blocking mode */
int connection_set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) {
        return -1;
    }

    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1) {
        return -1;
    }

    return 0;
}

/* Set TCP socket options for performance */
int connection_set_socket_options(int fd) {
    int opt;

    /* TCP_NODELAY - disable Nagle's algorithm */
    opt = 1;
    if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt)) < 0) {
        return -1;
    }

    /* SO_REUSEADDR - allow fast restart */
    opt = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        return -1;
    }

    /* SO_KEEPALIVE - enable TCP keepalive */
    opt = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &opt, sizeof(opt)) < 0) {
        return -1;
    }

    /* Set send/receive buffer sizes */
    opt = 32768;  /* 32KB */
    if (setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &opt, sizeof(opt)) < 0) {
        /* Log warning but continue - buffer size failure is not critical */
        perror("SO_SNDBUF");
    }
    if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &opt, sizeof(opt)) < 0) {
        /* Log warning but continue - buffer size failure is not critical */
        perror("SO_RCVBUF");
    }

    return 0;
}
