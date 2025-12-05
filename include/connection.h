/*
 * connection.h - Connection State Machine for Ultra-Scale pixelserv-tls
 *
 * Designed for 10M+ concurrent connections on 32-core EPYC / 256GB RAM
 *
 * Architecture:
 *   - Event-driven, non-blocking
 *   - Zero malloc per request (pre-allocated pools)
 *   - Lock-free where possible
 */

#ifndef CONNECTION_H
#define CONNECTION_H

#include <stdint.h>
#include <stdatomic.h>
#include <time.h>
#include <sys/epoll.h>
#include <openssl/ssl.h>

/* =============================================================================
 * Connection States
 * =============================================================================
 * State machine for each connection. Transitions are driven by epoll events.
 *
 *   ACCEPT -> TLS_HANDSHAKE -> READ_REQUEST -> PROCESS -> WRITE_RESPONSE
 *                                   ^                          |
 *                                   |_______ KEEPALIVE _________|
 *                                                |
 *                                              CLOSE
 */

typedef enum {
    CONN_STATE_NONE = 0,          /* Uninitialized / in free pool */
    CONN_STATE_ACCEPT,            /* Just accepted, setting up */
    CONN_STATE_TLS_HANDSHAKE,     /* SSL_accept() in progress (non-blocking) */
    CONN_STATE_READ_REQUEST,      /* Reading HTTP request */
    CONN_STATE_WAIT_CERT,         /* Waiting for cert generation (async) */
    CONN_STATE_WRITE_RESPONSE,    /* Writing HTTP response */
    CONN_STATE_KEEPALIVE,         /* Waiting for next request (HTTP/1.1) */
    CONN_STATE_CLOSING,           /* Graceful shutdown in progress */
    CONN_STATE_CLOSED             /* Ready to return to pool */
} conn_state_t;

/* Connection flags */
#define CONN_FLAG_TLS           (1 << 0)  /* TLS connection */
#define CONN_FLAG_KEEPALIVE     (1 << 1)  /* HTTP/1.1 keep-alive */
#define CONN_FLAG_HTTP2         (1 << 2)  /* HTTP/2 (future) */
#define CONN_FLAG_WANT_READ     (1 << 3)  /* Waiting for EPOLLIN */
#define CONN_FLAG_WANT_WRITE    (1 << 4)  /* Waiting for EPOLLOUT */
#define CONN_FLAG_CERT_PENDING  (1 << 5)  /* Waiting for cert generation */
#define CONN_FLAG_ERROR         (1 << 6)  /* Error occurred */

/* =============================================================================
 * Connection Structure
 * =============================================================================
 * Designed for cache-line efficiency (64 bytes hot path, rest cold)
 */

/* Hot data - frequently accessed, fits in 1 cache line */
typedef struct conn_hot {
    int fd;                       /* Socket file descriptor */
    conn_state_t state;           /* Current state */
    uint16_t flags;               /* Connection flags */
    uint16_t worker_id;           /* Owning worker thread */
    uint32_t events;              /* Current epoll events */
    void *ssl;                    /* SSL* (cast to avoid include) */
    char *read_buf;               /* Read buffer (from pool) */
    char *write_buf;              /* Write buffer (from pool) */
    uint32_t read_pos;            /* Current read position */
    uint32_t write_pos;           /* Current write position */
    uint32_t write_len;           /* Total bytes to write */
} conn_hot_t;  /* 64 bytes */

/* Cold data - less frequently accessed */
typedef struct conn_cold {
    time_t created;               /* Connection creation time */
    time_t last_activity;         /* Last activity timestamp */
    uint32_t request_count;       /* Requests on this connection */
    uint32_t bytes_read;          /* Total bytes read */
    uint32_t bytes_written;       /* Total bytes written */
    char client_ip[46];           /* Client IP (v4 or v6) */
    uint16_t client_port;         /* Client port */
    uint16_t local_port;          /* Local listening port */
    char sni_hostname[256];       /* SNI hostname for TLS */
} conn_cold_t;  /* ~320 bytes */

/* Full connection structure */
typedef struct connection {
    conn_hot_t hot;               /* Hot path data */
    conn_cold_t cold;             /* Cold path data */

    /* Pool management */
    struct connection *next;      /* Next in free list */
    uint32_t pool_index;          /* Index in connection pool */
} connection_t;

/* =============================================================================
 * Connection Pool
 * =============================================================================
 * Pre-allocated pool of connections for zero-malloc operation
 */

typedef struct conn_pool {
    connection_t *connections;    /* Array of all connections */
    uint32_t capacity;            /* Total capacity */
    _Atomic uint32_t count;       /* Current active count */

    /* Lock-free free list using Treiber stack */
    _Atomic(connection_t *) free_head;

    /* Stats */
    _Atomic uint64_t alloc_count;
    _Atomic uint64_t free_count;
    _Atomic uint64_t alloc_fail;
} conn_pool_t;

/* =============================================================================
 * API Functions
 * =============================================================================
 */

/* Pool management */
int conn_pool_init(conn_pool_t *pool, uint32_t capacity);
void conn_pool_destroy(conn_pool_t *pool);

/* Connection allocation (lock-free) */
connection_t *conn_alloc(conn_pool_t *pool);
void conn_free(conn_pool_t *pool, connection_t *conn);

/* Connection state machine */
void conn_init(connection_t *conn, int fd, uint16_t worker_id, int is_tls);
void conn_set_state(connection_t *conn, conn_state_t new_state);
int conn_advance(connection_t *conn, uint32_t events);
void conn_close(connection_t *conn);

/* State handlers - return 0 on success, -1 on error, 1 if would block */
int conn_handle_accept(connection_t *conn);
int conn_handle_tls_handshake(connection_t *conn);
int conn_handle_read(connection_t *conn);
int conn_handle_write(connection_t *conn);
int conn_handle_keepalive(connection_t *conn);

/* Utility */
const char *conn_state_name(conn_state_t state);
void conn_update_epoll(connection_t *conn, int epfd);
int conn_check_timeout(connection_t *conn, time_t now, int timeout_sec);

/* =============================================================================
 * Inline Functions (hot path)
 * =============================================================================
 */

static inline int conn_wants_read(connection_t *conn) {
    return (conn->hot.flags & CONN_FLAG_WANT_READ) != 0;
}

static inline int conn_wants_write(connection_t *conn) {
    return (conn->hot.flags & CONN_FLAG_WANT_WRITE) != 0;
}

static inline int conn_is_tls(connection_t *conn) {
    return (conn->hot.flags & CONN_FLAG_TLS) != 0;
}

static inline int conn_has_error(connection_t *conn) {
    return (conn->hot.flags & CONN_FLAG_ERROR) != 0;
}

static inline void conn_set_want_read(connection_t *conn) {
    conn->hot.flags |= CONN_FLAG_WANT_READ;
    conn->hot.flags &= ~CONN_FLAG_WANT_WRITE;
}

static inline void conn_set_want_write(connection_t *conn) {
    conn->hot.flags |= CONN_FLAG_WANT_WRITE;
    conn->hot.flags &= ~CONN_FLAG_WANT_READ;
}

static inline void conn_set_want_both(connection_t *conn) {
    conn->hot.flags |= (CONN_FLAG_WANT_READ | CONN_FLAG_WANT_WRITE);
}

#endif /* CONNECTION_H */
