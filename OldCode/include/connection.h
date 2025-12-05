/*
 * connection.h - Connection Pool and State Machine
 *
 * High-performance connection management for multi-threaded server
 * - Fixed-size connection pool (no malloc per connection)
 * - Free list management
 * - Connection state machine
 * - Non-blocking I/O ready
 */

#ifndef CONNECTION_H
#define CONNECTION_H

#include <stdint.h>
#include <time.h>
#include <sys/types.h>
#include <stdatomic.h>
#include <pthread.h>
#include <openssl/ssl.h>

/* Connection States */
typedef enum {
    CONN_STATE_IDLE = 0,        /* In free list, not used */
    CONN_STATE_READING,         /* Reading HTTP request */
    CONN_STATE_PROCESSING,      /* Processing request, generating response */
    CONN_STATE_WRITING,         /* Sending response */
    CONN_STATE_KEEPALIVE,       /* Keep-alive, waiting for next request */
    CONN_STATE_CLOSING          /* Closing connection */
} connection_state_t;

/* Socket type for multi-port setup */
typedef enum {
    SOCKET_TYPE_HTTP = 0,       /* Port 80 - always HTTP */
    SOCKET_TYPE_HTTPS,          /* Port 443 - always HTTPS */
    SOCKET_TYPE_AUTO,           /* Port 8080 - auto-detect with MSG_PEEK (TCP) */
    SOCKET_TYPE_AUTO_UDP        /* Port 8080 - QUIC/HTTP3 blocking (UDP) */
} socket_type_t;

/* Connection structure - optimized for cache efficiency */
typedef struct connection {
    /* File descriptor and state - HOT cache line */
    int fd;
    _Atomic connection_state_t state;  /* Atomic for thread-safe state transitions */
    socket_type_t socket_type;  /* Type of listening socket (HTTP/HTTPS/AUTO) */
    time_t last_activity;

    /* TLS/SSL fields */
    SSL *ssl;                   /* SSL connection (NULL for HTTP) */
    char sni[2048];             /* SNI hostname from TLS ClientHello */
    int is_https;               /* 1 if HTTPS connection */
    int needs_tls_detection;    /* 1 if auto-port (needs MSG_PEEK detection) */
    int tls_detected;           /* 1 if TLS detection has been performed */
    int handshake_complete;     /* 1 if TLS handshake completed */
    int handshake_retries;      /* Handshake retry counter (max 6) */
    struct timespec handshake_start_ts;  /* Timestamp of first handshake attempt (ms precision) */

    /* HTTP request data */
    char request_buf[131072];   /* 128KB request buffer (supports long URLs) */
    size_t request_len;

    /* HTTP response data */
    char *response_buf;         /* Dynamically allocated or static */
    size_t response_len;
    size_t response_sent;       /* Bytes already sent */
    int response_is_static;     /* 1 if response_buf is static (don't free) */

    /* Parsed HTTP data */
    char method[16];            /* GET, POST, etc. */
    char path[32768];           /* Request path (32KB - supports very long URLs with tracking params) */
    char *ext;                  /* File extension pointer (into path) */
    int keep_alive;             /* 1 if Connection: keep-alive */
    int close_after_write;      /* 1 if should close after response */
    int skip_jitter;            /* 1 if timing jitter should be skipped (index/favicon) */

    /* HTTP headers (for anti-adblock fingerprinting) */
    char user_agent[512];       /* User-Agent header (e.g., "Mozilla/5.0...") */
    char remote_addr[64];       /* Remote IP address (IPv4/IPv6) */

    /* Free list linkage */
    struct connection *next;

} connection_t;

/* Connection Pool */
typedef struct connection_pool {
    connection_t *connections;  /* Array of all connections */
    connection_t *free_list;    /* Head of free list */
    size_t pool_size;           /* Total connections in pool */
    _Atomic size_t active_count;        /* Currently active connections (atomic for thread safety) */
    pthread_mutex_t pool_lock;  /* CRITICAL FIX: Mutex to protect free_list and active_count */

} connection_pool_t;

/* Initialize connection pool */
connection_pool_t* connection_pool_create(size_t pool_size);

/* Destroy connection pool */
void connection_pool_destroy(connection_pool_t *pool);

/* Allocate connection from pool */
connection_t* connection_alloc(connection_pool_t *pool);

/* Free connection back to pool */
void connection_free(connection_pool_t *pool, connection_t *conn);

/* Reset connection for reuse */
void connection_reset(connection_t *conn);

/* Set connection to non-blocking mode */
int connection_set_nonblocking(int fd);

/* Set TCP socket options for performance */
int connection_set_socket_options(int fd);

/* Connection state transitions (atomic for thread safety) */
static inline void connection_set_state(connection_t *conn, connection_state_t new_state) {
    atomic_store_explicit(&conn->state, new_state, memory_order_release);
    conn->last_activity = time(NULL);
}

/* Check if connection has timed out */
static inline int connection_is_timeout(connection_t *conn, time_t now, int timeout_sec) {
    return (now - conn->last_activity) > timeout_sec;
}

#endif /* CONNECTION_H */
