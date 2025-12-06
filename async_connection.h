#ifndef ASYNC_CONNECTION_H
#define ASYNC_CONNECTION_H

#include <openssl/ssl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <time.h>
#include <stdint.h>
#include <stdatomic.h>

/* Forward declarations to avoid circular includes */
typedef struct event_loop event_loop_t;

/**
 * ASYNC CONNECTION STATE MACHINE
 *
 * For 10M concurrent users with io_uring:
 * - No threads (no 360GB RAM for stacks)
 * - Pure async state transitions
 * - io_uring batched I/O operations
 * - Memory-pooled connection objects (~2KB per connection)
 *
 * State Flow:
 * INIT → ACCEPT → TLS_HANDSHAKE → HTTP_REQUEST_READ →
 * HTTP_REQUEST_PARSE → HTTP_RESPONSE_GENERATE → HTTP_RESPONSE_WRITE →
 * KEEP_ALIVE_WAIT → (HTTP_REQUEST_READ or CLOSE)
 */

typedef enum {
    CONN_STATE_INIT,                 /* Initial state, not yet accepted */
    CONN_STATE_ACCEPTED,             /* Socket accepted, waiting for TLS or HTTP */
    CONN_STATE_TLS_HANDSHAKE,        /* TLS handshake in progress */
    CONN_STATE_TLS_HANDSHAKE_DONE,   /* TLS done, ready for HTTP */
    CONN_STATE_HTTP_REQUEST_READ,    /* Reading HTTP request from client */
    CONN_STATE_HTTP_REQUEST_COMPLETE,/* Full HTTP request received */
    CONN_STATE_HTTP_RESPONSE_GENERATE,/* Generating response */
    CONN_STATE_HTTP_RESPONSE_WRITE,  /* Writing HTTP response to client */
    CONN_STATE_KEEP_ALIVE_WAIT,      /* Waiting for next request (with timeout) */
    CONN_STATE_CLOSING,              /* Closing connection */
    CONN_STATE_CLOSED,               /* Connection fully closed */
    CONN_STATE_ERROR,                /* Error state */
    CONN_STATE_MAX
} async_conn_state_t;

typedef enum {
    IO_OP_NONE,
    IO_OP_ACCEPT,
    IO_OP_READ,
    IO_OP_WRITE,
    IO_OP_POLL,
    IO_OP_CLOSE,
    IO_OP_TLS_READ,
    IO_OP_TLS_WRITE,
    IO_OP_MAX
} io_op_type_t;

/**
 * Pending I/O Operation descriptor
 * Used to track what io_uring operation is pending for this connection
 */
typedef struct {
    io_op_type_t type;
    int fd;
    uint64_t user_data;              /* io_uring user_data */
    uint32_t flags;
    struct timespec start_time;
    int retry_count;
} pending_io_t;

/**
 * HTTP Request/Response state
 * Minimal parsing state machine
 */
typedef struct {
    char *request_buf;               /* Request buffer (pre-allocated) */
    size_t request_len;              /* Bytes received so far */
    size_t request_capacity;         /* Allocated buffer size */

    int request_complete;            /* 1 if full request received (\r\n\r\n found) */
    const char *method_start;        /* Pointer to method in buffer */
    const char *uri_start;           /* Pointer to URI in buffer */
    const char *headers_end;         /* Pointer to end of headers */

    /* Response state */
    char *response_buf;              /* Response buffer (pre-allocated) */
    size_t response_len;             /* Response bytes to send */
    size_t response_sent;            /* Response bytes already sent */
} http_state_t;

/**
 * Core async connection object
 * One per active connection, reused from pool
 *
 * Memory footprint: ~2KB + buffer allocations
 * Compare to: ~36KB per thread
 */
typedef struct async_connection {
    /* Connection metadata */
    int fd;                          /* Socket file descriptor */
    async_conn_state_t state;        /* Current state in state machine */
    async_conn_state_t prev_state;   /* Previous state (for debugging) */
    struct timespec created_at;      /* When connection was accepted */
    struct timespec last_activity;   /* Last time this connection did I/O */

    /* TLS state */
    SSL *ssl;                        /* OpenSSL SSL connection (NULL if non-TLS) */
    int is_https;                    /* 1 if TLS connection */
    int ssl_handshake_done;          /* 1 if SSL_accept() completed */
    int tls_attempt;                 /* Retry counter for TLS handshake */

    /* HTTP state */
    http_state_t http;               /* HTTP request/response state machine */

    /* Pending I/O */
    pending_io_t pending_io;         /* Currently pending io_uring operation */

    /* Statistics */
    uint64_t bytes_received;
    uint64_t bytes_sent;
    int request_count;               /* Number of requests on this connection (keep-alive) */

    /* Pool management */
    int in_pool;                     /* 1 if in connection pool, 0 if active */
    struct async_connection *pool_next; /* Next in pool free list */

    /* Error tracking */
    int last_error;
    const char *error_reason;
} async_connection_t;

/**
 * Connection pool
 * Pre-allocated array of connection objects
 * Reused across connections to avoid malloc/free
 */
typedef struct {
    async_connection_t *pool;        /* Array of pre-allocated connections */
    size_t pool_size;                /* Total pool size */
    size_t active_count;             /* Currently active connections */
    _Atomic(async_connection_t *) free_list; /* Lock-free free list head */
    _Atomic(uint64_t) alloc_count;   /* Total allocations (stats) */
    _Atomic(uint64_t) reuse_count;   /* Total reuses (stats) */
} connection_pool_t;

/* Connection pool management */
connection_pool_t *conn_pool_create(size_t pool_size);
void conn_pool_destroy(connection_pool_t *pool);
async_connection_t *conn_pool_acquire(connection_pool_t *pool, int fd);
void conn_pool_release(connection_pool_t *pool, async_connection_t *conn);

/* State machine transitions */
void conn_state_transition(async_connection_t *conn, async_conn_state_t new_state);
const char *conn_state_name(async_conn_state_t state);

/* Connection lifecycle */
async_connection_t *conn_init(async_connection_t *conn, int fd, int is_https);
void conn_reset(async_connection_t *conn);
void conn_cleanup(async_connection_t *conn);

/* HTTP state operations */
int http_request_append_data(http_state_t *http, const char *data, size_t len);
int http_request_is_complete(http_state_t *http);
void http_parse_request(http_state_t *http);
void http_generate_response(http_state_t *http);

/* Async TLS operations (non-blocking with portable event loop) */
int tls_accept_async(void *ssl_ctx, async_connection_t *conn, event_loop_t *loop);
int tls_read_async(async_connection_t *conn, char *buf, size_t len, event_loop_t *loop);
int tls_write_async(async_connection_t *conn, const char *buf, size_t len, event_loop_t *loop);

#endif // ASYNC_CONNECTION_H
