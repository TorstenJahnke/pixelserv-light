#include "async_connection.h"
#include "event_loop.h"
#include "logger.h"
#include "util.h"
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define HTTP_BUFFER_SIZE 131072  /* 128KB pre-allocated */
#define CONN_POOL_DEFAULT_SIZE 1048576  /* 1M connections */

/**
 * Create connection pool
 */
connection_pool_t *conn_pool_create(size_t pool_size) {
    connection_pool_t *pool = malloc(sizeof(connection_pool_t));
    if (!pool) {
        log_msg(LGG_ERR, "Failed to allocate connection pool struct");
        return NULL;
    }

    pool->pool = calloc(pool_size, sizeof(async_connection_t));
    if (!pool->pool) {
        log_msg(LGG_ERR, "Failed to allocate %zu connection objects", pool_size);
        free(pool);
        return NULL;
    }

    pool->pool_size = pool_size;
    pool->active_count = 0;
    atomic_store(&pool->free_list, pool->pool);  /* Start of pool is free list */
    atomic_store(&pool->alloc_count, 0);
    atomic_store(&pool->reuse_count, 0);

    /* Initialize free list: each conn points to next */
    for (size_t i = 0; i < pool_size - 1; ++i) {
        pool->pool[i].pool_next = &pool->pool[i + 1];
        pool->pool[i].in_pool = 1;
    }
    pool->pool[pool_size - 1].pool_next = NULL;
    pool->pool[pool_size - 1].in_pool = 1;

    log_msg(LGG_NOTICE, "Connection pool created: %zu slots (~%.1f GB RAM)",
            pool_size, (pool_size * sizeof(async_connection_t) + HTTP_BUFFER_SIZE * pool_size) / (1024.0*1024.0*1024.0));

    return pool;
}

/**
 * Destroy connection pool
 */
void conn_pool_destroy(connection_pool_t *pool) {
    if (!pool) return;

    for (size_t i = 0; i < pool->pool_size; ++i) {
        conn_cleanup(&pool->pool[i]);
    }
    free(pool->pool);
    free(pool);
}

/**
 * Acquire connection from pool (lock-free)
 */
async_connection_t *conn_pool_acquire(connection_pool_t *pool, int fd) {
    if (!pool) return NULL;

    /* Try to reuse from free list */
    async_connection_t *conn;
    do {
        conn = atomic_load(&pool->free_list);
        if (!conn) {
            log_msg(LGG_ERR, "Connection pool exhausted! Increase pool size or close connections faster.");
            return NULL;
        }
    } while (!atomic_compare_exchange_strong(&pool->free_list, &conn, conn->pool_next));

    /* Initialize connection for reuse */
    conn_init(conn, fd, 0);
    conn->in_pool = 0;
    atomic_fetch_add(&pool->active_count, 1);
    atomic_fetch_add(&pool->reuse_count, 1);

    return conn;
}

/**
 * Release connection back to pool (lock-free)
 */
void conn_pool_release(connection_pool_t *pool, async_connection_t *conn) {
    if (!pool || !conn) return;

    conn_cleanup(conn);
    conn->in_pool = 1;

    /* Add back to free list */
    async_connection_t *head;
    do {
        head = atomic_load(&pool->free_list);
        conn->pool_next = head;
    } while (!atomic_compare_exchange_strong(&pool->free_list, &head, conn));

    atomic_fetch_sub(&pool->active_count, 1);
}

/**
 * Transition connection to new state
 */
void conn_state_transition(async_connection_t *conn, async_conn_state_t new_state) {
    if (!conn) return;

    conn->prev_state = conn->state;
    conn->state = new_state;
    conn->pending_io.type = IO_OP_NONE;

    if (conn->state != new_state) {
        log_msg(LGG_DEBUG, "Connection %d: %s → %s",
                conn->fd, conn_state_name(conn->prev_state), conn_state_name(new_state));
    }
}

/**
 * Get human-readable state name
 */
const char *conn_state_name(async_conn_state_t state) {
    static const char *names[] = {
        [CONN_STATE_INIT] = "INIT",
        [CONN_STATE_ACCEPTED] = "ACCEPTED",
        [CONN_STATE_TLS_HANDSHAKE] = "TLS_HANDSHAKE",
        [CONN_STATE_TLS_HANDSHAKE_DONE] = "TLS_HANDSHAKE_DONE",
        [CONN_STATE_HTTP_REQUEST_READ] = "HTTP_REQUEST_READ",
        [CONN_STATE_HTTP_REQUEST_COMPLETE] = "HTTP_REQUEST_COMPLETE",
        [CONN_STATE_HTTP_RESPONSE_GENERATE] = "HTTP_RESPONSE_GENERATE",
        [CONN_STATE_HTTP_RESPONSE_WRITE] = "HTTP_RESPONSE_WRITE",
        [CONN_STATE_KEEP_ALIVE_WAIT] = "KEEP_ALIVE_WAIT",
        [CONN_STATE_CLOSING] = "CLOSING",
        [CONN_STATE_CLOSED] = "CLOSED",
        [CONN_STATE_ERROR] = "ERROR",
    };
    if (state >= 0 && state < CONN_STATE_MAX) {
        return names[state];
    }
    return "UNKNOWN";
}

/**
 * Initialize connection for new client
 */
async_connection_t *conn_init(async_connection_t *conn, int fd, int is_https) {
    if (!conn) return NULL;

    memset(conn, 0, sizeof(async_connection_t));
    conn->fd = fd;
    conn->is_https = is_https;
    conn->state = CONN_STATE_ACCEPTED;
    conn->ssl_handshake_done = 0;
    conn->tls_attempt = 5;
    conn->request_count = 0;
    conn->bytes_received = 0;
    conn->bytes_sent = 0;
    conn->in_pool = 0;

    /* Allocate HTTP buffers if not already done */
    if (!conn->http.request_buf) {
        conn->http.request_buf = malloc(HTTP_BUFFER_SIZE);
        conn->http.response_buf = malloc(HTTP_BUFFER_SIZE);
        if (!conn->http.request_buf || !conn->http.response_buf) {
            log_msg(LGG_ERR, "Failed to allocate HTTP buffers");
            free(conn->http.request_buf);
            free(conn->http.response_buf);
            return NULL;
        }
    }

    conn->http.request_capacity = HTTP_BUFFER_SIZE;
    conn->http.request_len = 0;
    conn->http.request_complete = 0;
    conn->http.response_len = 0;
    conn->http.response_sent = 0;

    get_time(&conn->created_at);
    conn->last_activity = conn->created_at;

    return conn;
}

/**
 * Reset connection for next request (keep-alive)
 */
void conn_reset(async_connection_t *conn) {
    if (!conn) return;

    /* Clear HTTP state but keep connection alive */
    conn->http.request_len = 0;
    conn->http.request_complete = 0;
    conn->http.response_sent = 0;
    conn->request_count++;

    conn->state = CONN_STATE_HTTP_REQUEST_READ;
}

/**
 * Clean up connection
 */
void conn_cleanup(async_connection_t *conn) {
    if (!conn) return;

    if (conn->ssl) {
        SSL_set_shutdown(conn->ssl, SSL_SENT_SHUTDOWN | SSL_RECEIVED_SHUTDOWN);
        SSL_free(conn->ssl);
        conn->ssl = NULL;
    }

    if (conn->fd >= 0) {
        shutdown(conn->fd, SHUT_RDWR);
        close(conn->fd);
        conn->fd = -1;
    }

    /* Note: Don't free HTTP buffers - they're reused from pool */
    conn->state = CONN_STATE_CLOSED;
}

/**
 * Append received data to HTTP request buffer
 */
int http_request_append_data(http_state_t *http, const char *data, size_t len) {
    if (!http || !data || len == 0) return 0;

    if (http->request_len + len > http->request_capacity) {
        log_msg(LGG_WARNING, "HTTP request buffer overflow: %zu + %zu > %zu",
                http->request_len, len, http->request_capacity);
        return -1;
    }

    memcpy(http->request_buf + http->request_len, data, len);
    http->request_len += len;
    http->request_buf[http->request_len] = '\0';

    return len;
}

/**
 * Check if full HTTP request received (ends with \r\n\r\n)
 */
int http_request_is_complete(http_state_t *http) {
    if (!http || http->request_len < 4) return 0;

    /* Look for \r\n\r\n */
    for (size_t i = 0; i < http->request_len - 3; ++i) {
        if (http->request_buf[i] == '\r' &&
            http->request_buf[i+1] == '\n' &&
            http->request_buf[i+2] == '\r' &&
            http->request_buf[i+3] == '\n') {
            http->request_complete = 1;
            http->headers_end = &http->request_buf[i];
            return 1;
        }
    }
    return 0;
}

/**
 * Parse HTTP request (minimal parsing for pixelserv)
 */
void http_parse_request(http_state_t *http) {
    if (!http || !http->request_complete) return;

    /* Extract method and URI from first line */
    http->method_start = http->request_buf;

    /* Find first space (after method) */
    const char *space = strchr(http->method_start, ' ');
    if (!space) return;

    http->uri_start = space + 1;

    /* Find second space (after URI) */
    space = strchr(http->uri_start, ' ');
    if (!space) return;

    /* Now we have method and URI parsed */
}

/**
 * Generate simple GIF response
 */
void http_generate_response(http_state_t *http) {
    if (!http) return;

    /* Minimal GIF response - single pixel */
    static const unsigned char gif_pixel[] = {
        'G', 'I', 'F', '8', '9', 'a',  /* Signature */
        0x01, 0x00, 0x01, 0x00,        /* Width, Height */
        0x80, 0x00, 0x00,              /* Packed fields, bgcolor, aspect ratio */
        0x01, 0x01, 0x01,              /* Color table (1 color: black) */
        0x00, 0x00, 0x00,
        0x21, 0xf9, 0x04, 0x01,        /* Graphics Control Extension */
        0x00, 0x00, 0x00, 0x00,
        0x2c, 0x00, 0x00, 0x00, 0x00,  /* Image descriptor */
        0x01, 0x00, 0x01, 0x00, 0x00,
        0x02, 0x01, 0x44, 0x00, 0x3b   /* Image data + trailer */
    };

    const char *http_header =
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: image/gif\r\n"
        "Content-Length: 42\r\n"
        "Connection: close\r\n"
        "Cache-Control: no-cache, no-store, must-revalidate\r\n"
        "\r\n";

    size_t header_len = strlen(http_header);
    size_t gif_len = sizeof(gif_pixel);

    if (header_len + gif_len > http->request_capacity) {
        log_msg(LGG_ERR, "Response buffer too small: %zu + %zu > %zu",
                header_len, gif_len, http->request_capacity);
        return;
    }

    /* Copy HTTP header */
    memcpy(http->response_buf, http_header, header_len);

    /* Copy GIF binary */
    memcpy(http->response_buf + header_len, gif_pixel, gif_len);

    http->response_len = header_len + gif_len;
    http->response_sent = 0;
}

/* =============================================================================
 * ASYNC TLS OPERATIONS
 * ============================================================================= */

/**
 * Perform async SSL_accept()
 * Returns:
 *   1 = handshake complete, transition to TLS_HANDSHAKE_DONE
 *   0 = need more I/O (poll queued), stay in TLS_HANDSHAKE
 *  -1 = error, transition to ERROR
 */
int tls_accept_async(void *ssl_ctx, async_connection_t *conn,
                     event_loop_t *uring) {
    SSL_CTX *ctx = (SSL_CTX *)ssl_ctx;
    if (!ssl_ctx || !conn || conn->fd < 0) {
        log_msg(LGG_ERR, "Invalid TLS accept args");
        return -1;
    }

    /* Create SSL object on first attempt */
    if (!conn->ssl) {
        conn->ssl = SSL_new(ctx);
        if (!conn->ssl) {
            log_msg(LGG_ERR, "Failed to create SSL object: %s",
                    ERR_error_string(ERR_get_error(), NULL));
            return -1;
        }
        SSL_set_fd(conn->ssl, conn->fd);
    }

    /* Attempt SSL_accept() */
    int ret = SSL_accept(conn->ssl);
    if (ret > 0) {
        /* Handshake complete */
        conn->ssl_handshake_done = 1;
        log_msg(LGG_DEBUG, "TLS handshake complete for fd %d", conn->fd);
        return 1;
    }

    /* Handle SSL_accept errors */
    int ssl_err = SSL_get_error(conn->ssl, ret);
    switch (ssl_err) {
    case SSL_ERROR_WANT_READ:
        /* Need to wait for socket readable */
        if (uring) {
            event_loop_read(uring, conn, (char *)&conn->ssl, 1);
        }
        return 0;  /* Continue in TLS_HANDSHAKE state */

    case SSL_ERROR_WANT_WRITE:
        /* Need to wait for socket writable */
        if (uring) {
            event_loop_write(uring, conn, (const char *)&conn->ssl, 1);
        }
        return 0;  /* Continue in TLS_HANDSHAKE state */

    case SSL_ERROR_NONE:
        /* Connection closed cleanly (SSL_accept returned 0) */
        log_msg(LGG_WARNING, "TLS handshake connection closed (fd %d)", conn->fd);
        return -1;

    case SSL_ERROR_SSL:
    case SSL_ERROR_SYSCALL:
    default:
        log_msg(LGG_ERR, "TLS handshake error (fd %d): %s",
                conn->fd, ERR_error_string(ERR_get_error(), NULL));
        return -1;
    }
}

/**
 * Perform async SSL_read()
 * Returns:
 *   > 0 = bytes read, call http_request_append_data()
 *   0 = need more I/O (poll queued), stay in HTTP_REQUEST_READ
 *  -1 = error, transition to ERROR
 */
int tls_read_async(async_connection_t *conn, char *buf, size_t len,
                   event_loop_t *uring) {
    if (!conn || !conn->ssl || !buf || len == 0) {
        log_msg(LGG_ERR, "Invalid TLS read args");
        return -1;
    }

    /* Attempt SSL_read() */
    int ret = SSL_read(conn->ssl, buf, len);
    if (ret > 0) {
        /* Data received */
        conn->bytes_received += ret;
        return ret;
    }

    /* Handle SSL_read errors */
    int ssl_err = SSL_get_error(conn->ssl, ret);
    switch (ssl_err) {
    case SSL_ERROR_WANT_READ:
        /* Need to wait for socket readable */
        if (uring) {
            event_loop_read(uring, conn, buf, len);
        }
        return 0;  /* Continue in current state */

    case SSL_ERROR_WANT_WRITE:
        /* Need to send pending write (internal TLS state) */
        if (uring) {
            event_loop_write(uring, conn, (const char *)buf, 1);
        }
        return 0;  /* Continue in current state */

    case SSL_ERROR_NONE:
        /* Connection closed cleanly */
        log_msg(LGG_DEBUG, "TLS read: connection closed (fd %d)", conn->fd);
        return -1;

    case SSL_ERROR_SSL:
    case SSL_ERROR_SYSCALL:
    default:
        log_msg(LGG_ERR, "TLS read error (fd %d): %s",
                conn->fd, ERR_error_string(ERR_get_error(), NULL));
        return -1;
    }
}

/**
 * Perform async SSL_write()
 * Returns:
 *   > 0 = bytes written, update response_sent
 *   0 = need more I/O (poll queued), stay in HTTP_RESPONSE_WRITE
 *  -1 = error, transition to ERROR
 */
int tls_write_async(async_connection_t *conn, const char *buf, size_t len,
                    event_loop_t *uring) {
    if (!conn || !conn->ssl || !buf || len == 0) {
        log_msg(LGG_ERR, "Invalid TLS write args");
        return -1;
    }

    /* Attempt SSL_write() */
    int ret = SSL_write(conn->ssl, buf, len);
    if (ret > 0) {
        /* Data sent */
        conn->bytes_sent += ret;
        return ret;
    }

    /* Handle SSL_write errors */
    int ssl_err = SSL_get_error(conn->ssl, ret);
    switch (ssl_err) {
    case SSL_ERROR_WANT_WRITE:
        /* Need to wait for socket writable */
        if (uring) {
            event_loop_write(uring, conn, buf, len);
        }
        return 0;  /* Continue in current state */

    case SSL_ERROR_WANT_READ:
        /* Need to receive pending data (internal TLS state) */
        if (uring) {
            event_loop_read(uring, conn, (char *)buf, 1);
        }
        return 0;  /* Continue in current state */

    case SSL_ERROR_NONE:
        /* Connection closed cleanly */
        log_msg(LGG_DEBUG, "TLS write: connection closed (fd %d)", conn->fd);
        return -1;

    case SSL_ERROR_SSL:
    case SSL_ERROR_SYSCALL:
    default:
        log_msg(LGG_ERR, "TLS write error (fd %d): %s",
                conn->fd, ERR_error_string(ERR_get_error(), NULL));
        return -1;
    }
}
