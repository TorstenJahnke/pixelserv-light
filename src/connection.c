/*
 * connection.c - Connection State Machine Implementation
 *
 * Lock-free connection pool with Treiber stack for 10M+ concurrent connections
 */

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#include "../include/connection.h"

/* =============================================================================
 * Connection Pool - Lock-Free Treiber Stack
 * =============================================================================
 */

int conn_pool_init(conn_pool_t *pool, uint32_t capacity)
{
    if (!pool || capacity == 0)
        return -1;

    /* Allocate connection array */
    pool->connections = calloc(capacity, sizeof(connection_t));
    if (!pool->connections)
        return -1;

    pool->capacity = capacity;
    atomic_store(&pool->count, 0);
    atomic_store(&pool->alloc_count, 0);
    atomic_store(&pool->free_count, 0);
    atomic_store(&pool->alloc_fail, 0);

    /* Build free list - all connections start free */
    for (uint32_t i = 0; i < capacity - 1; i++) {
        pool->connections[i].next = &pool->connections[i + 1];
        pool->connections[i].pool_index = i;
        pool->connections[i].hot.state = CONN_STATE_NONE;
        pool->connections[i].hot.fd = -1;
    }
    pool->connections[capacity - 1].next = NULL;
    pool->connections[capacity - 1].pool_index = capacity - 1;
    pool->connections[capacity - 1].hot.state = CONN_STATE_NONE;
    pool->connections[capacity - 1].hot.fd = -1;

    atomic_store(&pool->free_head, &pool->connections[0]);

    return 0;
}

void conn_pool_destroy(conn_pool_t *pool)
{
    if (!pool)
        return;

    /* Close any open connections */
    for (uint32_t i = 0; i < pool->capacity; i++) {
        if (pool->connections[i].hot.fd >= 0) {
            close(pool->connections[i].hot.fd);
        }
        if (pool->connections[i].hot.ssl) {
            /* SSL_free() would go here */
        }
    }

    free(pool->connections);
    pool->connections = NULL;
    pool->capacity = 0;
}

/*
 * Lock-free allocation using Treiber stack pop
 * Returns NULL if pool exhausted
 */
connection_t *conn_alloc(conn_pool_t *pool)
{
    connection_t *head;
    connection_t *next;

    do {
        head = atomic_load(&pool->free_head);
        if (!head) {
            atomic_fetch_add(&pool->alloc_fail, 1);
            return NULL;  /* Pool exhausted */
        }
        next = head->next;
    } while (!atomic_compare_exchange_weak(&pool->free_head, &head, next));

    atomic_fetch_add(&pool->count, 1);
    atomic_fetch_add(&pool->alloc_count, 1);

    /* Reset connection state */
    memset(&head->hot, 0, sizeof(head->hot));
    head->hot.fd = -1;
    head->hot.state = CONN_STATE_NONE;
    head->next = NULL;

    return head;
}

/*
 * Lock-free deallocation using Treiber stack push
 */
void conn_free(conn_pool_t *pool, connection_t *conn)
{
    if (!pool || !conn)
        return;

    /* Clean up connection */
    if (conn->hot.fd >= 0) {
        close(conn->hot.fd);
        conn->hot.fd = -1;
    }

    conn->hot.state = CONN_STATE_NONE;
    conn->hot.flags = 0;
    conn->hot.ssl = NULL;
    conn->hot.read_buf = NULL;
    conn->hot.write_buf = NULL;

    /* Push to free list */
    connection_t *head;
    do {
        head = atomic_load(&pool->free_head);
        conn->next = head;
    } while (!atomic_compare_exchange_weak(&pool->free_head, &head, conn));

    atomic_fetch_sub(&pool->count, 1);
    atomic_fetch_add(&pool->free_count, 1);
}

/* =============================================================================
 * Connection Initialization
 * =============================================================================
 */

void conn_init(connection_t *conn, int fd, uint16_t worker_id, int is_tls)
{
    conn->hot.fd = fd;
    conn->hot.worker_id = worker_id;
    conn->hot.state = CONN_STATE_ACCEPT;
    conn->hot.flags = is_tls ? CONN_FLAG_TLS : 0;
    conn->hot.events = 0;
    conn->hot.read_pos = 0;
    conn->hot.write_pos = 0;
    conn->hot.write_len = 0;

    conn->cold.created = time(NULL);
    conn->cold.last_activity = conn->cold.created;
    conn->cold.request_count = 0;
    conn->cold.bytes_read = 0;
    conn->cold.bytes_written = 0;

    /* Set non-blocking */
    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);

    /* TCP optimizations */
    int opt = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt));

#ifdef TCP_QUICKACK
    setsockopt(fd, IPPROTO_TCP, TCP_QUICKACK, &opt, sizeof(opt));
#endif
}

void conn_set_state(connection_t *conn, conn_state_t new_state)
{
    conn->hot.state = new_state;
    conn->cold.last_activity = time(NULL);
}

/* =============================================================================
 * State Machine Advancement
 * =============================================================================
 * Returns: 0 = continue, 1 = would block, -1 = error/close
 */

int conn_advance(connection_t *conn, uint32_t events)
{
    conn->hot.events = events;
    conn->cold.last_activity = time(NULL);

    /* Handle errors and hangups */
    if (events & (EPOLLERR | EPOLLHUP)) {
        conn->hot.flags |= CONN_FLAG_ERROR;
        return -1;
    }

    switch (conn->hot.state) {
    case CONN_STATE_ACCEPT:
        return conn_handle_accept(conn);

    case CONN_STATE_TLS_HANDSHAKE:
        return conn_handle_tls_handshake(conn);

    case CONN_STATE_READ_REQUEST:
        return conn_handle_read(conn);

    case CONN_STATE_WRITE_RESPONSE:
        return conn_handle_write(conn);

    case CONN_STATE_KEEPALIVE:
        return conn_handle_keepalive(conn);

    case CONN_STATE_WAIT_CERT:
        /* Cert generation callback will advance state */
        return 1;  /* Still waiting */

    case CONN_STATE_CLOSING:
    case CONN_STATE_CLOSED:
        return -1;

    default:
        return -1;
    }
}

/* =============================================================================
 * State Handlers
 * =============================================================================
 */

int conn_handle_accept(connection_t *conn)
{
    /* Get client address info */
    struct sockaddr_storage addr;
    socklen_t addr_len = sizeof(addr);

    if (getpeername(conn->hot.fd, (struct sockaddr *)&addr, &addr_len) == 0) {
        if (addr.ss_family == AF_INET) {
            struct sockaddr_in *sin = (struct sockaddr_in *)&addr;
            inet_ntop(AF_INET, &sin->sin_addr, conn->cold.client_ip, sizeof(conn->cold.client_ip));
            conn->cold.client_port = ntohs(sin->sin_port);
        } else if (addr.ss_family == AF_INET6) {
            struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&addr;
            inet_ntop(AF_INET6, &sin6->sin6_addr, conn->cold.client_ip, sizeof(conn->cold.client_ip));
            conn->cold.client_port = ntohs(sin6->sin6_port);
        }
    }

    /* Transition to next state */
    if (conn->hot.flags & CONN_FLAG_TLS) {
        conn_set_state(conn, CONN_STATE_TLS_HANDSHAKE);
        conn_set_want_read(conn);
    } else {
        conn_set_state(conn, CONN_STATE_READ_REQUEST);
        conn_set_want_read(conn);
    }

    return 0;
}

int conn_handle_tls_handshake(connection_t *conn)
{
    SSL *ssl = (SSL *)conn->hot.ssl;
    if (!ssl)
        return -1;

    int ret = SSL_accept(ssl);

    if (ret == 1) {
        /* Handshake complete */
        conn_set_state(conn, CONN_STATE_READ_REQUEST);
        conn_set_want_read(conn);
        return 0;
    }

    int err = SSL_get_error(ssl, ret);
    switch (err) {
    case SSL_ERROR_WANT_READ:
        conn_set_want_read(conn);
        return 1;  /* Would block */

    case SSL_ERROR_WANT_WRITE:
        conn_set_want_write(conn);
        return 1;  /* Would block */

    case SSL_ERROR_ZERO_RETURN:
    case SSL_ERROR_SYSCALL:
    case SSL_ERROR_SSL:
    default:
        conn->hot.flags |= CONN_FLAG_ERROR;
        return -1;
    }
}

int conn_handle_read(connection_t *conn)
{
    if (!conn->hot.read_buf)
        return -1;

    char *buf = conn->hot.read_buf + conn->hot.read_pos;
    size_t buf_remain = 4096 - conn->hot.read_pos - 1;  /* Leave room for null */

    ssize_t n;
    if (conn->hot.flags & CONN_FLAG_TLS) {
        SSL *ssl = (SSL *)conn->hot.ssl;
        n = SSL_read(ssl, buf, buf_remain);
        if (n <= 0) {
            int err = SSL_get_error(ssl, n);
            if (err == SSL_ERROR_WANT_READ) {
                conn_set_want_read(conn);
                return 1;
            } else if (err == SSL_ERROR_WANT_WRITE) {
                conn_set_want_write(conn);
                return 1;
            }
            return -1;
        }
    } else {
        n = read(conn->hot.fd, buf, buf_remain);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                conn_set_want_read(conn);
                return 1;
            }
            return -1;
        } else if (n == 0) {
            return -1;  /* Connection closed */
        }
    }

    conn->hot.read_pos += n;
    conn->cold.bytes_read += n;
    conn->hot.read_buf[conn->hot.read_pos] = '\0';

    /* Check if we have a complete HTTP request (ends with \r\n\r\n) */
    if (strstr(conn->hot.read_buf, "\r\n\r\n")) {
        conn->cold.request_count++;
        /* Request complete - process and prepare response */
        /* For now, transition to write (response will be set by caller) */
        conn_set_state(conn, CONN_STATE_WRITE_RESPONSE);
        conn_set_want_write(conn);
        return 0;
    }

    /* Need more data */
    conn_set_want_read(conn);
    return 1;
}

int conn_handle_write(connection_t *conn)
{
    if (!conn->hot.write_buf || conn->hot.write_len == 0)
        return -1;

    char *buf = conn->hot.write_buf + conn->hot.write_pos;
    size_t remain = conn->hot.write_len - conn->hot.write_pos;

    ssize_t n;
    if (conn->hot.flags & CONN_FLAG_TLS) {
        SSL *ssl = (SSL *)conn->hot.ssl;
        n = SSL_write(ssl, buf, remain);
        if (n <= 0) {
            int err = SSL_get_error(ssl, n);
            if (err == SSL_ERROR_WANT_READ) {
                conn_set_want_read(conn);
                return 1;
            } else if (err == SSL_ERROR_WANT_WRITE) {
                conn_set_want_write(conn);
                return 1;
            }
            return -1;
        }
    } else {
        n = write(conn->hot.fd, buf, remain);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                conn_set_want_write(conn);
                return 1;
            }
            return -1;
        }
    }

    conn->hot.write_pos += n;
    conn->cold.bytes_written += n;

    if (conn->hot.write_pos >= conn->hot.write_len) {
        /* Write complete */
        if (conn->hot.flags & CONN_FLAG_KEEPALIVE) {
            /* Reset for next request */
            conn->hot.read_pos = 0;
            conn->hot.write_pos = 0;
            conn->hot.write_len = 0;
            conn_set_state(conn, CONN_STATE_KEEPALIVE);
            conn_set_want_read(conn);
            return 0;
        } else {
            /* Close connection */
            conn_set_state(conn, CONN_STATE_CLOSING);
            return -1;
        }
    }

    /* More to write */
    conn_set_want_write(conn);
    return 1;
}

int conn_handle_keepalive(connection_t *conn)
{
    /* Check if data available */
    if (conn->hot.events & EPOLLIN) {
        conn_set_state(conn, CONN_STATE_READ_REQUEST);
        return conn_handle_read(conn);
    }

    /* Still waiting */
    conn_set_want_read(conn);
    return 1;
}

/* =============================================================================
 * Utility Functions
 * =============================================================================
 */

void conn_close(connection_t *conn)
{
    if (conn->hot.ssl) {
        SSL *ssl = (SSL *)conn->hot.ssl;
        SSL_shutdown(ssl);
        SSL_free(ssl);
        conn->hot.ssl = NULL;
    }

    if (conn->hot.fd >= 0) {
        close(conn->hot.fd);
        conn->hot.fd = -1;
    }

    conn_set_state(conn, CONN_STATE_CLOSED);
}

const char *conn_state_name(conn_state_t state)
{
    switch (state) {
    case CONN_STATE_NONE:           return "NONE";
    case CONN_STATE_ACCEPT:         return "ACCEPT";
    case CONN_STATE_TLS_HANDSHAKE:  return "TLS_HANDSHAKE";
    case CONN_STATE_READ_REQUEST:   return "READ_REQUEST";
    case CONN_STATE_WAIT_CERT:      return "WAIT_CERT";
    case CONN_STATE_WRITE_RESPONSE: return "WRITE_RESPONSE";
    case CONN_STATE_KEEPALIVE:      return "KEEPALIVE";
    case CONN_STATE_CLOSING:        return "CLOSING";
    case CONN_STATE_CLOSED:         return "CLOSED";
    default:                        return "UNKNOWN";
    }
}

void conn_update_epoll(connection_t *conn, int epfd)
{
    struct epoll_event ev;
    ev.data.ptr = conn;
    ev.events = EPOLLET;  /* Edge-triggered */

    if (conn->hot.flags & CONN_FLAG_WANT_READ)
        ev.events |= EPOLLIN;
    if (conn->hot.flags & CONN_FLAG_WANT_WRITE)
        ev.events |= EPOLLOUT;

    epoll_ctl(epfd, EPOLL_CTL_MOD, conn->hot.fd, &ev);
}

int conn_check_timeout(connection_t *conn, time_t now, int timeout_sec)
{
    if (now - conn->cold.last_activity > timeout_sec) {
        conn->hot.flags |= CONN_FLAG_ERROR;
        return 1;  /* Timed out */
    }
    return 0;
}
