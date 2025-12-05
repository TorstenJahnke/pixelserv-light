/*
 * worker.c - Worker Thread Implementation
 */

#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "worker.h"
#include "connection.h"
#include "response.h"
#include "timing_jitter.h"
#include "tls/sni_extractor.h"
#include "../util/logger.h"

/* TLS globals (defined in main) */
typedef struct cert_generator cert_generator_t;  /* Forward declaration */
extern SSL_CTX *g_default_sslctx;
extern cert_generator_t *g_cert_gen;

/* Forward declarations */
static void process_http_request(worker_t *worker, connection_t *conn);
static void send_minimal_response(worker_t *worker, connection_t *conn);
static void send_error_response(worker_t *worker, connection_t *conn, const char *response, size_t response_len);

/* Create worker */
worker_t* worker_create(int worker_id, size_t conn_pool_size) {
    worker_t *worker = calloc(1, sizeof(worker_t));
    if (!worker) {
        return NULL;
    }

    worker->worker_id = worker_id;
    atomic_init(&worker->running, 0);

    /* Create epoll instance */
    worker->epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    if (worker->epoll_fd < 0) {
        free(worker);
        return NULL;
    }

    /* Create connection pool */
    worker->conn_pool = connection_pool_create(conn_pool_size);
    if (!worker->conn_pool) {
        close(worker->epoll_fd);
        free(worker);
        return NULL;
    }

    /* Create pipe for communication with main thread */
    if (pipe(worker->pipe_fd) < 0) {
        connection_pool_destroy(worker->conn_pool);
        close(worker->epoll_fd);
        free(worker);
        return NULL;
    }

    /* Set pipe to non-blocking */
    if (connection_set_nonblocking(worker->pipe_fd[0]) < 0) {
        close(worker->pipe_fd[0]);
        close(worker->pipe_fd[1]);
        connection_pool_destroy(worker->conn_pool);
        close(worker->epoll_fd);
        free(worker);
        return NULL;
    }

    /* Add pipe to epoll */
    struct epoll_event ev;
    ev.events = EPOLLIN;
    ev.data.ptr = NULL;  /* NULL means this is the pipe */
    if (epoll_ctl(worker->epoll_fd, EPOLL_CTL_ADD, worker->pipe_fd[0], &ev) < 0) {
        close(worker->pipe_fd[0]);
        close(worker->pipe_fd[1]);
        connection_pool_destroy(worker->conn_pool);
        close(worker->epoll_fd);
        free(worker);
        return NULL;
    }

    return worker;
}

/* Destroy worker */
void worker_destroy(worker_t *worker) {
    if (!worker) return;

    worker_stop(worker);

    close(worker->pipe_fd[0]);
    close(worker->pipe_fd[1]);
    connection_pool_destroy(worker->conn_pool);
    close(worker->epoll_fd);
    free(worker);
}

/* Start worker thread */
int worker_start(worker_t *worker) {
    atomic_store(&worker->running, 1);

    if (pthread_create(&worker->thread_id, NULL, worker_thread_main, worker) != 0) {
        atomic_store(&worker->running, 0);
        return -1;
    }

    return 0;
}

/* Stop worker thread */
void worker_stop(worker_t *worker) {
    atomic_store(&worker->running, 0);

    /* Send wake-up signal through pipe */
    char dummy = 0;
    ssize_t ret = write(worker->pipe_fd[1], &dummy, 1);
    if (ret < 0) {
        /* Pipe error (e.g., EPIPE if reader closed) - log but don't fail */
        if (errno != EPIPE) {
            LOG_WARN("Failed to write wake-up signal to worker pipe: %s", strerror(errno));
        }
    }

    /* Wait for thread to finish */
    if (worker->thread_id) {
        pthread_join(worker->thread_id, NULL);
    }
}

/* Worker thread main loop */
void* worker_thread_main(void *arg) {
    worker_t *worker = (worker_t*)arg;
    time_t last_timeout_check = time(NULL);


    while (atomic_load_explicit(&worker->running, memory_order_acquire)) {
        /* Wait for events */
        int n = epoll_wait(worker->epoll_fd, worker->events, MAX_EPOLL_EVENTS, WORKER_TIMEOUT_MS);

        if (n < 0) {
            if (errno == EINTR) continue;
            perror("epoll_wait");
            break;
        }

        /* Process events */
        for (int i = 0; i < n; i++) {
            struct epoll_event *ev = &worker->events[i];

            /* Check if this is the pipe (NULL data.ptr) */
            if (ev->data.ptr == NULL) {
                worker_handle_pipe(worker);
                continue;
            }

            /* This is a connection */
            connection_t *conn = (connection_t*)ev->data.ptr;

            /* Handle errors */
            if (ev->events & (EPOLLERR | EPOLLHUP)) {
                connection_free(worker->conn_pool, conn);
                continue;
            }

            /* Handle readable */
            if (ev->events & EPOLLIN) {
                worker_handle_connection_read(worker, conn);
            }

            /* Handle writable */
            if (ev->events & EPOLLOUT) {
                worker_handle_connection_write(worker, conn);
            }
        }

        /* Check for timeouts every second */
        time_t now = time(NULL);
        if (now > last_timeout_check) {
            worker_check_timeouts(worker);
            last_timeout_check = now;
        }
    }

    return NULL;
}

/* Handle new connection from pipe */
void worker_handle_pipe(worker_t *worker) {
    connection_pipe_msg_t msg;

    /* Process all available messages from pipe
     * SECURITY FIX: Properly handle partial reads from pipe */
    for (;;) {
        size_t total_read = 0;  /* Use size_t to match sizeof() type */

        /* Read one complete message - handle partial reads correctly
         * read() may return less than requested bytes even when
         * more data is available (signals, partial I/O). Must loop until complete. */
        while (total_read < sizeof(msg)) {
            ssize_t n = read(worker->pipe_fd[0],
                             ((char*)&msg) + total_read,
                             sizeof(msg) - total_read);
            if (n < 0) {
                if (errno == EINTR) continue;  /* Retry on signal interruption */
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    /* No more data available now */
                    if (total_read == 0) {
                        return;  /* No partial message, just no data - normal */
                    }
                    /* Partial message but no more data - this is an error */
                    LOG_ERROR("Partial pipe message (%zu/%zu bytes) - pipe broken?",
                              total_read, sizeof(msg));
                    return;
                }
                LOG_ERROR("Pipe read error: %s", strerror(errno));
                return;
            }
            if (n == 0) {
                /* EOF - pipe closed */
                if (total_read > 0) {
                    LOG_ERROR("Partial pipe message on EOF (%zu/%zu bytes)",
                              total_read, sizeof(msg));
                }
                return;
            }
            total_read += n;
        }

        /* We have a complete message - process it */
        /* Allocate connection from pool */
        connection_t *conn = connection_alloc(worker->conn_pool);
        if (!conn) {
            /* Pool exhausted - close connection */
            close(msg.fd);
            atomic_fetch_add(&worker->stats.errors, 1);
            continue;
        }

        /* Set up connection */
        conn->fd = msg.fd;

        /* SECURITY FIX: Check return values of socket operations */
        if (connection_set_nonblocking(msg.fd) < 0) {
            LOG_ERROR("Failed to set nonblocking on fd=%d", msg.fd);
            close(msg.fd);
            connection_free(worker->conn_pool, conn);
            atomic_fetch_add(&worker->stats.errors, 1);
            continue;
        }

        if (connection_set_socket_options(msg.fd) < 0) {
            LOG_ERROR("Failed to set socket options on fd=%d", msg.fd);
            close(msg.fd);
            connection_free(worker->conn_pool, conn);
            atomic_fetch_add(&worker->stats.errors, 1);
            continue;
        }

        /* Copy remote address from pipe message */
        /* SECURITY FIX: Ensure msg.remote_addr is null-terminated before using strnlen
         * to prevent reading past buffer if pipe message is corrupted */
        msg.remote_addr[sizeof(msg.remote_addr) - 1] = '\0';

        /* SECURITY FIX: Validate remote_addr contains only valid IP address characters
         * to prevent injection attacks or corrupted data from crashing the server */
        size_t addr_len = strnlen(msg.remote_addr, sizeof(msg.remote_addr) - 1);
        int valid_addr = 1;
        for (size_t i = 0; i < addr_len; i++) {
            char c = msg.remote_addr[i];
            /* Allow only digits, dots (IPv4), colons (IPv6), and brackets [IPv6] */
            if (!((c >= '0' && c <= '9') || c == '.' || c == ':' ||
                  c == '[' || c == ']' || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) {
                valid_addr = 0;
                break;
            }
        }

        if (!valid_addr || addr_len == 0) {
            LOG_ERROR("Invalid remote address received via pipe, using 'unknown'");
            strncpy(conn->remote_addr, "unknown", sizeof(conn->remote_addr) - 1);
            conn->remote_addr[sizeof(conn->remote_addr) - 1] = '\0';
        } else {
            if (addr_len >= sizeof(conn->remote_addr)) {
                addr_len = sizeof(conn->remote_addr) - 1;
            }
            memcpy(conn->remote_addr, msg.remote_addr, addr_len);
            conn->remote_addr[addr_len] = '\0';
        }

        /* Initialize TLS fields based on socket type */
        conn->ssl = NULL;
        conn->handshake_complete = 0;

        switch (msg.socket_type) {
            case 0:  /* HTTP port - always plain HTTP */
                conn->is_https = 0;
                conn->needs_tls_detection = 0;
                conn->tls_detected = 1;  /* No detection needed */
                break;

            case 1:  /* HTTPS port - always TLS */
                conn->is_https = 1;
                conn->needs_tls_detection = 0;
                conn->tls_detected = 1;  /* No detection needed, create SSL immediately */

                /* Create SSL object immediately for HTTPS port */
                conn->ssl = SSL_new(g_default_sslctx);
                if (!conn->ssl) {
                    LOG_ERROR("SSL_new() failed for fd=%d", msg.fd);
                    connection_free(worker->conn_pool, conn);
                    atomic_fetch_add(&worker->stats.errors, 1);
                    continue;
                }
                if (SSL_set_fd(conn->ssl, msg.fd) != 1) {
                    LOG_ERROR("SSL_set_fd() failed for fd=%d", msg.fd);
                    SSL_free(conn->ssl);
                    conn->ssl = NULL;
                    connection_free(worker->conn_pool, conn);
                    atomic_fetch_add(&worker->stats.errors, 1);
                    continue;
                }
                if (SSL_set_app_data(conn->ssl, conn) != 1) {
                    LOG_ERROR("SSL_set_app_data() failed for fd=%d", msg.fd);
                    SSL_free(conn->ssl);
                    conn->ssl = NULL;
                    connection_free(worker->conn_pool, conn);
                    atomic_fetch_add(&worker->stats.errors, 1);
                    continue;
                }
                SSL_set_accept_state(conn->ssl);  /* void function - no error return */
                break;

            case 2:  /* AUTO port - needs MSG_PEEK detection */
            default:
                conn->is_https = 0;  /* Unknown until detected */
                conn->needs_tls_detection = 1;
                conn->tls_detected = 0;  /* Detection will happen on first read */
                break;
        }

        connection_set_state(conn, CONN_STATE_READING);

        /* Add to epoll */
        struct epoll_event ev;
        ev.events = EPOLLIN | EPOLLET;  /* Edge-triggered */
        ev.data.ptr = conn;

        if (epoll_ctl(worker->epoll_fd, EPOLL_CTL_ADD, msg.fd, &ev) < 0) {
            connection_free(worker->conn_pool, conn);
            atomic_fetch_add(&worker->stats.errors, 1);
            continue;
        }

        atomic_fetch_add(&worker->stats.connections_accepted, 1);
    }
}

/* Handle connection read event */
void worker_handle_connection_read(worker_t *worker, connection_t *conn) {
    ssize_t n;

    /* TLS detection on first read event (ONLY for AUTO port) */
    if (conn->needs_tls_detection && !conn->tls_detected && conn->request_len == 0) {
        /* ROBUSTNESS FIX: Increased peek buffer from 16 to 64 bytes
         * TLS ClientHello can be larger, especially with extensions.
         * 64 bytes ensures we can reliably detect TLS record header (5 bytes)
         * plus enough handshake data for proper detection */
        unsigned char peek_buf[64];
        ssize_t peek_len = recv(conn->fd, peek_buf, sizeof(peek_buf), MSG_PEEK);

        /* Handle different peek_len cases */
        if (peek_len < 0) {
            /* Error occurred */
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                /* No data available yet - wait for next read event */
                return;  /* Don't mark as detected, retry on next event */
            }
            /* Real error - close connection */
            connection_free(worker->conn_pool, conn);
            atomic_fetch_add(&worker->stats.errors, 1);
            return;
        } else if (peek_len == 0) {
            /* EOF - client closed connection */
            connection_free(worker->conn_pool, conn);
            return;
        }

        /* peek_len > 0 - we have data! */
        if (is_tls_client_hello(peek_buf, peek_len)) {
            /* This is HTTPS - create SSL object */
            conn->is_https = 1;
            conn->ssl = SSL_new(g_default_sslctx);
            if (!conn->ssl) {
                LOG_ERROR("SSL_new() failed for AUTO port fd=%d", conn->fd);
                connection_free(worker->conn_pool, conn);
                atomic_fetch_add(&worker->stats.errors, 1);
                return;
            }

            /* Bind SSL to socket */
            if (SSL_set_fd(conn->ssl, conn->fd) != 1) {
                LOG_ERROR("SSL_set_fd() failed for AUTO port fd=%d", conn->fd);
                SSL_free(conn->ssl);
                conn->ssl = NULL;
                connection_free(worker->conn_pool, conn);
                atomic_fetch_add(&worker->stats.errors, 1);
                return;
            }

            /* Set connection pointer for SNI callback */
            if (SSL_set_app_data(conn->ssl, conn) != 1) {
                LOG_ERROR("SSL_set_app_data() failed for AUTO port fd=%d", conn->fd);
                SSL_free(conn->ssl);
                conn->ssl = NULL;
                connection_free(worker->conn_pool, conn);
                atomic_fetch_add(&worker->stats.errors, 1);
                return;
            }

            /* Set SSL to accept mode */
            SSL_set_accept_state(conn->ssl);  /* void function - no error return */
        } else {
            /* This is HTTP (plain) */
            conn->is_https = 0;
            conn->ssl = NULL;
        }

        conn->tls_detected = 1;  /* Mark as detected */
    }

    /* For HTTPS connections, perform TLS handshake first */
    if (conn->is_https && conn->ssl && !conn->handshake_complete) {
        int ret = SSL_do_handshake(conn->ssl);

        if (ret == 1) {
            /* Handshake complete! */
            conn->handshake_complete = 1;
            /* Fall through to read HTTP request immediately */
            /* With edge-triggered epoll, we must process all available data in one go */
        } else {
            int ssl_err = SSL_get_error(conn->ssl, ret);

            if (ssl_err == SSL_ERROR_WANT_READ || ssl_err == SSL_ERROR_WANT_WRITE) {
                /* Need more data - wait for next event */
                return;
            } else {
                /* PERFORMANCE FIX: Fast backoff for handshake retries
                 * Timeouts: 0ms, 50ms, 100ms, 200ms, 1500ms, 3000ms (6 retries, max 5 sec)
                 * Quickly detect and drop clients without RootCA */

                /* Backoff delays in milliseconds */
                static const long backoff_ms[] = {0, 50, 100, 200, 1500, 3000};

                struct timespec now_ts;
                clock_gettime(CLOCK_MONOTONIC, &now_ts);

                if (conn->handshake_retries == 0) {
                    conn->handshake_start_ts = now_ts;
                }

                /* Calculate elapsed time in milliseconds */
                long elapsed_ms = (now_ts.tv_sec - conn->handshake_start_ts.tv_sec) * 1000 +
                                  (now_ts.tv_nsec - conn->handshake_start_ts.tv_nsec) / 1000000;

                if (conn->handshake_retries < 6 && elapsed_ms < 5000) {
                    /* Check if enough time has passed for this retry */
                    long required_ms = backoff_ms[conn->handshake_retries];

                    if (elapsed_ms < required_ms) {
                        /* Too soon to retry - wait for next event */
                        return;
                    }

                    /* Retry: increment counter and wait for next event */
                    conn->handshake_retries++;
                    return;  /* Try again on next epoll event */
                }

                /* Max retries (6) or timeout (5 sec) exceeded - give up */
                LOG_ERROR("TLS handshake failed after %d retries (%ld ms) with error %d",
                        conn->handshake_retries, elapsed_ms, ssl_err);
                connection_free(worker->conn_pool, conn);
                atomic_fetch_add(&worker->stats.errors, 1);
                return;
            }
        }
    }

    /* Read data */
    while (1) {
        /* Check for buffer overflow - prevent underflow */
        if (conn->request_len >= sizeof(conn->request_buf) - 1) {
            LOG_WARN("Request buffer overflow: request_len=%zu, buf_size=%zu",
                    conn->request_len, sizeof(conn->request_buf));
            connection_free(worker->conn_pool, conn);
            atomic_fetch_add(&worker->stats.errors, 1);
            return;
        }

        size_t available = sizeof(conn->request_buf) - conn->request_len - 1;
        if (available == 0) {
            /* Request buffer full - send HTTP 413 Payload Too Large
             * instead of just closing connection */
            static const char response_413[] =
                "HTTP/1.1 413 Payload Too Large\r\n"
                "Content-Type: text/plain\r\n"
                "Content-Length: 24\r\n"
                "Connection: close\r\n"
                "\r\n"
                "413 Payload Too Large";
            send_error_response(worker, conn, response_413, sizeof(response_413) - 1);
            return;
        }

        /* Use SSL_read for HTTPS, recv for HTTP */
        if (conn->is_https && conn->ssl) {
            n = SSL_read(conn->ssl, conn->request_buf + conn->request_len, available);
            if (n <= 0) {
                int ssl_err = SSL_get_error(conn->ssl, n);
                if (ssl_err == SSL_ERROR_WANT_READ || ssl_err == SSL_ERROR_WANT_WRITE) {
                    /* No more data available */
                    break;
                } else if (ssl_err == SSL_ERROR_ZERO_RETURN) {
                    /* Connection closed */
                    connection_free(worker->conn_pool, conn);
                    return;
                } else {
                    /* Error */
                    connection_free(worker->conn_pool, conn);
                    atomic_fetch_add(&worker->stats.errors, 1);
                    return;
                }
            }
        } else {
            n = recv(conn->fd, conn->request_buf + conn->request_len, available, 0);
            if (n == 0) {
                /* Connection closed */
                connection_free(worker->conn_pool, conn);
                return;
            } else if (n < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    /* No more data available */
                    break;
                }
                /* Error */
                connection_free(worker->conn_pool, conn);
                atomic_fetch_add(&worker->stats.errors, 1);
                return;
            }
        }

        if (n > 0) {
            conn->request_len += n;
            conn->request_buf[conn->request_len] = '\0';
            atomic_fetch_add(&worker->stats.bytes_received, n);

            /* Check if we have complete request (double CRNL) */
            if (strstr(conn->request_buf, "\r\n\r\n") ||
                strstr(conn->request_buf, "\n\n")) {
                /* Process request */
                process_http_request(worker, conn);
                return;
            }
        }
    }

    connection_set_state(conn, CONN_STATE_READING);
}

/* Handle connection write event */
void worker_handle_connection_write(worker_t *worker, connection_t *conn) {
    if (!conn->response_buf || conn->response_sent >= conn->response_len) {
        /* Nothing to send or already sent */
        if (conn->close_after_write) {
            connection_free(worker->conn_pool, conn);
        } else {
            /* Switch back to reading */
            struct epoll_event ev;
            ev.events = EPOLLIN | EPOLLET;
            ev.data.ptr = conn;
            if (epoll_ctl(worker->epoll_fd, EPOLL_CTL_MOD, conn->fd, &ev) < 0) {
                LOG_ERROR("epoll_ctl MOD failed for fd=%d: %s", conn->fd, strerror(errno));
                connection_free(worker->conn_pool, conn);
                atomic_fetch_add(&worker->stats.errors, 1);
                return;
            }
            connection_reset(conn);
            connection_set_state(conn, CONN_STATE_READING);
        }
        return;
    }

    /* Apply timing jitter on first send (anti-fingerprinting) */
    if (conn->response_sent == 0) {
        timing_jitter_apply(conn);
    }

    /* Send response - use SSL_write for HTTPS, send for HTTP */
    ssize_t n;
    if (conn->is_https && conn->ssl) {
        n = SSL_write(conn->ssl,
                      conn->response_buf + conn->response_sent,
                      conn->response_len - conn->response_sent);
        if (n <= 0) {
            int ssl_err = SSL_get_error(conn->ssl, n);
            if (ssl_err == SSL_ERROR_WANT_READ || ssl_err == SSL_ERROR_WANT_WRITE) {
                /* Can't write yet - wait for next event */
                return;
            } else {
                /* Error */
                connection_free(worker->conn_pool, conn);
                atomic_fetch_add(&worker->stats.errors, 1);
                return;
            }
        }
    } else {
        n = send(conn->fd,
                conn->response_buf + conn->response_sent,
                conn->response_len - conn->response_sent,
                MSG_NOSIGNAL);
        if (n < 0) {
            if (errno != EAGAIN && errno != EWOULDBLOCK) {
                connection_free(worker->conn_pool, conn);
                atomic_fetch_add(&worker->stats.errors, 1);
            }
            return;
        }
    }

    if (n > 0) {
        conn->response_sent += n;
        atomic_fetch_add(&worker->stats.bytes_sent, n);

        if (conn->response_sent >= conn->response_len) {
            /* Response complete */
            if (conn->close_after_write) {
                connection_free(worker->conn_pool, conn);
            } else {
                /* Keep-alive: wait for next request */
                struct epoll_event ev;
                ev.events = EPOLLIN | EPOLLET;
                ev.data.ptr = conn;
                if (epoll_ctl(worker->epoll_fd, EPOLL_CTL_MOD, conn->fd, &ev) < 0) {
                    LOG_ERROR("epoll_ctl MOD failed for fd=%d: %s", conn->fd, strerror(errno));
                    connection_free(worker->conn_pool, conn);
                    atomic_fetch_add(&worker->stats.errors, 1);
                    return;
                }
                connection_reset(conn);
                connection_set_state(conn, CONN_STATE_READING);
            }
        }
    }
}

/* Check for connection timeouts */
void worker_check_timeouts(worker_t *worker) {
    time_t now = time(NULL);
    const int timeout_sec = 60;  /* 60 second timeout (HTTP/1.1 keep-alive) */

    for (size_t i = 0; i < worker->conn_pool->pool_size; i++) {
        connection_t *conn = &worker->conn_pool->connections[i];

        /* RACE CONDITION FIX: Use atomic compare-and-swap to prevent TOCTOU
         * Check state and timeout, then atomically try to set to CLOSING
         * Only free if we successfully claimed the connection */
        connection_state_t current_state = atomic_load_explicit(&conn->state, memory_order_acquire);

        if (current_state != CONN_STATE_IDLE &&
            current_state != CONN_STATE_CLOSING &&
            connection_is_timeout(conn, now, timeout_sec)) {

            /* Try to atomically transition to CLOSING state
             * If this fails, another thread already modified the state */
            if (atomic_compare_exchange_strong_explicit(&conn->state,
                                                       &current_state,
                                                       CONN_STATE_CLOSING,
                                                       memory_order_acq_rel,
                                                       memory_order_acquire)) {
                /* We successfully claimed this connection for cleanup */
                connection_free(worker->conn_pool, conn);
                atomic_fetch_add(&worker->stats.timeouts, 1);
            }
        }
    }
}

/* Helper: Send static error response */
static void send_error_response(worker_t *worker, connection_t *conn, const char *response, size_t response_len) {
    conn->response_buf = (char*)response;
    conn->response_len = response_len;
    conn->response_is_static = 1;
    conn->close_after_write = 1;

    struct epoll_event ev;
    ev.events = EPOLLOUT | EPOLLET;
    ev.data.ptr = conn;
    if (epoll_ctl(worker->epoll_fd, EPOLL_CTL_MOD, conn->fd, &ev) < 0) {
        LOG_ERROR("epoll_ctl MOD failed for fd=%d: %s", conn->fd, strerror(errno));
        connection_free(worker->conn_pool, conn);
        atomic_fetch_add(&worker->stats.errors, 1);
        return;
    }
    connection_set_state(conn, CONN_STATE_WRITING);
}

/* Process HTTP request and generate response */
static void process_http_request(worker_t *worker, connection_t *conn) {
    /* ========== RFC 2616 COMPLIANCE CHECKS ========== */

    /* Check 1: 431 Request Header Fields Too Large (>128KB request)
     * Note: 128KB buffer supports very long URLs with tracking parameters */
    if (conn->request_len >= 131072) {
        static const char response_431[] =
            "HTTP/1.1 431 Request Header Fields Too Large\r\n"
            "Content-Type: text/plain\r\n"
            "Content-Length: 37\r\n"
            "Connection: close\r\n"
            "\r\n"
            "431 Request Header Fields Too Large";
        send_error_response(worker, conn, response_431, sizeof(response_431) - 1);
        return;
    }

    /* SECURITY FIX: Parse HTTP request line with bounds checking
     * METHOD: 15 chars + null = 16 bytes
     * PATH: Calculated to fit in buffer with null terminator
     * VERSION: 15 chars + null = 16 bytes
     *
     * Note: sscanf with %Ns writes N+1 bytes (including NUL), so use sizeof-1
     * For 32767-byte path buffer, use %32766s maximum
     */
    char http_version[16] = {0};  /* Ensure version string is initialized */
    if (sscanf(conn->request_buf, "%15s %32766s %15s", conn->method, conn->path, http_version) < 2) {
        /* Check 2: 400 Bad Request (malformed HTTP syntax) */
        static const char response_400[] =
            "HTTP/1.1 400 Bad Request\r\n"
            "Content-Type: text/plain\r\n"
            "Content-Length: 15\r\n"
            "Connection: close\r\n"
            "\r\n"
            "400 Bad Request";
        send_error_response(worker, conn, response_400, sizeof(response_400) - 1);
        return;
    }

    /* SECURITY FIX: Validate path length didn't exceed expectations
     * This catches any potential sscanf overflow */
    if (strlen(conn->path) > 32766) {
        LOG_WARN("Path length exceeds maximum: %zu bytes", strlen(conn->path));
        static const char response_414[] =
            "HTTP/1.1 414 URI Too Long\r\n"
            "Content-Type: text/plain\r\n"
            "Content-Length: 17\r\n"
            "Connection: close\r\n"
            "\r\n"
            "414 URI Too Long";
        send_error_response(worker, conn, response_414, sizeof(response_414) - 1);
        return;
    }

    /* CRITICAL FIX: Decode URL-encoded path for polyglot content type detection
     *
     * Polyglot URLs encode the expected content type at the end using %HH notation.
     * Example: /player/www.example.com/...base64hash...%48%54%4D%4C
     * Decodes to: /player/www.example.com/...base64hash...HTML
     *
     * Without decoding, the response handler doesn't know if it should return
     * HTML/JS/PNG, resulting in "response error".
     *
     * This fix extracts the decoded path so the response handler can determine
     * the correct Content-Type header.
     */
    {
        char decoded_path[32768];
        char *decoded = decoded_path;
        const char *src = conn->path;
        size_t remaining = sizeof(decoded_path) - 1;  /* Reserve space for null terminator */

        /* SECURITY FIX: URL decode with proper bounds checking and validation
         * Check remaining BEFORE writing to ensure we never overflow the buffer */
        while (*src && remaining >= 1) {  /* >= 1 ensures space for char + null terminator */
            remaining--;  /* Decrement FIRST before using the space */

            if (*src == '%' && *(src + 1) && *(src + 2)) {
                unsigned int hex_val = 0;
                /* Validate that next 2 chars are valid hex digits before sscanf */
                char c1 = *(src + 1);
                char c2 = *(src + 2);

                if (((c1 >= '0' && c1 <= '9') || (c1 >= 'a' && c1 <= 'f') || (c1 >= 'A' && c1 <= 'F')) &&
                    ((c2 >= '0' && c2 <= '9') || (c2 >= 'a' && c2 <= 'f') || (c2 >= 'A' && c2 <= 'F'))) {

                    if (sscanf(src + 1, "%2x", &hex_val) == 1 && hex_val <= 0xFF) {
                        *decoded++ = (unsigned char)hex_val;  /* Use unsigned char for clarity */
                        src += 3;  /* Skip %HH */
                    } else {
                        /* Should not happen given validation above, but be safe */
                        *decoded++ = *src++;
                    }
                } else {
                    /* Not valid hex encoding - copy the % and continue */
                    *decoded++ = *src++;
                }
            } else {
                *decoded++ = *src++;
            }
        }
        *decoded = '\0';  /* Safe: remaining was decremented first, guaranteeing space */

        /* SECURITY FIX: Multi-pass decoding to catch double-encoded traversal attacks
         * Example: %252e%252e%252f → %2e%2e%2f (still dangerous, re-decode)
         *          %2e%2e%2f → .. / (now we can detect it)
         * This prevents multiple levels of encoding bypass attempts */
        char prev_path[32768];
        int decode_iterations = 0;
        const int MAX_DECODE_ITERATIONS = 5;  /* Prevent infinite loops */

        do {
            strncpy(prev_path, decoded_path, sizeof(prev_path) - 1);
            prev_path[sizeof(prev_path) - 1] = '\0';

            /* Re-decode if we find percent signs (indicates another encoding layer) */
            if (strchr(decoded_path, '%')) {
                const char *src_inner = decoded_path;
                char *dest_inner = decoded_path;
                size_t remaining_inner = sizeof(decoded_path) - 1;

                while (*src_inner && remaining_inner >= 1) {
                    remaining_inner--;
                    if (*src_inner == '%' && *(src_inner + 1) && *(src_inner + 2)) {
                        unsigned int hex_val = 0;
                        char c1 = *(src_inner + 1);
                        char c2 = *(src_inner + 2);

                        if (((c1 >= '0' && c1 <= '9') || (c1 >= 'a' && c1 <= 'f') || (c1 >= 'A' && c1 <= 'F')) &&
                            ((c2 >= '0' && c2 <= '9') || (c2 >= 'a' && c2 <= 'f') || (c2 >= 'A' && c2 <= 'F'))) {
                            if (sscanf(src_inner + 1, "%2x", &hex_val) == 1 && hex_val <= 0xFF) {
                                *dest_inner++ = (unsigned char)hex_val;
                                src_inner += 3;
                            } else {
                                *dest_inner++ = *src_inner++;
                            }
                        } else {
                            *dest_inner++ = *src_inner++;
                        }
                    } else {
                        *dest_inner++ = *src_inner++;
                    }
                }
                *dest_inner = '\0';
            }

            decode_iterations++;
        } while (strcmp(prev_path, decoded_path) != 0 && decode_iterations < MAX_DECODE_ITERATIONS);

        if (decode_iterations >= MAX_DECODE_ITERATIONS) {
            LOG_WARN("Path decoding exceeded max iterations - possible encoding attack: %s", conn->path);
            static const char response_403[] =
                "HTTP/1.1 403 Forbidden\r\n"
                "Content-Type: text/plain\r\n"
                "Content-Length: 13\r\n"
                "Connection: close\r\n"
                "\r\n"
                "403 Forbidden";
            send_error_response(worker, conn, response_403, sizeof(response_403) - 1);
            return;
        }

        /* SECURITY FIX: Enhanced path traversal detection
         * Check for dangerous sequences: ../, ..\, absolute paths, and URL-encoded variants
         * Also detects Unicode overlong encoding attacks: %c0%ae (overlong encoding of .)
         */
        const char *p = decoded_path;
        bool has_traversal = false;
        while (*p) {
            /* Check for ../ or ..\ */
            if (p[0] == '.' && p[1] == '.' && (p[2] == '/' || p[2] == '\\')) {
                has_traversal = true;
                break;
            }
            /* Check for /.. or \.. at end of string */
            if (p[0] == '.' && p[1] == '.' && (p[2] == '\0' || p[2] == '?')) {
                if (p > decoded_path && (p[-1] == '/' || p[-1] == '\\')) {
                    has_traversal = true;
                    break;
                }
            }
            /* Check for null bytes (can bypass string operations) */
            if (p[0] == '\0' && p > decoded_path) {
                has_traversal = true;
                break;
            }
            /* Check for remaining URL-encoded sequences after full decode */
            if (p[0] == '%' && p[1] && p[2]) {
                char c1 = p[1];
                char c2 = p[2];
                if (((c1 >= '0' && c1 <= '9') || (c1 >= 'a' && c1 <= 'f') || (c1 >= 'A' && c1 <= 'F')) &&
                    ((c2 >= '0' && c2 <= '9') || (c2 >= 'a' && c2 <= 'f') || (c2 >= 'A' && c2 <= 'F'))) {
                    /* Found valid percent encoding after full decode - suspicious */
                    has_traversal = true;
                    break;
                }
            }
            p++;
        }

        /* Block path traversal attempts */
        if (has_traversal) {
            static const char response_403[] =
                "HTTP/1.1 403 Forbidden\r\n"
                "Content-Type: text/plain\r\n"
                "Content-Length: 13\r\n"
                "Connection: close\r\n"
                "\r\n"
                "403 Forbidden";
            send_error_response(worker, conn, response_403, sizeof(response_403) - 1);
            return;
        }

        /* Replace original path with decoded version
         * Use explicit length check to avoid truncation warnings */
        size_t decoded_len = strlen(decoded_path);
        if (decoded_len >= sizeof(conn->path)) {
            decoded_len = sizeof(conn->path) - 1;
        }
        memcpy(conn->path, decoded_path, decoded_len);
        conn->path[decoded_len] = '\0';
    }

    /* Extract User-Agent header (for anti-adblock fingerprinting)
     *
     * User-Agent helps anti-adblock system generate realistic headers:
     * - Server rotation based on browser/OS
     * - CF-RAY format adjustments
     * - Cache-Control variations
     *
     * Header format: "User-Agent: Mozilla/5.0 ..."
     * Case-insensitive search (RFC 2616)
     */
    conn->user_agent[0] = '\0';  /* Default: empty */
    const char *ua_header = strcasestr(conn->request_buf, "\r\nUser-Agent:");
    if (ua_header) {
        ua_header += 14;  /* Skip "\r\nUser-Agent:" */
        const char *ua_end = strstr(ua_header, "\r\n");
        if (ua_end) {
            size_t ua_len = ua_end - ua_header;
            if (ua_len > 0) {
                /* Trim leading whitespace */
                while (ua_len > 0 && (*ua_header == ' ' || *ua_header == '\t')) {
                    ua_header++;
                    ua_len--;
                }
                /* Copy User-Agent (truncate if too long) */
                if (ua_len >= sizeof(conn->user_agent)) {
                    ua_len = sizeof(conn->user_agent) - 1;
                }
                memcpy(conn->user_agent, ua_header, ua_len);
                conn->user_agent[ua_len] = '\0';
            }
        }
    }

    /* Check 3: 414 URI Too Long (>32KB path) */
    if (strlen(conn->path) >= 32768) {
        static const char response_414[] =
            "HTTP/1.1 414 URI Too Long\r\n"
            "Content-Type: text/plain\r\n"
            "Content-Length: 18\r\n"
            "Connection: close\r\n"
            "\r\n"
            "414 URI Too Long";
        send_error_response(worker, conn, response_414, sizeof(response_414) - 1);
        return;
    }

    /* Validate HTTP method (RFC 2616 + common extensions)
     *
     * DNS SINKHOLE STEALTH: WHY we send 405 for invalid methods
     *
     * Goal: Behave EXACTLY like the real servers we're impersonating!
     *
     * Real servers (Google Analytics, Facebook Pixel, Cloudflare):
     *   INVALID method → 405 Method Not Allowed
     *
     * If we send 200 OK for INVALID methods:
     *   - Malware tests: "INVALID method → 200 OK?? No real server does that!"
     *   - Detection: "This is a sinkhole/termination endpoint, not the real server!"
     *   - Result: Malware activates fallback mechanisms
     *
     * If we send 405 (like we do):
     *   - Malware tests: "INVALID method → 405, as expected"
     *   - Result: "Looks like a normal server, everything OK"
     *   - We stay INVISIBLE!
     *
     * Stealth = Act normal, not suspicious!
     */
    const char *valid_methods[] = {
        "GET", "POST", "HEAD", "PUT", "DELETE", "OPTIONS", "TRACE",
        "CONNECT", "PATCH", NULL
    };
    int method_valid = 0;
    for (int i = 0; valid_methods[i] != NULL; i++) {
        if (strcasecmp(conn->method, valid_methods[i]) == 0) {
            method_valid = 1;
            break;
        }
    }
    if (!method_valid) {
        /* Send 405 Method Not Allowed (RFC 2616 compliant + stealth!) */
        static const char method_not_allowed[] =
            "HTTP/1.1 405 Method Not Allowed\r\n"
            "Content-Type: text/plain\r\n"
            "Content-Length: 22\r\n"
            "Allow: GET, POST, HEAD, PUT, DELETE, OPTIONS, TRACE, CONNECT, PATCH\r\n"
            "Connection: close\r\n"
            "\r\n"
            "405 Method Not Allowed";
        conn->response_buf = (char*)method_not_allowed;
        conn->response_len = sizeof(method_not_allowed) - 1;
        conn->response_is_static = 1;
        conn->close_after_write = 1;

        struct epoll_event ev;
        ev.events = EPOLLOUT | EPOLLET;
        ev.data.ptr = conn;
        if (epoll_ctl(worker->epoll_fd, EPOLL_CTL_MOD, conn->fd, &ev) < 0) {
            LOG_ERROR("epoll_ctl MOD failed for fd=%d: %s", conn->fd, strerror(errno));
            connection_free(worker->conn_pool, conn);
            atomic_fetch_add(&worker->stats.errors, 1);
            return;
        }
        connection_set_state(conn, CONN_STATE_WRITING);
        return;
    }

    /* Check 4: OPTIONS method (CORS preflight) */
    if (strcasecmp(conn->method, "OPTIONS") == 0) {
        /* CRITICAL for modern web apps: CORS preflight requests!
         * Browser sends OPTIONS before POST/PUT/DELETE
         * Must respond with Allow + CORS headers */
        static const char options_response[] =
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: text/plain\r\n"
            "Content-Length: 0\r\n"
            "Connection: keep-alive\r\n"
            "Allow: GET, POST, HEAD, PUT, DELETE, OPTIONS, TRACE, CONNECT, PATCH\r\n"
            "Access-Control-Allow-Origin: *\r\n"
            "Access-Control-Allow-Methods: GET, POST, HEAD, PUT, DELETE, OPTIONS, TRACE, CONNECT, PATCH\r\n"
            "Access-Control-Allow-Headers: *\r\n"
            "Access-Control-Allow-Credentials: true\r\n"
            "Access-Control-Max-Age: 86400\r\n"
            "\r\n";
        conn->response_buf = (char*)options_response;
        conn->response_len = sizeof(options_response) - 1;
        conn->response_is_static = 1;
        conn->close_after_write = 0;  /* Keep-alive for OPTIONS! */

        struct epoll_event ev;
        ev.events = EPOLLOUT | EPOLLET;
        ev.data.ptr = conn;
        if (epoll_ctl(worker->epoll_fd, EPOLL_CTL_MOD, conn->fd, &ev) < 0) {
            LOG_ERROR("epoll_ctl MOD failed for fd=%d: %s", conn->fd, strerror(errno));
            connection_free(worker->conn_pool, conn);
            atomic_fetch_add(&worker->stats.errors, 1);
            return;
        }
        connection_set_state(conn, CONN_STATE_WRITING);
        atomic_fetch_add(&worker->stats.requests_handled, 1);
        return;
    }

    /* Extract file extension from last path segment only
     * This prevents false positives with domain names in path:
     * - /player/www.example.com → no extension (not .com!)
     * - /player/file.js → extension .js ✓
     * - /path/to/file.tar.gz → extension .gz (last extension)
     *
     * Special handling: Ignore common TLDs (.com, .de, .org, etc.)
     * to prevent treating domain names as file extensions
     */
    char *last_slash = strrchr(conn->path, '/');
    char *search_start = last_slash ? last_slash : conn->path;
    conn->ext = strrchr(search_start, '.');
    if (conn->ext) {
        conn->ext++;  /* Skip the '.' */

        /* Check if this is a common TLD (domain name) and ignore it
         * List of most common TLDs that should NOT be treated as file extensions */
        static const char *tlds[] = {
            "com", "org", "net", "edu", "gov", "mil", "int",
            "de", "uk", "fr", "it", "es", "nl", "be", "ch", "at",
            "eu", "io", "co", "me", "tv", "info", "biz", "name",
            "ru", "cn", "jp", "br", "au", "ca", "us", "in",
            NULL
        };

        for (int i = 0; tlds[i] != NULL; i++) {
            if (strcasecmp(conn->ext, tlds[i]) == 0) {
                /* This is a TLD, not a file extension */
                conn->ext = NULL;
                break;
            }
        }
    }

    /* RFC 2616: HTTP/1.1 keep-alive is DEFAULT unless "Connection: close"
     * HTTP/1.0 requires explicit "Connection: keep-alive" */
    int is_http_11 = (strstr(http_version, "HTTP/1.1") != NULL);
    int has_close = (strstr(conn->request_buf, "Connection: close") != NULL ||
                     strstr(conn->request_buf, "Connection: Close") != NULL);
    int has_keepalive = (strstr(conn->request_buf, "Connection: keep-alive") != NULL ||
                         strstr(conn->request_buf, "Connection: Keep-Alive") != NULL);

    if (is_http_11) {
        /* HTTP/1.1: keep-alive unless explicitly closed */
        conn->keep_alive = !has_close;
    } else {
        /* HTTP/1.0: keep-alive only if explicitly requested */
        conn->keep_alive = has_keepalive && !has_close;
    }

    conn->close_after_write = !conn->keep_alive;

    /* Generate response using full response logic (Phase 1 integration) */
    if (response_generate(conn) != 0) {
        /* Response generation failed - use minimal fallback */
        send_minimal_response(worker, conn);
    } else {
        /* HEAD request: Send headers only (RFC 2616 - same headers as GET but no body) */
        if (strcasecmp(conn->method, "HEAD") == 0) {
            /* Find end of headers */
            char *body_start = strstr(conn->response_buf, "\r\n\r\n");
            if (body_start) {
                /* Keep Content-Length in headers, but don't send body */
                conn->response_len = (body_start - conn->response_buf) + 4;  /* Include \r\n\r\n */
            }
        }

        /* Response generated successfully - switch to writing mode */
        struct epoll_event ev;
        ev.events = EPOLLOUT | EPOLLET;
        ev.data.ptr = conn;
        if (epoll_ctl(worker->epoll_fd, EPOLL_CTL_MOD, conn->fd, &ev) < 0) {
            LOG_ERROR("epoll_ctl MOD failed for fd=%d: %s", conn->fd, strerror(errno));
            connection_free(worker->conn_pool, conn);
            atomic_fetch_add(&worker->stats.errors, 1);
            return;
        }
        connection_set_state(conn, CONN_STATE_WRITING);
    }

    atomic_fetch_add(&worker->stats.requests_handled, 1);
}

/* Send minimal HTTP response (empty - no static signatures!) */
static void send_minimal_response(worker_t *worker, connection_t *conn) {
    /* Empty response - no static "OK" or other signatures! */
    static const char response[] =
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/plain\r\n"
        "Content-Length: 0\r\n"
        "Connection: close\r\n"
        "\r\n";

    /* IMPORTANT: Don't allocate - use static buffer */
    conn->response_buf = (char*)response;
    conn->response_len = sizeof(response) - 1;
    conn->response_sent = 0;
    conn->response_is_static = 1;  /* Mark as static - don't free! */

    /* Switch to writing mode */
    struct epoll_event ev;
    ev.events = EPOLLOUT | EPOLLET;
    ev.data.ptr = conn;
    if (epoll_ctl(worker->epoll_fd, EPOLL_CTL_MOD, conn->fd, &ev) < 0) {
        LOG_ERROR("epoll_ctl MOD failed for fd=%d: %s", conn->fd, strerror(errno));
        connection_free(worker->conn_pool, conn);
        atomic_fetch_add(&worker->stats.errors, 1);
        return;
    }

    connection_set_state(conn, CONN_STATE_WRITING);
}

/* Print worker statistics */
void worker_print_stats(worker_t *worker) {
    LOG_INFO("Worker %d Stats: Connections=%lu, Requests=%lu, Bytes_sent=%lu, Bytes_recv=%lu, Errors=%lu, Timeouts=%lu, Active=%zu",
        worker->worker_id,
        atomic_load_explicit(&worker->stats.connections_accepted, memory_order_acquire),
        atomic_load_explicit(&worker->stats.requests_handled, memory_order_acquire),
        atomic_load_explicit(&worker->stats.bytes_sent, memory_order_acquire),
        atomic_load_explicit(&worker->stats.bytes_received, memory_order_acquire),
        atomic_load_explicit(&worker->stats.errors, memory_order_acquire),
        atomic_load_explicit(&worker->stats.timeouts, memory_order_acquire),
        worker->conn_pool->active_count);
}

/* Add connection to worker (legacy - assumes AUTO type)
 *
 * FIX: Better error documentation
 * Returns -1 if pipe write fails. Caller MUST close client_fd to prevent FD leak.
 * This is correctly handled in tlsgateNG.c:720-722.
 */
int worker_add_connection(worker_t *worker, int client_fd) {
    connection_pipe_msg_t msg = {
        .fd = client_fd,
        .socket_type = 2  /* AUTO - needs detection */
    };
    if (write(worker->pipe_fd[1], &msg, sizeof(msg)) != sizeof(msg)) {
        /* IMPORTANT: Do NOT close client_fd here! Caller owns the FD and must close it.
         * Closing here would cause double-close if caller also closes on error. */
        return -1;
    }
    return 0;
}

/* Add connection to worker with explicit socket type and remote address
 *
 * FIX: Better error documentation
 * Returns -1 if pipe write fails. Caller MUST close client_fd to prevent FD leak.
 * This is correctly handled in tlsgateNG.c:720-722.
 */
int worker_add_connection_ex(worker_t *worker, int client_fd, int socket_type, const char *remote_addr) {
    connection_pipe_msg_t msg = {
        .fd = client_fd,
        .socket_type = socket_type
    };

    /* Copy remote address (or empty string if NULL) */
    if (remote_addr) {
        size_t addr_len = strlen(remote_addr);
        if (addr_len >= sizeof(msg.remote_addr)) {
            addr_len = sizeof(msg.remote_addr) - 1;
        }
        memcpy(msg.remote_addr, remote_addr, addr_len);
        msg.remote_addr[addr_len] = '\0';  /* Ensure null-termination */
    } else {
        msg.remote_addr[0] = '\0';
    }

    if (write(worker->pipe_fd[1], &msg, sizeof(msg)) != sizeof(msg)) {
        /* IMPORTANT: Do NOT close client_fd here! Caller owns the FD and must close it.
         * Closing here would cause double-close if caller also closes on error. */
        return -1;
    }
    return 0;
}
