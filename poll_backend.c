#include "event_loop.h"
#include "async_connection.h"
#include "logger.h"
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/poll.h>
#include <errno.h>

/**
 * poll() based backend implementation - Fallback when io_uring unavailable
 * Works on all POSIX systems
 */

#define MAX_EVENTS 4096

typedef struct pending_op {
    async_connection_t *conn;
    io_op_type_t type;
    char *buf;
    size_t len;
    int fd;
} pending_op_t;

struct event_loop {
    struct pollfd fds[MAX_EVENTS];
    pending_op_t ops[MAX_EVENTS];
    int nfds;
    unsigned int queue_depth;
    uint64_t ops_submitted;
    uint64_t ops_completed;
    int initialized;
};

/**
 * Initialize poll event loop
 */
event_loop_t *event_loop_init(unsigned int queue_depth) {
    event_loop_t *loop = malloc(sizeof(event_loop_t));
    if (!loop) {
        log_msg(LGG_ERR, "Failed to allocate event loop");
        return NULL;
    }

    memset(loop, 0, sizeof(event_loop_t));
    loop->queue_depth = queue_depth > MAX_EVENTS ? MAX_EVENTS : queue_depth;
    loop->nfds = 0;
    loop->initialized = 1;

    log_msg(LGG_NOTICE, "poll backend initialized with max events %u", loop->queue_depth);

    return loop;
}

/**
 * Destroy poll event loop
 */
void event_loop_destroy(event_loop_t *loop) {
    if (!loop) return;
    free(loop);
}

static int add_pending_op(event_loop_t *loop, async_connection_t *conn,
                          io_op_type_t type, int fd, char *buf, size_t len, short events) {
    if (loop->nfds >= MAX_EVENTS) {
        log_msg(LGG_WARNING, "poll: max events reached");
        return -1;
    }

    int idx = loop->nfds;
    loop->fds[idx].fd = fd;
    loop->fds[idx].events = events;
    loop->fds[idx].revents = 0;

    loop->ops[idx].conn = conn;
    loop->ops[idx].type = type;
    loop->ops[idx].buf = buf;
    loop->ops[idx].len = len;
    loop->ops[idx].fd = fd;

    /* Update connection pending_io type */
    if (conn) {
        conn->pending_io.type = type;
        conn->pending_io.fd = fd;
    }

    loop->nfds++;
    loop->ops_submitted++;
    return 0;
}

/**
 * Submit async accept
 */
int event_loop_accept(event_loop_t *loop, int listen_fd, async_connection_t *conn) {
    if (!loop || !conn) return -1;
    conn->pending_io.type = IO_OP_ACCEPT;
    return add_pending_op(loop, conn, IO_OP_ACCEPT, listen_fd, NULL, 0, POLLIN);
}

/**
 * Submit async read
 */
int event_loop_read(event_loop_t *loop, async_connection_t *conn, char *buf, size_t len) {
    if (!loop || !conn || !buf) return -1;
    return add_pending_op(loop, conn, IO_OP_READ, conn->fd, buf, len, POLLIN);
}

/**
 * Submit async write
 */
int event_loop_write(event_loop_t *loop, async_connection_t *conn, const char *buf, size_t len) {
    if (!loop || !conn || !buf) return -1;
    return add_pending_op(loop, conn, IO_OP_WRITE, conn->fd, (char*)buf, len, POLLOUT);
}

/**
 * Submit async poll
 */
int event_loop_poll(event_loop_t *loop, async_connection_t *conn, int timeout_ms) {
    if (!loop || !conn) return -1;
    return add_pending_op(loop, conn, IO_OP_READ, conn->fd, NULL, 0, POLLIN);
}

/**
 * Submit async close - executed immediately for poll backend
 */
int event_loop_close(event_loop_t *loop, async_connection_t *conn) {
    if (!loop || !conn) return -1;
    /* For poll backend, execute close immediately and add a "done" marker
     * that will be processed on next event_loop_wait */
    close(conn->fd);
    conn->fd = -1;
    return add_pending_op(loop, conn, IO_OP_CLOSE, -1, NULL, 0, POLLIN);
}

/**
 * Wait for completions and invoke handlers
 */
int event_loop_wait(event_loop_t *loop, int timeout_ms, event_completion_handler_t handler) {
    if (!loop || !handler) return -1;
    if (loop->nfds == 0) return 0;

    int processed = 0;

    /* First, process any immediate operations (CLOSE with fd=-1) */
    for (int i = 0; i < loop->nfds; i++) {
        if (loop->ops[i].type == IO_OP_CLOSE && loop->ops[i].fd == -1) {
            handler(loop, loop->ops[i].conn, 0);
            processed++;
            loop->ops_completed++;
            /* Remove this entry */
            if (i < loop->nfds - 1) {
                loop->fds[i] = loop->fds[loop->nfds - 1];
                loop->ops[i] = loop->ops[loop->nfds - 1];
                i--;
            }
            loop->nfds--;
        }
    }

    if (loop->nfds == 0) return processed;

    /* Poll for events */
    int ret = poll(loop->fds, loop->nfds, timeout_ms > 0 ? timeout_ms : 100);
    if (ret < 0) {
        if (errno == EINTR) return processed;
        log_msg(LGG_ERR, "poll failed: %m");
        return ret;
    }

    if (ret == 0) return processed; /* Timeout, no events */

    /* Process completed operations */
    for (int i = 0; i < loop->nfds; i++) {
        if (loop->fds[i].revents == 0) continue;

        async_connection_t *conn = loop->ops[i].conn;
        io_op_type_t type = loop->ops[i].type;
        int result = 0;

        switch (type) {
            case IO_OP_ACCEPT: {
                if (loop->fds[i].revents & POLLIN) {
                    result = accept(loop->ops[i].fd, NULL, NULL);
                } else {
                    result = -1;
                }
                break;
            }
            case IO_OP_READ: {
                if (loop->fds[i].revents & (POLLERR | POLLNVAL)) {
                    result = -1;
                } else if (loop->fds[i].revents & (POLLIN | POLLHUP)) {
                    /* For TLS operations (len=1, dummy buffer), just signal readability
                     * without actually reading - SSL_accept/SSL_read will do the I/O */
                    if (loop->ops[i].len == 1 && loop->ops[i].buf != NULL) {
                        result = 1; /* Signal socket is readable */
                    } else if (loop->ops[i].buf && loop->ops[i].len > 0) {
                        result = read(conn->fd, loop->ops[i].buf, loop->ops[i].len);
                        if (result < 0) result = -errno;
                    } else {
                        result = 1; /* Just signal readability */
                    }
                }
                break;
            }
            case IO_OP_WRITE: {
                if (loop->fds[i].revents & (POLLERR | POLLNVAL)) {
                    result = -1;
                } else if (loop->fds[i].revents & POLLOUT) {
                    /* For TLS operations (len=1, dummy buffer), just signal writability */
                    if (loop->ops[i].len == 1 && loop->ops[i].buf != NULL) {
                        result = 1; /* Signal socket is writable */
                    } else if (loop->ops[i].buf && loop->ops[i].len > 0) {
                        result = write(conn->fd, loop->ops[i].buf, loop->ops[i].len);
                        if (result < 0) result = -errno;
                    } else {
                        result = 1; /* Just signal writability */
                    }
                }
                break;
            }
            case IO_OP_CLOSE: {
                close(conn->fd);
                result = 0;
                break;
            }
            default:
                result = -1;
                break;
        }

        handler(loop, conn, result);
        processed++;
        loop->ops_completed++;

        /* Remove this fd from array by moving last element here */
        if (i < loop->nfds - 1) {
            loop->fds[i] = loop->fds[loop->nfds - 1];
            loop->ops[i] = loop->ops[loop->nfds - 1];
            i--; /* Re-check this index */
        }
        loop->nfds--;
    }

    return processed;
}

/**
 * Print event loop statistics
 */
void event_loop_stats(event_loop_t *loop) {
    if (!loop) return;

    log_msg(LGG_INFO, "poll stats: submitted=%lu completed=%lu pending=%d",
            loop->ops_submitted, loop->ops_completed, loop->nfds);
}
