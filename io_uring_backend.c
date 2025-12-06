#include "event_loop.h"
#include "async_connection.h"
#include "logger.h"
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/poll.h>
#include <liburing.h>

/**
 * io_uring backend implementation of abstract event_loop interface
 * Linux 5.1+ with io_uring support
 */

struct event_loop {
    struct io_uring ring;
    unsigned int queue_depth;
    uint64_t ops_submitted;
    uint64_t ops_completed;
    int initialized;
};

/**
 * Initialize io_uring event loop
 */
event_loop_t *event_loop_init(unsigned int queue_depth) {
    event_loop_t *loop = malloc(sizeof(event_loop_t));
    if (!loop) {
        log_msg(LGG_ERR, "Failed to allocate event loop");
        return NULL;
    }

    memset(loop, 0, sizeof(event_loop_t));
    loop->queue_depth = queue_depth;

    /* Initialize io_uring */
    int ret = io_uring_queue_init(queue_depth, &loop->ring, 0);
    if (ret < 0) {
        log_msg(LGG_ERR, "Failed to initialize io_uring: %d", ret);
        free(loop);
        return NULL;
    }

    loop->initialized = 1;
    log_msg(LGG_NOTICE, "io_uring initialized with queue depth %u", queue_depth);

    return loop;
}

/**
 * Destroy io_uring event loop
 */
void event_loop_destroy(event_loop_t *loop) {
    if (!loop) return;

    if (loop->initialized) {
        io_uring_queue_exit(&loop->ring);
    }
    free(loop);
}

/**
 * Submit async accept
 */
int event_loop_accept(event_loop_t *loop, int listen_fd, async_connection_t *conn) {
    if (!loop || !conn) return -1;

    struct io_uring_sqe *sqe = io_uring_get_sqe(&loop->ring);
    if (!sqe) {
        log_msg(LGG_WARNING, "io_uring SQE exhausted");
        return -1;
    }

    io_uring_prep_accept(sqe, listen_fd, NULL, NULL, 0);
    sqe->user_data = (uint64_t)conn;

    loop->ops_submitted++;
    return 0;
}

/**
 * Submit async read
 */
int event_loop_read(event_loop_t *loop, async_connection_t *conn, char *buf, size_t len) {
    if (!loop || !conn || !buf) return -1;

    struct io_uring_sqe *sqe = io_uring_get_sqe(&loop->ring);
    if (!sqe) {
        log_msg(LGG_WARNING, "io_uring SQE exhausted");
        return -1;
    }

    io_uring_prep_read(sqe, conn->fd, buf, len, 0);
    sqe->user_data = (uint64_t)conn;

    loop->ops_submitted++;
    return 0;
}

/**
 * Submit async write
 */
int event_loop_write(event_loop_t *loop, async_connection_t *conn, const char *buf, size_t len) {
    if (!loop || !conn || !buf) return -1;

    struct io_uring_sqe *sqe = io_uring_get_sqe(&loop->ring);
    if (!sqe) {
        log_msg(LGG_WARNING, "io_uring SQE exhausted");
        return -1;
    }

    io_uring_prep_write(sqe, conn->fd, buf, len, 0);
    sqe->user_data = (uint64_t)conn;

    loop->ops_submitted++;
    return 0;
}

/**
 * Submit async poll
 */
int event_loop_poll(event_loop_t *loop, async_connection_t *conn, int timeout_ms) {
    if (!loop || !conn) return -1;

    struct io_uring_sqe *sqe = io_uring_get_sqe(&loop->ring);
    if (!sqe) {
        log_msg(LGG_WARNING, "io_uring SQE exhausted");
        return -1;
    }

    io_uring_prep_poll_add(sqe, conn->fd, POLLIN);
    sqe->user_data = (uint64_t)conn;

    loop->ops_submitted++;
    return 0;
}

/**
 * Submit async close
 */
int event_loop_close(event_loop_t *loop, async_connection_t *conn) {
    if (!loop || !conn) return -1;

    struct io_uring_sqe *sqe = io_uring_get_sqe(&loop->ring);
    if (!sqe) {
        log_msg(LGG_WARNING, "io_uring SQE exhausted");
        return -1;
    }

    io_uring_prep_close(sqe, conn->fd);
    sqe->user_data = (uint64_t)conn;

    loop->ops_submitted++;
    return 0;
}

/**
 * Wait for completions and invoke handlers
 */
int event_loop_wait(event_loop_t *loop, int timeout_ms, event_completion_handler_t handler) {
    if (!loop || !handler) return -1;

    /* Submit all pending operations */
    int ret = io_uring_submit(&loop->ring);
    if (ret < 0) {
        log_msg(LGG_ERR, "io_uring_submit failed: %d", ret);
        return ret;
    }

    /* Wait for completions */
    struct io_uring_cqe *cqe;
    unsigned head;
    int processed = 0;

    io_uring_for_each_cqe(&loop->ring, head, cqe) {
        async_connection_t *conn = (async_connection_t *)cqe->user_data;
        if (conn) {
            int result = cqe->res;
            handler(loop, conn, result);
            processed++;
        }
        loop->ops_completed++;
    }

    io_uring_cq_advance(&loop->ring, processed);

    return processed;
}

/**
 * Print event loop statistics
 */
void event_loop_stats(event_loop_t *loop) {
    if (!loop) return;

    log_msg(LGG_INFO, "io_uring stats: submitted=%lu completed=%lu queue_depth=%u",
            loop->ops_submitted, loop->ops_completed, loop->queue_depth);
}
