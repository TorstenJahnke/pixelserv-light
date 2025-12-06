#include "io_uring_async.h"
#include "logger.h"
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/poll.h>
#include <liburing.h>

struct io_uring_wrapper {
    struct io_uring ring;
    unsigned int queue_depth;
    uint64_t ops_submitted;
    uint64_t ops_completed;
    int initialized;
};

/**
 * Initialize io_uring event loop
 */
io_uring_wrapper_t *io_uring_async_init(unsigned int queue_depth) {
    io_uring_wrapper_t *uring = malloc(sizeof(io_uring_wrapper_t));
    if (!uring) {
        log_msg(LGG_ERR, "Failed to allocate io_uring wrapper");
        return NULL;
    }

    memset(uring, 0, sizeof(io_uring_wrapper_t));
    uring->queue_depth = queue_depth;

    /* Initialize io_uring */
    int ret = io_uring_queue_init(queue_depth, &uring->ring, 0);
    if (ret < 0) {
        log_msg(LGG_ERR, "Failed to initialize io_uring: %d", ret);
        free(uring);
        return NULL;
    }

    uring->initialized = 1;
    log_msg(LGG_NOTICE, "io_uring initialized with queue depth %u", queue_depth);

    return uring;
}

/**
 * Destroy io_uring event loop
 */
void io_uring_async_destroy(io_uring_wrapper_t *uring) {
    if (!uring) return;

    if (uring->initialized) {
        io_uring_queue_exit(&uring->ring);
    }
    free(uring);
}

/**
 * Submit async accept operation
 */
int io_uring_async_accept(io_uring_wrapper_t *uring, int listen_fd, async_connection_t *conn) {
    if (!uring || !conn) return -1;

    struct io_uring_sqe *sqe = io_uring_get_sqe(&uring->ring);
    if (!sqe) {
        log_msg(LGG_WARNING, "io_uring SQE exhausted");
        return -1;
    }

    io_uring_prep_accept(sqe, listen_fd, NULL, NULL, 0);
    sqe->user_data = (uint64_t)conn;

    uring->ops_submitted++;
    return 0;
}

/**
 * Submit async read operation
 */
int io_uring_async_read(io_uring_wrapper_t *uring, async_connection_t *conn, char *buf, size_t len) {
    if (!uring || !conn || !buf) return -1;

    struct io_uring_sqe *sqe = io_uring_get_sqe(&uring->ring);
    if (!sqe) {
        log_msg(LGG_WARNING, "io_uring SQE exhausted");
        return -1;
    }

    io_uring_prep_read(sqe, conn->fd, buf, len, 0);
    sqe->user_data = (uint64_t)conn;

    uring->ops_submitted++;
    return 0;
}

/**
 * Submit async write operation
 */
int io_uring_async_write(io_uring_wrapper_t *uring, async_connection_t *conn, const char *buf, size_t len) {
    if (!uring || !conn || !buf) return -1;

    struct io_uring_sqe *sqe = io_uring_get_sqe(&uring->ring);
    if (!sqe) {
        log_msg(LGG_WARNING, "io_uring SQE exhausted");
        return -1;
    }

    io_uring_prep_write(sqe, conn->fd, buf, len, 0);
    sqe->user_data = (uint64_t)conn;

    uring->ops_submitted++;
    return 0;
}

/**
 * Submit async poll operation (for keep-alive timeout)
 */
int io_uring_async_poll(io_uring_wrapper_t *uring, async_connection_t *conn, int timeout_ms) {
    if (!uring || !conn) return -1;

    struct io_uring_sqe *sqe = io_uring_get_sqe(&uring->ring);
    if (!sqe) {
        log_msg(LGG_WARNING, "io_uring SQE exhausted");
        return -1;
    }

    io_uring_prep_poll_add(sqe, conn->fd, POLLIN);
    sqe->user_data = (uint64_t)conn;

    uring->ops_submitted++;
    return 0;
}

/**
 * Submit async close operation
 */
int io_uring_async_close(io_uring_wrapper_t *uring, async_connection_t *conn) {
    if (!uring || !conn) return -1;

    struct io_uring_sqe *sqe = io_uring_get_sqe(&uring->ring);
    if (!sqe) {
        log_msg(LGG_WARNING, "io_uring SQE exhausted");
        return -1;
    }

    io_uring_prep_close(sqe, conn->fd);
    sqe->user_data = (uint64_t)conn;

    uring->ops_submitted++;
    return 0;
}

/**
 * Wait for completed I/O operations and call handler
 */
int io_uring_async_wait(io_uring_wrapper_t *uring, int timeout_ms, io_completion_handler_t handler) {
    if (!uring || !handler) return -1;

    /* Submit all pending operations */
    int ret = io_uring_submit(&uring->ring);
    if (ret < 0) {
        log_msg(LGG_ERR, "io_uring_submit failed: %d", ret);
        return ret;
    }

    /* Wait for completions */
    struct io_uring_cqe *cqe;
    unsigned head;
    int processed = 0;

    io_uring_for_each_cqe(&uring->ring, head, cqe) {
        async_connection_t *conn = (async_connection_t *)cqe->user_data;
        if (conn) {
            int result = cqe->res;
            handler(uring, conn, result);
            processed++;
        }
        uring->ops_completed++;
    }

    io_uring_cq_advance(&uring->ring, processed);

    return processed;
}

/**
 * Print io_uring statistics
 */
void io_uring_async_stats(io_uring_wrapper_t *uring) {
    if (!uring) return;

    log_msg(LGG_INFO, "io_uring stats: submitted=%lu completed=%lu queue_depth=%u",
            uring->ops_submitted, uring->ops_completed, uring->queue_depth);
}
