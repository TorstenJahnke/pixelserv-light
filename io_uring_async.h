#ifndef IO_URING_ASYNC_H
#define IO_URING_ASYNC_H

#include <stdint.h>
#include <sys/types.h>
#include "async_connection.h"

/**
 * io_uring Async I/O wrapper
 *
 * Abstracts all I/O operations through io_uring for 10M concurrent users
 * - Zero syscalls for most operations (batched)
 * - Native kernel async support (Linux 5.1+)
 * - Falls back to epoll/kqueue if io_uring not available
 */

typedef struct io_uring_wrapper io_uring_wrapper_t;

/* Initialize io_uring event loop */
io_uring_wrapper_t *io_uring_async_init(unsigned int queue_depth);
void io_uring_async_destroy(io_uring_wrapper_t *uring);

/* Submit operations to io_uring */
int io_uring_async_accept(io_uring_wrapper_t *uring, int listen_fd, async_connection_t *conn);
int io_uring_async_read(io_uring_wrapper_t *uring, async_connection_t *conn, char *buf, size_t len);
int io_uring_async_write(io_uring_wrapper_t *uring, async_connection_t *conn, const char *buf, size_t len);
int io_uring_async_poll(io_uring_wrapper_t *uring, async_connection_t *conn, int timeout_ms);
int io_uring_async_close(io_uring_wrapper_t *uring, async_connection_t *conn);

/* Process completed I/O operations */
typedef int (*io_completion_handler_t)(io_uring_wrapper_t *uring, async_connection_t *conn, int result);

int io_uring_async_wait(io_uring_wrapper_t *uring, int timeout_ms, io_completion_handler_t handler);

/* Stats */
void io_uring_async_stats(io_uring_wrapper_t *uring);

#endif // IO_URING_ASYNC_H
