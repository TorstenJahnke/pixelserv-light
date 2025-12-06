#ifndef EVENT_LOOP_H
#define EVENT_LOOP_H

#include <stdint.h>
#include <sys/types.h>

/**
 * ABSTRACT EVENT LOOP INTERFACE
 *
 * Portable abstraction for:
 * - Linux: io_uring (kernel async I/O, batch submissions)
 * - FreeBSD: kqueue (BSD-style event notification)
 *
 * All implementations must provide identical behavior:
 * - Non-blocking submit operations
 * - Completion-based notifications
 * - Per-connection state tracking
 */

/* Forward declarations */
typedef struct event_loop event_loop_t;
typedef struct async_connection async_connection_t;

/**
 * Initialize event loop
 * @param queue_depth: max pending operations (ignored on kqueue)
 * @return: event loop instance or NULL on failure
 */
event_loop_t *event_loop_init(unsigned int queue_depth);

/**
 * Destroy event loop
 */
void event_loop_destroy(event_loop_t *loop);

/**
 * Submit async accept() operation
 * @param loop: event loop instance
 * @param listen_fd: listening socket file descriptor
 * @param conn: connection object to associate with this operation
 * @return: 0 on success, -1 on failure (queue exhausted, etc)
 */
int event_loop_accept(event_loop_t *loop, int listen_fd, async_connection_t *conn);

/**
 * Submit async read() operation
 * @param loop: event loop instance
 * @param conn: connection object
 * @param buf: read buffer
 * @param len: buffer size
 * @return: 0 on success, -1 on failure
 */
int event_loop_read(event_loop_t *loop, async_connection_t *conn, char *buf, size_t len);

/**
 * Submit async write() operation
 * @param loop: event loop instance
 * @param conn: connection object
 * @param buf: write buffer
 * @param len: buffer size
 * @return: 0 on success, -1 on failure
 */
int event_loop_write(event_loop_t *loop, async_connection_t *conn, const char *buf, size_t len);

/**
 * Submit async poll() operation (for keep-alive timeouts)
 * @param loop: event loop instance
 * @param conn: connection object
 * @param timeout_ms: timeout in milliseconds
 * @return: 0 on success, -1 on failure
 */
int event_loop_poll(event_loop_t *loop, async_connection_t *conn, int timeout_ms);

/**
 * Submit async close() operation
 * @param loop: event loop instance
 * @param conn: connection object
 * @return: 0 on success, -1 on failure
 */
int event_loop_close(event_loop_t *loop, async_connection_t *conn);

/**
 * Completion handler callback type
 * Called for each completed I/O operation
 * @param loop: event loop instance
 * @param conn: connection that completed
 * @param result: operation result (bytes for read/write, return code for others)
 * @return: 0 to continue, -1 to close connection
 */
typedef int (*event_completion_handler_t)(event_loop_t *loop, async_connection_t *conn, int result);

/**
 * Wait for I/O completions and invoke handlers
 * @param loop: event loop instance
 * @param timeout_ms: timeout in milliseconds (-1 = block forever)
 * @param handler: callback for each completion
 * @return: number of completions processed, -1 on error
 */
int event_loop_wait(event_loop_t *loop, int timeout_ms, event_completion_handler_t handler);

/**
 * Print event loop statistics
 */
void event_loop_stats(event_loop_t *loop);

#endif // EVENT_LOOP_H
