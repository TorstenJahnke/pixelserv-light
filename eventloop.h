#ifndef EVENTLOOP_H
#define EVENTLOOP_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdint.h>

/* =============================================================================
 * HIGH-PERFORMANCE EVENT LOOP ABSTRACTION
 *
 * Priority order (best to fallback):
 *   1. io_uring (Linux 5.1+) - async I/O, zero-copy, batched syscalls
 *   2. epoll (Linux 2.6+)    - O(1) scalable I/O multiplexing
 *   3. kqueue (BSD/macOS)    - BSD equivalent to epoll
 *
 * No select() fallback - if none of these work, the server won't run.
 * For 10M+ concurrent connections, legacy APIs are not acceptable.
 * ============================================================================= */

/* Event types */
#define EVL_READ   (1 << 0)
#define EVL_WRITE  (1 << 1)
#define EVL_ERROR  (1 << 2)
#define EVL_HANGUP (1 << 3)

/* Event structure returned by evl_wait() */
typedef struct {
    int fd;
    uint32_t events;    /* EVL_READ, EVL_WRITE, etc. */
    void *data;         /* User data pointer */
} evl_event_t;

/* Opaque event loop handle */
typedef struct evl_loop evl_loop_t;

/* Backend type enumeration */
typedef enum {
    EVL_BACKEND_NONE = 0,
    EVL_BACKEND_IO_URING,
    EVL_BACKEND_EPOLL,
    EVL_BACKEND_KQUEUE
} evl_backend_t;

/* =============================================================================
 * API Functions
 * ============================================================================= */

/**
 * Create a new event loop
 * @param max_events Maximum number of events to handle per wait call
 * @return Event loop handle, or NULL on failure
 *
 * Automatically selects best available backend:
 * io_uring > epoll > kqueue
 */
evl_loop_t *evl_create(int max_events);

/**
 * Destroy event loop and free resources
 */
void evl_destroy(evl_loop_t *loop);

/**
 * Get the backend type being used
 */
evl_backend_t evl_get_backend(evl_loop_t *loop);

/**
 * Get backend name as string
 */
const char *evl_backend_name(evl_backend_t backend);

/**
 * Add a file descriptor to the event loop
 * @param loop Event loop handle
 * @param fd File descriptor to monitor
 * @param events Events to monitor (EVL_READ | EVL_WRITE)
 * @param data User data pointer (returned in evl_event_t)
 * @return 0 on success, -1 on error
 */
int evl_add(evl_loop_t *loop, int fd, uint32_t events, void *data);

/**
 * Modify events for a file descriptor
 * @param loop Event loop handle
 * @param fd File descriptor
 * @param events New events to monitor
 * @param data New user data pointer
 * @return 0 on success, -1 on error
 */
int evl_mod(evl_loop_t *loop, int fd, uint32_t events, void *data);

/**
 * Remove a file descriptor from the event loop
 * @param loop Event loop handle
 * @param fd File descriptor to remove
 * @return 0 on success, -1 on error
 */
int evl_del(evl_loop_t *loop, int fd);

/**
 * Wait for events
 * @param loop Event loop handle
 * @param events Array to store returned events
 * @param max_events Maximum events to return
 * @param timeout_ms Timeout in milliseconds (-1 = infinite, 0 = non-blocking)
 * @return Number of events, 0 on timeout, -1 on error
 */
int evl_wait(evl_loop_t *loop, evl_event_t *events, int max_events, int timeout_ms);

/**
 * Check if a specific backend is available at compile time
 */
int evl_has_io_uring(void);
int evl_has_epoll(void);
int evl_has_kqueue(void);

#endif /* EVENTLOOP_H */
