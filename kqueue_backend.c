#include "event_loop.h"
#include "async_connection.h"
#include "logger.h"
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/event.h>
#include <sys/time.h>
#include <errno.h>

/**
 * kqueue backend implementation of abstract event_loop interface
 * FreeBSD/macOS event notification system
 */

#define MAX_EVENTS 512

typedef enum {
    OP_ACCEPT,
    OP_READ,
    OP_WRITE,
    OP_POLL,
    OP_CLOSE
} op_type_t;

typedef struct {
    op_type_t type;
    async_connection_t *conn;
    char *buf;
    size_t len;
} pending_op_t;

struct event_loop {
    int kq;
    pending_op_t pending[MAX_EVENTS];
    int pending_count;
    uint64_t ops_submitted;
    uint64_t ops_completed;
    struct kevent *events;
    int initialized;
};

/**
 * Initialize kqueue event loop
 */
event_loop_t *event_loop_init(unsigned int queue_depth) {
    event_loop_t *loop = malloc(sizeof(event_loop_t));
    if (!loop) {
        log_msg(LGG_ERR, "Failed to allocate event loop");
        return NULL;
    }

    memset(loop, 0, sizeof(event_loop_t));

    /* Create kqueue */
    loop->kq = kqueue();
    if (loop->kq < 0) {
        log_msg(LGG_ERR, "Failed to create kqueue: %s", strerror(errno));
        free(loop);
        return NULL;
    }

    /* Allocate event buffer */
    loop->events = malloc(sizeof(struct kevent) * MAX_EVENTS);
    if (!loop->events) {
        log_msg(LGG_ERR, "Failed to allocate event buffer");
        close(loop->kq);
        free(loop);
        return NULL;
    }

    loop->initialized = 1;
    log_msg(LGG_NOTICE, "kqueue initialized");

    return loop;
}

/**
 * Destroy kqueue event loop
 */
void event_loop_destroy(event_loop_t *loop) {
    if (!loop) return;

    if (loop->kq >= 0) {
        close(loop->kq);
    }
    free(loop->events);
    free(loop);
}

/**
 * Submit async accept
 * kqueue doesn't support accept operations natively
 * We use READ on the listening socket instead
 */
int event_loop_accept(event_loop_t *loop, int listen_fd, async_connection_t *conn) {
    if (!loop || !conn) return -1;

    struct kevent kev;
    EV_SET(&kev, listen_fd, EVFILT_READ, EV_ADD | EV_ENABLE, 0, 0, (uintptr_t)conn);

    if (kevent(loop->kq, &kev, 1, NULL, 0, NULL) < 0) {
        log_msg(LGG_WARNING, "Failed to register accept on fd %d: %s", listen_fd, strerror(errno));
        return -1;
    }

    loop->ops_submitted++;
    return 0;
}

/**
 * Submit async read
 */
int event_loop_read(event_loop_t *loop, async_connection_t *conn, char *buf, size_t len) {
    if (!loop || !conn || !buf) return -1;

    struct kevent kev;
    EV_SET(&kev, conn->fd, EVFILT_READ, EV_ADD | EV_ENABLE, 0, 0, (uintptr_t)conn);

    if (kevent(loop->kq, &kev, 1, NULL, 0, NULL) < 0) {
        log_msg(LGG_WARNING, "Failed to register read on fd %d: %s", conn->fd, strerror(errno));
        return -1;
    }

    /* Store buffer info for later retrieval (kqueue doesn't buffer) */
    if (loop->pending_count < MAX_EVENTS) {
        loop->pending[loop->pending_count].type = OP_READ;
        loop->pending[loop->pending_count].conn = conn;
        loop->pending[loop->pending_count].buf = buf;
        loop->pending[loop->pending_count].len = len;
        loop->pending_count++;
    }

    loop->ops_submitted++;
    return 0;
}

/**
 * Submit async write
 */
int event_loop_write(event_loop_t *loop, async_connection_t *conn, const char *buf, size_t len) {
    if (!loop || !conn || !buf) return -1;

    struct kevent kev;
    EV_SET(&kev, conn->fd, EVFILT_WRITE, EV_ADD | EV_ENABLE, 0, 0, (uintptr_t)conn);

    if (kevent(loop->kq, &kev, 1, NULL, 0, NULL) < 0) {
        log_msg(LGG_WARNING, "Failed to register write on fd %d: %s", conn->fd, strerror(errno));
        return -1;
    }

    /* Store buffer info for later retrieval */
    if (loop->pending_count < MAX_EVENTS) {
        loop->pending[loop->pending_count].type = OP_WRITE;
        loop->pending[loop->pending_count].conn = conn;
        loop->pending[loop->pending_count].buf = (char *)buf;
        loop->pending[loop->pending_count].len = len;
        loop->pending_count++;
    }

    loop->ops_submitted++;
    return 0;
}

/**
 * Submit async poll (timeout monitoring)
 */
int event_loop_poll(event_loop_t *loop, async_connection_t *conn, int timeout_ms) {
    if (!loop || !conn) return -1;

    struct kevent kev;
    struct timespec ts;

    ts.tv_sec = timeout_ms / 1000;
    ts.tv_nsec = (timeout_ms % 1000) * 1000000;

    EV_SET(&kev, conn->fd, EVFILT_READ, EV_ADD | EV_ENABLE, NOTE_TIMEOUT, ts.tv_sec * 1000 + ts.tv_nsec / 1000000, (uintptr_t)conn);

    if (kevent(loop->kq, &kev, 1, NULL, 0, NULL) < 0) {
        log_msg(LGG_WARNING, "Failed to register poll on fd %d: %s", conn->fd, strerror(errno));
        return -1;
    }

    loop->ops_submitted++;
    return 0;
}

/**
 * Submit async close
 */
int event_loop_close(event_loop_t *loop, async_connection_t *conn) {
    if (!loop || !conn) return -1;

    if (conn->fd >= 0) {
        close(conn->fd);
        conn->fd = -1;
    }

    loop->ops_submitted++;
    return 0;
}

/**
 * Wait for completions and invoke handlers
 */
int event_loop_wait(event_loop_t *loop, int timeout_ms, event_completion_handler_t handler) {
    if (!loop || !handler) return -1;

    struct timespec ts, *tsp;

    if (timeout_ms < 0) {
        tsp = NULL;
    } else {
        ts.tv_sec = timeout_ms / 1000;
        ts.tv_nsec = (timeout_ms % 1000) * 1000000;
        tsp = &ts;
    }

    int nev = kevent(loop->kq, NULL, 0, loop->events, MAX_EVENTS, tsp);
    if (nev < 0) {
        log_msg(LGG_ERR, "kevent failed: %s", strerror(errno));
        return -1;
    }

    /* Process each event */
    for (int i = 0; i < nev; i++) {
        struct kevent *kev = &loop->events[i];
        async_connection_t *conn = (async_connection_t *)kev->udata;

        if (conn) {
            int result = 0;

            if (kev->filter == EVFILT_READ) {
                /* For read events, return available bytes */
                result = kev->data > 0 ? kev->data : 1;
            } else if (kev->filter == EVFILT_WRITE) {
                /* For write events, return available space */
                result = kev->data > 0 ? kev->data : 1;
            } else if (kev->flags & EV_EOF) {
                /* Connection closed */
                result = 0;
            }

            /* Handle errors */
            if (kev->flags & EV_ERROR) {
                result = -1;
                log_msg(LGG_WARNING, "kqueue error on fd %d: %s", conn->fd, strerror(kev->data));
            }

            handler(loop, conn, result);
            loop->ops_completed++;
        }
    }

    return nev;
}

/**
 * Print event loop statistics
 */
void event_loop_stats(event_loop_t *loop) {
    if (!loop) return;

    log_msg(LGG_INFO, "kqueue stats: submitted=%lu completed=%lu pending=%d",
            loop->ops_submitted, loop->ops_completed, loop->pending_count);
}
