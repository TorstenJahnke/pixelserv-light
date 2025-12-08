/*
 * io_engine.c - Unified I/O Multiplexing Implementation
 * Supports: epoll (Linux), io_uring (Linux 5.1+), kqueue (BSD)
 */

#include "net/io_engine.h"
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <fcntl.h>
#include <signal.h>

/* ========== Platform-Specific Includes ========== */

#ifdef IO_ENGINE_EPOLL
  #include <sys/epoll.h>

#elif defined(IO_ENGINE_URING)
  #include <liburing.h>
  #include <sys/epoll.h>  /* Needed for epoll fallback */

#elif defined(IO_ENGINE_KQUEUE)
  #include <sys/event.h>
  #include <sys/time.h>
#endif

/* ========== Engine Structure ========== */

struct io_engine {
    int max_events;
    int max_fds;
    char backend_name[32];

#ifdef IO_ENGINE_EPOLL
    int epoll_fd;

#elif defined(IO_ENGINE_URING)
    struct io_uring ring;
    int using_uring;  /* 1 = io_uring, 0 = fallback to epoll */
    int epoll_fd;     /* Fallback for older kernels */

#elif defined(IO_ENGINE_KQUEUE)
    int kq_fd;
    struct kevent *events;
#endif
};

/* ========== EPOLL Backend ========== */

#ifdef IO_ENGINE_EPOLL

io_engine_t* io_engine_create(int max_events, int max_fds) {
    io_engine_t *engine = malloc(sizeof(io_engine_t));
    if (!engine) return NULL;

    engine->max_events = max_events > 0 ? max_events : 1024;
    engine->max_fds = max_fds;
    engine->epoll_fd = epoll_create1(EPOLL_CLOEXEC);

    if (engine->epoll_fd < 0) {
        free(engine);
        return NULL;
    }

    snprintf(engine->backend_name, sizeof(engine->backend_name), "epoll");
    return engine;
}

void io_engine_destroy(io_engine_t *engine) {
    if (!engine) return;
    if (engine->epoll_fd >= 0) close(engine->epoll_fd);
    free(engine);
}

int io_engine_add(io_engine_t *engine, const io_event_t *event) {
    struct epoll_event ep_event = {
        .events = event->events,
        .data = {.u64 = event->user_data}
    };
    return epoll_ctl(engine->epoll_fd, EPOLL_CTL_ADD, event->fd, &ep_event);
}

int io_engine_mod(io_engine_t *engine, const io_event_t *event) {
    struct epoll_event ep_event = {
        .events = event->events,
        .data = {.u64 = event->user_data}
    };
    return epoll_ctl(engine->epoll_fd, EPOLL_CTL_MOD, event->fd, &ep_event);
}

int io_engine_del(io_engine_t *engine, int fd) {
    return epoll_ctl(engine->epoll_fd, EPOLL_CTL_DEL, fd, NULL);
}

int io_engine_wait(io_engine_t *engine, io_result_t *results, int timeout_ms) {
    struct epoll_event *events = malloc(engine->max_events * sizeof(struct epoll_event));
    if (!events) return -1;

    int nfds = epoll_wait(engine->epoll_fd, events, engine->max_events, timeout_ms);

    if (nfds > 0) {
        for (int i = 0; i < nfds; i++) {
            results[i].fd = events[i].data.fd;
            results[i].events = events[i].events;
            results[i].user_data = events[i].data.u64;
        }
    }

    free(events);
    return nfds >= 0 ? nfds : -1;
}

const char* io_engine_backend(const io_engine_t *engine) {
    return engine ? engine->backend_name : "unknown";
}

#endif /* IO_ENGINE_EPOLL */

/* ========== IO_URING Backend ========== */

#ifdef IO_ENGINE_URING

static int detect_uring_support(void) {
    /* Simple detection: try to create ring, if it fails, io_uring not available */
    struct io_uring ring;
    int ret = io_uring_queue_init(16, &ring, 0);
    if (ret == 0) {
        io_uring_queue_exit(&ring);
        return 1;
    }
    return 0;
}

io_engine_t* io_engine_create(int max_events, int max_fds) {
    io_engine_t *engine = malloc(sizeof(io_engine_t));
    if (!engine) return NULL;

    engine->max_events = max_events > 0 ? max_events : 1024;
    engine->max_fds = max_fds;
    engine->using_uring = 0;
    engine->epoll_fd = -1;

    /* Try io_uring first (Linux 5.1+) */
    if (detect_uring_support()) {
        int ret = io_uring_queue_init(engine->max_events, &engine->ring, 0);
        if (ret == 0) {
            engine->using_uring = 1;
            snprintf(engine->backend_name, sizeof(engine->backend_name), "io_uring");
            return engine;
        }
    }

    /* Fallback to epoll if io_uring not available */
    engine->epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    if (engine->epoll_fd < 0) {
        free(engine);
        return NULL;
    }

    snprintf(engine->backend_name, sizeof(engine->backend_name), "epoll (fallback)");
    return engine;
}

void io_engine_destroy(io_engine_t *engine) {
    if (!engine) return;

    if (engine->using_uring) {
        io_uring_queue_exit(&engine->ring);
    } else if (engine->epoll_fd >= 0) {
        close(engine->epoll_fd);
    }
    free(engine);
}

int io_engine_add(io_engine_t *engine, const io_event_t *event) {
    if (engine->using_uring) {
        struct io_uring_sqe *sqe = io_uring_get_sqe(&engine->ring);
        if (!sqe) return -1;

        io_uring_prep_poll_add(sqe, event->fd, event->events);
        sqe->user_data = event->user_data;
        io_uring_submit(&engine->ring);
        return 0;
    } else {
        struct epoll_event ep_event = {
            .events = event->events,
            .data = {.u64 = event->user_data}
        };
        return epoll_ctl(engine->epoll_fd, EPOLL_CTL_ADD, event->fd, &ep_event);
    }
}

int io_engine_mod(io_engine_t *engine, const io_event_t *event) {
    if (engine->using_uring) {
        /* io_uring doesn't have modify, remove + re-add */
        struct io_uring_sqe *sqe = io_uring_get_sqe(&engine->ring);
        if (!sqe) return -1;
        io_uring_prep_poll_remove(sqe, event->fd);
        io_uring_submit(&engine->ring);
        return io_engine_add(engine, event);
    } else {
        struct epoll_event ep_event = {
            .events = event->events,
            .data = {.u64 = event->user_data}
        };
        return epoll_ctl(engine->epoll_fd, EPOLL_CTL_MOD, event->fd, &ep_event);
    }
}

int io_engine_del(io_engine_t *engine, int fd) {
    if (engine->using_uring) {
        struct io_uring_sqe *sqe = io_uring_get_sqe(&engine->ring);
        if (!sqe) return -1;
        io_uring_prep_poll_remove(sqe, fd);
        io_uring_submit(&engine->ring);
        return 0;
    } else {
        return epoll_ctl(engine->epoll_fd, EPOLL_CTL_DEL, fd, NULL);
    }
}

int io_engine_wait(io_engine_t *engine, io_result_t *results, int timeout_ms) {
    if (engine->using_uring) {
        struct __kernel_timespec ts = {0, 0};
        if (timeout_ms > 0) {
            ts.tv_sec = timeout_ms / 1000;
            ts.tv_nsec = (timeout_ms % 1000) * 1000000;
        }

        int ret = io_uring_wait_cqe_timeout(&engine->ring, NULL, timeout_ms >= 0 ? &ts : NULL);
        if (ret < 0 && ret != -ETIME) return -1;

        int nfds = 0;
        unsigned head;
        struct io_uring_cqe *cqe;
        io_uring_for_each_cqe(&engine->ring, head, cqe) {
            if (nfds >= engine->max_events) break;
            results[nfds].user_data = cqe->user_data;
            results[nfds].events = cqe->res;
            nfds++;
        }

        io_uring_cq_advance(&engine->ring, nfds);
        return nfds;
    } else {
        struct epoll_event *events = malloc(engine->max_events * sizeof(struct epoll_event));
        if (!events) return -1;

        int nfds = epoll_wait(engine->epoll_fd, events, engine->max_events, timeout_ms);

        if (nfds > 0) {
            for (int i = 0; i < nfds; i++) {
                results[i].fd = events[i].data.fd;
                results[i].events = events[i].events;
                results[i].user_data = events[i].data.u64;
            }
        }

        free(events);
        return nfds >= 0 ? nfds : -1;
    }
}

const char* io_engine_backend(const io_engine_t *engine) {
    return engine ? engine->backend_name : "unknown";
}

#endif /* IO_ENGINE_URING */

/* ========== KQUEUE Backend ========== */

#ifdef IO_ENGINE_KQUEUE

io_engine_t* io_engine_create(int max_events, int max_fds) {
    io_engine_t *engine = malloc(sizeof(io_engine_t));
    if (!engine) return NULL;

    engine->max_events = max_events > 0 ? max_events : 1024;
    engine->max_fds = max_fds;
    engine->kq_fd = kqueue();

    if (engine->kq_fd < 0) {
        free(engine);
        return NULL;
    }

    engine->events = malloc(engine->max_events * sizeof(struct kevent));
    if (!engine->events) {
        close(engine->kq_fd);
        free(engine);
        return NULL;
    }

    snprintf(engine->backend_name, sizeof(engine->backend_name), "kqueue");
    return engine;
}

void io_engine_destroy(io_engine_t *engine) {
    if (!engine) return;
    if (engine->kq_fd >= 0) close(engine->kq_fd);
    if (engine->events) free(engine->events);
    free(engine);
}

int io_engine_add(io_engine_t *engine, const io_event_t *event) {
    struct kevent ke[2];
    int nev = 0;

    if (event->events & IO_IN) {
        EV_SET(&ke[nev++], event->fd, EVFILT_READ, EV_ADD, 0, 0, (void*)event->user_data);
    }
    if (event->events & IO_OUT) {
        EV_SET(&ke[nev++], event->fd, EVFILT_WRITE, EV_ADD, 0, 0, (void*)event->user_data);
    }

    if (nev > 0) {
        return kevent(engine->kq_fd, ke, nev, NULL, 0, NULL) < 0 ? -1 : 0;
    }
    return 0;
}

int io_engine_mod(io_engine_t *engine, const io_event_t *event) {
    /* kqueue: delete old, add new */
    io_engine_del(engine, event->fd);
    return io_engine_add(engine, event);
}

int io_engine_del(io_engine_t *engine, int fd) {
    struct kevent ke[2];
    EV_SET(&ke[0], fd, EVFILT_READ, EV_DELETE, 0, 0, NULL);
    EV_SET(&ke[1], fd, EVFILT_WRITE, EV_DELETE, 0, 0, NULL);

    return kevent(engine->kq_fd, ke, 2, NULL, 0, NULL) < 0 ? -1 : 0;
}

int io_engine_wait(io_engine_t *engine, io_result_t *results, int timeout_ms) {
    struct timespec ts = {0, 0};
    struct timespec *ts_ptr = NULL;

    if (timeout_ms >= 0) {
        ts.tv_sec = timeout_ms / 1000;
        ts.tv_nsec = (timeout_ms % 1000) * 1000000;
        ts_ptr = &ts;
    }

    int nev = kevent(engine->kq_fd, NULL, 0, engine->events, engine->max_events, ts_ptr);

    if (nev > 0) {
        for (int i = 0; i < nev; i++) {
            results[i].fd = engine->events[i].ident;
            results[i].user_data = (uint64_t)engine->events[i].udata;

            if (engine->events[i].filter == EVFILT_READ) {
                results[i].events = IO_IN;
            } else if (engine->events[i].filter == EVFILT_WRITE) {
                results[i].events = IO_OUT;
            }

            if (engine->events[i].flags & EV_ERROR) {
                results[i].events |= IO_ERR;
            }
            if (engine->events[i].flags & EV_EOF) {
                results[i].events |= IO_HUP;
            }
        }
    }

    return nev < 0 ? -1 : nev;
}

const char* io_engine_backend(const io_engine_t *engine) {
    return engine ? engine->backend_name : "unknown";
}

#endif /* IO_ENGINE_KQUEUE */
