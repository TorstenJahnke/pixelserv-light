/* _GNU_SOURCE is defined by Makefile on Linux */
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "eventloop.h"
#include "logger.h"

/* =============================================================================
 * BACKEND DETECTION
 * ============================================================================= */

/* io_uring (Linux 5.1+) */
#if defined(__linux__) && defined(HAVE_IO_URING)
#  include <liburing.h>
#  include <poll.h>  /* POLLIN, POLLOUT, etc. */
#  define EVL_HAS_IO_URING 1
#else
#  define EVL_HAS_IO_URING 0
#endif

/* epoll (Linux) */
#if defined(__linux__)
#  include <sys/epoll.h>
#  define EVL_HAS_EPOLL 1
#else
#  define EVL_HAS_EPOLL 0
#endif

/* kqueue (BSD/macOS) */
#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
#  include <sys/types.h>
#  include <sys/event.h>
#  include <sys/time.h>
#  define EVL_HAS_KQUEUE 1
#else
#  define EVL_HAS_KQUEUE 0
#endif

/* =============================================================================
 * EVENT LOOP STRUCTURE
 * ============================================================================= */

struct evl_loop {
    evl_backend_t backend;
    int max_events;

    union {
#if EVL_HAS_IO_URING
        struct {
            struct io_uring ring;
            int ring_fd;
        } uring;
#endif
#if EVL_HAS_EPOLL
        struct {
            int epfd;
        } epoll;
#endif
#if EVL_HAS_KQUEUE
        struct {
            int kqfd;
        } kqueue;
#endif
        int dummy;  /* Ensure union is never empty */
    } u;
};

/* =============================================================================
 * BACKEND AVAILABILITY CHECKS
 * ============================================================================= */

int evl_has_io_uring(void) {
#if EVL_HAS_IO_URING
    return 1;
#else
    return 0;
#endif
}

int evl_has_epoll(void) {
#if EVL_HAS_EPOLL
    return 1;
#else
    return 0;
#endif
}

int evl_has_kqueue(void) {
#if EVL_HAS_KQUEUE
    return 1;
#else
    return 0;
#endif
}

const char *evl_backend_name(evl_backend_t backend) {
    switch (backend) {
        case EVL_BACKEND_IO_URING: return "io_uring";
        case EVL_BACKEND_EPOLL:    return "epoll";
        case EVL_BACKEND_KQUEUE:   return "kqueue";
        default:                   return "none";
    }
}

evl_backend_t evl_get_backend(evl_loop_t *loop) {
    return loop ? loop->backend : EVL_BACKEND_NONE;
}

/* =============================================================================
 * IO_URING BACKEND (Linux 5.1+)
 * ============================================================================= */

#if EVL_HAS_IO_URING

static evl_loop_t *evl_create_io_uring(int max_events) {
    evl_loop_t *loop = calloc(1, sizeof(evl_loop_t));
    if (!loop) return NULL;

    struct io_uring_params params;
    memset(&params, 0, sizeof(params));

    /* Use SQPOLL for kernel-side polling (reduces syscalls) */
    /* params.flags = IORING_SETUP_SQPOLL; */

    if (io_uring_queue_init_params(max_events * 2, &loop->u.uring.ring, &params) < 0) {
        free(loop);
        return NULL;
    }

    loop->backend = EVL_BACKEND_IO_URING;
    loop->max_events = max_events;
    loop->u.uring.ring_fd = loop->u.uring.ring.ring_fd;

    log_msg(LGG_NOTICE, "Event loop: io_uring initialized (kernel %d.%d features)",
            params.sq_entries, params.cq_entries);
    return loop;
}

static void evl_destroy_io_uring(evl_loop_t *loop) {
    io_uring_queue_exit(&loop->u.uring.ring);
}

static int evl_add_io_uring(evl_loop_t *loop, int fd, uint32_t events, void *data) {
    struct io_uring_sqe *sqe = io_uring_get_sqe(&loop->u.uring.ring);
    if (!sqe) return -1;

    /* For accept loop, we use poll */
    unsigned poll_mask = 0;
    if (events & EVL_READ)  poll_mask |= POLLIN;
    if (events & EVL_WRITE) poll_mask |= POLLOUT;

    io_uring_prep_poll_add(sqe, fd, poll_mask);
    io_uring_sqe_set_data(sqe, data);

    return io_uring_submit(&loop->u.uring.ring) >= 0 ? 0 : -1;
}

static int evl_mod_io_uring(evl_loop_t *loop, int fd, uint32_t events, void *data) {
    /* io_uring: cancel old and add new */
    struct io_uring_sqe *sqe = io_uring_get_sqe(&loop->u.uring.ring);
    if (!sqe) return -1;

    io_uring_prep_poll_remove(sqe, (__u64)(uintptr_t)fd);
    io_uring_submit(&loop->u.uring.ring);

    return evl_add_io_uring(loop, fd, events, data);
}

static int evl_del_io_uring(evl_loop_t *loop, int fd) {
    struct io_uring_sqe *sqe = io_uring_get_sqe(&loop->u.uring.ring);
    if (!sqe) return -1;

    io_uring_prep_poll_remove(sqe, (__u64)(uintptr_t)fd);
    return io_uring_submit(&loop->u.uring.ring) >= 0 ? 0 : -1;
}

static int evl_wait_io_uring(evl_loop_t *loop, evl_event_t *events, int max_events, int timeout_ms) {
    struct io_uring_cqe *cqe;
    struct __kernel_timespec ts;
    int count = 0;

    if (timeout_ms >= 0) {
        ts.tv_sec = timeout_ms / 1000;
        ts.tv_nsec = (timeout_ms % 1000) * 1000000;
    }

    for (int i = 0; i < max_events; i++) {
        int ret;
        if (timeout_ms < 0) {
            ret = io_uring_wait_cqe(&loop->u.uring.ring, &cqe);
        } else if (i == 0) {
            ret = io_uring_wait_cqe_timeout(&loop->u.uring.ring, &cqe, &ts);
        } else {
            ret = io_uring_peek_cqe(&loop->u.uring.ring, &cqe);
        }

        if (ret < 0) {
            if (ret == -ETIME || ret == -EAGAIN) break;
            if (ret == -EINTR) continue;
            return -1;
        }

        events[count].data = io_uring_cqe_get_data(cqe);
        events[count].events = 0;
        if (cqe->res & POLLIN)  events[count].events |= EVL_READ;
        if (cqe->res & POLLOUT) events[count].events |= EVL_WRITE;
        if (cqe->res & POLLERR) events[count].events |= EVL_ERROR;
        if (cqe->res & POLLHUP) events[count].events |= EVL_HANGUP;
        events[count].fd = -1;  /* fd not directly available, use data */

        io_uring_cqe_seen(&loop->u.uring.ring, cqe);
        count++;
    }

    return count;
}

#endif /* EVL_HAS_IO_URING */

/* =============================================================================
 * EPOLL BACKEND (Linux)
 * ============================================================================= */

#if EVL_HAS_EPOLL

static evl_loop_t *evl_create_epoll(int max_events) {
    evl_loop_t *loop = calloc(1, sizeof(evl_loop_t));
    if (!loop) return NULL;

    loop->u.epoll.epfd = epoll_create1(EPOLL_CLOEXEC);
    if (loop->u.epoll.epfd < 0) {
        free(loop);
        return NULL;
    }

    loop->backend = EVL_BACKEND_EPOLL;
    loop->max_events = max_events;

    log_msg(LGG_NOTICE, "Event loop: epoll initialized (fd=%d)", loop->u.epoll.epfd);
    return loop;
}

static void evl_destroy_epoll(evl_loop_t *loop) {
    close(loop->u.epoll.epfd);
}

static int evl_add_epoll(evl_loop_t *loop, int fd, uint32_t events, void *data) {
    struct epoll_event ev;
    ev.events = EPOLLET;  /* Edge-triggered for high performance */
    if (events & EVL_READ)  ev.events |= EPOLLIN;
    if (events & EVL_WRITE) ev.events |= EPOLLOUT;
    ev.data.ptr = data;

    return epoll_ctl(loop->u.epoll.epfd, EPOLL_CTL_ADD, fd, &ev);
}

static int evl_mod_epoll(evl_loop_t *loop, int fd, uint32_t events, void *data) {
    struct epoll_event ev;
    ev.events = EPOLLET;
    if (events & EVL_READ)  ev.events |= EPOLLIN;
    if (events & EVL_WRITE) ev.events |= EPOLLOUT;
    ev.data.ptr = data;

    return epoll_ctl(loop->u.epoll.epfd, EPOLL_CTL_MOD, fd, &ev);
}

static int evl_del_epoll(evl_loop_t *loop, int fd) {
    return epoll_ctl(loop->u.epoll.epfd, EPOLL_CTL_DEL, fd, NULL);
}

static int evl_wait_epoll(evl_loop_t *loop, evl_event_t *events, int max_events, int timeout_ms) {
    struct epoll_event *ep_events = alloca(max_events * sizeof(struct epoll_event));

    int n = epoll_wait(loop->u.epoll.epfd, ep_events, max_events, timeout_ms);
    if (n < 0) {
        if (errno == EINTR) return 0;
        return -1;
    }

    for (int i = 0; i < n; i++) {
        events[i].data = ep_events[i].data.ptr;
        events[i].fd = -1;  /* fd stored in data.ptr typically */
        events[i].events = 0;
        if (ep_events[i].events & EPOLLIN)  events[i].events |= EVL_READ;
        if (ep_events[i].events & EPOLLOUT) events[i].events |= EVL_WRITE;
        if (ep_events[i].events & EPOLLERR) events[i].events |= EVL_ERROR;
        if (ep_events[i].events & EPOLLHUP) events[i].events |= EVL_HANGUP;
    }

    return n;
}

#endif /* EVL_HAS_EPOLL */

/* =============================================================================
 * KQUEUE BACKEND (BSD/macOS)
 * ============================================================================= */

#if EVL_HAS_KQUEUE

static evl_loop_t *evl_create_kqueue(int max_events) {
    evl_loop_t *loop = calloc(1, sizeof(evl_loop_t));
    if (!loop) return NULL;

    loop->u.kqueue.kqfd = kqueue();
    if (loop->u.kqueue.kqfd < 0) {
        free(loop);
        return NULL;
    }

    /* Set close-on-exec */
    fcntl(loop->u.kqueue.kqfd, F_SETFD, FD_CLOEXEC);

    loop->backend = EVL_BACKEND_KQUEUE;
    loop->max_events = max_events;

    log_msg(LGG_NOTICE, "Event loop: kqueue initialized (fd=%d)", loop->u.kqueue.kqfd);
    return loop;
}

static void evl_destroy_kqueue(evl_loop_t *loop) {
    close(loop->u.kqueue.kqfd);
}

static int evl_add_kqueue(evl_loop_t *loop, int fd, uint32_t events, void *data) {
    struct kevent kev[2];
    int n = 0;

    if (events & EVL_READ) {
        EV_SET(&kev[n], fd, EVFILT_READ, EV_ADD | EV_CLEAR, 0, 0, data);
        n++;
    }
    if (events & EVL_WRITE) {
        EV_SET(&kev[n], fd, EVFILT_WRITE, EV_ADD | EV_CLEAR, 0, 0, data);
        n++;
    }

    return kevent(loop->u.kqueue.kqfd, kev, n, NULL, 0, NULL);
}

static int evl_mod_kqueue(evl_loop_t *loop, int fd, uint32_t events, void *data) {
    /* kqueue: delete old filters and add new ones */
    struct kevent kev[4];
    int n = 0;

    /* Delete existing */
    EV_SET(&kev[n++], fd, EVFILT_READ, EV_DELETE, 0, 0, NULL);
    EV_SET(&kev[n++], fd, EVFILT_WRITE, EV_DELETE, 0, 0, NULL);

    /* Add new */
    if (events & EVL_READ) {
        EV_SET(&kev[n++], fd, EVFILT_READ, EV_ADD | EV_CLEAR, 0, 0, data);
    }
    if (events & EVL_WRITE) {
        EV_SET(&kev[n++], fd, EVFILT_WRITE, EV_ADD | EV_CLEAR, 0, 0, data);
    }

    /* Ignore errors from deleting non-existent filters */
    kevent(loop->u.kqueue.kqfd, kev, n, NULL, 0, NULL);
    return 0;
}

static int evl_del_kqueue(evl_loop_t *loop, int fd) {
    struct kevent kev[2];
    EV_SET(&kev[0], fd, EVFILT_READ, EV_DELETE, 0, 0, NULL);
    EV_SET(&kev[1], fd, EVFILT_WRITE, EV_DELETE, 0, 0, NULL);

    /* Ignore errors - filter might not exist */
    kevent(loop->u.kqueue.kqfd, kev, 2, NULL, 0, NULL);
    return 0;
}

static int evl_wait_kqueue(evl_loop_t *loop, evl_event_t *events, int max_events, int timeout_ms) {
    struct kevent *kev_events = alloca(max_events * sizeof(struct kevent));
    struct timespec ts, *pts = NULL;

    if (timeout_ms >= 0) {
        ts.tv_sec = timeout_ms / 1000;
        ts.tv_nsec = (timeout_ms % 1000) * 1000000;
        pts = &ts;
    }

    int n = kevent(loop->u.kqueue.kqfd, NULL, 0, kev_events, max_events, pts);
    if (n < 0) {
        if (errno == EINTR) return 0;
        return -1;
    }

    for (int i = 0; i < n; i++) {
        events[i].fd = (int)kev_events[i].ident;
        events[i].data = kev_events[i].udata;
        events[i].events = 0;

        if (kev_events[i].filter == EVFILT_READ)  events[i].events |= EVL_READ;
        if (kev_events[i].filter == EVFILT_WRITE) events[i].events |= EVL_WRITE;
        if (kev_events[i].flags & EV_ERROR)       events[i].events |= EVL_ERROR;
        if (kev_events[i].flags & EV_EOF)         events[i].events |= EVL_HANGUP;
    }

    return n;
}

#endif /* EVL_HAS_KQUEUE */

/* =============================================================================
 * PUBLIC API - DISPATCHER
 * ============================================================================= */

evl_loop_t *evl_create(int max_events) {
    evl_loop_t *loop = NULL;

    /* Try backends in order of preference */
#if EVL_HAS_IO_URING
    loop = evl_create_io_uring(max_events);
    if (loop) return loop;
    log_msg(LGG_WARNING, "io_uring initialization failed, trying epoll...");
#endif

#if EVL_HAS_EPOLL
    loop = evl_create_epoll(max_events);
    if (loop) return loop;
    log_msg(LGG_WARNING, "epoll initialization failed, trying kqueue...");
#endif

#if EVL_HAS_KQUEUE
    loop = evl_create_kqueue(max_events);
    if (loop) return loop;
    log_msg(LGG_WARNING, "kqueue initialization failed");
#endif

    log_msg(LGG_CRIT, "No event loop backend available! Server cannot run.");
    return NULL;
}

void evl_destroy(evl_loop_t *loop) {
    if (!loop) return;

    switch (loop->backend) {
#if EVL_HAS_IO_URING
        case EVL_BACKEND_IO_URING:
            evl_destroy_io_uring(loop);
            break;
#endif
#if EVL_HAS_EPOLL
        case EVL_BACKEND_EPOLL:
            evl_destroy_epoll(loop);
            break;
#endif
#if EVL_HAS_KQUEUE
        case EVL_BACKEND_KQUEUE:
            evl_destroy_kqueue(loop);
            break;
#endif
        default:
            break;
    }
    free(loop);
}

int evl_add(evl_loop_t *loop, int fd, uint32_t events, void *data) {
    if (!loop) return -1;

    switch (loop->backend) {
#if EVL_HAS_IO_URING
        case EVL_BACKEND_IO_URING:
            return evl_add_io_uring(loop, fd, events, data);
#endif
#if EVL_HAS_EPOLL
        case EVL_BACKEND_EPOLL:
            return evl_add_epoll(loop, fd, events, data);
#endif
#if EVL_HAS_KQUEUE
        case EVL_BACKEND_KQUEUE:
            return evl_add_kqueue(loop, fd, events, data);
#endif
        default:
            return -1;
    }
}

int evl_mod(evl_loop_t *loop, int fd, uint32_t events, void *data) {
    if (!loop) return -1;

    switch (loop->backend) {
#if EVL_HAS_IO_URING
        case EVL_BACKEND_IO_URING:
            return evl_mod_io_uring(loop, fd, events, data);
#endif
#if EVL_HAS_EPOLL
        case EVL_BACKEND_EPOLL:
            return evl_mod_epoll(loop, fd, events, data);
#endif
#if EVL_HAS_KQUEUE
        case EVL_BACKEND_KQUEUE:
            return evl_mod_kqueue(loop, fd, events, data);
#endif
        default:
            return -1;
    }
}

int evl_del(evl_loop_t *loop, int fd) {
    if (!loop) return -1;

    switch (loop->backend) {
#if EVL_HAS_IO_URING
        case EVL_BACKEND_IO_URING:
            return evl_del_io_uring(loop, fd);
#endif
#if EVL_HAS_EPOLL
        case EVL_BACKEND_EPOLL:
            return evl_del_epoll(loop, fd);
#endif
#if EVL_HAS_KQUEUE
        case EVL_BACKEND_KQUEUE:
            return evl_del_kqueue(loop, fd);
#endif
        default:
            return -1;
    }
}

int evl_wait(evl_loop_t *loop, evl_event_t *events, int max_events, int timeout_ms) {
    if (!loop || !events) return -1;

    switch (loop->backend) {
#if EVL_HAS_IO_URING
        case EVL_BACKEND_IO_URING:
            return evl_wait_io_uring(loop, events, max_events, timeout_ms);
#endif
#if EVL_HAS_EPOLL
        case EVL_BACKEND_EPOLL:
            return evl_wait_epoll(loop, events, max_events, timeout_ms);
#endif
#if EVL_HAS_KQUEUE
        case EVL_BACKEND_KQUEUE:
            return evl_wait_kqueue(loop, events, max_events, timeout_ms);
#endif
        default:
            return -1;
    }
}
