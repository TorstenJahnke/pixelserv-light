/*
 * io_engine.h - Unified I/O Multiplexing Layer
 *
 * Abstracts epoll (Linux), io_uring (Linux 5.1+), and kqueue (BSD)
 * Provides single interface for all platforms
 *
 * Platform Detection:
 *   - Linux + io_uring support -> use io_uring
 *   - Linux (no io_uring) -> use epoll
 *   - BSD/FreeBSD/OpenBSD/NetBSD -> use kqueue
 *   - Other -> compile error (no legacy support)
 */

#ifndef IO_ENGINE_H
#define IO_ENGINE_H

#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <time.h>
#include <stdint.h>

/* ========== Platform Detection ========== */

#ifdef __linux__
  #define IO_ENGINE_LINUX 1
  /*
   * io_uring requires -luring at link time. Only enable if explicitly
   * configured with HAVE_LIBURING (e.g., via configure --with-uring).
   * Default to epoll which has no extra dependencies.
   */
  #if defined(HAVE_LIBURING)
    #define IO_ENGINE_URING 1
  #else
    #define IO_ENGINE_EPOLL 1
  #endif

#elif defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__) || defined(__APPLE__)
  #define IO_ENGINE_KQUEUE 1

#else
  #error "Unsupported platform: Please use Linux (epoll/io_uring) or BSD/macOS (kqueue)"
#endif

/* ========== Event Structure ========== */

typedef struct {
    int fd;                    /* File descriptor */
    uint32_t events;           /* Requested events (EPOLLIN, EPOLLOUT, etc.) */
    uint64_t user_data;        /* User-provided context */
} io_event_t;

typedef struct {
    int fd;                    /* File descriptor that triggered event */
    uint32_t events;           /* Actual events that occurred */
    uint64_t user_data;        /* User-provided context from io_event_t */
} io_result_t;

/* ========== I/O Engine Handle ========== */

typedef struct io_engine io_engine_t;

/* ========== API Functions ========== */

/**
 * Create I/O engine with specified capacity
 *
 * @param max_events  Maximum number of events to handle per wait
 * @param max_fds     Maximum file descriptors to register (hint only)
 * @return io_engine_t* or NULL on error
 */
io_engine_t* io_engine_create(int max_events, int max_fds);

/**
 * Destroy I/O engine and free resources
 */
void io_engine_destroy(io_engine_t *engine);

/**
 * Register file descriptor for monitoring
 *
 * @param engine   I/O engine
 * @param event    Event to register (fd, events, user_data)
 * @return 0 on success, -1 on error
 */
int io_engine_add(io_engine_t *engine, const io_event_t *event);

/**
 * Modify registered file descriptor events
 *
 * @param engine   I/O engine
 * @param event    Event to modify
 * @return 0 on success, -1 on error
 */
int io_engine_mod(io_engine_t *engine, const io_event_t *event);

/**
 * Unregister file descriptor
 *
 * @param engine   I/O engine
 * @param fd       File descriptor to remove
 * @return 0 on success, -1 on error
 */
int io_engine_del(io_engine_t *engine, int fd);

/**
 * Wait for I/O events (blocking)
 *
 * @param engine      I/O engine
 * @param results     Array to store results (must have capacity for engine->max_events)
 * @param timeout_ms  Timeout in milliseconds (-1 = infinite, 0 = non-blocking)
 * @return Number of events received (0 if timeout), -1 on error
 */
int io_engine_wait(io_engine_t *engine, io_result_t *results, int timeout_ms);

/**
 * Get engine info for debugging
 */
const char* io_engine_backend(const io_engine_t *engine);

/* ========== Event Masks (compatible with epoll) ========== */

#ifdef IO_ENGINE_EPOLL
  #include <sys/epoll.h>
  #define IO_IN    EPOLLIN
  #define IO_OUT   EPOLLOUT
  #define IO_ERR   EPOLLERR
  #define IO_HUP   EPOLLHUP

#elif defined(IO_ENGINE_URING)
  /* io_uring events (use same as epoll for compatibility) */
  #define IO_IN    (1 << 0)    /* EPOLLIN */
  #define IO_OUT   (1 << 1)    /* EPOLLOUT */
  #define IO_ERR   (1 << 3)    /* EPOLLERR */
  #define IO_HUP   (1 << 4)    /* EPOLLHUP */

#elif defined(IO_ENGINE_KQUEUE)
  /* kqueue filters */
  #define IO_IN    1            /* EVFILT_READ */
  #define IO_OUT   2            /* EVFILT_WRITE */
  #define IO_ERR   0x4000       /* EV_ERROR */
  #define IO_HUP   0x0001       /* EV_EOF */
#endif

#endif /* IO_ENGINE_H */
