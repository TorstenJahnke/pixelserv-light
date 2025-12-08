/* timing_jitter.c - Anti-Fingerprinting Timing Jitter Implementation
 * Part of pixelserv-tls anti-fingerprinting suite
 */

#include <stdlib.h>
#include <string.h>
#include <stdatomic.h>
#include <time.h>
#include <unistd.h>
#include "content/timing_jitter.h"

/* Global enable/disable flag - DEFAULT: DISABLED! */
int timing_jitter_enabled = 0;

/* THREAD SAFETY: Use atomic_int to prevent double-checked locking bug
 * Multiple threads calling timing_jitter functions could all see initialized=0
 * and call srand() simultaneously, causing nondeterministic behavior */
static _Atomic int jitter_initialized = 0;

/* Initialize timing jitter system */
void timing_jitter_init(void) {
    /* Use atomic compare-exchange to ensure only ONE thread calls srand() */
    int expected = 0;
    if (!atomic_compare_exchange_strong(&jitter_initialized, &expected, 1)) {
        /* Another thread already initialized - nothing to do */
        return;
    }

    /* We got here because we successfully CAS'd 0->1, so we're the only initializer */
    /* Seed random number generator with time and process ID */
    srand((unsigned int)(time(NULL) ^ getpid()));
}

/* Apply delay in microseconds */
void timing_jitter_delay_us(uint32_t microseconds) {
    if (microseconds == 0) return;

    struct timespec ts;
    ts.tv_sec = microseconds / 1000000;
    ts.tv_nsec = (microseconds % 1000000) * 1000;
    nanosleep(&ts, NULL);
}

/* Apply delay in milliseconds */
void timing_jitter_delay_ms(uint32_t milliseconds) {
    timing_jitter_delay_us(milliseconds * 1000);
}

/* Apply random jitter (5-20ms range) */
void timing_jitter_random(void) {
    if (!timing_jitter_enabled) return;

    /* Ensure initialized */
    if (!atomic_load(&jitter_initialized)) {
        timing_jitter_init();
    }

    uint32_t delay_ms = 5 + ((uint32_t)rand() % 16);  /* 5 to 20ms */
    timing_jitter_delay_ms(delay_ms);
}

/* Apply light jitter (0-10ms range, 20% chance) */
void timing_jitter_light(void) {
    if (!timing_jitter_enabled) return;

    /* Ensure initialized */
    if (!atomic_load(&jitter_initialized)) {
        timing_jitter_init();
    }

    /* 80% no delay, 20% light jitter */
    int chance = rand() % 100;
    if (chance < 80) {
        return;  /* No delay */
    }

    uint32_t delay_ms = (uint32_t)rand() % 11;  /* 0 to 10ms */
    timing_jitter_delay_ms(delay_ms);
}

/* Apply timing jitter based on path
 *
 * LOGIC:
 *   - Fast paths (index, favicon): 80% no delay, 20% light jitter (0-10ms)
 *   - All other responses: 100% jitter (5-20ms)
 */
void timing_jitter_apply_for_path(const char *path, int is_fast_path) {
    if (!timing_jitter_enabled) return;

    /* Ensure initialized */
    if (!atomic_load(&jitter_initialized)) {
        timing_jitter_init();
    }

    /* Check if this is a fast path (index, favicon) */
    if (is_fast_path) {
        /* Fast paths: 80% no delay, 20% light jitter (0-10ms) */
        timing_jitter_light();
    } else if (path) {
        /* Check for common fast paths by name */
        if (strcmp(path, "/") == 0 ||
            strcmp(path, "/index.html") == 0 ||
            strcmp(path, "/favicon.ico") == 0 ||
            strstr(path, "favicon") != NULL) {
            timing_jitter_light();
        } else {
            /* All other paths: Apply 5-20ms random jitter */
            timing_jitter_random();
        }
    } else {
        /* No path info - apply normal jitter */
        timing_jitter_random();
    }
}

/* Enable/disable timing jitter at runtime */
void timing_jitter_set_enabled(int enabled) {
    timing_jitter_enabled = enabled ? 1 : 0;
    if (enabled && !atomic_load(&jitter_initialized)) {
        timing_jitter_init();
    }
}

/* Get current jitter status */
int timing_jitter_is_enabled(void) {
    return timing_jitter_enabled;
}
