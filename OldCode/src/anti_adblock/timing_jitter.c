/* timing_jitter.c - Anti-Fingerprinting Timing Jitter Implementation */
#include <stdlib.h>
#include <string.h>
#include <stdatomic.h>
#include <time.h>
#include <unistd.h>
#include "timing_jitter.h"
#include "connection.h"

/* ============================================================================
 * Timing Jitter Configuration
 * ============================================================================ */

/* Global enable/disable flag - DEFAULT: DISABLED! */
int timing_jitter_enabled = 0;

/* THREAD SAFETY FIX: Use atomic_int to prevent double-checked locking bug
 * Multiple threads calling timing_jitter_apply() could all see initialized=0
 * and call srand() simultaneously, causing nondeterministic behavior */
static atomic_int jitter_initialized = 0;

/* ============================================================================
 * Jitter Functions
 * ============================================================================ */

/* Initialize timing jitter system */
void timing_jitter_init(void) {
    /* Use atomic compare-exchange to ensure only ONE thread calls srand() */
    int expected = 0;
    if (!atomic_compare_exchange_strong_explicit(&jitter_initialized,
                                                 &expected,
                                                 1,
                                                 memory_order_acq_rel,
                                                 memory_order_acquire)) {
        /* Another thread already initialized - nothing to do */
        return;
    }

    /* We got here because we successfully CAS'd 0→1, so we're the only initializer */
    /* Seed random number generator with time and process ID */
    srand(time(NULL) ^ getpid());
}

/* Apply delay in microseconds */
void timing_jitter_delay_us(uint32_t microseconds) {
    if (microseconds == 0) return;

    struct timespec ts;
    ts.tv_sec = microseconds / 1000000;
    ts.tv_nsec = (microseconds % 1000000) * 1000;
    nanosleep(&ts, NULL);
}

/* Apply timing jitter based on connection
 *
 * COMPILE-TIME OPTIONAL: Only active when ENABLE_TIMING_JITTER is defined
 *
 * LOGIC:
 *   - Index/Favicon (skip_jitter=1): 80% no delay, 20% light jitter (0-10ms)
 *   - All other responses:            100% jitter (5-20ms)
 */
void timing_jitter_apply(connection_t *conn) {
#ifdef ENABLE_TIMING_JITTER
    /* Quick exit if jitter disabled globally or no connection */
    if (!timing_jitter_enabled || !conn) return;

    /* Ensure initialized (thread-safe with atomic compare-exchange) */
    if (!atomic_load_explicit(&jitter_initialized, memory_order_acquire)) {
        timing_jitter_init();
    }

    /* Check if this response should skip jitter (index.html / favicon.ico) */
    if (conn->skip_jitter) {
        /* Index/Favicon: 80% no delay, 20% light jitter (0-10ms) */
        /* This simulates occasional cache misses or slight network variation */
        int chance = rand() % 100;
        if (chance < 80) {
            /* 80%: No delay - fast response */
            return;
        } else {
            /* 20%: Light jitter 0-10ms */
            uint32_t delay_ms = rand() % 11;  /* 0 to 10ms */
            timing_jitter_delay_us(delay_ms * 1000);
        }
    } else {
        /* ALL OTHER PATHS: Apply 5-20ms random jitter */
        /* This simulates real server variability (network, load, etc.) */
        uint32_t delay_ms = 5 + (rand() % 16);  /* 5 to 20ms */
        timing_jitter_delay_us(delay_ms * 1000);
    }
#else
    /* Timing jitter not compiled in - this function does nothing */
    (void)conn;  /* Suppress unused parameter warning */
    return;
#endif
}

/* Enable/disable timing jitter at runtime */
void timing_jitter_set_enabled(int enabled) {
    timing_jitter_enabled = enabled ? 1 : 0;
}

/* Get current jitter status */
int timing_jitter_is_enabled(void) {
    return timing_jitter_enabled;
}
