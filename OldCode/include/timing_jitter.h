/* timing_jitter.h - Anti-Fingerprinting Timing Jitter System */
#ifndef TIMING_JITTER_H
#define TIMING_JITTER_H

#include <stddef.h>
#include <stdint.h>

/* ============================================================================
 * TIMING JITTER - Anti-Fingerprinting Defense
 * ============================================================================
 *
 * PURPOSE: Defeat timing-based fingerprinting attacks
 *
 * HOW IT WORKS:
 *   1. Adds random delays (5-20ms) before sending responses
 *   2. Exceptions: / (index.html) and /favicon.ico get NO delay (fast UX)
 *   3. All other paths get random jitter (realistic server behavior)
 *
 * WHY:
 *   - Attackers can fingerprint servers by measuring response times
 *   - Different servers have different timing characteristics
 *   - Random jitter makes timing measurements unreliable
 *
 * STEALTH BENEFIT:
 *   - Real servers have variable response times (load, network, etc.)
 *   - Index and favicon are fast (good UX, looks legit)
 *   - Assets have delays (realistic behavior)
 *   - Defeats statistical timing analysis
 *
 * DEFAULT: DISABLED (minimal overhead)
 * Enable: timing_jitter_set_enabled(1)
 * ============================================================================
 */

/* Timing jitter rule structure */
typedef struct {
    const char *path_pattern;    /* Path pattern (e.g., "*.js", "/api/wildcard") */
    uint32_t min_delay_ms;       /* Minimum delay in milliseconds */
    uint32_t max_delay_ms;       /* Maximum delay in milliseconds */
    int enabled;                 /* 1 = enabled, 0 = disabled */
} timing_jitter_rule_t;

/* Global jitter enable/disable flag */
extern int timing_jitter_enabled;

/* Initialize timing jitter system */
void timing_jitter_init(void);

/* Apply timing jitter based on connection (compile-time optional) */
struct connection;  /* Forward declaration */
void timing_jitter_apply(struct connection *conn);

/* Enable/disable timing jitter at runtime */
void timing_jitter_set_enabled(int enabled);

/* Get current jitter status */
int timing_jitter_is_enabled(void);

/* Apply a specific delay in microseconds (for testing) */
void timing_jitter_delay_us(uint32_t microseconds);

#endif /* TIMING_JITTER_H */
