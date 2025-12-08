/* timing_jitter.h - Anti-Fingerprinting Timing Jitter System
 * Part of pixelserv-tls anti-fingerprinting suite
 *
 * PURPOSE: Defeat timing-based fingerprinting attacks
 *
 * HOW IT WORKS:
 *   1. Adds random delays (5-20ms) before sending responses
 *   2. Fast paths (index, favicon) get minimal/no delay
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
 */

#ifndef TIMING_JITTER_H
#define TIMING_JITTER_H

#include <stdint.h>

/* Global jitter enable/disable flag */
extern int timing_jitter_enabled;

/* Initialize timing jitter system (thread-safe) */
void timing_jitter_init(void);

/* Apply timing jitter for a request path
 * @param path: Request path (e.g., "/script.js")
 * @param is_fast_path: 1 for index/favicon (minimal jitter), 0 for normal
 */
void timing_jitter_apply_for_path(const char *path, int is_fast_path);

/* Apply a specific delay in microseconds */
void timing_jitter_delay_us(uint32_t microseconds);

/* Apply a specific delay in milliseconds */
void timing_jitter_delay_ms(uint32_t milliseconds);

/* Enable/disable timing jitter at runtime */
void timing_jitter_set_enabled(int enabled);

/* Get current jitter status */
int timing_jitter_is_enabled(void);

/* Apply random jitter (5-20ms range) */
void timing_jitter_random(void);

/* Apply light jitter (0-10ms range, 20% chance) */
void timing_jitter_light(void);

#endif /* TIMING_JITTER_H */
