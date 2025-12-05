/* TLS-Gate NG - High Availability Leader Election
 * Copyright (C) 2025 Torsten Jahnke
 *
 * Active-Passive failover for poolgen using flock-based leader election.
 * Only one poolgen instance can be active at a time.
 */

#ifndef TLSGATENG_HA_LEADER_H
#define TLSGATENG_HA_LEADER_H

#include <stdbool.h>
#include <stdatomic.h>
#include <pthread.h>

/* HA role types */
typedef enum {
    HA_ROLE_DISABLED = 0,   /* No HA - single instance mode (default) */
    HA_ROLE_PRIMARY,        /* Primary poolgen - tries to become leader */
    HA_ROLE_BACKUP          /* Backup poolgen - takes over if primary fails */
} ha_role_t;

/* HA state */
typedef enum {
    HA_STATE_INIT = 0,      /* Initializing */
    HA_STATE_STANDBY,       /* Waiting for lock (passive) */
    HA_STATE_ACTIVE,        /* Holding lock (active leader) */
    HA_STATE_FAILED         /* Failed to initialize */
} ha_state_t;

/* HA leader context */
typedef struct {
    ha_role_t role;                 /* Configured role */
    ha_state_t state;               /* Current state */
    int lock_fd;                    /* Lock file descriptor */
    char lock_path[256];            /* Path to lock file */
    pthread_t monitor_thread;       /* Thread for monitoring lock */
    atomic_int running;             /* Monitor thread control */
    void (*on_become_leader)(void *ctx);    /* Callback when becoming leader */
    void (*on_lose_leader)(void *ctx);      /* Callback when losing leadership */
    void *callback_ctx;             /* Context for callbacks */
} ha_leader_t;

/* Initialize HA leader election
 *
 * @param ha          HA context to initialize
 * @param role        Configured role (PRIMARY/BACKUP)
 * @param lock_dir    Directory for lock file (e.g., /var/run/tlsgateNG)
 * @return            true on success, false on failure
 */
bool ha_leader_init(ha_leader_t *ha, ha_role_t role, const char *lock_dir);

/* Try to become leader (non-blocking)
 *
 * @param ha          HA context
 * @return            true if now leader, false if waiting
 */
bool ha_leader_try_acquire(ha_leader_t *ha);

/* Wait to become leader (blocking)
 *
 * Blocks until lock is acquired. Use for startup.
 *
 * @param ha          HA context
 * @return            true on success, false on error
 */
bool ha_leader_wait_acquire(ha_leader_t *ha);

/* Release leadership
 *
 * @param ha          HA context
 */
void ha_leader_release(ha_leader_t *ha);

/* Check if currently leader
 *
 * @param ha          HA context
 * @return            true if currently holding lock
 */
bool ha_leader_is_active(const ha_leader_t *ha);

/* Get current HA state as string
 *
 * @param ha          HA context
 * @return            State description
 */
const char *ha_leader_state_str(const ha_leader_t *ha);

/* Set callbacks for leadership changes
 *
 * @param ha              HA context
 * @param on_become       Callback when becoming leader (may be NULL)
 * @param on_lose         Callback when losing leadership (may be NULL)
 * @param ctx             Context passed to callbacks
 */
void ha_leader_set_callbacks(ha_leader_t *ha,
                            void (*on_become)(void *),
                            void (*on_lose)(void *),
                            void *ctx);

/* Start background monitoring thread
 *
 * For backup nodes: monitors lock and acquires when available.
 *
 * @param ha          HA context
 * @return            true on success
 */
bool ha_leader_start_monitor(ha_leader_t *ha);

/* Stop monitoring thread
 *
 * @param ha          HA context
 */
void ha_leader_stop_monitor(ha_leader_t *ha);

/* Cleanup HA context
 *
 * @param ha          HA context
 */
void ha_leader_cleanup(ha_leader_t *ha);

/* Parse HA role from string
 *
 * @param str         "primary", "backup", or "disabled"
 * @return            Parsed role, or HA_ROLE_DISABLED on invalid input
 */
ha_role_t ha_role_from_string(const char *str);

/* Convert HA role to string
 *
 * @param role        Role to convert
 * @return            String representation
 */
const char *ha_role_to_string(ha_role_t role);

#endif /* TLSGATENG_HA_LEADER_H */
