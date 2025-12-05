/* TLS-Gate NG - High Availability Leader Election
 * Copyright (C) 2025 Torsten Jahnke
 */

#include "ha_leader.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <time.h>

#define HA_LOCK_FILENAME "tlsgateNG-poolgen.lock"
#define HA_MONITOR_INTERVAL_SEC 5   /* Check lock every 5 seconds */

/* Monitor thread function - tries to acquire lock periodically */
static void *ha_monitor_thread(void *arg) {
    ha_leader_t *ha = (ha_leader_t *)arg;

    while (atomic_load_explicit(&ha->running, memory_order_acquire)) {
        if (ha->state == HA_STATE_STANDBY) {
            /* Try to acquire lock */
            if (flock(ha->lock_fd, LOCK_EX | LOCK_NB) == 0) {
                /* Got the lock! */
                ha->state = HA_STATE_ACTIVE;
                printf("[HA] Acquired leadership - now ACTIVE\n");

                /* Call callback if set */
                if (ha->on_become_leader) {
                    ha->on_become_leader(ha->callback_ctx);
                }
            }
        }

        /* Sleep before next check */
        for (int i = 0; i < HA_MONITOR_INTERVAL_SEC && atomic_load_explicit(&ha->running, memory_order_acquire); i++) {
            sleep(1);
        }
    }

    return NULL;
}

bool ha_leader_init(ha_leader_t *ha, ha_role_t role, const char *lock_dir) {
    if (!ha || !lock_dir) {
        return false;
    }

    memset(ha, 0, sizeof(*ha));
    ha->role = role;
    ha->state = HA_STATE_INIT;
    ha->lock_fd = -1;
    atomic_init(&ha->running, 0);

    /* HA disabled - nothing to do */
    if (role == HA_ROLE_DISABLED) {
        ha->state = HA_STATE_ACTIVE;  /* Always active when HA disabled */
        return true;
    }

    /* Create lock directory if needed */
    struct stat st;
    if (stat(lock_dir, &st) != 0) {
        if (mkdir(lock_dir, 0755) != 0 && errno != EEXIST) {
            fprintf(stderr, "[HA] Failed to create lock directory %s: %s\n",
                    lock_dir, strerror(errno));
            ha->state = HA_STATE_FAILED;
            return false;
        }
    }

    /* Build lock file path */
    snprintf(ha->lock_path, sizeof(ha->lock_path), "%s/%s", lock_dir, HA_LOCK_FILENAME);

    /* Open lock file (create if needed) */
    ha->lock_fd = open(ha->lock_path, O_RDWR | O_CREAT, 0644);
    if (ha->lock_fd < 0) {
        fprintf(stderr, "[HA] Failed to open lock file %s: %s\n",
                ha->lock_path, strerror(errno));
        ha->state = HA_STATE_FAILED;
        return false;
    }

    /* Write PID and role to lock file for debugging */
    char info[128];
    snprintf(info, sizeof(info), "PID: %d\nRole: %s\nStarted: %ld\n",
             getpid(), ha_role_to_string(role), (long)time(NULL));

    /* Don't fail if write fails - lock file content is just for debugging */
    if (write(ha->lock_fd, info, strlen(info)) < 0) {
        /* Ignore write errors */
    }

    ha->state = HA_STATE_STANDBY;
    printf("[HA] Initialized as %s (lock: %s)\n",
           ha_role_to_string(role), ha->lock_path);

    return true;
}

bool ha_leader_try_acquire(ha_leader_t *ha) {
    if (!ha || ha->lock_fd < 0) {
        return false;
    }

    if (ha->role == HA_ROLE_DISABLED) {
        return true;  /* Always "leader" when disabled */
    }

    if (ha->state == HA_STATE_ACTIVE) {
        return true;  /* Already leader */
    }

    /* Try non-blocking lock */
    if (flock(ha->lock_fd, LOCK_EX | LOCK_NB) == 0) {
        ha->state = HA_STATE_ACTIVE;
        printf("[HA] Acquired leadership - now ACTIVE\n");

        if (ha->on_become_leader) {
            ha->on_become_leader(ha->callback_ctx);
        }
        return true;
    }

    /* Lock held by another process */
    if (errno == EWOULDBLOCK) {
        printf("[HA] Lock held by another instance - waiting in STANDBY\n");
        return false;
    }

    fprintf(stderr, "[HA] flock failed: %s\n", strerror(errno));
    return false;
}

bool ha_leader_wait_acquire(ha_leader_t *ha) {
    if (!ha || ha->lock_fd < 0) {
        return false;
    }

    if (ha->role == HA_ROLE_DISABLED) {
        return true;
    }

    if (ha->state == HA_STATE_ACTIVE) {
        return true;
    }

    printf("[HA] Waiting to acquire leadership...\n");

    /* Blocking lock */
    if (flock(ha->lock_fd, LOCK_EX) == 0) {
        ha->state = HA_STATE_ACTIVE;
        printf("[HA] Acquired leadership - now ACTIVE\n");

        if (ha->on_become_leader) {
            ha->on_become_leader(ha->callback_ctx);
        }
        return true;
    }

    fprintf(stderr, "[HA] flock failed: %s\n", strerror(errno));
    ha->state = HA_STATE_FAILED;
    return false;
}

void ha_leader_release(ha_leader_t *ha) {
    if (!ha || ha->lock_fd < 0) {
        return;
    }

    if (ha->role == HA_ROLE_DISABLED) {
        return;
    }

    if (ha->state == HA_STATE_ACTIVE) {
        flock(ha->lock_fd, LOCK_UN);
        ha->state = HA_STATE_STANDBY;
        printf("[HA] Released leadership - now STANDBY\n");

        if (ha->on_lose_leader) {
            ha->on_lose_leader(ha->callback_ctx);
        }
    }
}

bool ha_leader_is_active(const ha_leader_t *ha) {
    if (!ha) {
        return false;
    }

    /* HA disabled = always active */
    if (ha->role == HA_ROLE_DISABLED) {
        return true;
    }

    return ha->state == HA_STATE_ACTIVE;
}

const char *ha_leader_state_str(const ha_leader_t *ha) {
    if (!ha) {
        return "UNKNOWN";
    }

    switch (ha->state) {
        case HA_STATE_INIT:    return "INIT";
        case HA_STATE_STANDBY: return "STANDBY";
        case HA_STATE_ACTIVE:  return "ACTIVE";
        case HA_STATE_FAILED:  return "FAILED";
        default:               return "UNKNOWN";
    }
}

void ha_leader_set_callbacks(ha_leader_t *ha,
                            void (*on_become)(void *),
                            void (*on_lose)(void *),
                            void *ctx) {
    if (!ha) {
        return;
    }

    ha->on_become_leader = on_become;
    ha->on_lose_leader = on_lose;
    ha->callback_ctx = ctx;
}

bool ha_leader_start_monitor(ha_leader_t *ha) {
    if (!ha || ha->role == HA_ROLE_DISABLED) {
        return true;  /* No monitoring needed */
    }

    if (atomic_load_explicit(&ha->running, memory_order_acquire)) {
        return true;  /* Already running */
    }

    atomic_store(&ha->running, 1);

    if (pthread_create(&ha->monitor_thread, NULL, ha_monitor_thread, ha) != 0) {
        fprintf(stderr, "[HA] Failed to start monitor thread\n");
        atomic_store(&ha->running, 0);
        return false;
    }

    printf("[HA] Monitor thread started\n");
    return true;
}

void ha_leader_stop_monitor(ha_leader_t *ha) {
    if (!ha) {
        return;
    }

    if (atomic_load_explicit(&ha->running, memory_order_acquire)) {
        atomic_store(&ha->running, 0);
        pthread_join(ha->monitor_thread, NULL);
        printf("[HA] Monitor thread stopped\n");
    }
}

void ha_leader_cleanup(ha_leader_t *ha) {
    if (!ha) {
        return;
    }

    /* Stop monitor thread if running */
    ha_leader_stop_monitor(ha);

    /* Release lock if held */
    if (ha->state == HA_STATE_ACTIVE && ha->lock_fd >= 0) {
        flock(ha->lock_fd, LOCK_UN);
    }

    /* Close lock file */
    if (ha->lock_fd >= 0) {
        close(ha->lock_fd);
        ha->lock_fd = -1;
    }

    ha->state = HA_STATE_INIT;
    printf("[HA] Cleanup complete\n");
}

ha_role_t ha_role_from_string(const char *str) {
    if (!str) {
        return HA_ROLE_DISABLED;
    }

    if (strcasecmp(str, "primary") == 0) {
        return HA_ROLE_PRIMARY;
    } else if (strcasecmp(str, "backup") == 0) {
        return HA_ROLE_BACKUP;
    } else if (strcasecmp(str, "disabled") == 0 || strcasecmp(str, "none") == 0) {
        return HA_ROLE_DISABLED;
    }

    return HA_ROLE_DISABLED;
}

const char *ha_role_to_string(ha_role_t role) {
    switch (role) {
        case HA_ROLE_PRIMARY:  return "primary";
        case HA_ROLE_BACKUP:   return "backup";
        case HA_ROLE_DISABLED: return "disabled";
        default:               return "unknown";
    }
}
