/*
 * http_responder_mt.c - Multi-Threaded HTTP Responder
 *
 * DNS Sinkhole Response Server with Worker Pool
 * - Main thread accepts connections
 * - Worker threads handle requests with epoll
 * - Target: 160K connections per process (4 workers × 40K each)
 *
 * Build:
 *   gcc -o http_responder_mt src/http_responder_mt.c src/worker.c src/connection.c \
 *       -Iinclude -pthread -O2
 *
 * Run:
 *   ./http_responder_mt 8080 127.0.0.1 -w 4
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <signal.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <limits.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <pwd.h>
#include <grp.h>
#include <dirent.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "worker.h"
#include "connection.h"
#include "response.h"
#include "version.h"
#include "config/config_file.h"
#include "html_loader.h"

/* TLS components */
#include "pki/pki_manager.h"
#include "crypto/keypool.h"
#include "cert/cert_generator.h"
#include "ipc/shm_manager.h"
#include "ipc/ha_leader.h"
#include "security/security_intel.h"
#include "cert/cert_cache.h"
#include "cert/cert_index.h"

/* Utilities */
#include "util/address_validation.h"
#include "cert/ca_loader.h"
#include "cert/cert_maintenance.h"
#include "tls/sni_extractor.h"
#include "util/logger.h"
#include "config/config_file.h"
#include "config/config_generator.h"
#include "http/silent_blocker.h"
#include "http/reverse_proxy.h"

#define DEFAULT_WORKER_COUNT 4
#define DEFAULT_CONN_PER_WORKER 50000  /* Production: 50K connections per worker */

/* Configuration structure */
typedef struct {
    const char *listen_addr;
    int http_port;
    int https_port;
    int auto_port;      /* Port for auto-detection (MSG_PEEK) */
    int worker_count;
    const char *ca_base_dir;
    const char *cert_dir;
    const char *bundle_dir;
    const char *prime_pool_dir;
    const char *drop_user;
    const char *drop_group;
    bool use_shm_keypool;
    bool is_keygen;
    int max_connections;
    bool daemonize;
    bool verbose;
    const char *force_algorithm;  /* Force single algorithm (e.g., "RSA-3072") */
    int pool_size;                 /* Keypool size (0 = use default) */
    const char *ha_role;          /* HA role: "primary", "backup", or NULL (disabled) */
} config_t;

/* Global state */
static atomic_int g_running = 1;
static worker_t **g_workers = NULL;
static int g_worker_count = 0;

/* Watchdog state (for workers) */
static int g_worker_slot = -1;              /* Worker's slot in watchdog registry */
static keypool_shm_t *g_watchdog_pool = NULL;  /* SHM reference for heartbeat */
static time_t g_last_heartbeat = 0;         /* Last heartbeat timestamp */

/* Maintenance thread state */
static pthread_t g_maintenance_thread;
static atomic_int g_maintenance_running = 0;
static cert_generator_t *g_cert_generator = NULL;
static const char *g_ca_base_dir = NULL;

/* HA leader election state */
static ha_leader_t g_ha_leader;

/* TLS global state */
static pki_manager_t *g_pki = NULL;
static keypool_t *g_keypool = NULL;
static cert_cache_t *g_cert_cache = NULL;
static cert_index_t *g_cert_index = NULL;
static certcache_shm_t *g_shm_certcache = NULL;  /* Shared memory cert index */
static int g_shm_certcache_fd = -1;              /* SHM file descriptor */
cert_generator_t *g_cert_gen = NULL;  /* Non-static for worker access */
SSL_CTX *g_default_sslctx = NULL;     /* Non-static for worker access */

/* Master configuration (global for response generation) */
config_file_t *g_master_config = NULL;  /* Non-static for response generation access */

/* Saved paths for SHM persistence */
static char g_saved_index_dir[4096] = "";

/* Security configuration */
bool g_legacy_crypto_enabled = false;  /* Enable legacy/weak crypto (RSA-1024/2048, SHA1) */

/* None-SNI configuration */
int g_default_domain_mode = NONE_SNI_MODE_AUTO;  /* 0=auto, 1=static, 2=disabled */
char g_default_domain[256] = "";  /* Current domain for SNI-less clients (auto-updated in auto mode) */

/* SIGHUP hot-reload support (Poolgen only) */
static bool g_is_shm_master = false;  /* True if this is the Poolgen (SHM master) */

/* Signal flags - async-signal-safe communication from handler to main loop
 * CRITICAL: Signal handlers must ONLY set these flags. All actual work
 * (malloc, stdio, complex operations) must be done in the main loop. */
static volatile sig_atomic_t g_print_stats_requested = 0;  /* SIGUSR1 */
static volatile sig_atomic_t g_reload_requested = 0;       /* SIGHUP */

/* Signal handler */
/* Certificate Maintenance Thread
 *
 * Runs every 12 hours to:
 * 1. Scan all certificates in RSA/ECDSA/SM2 directories
 * 2. Identify certificates expiring within 7 days
 * 3. Automatically renew and replace expiring certificates
 */
static void* maintenance_thread_func(void *arg) {
    (void)arg;  /* Unused */

    LOG_INFO("Certificate maintenance thread started");
    LOG_INFO("Base directory: %s", g_ca_base_dir);

    const int TWELVE_HOURS = 12 * 3600;  /* 12 hours in seconds */
    time_t last_maintenance = 0;

    while (atomic_load_explicit(&g_maintenance_running, memory_order_acquire)) {
        time_t now = time(NULL);

        /* Run maintenance every 12 hours */
        if (now - last_maintenance >= TWELVE_HOURS) {
            LOG_INFO("=== Starting 12-hour maintenance cycle ===");

            /* Run maintenance for each algorithm directory */
            char rsa_dir[4096], ecdsa_dir[4096], sm2_dir[4096];
            snprintf(rsa_dir, sizeof(rsa_dir), "%s/RSA", g_ca_base_dir);
            snprintf(ecdsa_dir, sizeof(ecdsa_dir), "%s/ECDSA", g_ca_base_dir);
            snprintf(sm2_dir, sizeof(sm2_dir), "%s/SM2", g_ca_base_dir);

            int total_renewed = 0;

            /* Renew RSA certificates */
            int rsa_renewed = cert_maintenance_cycle_12h(g_cert_generator, rsa_dir);
            if (rsa_renewed > 0) {
                LOG_INFO("RSA: Renewed %d certificates", rsa_renewed);
                total_renewed += rsa_renewed;
            }

            /* Renew ECDSA certificates */
            int ecdsa_renewed = cert_maintenance_cycle_12h(g_cert_generator, ecdsa_dir);
            if (ecdsa_renewed > 0) {
                LOG_INFO("ECDSA: Renewed %d certificates", ecdsa_renewed);
                total_renewed += ecdsa_renewed;
            }

            /* Renew SM2 certificates (国密/商用密码) */
            int sm2_renewed = cert_maintenance_cycle_12h(g_cert_generator, sm2_dir);
            if (sm2_renewed > 0) {
                LOG_INFO("SM2 (国密/商用密码): Renewed %d certificates", sm2_renewed);
                total_renewed += sm2_renewed;
            }

            if (total_renewed > 0) {
                LOG_INFO("=== Maintenance cycle complete: %d certificates renewed ===", total_renewed);
            } else {
                LOG_INFO("=== Maintenance cycle complete: No certificates needed renewal ===");
            }

            last_maintenance = now;
        }

        /* Save SHM certcache to disk periodically (if master and dirty) */
        if (g_shm_certcache && g_master_config && g_master_config->index_master) {
            if (atomic_load_explicit(&g_shm_certcache->dirty, memory_order_acquire)) {
                char index_file[4128];  /* 4096 (max path) + 32 (filename) */
                snprintf(index_file, sizeof(index_file), "%s/shm_certcache.bin",
                         g_saved_index_dir[0] ? g_saved_index_dir : "/tmp");
                /* ERROR HANDLING FIX: Check save result and log errors
                 * Previous: Silently ignored save failures, could lose data on restart */
                shm_error_t save_result = certcache_shm_save(g_shm_certcache, index_file);
                if (save_result == SHM_OK) {
                    LOG_DEBUG("SHM certcache saved to disk: %s", index_file);
                } else {
                    LOG_ERROR("Failed to save SHM certcache to disk: %s (error %d)",
                              index_file, save_result);
                    /* Note: Not clearing dirty flag - will retry on next cycle */
                }
            }
        }

        /* Sleep for 5 minutes before checking again */
        for (int i = 0; i < 5 * 60 && atomic_load_explicit(&g_maintenance_running, memory_order_acquire); i++) {
            sleep(1);  /* 1 second sleep for responsive shutdown */
        }
    }

    LOG_INFO("Certificate maintenance thread stopped");
    return NULL;
}

static void signal_handler(int sig) {
    /* ASYNC-SIGNAL-SAFE: Only set flags here, actual work done in main loop.
     * Calling malloc(), printf(), or complex functions in signal handlers
     * can cause deadlocks or corruption under high load (5M+ requests). */
    if (sig == SIGINT || sig == SIGTERM) {
        /* write() is async-signal-safe, use it instead of printf() */
        const char msg[] = "\nShutting down...\n";
        if (write(STDERR_FILENO, msg, sizeof(msg) - 1) < 0) { /* ignore */ }
        atomic_store(&g_running, 0);
        atomic_store(&g_maintenance_running, 0);  /* Stop maintenance thread */
    } else if (sig == SIGUSR1) {
        /* Set flag - stats will be printed in main loop */
        g_print_stats_requested = 1;
    } else if (sig == SIGHUP) {
        /* Set flag - reload will be done in main loop */
        g_reload_requested = 1;
    }
}

/* Process deferred signal actions - called from main loop (async-signal-UNSAFE OK here) */
static void process_signal_actions(void) {
    /* SIGUSR1: Print statistics */
    if (g_print_stats_requested) {
        g_print_stats_requested = 0;
        printf("\n=== Statistics ===\n");
        for (int i = 0; i < g_worker_count; i++) {
            if (g_workers && g_workers[i]) {
                worker_print_stats(g_workers[i]);
                printf("\n");
            }
        }
    }

    /* SIGHUP: Hot-reload configuration (Poolgen/master only) */
    if (g_reload_requested) {
        g_reload_requested = 0;

        if (g_is_shm_master && g_shm_certcache && g_master_config) {
            printf("\n=== SIGHUP: Reloading configuration ===\n");

            /* Reload TLDs into SHM */
            if (g_master_config->second_level_tld_file[0] != '\0') {
                int tld_count = certcache_shm_load_tlds(g_shm_certcache,
                                                         g_master_config->second_level_tld_file);
                if (tld_count >= 0) {
                    printf("Reloaded %d TLDs from %s\n",
                           tld_count, g_master_config->second_level_tld_file);
                } else {
                    fprintf(stderr, "Failed to reload TLDs\n");
                }
            }

            /* Reload silent-block rules into SHM (increments version) */
            if (g_master_config->silent_block_file[0] != '\0') {
                int sb_result = certcache_shm_load_silentblocks(g_shm_certcache,
                                                                 g_master_config->silent_block_file);
                if (sb_result == 0) {
                    printf("Reloaded silent-blocks from %s (version %d)\n",
                           g_master_config->silent_block_file,
                           certcache_shm_silentblock_version(g_shm_certcache));
                    printf("Workers will pick up changes automatically.\n");
                } else {
                    fprintf(stderr, "Failed to reload silent-blocks\n");
                }
            }

            printf("=== Reload complete ===\n\n");
        } else if (!g_is_shm_master) {
            printf("\nSIGHUP received but this is a worker - ignoring.\n");
            printf("Send SIGHUP to Poolgen for configuration reload.\n\n");
        }
    }
}

/* Fix CA directory permissions before DropRoot
 *
 * CRITICAL: rootCA directories must be owned by root:root and have proper permissions!
 * If they have wrong ownership (e.g., tlsgateNX:tlsgateNX), DropRoot will make them unreadable.
 *
 * This function ensures:
 * - rootCA directories: root:root, 755 (rwxr-xr-x)
 * - rootCA files: root:root, 644 (rw-r--r--)
 * - Works for all algorithms: RSA, ECDSA, SM2
 * - Also handles Legacy rootCA if legacy_crypto enabled
 */
static void fix_ca_permissions(const char *ca_base_dir) {
    if (!ca_base_dir || !ca_base_dir[0]) {
        return;
    }

    /* List of algorithms to check */
    const char *algorithms[] = { "RSA", "ECDSA", "SM2", NULL };

    printf("🔐 Verifying CA directory permissions...\n");

    for (int i = 0; algorithms[i] != NULL; i++) {
        char ca_dir[4128];  /* 4096 + 32 for path suffix */
        snprintf(ca_dir, sizeof(ca_dir), "%s/%s/rootCA", ca_base_dir, algorithms[i]);

        struct stat st;
        if (stat(ca_dir, &st) == 0 && S_ISDIR(st.st_mode)) {
            /* Check and fix directory ownership and permissions */
            uid_t current_uid = getuid();

            /* If not root, skip (can't change permissions) */
            if (current_uid != 0) {
                continue;
            }

            /* Fix directory permissions: 755 (rwxr-xr-x) */
            if ((st.st_mode & 0777) != 0755) {
                if (chmod(ca_dir, 0755) != 0) {
                    perror("chmod ca_dir");
                }
            }

            /* Fix directory ownership: root:root (uid=0, gid=0) */
            if (st.st_uid != 0 || st.st_gid != 0) {
                if (chown(ca_dir, 0, 0) != 0) {
                    LOG_DEBUG("Warning: Could not change ownership of %s", ca_dir);
                }
            }

            /* Fix file permissions in rootCA directory: 644 (rw-r--r--) */
            DIR *dir = opendir(ca_dir);
            if (dir) {
                struct dirent *entry;
                while ((entry = readdir(dir)) != NULL) {
                    if (entry->d_name[0] == '.') {
                        continue;  /* Skip . and .. */
                    }

                    char file_path[8192];
                    int len = snprintf(file_path, sizeof(file_path), "%s/%s", ca_dir, entry->d_name);
                    if (len < 0 || len >= (int)sizeof(file_path)) {
                        LOG_DEBUG("Path too long: %s/%s", ca_dir, entry->d_name);
                        continue;
                    }

                    if (stat(file_path, &st) == 0 && S_ISREG(st.st_mode)) {
                        /* Fix file permissions: 644 (rw-r--r--) */
                        if ((st.st_mode & 0777) != 0644) {
                            (void)chmod(file_path, 0644);
                        }

                        /* Fix file ownership: root:root */
                        if (st.st_uid != 0 || st.st_gid != 0) {
                            if (chown(file_path, 0, 0) != 0) {
                                LOG_DEBUG("Warning: Could not change ownership of %s", file_path);
                            }
                        }
                    }
                }
                closedir(dir);
            }

            printf("  ✓ %s/rootCA permissions verified\n", algorithms[i]);
        }
    }

    /* Handle Legacy rootCA if legacy_crypto is enabled */
    if (g_legacy_crypto_enabled) {
        char legacy_ca_dir[4096];
        snprintf(legacy_ca_dir, sizeof(legacy_ca_dir), "%s/Legacy/rootCA", ca_base_dir);

        struct stat st;
        if (stat(legacy_ca_dir, &st) == 0 && S_ISDIR(st.st_mode)) {
            uid_t current_uid = getuid();
            if (current_uid != 0) {
                return;  /* Can't change permissions without root */
            }

            /* Fix directory permissions: 755 */
            if ((st.st_mode & 0777) != 0755) {
                chmod(legacy_ca_dir, 0755);
            }

            /* Fix directory ownership: root:root */
            if (st.st_uid != 0 || st.st_gid != 0) {
                if (chown(legacy_ca_dir, 0, 0) != 0) {
                    LOG_DEBUG("Warning: Could not change ownership of %s", legacy_ca_dir);
                }
            }

            /* Fix file permissions */
            DIR *dir = opendir(legacy_ca_dir);
            if (dir) {
                struct dirent *entry;
                while ((entry = readdir(dir)) != NULL) {
                    if (entry->d_name[0] == '.') {
                        continue;
                    }

                    char file_path[8192];
                    int len = snprintf(file_path, sizeof(file_path), "%s/%s", legacy_ca_dir, entry->d_name);
                    if (len < 0 || len >= (int)sizeof(file_path)) {
                        LOG_DEBUG("Path too long: %s/%s", legacy_ca_dir, entry->d_name);
                        continue;
                    }

                    if (stat(file_path, &st) == 0 && S_ISREG(st.st_mode)) {
                        if ((st.st_mode & 0777) != 0644) {
                            (void)chmod(file_path, 0644);
                        }

                        if (st.st_uid != 0 || st.st_gid != 0) {
                            if (chown(file_path, 0, 0) != 0) {
                                LOG_DEBUG("Warning: Could not change ownership of %s", file_path);
                            }
                        }
                    }
                }
                closedir(dir);
            }

            printf("  ✓ Legacy/rootCA permissions verified\n");
        }
    }

    printf("\n");
}

/* Drop root privileges to specified user/group
 *
 * CRITICAL SECURITY FUNCTION!
 * Must be called AFTER:
 *   - Binding privileged ports (80, 443)
 *   - Loading CA certificate (ca.key readable only by root)
 * Must be called BEFORE:
 *   - Starting worker threads
 *
 * Security model:
 *   1. Start as root (uid=0)
 *   2. Bind ports 80/443 (requires root)
 *   3. Load CA key (only root can read ca.key:600)
 *   4. Drop to unprivileged user/group
 *   5. Workers run as unprivileged user
 *
 * If compromised, attacker only has unprivileged user access!
 */
/* Setup HTML file permissions BEFORE dropping privileges
 *
 * If HTML file is configured, adjust its permissions so the unprivileged user
 * can read it after DropRoot. This is done while still root (before drop_privileges).
 *
 * Returns 0 on success, -1 on error
 */
static int setup_html_permissions(const char *html_path, const char *user, const char *group) {
    struct passwd *pw = NULL;
    struct group *gr = NULL;
    uid_t target_uid = 0;
    gid_t target_gid = 0;

    /* Nothing to do if HTML not configured */
    if (!html_path || !html_path[0]) {
        return 0;
    }

    /* Nothing to do if not dropping privileges */
    if (!user && !group) {
        return 0;
    }

    printf("Setting up HTML file permissions...\n");

    /* Lookup group (if specified) */
    if (group) {
        gr = getgrnam(group);
        if (!gr) {
            fprintf(stderr, "WARNING: Group '%s' not found (skipping HTML chmod)\n", group);
            return 0;  /* Non-fatal - HTML loading will fail if permissions wrong */
        }
        target_gid = gr->gr_gid;
    }

    /* Lookup user (if specified) */
    if (user) {
        pw = getpwnam(user);
        if (!pw) {
            fprintf(stderr, "WARNING: User '%s' not found (skipping HTML chmod)\n", user);
            return 0;  /* Non-fatal */
        }
        target_uid = pw->pw_uid;

        /* If no group specified, use user's primary group */
        if (!group) {
            target_gid = pw->pw_gid;
        }
    }

    /* Check if file/directory exists */
    struct stat st;
    if (stat(html_path, &st) < 0) {
        fprintf(stderr, "WARNING: HTML file not found: %s\n", html_path);
        return 0;  /* Non-fatal - might be created later */
    }

    /* Change ownership to target user:group */
    if (chown(html_path, target_uid, target_gid) < 0) {
        perror("chown failed");
        fprintf(stderr, "WARNING: Failed to change ownership of %s to %d:%d\n",
                html_path, target_uid, target_gid);
        /* Non-fatal - file might already have correct ownership */
    } else {
        printf("  ✓ chown %d:%d %s\n", target_uid, target_gid, html_path);
    }

    /* Set readable permissions (owner and group can read, no execute for HTML!) */
    if (chmod(html_path, 0640) < 0) {
        perror("chmod failed");
        fprintf(stderr, "WARNING: Failed to chmod 0640 %s\n", html_path);
        /* Non-fatal - permissions might already be correct */
    } else {
        printf("  ✓ chmod 0640 %s\n", html_path);
    }

    return 0;
}

/* Setup working directory permissions BEFORE dropping privileges
 *
 * Sets ownership and permissions on directories that need to be writable
 * by the unprivileged user after DropRoot:
 *   - certs/     (generated certificates)
 *   - index/     (certificate index)
 *   - backup/    (keypool backups)
 *
 * Directories: user:group 0750 (rwxr-x---)
 * Files inside: user:group 0640 (rw-r-----)
 *
 * Returns 0 on success, -1 on error (non-fatal)
 */
static int setup_working_directory_permissions(const char *ca_base_dir, const char *user, const char *group,
                                                const char *backup_path, const char *keypool_path) {
    struct passwd *pw = NULL;
    struct group *gr = NULL;
    uid_t target_uid = 0;
    gid_t target_gid = 0;

    /* Nothing to do if not dropping privileges */
    if (!user && !group) {
        return 0;
    }

    /* Must be root to change permissions */
    if (getuid() != 0) {
        return 0;
    }

    /* Lookup group */
    if (group) {
        gr = getgrnam(group);
        if (!gr) {
            fprintf(stderr, "WARNING: Group '%s' not found (skipping working dir permissions)\n", group);
            return 0;
        }
        target_gid = gr->gr_gid;
    }

    /* Lookup user */
    if (user) {
        pw = getpwnam(user);
        if (!pw) {
            fprintf(stderr, "WARNING: User '%s' not found (skipping working dir permissions)\n", user);
            return 0;
        }
        target_uid = pw->pw_uid;
        if (!group) {
            target_gid = pw->pw_gid;
        }
    }

    printf("📁 Setting up working directory permissions for %s:%s...\n", user ? user : "(none)", group ? group : "(default)");

    /* Helper macro to set directory permissions */
    #define SETUP_DIR_PERMS(dir_path, create_if_missing) do { \
        struct stat st; \
        if (stat(dir_path, &st) == 0 && S_ISDIR(st.st_mode)) { \
            if (chown(dir_path, target_uid, target_gid) == 0) { \
                (void)chmod(dir_path, 0750); \
                printf("  ✓ %s → %d:%d (0750)\n", dir_path, target_uid, target_gid); \
            } else { \
                fprintf(stderr, "  ✗ Failed to chown %s\n", dir_path); \
            } \
        } else if (create_if_missing) { \
            if (mkdir(dir_path, 0750) == 0) { \
                if (chown(dir_path, target_uid, target_gid) != 0) { \
                    fprintf(stderr, "  ✗ Failed to chown new dir %s\n", dir_path); \
                } else { \
                    printf("  ✓ Created %s → %d:%d (0750)\n", dir_path, target_uid, target_gid); \
                } \
            } \
        } \
    } while(0)

    /* Algorithms to process */
    const char *algorithms[] = { "RSA", "ECDSA", "SM2", "Legacy", NULL };

    if (ca_base_dir && ca_base_dir[0]) {
        char path[4128];  /* 4096 + 32 for path suffix */

        /* Top-level certs and index directories */
        snprintf(path, sizeof(path), "%s/certs", ca_base_dir);
        SETUP_DIR_PERMS(path, true);

        snprintf(path, sizeof(path), "%s/index", ca_base_dir);
        SETUP_DIR_PERMS(path, true);

        /* Per-algorithm certs and index directories */
        for (int i = 0; algorithms[i] != NULL; i++) {
            snprintf(path, sizeof(path), "%s/certs/%s", ca_base_dir, algorithms[i]);
            SETUP_DIR_PERMS(path, true);

            snprintf(path, sizeof(path), "%s/index/%s", ca_base_dir, algorithms[i]);
            SETUP_DIR_PERMS(path, true);
        }
    }

    /* Backup directory */
    if (backup_path && backup_path[0]) {
        SETUP_DIR_PERMS(backup_path, true);
    }

    /* Keypool directory */
    if (keypool_path && keypool_path[0]) {
        SETUP_DIR_PERMS(keypool_path, true);
    }

    #undef SETUP_DIR_PERMS

    printf("\n");
    return 0;
}

static int drop_privileges(const char *user, const char *group) {
    struct passwd *pw = NULL;
    struct group *gr = NULL;
    uid_t target_uid = 0;
    gid_t target_gid = 0;

    /* If neither user nor group specified, nothing to do */
    if (!user && !group) {
        return 0;
    }

    /* Get current UID to check if we're root */
    uid_t current_uid = getuid();

    printf("╔════════════════════════════════════════════════════════╗\n");
    printf("║  Dropping Root Privileges                              ║\n");
    printf("╚════════════════════════════════════════════════════════╝\n");
    printf("\n");
    printf("Current UID: %d %s\n", current_uid, current_uid == 0 ? "(root)" : "(non-root)");

    /* Lookup group first (if specified) */
    if (group) {
        gr = getgrnam(group);
        if (!gr) {
            fprintf(stderr, "ERROR: Group '%s' not found\n", group);
            fprintf(stderr, "Create group with: groupadd --system %s\n", group);
            return -1;
        }
        target_gid = gr->gr_gid;
        printf("Target group: %s (gid=%d)\n", group, target_gid);
    }

    /* Lookup user (if specified) */
    if (user) {
        pw = getpwnam(user);
        if (!pw) {
            fprintf(stderr, "ERROR: User '%s' not found\n", user);
            fprintf(stderr, "Create user with: useradd --system --no-create-home %s\n", user);
            return -1;
        }
        target_uid = pw->pw_uid;

        /* If no group specified, use user's primary group */
        if (!group) {
            target_gid = pw->pw_gid;
        }

        printf("Target user: %s (uid=%d, gid=%d)\n", user, target_uid, target_gid);
    }

    /* Check if we're already the target user */
    if (current_uid == target_uid && getgid() == target_gid) {
        printf("Already running as target user/group - no privilege drop needed\n");
        printf("\n");
        return 0;
    }

    /* Check if we have permission to drop privileges */
    if (current_uid != 0 && current_uid != target_uid) {
        fprintf(stderr, "ERROR: Cannot drop privileges from uid=%d to uid=%d\n",
                current_uid, target_uid);
        fprintf(stderr, "Must be root or target user to drop privileges\n");
        return -1;
    }

    /* IMPORTANT: Set GID FIRST, then UID!
     * After setuid(), we lose root privileges and can't setgid() anymore! */

    /* Drop group privileges */
    if (setgid(target_gid) != 0) {
        perror("setgid failed");
        fprintf(stderr, "Failed to set gid to %d\n", target_gid);
        return -1;
    }
    printf("✅ Set GID: %d\n", target_gid);

    /* Drop supplementary groups */
    if (setgroups(0, NULL) != 0) {
        perror("setgroups failed");
        fprintf(stderr, "Failed to drop supplementary groups\n");
        return -1;
    }
    printf("✅ Dropped supplementary groups\n");

    /* Drop user privileges */
    if (setuid(target_uid) != 0) {
        perror("setuid failed");
        fprintf(stderr, "Failed to set uid to %d\n", target_uid);
        return -1;
    }
    printf("✅ Set UID: %d\n", target_uid);

    /* Verify we can't regain root privileges */
    if (setuid(0) == 0) {
        fprintf(stderr, "SECURITY ERROR: Was able to regain root privileges!\n");
        fprintf(stderr, "Privilege dropping FAILED - aborting!\n");
        return -1;
    }
    printf("✅ Verified: Cannot regain root privileges\n");

    /* Verify current UID/GID */
    uid_t final_uid = getuid();
    gid_t final_gid = getgid();

    if (final_uid != target_uid || final_gid != target_gid) {
        fprintf(stderr, "SECURITY ERROR: UID/GID mismatch after drop!\n");
        fprintf(stderr, "Expected: uid=%d, gid=%d\n", target_uid, target_gid);
        fprintf(stderr, "Got: uid=%d, gid=%d\n", final_uid, final_gid);
        return -1;
    }

    printf("\n");
    printf("✅ Privilege drop successful!\n");
    printf("   Running as: uid=%d, gid=%d\n", final_uid, final_gid);
    if (user) {
        printf("   User: %s\n", user);
    }
    if (group) {
        printf("   Group: %s\n", group);
    }
    printf("\n");
    printf("🔒 Security: If compromised, attacker limited to %s privileges\n",
           user ? user : "unprivileged user");
    printf("\n");

    return 0;
}

/* Setup signal handlers */
static void setup_signals(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;

    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGUSR1, &sa, NULL);
    sigaction(SIGHUP, &sa, NULL);  /* Hot-reload (Poolgen: reload TLDs/silent-blocks) */

    /* Ignore SIGPIPE */
    signal(SIGPIPE, SIG_IGN);
}

/* Initialize OpenSSL */
static int init_openssl(void) {
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
    return 0;
}

/* SNI callback for OpenSSL (on-the-fly certificate generation) */
static int sni_callback(SSL *ssl, int *ad, void *arg) {
    (void)ad;
    (void)arg;

    /* CRITICAL FIX: Removed all DEBUG fprintf statements
     * Previously, 9 fprintf calls were executed on EVERY HTTPS connection:
     * - PERFORMANCE: fprintf to stderr is slow (mutex, system call, blocking I/O)
     * - SECURITY: Logged sensitive SNI hostnames (information disclosure)
     * - PRODUCTION: Debug output should not be in production code
     */

    /* Get connection from SSL app_data */
    connection_t *conn = (connection_t*)SSL_get_app_data(ssl);
    if (!conn) {
        return SSL_TLSEXT_ERR_ALERT_FATAL;
    }

    /* Extract SNI from ClientHello */
    const char *servername = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
    if (servername) {
        strncpy(conn->sni, servername, sizeof(conn->sni) - 1);
        conn->sni[sizeof(conn->sni) - 1] = '\0';
    } else {
        conn->sni[0] = '\0';
    }

    /* Generate certificate for SNI hostname
     *
     * None-SNI handling modes (configured in [none-sni] section):
     *   - auto: g_default_domain is updated to current SNI in realtime
     *   - static: g_default_domain is fixed value from config
     *   - disabled: SNI-less clients are rejected
     *
     * In auto mode, SNI-less clients get the last seen SNI domain.
     * This is useful for TLS 1.3 where timing is critical.
     */
    const char *domain;
    if (conn->sni[0] != '\0') {
        /* Client with SNI - use requested hostname */
        domain = conn->sni;

        /* In auto mode: update g_default_domain to current SNI (realtime sync) */
        if (g_default_domain_mode == NONE_SNI_MODE_AUTO) {
            size_t sni_len = strnlen(conn->sni, sizeof(g_default_domain) - 1);
            memcpy(g_default_domain, conn->sni, sni_len);
            g_default_domain[sni_len] = '\0';
        }
    } else {
        /* Client without SNI - handle based on mode */
        switch (g_default_domain_mode) {
            case NONE_SNI_MODE_AUTO:
                /* Use last seen SNI (may be empty on first connection) */
                if (g_default_domain[0] == '\0') {
                    LOG_WARN("SNI-less client rejected: no SNI seen yet (auto mode)");
                    return SSL_TLSEXT_ERR_ALERT_FATAL;
                }
                domain = g_default_domain;
                LOG_DEBUG("SNI-less client using auto domain: %s", domain);
                break;

            case NONE_SNI_MODE_STATIC:
                /* Use configured static domain */
                if (g_default_domain[0] == '\0') {
                    LOG_WARN("SNI-less client rejected: no default-domain configured (static mode)");
                    return SSL_TLSEXT_ERR_ALERT_FATAL;
                }
                domain = g_default_domain;
                LOG_DEBUG("SNI-less client using static domain: %s", domain);
                break;

            case NONE_SNI_MODE_DISABLED:
            default:
                /* Reject SNI-less clients */
                LOG_INFO("SNI-less client rejected (none-sni mode=disabled)");
                return SSL_TLSEXT_ERR_ALERT_FATAL;
        }
    }

    SSL_CTX *ssl_ctx = cert_generator_get_ctx(g_cert_gen, domain, NULL);
    if (!ssl_ctx) {
        return SSL_TLSEXT_ERR_ALERT_FATAL;
    }

    /* ROBUSTNESS FIX: Validate SSL_CTX switch
     * SSL_set_SSL_CTX returns the old context on success, NULL on failure */
    SSL_CTX *old_ctx = SSL_set_SSL_CTX(ssl, ssl_ctx);
    if (!old_ctx) {
        return SSL_TLSEXT_ERR_ALERT_FATAL;
    }

    return SSL_TLSEXT_ERR_OK;
}

/* Cleanup TLS resources */
static void cleanup_tls(void) {
    security_intel_shutdown();  /* Close security log file */
    if (g_default_sslctx) SSL_CTX_free(g_default_sslctx);
    if (g_cert_gen) cert_generator_destroy(g_cert_gen);

    /* Save SHM certcache to disk before cleanup (if master) */
    if (g_shm_certcache && g_master_config && g_master_config->index_master) {
        char index_file[4128];  /* 4096 (max path) + 32 (filename) */
        snprintf(index_file, sizeof(index_file), "%s/shm_certcache.bin",
                 g_saved_index_dir[0] ? g_saved_index_dir : "/tmp");
        certcache_shm_save(g_shm_certcache, index_file);
    }
    if (g_shm_certcache) certcache_shm_cleanup(g_shm_certcache, g_shm_certcache_fd);

    if (g_cert_index) cert_index_destroy(g_cert_index);
    if (g_cert_cache) cert_cache_destroy(g_cert_cache);

    if (g_keypool) keypool_destroy(g_keypool);

    if (g_pki) pki_manager_destroy(g_pki);
}

/* Create listening socket */
static int create_listener(const char *bind_ip, int port) {
    /* Detect IPv4 vs IPv6 */
    int is_ipv6 = (strchr(bind_ip, ':') != NULL);
    int family = is_ipv6 ? AF_INET6 : AF_INET;

    int listen_fd = socket(family, SOCK_STREAM, 0);
    if (listen_fd < 0) {
        perror("socket");
        return -1;
    }

    /* Set socket options */
    int opt = 1;
    if (setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        LOG_WARN("SO_REUSEADDR failed: %s (may cause 'Address already in use' on restart)", strerror(errno));
    }
    if (setsockopt(listen_fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt)) < 0) {
        LOG_WARN("SO_REUSEPORT failed: %s (multi-instance load balancing disabled)", strerror(errno));
    }

    /* TCP HARDENING: Performance + Security */

    /* Disable Nagle algorithm for low latency (critical for HTTPS!) */
    if (setsockopt(listen_fd, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt)) < 0) {
        LOG_WARN("TCP_NODELAY failed: %s (increased latency possible)", strerror(errno));
    }

    /* TCP_DEFER_ACCEPT: Only accept() when data arrives (SYN Flood protection!)
     * Wait up to 3 seconds for client to send data before accept()
     * This prevents accept queue exhaustion attacks */
#ifdef TCP_DEFER_ACCEPT
    int defer_accept = 3;
    if (setsockopt(listen_fd, IPPROTO_TCP, TCP_DEFER_ACCEPT, &defer_accept, sizeof(defer_accept)) < 0) {
        LOG_WARN("TCP_DEFER_ACCEPT not supported (SYN flood protection disabled)");
    }
#endif

    /* TCP Fast Open: Save 1 RTT on connection setup (Linux 3.7+)
     * Queue size 256 for high-performance scenarios */
#ifdef TCP_FASTOPEN
    int fastopen_qlen = 256;
    if (setsockopt(listen_fd, IPPROTO_TCP, TCP_FASTOPEN, &fastopen_qlen, sizeof(fastopen_qlen)) < 0) {
        LOG_WARN("TCP_FASTOPEN not supported (1 RTT overhead on each connection)");
    }
#endif

    /* Increase socket buffers for high-throughput (128KB each)
     * Important for handling 200K+ connections/sec */
    int bufsize = 131072;  /* 128KB */
    if (setsockopt(listen_fd, SOL_SOCKET, SO_RCVBUF, &bufsize, sizeof(bufsize)) < 0) {
        LOG_WARN("SO_RCVBUF failed: %s (using default buffer size)", strerror(errno));
    }
    if (setsockopt(listen_fd, SOL_SOCKET, SO_SNDBUF, &bufsize, sizeof(bufsize)) < 0) {
        LOG_WARN("SO_SNDBUF failed: %s (using default buffer size)", strerror(errno));
    }

    /* Configure IPv6-only mode based on binary type
     * IPv4-optimized binary: N/A (uses AF_INET)
     * IPv6-optimized binary: Enable V6ONLY to avoid port conflicts
     * This allows running IPv4 and IPv6 binaries simultaneously on same ports!
     */
    if (is_ipv6) {
#ifdef IPV6_OPTIMIZED
        /* IPv6-only: strict separation (no IPv4-mapped addresses) */
        int ipv6only = 1;
#else
        /* Dual-stack: accept IPv4-mapped IPv6 addresses */
        int ipv6only = 0;
#endif
        if (setsockopt(listen_fd, IPPROTO_IPV6, IPV6_V6ONLY, &ipv6only, sizeof(ipv6only)) < 0) {
            LOG_WARN("IPV6_V6ONLY failed: %s", strerror(errno));
        }
    }

    /* Bind */
    if (is_ipv6) {
        struct sockaddr_in6 addr6;
        memset(&addr6, 0, sizeof(addr6));
        addr6.sin6_family = AF_INET6;
        addr6.sin6_port = htons(port);

        if (!is_valid_ipv6(bind_ip, &addr6.sin6_addr)) {
            fprintf(stderr, "Invalid IPv6 address: %s\n", bind_ip);
            close(listen_fd);
            return -1;
        }

        if (bind(listen_fd, (struct sockaddr*)&addr6, sizeof(addr6)) < 0) {
            perror("bind");
            close(listen_fd);
            return -1;
        }
    } else {
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);

        if (!is_valid_ipv4(bind_ip, &addr.sin_addr)) {
            fprintf(stderr, "Invalid IPv4 address: %s\n", bind_ip);
            close(listen_fd);
            return -1;
        }

        if (bind(listen_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
            perror("bind");
            close(listen_fd);
            return -1;
        }
    }

    /* Listen with large backlog for DDoS resilience
     * 65535 (max) instead of 4096 to prevent accept queue exhaustion
     * Combined with TCP_DEFER_ACCEPT for SYN flood protection */
    if (listen(listen_fd, 65535) < 0) {
        perror("listen");
        close(listen_fd);
        return -1;
    }

    printf("Listening on %s:%d (TCP)\n", bind_ip, port);
    return listen_fd;
}

/* Create UDP listening socket for QUIC/HTTP3 blocking */
static int create_udp_listener(const char *bind_ip, int port) {
    /* Detect IPv4 vs IPv6 */
    int is_ipv6 = (strchr(bind_ip, ':') != NULL);
    int family = is_ipv6 ? AF_INET6 : AF_INET;

    int udp_fd = socket(family, SOCK_DGRAM, 0);
    if (udp_fd < 0) {
        perror("socket (UDP)");
        return -1;
    }

    /* Set socket options */
    int opt = 1;
    setsockopt(udp_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    setsockopt(udp_fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));

    /* Configure IPv6-only mode (same as TCP) */
    if (is_ipv6) {
#ifdef IPV6_OPTIMIZED
        int ipv6only = 1;  /* IPv6-only for separate binaries */
#else
        int ipv6only = 0;  /* Dual-stack mode */
#endif
        setsockopt(udp_fd, IPPROTO_IPV6, IPV6_V6ONLY, &ipv6only, sizeof(ipv6only));
    }

    /* Bind */
    if (is_ipv6) {
        struct sockaddr_in6 addr6;
        memset(&addr6, 0, sizeof(addr6));
        addr6.sin6_family = AF_INET6;
        addr6.sin6_port = htons(port);

        if (!is_valid_ipv6(bind_ip, &addr6.sin6_addr)) {
            fprintf(stderr, "Invalid IPv6 address: %s\n", bind_ip);
            close(udp_fd);
            return -1;
        }

        if (bind(udp_fd, (struct sockaddr*)&addr6, sizeof(addr6)) < 0) {
            perror("bind (UDP)");
            close(udp_fd);
            return -1;
        }
    } else {
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);

        if (!is_valid_ipv4(bind_ip, &addr.sin_addr)) {
            fprintf(stderr, "Invalid IPv4 address: %s\n", bind_ip);
            close(udp_fd);
            return -1;
        }

        if (bind(udp_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
            perror("bind (UDP)");
            close(udp_fd);
            return -1;
        }
    }

    /* SECURITY FIX: Check fcntl return values */
    int flags = fcntl(udp_fd, F_GETFL, 0);
    if (flags < 0) {
        perror("fcntl (F_GETFL)");
        close(udp_fd);
        return -1;
    }

    if (fcntl(udp_fd, F_SETFL, flags | O_NONBLOCK) < 0) {
        perror("fcntl (F_SETFL)");
        close(udp_fd);
        return -1;
    }

    printf("Listening on %s:%d (UDP - QUIC blocking)\n", bind_ip, port);
    return udp_fd;
}

/* Socket info for epoll (socket_type_t defined in connection.h) */
typedef struct {
    int fd;
    socket_type_t type;
} socket_info_t;

/* Main accept loop - handles TCP + UDP listening sockets with epoll */
static void accept_loop(int http_fd, int https_fd, int auto_fd, int auto_udp_fd,
                        worker_t **workers, int worker_count) {
    int next_worker = 0;

    /* Create epoll for listening sockets */
    int epoll_fd = epoll_create1(0);
    if (epoll_fd < 0) {
        perror("epoll_create1");
        return;
    }

    /* Register enabled listening sockets in epoll (skip disabled ports with fd=-1) */
    socket_info_t http_info = { .fd = http_fd, .type = SOCKET_TYPE_HTTP };
    socket_info_t https_info = { .fd = https_fd, .type = SOCKET_TYPE_HTTPS };
    socket_info_t auto_info = { .fd = auto_fd, .type = SOCKET_TYPE_AUTO };
    socket_info_t auto_udp_info = { .fd = auto_udp_fd, .type = SOCKET_TYPE_AUTO_UDP };

    struct epoll_event ev;
    ev.events = EPOLLIN;

    int enabled_ports = 0;

    if (http_fd >= 0) {
        ev.data.ptr = &http_info;
        if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, http_fd, &ev) < 0) {
            perror("epoll_ctl HTTP");
            close(epoll_fd);
            return;
        }
        enabled_ports++;
    }

    if (https_fd >= 0) {
        ev.data.ptr = &https_info;
        if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, https_fd, &ev) < 0) {
            perror("epoll_ctl HTTPS");
            close(epoll_fd);
            return;
        }
        enabled_ports++;
    }

    if (auto_fd >= 0) {
        ev.data.ptr = &auto_info;
        if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, auto_fd, &ev) < 0) {
            perror("epoll_ctl AUTO TCP");
            close(epoll_fd);
            return;
        }
        enabled_ports++;

        /* Register AUTO UDP if available */
        if (auto_udp_fd >= 0) {
            ev.data.ptr = &auto_udp_info;
            if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, auto_udp_fd, &ev) < 0) {
                perror("epoll_ctl AUTO UDP");
                close(epoll_fd);
                return;
            }
        }
    }

    printf("Starting accept loop (%d enabled port%s", enabled_ports, enabled_ports > 1 ? "s" : "");
    if (auto_udp_fd >= 0) {
        printf(" + UDP QUIC blocking");
    }
    printf(")\n");
    printf("Round-robin to %d workers\n", worker_count);

    struct epoll_event events[16];  /* Handle up to 16 simultaneous accepts */

    while (atomic_load_explicit(&g_running, memory_order_acquire)) {
        /* Use 1 second timeout instead of -1 (infinite) to allow graceful shutdown */
        int nfds = epoll_wait(epoll_fd, events, 16, 1000);

        if (nfds < 0) {
            if (errno == EINTR) continue;
            perror("epoll_wait");
            break;
        }

        /* Timeout (nfds == 0) - check g_running flag and send heartbeat */
        if (nfds == 0) {
            /* Process any pending signal actions (SIGUSR1 stats, SIGHUP reload) */
            process_signal_actions();

            /* Send heartbeat every WORKER_HEARTBEAT_INTERVAL seconds */
            if (g_worker_slot >= 0 && g_watchdog_pool != NULL) {
                time_t now = time(NULL);
                if (now - g_last_heartbeat >= WORKER_HEARTBEAT_INTERVAL) {
                    worker_heartbeat(g_watchdog_pool, g_worker_slot);
                    g_last_heartbeat = now;
                }
            }
            continue;
        }

        /* Handle all ready sockets */
        for (int i = 0; i < nfds; i++) {
            socket_info_t *sock_info = (socket_info_t*)events[i].data.ptr;

            /* UDP socket - QUIC/HTTP3 handled by HAProxy
             *
             * QUIC/HTTP3 traffic is terminated at HAProxy level (passthrough mode)
             * This server only handles HTTP/1.1 and HTTP/2 over TCP
             * UDP sockets should not be present in production configuration
             */
            if (sock_info->type == SOCKET_TYPE_AUTO_UDP) {
                /* Drain UDP socket to prevent buffer overflow, but ignore data */
                char discard_buf[2048];
                struct sockaddr_storage client_addr;
                socklen_t client_len = sizeof(client_addr);
                recvfrom(sock_info->fd, discard_buf, sizeof(discard_buf), 0,
                        (struct sockaddr*)&client_addr, &client_len);
                continue;  /* Skip UDP packets - HAProxy handles QUIC */
            }

            /* TCP socket - standard accept */
            struct sockaddr_storage client_addr;
            socklen_t client_len = sizeof(client_addr);

            int client_fd = accept(sock_info->fd, (struct sockaddr*)&client_addr, &client_len);

            if (client_fd < 0) {
                if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) continue;
                perror("accept");
                continue;
            }

            /* Extract remote IP address (IPv4/IPv6) */
            char remote_addr[64] = {0};
            if (client_addr.ss_family == AF_INET) {
                /* IPv4 */
                struct sockaddr_in *addr_in = (struct sockaddr_in*)&client_addr;
                inet_ntop(AF_INET, &addr_in->sin_addr, remote_addr, sizeof(remote_addr));
            } else if (client_addr.ss_family == AF_INET6) {
                /* IPv6 */
                struct sockaddr_in6 *addr_in6 = (struct sockaddr_in6*)&client_addr;
                inet_ntop(AF_INET6, &addr_in6->sin6_addr, remote_addr, sizeof(remote_addr));
            }

            /* TCP HARDENING for accepted connections: Anti-Slowloris + Anti-Zombie */

            /* Performance: Disable Nagle algorithm for low latency */
            int opt = 1;
            setsockopt(client_fd, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt));

            /* Performance: Enable quick ACK (reduce latency) */
#ifdef TCP_QUICKACK
            setsockopt(client_fd, IPPROTO_TCP, TCP_QUICKACK, &opt, sizeof(opt));
#endif

            /* SECURITY: Read/Write timeouts to prevent Slowloris attack
             * 30 second timeout - aggressive but necessary for DDoS protection */
            struct timeval timeout;
            timeout.tv_sec = 30;
            timeout.tv_usec = 0;
            setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
            setsockopt(client_fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

            /* SECURITY: SO_LINGER with timeout 0 = immediate RST on close
             * Prevents TIME_WAIT and FIN_WAIT_2 zombie connections */
            struct linger sl;
            sl.l_onoff = 1;
            sl.l_linger = 0;
            setsockopt(client_fd, SOL_SOCKET, SO_LINGER, &sl, sizeof(sl));

            /* SECURITY: TCP_USER_TIMEOUT - kill dead connections after 30s
             * Detects network failures faster than keep-alive alone */
#ifdef TCP_USER_TIMEOUT
            int user_timeout = 30000;  /* 30 seconds in milliseconds */
            setsockopt(client_fd, IPPROTO_TCP, TCP_USER_TIMEOUT, &user_timeout, sizeof(user_timeout));
#endif

            /* SECURITY: Enable keep-alive to detect dead connections
             * Probes: 3 attempts, every 10s, starting after 60s idle */
            setsockopt(client_fd, SOL_SOCKET, SO_KEEPALIVE, &opt, sizeof(opt));
#ifdef TCP_KEEPCNT
            int keepcnt = 3;
            int keepidle = 60;
            int keepintvl = 10;
            setsockopt(client_fd, IPPROTO_TCP, TCP_KEEPCNT, &keepcnt, sizeof(keepcnt));
            setsockopt(client_fd, IPPROTO_TCP, TCP_KEEPIDLE, &keepidle, sizeof(keepidle));
            setsockopt(client_fd, IPPROTO_TCP, TCP_KEEPINTVL, &keepintvl, sizeof(keepintvl));
#endif

            /* Distribute to worker (round-robin) */
            worker_t *worker = workers[next_worker];
            next_worker = (next_worker + 1) % worker_count;

            /* Add connection with socket type info and remote address */
            if (worker_add_connection_ex(worker, client_fd, sock_info->type, remote_addr) < 0) {
                close(client_fd);
            }
        }
    }

    close(epoll_fd);
}

/* Check configuration and permissions */
static int check_configuration(const config_t *config) {
    int errors = 0;
    int warnings = 0;

    printf("╔═══════════════════════════════════════════════════════════════╗\n");
    printf("║  TLSGate NG v%s - Configuration Test                     ║\n", TLSGATENG_VERSION_STRING);
    printf("╚═══════════════════════════════════════════════════════════════╝\n");
    printf("\n");
    printf("Testing configuration for worker directory: %s\n", config->ca_base_dir);
    printf("\n");

    /* Check worker base directory */
    printf("Checking worker directory...\n");
    if (access(config->ca_base_dir, F_OK) != 0) {
        printf("  ❌ ERROR: Worker directory does not exist: %s\n", config->ca_base_dir);
        errors++;
    } else if (access(config->ca_base_dir, W_OK) != 0) {
        printf("  ⚠️  WARNING: Worker directory is not writable: %s\n", config->ca_base_dir);
        printf("      (needed for certificate storage)\n");
        warnings++;
    } else {
        printf("  ✅ Worker directory exists and is writable\n");
    }

    /* Check CA directory */
    char ca_dir[4128];  /* 4096 + 32 for path suffix */
    snprintf(ca_dir, sizeof(ca_dir), "%s/rootCA", config->ca_base_dir);
    printf("\nChecking CA directory...\n");
    if (access(ca_dir, F_OK) != 0) {
        printf("  ❌ ERROR: CA directory does not exist: %s/\n", ca_dir);
        errors++;
    } else {
        printf("  ✅ CA directory exists: %s/\n", ca_dir);
    }

    /* Check CA certificate - multiple formats supported (same as ca_loader.c) */
    const char *cert_names[] = { "ca.crt", "ca.pem", "rootca.crt", "rootca.pem",
                                 "RootCA.crt", "RootCA.pem", "subca.crt", "subca.pem",
                                 "SubCA.crt", "SubCA.pem", NULL };
    char ca_cert_path[4128];  /* 4096 + 32 for path suffix */
    bool found_cert = false;
    printf("\nChecking CA certificate...\n");
    for (int i = 0; cert_names[i] != NULL; i++) {
        snprintf(ca_cert_path, sizeof(ca_cert_path), "%s/rootCA/%s", config->ca_base_dir, cert_names[i]);
        if (access(ca_cert_path, R_OK) == 0) {
            printf("  ✅ CA certificate found: %s\n", ca_cert_path);
            found_cert = true;
            break;
        }
    }
    if (!found_cert) {
        printf("  ❌ ERROR: No CA certificate found in %s/rootCA/\n", config->ca_base_dir);
        printf("      Expected one of: ca.crt, rootca.crt, RootCA.crt, subca.crt, SubCA.crt\n");
        errors++;
    }

    /* Check CA private key - multiple formats supported */
    const char *key_names[] = { "ca.key", "ca-key.pem", "rootca.key", "RootCA.key",
                                "subca.key", "SubCA.key", NULL };
    char ca_key_path[4128];  /* 4096 + 32 for path suffix */
    bool found_key = false;
    printf("\nChecking CA private key...\n");
    for (int i = 0; key_names[i] != NULL; i++) {
        snprintf(ca_key_path, sizeof(ca_key_path), "%s/rootCA/%s", config->ca_base_dir, key_names[i]);
        if (access(ca_key_path, R_OK) == 0) {
            printf("  ✅ CA private key found: %s\n", ca_key_path);
            found_key = true;
            break;
        }
    }
    if (!found_key) {
        printf("  ❌ ERROR: No CA private key found in %s/rootCA/\n", config->ca_base_dir);
        printf("      Expected one of: ca.key, ca-key.pem, rootca.key, subca.key\n");
        errors++;
    }

    /* Check for Cross-Signed SubCA certificate (optional) */
    const char *cs_names[] = { "subca.cs.crt", "subca.cs.pem", "SubCA.cs.crt", "SubCA.cs.pem",
                               "ca.cs.crt", "ca.cs.pem", NULL };
    char cs_cert_path[4128];
    bool found_cs = false;
    printf("\nChecking Cross-Signed certificate (optional)...\n");
    for (int i = 0; cs_names[i] != NULL; i++) {
        snprintf(cs_cert_path, sizeof(cs_cert_path), "%s/rootCA/%s", config->ca_base_dir, cs_names[i]);
        if (access(cs_cert_path, R_OK) == 0) {
            printf("  ✅ Cross-Signed cert found: %s\n", cs_cert_path);
            found_cs = true;
            break;
        }
    }
    if (!found_cs) {
        printf("  ℹ️  No Cross-Signed certificate (optional - not required)\n");
        printf("      Expected one of: subca.cs.crt, SubCA.cs.crt, ca.cs.crt\n");
    }

    /* Check server-wide prime pool directory (must exist, files optional) */
    const char *prime_dir = config->prime_pool_dir;
    printf("\nChecking prime pool directory...\n");
    if (!prime_dir || !prime_dir[0]) {
        printf("  ⚠️  WARNING: Prime pool directory not configured\n");
        printf("      (optional - RSA generation will be slower without primes)\n");
        warnings++;
    } else if (access(prime_dir, F_OK) != 0) {
        printf("  ⚠️  WARNING: Prime pool directory not found: %s/\n", prime_dir);
        printf("      (optional - RSA generation will be slower without primes)\n");
        warnings++;
    } else {
        printf("  ✅ Prime pool directory exists: %s/\n", prime_dir);

        /* Check for prime files (optional - just informational)
         * Format: prime-{1024,2048,3072,4096,8192,16384}.bin */
        const int prime_sizes[] = {1024, 2048, 3072, 4096, 8192, 16384, 0};
        int found_primes = 0;
        printf("      Prime files found:\n");
        for (int i = 0; prime_sizes[i] != 0; i++) {
            char prime_file[PATH_MAX + 32];
            snprintf(prime_file, sizeof(prime_file), "%s/prime-%d.bin", prime_dir, prime_sizes[i]);
            if (access(prime_file, R_OK) == 0) {
                printf("        ✅ prime-%d.bin\n", prime_sizes[i]);
                found_primes++;
            }
        }
        if (found_primes == 0) {
            printf("        (none found - RSA generation will be slower)\n");
            printf("      Generate with: tlsgateNG-poolgen --generate-primes\n");
        }
    }

    /* Check server-wide keypool directory (must exist, files optional) */
    const char *keypool_dir = config->bundle_dir;
    printf("\nChecking keypool directory...\n");
    if (!keypool_dir || !keypool_dir[0]) {
        printf("  ⚠️  WARNING: Keypool directory not configured\n");
        printf("      (optional - keys will be generated on-demand)\n");
        warnings++;
    } else if (access(keypool_dir, F_OK) != 0) {
        printf("  ⚠️  WARNING: Keypool directory not found: %s/\n", keypool_dir);
        printf("      (optional - keys will be generated on-demand)\n");
        warnings++;
    } else {
        printf("  ✅ Keypool directory exists: %s/\n", keypool_dir);
        printf("      (bundle files optional - will generate on-demand if missing)\n");
    }

    /* Summary */
    printf("\n");
    printf("═══════════════════════════════════════════════════════════════\n");
    if (errors == 0 && warnings == 0) {
        printf("✅ All checks passed! Configuration is ready.\n");
    } else if (errors == 0) {
        printf("✅ All required checks passed! (%d warning(s))\n", warnings);
    } else {
        printf("❌ Configuration test failed! %d error(s), %d warning(s)\n", errors, warnings);
    }
    printf("═══════════════════════════════════════════════════════════════\n");
    printf("\n");

    return (errors == 0) ? 0 : 1;
}

/* Print version information */
/* print_version() moved to src/version.c - see version.h */

/* Count files matching a pattern in directory
 *
 * Returns: number of matching files, or -1 on error
 */
static int count_files_matching(const char *dir_path, const char *pattern) {
    DIR *dir = opendir(dir_path);
    if (!dir) {
        return -1;
    }

    int count = 0;
    struct dirent *entry;
    errno = 0;  /* Clear errno before reading */
    while ((entry = readdir(dir)) != NULL) {
        /* Skip . and .. */
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        /* Check if filename contains pattern */
        if (strstr(entry->d_name, pattern) != NULL) {
            count++;
        }
    }

    /* Check for readdir() error (NULL with errno set) */
    int error = errno;
    closedir(dir);

    if (error != 0) {
        fprintf(stderr, "Error reading directory %s: %s\n", dir_path, strerror(error));
        return -1;  /* Error occurred */
    }

    return count;
}

/* Count prime pool files (prime-{size}.bin)
 *
 * Returns: number of prime files found
 */
static int count_prime_files(const char *dir_path) {
    return count_files_matching(dir_path, "prime-");
}

/* Count bundle files (keys.*.bundle.gz)
 *
 * Returns: number of bundle files found
 */
static int count_bundle_files(const char *dir_path) {
    return count_files_matching(dir_path, ".bundle.gz");
}

/* Print SHM keypool status (read-only attach) */
static void print_shm_status(void) {
    printf("TLSGate NG - SHM Keypool Status\n");
    printf("═══════════════════════════════════════════════════════════════\n\n");

    /* Try to attach to existing SHM (read-only) */
    int fd = shm_open("/tlsgateNG_keypool", O_RDONLY, 0600);
    if (fd < 0) {
        printf("❌ SHM Keypool not found (/dev/shm/tlsgateNG_keypool)\n");
        printf("   The poolgen service may not be running or SHM was cleared after reboot.\n");
        return;
    }

    /* Get SHM size */
    struct stat st;
    if (fstat(fd, &st) < 0) {
        printf("❌ Failed to stat SHM: %s\n", strerror(errno));
        close(fd);
        return;
    }

    /* Map read-only */
    keypool_shm_t *shm = mmap(NULL, st.st_size, PROT_READ, MAP_SHARED, fd, 0);
    close(fd);

    if (shm == MAP_FAILED) {
        printf("❌ Failed to map SHM: %s\n", strerror(errno));
        return;
    }

    /* Validate magic */
    if (shm->magic != SHM_KEYPOOL_MAGIC) {
        printf("❌ Invalid SHM magic (corrupted or wrong version)\n");
        munmap(shm, st.st_size);
        return;
    }

    /* Read stats (atomic) */
    int available = atomic_load_explicit(&shm->available, memory_order_acquire);
    int capacity = shm->capacity;
    double pct = (capacity > 0) ? (100.0 * available / capacity) : 0.0;

    /* Count keys by algorithm */
    int count_rsa_1024 = 0, count_rsa_2048 = 0, count_rsa_3072 = 0;
    int count_rsa_4096 = 0, count_rsa_8192 = 0, count_rsa_16384 = 0;
    int count_ecdsa_p256 = 0, count_ecdsa_p384 = 0, count_ecdsa_p521 = 0;
    int count_sm2 = 0, count_ed25519 = 0, count_auto = 0, count_unknown = 0;

    for (int i = 0; i < capacity; i++) {
        int offset = atomic_load_explicit(&shm->key_offsets[i], memory_order_acquire);
        if (offset < 0) continue;  /* Empty slot */

        int alg = atomic_load_explicit(&shm->key_algorithms[i], memory_order_acquire);
        switch (alg) {
            case CRYPTO_ALG_RSA_1024:   count_rsa_1024++; break;
            case CRYPTO_ALG_RSA_2048:   count_rsa_2048++; break;
            case CRYPTO_ALG_RSA_3072:   count_rsa_3072++; break;
            case CRYPTO_ALG_RSA_4096:   count_rsa_4096++; break;
            case CRYPTO_ALG_RSA_8192:   count_rsa_8192++; break;
            case CRYPTO_ALG_RSA_16384:  count_rsa_16384++; break;
            case CRYPTO_ALG_ECDSA_P256: count_ecdsa_p256++; break;
            case CRYPTO_ALG_ECDSA_P384: count_ecdsa_p384++; break;
            case CRYPTO_ALG_ECDSA_P521: count_ecdsa_p521++; break;
            case CRYPTO_ALG_SM2:        count_sm2++; break;
            case CRYPTO_ALG_ED25519:    count_ed25519++; break;
            case CRYPTO_ALG_AUTO:       count_auto++; break;
            default:                    count_unknown++; break;
        }
    }

    /* Print summary */
    printf("Pool Status:\n");
    printf("  Total:    %d / %d keys (%.1f%%)\n", available, capacity, pct);
    printf("  SHM Size: %.2f GB\n", (double)st.st_size / (1024*1024*1024));
    printf("\n");

    /* Progress bar */
    printf("  [");
    int bar_width = 50;
    int filled = (int)(pct / 100.0 * bar_width);
    for (int i = 0; i < bar_width; i++) {
        if (i < filled) printf("█");
        else printf("░");
    }
    printf("] %.1f%%\n\n", pct);

    /* Breakdown by algorithm */
    printf("Keys by Algorithm:\n");
    if (count_rsa_1024 > 0)   printf("  RSA-1024:    %9d (legacy)\n", count_rsa_1024);
    if (count_rsa_2048 > 0)   printf("  RSA-2048:    %9d (legacy)\n", count_rsa_2048);
    if (count_rsa_3072 > 0)   printf("  RSA-3072:    %9d\n", count_rsa_3072);
    if (count_rsa_4096 > 0)   printf("  RSA-4096:    %9d\n", count_rsa_4096);
    if (count_rsa_8192 > 0)   printf("  RSA-8192:    %9d\n", count_rsa_8192);
    if (count_rsa_16384 > 0)  printf("  RSA-16384:   %9d (demo)\n", count_rsa_16384);
    if (count_ecdsa_p256 > 0) printf("  ECDSA-P256:  %9d\n", count_ecdsa_p256);
    if (count_ecdsa_p384 > 0) printf("  ECDSA-P384:  %9d\n", count_ecdsa_p384);
    if (count_ecdsa_p521 > 0) printf("  ECDSA-P521:  %9d\n", count_ecdsa_p521);
    if (count_sm2 > 0)        printf("  SM2:         %9d\n", count_sm2);
    if (count_ed25519 > 0)    printf("  Ed25519:     %9d\n", count_ed25519);
    if (count_auto > 0)       printf("  Auto:        %9d (undetected algorithm)\n", count_auto);
    if (count_unknown > 0)    printf("  Unknown:     %9d (invalid algorithm ID)\n", count_unknown);
    printf("\n");

    /* Generator info */
    printf("Generator:\n");
    int keygen_pid = atomic_load_explicit(&shm->keygen_pid, memory_order_acquire);
    bool is_keygen = atomic_load_explicit(&shm->is_keygen, memory_order_acquire);
    long long last_hb = atomic_load_explicit(&shm->last_keygen_heartbeat, memory_order_acquire);
    time_t now = time(NULL);
    long hb_age = (last_hb > 0) ? (now - last_hb) : -1;

    if (keygen_pid > 0 && is_keygen) {
        printf("  PID:        %d\n", keygen_pid);
        if (hb_age >= 0) {
            printf("  Heartbeat:  %ld seconds ago%s\n", hb_age,
                   hb_age > 120 ? " ⚠️  (stale)" : " ✅");
        }
    } else {
        printf("  Status:     ❌ No active generator\n");
    }
    printf("\n");

    /* Restore locks status (refill waits for all to be cleared) */
    printf("Restore Locks:\n");
    bool shm_backup_lock = atomic_load_explicit(&shm->restore_lock_shm_backup, memory_order_acquire);
    bool keybundle_lock = atomic_load_explicit(&shm->restore_lock_keybundle, memory_order_acquire);
    bool prime_lock = atomic_load_explicit(&shm->restore_lock_prime, memory_order_acquire);

    printf("  SHM-Backup: %s\n", shm_backup_lock ? "🔒 locked (pending)" : "✅ cleared");
    printf("  Keybundle:  %s\n", keybundle_lock ? "🔒 locked (pending)" : "✅ cleared");
    printf("  Prime:      %s\n", prime_lock ? "🔒 locked (pending)" : "✅ cleared");

    if (!shm_backup_lock && !keybundle_lock && !prime_lock) {
        printf("  Refill:     ✅ All locks cleared - refill can run\n");
    } else {
        printf("  Refill:     ⏳ Waiting for locks to clear...\n");
    }

    munmap(shm, st.st_size);
}

/* Print system status */
static void print_status(const config_file_t *master_config, const config_t *config) {
    printf("TLSGate NG v%s - System Status\n", TLSGATENG_VERSION_STRING);
    printf("═══════════════════════════════════════════════════════════════\n\n");

    /* Master Configuration */
    printf("Master Configuration:\n");
    printf("  File: %s\n", master_config->config_path);
    if (master_config->loaded) {
        printf("  Status: ✅ Loaded\n");
        printf("  Version: %d.%d.%d.%d (MATCH)\n",
               master_config->version_major, master_config->version_minor,
               master_config->version_patch, master_config->version_build);
    } else {
        printf("  Status: ⚠️  Empty template (all features disabled)\n");
    }
    printf("\n");

    /* Prime Pool Status */
    printf("Prime Pool:\n");
    if (config->prime_pool_dir && config->prime_pool_dir[0]) {
        printf("  Path: %s\n", config->prime_pool_dir);
        if (access(config->prime_pool_dir, F_OK) == 0) {
            int prime_count = count_prime_files(config->prime_pool_dir);
            if (prime_count > 0) {
                printf("  Status: ✅ Directory exists (%d prime files found)\n", prime_count);
            } else {
                printf("  Status: ⚠️  Directory exists (no prime files found)\n");
            }
        } else {
            printf("  Status: ❌ Directory not found\n");
        }
    } else {
        printf("  Status: ⚠️  Disabled (no path configured)\n");
    }
    printf("\n");

    /* Keypool Status */
    printf("Keypool:\n");
    if (config->bundle_dir && config->bundle_dir[0]) {
        printf("  Path: %s\n", config->bundle_dir);
        if (access(config->bundle_dir, F_OK) == 0) {
            int bundle_count = count_bundle_files(config->bundle_dir);
            if (bundle_count > 0) {
                printf("  Status: ✅ Directory exists (%d bundle files found)\n", bundle_count);
            } else {
                printf("  Status: ⚠️  Directory exists (no bundle files found)\n");
            }
        } else {
            printf("  Status: ❌ Directory not found\n");
        }
    } else {
        printf("  Status: ⚠️  Disabled (no path configured)\n");
    }
    printf("\n");

    /* CA Status - check multi-CA structure (RSA/ECDSA/SM2 subdirs) */
    printf("Certificate Authority:\n");
    printf("  Base directory: %s\n", config->ca_base_dir);
    char ca_cert_path[4128];  /* 4096 + 32 for path suffix */
    char ca_key_path[4128];   /* 4096 + 32 for path suffix */

    /* Try multi-CA structure first: {base}/RSA/rootCA/subca.crt */
    snprintf(ca_cert_path, sizeof(ca_cert_path), "%s/RSA/rootCA/subca.crt", config->ca_base_dir);
    snprintf(ca_key_path, sizeof(ca_key_path), "%s/RSA/rootCA/subca.key", config->ca_base_dir);

    /* Fallback to old single-CA structure: {base}/rootCA/ca.crt */
    if (access(ca_cert_path, R_OK) != 0) {
        snprintf(ca_cert_path, sizeof(ca_cert_path), "%s/rootCA/subca.crt", config->ca_base_dir);
        snprintf(ca_key_path, sizeof(ca_key_path), "%s/rootCA/subca.key", config->ca_base_dir);
    }
    if (access(ca_cert_path, R_OK) != 0) {
        snprintf(ca_cert_path, sizeof(ca_cert_path), "%s/rootCA/ca.crt", config->ca_base_dir);
        snprintf(ca_key_path, sizeof(ca_key_path), "%s/rootCA/ca-key.pem", config->ca_base_dir);
    }

    if (access(ca_cert_path, R_OK) == 0 && access(ca_key_path, R_OK) == 0) {
        printf("  CA Certificate: ✅ %s\n", ca_cert_path);
        printf("  CA Private Key: ✅ %s\n", ca_key_path);
        printf("  Status: ✅ Ready\n");
    } else {
        printf("  CA Certificate: %s %s\n",
               access(ca_cert_path, R_OK) == 0 ? "✅" : "❌",
               ca_cert_path);
        printf("  CA Private Key: %s %s\n",
               access(ca_key_path, R_OK) == 0 ? "✅" : "❌",
               ca_key_path);
        printf("  Status: ❌ CA not found\n");
    }
    printf("\n");

    /* Runtime Configuration */
    printf("Runtime Configuration:\n");
    printf("  Listen address: %s\n", config->listen_addr);
    printf("  HTTP port: %d\n", config->http_port);
    printf("  HTTPS port: %d\n", config->https_port);
    printf("  Worker count: %d\n", config->worker_count);
    printf("  Max connections: %d\n", config->max_connections);
    printf("  Shared memory keypool: %s\n", config->use_shm_keypool ? "yes" : "no");
    printf("  Keypool generator mode: %s\n", config->is_keygen ? "yes" : "no");
    printf("\n");

    printf("═══════════════════════════════════════════════════════════════\n");
}

/* Print usage */
/* print_usage() moved to src/version.c - see version.h for function declaration */

/* Silent check for tlsgateNG user/group - NO LOGGING AT ALL!
 * This is a fun Easter egg with zero trace in logs or debug output */
static void check_tlsgateNG_user_silent(void) {
    struct passwd *pwd = getpwnam("tlsgateNG");
    struct group *grp = getgrnam("tlsgateNG");

    if (!pwd || !grp) {
        fprintf(stderr, "\n");
        fprintf(stderr, "╔═══════════════════════════════════════════════════════════════╗\n");
        fprintf(stderr, "║  ⚠️  SECURITY ALERT - ILLEGAL COPY DETECTED                  ║\n");
        fprintf(stderr, "╚═══════════════════════════════════════════════════════════════╝\n");
        fprintf(stderr, "\n");
        fprintf(stderr, "Hold on... detecting an illegal copy of TLSGate.\n");
        fprintf(stderr, "That's evil. Authorities have been alerted.\n");
        fprintf(stderr, "Look forward to three square meals a day for the next 20 years.\n");
        fprintf(stderr, "\n");
        fprintf(stderr, "Click your choice:\n");
        fprintf(stderr, "\n");
        fprintf(stderr, "  [ ] I surrender\n");
        fprintf(stderr, "  [ ] I don't like prison food\n");
        fprintf(stderr, "  [ ] I buy a License immediately for the double price\n");
        fprintf(stderr, "\n");
        fprintf(stderr, "Enter choice (1-3): ");
        fflush(stderr);

        int choice;
        if (scanf("%d", &choice) != 1) {
            fprintf(stderr, "\nInvalid choice. Prison it is!\n");
            exit(1);
        }

        fprintf(stderr, "\n");
        switch (choice) {
            case 1:
                fprintf(stderr, "Smart choice, but we remain unimpressed. Try again.\n");
                break;
            case 2:
                fprintf(stderr, "Too bad. Give it 3 or 4 months, and you'll learn to love the taste. Or... try again.\n");
                break;
            case 3:
                fprintf(stderr, "Excellent! Create the user, place the order, pay the bill and activate your license.\n");
                break;
            default:
                fprintf(stderr, "Invalid choice. Are your hands shaking? Try again.\n");
        }
        fprintf(stderr, "\n");
        exit(1);
    }
}

/* Parse algorithm name to crypto_alg_t */
static crypto_alg_t parse_algorithm(const char *name) {
    if (!name) return CRYPTO_ALG_AUTO;

    /* Convert to uppercase for case-insensitive matching */
    if (strcasecmp(name, "RSA-1024") == 0 || strcasecmp(name, "RSA1024") == 0) {
        return CRYPTO_ALG_RSA_1024;
    } else if (strcasecmp(name, "RSA-2048") == 0 || strcasecmp(name, "RSA2048") == 0) {
        return CRYPTO_ALG_RSA_2048;
    } else if (strcasecmp(name, "RSA-3072") == 0 || strcasecmp(name, "RSA3072") == 0) {
        return CRYPTO_ALG_RSA_3072;
    } else if (strcasecmp(name, "RSA-4096") == 0 || strcasecmp(name, "RSA4096") == 0) {
        return CRYPTO_ALG_RSA_4096;
    } else if (strcasecmp(name, "RSA-8192") == 0 || strcasecmp(name, "RSA8192") == 0) {
        return CRYPTO_ALG_RSA_8192;
    } else if (strcasecmp(name, "RSA-16384") == 0 || strcasecmp(name, "RSA16384") == 0) {
        return CRYPTO_ALG_RSA_16384;
    } else if (strcasecmp(name, "ECDSA-P256") == 0 || strcasecmp(name, "P256") == 0) {
        return CRYPTO_ALG_ECDSA_P256;
    } else if (strcasecmp(name, "ECDSA-P384") == 0 || strcasecmp(name, "P384") == 0) {
        return CRYPTO_ALG_ECDSA_P384;
    } else if (strcasecmp(name, "ECDSA-P521") == 0 || strcasecmp(name, "P521") == 0) {
        return CRYPTO_ALG_ECDSA_P521;
    } else if (strcasecmp(name, "SM2") == 0) {
        return CRYPTO_ALG_SM2;
    } else if (strcasecmp(name, "AUTO") == 0) {
        return CRYPTO_ALG_AUTO;
    } else {
        fprintf(stderr, "Error: Unknown algorithm '%s'\n", name);
        fprintf(stderr, "Supported algorithms: RSA-3072, RSA-4096, RSA-8192, RSA-16384, ");
        fprintf(stderr, "ECDSA-P256, ECDSA-P384, ECDSA-P521, SM2, AUTO\n");
        return CRYPTO_ALG_AUTO;
    }
}

/* Check if file is readable */
static bool is_file_readable(const char *path) {
    return (access(path, R_OK) == 0);
}

/* Validate and display configuration */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-truncation"
static int validate_config(const config_t *config, const config_file_t *master_config) {
    printf("\n╔════════════════════════════════════════════════════════════════╗\n");
    printf("║  TLSGate NG v%s - Quick Configuration Check             ║\n", TLSGATENG_VERSION_STRING);
    printf("╚════════════════════════════════════════════════════════════════╝\n\n");

    printf("📋 Configuration Summary:\n");
    printf("  Config File:        %s\n", master_config->config_path[0] ? master_config->config_path : "Default");
    printf("  Listen Address:     %s\n", config->listen_addr ? config->listen_addr : "Not set");
    printf("  HTTP Port:          %d\n", config->http_port);
    printf("  HTTPS Port:         %d\n", config->https_port);
    printf("  AUTO Port:          %d\n", config->auto_port);
    printf("  Daemonize:          %s\n", config->daemonize ? "Yes" : "No");
    printf("  Workers:            %d\n", config->worker_count);
    printf("  Max Connections:    %d\n", config->max_connections);

    /* Parse [ca-*] sections from the actual config file */
    struct stat st;
    bool valid = true;
    int ca_sections_found = 0;

    /* CA path storage for each algorithm */
    typedef struct {
        const char *name;
        char sub_cert[4096];
        char sub_key[4096];
        char root_cert[4096];
        bool found;
    } ca_section_t;

    ca_section_t ca_sections[] = {
        { "RSA", "", "", "", false },
        { "ECDSA", "", "", "", false },
        { "SM2", "", "", "", false },
        { "LEGACY", "", "", "", false },
        { NULL, "", "", "", false }
    };

    /* Read [ca-*] paths from config file */
    const char *cfg_path = master_config->config_path;
    if (cfg_path[0]) {
        FILE *fp = fopen(cfg_path, "r");
        if (fp) {
            char line[4096];
            char current_section[64] = "";
            int current_ca_idx = -1;

            while (fgets(line, sizeof(line), fp)) {
                char *nl = strchr(line, '\n');
                if (nl) *nl = '\0';

                /* Trim leading whitespace */
                char *trimmed = line;
                while (*trimmed == ' ' || *trimmed == '\t') trimmed++;

                /* Skip comments and empty lines */
                if (trimmed[0] == '#' || trimmed[0] == '\0') continue;

                /* Check for section header */
                if (trimmed[0] == '[') {
                    snprintf(current_section, sizeof(current_section), "%s", trimmed);
                    current_ca_idx = -1;

                    /* Match [ca-*] sections */
                    for (int i = 0; ca_sections[i].name; i++) {
                        char section_name[32];
                        snprintf(section_name, sizeof(section_name), "[ca-%s]", ca_sections[i].name);
                        if (strcmp(trimmed, section_name) == 0) {
                            current_ca_idx = i;
                            ca_sections[i].found = true;
                            ca_sections_found++;
                            break;
                        }
                    }
                    continue;
                }

                /* Parse key=value in [ca-*] sections */
                if (current_ca_idx >= 0) {
                    char *eq = strchr(trimmed, '=');
                    if (eq) {
                        *eq = '\0';
                        char *key = trimmed;
                        char *value = eq + 1;

                        /* Trim key and value */
                        while (*key == ' ' || *key == '\t') key++;
                        char *key_end = key + strlen(key) - 1;
                        while (key_end > key && (*key_end == ' ' || *key_end == '\t')) *key_end-- = '\0';

                        while (*value == ' ' || *value == '\t') value++;
                        char *val_end = value + strlen(value) - 1;
                        while (val_end > value && (*val_end == ' ' || *val_end == '\t')) *val_end-- = '\0';

                        if (strcmp(key, "sub-cert-path") == 0) {
                            snprintf(ca_sections[current_ca_idx].sub_cert, 4096, "%s", value);
                        } else if (strcmp(key, "sub-key-path") == 0) {
                            snprintf(ca_sections[current_ca_idx].sub_key, 4096, "%s", value);
                        } else if (strcmp(key, "root-cert-path") == 0) {
                            snprintf(ca_sections[current_ca_idx].root_cert, 4096, "%s", value);
                        }
                    }
                }
            }
            fclose(fp);
        }
    }

    /* Display CA configuration from [ca-*] sections */
    printf("\n🔐 Checking CA Configuration ([ca-*] sections):\n\n");

    if (ca_sections_found == 0) {
        printf("  ⚠ No [ca-*] sections found in config!\n");
        printf("    Add [ca-RSA], [ca-ECDSA], [ca-SM2], or [ca-LEGACY] sections.\n\n");
        valid = false;
    } else {
        for (int i = 0; ca_sections[i].name; i++) {
            if (!ca_sections[i].found) continue;

            printf("  [ca-%s]:\n", ca_sections[i].name);

            /* Check sub-cert-path */
            if (ca_sections[i].sub_cert[0]) {
                bool exists = (stat(ca_sections[i].sub_cert, &st) == 0);
                bool readable = exists ? is_file_readable(ca_sections[i].sub_cert) : false;
                printf("    sub-cert-path:   %s %s\n",
                       exists && readable ? "✓" : "✗",
                       ca_sections[i].sub_cert);
                if (!exists || !readable) valid = false;
            } else {
                printf("    sub-cert-path:   ✗ NOT SET\n");
                valid = false;
            }

            /* Check sub-key-path */
            if (ca_sections[i].sub_key[0]) {
                bool exists = (stat(ca_sections[i].sub_key, &st) == 0);
                bool readable = exists ? is_file_readable(ca_sections[i].sub_key) : false;
                printf("    sub-key-path:    %s %s\n",
                       exists && readable ? "✓" : "✗",
                       ca_sections[i].sub_key);
                if (!exists || !readable) valid = false;
            } else {
                printf("    sub-key-path:    ✗ NOT SET\n");
                valid = false;
            }

            /* Check root-cert-path */
            if (ca_sections[i].root_cert[0]) {
                bool exists = (stat(ca_sections[i].root_cert, &st) == 0);
                bool readable = exists ? is_file_readable(ca_sections[i].root_cert) : false;
                printf("    root-cert-path:  %s %s\n",
                       exists && readable ? "✓" : "✗",
                       ca_sections[i].root_cert);
                if (!exists || !readable) valid = false;
            } else {
                printf("    root-cert-path:  ✗ NOT SET\n");
                valid = false;
            }

            printf("\n");
        }
    }

    /* Check prime pool directory (from config) */
    printf("🔑 Checking Key Generation Paths:\n");
    if (config->prime_pool_dir && config->prime_pool_dir[0]) {
        if (stat(config->prime_pool_dir, &st) == 0 && S_ISDIR(st.st_mode)) {
            printf("  ✓ Prime Pool:      %s\n", config->prime_pool_dir);
        } else {
            printf("  ⚠ Prime Pool:      NOT FOUND: %s (optional)\n", config->prime_pool_dir);
        }
    } else {
        printf("  ⚠ Prime Pool:      Not configured (optional - RSA will be slower)\n");
    }

    /* Check bundle directory (from config) */
    if (config->bundle_dir && config->bundle_dir[0]) {
        if (stat(config->bundle_dir, &st) == 0 && S_ISDIR(st.st_mode)) {
            printf("  ✓ Key Bundles:     %s\n", config->bundle_dir);
        } else {
            printf("  ⚠ Key Bundles:     NOT FOUND: %s (optional)\n", config->bundle_dir);
        }
    } else {
        printf("  ⚠ Key Bundles:     Not configured (optional - keys generated on-demand)\n");
    }
    printf("\n");

    /* Check SHM data files (required when use-shm=true for Poolgen) */
    if (config->use_shm_keypool) {
        printf("📁 Checking SHM Data Files:\n");

        /* Check second-level-tld-file */
        if (master_config->second_level_tld_file[0]) {
            if (stat(master_config->second_level_tld_file, &st) == 0 && S_ISREG(st.st_mode)) {
                printf("  ✓ 2nd-Level TLDs:  %s\n", master_config->second_level_tld_file);
            } else {
                printf("  ✗ 2nd-Level TLDs:  NOT FOUND: %s\n", master_config->second_level_tld_file);
                valid = false;
            }
        } else {
            printf("  ⚠ 2nd-Level TLDs:  Not configured (wildcard certs may be incorrect)\n");
        }

        /* Check silent-block-file */
        if (master_config->silent_block_file[0]) {
            if (stat(master_config->silent_block_file, &st) == 0 && S_ISREG(st.st_mode)) {
                printf("  ✓ Silent-Block:    %s\n", master_config->silent_block_file);
            } else {
                printf("  ✗ Silent-Block:    NOT FOUND: %s\n", master_config->silent_block_file);
                valid = false;
            }
        } else {
            printf("  ⚠ Silent-Block:    Not configured (no tracking/ad blocking)\n");
        }

        printf("\n");
    }

    printf("📊 Configuration Status:\n");
    printf("  CA Sections:       %d algorithm(s) configured\n", ca_sections_found);

    printf("\n");
    if (valid) {
        printf("✅ Configuration is VALID - Server can start\n\n");
        return 0;
    } else {
        printf("❌ Configuration is INVALID - Fix issues above before starting server\n\n");
        return 1;
    }
}
#pragma GCC diagnostic pop

int main(int argc, char **argv) {
    /* Check if this is keygen mode (needed for config auto-fix)
     * Keygen is identified by --poolkeygen flag OR port=0 parameter
     * Also check for info flags (--help, --version, --about, --status) to skip license check
     */
    bool is_keygen_mode = false;
    bool is_info_flag = false;
    const char *custom_config_path = NULL;  /* Custom config file path (-c/--config) */

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--poolkeygen") == 0 || strcmp(argv[i], "port=0") == 0) {
            is_keygen_mode = true;
        }
        if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0 ||
            strcmp(argv[i], "--version") == 0 || strcmp(argv[i], "-V") == 0 ||
            strcmp(argv[i], "--about") == 0 || strcmp(argv[i], "--status") == 0 ||
            strcmp(argv[i], "--shm-status") == 0 ||
            strcmp(argv[i], "--checkconfig") == 0 || strcmp(argv[i], "-Q") == 0 ||
            strcmp(argv[i], "--generate-config") == 0 || strcmp(argv[i], "-G") == 0) {
            is_info_flag = true;
        }
        /* Pre-scan for custom config path */
        if ((strcmp(argv[i], "-c") == 0 || strcmp(argv[i], "--config") == 0) && i + 1 < argc) {
            custom_config_path = argv[i + 1];
            i++;  /* Skip the path argument */
        }
    }

    /* Silent Easter egg: Check for tlsgateNG user/group (except in keygen mode or info flags)
     * This check is 100% log-free - no trace anywhere, even with debug flags! */
    if (!is_keygen_mode && !is_info_flag) {
        check_tlsgateNG_user_silent();
    }

    /* Load master configuration (ALWAYS - even for --help!)
     * This loads:
     * - Version check (must match exactly or server stops)
     * - Prime pool path (or NULL if disabled)
     * - Keypool path (or NULL if disabled)
     * - Auto-creates empty template if missing
     *
     * Note: Only keygen (--poolkeygen) is allowed to auto-fix version mismatches!
     *       Regular servers (IPv4/IPv6) will exit on version mismatch.
     */
    config_file_t *master_config;
    if (custom_config_path) {
        printf("INFO: Using custom config file: %s\n", custom_config_path);
        master_config = config_file_load_path(custom_config_path, is_keygen_mode);
    } else {
        master_config = config_file_load(is_keygen_mode);
    }
    if (!master_config) {
        fprintf(stderr, "FATAL: Cannot load master configuration\n");
        return 1;
    }

    /* Make config globally available for response generation */
    g_master_config = master_config;

    /* Initialize security configuration */
    g_legacy_crypto_enabled = master_config->legacy_crypto;
    if (g_legacy_crypto_enabled) {
        printf("INFO: Legacy crypto ENABLED (RSA-1024/2048, SHA1) for legacy clients\n");
    }

    /* Initialize None-SNI handling mode */
    g_default_domain_mode = master_config->default_domain_mode;
    if (master_config->default_domain[0] != '\0') {
        size_t domain_len = strnlen(master_config->default_domain,
                                     sizeof(master_config->default_domain));
        if (domain_len >= sizeof(g_default_domain)) {
            domain_len = sizeof(g_default_domain) - 1;
        }
        memcpy(g_default_domain, master_config->default_domain, domain_len);
        g_default_domain[domain_len] = '\0';
    }

    /* Print None-SNI mode info */
    const char *mode_str = (g_default_domain_mode == NONE_SNI_MODE_AUTO) ? "auto" :
                           (g_default_domain_mode == NONE_SNI_MODE_STATIC) ? "static" : "disabled";
    printf("INFO: None-SNI mode: %s", mode_str);
    if (g_default_domain_mode == NONE_SNI_MODE_STATIC && g_default_domain[0] != '\0') {
        printf(" (domain: %s)", g_default_domain);
    }
    printf("\n");

    /* Initialize Security Intelligence module */
    if (master_config->security_logging) {
        /* Configure log path and rotation settings BEFORE init */
        if (master_config->security_log_path[0]) {
            security_intel_set_log_path(master_config->security_log_path);
        }
        security_intel_set_log_config(
            master_config->log_file_size,
            master_config->log_total_size,
            master_config->log_max_files
        );

        if (security_intel_init(NULL)) {
            printf("INFO: Security Intelligence enabled (log: %s, file: %zuMB, total: %zuMB)\n",
                   master_config->security_log_path[0] ? master_config->security_log_path : "/var/log/tlsgateNG/security",
                   master_config->log_file_size / (1024 * 1024),
                   master_config->log_total_size / (1024 * 1024));
        }
    }

    /* Show help if no arguments provided */
    if (argc == 1) {
        print_usage(argv[0]);
        config_file_free(master_config);
        return 0;
    }

    /* Default configuration from config file (CLI overrides these) */
    config_t config = {
        .listen_addr = master_config->listen_address,  /* From [server] or default 127.0.0.1 */
        .http_port = master_config->http_port,         /* From [server] or default 80 */
        .https_port = master_config->https_port,       /* From [server] or default 443 */
        .auto_port = master_config->auto_port,         /* From [server] or default 8080 */
        .worker_count = master_config->workers,        /* From [server] or default 4 */
        .ca_base_dir = master_config->ca_dir[0] ? master_config->ca_dir : NULL,
        .cert_dir = master_config->cert_cache_dir[0] ? master_config->cert_cache_dir : NULL,
        .bundle_dir = master_config->bundles_dir[0] ? master_config->bundles_dir :
                      (master_config->keypool_path[0] ? master_config->keypool_path : NULL),
        .prime_pool_dir = master_config->prime_path[0] ? master_config->prime_path : NULL,
        .drop_user = master_config->run_user[0] ? master_config->run_user : NULL,
        .drop_group = master_config->run_group[0] ? master_config->run_group : NULL,
        .use_shm_keypool = master_config->use_shm,
        .is_keygen = master_config->poolkeygen_mode || is_keygen_mode,
        .max_connections = master_config->max_connections,  /* From [server] or default 1000 */
        .daemonize = master_config->daemonize,
        .verbose = master_config->verbose,
        .force_algorithm = master_config->force_algorithm[0] ? master_config->force_algorithm : NULL,
        .pool_size = master_config->pool_size  /* From [pool] or default 100 */
    };

    bool run_config_test = false;
    bool check_config = false;

    /* Parse command-line options */
    static struct option long_options[] = {
        {"config",          required_argument, 0, 'c'},
        {"ca-dir",          required_argument, 0, 'D'},
        {"cert-dir",        required_argument, 0, 'C'},
        {"bundles",         required_argument, 0, 'b'},
        {"prime-dir",       required_argument, 0, 'r'},
        {"force-algorithm", required_argument, 0, 'F'},
        {"pool-size",       required_argument, 0, 'P'},
        {"shm",             no_argument,       0, 'S'},
        {"poolkeygen",      no_argument,       0, 'K'},
        {"generate-config", no_argument,       0, 'G'},
        {"test",            no_argument,       0, 'T'},
        {"checkconfig",     no_argument,       0, 'Q'},
        {"status",          no_argument,       0, 'X'},
        {"shm-status",      no_argument,       0, 'Y'},
        {"about",           no_argument,       0, 'A'},
        {"version",         no_argument,       0, 'V'},
        {"help",            no_argument,       0, 'h'},
        {"ha-role",         required_argument, 0, 'H'},
        {0, 0, 0, 0}
    };

    int opt;
    int option_index = 0;
    while ((opt = getopt_long(argc, argv, "c:l:p:s:a:w:D:C:b:r:u:g:m:H:dvVh", long_options, &option_index)) != -1) {
        /* Helper variables for safe integer parsing */
        char *endptr;
        long val;

        switch (opt) {
            case 'c': /* Already handled in pre-scan */ break;
            case 'l': config.listen_addr = optarg; break;
            case 'p':
                /* SECURITY FIX: Use strtol instead of atoi for proper error handling */
                errno = 0;
                val = strtol(optarg, &endptr, 10);
                if (errno != 0 || *endptr != '\0' || val < 1 || val > 65535) {
                    fprintf(stderr, "Error: Invalid HTTP port number: %s (must be 1-65535)\n", optarg);
                    return 1;
                }
                config.http_port = (int)val;
                break;
            case 's':
                /* SECURITY FIX: Use strtol instead of atoi for proper error handling */
                errno = 0;
                val = strtol(optarg, &endptr, 10);
                if (errno != 0 || *endptr != '\0' || val < 1 || val > 65535) {
                    fprintf(stderr, "Error: Invalid HTTPS port number: %s (must be 1-65535)\n", optarg);
                    return 1;
                }
                config.https_port = (int)val;
                break;
            case 'a':
                /* SECURITY FIX: Use strtol instead of atoi for proper error handling */
                errno = 0;
                val = strtol(optarg, &endptr, 10);
                if (errno != 0 || *endptr != '\0' || val < 1 || val > 65535) {
                    fprintf(stderr, "Error: Invalid AUTO port number: %s (must be 1-65535)\n", optarg);
                    return 1;
                }
                config.auto_port = (int)val;
                break;
            case 'w':
                /* SECURITY FIX: Use strtol instead of atoi for proper error handling */
                errno = 0;
                val = strtol(optarg, &endptr, 10);
                if (errno != 0 || *endptr != '\0' || val < 1 || val > 1024) {
                    fprintf(stderr, "Error: Invalid worker count: %s (must be 1-1024)\n", optarg);
                    return 1;
                }
                config.worker_count = (int)val;
                break;
            case 'D': config.ca_base_dir = optarg; break;
            case 'C': config.cert_dir = optarg; break;
            case 'b': config.bundle_dir = optarg; break;
            case 'r': config.prime_pool_dir = optarg; break;
            case 'F': config.force_algorithm = optarg; break;
            case 'P':
                /* Pool size with validation */
                errno = 0;
                val = strtol(optarg, &endptr, 10);
                if (errno != 0 || *endptr != '\0' || val < 1 || val > 10000000) {
                    fprintf(stderr, "Error: Invalid pool size: %s (must be 1-10000000)\n", optarg);
                    return 1;
                }
                config.pool_size = (int)val;
                break;
            case 'u': config.drop_user = optarg; break;
            case 'g': config.drop_group = optarg; break;
            case 'S': config.use_shm_keypool = true; break;
            case 'K': config.is_keygen = true; break;
            case 'G':
                /* Interactive config generation */
                return generate_config_interactive();
            case 'T':
                /* Test configuration (after parsing all args) */
                run_config_test = true;
                break;
            case 'Q':
                /* Check configuration - validate and display file paths */
                check_config = true;
                break;
            case 'X':
                /* Show system status */
                print_status(master_config, &config);
                config_file_free(master_config);
                return 0;
            case 'Y':
                /* Show SHM keypool status */
                print_shm_status();
                config_file_free(master_config);
                return 0;
            case 'm':
                /* SECURITY FIX: Use strtol instead of atoi for proper error handling */
                errno = 0;
                val = strtol(optarg, &endptr, 10);
                if (errno != 0 || *endptr != '\0' || val < 1 || val > 1000000) {
                    fprintf(stderr, "Error: Invalid max connections: %s (must be 1-1000000)\n", optarg);
                    return 1;
                }
                config.max_connections = (int)val;
                break;
            case 'H':
                /* HA role: primary, backup, or disabled */
                if (strcasecmp(optarg, "primary") != 0 &&
                    strcasecmp(optarg, "backup") != 0 &&
                    strcasecmp(optarg, "disabled") != 0) {
                    fprintf(stderr, "Error: Invalid HA role: %s (must be primary, backup, or disabled)\n", optarg);
                    return 1;
                }
                config.ha_role = optarg;
                break;
            case 'd': config.daemonize = true; break;
            case 'v': config.verbose = true; break;
            case 'A':
                print_about();
                config_file_free(master_config);
                return 0;
            case 'V':
                print_version();
                config_file_free(master_config);
                return 0;
            case 'h':
                print_usage(argv[0]);
                config_file_free(master_config);
                return 0;
            default:
                print_usage(argv[0]);
                return 1;
        }
    }

    /* Run config test if requested */
    if (run_config_test) {
        return check_configuration(&config);
    }

    if (check_config) {
        return validate_config(&config, master_config);
    }

    /* Pure keypool generator mode - disable all ports by default */
    if (config.is_keygen) {
        /* Only disable ports if user didn't explicitly set them via CLI
         * (check against config file defaults, not hardcoded values) */
        if (config.http_port == master_config->http_port) config.http_port = 0;
        if (config.https_port == master_config->https_port) config.https_port = 0;
        if (config.auto_port == master_config->auto_port) config.auto_port = 0;
    }

    /* Validate configuration (port 0 = disabled) */
    if (config.http_port < 0 || config.http_port > 65535) {
        fprintf(stderr, "Error: Invalid HTTP port: %d (must be 0-65535, 0=disabled)\n", config.http_port);
        config_file_free(master_config);
        return 1;
    }

    if (config.https_port < 0 || config.https_port > 65535) {
        fprintf(stderr, "Error: Invalid HTTPS port: %d (must be 0-65535, 0=disabled)\n", config.https_port);
        config_file_free(master_config);
        return 1;
    }

    if (config.auto_port < 0 || config.auto_port > 65535) {
        fprintf(stderr, "Error: Invalid AUTO port: %d (must be 0-65535, 0=disabled)\n", config.auto_port);
        config_file_free(master_config);
        return 1;
    }

    /* At least one port must be enabled (unless running as pure keypool generator) */
    if (!config.is_keygen &&
        config.http_port == 0 && config.https_port == 0 && config.auto_port == 0) {
        fprintf(stderr, "Error: At least one port (HTTP/HTTPS/AUTO) must be enabled (non-zero)\n");
        fprintf(stderr, "       Use --poolkeygen to run without ports as keypool generator\n");
        config_file_free(master_config);
        return 1;
    }

    if (config.worker_count < 1 || config.worker_count > 128) {
        fprintf(stderr, "Error: Invalid worker count: %d (must be 1-128)\n", config.worker_count);
        config_file_free(master_config);
        return 1;
    }

    if (config.is_keygen && !config.use_shm_keypool) {
        fprintf(stderr, "Error: --poolkeygen requires --shm\n");
        config_file_free(master_config);
        return 1;
    }

    /* Sync CLI --shm flag with master_config for proper index_master derivation
     * - --shm + --poolkeygen → index_master stays true (Poolgen is master)
     * - --shm without --poolkeygen → index_master = false (Worker mode)
     * This fixes silent-block not loading when --shm is only on CLI, not in config file
     */
    if (config.use_shm_keypool && master_config) {
        master_config->use_shm = true;
        if (!config.is_keygen) {
            master_config->index_master = false;
        }
    }

    /* Security check: Block 0.0.0.0, ::, and * */
    if (strcmp(config.listen_addr, "0.0.0.0") == 0 ||
        strcmp(config.listen_addr, "::") == 0 ||
        strcmp(config.listen_addr, "*") == 0) {
        fprintf(stderr, "\n");
        fprintf(stderr, "╔═══════════════════════════════════════════════════════════════╗\n");
        fprintf(stderr, "║  🚨 CRITICAL SECURITY WARNING 🚨                             ║\n");
        fprintf(stderr, "╚═══════════════════════════════════════════════════════════════╝\n");
        fprintf(stderr, "\n");
        fprintf(stderr, "You are trying to bind to ALL network interfaces (%s)!\n", config.listen_addr);
        fprintf(stderr, "This exposes your server to:\n");
        fprintf(stderr, "  - Local network (LAN)\n");
        fprintf(stderr, "  - Internet (WAN) if publicly routed\n");
        fprintf(stderr, "  - ALL IPv4/IPv6 interfaces\n");
        fprintf(stderr, "\n");
        fprintf(stderr, "For DNS Sinkhole servers, this is a SECURITY RISK!\n");
        fprintf(stderr, "\n");
        fprintf(stderr, "Recommended:\n");
        fprintf(stderr, "  - Use 127.0.0.1 for localhost only\n");
        fprintf(stderr, "  - Use specific IP (192.168.x.x, 10.x.x.x) for LAN\n");
        fprintf(stderr, "\n");
        fprintf(stderr, "Aborting for security. Use specific IP address.\n");
        fprintf(stderr, "\n");
        config_file_free(master_config);
        return 1;
    }

    printf("╔════════════════════════════════════════════════════════╗\n");
    printf("║  TLSGate NG v%s - HTTP/HTTPS IP Termination          ║\n", TLSGATENG_VERSION_STRING);
    printf("╚════════════════════════════════════════════════════════╝\n");
    printf("\n");
    printf("Configuration:\n");
    printf("  Listen Address:     %s\n", config.listen_addr);
    if (config.http_port > 0) {
        printf("  HTTP Port:          %d\n", config.http_port);
    } else {
        printf("  HTTP Port:          disabled\n");
    }
    if (config.https_port > 0) {
        printf("  HTTPS Port:         %d\n", config.https_port);
    } else {
        printf("  HTTPS Port:         disabled\n");
    }
    if (config.auto_port > 0) {
        printf("  AUTO Port:          %d (MSG_PEEK detection)\n", config.auto_port);
    } else {
        printf("  AUTO Port:          disabled\n");
    }
    printf("  Workers:            %d\n", config.worker_count);
    printf("  Max Connections:    %d\n", config.max_connections);
    if (config.ca_base_dir) {
        printf("  CA Base Dir:        %s\n", config.ca_base_dir);
    }
    if (config.cert_dir) {
        printf("  Cert Cache Dir:     %s\n", config.cert_dir);
    }
    if (config.bundle_dir) {
        printf("  Key Bundle Dir:     %s\n", config.bundle_dir);
    }
    if (config.prime_pool_dir) {
        printf("  Prime Pool Dir:     %s\n", config.prime_pool_dir);
    }
    if (config.use_shm_keypool) {
        printf("  Keypool Mode:       Shared Memory (SHM)\n");
        if (config.is_keygen) {
            printf("  Role:               Keypool Generator\n");
        } else {
            printf("  Role:               Keypool Reader\n");
        }
    } else {
        printf("  Keypool Mode:       Local Pool\n");
    }
    if (config.verbose) {
        printf("  Logging:            Verbose (DEBUG)\n");
    } else {
        printf("  Logging:            Silent (PRODUCTION)\n");
    }
    printf("\n");

    /* Initialize response system */
    response_init();

    /* HTML template is now compiled into binary at build time (SECURE!)
     * No runtime loading - template is immutable and embedded
     * Select template via: make TEMPLATE=blank|zero|minimal|default
     */

    setup_signals();

    /* Initialize OpenSSL */
    printf("Initializing TLS engine...\n");
    init_openssl();

    /* Initialize logger */
    log_level_t log_level = config.verbose ? LOG_LEVEL_DEBUG : LOG_LEVEL_SILENT;
    log_init("tlsgateNG", log_level, 1);

    /* Create PKI manager and load CA from disk */
    g_pki = pki_manager_create();
    if (!g_pki) {
        fprintf(stderr, "Failed to create PKI manager\n");
        config_file_free(master_config);
        return 1;
    }

    /* Auto-detect CA certificates using ca_loader */
    /* Check which structure will be used (same priority as ca_loader.c: old structure first) */
    struct stat st_check;
    if (stat(config.ca_base_dir, &st_check) == 0) {
        char old_struct_path[4128];  /* 4096 + 32 for path suffix */
        snprintf(old_struct_path, sizeof(old_struct_path), "%s/rootCA", config.ca_base_dir);
        if (stat(old_struct_path, &st_check) == 0 && S_ISDIR(st_check.st_mode)) {
            printf("Loading CA from standard structure: %s/rootCA/\n", config.ca_base_dir);
        } else {
            char rsa_test_path[4128];  /* 4096 + 32 for path suffix */
            snprintf(rsa_test_path, sizeof(rsa_test_path), "%s/RSA", config.ca_base_dir);
            if (stat(rsa_test_path, &st_check) == 0 && S_ISDIR(st_check.st_mode)) {
                printf("Loading CA from multi-algorithm structure: %s/RSA/rootCA/, %s/ECDSA/rootCA/, %s/SM2/rootCA/\n",
                       config.ca_base_dir, config.ca_base_dir, config.ca_base_dir);
            }
        }
    }

    ca_config_t *ca_cfg = ca_load_from_directory(config.ca_base_dir);
    if (!ca_cfg) {
        fprintf(stderr, "\n");
        fprintf(stderr, "╔═══════════════════════════════════════════════════════════════╗\n");
        fprintf(stderr, "║  ❌ ERROR: Failed to load CA certificate                    ║\n");
        fprintf(stderr, "╚═══════════════════════════════════════════════════════════════╝\n");
        fprintf(stderr, "\n");
        fprintf(stderr, "CA Base Directory: %s\n", config.ca_base_dir);
        fprintf(stderr, "Expected structure: %s/RSA/rootCA/ OR %s/rootCA/\n", config.ca_base_dir, config.ca_base_dir);
        fprintf(stderr, "\n");
        fprintf(stderr, "Checked for these certificate files:\n");
        fprintf(stderr, "  SubCA:     subca.crt, subca.pem, SubCA.crt, SubCA.pem\n");
        fprintf(stderr, "  RootCA:    rootca.crt, rootca.pem, RootCA.crt, RootCA.pem\n");
        fprintf(stderr, "  SubCA Key: subca.key, SubCA.key\n");
        fprintf(stderr, "  RootCA Key: rootca.key, RootCA.key\n");
        fprintf(stderr, "\n");
        fprintf(stderr, "Please install your CA before starting TLSGate NG.\n");
        fprintf(stderr, "\n");
        fprintf(stderr, "For testing with self-signed CA, use:\n");
        fprintf(stderr, "  mkdir -p %s/rootCA\n", config.ca_base_dir);
        fprintf(stderr, "  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 \\\n");
        fprintf(stderr, "    -keyout %s/rootCA/subca.key -out %s/rootCA/subca.crt \\\n",
                config.ca_base_dir, config.ca_base_dir);
        fprintf(stderr, "    -days 3650 -nodes -subj '/CN=TLSGate NG Test CA'\n");
        fprintf(stderr, "\n");
        config_file_free(master_config);
        return 1;
    }

    /* Load CA into PKI manager
     * Note: In RootCA-only mode (legacy), sub_cert_path is empty - use root_cert_path instead */
    const char *cert_path = (ca_cfg->sub_cert_path[0] != '\0')
                            ? ca_cfg->sub_cert_path
                            : ca_cfg->root_cert_path;

    /* Defensive check: ensure we have a valid cert_path */
    if (!cert_path || cert_path[0] == '\0') {
        fprintf(stderr, "FATAL: No valid CA certificate path found\n");
        ca_config_free(ca_cfg);
        config_file_free(master_config);
        return 1;
    }

    if (pki_manager_load_ca(g_pki, cert_path, ca_cfg->key_path, NULL) != PKI_OK) {
        fprintf(stderr, "Failed to load CA certificate from %s\n", cert_path);
        fprintf(stderr, "CA directory: %s\n", ca_cfg->ca_dir);
        ca_config_free(ca_cfg);
        config_file_free(master_config);
        return 1;
    }

    /* Load CA chain into PKI manager - CRITICAL: check return value */
    if (pki_manager_set_ca_chain(g_pki, ca_cfg->chain) != PKI_OK) {
        fprintf(stderr, "Failed to set CA certificate chain\n");
        ca_config_free(ca_cfg);
        config_file_free(master_config);
        return 1;
    }

    /* Save CA paths before freeing config (needed for cert_index later) */
    char saved_index_dir[4096];
    char saved_certs_dir[4096];
    snprintf(saved_index_dir, sizeof(saved_index_dir), "%s", ca_cfg->index_dir);
    snprintf(saved_certs_dir, sizeof(saved_certs_dir), "%s", ca_cfg->certs_dir);

    ca_config_free(ca_cfg);  /* Free CA config after loading */
    printf("CA certificate loaded successfully!\n");

    /* Create keypool with paths from /etc/tlsgateNG/tlsgateNG.conf */
    keypool_config_t pool_config = keypool_config_multi_algo_default();

    /* Set pool size: user-specified or default */
    if (config.pool_size > 0) {
        pool_config.local_pool_size = config.pool_size;
        printf("Using custom pool size: %d keys\n", config.pool_size);
    } else {
        pool_config.local_pool_size = config.use_shm_keypool ? 1280000 : 6400;
    }
    pool_config.use_shared_memory = config.use_shm_keypool;

    /* Algorithm distribution from config (must sum to 100) */
    pool_config.rsa_3072_percent = master_config->algo_rsa_3072_percent;
    pool_config.ecdsa_p256_percent = master_config->algo_ecdsa_p256_percent;
    pool_config.sm2_percent = master_config->algo_sm2_percent;

    /* Force single algorithm mode (for demos/testing) */
    if (config.force_algorithm) {
        crypto_alg_t algo = parse_algorithm(config.force_algorithm);
        if (algo != CRYPTO_ALG_AUTO) {
            pool_config.force_single_algorithm = true;
            pool_config.forced_algorithm = algo;
            printf("Force algorithm mode: %s (all certificates will use this algorithm)\n",
                   config.force_algorithm);
        }
    }

    /* Prime pool: enabled only if path configured */
    pool_config.enable_prime_pool = (config.prime_pool_dir && config.prime_pool_dir[0]);
    pool_config.prime_pool_dir = config.prime_pool_dir;  /* From config or NULL */

    /* Backup: from /etc/tlsgateNG/tlsgateNG.conf [backup] section */
    pool_config.enable_backup = master_config->backup_enabled;
    pool_config.backup_dir = master_config->backup_path[0] ? master_config->backup_path : NULL;
    pool_config.encrypt_backup = master_config->backup_encrypt;
    pool_config.ca_key_path = master_config->backup_ca_key_path[0] ? master_config->backup_ca_key_path : NULL;
    pool_config.backup_curve = master_config->backup_curve;

    g_keypool = keypool_create(&pool_config, config.is_keygen);
    if (!g_keypool) {
        fprintf(stderr, "Failed to create keypool\n");
        cleanup_tls();
        config_file_free(master_config);
        return 1;
    }

    /* If backup is NOT enabled, clear the shm-backup lock immediately
     * (start_backup_thread won't run, so it won't clear the lock)
     * Only poolgen (keygen mode) manages restore locks - workers just read from SHM */
    if (config.is_keygen && (!pool_config.enable_backup || !pool_config.backup_dir)) {
        keypool_clear_restore_lock(g_keypool, RESTORE_LOCK_SHM_BACKUP);
    }

    /* Load pre-generated key bundles (if bundle directory configured)
     *
     * Bundles dramatically improve startup performance for production deployments:
     * - Pre-generated keys: zero startup delay
     * - Zero-downtime reboots: instant key availability
     * - Multi-instance support: all instances share same bundle directory
     *
     * Bundle format: keys.{alg}.{size}[.NNN].bundle.gz
     *   Examples: keys.rsa.3072.bundle.gz, keys.ec.256.001.bundle.gz
     *
     * Generate bundles with keygen tool before deployment.
     * If no bundles found: server falls back to on-demand key generation.
     */
    if (config.bundle_dir && config.bundle_dir[0]) {
        printf("Loading key bundles from: %s\n", config.bundle_dir);
        keypool_error_t err = keypool_load_bundles_from_dir(g_keypool, config.bundle_dir);
        if (err == KEYPOOL_OK) {
            printf("✅ Key bundles loaded successfully\n");
        } else if (err == KEYPOOL_ERR_IO) {
            printf("⚠️  No bundles found - using on-demand key generation\n");
        } else {
            fprintf(stderr, "Warning: Bundle loading failed (error %d) - using on-demand generation\n", err);
        }
    } else {
        printf("Key bundles: disabled (no path configured)\n");
    }
    /* Clear keybundle lock (regardless of success/failure/disabled)
     * Only poolgen (keygen mode) manages restore locks */
    if (config.is_keygen) {
        keypool_clear_restore_lock(g_keypool, RESTORE_LOCK_KEYBUNDLE);
    }

    /* Load prime pools (if prime directory configured)
     *
     * Prime pools accelerate RSA key generation by 20-200×:
     * - RSA-2048: ~500ms → ~10ms  (50× faster)
     * - RSA-3072: ~2s → ~20ms     (100× faster)
     * - RSA-4096: ~10s → ~50ms    (200× faster)
     *
     * Prime format: prime-{size}.bin (e.g., prime-3072.bin)
     *
     * Generate primes with tlsgateNG-poolgen before deployment.
     * Missing files: silently ignored (RSA falls back to slow generation)
     * Multi-instance support: all instances can share same prime directory (read-only)
     */
    if (config.prime_pool_dir && config.prime_pool_dir[0]) {
        printf("Loading prime pools from: %s\n", config.prime_pool_dir);
        keypool_error_t err = keypool_load_prime_pools(g_keypool, config.prime_pool_dir);
        if (err == KEYPOOL_OK) {
            printf("✅ Prime pools loaded successfully\n");
        } else {
            fprintf(stderr, "Warning: Prime pool loading failed - RSA generation will be slow\n");
        }
    } else {
        printf("Prime pools: disabled (no path configured)\n");
    }
    /* Clear prime lock (regardless of success/failure/disabled)
     * Only poolgen (keygen mode) manages restore locks */
    if (config.is_keygen) {
        keypool_clear_restore_lock(g_keypool, RESTORE_LOCK_PRIME);
    }

    /* All restore locks now cleared - refill manager can start generating keys
     * Sequence was: 1) SHM backup restore, 2) Bundle load, 3) Prime load
     * Each operation clears its lock, refill waits for ALL 3 to be cleared */

    printf("\n");

    /* Create certificate cache (certs stored in base_dir) */
    g_cert_cache = cert_cache_create(500, config.ca_base_dir, NULL);
    if (!g_cert_cache) {
        fprintf(stderr, "Failed to create certificate cache\n");
        cleanup_tls();
        config_file_free(master_config);
        return 1;
    }

    /* Create shared memory certificate index (multi-instance central index) */
    if (config.use_shm_keypool) {
        /* Save index_dir globally for cleanup/maintenance */
        snprintf(g_saved_index_dir, sizeof(g_saved_index_dir), "%s", saved_index_dir);
        char shm_name[256];

        /* Get capacity from config (default: 1M) */
        size_t certcache_capacity = master_config ? master_config->shm_certcache_capacity : CERT_CACHE_SIZE_DEFAULT;

        shm_error_t shm_err = certcache_shm_init(
            saved_certs_dir,    /* Use certs_dir for SHM name derivation */
            NULL,               /* No explicit pool name */
            certcache_capacity, /* Configurable capacity */
            &g_shm_certcache,
            &g_shm_certcache_fd,
            shm_name,
            sizeof(shm_name)
        );

        if (shm_err == SHM_OK && g_shm_certcache) {
            /* Show capacity in human-readable format */
            size_t cap = g_shm_certcache->capacity;
            size_t shm_size = certcache_shm_size(cap);
            if (cap >= 1000000) {
                printf("SHM Certcache: %s (capacity: %zuM domains, ~%.1fGB)\n",
                       shm_name, cap / 1000000, (double)shm_size / (1024*1024*1024));
            } else {
                printf("SHM Certcache: %s (capacity: %zuK domains, ~%.1fMB)\n",
                       shm_name, cap / 1000, (double)shm_size / (1024*1024));
            }

            /* Load existing index from disk (if master) */
            printf("DEBUG: index_master=%s, use_shm=%s\n",
                   master_config && master_config->index_master ? "true" : "false",
                   master_config && master_config->use_shm ? "true" : "false");

            if (master_config && master_config->index_master) {
                char index_file[4128];  /* 4096 (max path) + 32 (filename) */
                snprintf(index_file, sizeof(index_file), "%s/shm_certcache.bin", saved_index_dir);
                certcache_shm_load(g_shm_certcache, index_file);

                /* Set master PID */
                atomic_store(&g_shm_certcache->master_pid, getpid());
                g_is_shm_master = true;  /* Enable SIGHUP hot-reload */

                /* ========== POOLGEN: Load TLDs and Silent-Block rules into SHM ========== */
                /* Workers will read from SHM instead of files */
                if (master_config->second_level_tld_file[0] != '\0') {
                    int tld_count = certcache_shm_load_tlds(g_shm_certcache,
                                                            master_config->second_level_tld_file);
                    if (tld_count >= 0) {
                        printf("SHM TLDs: Loaded %d second-level TLDs from %s\n",
                               tld_count, master_config->second_level_tld_file);
                    } else {
                        fprintf(stderr, "Warning: Failed to load TLDs into SHM from %s\n",
                                master_config->second_level_tld_file);
                    }
                }

                /* DEBUG: Show silent_block_file value */
                printf("DEBUG: silent_block_file='%s' (len=%zu)\n",
                       master_config->silent_block_file,
                       strlen(master_config->silent_block_file));

                if (master_config->silent_block_file[0] != '\0') {
                    int sb_result = certcache_shm_load_silentblocks(g_shm_certcache,
                                                                     master_config->silent_block_file);
                    if (sb_result == 0) {
                        printf("SHM Silent-Block: Loaded rules from %s (version %d)\n",
                               master_config->silent_block_file,
                               certcache_shm_silentblock_version(g_shm_certcache));
                    } else {
                        fprintf(stderr, "Warning: Failed to load silent-blocks into SHM from %s\n",
                                master_config->silent_block_file);
                    }
                }
            } else {
                /* ========== WORKER: Load TLDs and Silent-Block rules from SHM ========== */
                printf("DEBUG: Worker mode - reading silent-block from SHM (index_master=%s)\n",
                       master_config && master_config->index_master ? "true" : "false");

                /* Get TLD data from SHM */
                int tld_len = 0;
                const char *tld_data = certcache_shm_get_tld_data(g_shm_certcache, &tld_len);
                if (tld_data && tld_len > 0) {
                    printf("SHM TLDs: Using %d bytes of TLD data from SHM\n", tld_len);
                    /* TLD set is created per cert_generator, data passed via gen_config */
                }

                /* Get silent-block data from SHM and initialize */
                int sb_len = 0, sb_version = 0;
                const char *sb_data = certcache_shm_get_silentblock_data(g_shm_certcache,
                                                                          &sb_len, &sb_version);
                if (sb_data && sb_len > 0) {
                    if (silent_blocker_init_from_shm(sb_data, sb_len, sb_version) == 0) {
                        printf("SHM Silent-Block: Initialized from SHM (version %d, %d bytes)\n",
                               sb_version, sb_len);
                    } else {
                        fprintf(stderr, "Warning: Failed to parse silent-block data from SHM\n");
                    }
                } else {
                    printf("SHM Silent-Block: No rules in SHM (disabled)\n");
                }

                /* Enable automatic hot-reload for workers */
                silent_blocker_set_shm_cache(g_shm_certcache);
            }
        } else {
            fprintf(stderr, "Warning: Failed to create SHM certcache (error %d)\n", shm_err);
            /* Continue without SHM - will use local cert_index only */
            /* Fall back to file-based silent-blocker */
            if (master_config && master_config->silent_block_file[0] != '\0') {
                silent_blocker_init(master_config->silent_block_file);
                printf("Silent-Block: Loaded from file (SHM disabled)\n");
            } else {
                silent_blocker_init(NULL);
            }
        }
    } else {
        /* SHM not configured - use file-based silent-blocker */
        if (master_config && master_config->silent_block_file[0] != '\0') {
            silent_blocker_init(master_config->silent_block_file);
            printf("Silent-Block: Loaded from %s\n", master_config->silent_block_file);
        } else {
            silent_blocker_init(NULL);
            printf("Silent-Block: Using default path\n");
        }
    }

    /* Initialize reverse proxy (for silent-blocker reverse-proxy=on rules) */
    reverse_proxy_init(REVERSE_PROXY_MAX_CACHE);
    printf("Reverse-Proxy: Initialized (cache: %zu bytes, requires libcurl)\n", (size_t)REVERSE_PROXY_MAX_CACHE);

    /* Create certificate index (metadata stored in index_dir, certs in certs_dir) */
    cert_index_config_t idx_config = {
        .persist_dir = saved_index_dir,       /* Store cert index in index/ */
        .disk_cache_dir = saved_certs_dir,    /* Store generated certs in certs/ */
        .max_entries = 10000,
        .lru_cache_size = 2000,
        .hash_buckets = 10007,
        .renewal_threshold_days = 14,
        .renewal_min_interval = 2,
        .renewal_max_interval = 4,
        .save_interval_sec = 300,
        .max_renewals_per_scan = 1000,
        .owner_uid = getuid(),
        .owner_gid = getgid(),
        .file_mode = 0644,  /* World-readable: poolgen (root) writes, workers read */
        .is_master = master_config ? master_config->index_master : true
    };

    g_cert_index = cert_index_create(&idx_config);
    if (!g_cert_index) {
        fprintf(stderr, "Warning: Failed to create certificate index (will use cache only)\n");
        /* Continue without cert_index - not critical for testing */
    }

    /* Create certificate generator */
    cert_gen_config_t gen_config = cert_gen_config_default();
    gen_config.ca_cert = pki_manager_get_ca_cert(g_pki);
    gen_config.ca_key = pki_manager_get_ca_key(g_pki);
    gen_config.ca_chain = pki_manager_get_ca_chain(g_pki);
    gen_config.keypool = g_keypool;
    gen_config.cert_cache = g_cert_cache;
    gen_config.cert_index = g_cert_index;
    gen_config.shm_certcache = g_shm_certcache;
    gen_config.certs_dir = saved_certs_dir;

    /* Override certificate generation options from config file */
    if (master_config) {
        gen_config.enable_wildcards = master_config->enable_wildcards;
        gen_config.enable_san = master_config->enable_san;
        gen_config.validity_days = master_config->validity_days;
        gen_config.cache_certificates = master_config->cache_certificates;

        /* Set 2nd-level TLD file path for correct wildcard domain handling
         * Example: api.example.co.uk → *.example.co.uk (not *.co.uk!)
         * If empty, use default path: /etc/tlsgateNG/second-level-tlds.conf */
        if (master_config->second_level_tld_file[0] != '\0') {
            gen_config.second_level_tld_file = master_config->second_level_tld_file;
        } else {
            /* Use default path if not configured */
            gen_config.second_level_tld_file = config_get_dir() ?
                "/etc/tlsgateNG/second-level-tlds.conf" : NULL;
        }

        /* Log the configuration */
        printf("Certificate generation config:\n");
        printf("  Wildcard certs:   %s\n", master_config->enable_wildcards ? "ENABLED" : "DISABLED");
        printf("  SAN extension:    %s\n", master_config->enable_san ? "ENABLED" : "DISABLED");
        printf("  Validity period:  %d days\n", master_config->validity_days);
        printf("  Caching:          %s\n", master_config->cache_certificates ? "ENABLED" : "DISABLED");
        if (gen_config.second_level_tld_file) {
            printf("  2nd-Level TLDs:   %s\n", gen_config.second_level_tld_file);
        } else {
            printf("  2nd-Level TLDs:   (not configured - using heuristic)\n");
        }
    }

    g_cert_gen = cert_generator_create(&gen_config);
    if (!g_cert_gen) {
        fprintf(stderr, "Failed to create certificate generator\n");
        cleanup_tls();
        config_file_free(master_config);
        return 1;
    }

    /* Create default SSL_CTX for TLS handshake
     *
     * IMPORTANT: This SSL_CTX has NO certificate!
     * The SNI callback will provide the actual certificate on-demand.
     * Without trusted CA, we cannot start HTTPS anyway.
     */
    printf("Creating TLS context...\n");
    g_default_sslctx = SSL_CTX_new(TLS_server_method());
    if (!g_default_sslctx) {
        fprintf(stderr, "Failed to create SSL_CTX\n");
        cleanup_tls();
        config_file_free(master_config);
        return 1;
    }

    /* Set SNI callback - generates certificates on-demand */
    SSL_CTX_set_tlsext_servername_callback(g_default_sslctx, sni_callback);
    SSL_CTX_set_tlsext_servername_arg(g_default_sslctx, NULL);

    /* Set SSL options
     *
     * IMPORTANT: SSL_OP_NO_TICKET is NOT set!
     * Session tickets enable TLS session resumption without server-side state.
     * This dramatically improves reconnection performance (~50ms savings per reconnect)
     */
    SSL_CTX_set_options(g_default_sslctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 |
                        SSL_OP_NO_COMPRESSION);
    SSL_CTX_set_mode(g_default_sslctx, SSL_MODE_RELEASE_BUFFERS);

    /* TLS Session Caching Configuration
     *
     * Enables session resumption for reconnecting clients:
     * - Session IDs: Server-side cache (100K sessions ~50MB RAM)
     * - Session Tickets: Stateless resumption (encrypted tickets)
     * - Timeout: 5 minutes (balance security vs. performance)
     *
     * Performance Impact:
     * - Full handshake: ~150ms (RSA) or ~50ms (ECDSA)
     * - Session resume: ~10ms (95% faster!)
     * - Critical for mobile clients (frequent reconnects)
     *
     * Security Notes:
     * - Short timeout (5min) minimizes replay attack window
     * - Session tickets rotated automatically by OpenSSL
     * - Perfect Forward Secrecy still maintained
     */
    /* Enable session cache (uses OpenSSL's built-in hash table)
     * Future optimization: Could use external storage (SHM) for multi-instance sharing */
    SSL_CTX_set_session_cache_mode(g_default_sslctx, SSL_SESS_CACHE_SERVER);

    /* Session cache capacity: 100K sessions (~50MB RAM)
     * Calculated: 100,000 sessions × ~512 bytes/session = ~51.2 MB
     * This supports ~200K connections with 50% reconnect rate */
    SSL_CTX_sess_set_cache_size(g_default_sslctx, TLSGATENG_SSL_SESS_CACHE_SIZE);

    /* Session timeout: 5 minutes
     * Balance between performance and security:
     * - Mobile apps: reconnect every 30-60 seconds (covered)
     * - Web browsers: tabs stay open 1-5 minutes (covered)
     * - Security: short enough to minimize PFS concerns */
    SSL_CTX_set_timeout(g_default_sslctx, TLSGATENG_SSL_SESS_TIMEOUT);

    printf("TLS engine initialized successfully!\n");
    printf("  Session cache: %d sessions, %d second timeout\n",
           TLSGATENG_SSL_SESS_CACHE_SIZE, TLSGATENG_SSL_SESS_TIMEOUT);
    printf("\n");

    /* Pure keypool generator mode - no network ports */
    if (config.is_keygen && config.http_port == 0 && config.https_port == 0 && config.auto_port == 0) {
        printf("╔════════════════════════════════════════════════════════╗\n");
        printf("║  KEYPOOL GENERATOR MODE (no network ports)           ║\n");
        printf("╚════════════════════════════════════════════════════════╝\n");
        printf("\n");

        /* Initialize HA leader election if configured */
        ha_role_t ha_role = config.ha_role ? ha_role_from_string(config.ha_role) : HA_ROLE_DISABLED;
        if (ha_role != HA_ROLE_DISABLED) {
            printf("HA Mode: %s\n", ha_role_to_string(ha_role));

            /* Initialize HA with lock in /var/run/tlsgateNG */
            if (!ha_leader_init(&g_ha_leader, ha_role, "/var/run/tlsgateNG")) {
                fprintf(stderr, "Error: Failed to initialize HA leader election\n");
                cleanup_tls();
                config_file_free(master_config);
                return 1;
            }

            /* Try to acquire leadership */
            if (!ha_leader_try_acquire(&g_ha_leader)) {
                /* Not leader yet - start monitor thread and wait */
                printf("Another poolgen instance is active. Waiting in STANDBY...\n");
                printf("Press Ctrl+C to stop\n");
                printf("\n");

                /* Start monitor thread to check for leadership */
                ha_leader_start_monitor(&g_ha_leader);

                /* Wait until we become leader or shutdown */
                while (atomic_load_explicit(&g_running, memory_order_acquire) && !ha_leader_is_active(&g_ha_leader)) {
                    sleep(1);
                }

                /* Check if we should shutdown */
                if (!atomic_load_explicit(&g_running, memory_order_acquire)) {
                    printf("\nShutdown requested while in STANDBY\n");
                    ha_leader_cleanup(&g_ha_leader);
                    cleanup_tls();
                    config_file_free(master_config);
                    return 0;
                }

                printf("\n");
                printf("╔════════════════════════════════════════════════════════╗\n");
                printf("║  FAILOVER: Acquired leadership!                       ║\n");
                printf("╚════════════════════════════════════════════════════════╝\n");
                printf("\n");
            }

            printf("HA Status: ACTIVE (leader)\n");
            printf("\n");
        }

        printf("Running as dedicated keypool generator...\n");
        printf("Shared memory keypool will be filled by background threads.\n");
        printf("Press Ctrl+C to stop\n");
        printf("\n");

        /* Start keypool refill threads */
        if (keypool_start_refill(g_keypool, config.worker_count) != KEYPOOL_OK) {
            fprintf(stderr, "Warning: Failed to start keypool refill threads\n");
        }

        /* Start watchdog thread to monitor and restart workers */
        keypool_shm_t *shm_pool = keypool_get_shm_pool(g_keypool);
        if (shm_pool != NULL) {
            if (watchdog_start(shm_pool, argv[0]) == 0) {
                printf("Watchdog started: monitoring workers every %d seconds\n", WATCHDOG_CHECK_INTERVAL);
            } else {
                fprintf(stderr, "Warning: Failed to start watchdog thread\n");
            }
        }

        /* Start certificate maintenance thread (poolgen is index master)
         *
         * The poolgen handles:
         * - Certificate index management (SHM certcache)
         * - Auto-renewal of certificates expiring within 7 days
         * - Periodic backup of keypool and index
         *
         * Workers only READ from the index, poolgen WRITES.
         */
        if (master_config->index_master && g_cert_gen && config.ca_base_dir) {
            g_cert_generator = g_cert_gen;
            g_ca_base_dir = config.ca_base_dir;
            atomic_store(&g_maintenance_running, 1);

            if (pthread_create(&g_maintenance_thread, NULL, maintenance_thread_func, NULL) != 0) {
                fprintf(stderr, "Warning: Failed to start maintenance thread\n");
                atomic_store(&g_maintenance_running, 0);
            } else {
                printf("Certificate maintenance started (12-hour renewal cycle)\n");
                printf("  - Auto-renews certificates expiring within 7 days\n");
                printf("  - Manages SHM certificate index\n");
            }
        }

        /* Simple idle loop - just wait for shutdown signal */
        while (atomic_load_explicit(&g_running, memory_order_acquire)) {
            sleep(10);

            /* Process any pending signal actions (SIGUSR1 stats, SIGHUP reload) */
            process_signal_actions();

            /* Print stats periodically */
            keypool_stats_t stats;
            keypool_get_stats(g_keypool, &stats);
            printf("[KEYGEN] Pool: %d/%d keys (%.1f%% full), Generated: %d, Consumed: %d\n",
                   stats.current_available, stats.pool_capacity,
                   stats.fill_ratio * 100.0f,
                   stats.total_generated, stats.total_consumed);
        }

        printf("\nStopping keypool generator...\n");

        /* Stop maintenance thread if running */
        if (atomic_load_explicit(&g_maintenance_running, memory_order_acquire)) {
            atomic_store(&g_maintenance_running, 0);
            pthread_join(g_maintenance_thread, NULL);
            printf("Certificate maintenance stopped\n");
        }

        watchdog_stop();  /* Stop watchdog thread */
        keypool_stop_refill(g_keypool);

        /* Cleanup HA leader election if enabled */
        if (config.ha_role != NULL) {
            ha_leader_cleanup(&g_ha_leader);
        }

        cleanup_tls();
        config_file_free(master_config);
        printf("Keypool generator stopped\n");
        return 0;
    }

    /* Create listening sockets (only for enabled ports) */
    int http_fd = -1, https_fd = -1, auto_fd = -1, auto_udp_fd = -1;

    if (config.http_port > 0) {
        http_fd = create_listener(config.listen_addr, config.http_port);
        if (http_fd < 0) {
            cleanup_tls();
            config_file_free(master_config);
            return 1;
        }
        printf("✓ HTTP port %d listening on %s\n", config.http_port, config.listen_addr);
    } else {
        printf("✗ HTTP port disabled\n");
    }

    if (config.https_port > 0) {
        https_fd = create_listener(config.listen_addr, config.https_port);
        if (https_fd < 0) {
            if (http_fd >= 0) close(http_fd);
            cleanup_tls();
            config_file_free(master_config);
            return 1;
        }
        printf("✓ HTTPS port %d listening on %s\n", config.https_port, config.listen_addr);
    } else {
        printf("✗ HTTPS port disabled\n");
    }

    if (config.auto_port > 0) {
        /* TCP listener for AUTO port */
        auto_fd = create_listener(config.listen_addr, config.auto_port);
        if (auto_fd < 0) {
            if (http_fd >= 0) close(http_fd);
            if (https_fd >= 0) close(https_fd);
            cleanup_tls();
            config_file_free(master_config);
            return 1;
        }
        printf("✓ AUTO port %d (TCP) listening on %s (MSG_PEEK detection)\n", config.auto_port, config.listen_addr);

        /* UDP listener for AUTO port (QUIC/HTTP3) */
        auto_udp_fd = create_udp_listener(config.listen_addr, config.auto_port);
        if (auto_udp_fd < 0) {
            fprintf(stderr, "Warning: Failed to create UDP listener for AUTO port\n");
            /* Continue without UDP - not critical */
        } else {
            printf("✓ AUTO port %d (UDP) listening on %s (QUIC/HTTP3 support)\n", config.auto_port, config.listen_addr);
        }
    } else {
        printf("✗ AUTO port disabled\n");
    }
    printf("\n");

    /* Drop privileges if requested (SECURITY)
     *
     * This MUST happen:
     * 1. AFTER binding privileged ports (80/443) - requires root
     * 2. AFTER loading CA key (ca.key with 600 permissions) - requires root
     * 3. BEFORE starting worker threads - they run as unprivileged user
     *
     * Security rationale: Server handles malicious URLs, minimize attack surface
     * by running workers as unprivileged user (defense in depth)
     */
    if (config.drop_user || config.drop_group) {
        /* Setup HTML file permissions BEFORE dropping privileges
         * Ensures non-root user can read the HTML file after privilege drop */
        if (master_config && master_config->default_html_path[0] != '\0') {
            setup_html_permissions(master_config->default_html_path,
                                   config.drop_user, config.drop_group);

            /* Generate 100 HTML variants for anti-detection
             * Each request gets different variant → defeats pattern matching
             * All generated BEFORE dropping privileges (file access required) */
            html_variant_cache_t *variant_cache = html_variant_cache_create(
                master_config->default_html_path, 100);

            if (variant_cache) {
                html_variant_cache_set(variant_cache);
                printf("✓ HTML variant cache ready: 100 variants in memory\n");
            } else {
                fprintf(stderr, "WARNING: Failed to generate HTML variants\n");
                /* Fall back to single pre-loaded version if variant generation fails */
                printf("Pre-loading single HTML version as fallback...\n");
                html_content_t *cached_html = html_content_load(master_config->default_html_path);
                if (cached_html) {
                    html_content_set_cache(cached_html);
                    printf("✓ HTML cached: %zu bytes from %s (fallback)\n",
                           cached_html->length, master_config->default_html_path);
                }
            }
        }

        /* Setup working directory permissions BEFORE dropping privileges
         * Ensures certs/, index/, backup/ are writable by the unprivileged user */
        setup_working_directory_permissions(config.ca_base_dir,
                                            config.drop_user, config.drop_group,
                                            master_config->backup_path,
                                            master_config->keypool_path);

        /* Fix CA directory permissions BEFORE dropping privileges
         * Ensures rootCA directories are root:root even if they were incorrectly owned by tlsgateNX */
        fix_ca_permissions(config.ca_base_dir);

        /* Setup framework-logging directory with proper ownership BEFORE dropping privileges */
        security_intel_setup_log_dir(config.drop_user, config.drop_group);

        if (drop_privileges(config.drop_user, config.drop_group) < 0) {
            fprintf(stderr, "Failed to drop privileges - aborting for security\n");
            goto cleanup;
        }
    }

    /* Create workers */
    g_workers = calloc(config.worker_count, sizeof(worker_t*));
    if (!g_workers) {
        perror("calloc");
        if (http_fd >= 0) close(http_fd);
        if (https_fd >= 0) close(https_fd);
        if (auto_fd >= 0) close(auto_fd);
        if (auto_udp_fd >= 0) close(auto_udp_fd);
        cleanup_tls();
        config_file_free(master_config);
        return 1;
    }

    g_worker_count = config.worker_count;

    printf("Creating %d workers...\n", config.worker_count);
    for (int i = 0; i < config.worker_count; i++) {
        g_workers[i] = worker_create(i, config.max_connections);
        if (!g_workers[i]) {
            fprintf(stderr, "Failed to create worker %d\n", i);
            goto cleanup;
        }

        if (worker_start(g_workers[i]) < 0) {
            fprintf(stderr, "Failed to start worker %d\n", i);
            goto cleanup;
        }
    }

    printf("All workers started!\n");
    printf("\n");

    /* Start certificate maintenance thread (12-hour auto-renewal)
     * Only start if:
     *   1. We have a certificate generator and CA base directory
     *   2. This instance is configured as index_master (from [index] section)
     *
     * In multi-instance deployments (e.g., tlsgateNGv4 + tlsgateNGv6):
     *   - Only ONE instance should have index_master=true
     *   - That instance handles cert renewals and index writes
     *   - Other instances are read-only (no maintenance thread)
     */
    if (g_cert_gen && config.ca_base_dir) {
        if (master_config->index_master) {
            g_cert_generator = g_cert_gen;
            g_ca_base_dir = config.ca_base_dir;
            atomic_store(&g_maintenance_running, 1);

            if (pthread_create(&g_maintenance_thread, NULL, maintenance_thread_func, NULL) != 0) {
                fprintf(stderr, "Warning: Failed to start maintenance thread\n");
                atomic_store(&g_maintenance_running, 0);
            } else {
                printf("Certificate maintenance thread started (12-hour auto-renewal)\n");
                printf("  - Mode: INDEX MASTER (manages renewals and index writes)\n");
                printf("  - Monitors: RSA, ECDSA, SM2 (国密/商用密码)\n");
                printf("  - Auto-renews certificates expiring within 7 days\n");
                printf("\n");
            }
        } else {
            printf("Certificate maintenance thread: DISABLED (index_master=false)\n");
            printf("  - Mode: INDEX SLAVE (read-only, no renewals)\n");
            printf("  - Another instance should be configured as index master\n");
            printf("\n");
        }
    }

    printf("Ready to accept connections...\n");
    printf("Press Ctrl+C to stop, send SIGUSR1 for stats\n");
    printf("\n");

    /* Register with watchdog if SHM is available (not in keygen mode) */
    keypool_shm_t *shm_pool_worker = config.use_shm_keypool ? keypool_get_shm_pool(g_keypool) : NULL;
    if (!config.is_keygen && shm_pool_worker != NULL) {
        g_watchdog_pool = shm_pool_worker;
        g_worker_slot = worker_register(shm_pool_worker, argc, argv,
                                        config.listen_addr,
                                        config.http_port,
                                        config.https_port,
                                        config.auto_port);
        if (g_worker_slot >= 0) {
            g_last_heartbeat = time(NULL);
            printf("Registered with watchdog: slot %d\n", g_worker_slot);
        }
    }

    /* Main accept loop - monitors all 3 ports */
    accept_loop(http_fd, https_fd, auto_fd, auto_udp_fd, g_workers, config.worker_count);

    printf("Shutting down workers...\n");

    /* Unregister from watchdog (graceful shutdown) */
    if (g_worker_slot >= 0 && g_watchdog_pool != NULL) {
        worker_unregister(g_watchdog_pool, g_worker_slot);
        printf("Unregistered from watchdog\n");
    }

cleanup:
    /* Stop maintenance thread if running */
    if (atomic_load_explicit(&g_maintenance_running, memory_order_acquire)) {
        printf("Stopping certificate maintenance thread...\n");
        atomic_store(&g_maintenance_running, 0);
        pthread_join(g_maintenance_thread, NULL);
        printf("Maintenance thread stopped\n");
    }

    /* Stop and destroy workers */
    for (int i = 0; i < config.worker_count; i++) {
        if (g_workers[i]) {
            worker_destroy(g_workers[i]);
        }
    }

    free(g_workers);

    /* Close listening sockets (only if they were opened) */
    if (http_fd >= 0) close(http_fd);
    if (https_fd >= 0) close(https_fd);
    if (auto_fd >= 0) close(auto_fd);
    if (auto_udp_fd >= 0) close(auto_udp_fd);

    /* Cleanup TLS resources */
    cleanup_tls();

    /* Free master config */
    config_file_free(master_config);

    printf("Shutdown complete\n");
    return 0;
}
