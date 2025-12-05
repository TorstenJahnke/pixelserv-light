/* TLS-Gate NX - Shared Memory Manager
 * Copyright (C) 2025 Torsten Jahnke
 *
 * Modern, thread-safe shared memory abstraction for:
 * - Key pool sharing across 40+ instances (~3GB SHM)
 * - Certificate index sharing across all instances (~10GB SHM, 30M domains)
 * - High-availability primary/secondary failover
 */

#ifndef TLSGATENG_SHM_MANAGER_H
#define TLSGATENG_SHM_MANAGER_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include <pthread.h>
#include <stdatomic.h>
#include <errno.h>

/* Robust mutex lock helper for PTHREAD_MUTEX_ROBUST
 * Handles EOWNERDEAD: when previous owner died (SIGKILL) while holding the lock,
 * we recover the mutex with pthread_mutex_consistent() and continue.
 * This prevents deadlocks when processes are forcefully killed.
 */
static inline int robust_mutex_lock(pthread_mutex_t *mutex) {
    int ret = pthread_mutex_lock(mutex);
    if (ret == EOWNERDEAD) {
        /* Previous owner died - recover the mutex */
        pthread_mutex_consistent(mutex);
        return 0;  /* Lock acquired after recovery */
    }
    return ret;
}

/* Error codes */
typedef enum {
    SHM_OK = 0,
    SHM_ERR_NOMEM = -1,
    SHM_ERR_INVALID = -2,
    SHM_ERR_CREATE = -3,
    SHM_ERR_ATTACH = -4,
    SHM_ERR_LOCK = -5,
    SHM_ERR_MAGIC = -6,
    SHM_ERR_VERSION = -7
} shm_error_t;

/* Key Pool Configuration */
#define KEY_POOL_SIZE_SHARED 1280000   /* Shared pool size (~3GB SHM limit for security) */
#define KEY_POOL_SIZE_LOCAL 128000     /* Local fallback pool (per instance) */
#define KEY_POOL_BUNDLE_MAX_AGE (7 * 86400)  /* 7 days */

/* Adaptive refill thresholds */
#define REFILL_AGGRESSIVE_PCT 25       /* <25% full: aggressive refill */
#define REFILL_FAST_PCT 50             /* <50% full: fast refill */
#define REFILL_SLOW_PCT 75             /* >75% full: slow refill */

/* Worker Watchdog Configuration */
#define MAX_WATCHED_WORKERS 64           /* Max workers per server */
#define WORKER_HEARTBEAT_INTERVAL 30     /* Heartbeat every 30 seconds */
#define WORKER_HEARTBEAT_TIMEOUT 120     /* Consider dead after 2 minutes */
#define WATCHDOG_CHECK_INTERVAL 300      /* Check workers every 5 minutes */
#define WORKER_CMDLINE_MAX 1024          /* Max command line length */

/* Certificate Cache Configuration */
#define CERT_CACHE_SIZE_DEFAULT 1000000  /* Default: 1M domains (~320MB SHM) */
#define CERT_CACHE_SIZE_LOCAL 100        /* Local SSL_CTX cache */
#define CERT_INDEX_ENTRY_NAME_LEN 256

/* Second-Level TLD Storage (shared across workers) */
#define SHM_TLD_MAX_STORAGE (1024UL * 1024 * 1024) /* 1GB for TLDs */

/* Silent Blocker Storage (shared across workers, hot-reloadable) */
#define SHM_SILENTBLOCK_MAX_STORAGE (1024UL * 1024 * 1024) /* 1GB for silent-block rules */

/* Magic numbers for validation */
#define SHM_KEYPOOL_MAGIC 0x504B5348   /* "PKSH" - Keypool SHM */
#define SHM_CERTCACHE_MAGIC 0x43455254 /* "CERT" - Certcache SHM */
#define SHM_VERSION 5  /* Incremented: Added TLD + Silent Blocker storage */

/* Worker Entry for Watchdog Registry
 *
 * Each worker registers itself when starting.
 * Poolgen watchdog monitors all registered workers.
 */
typedef struct {
    atomic_int pid;                      /* Worker PID (0 = slot empty) */
    atomic_llong last_heartbeat;         /* time(NULL) of last heartbeat */
    atomic_llong start_time;             /* time(NULL) when worker started */
    atomic_int restart_count;            /* Number of times restarted */
    atomic_bool healthy;                 /* true if worker is responding */
    char cmdline[WORKER_CMDLINE_MAX];    /* Full command line for restart */
    char listen_addr[64];                /* Listen address (for logging) */
    atomic_int http_port;                /* HTTP port */
    atomic_int https_port;               /* HTTPS port */
    atomic_int auto_port;                /* AUTO port */
} __attribute__((aligned(64))) worker_entry_t;

/* Compile-time checks */
_Static_assert(SHM_KEYPOOL_MAGIC == 0x504B5348, "Keypool magic mismatch");
_Static_assert(SHM_CERTCACHE_MAGIC == 0x43455254, "Certcache magic mismatch");
_Static_assert(KEY_POOL_SIZE_SHARED > 0, "Invalid key pool size");
_Static_assert(CERT_CACHE_SIZE_DEFAULT > 0, "Invalid cert cache default size");

/* Keypool Shared Memory Structure
 *
 * Created by --poolkeygen instance (primary or secondary)
 * Attached by all other instances (readers)
 * Supports 40+ instances sharing one pool
 */
typedef struct {
    uint32_t magic;                      /* SHM_KEYPOOL_MAGIC */
    uint32_t version;                    /* SHM_VERSION */
    pthread_mutex_t lock;                /* PTHREAD_PROCESS_SHARED */

    /* Pool state (C11 atomics for lock-free reads) */
    atomic_int available;                /* Keys available for use */
    int capacity;                        /* Max capacity */

    /* Generator state */
    atomic_bool is_keygen;               /* true=Generator, false=Reader */
    atomic_bool shutdown;                /* true=Shutdown requested */
    atomic_bool backup_restored;         /* true=Backup already restored after reboot */

    /* Restore locks - refill waits for ALL to be false before generating keys
     * Each lock is set on SHM creation, cleared when respective operation completes.
     * If file doesn't exist, lock is still cleared (no stuck locks). */
    atomic_bool restore_lock_shm_backup; /* true=SHM backup restore pending */
    atomic_bool restore_lock_keybundle;  /* true=Keybundle restore pending */
    atomic_bool restore_lock_prime;      /* true=Prime pool loading pending */

    /* High-Availability Failover */
    atomic_llong last_keygen_heartbeat;  /* time(NULL) - atomic for lock-free read */
    atomic_int keygen_pid;               /* PID of active generator */
    atomic_bool is_secondary;            /* Secondary has taken over */
    uint8_t reserved[2];                 /* Alignment padding */

    /* Key storage - append-only circular buffer */
    atomic_int pem_write_cursor;         /* Next write position */
    atomic_int key_offsets[KEY_POOL_SIZE_SHARED];      /* -1 = empty */
    atomic_uint key_lengths[KEY_POOL_SIZE_SHARED];     /* PEM length */
    atomic_int key_algorithms[KEY_POOL_SIZE_SHARED];   /* Algorithm type (crypto_alg_t) */

    /* PEM data: [uint32_t len][pem_data][uint32_t len][pem_data]... */
    char pem_storage[KEY_POOL_SIZE_SHARED * 2500UL];  /* ~2.5KB per RSA-3072 (UL prevents overflow) */

    /* Worker Watchdog Registry
     * Managed by poolgen, workers register themselves here */
    atomic_bool watchdog_enabled;            /* true if watchdog is active */
    atomic_int worker_count;                 /* Number of registered workers */
    worker_entry_t workers[MAX_WATCHED_WORKERS];  /* Worker registry */
} __attribute__((aligned(64))) keypool_shm_t;  /* Cache-line aligned */

/* Certificate Index Entry */
typedef struct {
    char cert_name[CERT_INDEX_ENTRY_NAME_LEN];  /* No pointers - value type */
    atomic_uint last_use;                       /* process_uptime() */
    atomic_int reuse_count;                     /* Popularity */
    atomic_bool generation_in_progress;         /* Being generated */
    atomic_int generator_pid;                   /* Generating process */
    atomic_int algorithm;                       /* crypto_alg_t - key algorithm */
    atomic_llong expiry_time;                   /* Certificate expiry timestamp */
    atomic_bool on_disk;                        /* true if cert saved to disk */
    atomic_bool valid;                          /* true if entry is in use */
    uint8_t reserved[2];                        /* Padding */
} __attribute__((aligned(64))) certindex_entry_t;  /* Cache-line aligned */

/* Certificate Cache Shared Memory Structure
 *
 * Created by master (Poolgen) instance
 * Attached by all worker instances
 * Shared certificate index across all processes
 *
 * NOTE: Uses flexible array member for runtime-configurable capacity.
 * Actual SHM size = sizeof(certcache_shm_t) + capacity * sizeof(certindex_entry_t)
 */
typedef struct {
    uint32_t magic;                      /* SHM_CERTCACHE_MAGIC */
    uint32_t version;                    /* SHM_VERSION */
    pthread_mutex_t lock;                /* PTHREAD_PROCESS_SHARED */

    atomic_int count;                    /* Entries in use */
    int capacity;                        /* Runtime-configurable capacity */

    /* Master management */
    atomic_int master_pid;               /* PID of master (Poolgen) */
    atomic_llong last_save_time;         /* Last disk save timestamp */
    atomic_bool dirty;                   /* true if changes since last save */
    uint8_t reserved[5];                 /* Padding */

    /* Second-Level TLD storage (loaded by Poolgen, read by Workers)
     * Format: newline-separated TLDs (e.g., ".co.uk\n.com.au\n...")
     * Workers parse this once on startup to build local hash set */
    atomic_int tld_data_len;             /* Length of TLD data (0 = not loaded) */
    char tld_data[SHM_TLD_MAX_STORAGE];  /* Newline-separated TLDs (~512KB) */

    /* Silent Blocker storage (loaded by Poolgen, hot-reloadable via SIGHUP)
     * Format: raw file content (domain path-pattern delay status per line)
     * Workers check silentblock_version periodically for hot-reload */
    atomic_int silentblock_version;      /* Incremented on each reload (for hot-reload) */
    atomic_int silentblock_data_len;     /* Length of data (0 = not loaded) */
    char silentblock_data[SHM_SILENTBLOCK_MAX_STORAGE];  /* Raw file content (~128KB) */

    /* Hash table with open addressing (linear probing) - flexible array member */
    certindex_entry_t entries[];         /* Runtime-sized array */
} __attribute__((aligned(64))) certcache_shm_t;

/* Compile-time size checks */
_Static_assert(sizeof(keypool_shm_t) < 3 * 1024 * 1024 * 1024UL,
              "Keypool SHM too large (>3GB - security limit)");
/* Note: certcache_shm_t uses flexible array member, size is runtime-configurable */

/* Keypool SHM Management */

/* Create or attach to keypool shared memory
 *
 * @param is_keygen  true for generator instance, false for reader
 * @param out_pool   Output: pointer to mapped SHM
 * @param out_fd     Output: file descriptor (for cleanup)
 * @return SHM_OK on success, error code on failure
 */
shm_error_t keypool_shm_init(bool is_keygen, keypool_shm_t **out_pool, int *out_fd);

/* Cleanup keypool SHM (unmap and close) */
void keypool_shm_cleanup(keypool_shm_t *pool, int fd);

/* Certcache SHM Management */

/* Create or attach to certcache shared memory
 *
 * @param pem_dir    Certificate directory path
 * @param pool_name  Optional pool name for multi-instance
 * @param capacity   Number of entries (hash table size), use CERT_CACHE_SIZE_DEFAULT for default
 * @param out_cache  Output: pointer to mapped SHM
 * @param out_fd     Output: file descriptor (for cleanup)
 * @param out_name   Output: SHM name (for debugging)
 * @param name_len   Length of out_name buffer
 * @return SHM_OK on success, error code on failure
 *
 * NOTE: capacity determines SHM size: sizeof(header) + capacity * sizeof(entry)
 *       Typical values: 1M (~320MB), 10M (~3.2GB), 30M (~9.6GB)
 */
shm_error_t certcache_shm_init(const char *pem_dir, const char *pool_name,
                                size_t capacity,
                                certcache_shm_t **out_cache, int *out_fd,
                                char *out_name, size_t name_len);

/* Cleanup certcache SHM
 *
 * @param cache     Shared cache
 * @param fd        File descriptor
 *
 * NOTE: Uses cache->capacity to determine unmap size
 */
void certcache_shm_cleanup(certcache_shm_t *cache, int fd);

/* Calculate SHM size for given capacity */
static inline size_t certcache_shm_size(size_t capacity) {
    return sizeof(certcache_shm_t) + capacity * sizeof(certindex_entry_t);
}

/* Lookup certificate in shared index
 *
 * @param cache      Shared cache
 * @param cert_name  Certificate name to lookup
 * @param out_entry  Output: found entry (if exists)
 * @return true if found, false otherwise
 */
bool certcache_shm_lookup(const certcache_shm_t *cache, const char *cert_name,
                          certindex_entry_t *out_entry);

/* Insert certificate into shared index
 *
 * @param cache                  Shared cache
 * @param cert_name              Certificate name
 * @param generation_in_progress Mark as being generated
 * @return SHM_OK on success, error code on failure
 */
shm_error_t certcache_shm_insert(certcache_shm_t *cache, const char *cert_name,
                                  bool generation_in_progress);

/* Insert certificate with full metadata
 *
 * @param cache       Shared cache
 * @param cert_name   Domain name (e.g., "example.com")
 * @param algorithm   Key algorithm (crypto_alg_t)
 * @param expiry_time Certificate expiry timestamp
 * @param on_disk     true if cert file saved to disk
 * @return SHM_OK on success, error code on failure
 */
shm_error_t certcache_shm_insert_full(certcache_shm_t *cache,
                                       const char *cert_name,
                                       int algorithm,
                                       time_t expiry_time,
                                       bool on_disk);

/* Lookup certificate with algorithm filter
 *
 * @param cache      Shared cache
 * @param cert_name  Domain name to lookup
 * @param algorithm  Expected algorithm (-1 for any)
 * @param out_entry  Output: found entry (if exists)
 * @return true if found with matching algorithm, false otherwise
 */
bool certcache_shm_lookup_full(const certcache_shm_t *cache,
                                const char *cert_name,
                                int algorithm,
                                certindex_entry_t *out_entry);

/* Update certificate expiry time
 *
 * @param cache       Shared cache
 * @param cert_name   Domain name
 * @param algorithm   Key algorithm
 * @param expiry_time New expiry timestamp
 * @return true on success, false if not found
 */
bool certcache_shm_update_expiry(certcache_shm_t *cache,
                                  const char *cert_name,
                                  int algorithm,
                                  time_t expiry_time);

/* Save SHM index to disk file
 *
 * @param cache     Shared cache
 * @param filepath  Output file path
 * @return SHM_OK on success, error code on failure
 *
 * NOTE: Only master (Poolgen) should call this
 */
shm_error_t certcache_shm_save(certcache_shm_t *cache, const char *filepath);

/* Load SHM index from disk file
 *
 * @param cache     Shared cache (must be initialized)
 * @param filepath  Input file path
 * @return SHM_OK on success, error code on failure (file not found is not error)
 *
 * NOTE: Called by master on startup
 */
shm_error_t certcache_shm_load(certcache_shm_t *cache, const char *filepath);

/* Mark entry as having cert on disk
 *
 * @param cache     Shared cache
 * @param cert_name Domain name
 * @param algorithm Key algorithm
 * @return true on success, false if not found
 */
bool certcache_shm_mark_on_disk(certcache_shm_t *cache,
                                 const char *cert_name,
                                 int algorithm);

/* ========== Second-Level TLD API ========== */

/* Load TLDs from file into SHM (called by Poolgen)
 *
 * @param cache     Shared cache
 * @param filepath  Path to TLD file (one TLD per line, e.g., ".co.uk")
 * @return Number of TLDs loaded, or -1 on error
 *
 * NOTE: Only master (Poolgen) should call this
 */
int certcache_shm_load_tlds(certcache_shm_t *cache, const char *filepath);

/* Get TLD data from SHM (called by Workers)
 *
 * @param cache    Shared cache
 * @param out_len  Output: length of TLD data
 * @return Pointer to TLD data (newline-separated), or NULL if not loaded
 *
 * NOTE: Workers use this to build local hash set on startup
 */
const char* certcache_shm_get_tld_data(const certcache_shm_t *cache, int *out_len);

/* ========== Silent Blocker API ========== */

/* Load silent-block rules from file into SHM (called by Poolgen)
 *
 * @param cache     Shared cache
 * @param filepath  Path to silent-blocks.conf
 * @return 0 on success, -1 on error
 *
 * NOTE: Increments silentblock_version for hot-reload detection
 * NOTE: Called by Poolgen on startup and SIGHUP
 */
int certcache_shm_load_silentblocks(certcache_shm_t *cache, const char *filepath);

/* Get silent-block data from SHM (called by Workers)
 *
 * @param cache       Shared cache
 * @param out_len     Output: length of data
 * @param out_version Output: current version (for hot-reload check)
 * @return Pointer to data, or NULL if not loaded
 *
 * NOTE: Workers compare out_version with last seen version to detect updates
 */
const char* certcache_shm_get_silentblock_data(const certcache_shm_t *cache,
                                                int *out_len,
                                                int *out_version);

/* Get current silent-block version (for hot-reload polling)
 *
 * @param cache  Shared cache
 * @return Current version number (0 = not loaded)
 */
static inline int certcache_shm_silentblock_version(const certcache_shm_t *cache) {
    return atomic_load(&cache->silentblock_version);
}

/* ========== Worker Watchdog API ========== */

/* Register worker in watchdog registry
 *
 * Called by workers on startup to register themselves.
 * Poolgen will monitor and restart if worker becomes unresponsive.
 *
 * @param pool        Keypool SHM (contains worker registry)
 * @param argc        Argument count (for restart)
 * @param argv        Argument vector (for restart)
 * @param listen_addr Listen address string
 * @param http_port   HTTP port (0 if disabled)
 * @param https_port  HTTPS port (0 if disabled)
 * @param auto_port   AUTO port (0 if disabled)
 * @return Slot index (0-63), or -1 on error (registry full)
 */
int worker_register(keypool_shm_t *pool, int argc, char **argv,
                    const char *listen_addr, int http_port, int https_port, int auto_port);

/* Unregister worker from watchdog registry
 *
 * Called by workers on graceful shutdown.
 * Prevents watchdog from restarting a cleanly exiting worker.
 *
 * @param pool  Keypool SHM
 * @param slot  Slot index returned by worker_register()
 */
void worker_unregister(keypool_shm_t *pool, int slot);

/* Send heartbeat to watchdog
 *
 * Called periodically by workers (every WORKER_HEARTBEAT_INTERVAL seconds).
 * Missing heartbeats indicate worker is stuck/crashed.
 *
 * @param pool  Keypool SHM
 * @param slot  Slot index returned by worker_register()
 */
void worker_heartbeat(keypool_shm_t *pool, int slot);

/* Start watchdog thread in poolgen
 *
 * Called by poolgen to start monitoring workers.
 * Watchdog checks workers every WATCHDOG_CHECK_INTERVAL seconds.
 * Restarts workers that are dead or unresponsive.
 *
 * @param pool        Keypool SHM
 * @param binary_path Path to worker binary (for restart)
 * @return 0 on success, -1 on error
 */
int watchdog_start(keypool_shm_t *pool, const char *binary_path);

/* Stop watchdog thread
 *
 * Called by poolgen on shutdown.
 * Does NOT kill workers - they continue running.
 */
void watchdog_stop(void);

/* Check if a specific worker is healthy
 *
 * @param pool  Keypool SHM
 * @param slot  Worker slot index
 * @return true if worker is alive and sending heartbeats
 */
bool worker_is_healthy(const keypool_shm_t *pool, int slot);

/* Get worker count */
static inline int watchdog_worker_count(const keypool_shm_t *pool) {
    return atomic_load(&pool->worker_count);
}

/* Utilities */

/* Escape path to create valid SHM name
 * Converts /opt/var/cache/tlsgateNG → _opt_var_cache_tlsgateNG
 */
void escape_path_to_shm_name(const char * restrict pem_dir,
                              char * restrict out, size_t out_len);

#endif /* TLSGATENG_SHM_MANAGER_H */
