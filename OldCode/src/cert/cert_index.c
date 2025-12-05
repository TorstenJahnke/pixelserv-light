/**
 * Certificate Index Implementation
 *
 * High-performance index with:
 * - Hash table for O(1) lookups (10M entries)
 * - Sorted expiry array for renewal scans
 * - LRU cache for SSL_CTX (2M active)
 * - Disk overflow and persistence
 *
 * Author: Torsten Jahnke
 * Copyright: 2025 Aviontex GmbH
 */

#include "cert_index.h"
#include "cert_generator.h"
#include "../util/logger.h"
#include "../util/util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/time.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>

/* Utility: Get current time in microseconds */
static inline long long get_time_us(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (long long)tv.tv_sec * 1000000LL + tv.tv_usec;
}

/* Index entry - stored in hash table */
struct cert_index_entry {
    char *domain;                    /* Domain name (heap allocated) */
    crypto_alg_t algorithm;          /* Key algorithm */
    _Atomic time_t expiry_time;      /* Certificate expiry timestamp (atomic for lock-free renewal) */
    _Atomic time_t last_access;      /* Last access timestamp (atomic for lock-free) */
    _Atomic(SSL_CTX*) ctx;           /* SSL_CTX (atomic for lock-free access) */

    /* Hash table chain (atomic for lock-free insertion) */
    _Atomic(cert_index_entry_t*) hash_next;

    /* CLOCK algorithm (replaces LRU - completely lock-free) */
    _Atomic bool accessed;           /* CLOCK bit: set on access, cleared on eviction scan */

    /* Flags */
    _Atomic bool on_disk;            /* True if SSL_CTX saved to disk */
};

/* Grace-period reclamation for lock-free memory safety
 *
 * When entries are removed from the hash table, readers might still be
 * traversing them. We defer freeing to a "retired list" and only free
 * after a grace period (10 seconds) when all readers are guaranteed done.
 *
 * This is simpler than hazard pointers or epoch-based reclamation
 * and works perfectly for long-running daemon servers.
 */
#define RECLAIM_GRACE_PERIOD_SEC 10

typedef struct retired_entry {
    cert_index_entry_t *entry;       /* Entry to free */
    time_t retired_at;               /* When it was retired */
    struct retired_entry *next;      /* Next in retired list */
} retired_entry_t;

/* Main index structure */
struct cert_index {
    /* Configuration */
    cert_index_config_t config;
    char index_file[512];            /* Full path to index file */
    char disk_cache_dir[512];        /* Directory for SSL_CTX disk cache */

    /* Hash table (lock-free: atomic bucket heads) */
    _Atomic(cert_index_entry_t*) *hash_buckets;

    /* Sorted expiry array (for renewal scans - background only) */
    cert_index_entry_t **expiry_sorted;
    size_t expiry_count;
    pthread_rwlock_t expiry_lock;    /* Only for background renewal thread */

    /* CLOCK eviction algorithm (replaces LRU - lock-free) */
    _Atomic size_t clock_hand;       /* Current position in hash scan */
    _Atomic size_t ctx_in_memory;    /* Count of SSL_CTX currently in RAM */

    /* Background threads */
    pthread_t renewal_thread;
    pthread_t save_thread;
    /* THREAD SAFETY FIX: Use atomic_bool for thread control flags
     * These are written by main thread and read by background threads
     * in loop conditions without any locks, requiring atomics */
    _Atomic bool renewal_running;
    _Atomic bool save_running;
    void *cert_generator;            /* cert_generator_t* */

    /* Statistics */
    cert_index_stats_t stats;

    /* Dirty flag for async saves */
    _Atomic bool dirty;

    /* Grace-period memory reclamation */
    retired_entry_t *retired_list;   /* List of entries waiting to be freed */
    pthread_mutex_t retired_lock;    /* Protects retired_list (rare access) */
};

/* Binary index format (512-byte aligned entries) */
#define INDEX_MAGIC 0x544C5349444E58ULL  /* "TLSINDX" */
#define INDEX_VERSION 1
#define INDEX_ENTRY_SIZE 512

typedef struct {
    uint64_t magic;                  /* Magic number */
    uint32_t version;                /* Format version */
    uint32_t entry_count;            /* Number of entries */
    uint64_t timestamp;              /* Save timestamp */
    uint8_t reserved[488];           /* Padding to 512 bytes */
} __attribute__((packed)) index_header_t;

typedef struct {
    char domain[256];                /* Domain name */
    uint32_t algorithm;              /* crypto_alg_t */
    uint64_t expiry_time;            /* Certificate expiry */
    uint64_t last_access;            /* LRU timestamp */
    uint8_t on_disk;                 /* 1 if SSL_CTX on disk */
    uint8_t reserved[239];           /* Padding to 512 bytes */
} __attribute__((packed)) index_entry_disk_t;

/* Hash function (DJB2) */
static uint64_t hash_domain(const char *domain, crypto_alg_t algorithm) {
    uint64_t hash = 5381;
    int c;

    while ((c = *domain++)) {
        hash = ((hash << 5) + hash) + c; /* hash * 33 + c */
    }

    hash = ((hash << 5) + hash) + algorithm;
    return hash;
}

/* Create SSL_CTX disk filename
 * Note: In Multi-CA mode, disk_cache_dir is already algorithm-specific
 * (e.g., /opt/Aviontex/certs/RSA), so we can use domain.pem directly */
static void get_disk_cache_path(cert_index_t *index,
                                const char *domain,
                                crypto_alg_t algorithm,
                                char *path, size_t path_size) {
    (void)algorithm; /* Unused - algorithm is implicit in disk_cache_dir path */
    snprintf(path, path_size, "%s/%s.pem",
             index->disk_cache_dir, domain);
}

/* Validate file permissions and ownership */
static bool validate_file_permissions(const char *path,
                                      uid_t expected_uid,
                                      gid_t expected_gid,
                                      mode_t expected_mode) {
    struct stat st;
    if (stat(path, &st) != 0) {
        return false; /* File doesn't exist - ok */
    }

    /* Check ownership */
    if (st.st_uid != expected_uid || st.st_gid != expected_gid) {
        LOG_ERROR("File ownership mismatch: %s (expected %d:%d, got %d:%d)",
                  path, expected_uid, expected_gid, st.st_uid, st.st_gid);
        return false;
    }

    /* Check permissions (mask to file mode bits) */
    mode_t actual_mode = st.st_mode & 0777;
    if (actual_mode != expected_mode) {
        LOG_ERROR("File permission mismatch: %s (expected %o, got %o)",
                  path, expected_mode, actual_mode);
        return false;
    }

    return true;
}

/* CLOCK algorithm for eviction (completely lock-free)
 *
 * The CLOCK algorithm is a page replacement algorithm that approximates LRU
 * without requiring any locks on the hot path:
 *
 * - Each entry has an "accessed" bit (atomic bool)
 * - On cache hit: Set accessed=true (atomic store, no lock)
 * - On eviction: Scan hash table starting from clock_hand:
 *   - If accessed=true: Set to false, move to next
 *   - If accessed=false: Evict this entry
 *
 * This is O(n) worst case for eviction, but eviction is rare and happens
 * in the background. The hot path (lookup) is completely lock-free!
 */

/* Mark entry as accessed (lock-free, called on every cache hit) */
static inline void clock_mark_accessed(cert_index_entry_t *entry) {
    atomic_store_explicit(&entry->accessed, true, memory_order_relaxed);
}

/* CLOCK eviction: Find and evict one entry
 * Returns the evicted entry, or NULL if nothing to evict
 * This is called when ctx_in_memory > lru_cache_size */
static cert_index_entry_t* clock_find_victim(cert_index_t *index) {
    size_t buckets = index->config.hash_buckets;
    size_t max_scan = buckets * 2;  /* Limit scan to prevent infinite loop */

    for (size_t scan = 0; scan < max_scan; scan++) {
        /* Advance clock hand atomically */
        size_t hand = atomic_fetch_add(&index->clock_hand, 1) % buckets;

        /* Scan this bucket */
        cert_index_entry_t *entry = atomic_load_explicit(&index->hash_buckets[hand], memory_order_acquire);
        while (entry) {
            SSL_CTX *ctx = atomic_load_explicit(&entry->ctx, memory_order_acquire);

            /* Skip entries without SSL_CTX in memory */
            if (!ctx) {
                entry = atomic_load_explicit(&entry->hash_next, memory_order_acquire);
                continue;
            }

            /* Check accessed bit */
            if (atomic_load_explicit(&entry->accessed, memory_order_acquire)) {
                /* Recently accessed - give second chance */
                atomic_store(&entry->accessed, false);
            } else {
                /* Not recently accessed - victim found! */
                return entry;
            }

            entry = atomic_load_explicit(&entry->hash_next, memory_order_acquire);
        }
    }

    return NULL;  /* No victim found (all recently accessed) */
}

/* Grace-period reclamation: Add entry to retired list
 * Called after removing entry from hash table */
static void retire_entry(cert_index_t *index, cert_index_entry_t *entry) {
    retired_entry_t *retired = malloc(sizeof(retired_entry_t));
    if (!retired) {
        /* Worst case: leak memory rather than crash */
        LOG_WARN("Failed to allocate retired_entry - memory leak");
        return;
    }

    retired->entry = entry;
    retired->retired_at = time(NULL);

    pthread_mutex_lock(&index->retired_lock);
    retired->next = index->retired_list;
    index->retired_list = retired;
    pthread_mutex_unlock(&index->retired_lock);
}

/* Grace-period reclamation: Free entries that have passed grace period
 * Called periodically from save_thread */
static void reclaim_retired_entries(cert_index_t *index) {
    time_t now = time(NULL);
    time_t threshold = now - RECLAIM_GRACE_PERIOD_SEC;

    pthread_mutex_lock(&index->retired_lock);

    retired_entry_t **pp = &index->retired_list;
    size_t freed = 0;

    while (*pp) {
        retired_entry_t *r = *pp;

        if (r->retired_at <= threshold) {
            /* Grace period passed - safe to free */
            *pp = r->next;  /* Unlink from list */

            /* Free the actual entry */
            cert_index_entry_t *entry = r->entry;
            free(entry->domain);
            free(entry);
            free(r);
            freed++;
        } else {
            /* Not yet safe - keep in list */
            pp = &r->next;
        }
    }

    pthread_mutex_unlock(&index->retired_lock);

    if (freed > 0) {
        LOG_DEBUG("Reclaimed %zu retired entries", freed);
    }
}

/* Evict SSL_CTX to disk (lock-free using CAS) */
static bool evict_to_disk(cert_index_t *index, cert_index_entry_t *entry) {
    SSL_CTX *ctx = atomic_load_explicit(&entry->ctx, memory_order_acquire);
    if (!ctx || atomic_load_explicit(&entry->on_disk, memory_order_acquire)) {
        return true; /* Already evicted */
    }

    /* Evict SSL_CTX from memory (certificate already on disk)
     *
     * Certificates are saved to disk during generation (save_cert_chain_to_pem)
     * On eviction: Free memory, mark as on_disk
     * On cache miss: Reload from disk via load_from_disk()
     *
     * This is memory pressure management, not serialization - certs already persisted
     */
    LOG_DEBUG("Evicting SSL_CTX to disk: %s", entry->domain);

    /* Use CAS to atomically set ctx to NULL - only succeeds if no one else changed it */
    if (atomic_compare_exchange_strong(&entry->ctx, &ctx, NULL)) {
        /* We won the race - we're responsible for freeing */
        SSL_CTX_free(ctx);
        atomic_store(&entry->on_disk, true);
        atomic_fetch_sub(&index->ctx_in_memory, 1);
        atomic_fetch_add(&index->stats.evictions, 1);
        return true;
    }

    /* Someone else already evicted or changed it */
    return false;
}

/* Load SSL_CTX from disk (lock-free using CAS) */
static bool load_from_disk(cert_index_t *index, cert_index_entry_t *entry) {
    if (atomic_load_explicit(&entry->ctx, memory_order_acquire) || !atomic_load_explicit(&entry->on_disk, memory_order_acquire)) {
        return true; /* Already in memory */
    }

    char path[1024];
    get_disk_cache_path(index, entry->domain, entry->algorithm, path, sizeof(path));

    LOG_DEBUG("Loading SSL_CTX from disk: %s", path);

    /* Open PEM file */
    FILE *fp = fopen(path, "rb");
    if (!fp) {
        LOG_ERROR("Failed to open PEM file: %s (%s)", path, strerror(errno));
        entry->on_disk = false;
        return false;
    }

    /* Read server certificate */
    X509 *cert = PEM_read_X509(fp, NULL, NULL, NULL);
    if (!cert) {
        LOG_ERROR("Failed to read certificate from PEM: %s", path);
        fclose(fp);
        entry->on_disk = false;
        return false;
    }

    /* Read CA chain (all certs until private key) */
    STACK_OF(X509) *ca_chain = sk_X509_new_null();

    /* CRITICAL BUG FIX: sk_X509_new_null() can fail and return NULL
     * Must check before using! Otherwise sk_X509_push(NULL, ...) crashes */
    if (!ca_chain) {
        LOG_ERROR("Failed to create certificate chain (memory error)");
        X509_free(cert);
        fclose(fp);
        return false;
    }

    X509 *ca_cert = NULL;
    while ((ca_cert = PEM_read_X509(fp, NULL, NULL, NULL)) != NULL) {
        if (!sk_X509_push(ca_chain, ca_cert)) {
            /* Memory allocation failure in sk_X509_push */
            LOG_ERROR("Failed to push certificate to chain (memory error)");
            X509_free(ca_cert);
            break;
        }
    }

    /* Read private key */
    EVP_PKEY *pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);

    if (!pkey) {
        LOG_ERROR("Failed to read private key from PEM: %s", path);
        X509_free(cert);
        sk_X509_pop_free(ca_chain, X509_free);
        entry->on_disk = false;
        return false;
    }

    /* Create SSL_CTX */
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) {
        LOG_ERROR("Failed to create SSL_CTX for %s", entry->domain);
        X509_free(cert);
        EVP_PKEY_free(pkey);
        sk_X509_pop_free(ca_chain, X509_free);
        entry->on_disk = false;
        return false;
    }

    /* Set certificate */
    if (!SSL_CTX_use_certificate(ctx, cert)) {
        LOG_ERROR("Failed to use certificate: %s", entry->domain);
        SSL_CTX_free(ctx);
        X509_free(cert);
        EVP_PKEY_free(pkey);
        sk_X509_pop_free(ca_chain, X509_free);
        entry->on_disk = false;
        return false;
    }

    /* Set private key */
    if (!SSL_CTX_use_PrivateKey(ctx, pkey)) {
        LOG_ERROR("Failed to use private key: %s", entry->domain);
        SSL_CTX_free(ctx);
        X509_free(cert);
        EVP_PKEY_free(pkey);
        sk_X509_pop_free(ca_chain, X509_free);
        entry->on_disk = false;
        return false;
    }

    /* Add CA chain */
    if (ca_chain && sk_X509_num(ca_chain) > 0) {
        for (int i = 0; i < sk_X509_num(ca_chain); i++) {
            X509 *ca = sk_X509_value(ca_chain, i);
            if (!SSL_CTX_add_extra_chain_cert(ctx, X509_dup(ca))) {
                LOG_WARN("Failed to add CA chain cert %d for %s", i, entry->domain);
            }
        }
    }

    /* Cleanup temporary objects */
    X509_free(cert);
    EVP_PKEY_free(pkey);
    sk_X509_pop_free(ca_chain, X509_free);

    /* Set SSL options */
    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 |
                        SSL_OP_NO_COMPRESSION | SSL_OP_NO_TICKET);
    SSL_CTX_set_mode(ctx, SSL_MODE_RELEASE_BUFFERS);

    /* Store in entry using CAS (lock-free) */
    SSL_CTX *expected = NULL;
    if (atomic_compare_exchange_strong(&entry->ctx, &expected, ctx)) {
        /* We won the race - ctx is now stored */
        atomic_fetch_add(&index->ctx_in_memory, 1);
        LOG_INFO("Loaded SSL_CTX from disk: %s", entry->domain);
        return true;
    } else {
        /* Someone else loaded it first - free our copy, use theirs */
        SSL_CTX_free(ctx);
        return true;  /* Still success - entry->ctx is valid */
    }
}

/* Expiry array operations */
static int compare_expiry(const void *a, const void *b) {
    cert_index_entry_t *ea = *(cert_index_entry_t**)a;
    cert_index_entry_t *eb = *(cert_index_entry_t**)b;

    time_t exp_a = atomic_load_explicit(&ea->expiry_time, memory_order_acquire);
    time_t exp_b = atomic_load_explicit(&eb->expiry_time, memory_order_acquire);

    if (exp_a < exp_b) return -1;
    if (exp_a > exp_b) return 1;
    return 0;
}

static void rebuild_expiry_array(cert_index_t *index) {
    pthread_rwlock_wrlock(&index->expiry_lock);

    /* Collect all entries from hash table (atomic reads) */
    size_t count = 0;
    for (size_t i = 0; i < index->config.hash_buckets; i++) {
        cert_index_entry_t *entry = atomic_load_explicit(&index->hash_buckets[i], memory_order_acquire);
        while (entry) {
            if (count < index->config.max_entries) {
                index->expiry_sorted[count++] = entry;
            }
            entry = atomic_load_explicit(&entry->hash_next, memory_order_acquire);
        }
    }

    index->expiry_count = count;

    /* Sort by expiry time */
    qsort(index->expiry_sorted, count, sizeof(cert_index_entry_t*), compare_expiry);

    pthread_rwlock_unlock(&index->expiry_lock);

    LOG_DEBUG("Rebuilt expiry array: %zu entries", count);
}

/* Save index to disk */
bool cert_index_save(cert_index_t *index) {
    if (!index) return false;

    long long start = get_time_us();

    /* Validate target directory permissions */
    struct stat st;
    if (stat(index->config.persist_dir, &st) == 0) {
        if (st.st_uid != index->config.owner_uid ||
            st.st_gid != index->config.owner_gid) {
            LOG_ERROR("Persist directory ownership mismatch: %s",
                      index->config.persist_dir);
            atomic_fetch_add(&index->stats.permission_errors, 1);
            return false;
        }
    }

    char tmp_path[1024];
    snprintf(tmp_path, sizeof(tmp_path), "%s.tmp", index->index_file);

    FILE *fp = fopen(tmp_path, "wb");
    if (!fp) {
        LOG_ERROR("Failed to open index file for writing: %s (%s)",
                  tmp_path, strerror(errno));
        return false;
    }

    /* Write header */
    index_header_t header = {
        .magic = INDEX_MAGIC,
        .version = INDEX_VERSION,
        .entry_count = (uint32_t)atomic_load_explicit(&index->stats.total_entries, memory_order_acquire),
        .timestamp = (uint64_t)time(NULL)
    };

    if (fwrite(&header, sizeof(header), 1, fp) != 1) {
        LOG_ERROR("Failed to write index header");
        fclose(fp);
        unlink(tmp_path);
        return false;
    }

    /* Write entries (lock-free traversal using atomic loads) */
    for (size_t i = 0; i < index->config.hash_buckets; i++) {
        cert_index_entry_t *entry = atomic_load_explicit(&index->hash_buckets[i], memory_order_acquire);
        while (entry) {
            index_entry_disk_t disk_entry = {0};

            strncpy(disk_entry.domain, entry->domain, sizeof(disk_entry.domain) - 1);
            disk_entry.algorithm = entry->algorithm;
            disk_entry.expiry_time = (uint64_t)atomic_load_explicit(&entry->expiry_time, memory_order_acquire);
            disk_entry.last_access = (uint64_t)atomic_load_explicit(&entry->last_access, memory_order_acquire);
            disk_entry.on_disk = atomic_load_explicit(&entry->on_disk, memory_order_acquire) ? 1 : 0;

            if (fwrite(&disk_entry, sizeof(disk_entry), 1, fp) != 1) {
                LOG_ERROR("Failed to write index entry");
                fclose(fp);
                unlink(tmp_path);
                return false;
            }

            entry = atomic_load_explicit(&entry->hash_next, memory_order_acquire);
        }
    }

    fclose(fp);

    /* Set correct permissions on temp file */
    if (chmod(tmp_path, index->config.file_mode) != 0) {
        LOG_ERROR("Failed to set permissions on index file: %s", strerror(errno));
        unlink(tmp_path);
        return false;
    }

    if (chown(tmp_path, index->config.owner_uid, index->config.owner_gid) != 0) {
        LOG_ERROR("Failed to set ownership on index file: %s", strerror(errno));
        unlink(tmp_path);
        return false;
    }

    /* Atomic rename */
    if (rename(tmp_path, index->index_file) != 0) {
        LOG_ERROR("Failed to rename index file: %s", strerror(errno));
        unlink(tmp_path);
        return false;
    }

    atomic_store(&index->dirty, false);
    atomic_fetch_add(&index->stats.disk_saves, 1);

    long long elapsed = get_time_us() - start;
    LOG_INFO("Saved index to disk: %s (%u entries, %lld μs)",
             index->index_file, header.entry_count, elapsed);

    return true;
}

/* Load index from disk */
static bool load_index(cert_index_t *index) {
    /* Validate file permissions first */
    if (!validate_file_permissions(index->index_file,
                                   index->config.owner_uid,
                                   index->config.owner_gid,
                                   index->config.file_mode)) {
        LOG_WARN("Index file has invalid permissions - deleting and rebuilding: %s",
                 index->index_file);
        unlink(index->index_file);
        atomic_fetch_add(&index->stats.permission_errors, 1);
        return false;
    }

    FILE *fp = fopen(index->index_file, "rb");
    if (!fp) {
        if (errno != ENOENT) {
            LOG_ERROR("Failed to open index file: %s (%s)",
                      index->index_file, strerror(errno));
        }
        return false;
    }

    /* Read header */
    index_header_t header;
    if (fread(&header, sizeof(header), 1, fp) != 1) {
        LOG_ERROR("Failed to read index header");
        fclose(fp);
        return false;
    }

    /* Validate header */
    if (header.magic != INDEX_MAGIC) {
        LOG_ERROR("Invalid index magic: 0x%016lx", header.magic);
        fclose(fp);
        unlink(index->index_file);
        return false;
    }

    if (header.version != INDEX_VERSION) {
        LOG_WARN("Index version mismatch: %u (expected %u) - rebuilding",
                 header.version, INDEX_VERSION);
        fclose(fp);
        unlink(index->index_file);
        return false;
    }

    LOG_INFO("Loading index: %u entries from %s",
             header.entry_count, index->index_file);

    /* Read entries */
    for (uint32_t i = 0; i < header.entry_count; i++) {
        index_entry_disk_t disk_entry;
        if (fread(&disk_entry, sizeof(disk_entry), 1, fp) != 1) {
            LOG_ERROR("Failed to read index entry %u", i);
            break;
        }

        /* Create entry */
        cert_index_entry_t *entry = calloc(1, sizeof(cert_index_entry_t));
        if (!entry) {
            LOG_ERROR("Failed to allocate index entry");
            break;
        }

        entry->domain = strdup(disk_entry.domain);
        entry->algorithm = (crypto_alg_t)disk_entry.algorithm;
        atomic_store(&entry->expiry_time, (time_t)disk_entry.expiry_time);
        atomic_store(&entry->last_access, (time_t)disk_entry.last_access);
        atomic_store(&entry->on_disk, disk_entry.on_disk != 0);
        atomic_store(&entry->ctx, NULL); /* Not loaded yet */
        atomic_store(&entry->accessed, false);

        /* Add to hash table (at startup - no concurrent access yet) */
        uint64_t hash = hash_domain(entry->domain, entry->algorithm);
        size_t bucket = hash % index->config.hash_buckets;

        atomic_store(&entry->hash_next, atomic_load_explicit(&index->hash_buckets[bucket], memory_order_acquire));
        atomic_store(&index->hash_buckets[bucket], entry);

        atomic_fetch_add(&index->stats.total_entries, 1);
    }

    fclose(fp);
    atomic_fetch_add(&index->stats.disk_loads, 1);

    /* Rebuild expiry array */
    rebuild_expiry_array(index);

    LOG_INFO("Loaded index: %lu entries",
             atomic_load_explicit(&index->stats.total_entries, memory_order_acquire));

    return true;
}

/* Background save thread */
static void* save_thread_func(void *arg) {
    cert_index_t *index = (cert_index_t*)arg;

    LOG_INFO("Index save thread started (interval: %u seconds)",
             index->config.save_interval_sec);

    while (index->save_running) {
        sleep(index->config.save_interval_sec);

        if (!index->save_running) break;

        /* Reclaim retired entries (grace-period based memory reclamation) */
        reclaim_retired_entries(index);

        /* Only save if dirty */
        if (atomic_load_explicit(&index->dirty, memory_order_acquire)) {
            cert_index_save(index);
        }
    }

    /* Final save on exit */
    if (atomic_load_explicit(&index->dirty, memory_order_acquire)) {
        cert_index_save(index);
    }

    LOG_INFO("Index save thread stopped");
    return NULL;
}

/* Background renewal thread */
static void* renewal_thread_func(void *arg) {
    cert_index_t *index = (cert_index_t*)arg;
    cert_generator_t *gen = (cert_generator_t*)index->cert_generator;

    /* Calculate random interval (2-4 hours) */
    uint32_t min_sec = index->config.renewal_min_interval * 3600;
    uint32_t max_sec = index->config.renewal_max_interval * 3600;

    LOG_INFO("Index renewal thread started (interval: %u-%u hours)",
             index->config.renewal_min_interval,
             index->config.renewal_max_interval);

    while (index->renewal_running) {
        /* Random sleep between min and max */
        uint32_t sleep_sec = min_sec + (rand() % (max_sec - min_sec + 1));

        LOG_DEBUG("Next renewal scan in %u seconds (~%.1f hours)",
                  sleep_sec, sleep_sec / 3600.0);

        /* Sleep in 1-second intervals to allow quick shutdown */
        for (uint32_t i = 0; i < sleep_sec && index->renewal_running; i++) {
            sleep(1);
        }

        if (!index->renewal_running) break;

        /* Perform renewal scan */
        size_t renewed = cert_index_renewal_scan(index, gen);
        LOG_INFO("Renewal scan complete: %zu certificates renewed", renewed);
    }

    LOG_INFO("Index renewal thread stopped");
    return NULL;
}

/* Public API */

cert_index_t* cert_index_create(const cert_index_config_t *config) {
    if (!config || !config->persist_dir || !config->disk_cache_dir) {
        LOG_ERROR("Invalid config for cert_index_create (persist_dir and disk_cache_dir required)");
        return NULL;
    }

    cert_index_t *index = calloc(1, sizeof(cert_index_t));
    if (!index) {
        LOG_ERROR("Failed to allocate cert_index");
        return NULL;
    }

    /* Copy config */
    memcpy(&index->config, config, sizeof(cert_index_config_t));

    /* Create paths */
    snprintf(index->index_file, sizeof(index->index_file),
             "%s/cert_index.bin", config->persist_dir);
    snprintf(index->disk_cache_dir, sizeof(index->disk_cache_dir),
             "%s", config->disk_cache_dir);

    /* Create directories if needed */
    mkdir(config->persist_dir, 0700);
    mkdir(config->disk_cache_dir, 0700);

    /* Allocate hash table (atomic pointers for lock-free access) */
    index->hash_buckets = calloc(config->hash_buckets,
                                  sizeof(_Atomic(cert_index_entry_t*)));
    if (!index->hash_buckets) {
        LOG_ERROR("Failed to allocate hash buckets");
        free(index);
        return NULL;
    }

    /* Allocate expiry array */
    index->expiry_sorted = calloc(config->max_entries,
                                   sizeof(cert_index_entry_t*));
    if (!index->expiry_sorted) {
        LOG_ERROR("Failed to allocate expiry array");
        free(index->hash_buckets);
        free(index);
        return NULL;
    }

    /* Initialize CLOCK algorithm state */
    atomic_store(&index->clock_hand, 0);
    atomic_store(&index->ctx_in_memory, 0);

    /* Initialize remaining lock (only for background renewal thread) */
    pthread_rwlock_init(&index->expiry_lock, NULL);

    /* Initialize grace-period reclamation */
    index->retired_list = NULL;
    pthread_mutex_init(&index->retired_lock, NULL);

    /* Load existing index if available */
    load_index(index);

    LOG_INFO("Certificate index created: hash_buckets=%zu, max_entries=%zu, lru_cache=%zu",
             config->hash_buckets, config->max_entries, config->lru_cache_size);

    return index;
}

void cert_index_destroy(cert_index_t *index) {
    if (!index) return;

    LOG_INFO("Destroying certificate index...");

    /* Stop threads */
    cert_index_stop_renewal_thread(index);
    cert_index_stop_save_thread(index);

    /* Final save - only master saves (workers are read-only) */
    if (index->config.is_master && atomic_load_explicit(&index->dirty, memory_order_acquire)) {
        cert_index_save(index);
    } else if (!index->config.is_master) {
        LOG_DEBUG("Worker mode - skipping final save (master handles persistence)");
    }

    /* Free all entries (at shutdown - no concurrent access) */
    for (size_t i = 0; i < index->config.hash_buckets; i++) {
        cert_index_entry_t *entry = atomic_load_explicit(&index->hash_buckets[i], memory_order_acquire);
        while (entry) {
            cert_index_entry_t *next = atomic_load_explicit(&entry->hash_next, memory_order_acquire);

            free(entry->domain);
            SSL_CTX *ctx = atomic_load_explicit(&entry->ctx, memory_order_acquire);
            if (ctx) {
                SSL_CTX_free(ctx);
            }
            free(entry);

            entry = next;
        }
    }

    /* Free arrays */
    free(index->hash_buckets);
    free(index->expiry_sorted);

    /* Free any remaining retired entries (at shutdown, no grace period needed) */
    retired_entry_t *r = index->retired_list;
    while (r) {
        retired_entry_t *next = r->next;
        free(r->entry->domain);
        free(r->entry);
        free(r);
        r = next;
    }

    /* Destroy locks */
    pthread_rwlock_destroy(&index->expiry_lock);
    pthread_mutex_destroy(&index->retired_lock);

    free(index);

    LOG_INFO("Certificate index destroyed");
}

bool cert_index_add(cert_index_t *index,
                    const char *domain,
                    SSL_CTX *ctx,
                    X509 *cert,
                    crypto_alg_t algorithm) {
    if (!index || !domain || !ctx || !cert) return false;

    /* Extract expiry time from certificate */
    const ASN1_TIME *not_after = X509_get0_notAfter(cert);
    time_t expiry_time = 0;

    if (not_after) {
        struct tm tm = {0};
        ASN1_TIME_to_tm(not_after, &tm);
        expiry_time = mktime(&tm);
    }

    /* Calculate hash and bucket */
    uint64_t hash = hash_domain(domain, algorithm);
    size_t bucket = hash % index->config.hash_buckets;

    /* LOCK-FREE: Search for existing entry using atomic loads */
    cert_index_entry_t *entry = atomic_load_explicit(&index->hash_buckets[bucket], memory_order_acquire);
    while (entry) {
        if (entry->algorithm == algorithm &&
            strcmp(entry->domain, domain) == 0) {
            /* Update existing entry using CAS */
            SSL_CTX *old_ctx = atomic_load_explicit(&entry->ctx, memory_order_acquire);

            /* Try to swap in the new ctx */
            SSL_CTX_up_ref(ctx);
            if (atomic_compare_exchange_strong(&entry->ctx, &old_ctx, ctx)) {
                /* Success - we swapped in the new ctx */
                if (old_ctx) {
                    SSL_CTX_free(old_ctx);
                } else {
                    /* Was NULL, now has ctx - increment count */
                    atomic_fetch_add(&index->ctx_in_memory, 1);
                }
            } else {
                /* Someone else updated it - free our ref */
                SSL_CTX_free(ctx);
            }

            atomic_store(&entry->expiry_time, expiry_time);
            atomic_store(&entry->last_access, time(NULL));
            atomic_store(&entry->on_disk, false);
            atomic_store(&entry->accessed, true);  /* CLOCK: mark accessed */

            atomic_store(&index->dirty, true);
            return true;
        }
        entry = atomic_load_explicit(&entry->hash_next, memory_order_acquire);
    }

    /* Create new entry */
    entry = calloc(1, sizeof(cert_index_entry_t));
    if (!entry) {
        return false;
    }

    entry->domain = strdup(domain);
    if (!entry->domain) {
        free(entry);
        return false;
    }
    entry->algorithm = algorithm;
    atomic_store(&entry->expiry_time, expiry_time);
    atomic_store(&entry->last_access, time(NULL));
    SSL_CTX_up_ref(ctx);
    atomic_store(&entry->ctx, ctx);
    atomic_store(&entry->on_disk, false);
    atomic_store(&entry->accessed, true);  /* CLOCK: mark as recently accessed */

    /* LOCK-FREE: Insert at bucket head using CAS loop */
    cert_index_entry_t *expected;
    do {
        expected = atomic_load_explicit(&index->hash_buckets[bucket], memory_order_acquire);
        atomic_store(&entry->hash_next, expected);
    } while (!atomic_compare_exchange_weak(&index->hash_buckets[bucket], &expected, entry));

    atomic_fetch_add(&index->ctx_in_memory, 1);

    /* CLOCK eviction: Check if we need to evict */
    while (atomic_load_explicit(&index->ctx_in_memory, memory_order_acquire) > index->config.lru_cache_size) {
        cert_index_entry_t *victim = clock_find_victim(index);
        if (victim) {
            evict_to_disk(index, victim);
        } else {
            break;  /* No eviction candidates */
        }
    }

    atomic_fetch_add(&index->stats.total_entries, 1);
    atomic_fetch_add(&index->stats.active_entries, 1);
    atomic_store(&index->dirty, true);

    /* Note: Expiry array rebuilt periodically, not on every add */

    return true;
}

SSL_CTX* cert_index_get(cert_index_t *index,
                        const char *domain,
                        crypto_alg_t algorithm) {
    if (!index || !domain) return NULL;

    /* Calculate hash and bucket */
    uint64_t hash = hash_domain(domain, algorithm);
    size_t bucket = hash % index->config.hash_buckets;

    /* LOCK-FREE: Traverse bucket chain using atomic loads */
    cert_index_entry_t *entry = atomic_load_explicit(&index->hash_buckets[bucket], memory_order_acquire);
    while (entry) {
        if (entry->algorithm == algorithm &&
            strcmp(entry->domain, domain) == 0) {

            /* LOCK-FREE: Update last access and CLOCK bit (atomic) */
            atomic_store(&entry->last_access, time(NULL));
            clock_mark_accessed(entry);  /* Single atomic store - no lock! */

            SSL_CTX *ctx = atomic_load_explicit(&entry->ctx, memory_order_acquire);

            if (ctx) {
                /* In memory - just return (CLOCK bit already set) */
                atomic_fetch_add(&index->stats.cache_hits, 1);
                return ctx;
            } else if (atomic_load_explicit(&entry->on_disk, memory_order_acquire)) {
                /* On disk - load from PEM file (lock-free CAS inside) */
                if (load_from_disk(index, entry)) {
                    atomic_fetch_add(&index->stats.cache_hits, 1);
                    LOG_INFO("Loaded certificate from disk (NO RE-GENERATION!): %s", domain);
                    return atomic_load_explicit(&entry->ctx, memory_order_acquire);
                } else {
                    /* Load failed - caller will regenerate */
                    LOG_WARN("Failed to load certificate from disk, will regenerate: %s", domain);
                    atomic_fetch_add(&index->stats.cache_misses, 1);
                    return NULL;
                }
            } else {
                /* Not in memory, not on disk - return NULL for regeneration */
                atomic_fetch_add(&index->stats.cache_misses, 1);
                return NULL;
            }
        }
        entry = atomic_load_explicit(&entry->hash_next, memory_order_acquire);
    }

    atomic_fetch_add(&index->stats.cache_misses, 1);
    return NULL;
}

bool cert_index_exists(cert_index_t *index,
                       const char *domain,
                       crypto_alg_t algorithm) {
    if (!index || !domain) return false;

    uint64_t hash = hash_domain(domain, algorithm);
    size_t bucket = hash % index->config.hash_buckets;

    /* LOCK-FREE: Traverse using atomic loads */
    cert_index_entry_t *entry = atomic_load_explicit(&index->hash_buckets[bucket], memory_order_acquire);
    while (entry) {
        if (entry->algorithm == algorithm &&
            strcmp(entry->domain, domain) == 0) {
            return true;
        }
        entry = atomic_load_explicit(&entry->hash_next, memory_order_acquire);
    }

    return false;
}

bool cert_index_remove(cert_index_t *index,
                       const char *domain,
                       crypto_alg_t algorithm) {
    if (!index || !domain) return false;

    uint64_t hash = hash_domain(domain, algorithm);
    size_t bucket = hash % index->config.hash_buckets;

    /* LOCK-FREE removal using CAS with grace-period reclamation
     *
     * 1. CAS-remove from hash chain
     * 2. Free SSL_CTX immediately (it's refcounted by OpenSSL)
     * 3. Add entry to retired list for deferred freeing
     * 4. Background thread frees after grace period (10s)
     */

retry:  /* Loop instead of recursion to avoid stack overflow under contention */
    ;
    /* Find entry and its predecessor */
    cert_index_entry_t *entry = atomic_load_explicit(&index->hash_buckets[bucket], memory_order_acquire);
    cert_index_entry_t *prev = NULL;

    while (entry) {
        if (entry->algorithm == algorithm &&
            strcmp(entry->domain, domain) == 0) {

            /* Found it - try to remove from chain */
            cert_index_entry_t *next = atomic_load_explicit(&entry->hash_next, memory_order_acquire);

            if (prev == NULL) {
                /* Removing head of bucket */
                if (!atomic_compare_exchange_strong(&index->hash_buckets[bucket], &entry, next)) {
                    /* Bucket head changed - retry from beginning (loop, not recursion!) */
                    goto retry;
                }
            } else {
                /* Removing from middle/end - CAS on prev->hash_next */
                if (!atomic_compare_exchange_strong(&prev->hash_next, &entry, next)) {
                    /* Chain changed - retry from beginning (loop, not recursion!) */
                    goto retry;
                }
            }

            /* Successfully removed from chain - free SSL_CTX immediately
             * (OpenSSL refcount ensures safety if another thread grabbed it) */
            SSL_CTX *ctx = atomic_exchange(&entry->ctx, NULL);
            if (ctx) {
                atomic_fetch_sub(&index->ctx_in_memory, 1);
                SSL_CTX_free(ctx);
            }

            atomic_fetch_sub(&index->stats.total_entries, 1);
            atomic_store(&index->dirty, true);

            /* Defer entry memory free via grace-period reclamation
             * After 10 seconds, all readers are guaranteed to be done */
            retire_entry(index, entry);

            LOG_DEBUG("Removed certificate entry: %s (deferred free)", domain);
            return true;
        }

        prev = entry;
        entry = atomic_load_explicit(&entry->hash_next, memory_order_acquire);
    }

    return false;
}

size_t cert_index_renewal_scan(cert_index_t *index, void *gen) {
    if (!index || !gen) return 0;

    cert_generator_t *generator = (cert_generator_t*)gen;

    LOG_INFO("Starting renewal scan...");

    /* Rebuild expiry array to ensure it's current */
    rebuild_expiry_array(index);

    time_t now = time(NULL);
    time_t threshold = now + (index->config.renewal_threshold_days * 24 * 3600);

    size_t renewed = 0;
    size_t scanned = 0;

    pthread_rwlock_rdlock(&index->expiry_lock);

    /* Scan sorted array - entries expiring soon are at the front */
    for (size_t i = 0; i < index->expiry_count &&
                       renewed < index->config.max_renewals_per_scan; i++) {
        cert_index_entry_t *entry = index->expiry_sorted[i];

        /* Stop when we reach entries that don't need renewal yet */
        time_t entry_expiry = atomic_load_explicit(&entry->expiry_time, memory_order_acquire);
        if (entry_expiry > threshold) {
            break;
        }

        scanned++;

        /* Get current SSL_CTX to extract key (atomic load) */
        SSL_CTX *old_ctx = atomic_load_explicit(&entry->ctx, memory_order_acquire);
        if (!old_ctx) {
            /* Would need to load from disk or skip */
            continue;
        }

        EVP_PKEY *old_key = SSL_CTX_get0_privatekey(old_ctx);
        if (!old_key) {
            LOG_WARN("No key found for renewal: %s", entry->domain);
            continue;
        }

        /* Renew certificate with existing key */
        X509 *new_cert = cert_generator_renew_cert(generator,
                                                    entry->domain,
                                                    old_key);
        if (!new_cert) {
            LOG_ERROR("Failed to renew certificate: %s", entry->domain);
            atomic_fetch_add(&index->stats.renewal_errors, 1);
            continue;
        }

        /* Create new SSL_CTX */
        SSL_CTX *new_ctx = SSL_CTX_new(TLS_server_method());
        if (!new_ctx) {
            LOG_ERROR("Failed to create SSL_CTX for renewal: %s", entry->domain);
            X509_free(new_cert);
            atomic_fetch_add(&index->stats.renewal_errors, 1);
            continue;
        }

        /* SECURITY FIX: Check return values to prevent SSL_CTX resource leak */
        if (SSL_CTX_use_certificate(new_ctx, new_cert) != 1) {
            LOG_ERROR("Failed to use certificate for SSL_CTX: %s", entry->domain);
            SSL_CTX_free(new_ctx);
            X509_free(new_cert);
            atomic_fetch_add(&index->stats.renewal_errors, 1);
            continue;
        }

        if (SSL_CTX_use_PrivateKey(new_ctx, old_key) != 1) {
            LOG_ERROR("Failed to use private key for SSL_CTX: %s", entry->domain);
            SSL_CTX_free(new_ctx);
            X509_free(new_cert);
            atomic_fetch_add(&index->stats.renewal_errors, 1);
            continue;
        }

        /* Update entry */
        const ASN1_TIME *not_after = X509_get0_notAfter(new_cert);
        if (not_after) {
            struct tm tm = {0};
            ASN1_TIME_to_tm(not_after, &tm);
            atomic_store(&entry->expiry_time, mktime(&tm));
        }

        /* Replace SSL_CTX using CAS (lock-free) */
        SSL_CTX_up_ref(new_ctx);
        SSL_CTX *expected = old_ctx;
        if (atomic_compare_exchange_strong(&entry->ctx, &expected, new_ctx)) {
            /* Success - free old ctx */
            SSL_CTX_free(old_ctx);
        } else {
            /* Someone else updated it - free our new ctx */
            SSL_CTX_free(new_ctx);
            SSL_CTX_free(new_ctx);  /* Release our extra ref */
        }

        renewed++;
        atomic_fetch_add(&index->stats.renewals, 1);
        atomic_store(&index->dirty, true);

        LOG_INFO("Renewed certificate: %s (expires in %ld days)",
                 entry->domain,
                 (atomic_load_explicit(&entry->expiry_time, memory_order_acquire) - now) / 86400);

        X509_free(new_cert);
    }

    pthread_rwlock_unlock(&index->expiry_lock);

    LOG_INFO("Renewal scan complete: scanned=%zu, renewed=%zu",
             scanned, renewed);

    /* Re-sort expiry array if we renewed anything */
    if (renewed > 0) {
        rebuild_expiry_array(index);
    }

    return renewed;
}

void cert_index_get_stats(cert_index_t *index, cert_index_stats_t *stats) {
    if (!index || !stats) return;

    stats->total_entries = atomic_load_explicit(&index->stats.total_entries, memory_order_acquire);
    stats->active_entries = atomic_load_explicit(&index->stats.active_entries, memory_order_acquire);
    stats->cache_hits = atomic_load_explicit(&index->stats.cache_hits, memory_order_acquire);
    stats->cache_misses = atomic_load_explicit(&index->stats.cache_misses, memory_order_acquire);
    stats->evictions = atomic_load_explicit(&index->stats.evictions, memory_order_acquire);
    stats->renewals = atomic_load_explicit(&index->stats.renewals, memory_order_acquire);
    stats->renewal_errors = atomic_load_explicit(&index->stats.renewal_errors, memory_order_acquire);
    stats->disk_saves = atomic_load_explicit(&index->stats.disk_saves, memory_order_acquire);
    stats->disk_loads = atomic_load_explicit(&index->stats.disk_loads, memory_order_acquire);
    stats->permission_errors = atomic_load_explicit(&index->stats.permission_errors, memory_order_acquire);
}

bool cert_index_start_renewal_thread(cert_index_t *index, void *gen) {
    if (!index || !gen) return false;

    /* Workers (non-master) don't run renewal thread - master handles renewals */
    if (!index->config.is_master) {
        LOG_INFO("Renewal thread disabled (worker mode - master handles renewals)");
        return true;  /* Not an error - just not needed for workers */
    }

    if (index->renewal_running) {
        LOG_WARN("Renewal thread already running");
        return false;
    }

    index->cert_generator = gen;
    index->renewal_running = true;

    if (pthread_create(&index->renewal_thread, NULL,
                      renewal_thread_func, index) != 0) {
        LOG_ERROR("Failed to create renewal thread");
        index->renewal_running = false;
        return false;
    }

    return true;
}

void cert_index_stop_renewal_thread(cert_index_t *index) {
    if (!index || !index->renewal_running) return;

    LOG_INFO("Stopping renewal thread...");
    index->renewal_running = false;
    pthread_join(index->renewal_thread, NULL);
}

bool cert_index_start_save_thread(cert_index_t *index) {
    if (!index) return false;

    /* Workers (non-master) don't run save thread - master handles persistence */
    if (!index->config.is_master) {
        LOG_INFO("Save thread disabled (worker mode - master handles persistence)");
        return true;  /* Not an error - just not needed for workers */
    }

    if (index->save_running) {
        LOG_WARN("Save thread already running");
        return false;
    }

    index->save_running = true;

    if (pthread_create(&index->save_thread, NULL,
                      save_thread_func, index) != 0) {
        LOG_ERROR("Failed to create save thread");
        index->save_running = false;
        return false;
    }

    return true;
}

void cert_index_stop_save_thread(cert_index_t *index) {
    if (!index || !index->save_running) return;

    LOG_INFO("Stopping save thread...");
    index->save_running = false;
    pthread_join(index->save_thread, NULL);
}
