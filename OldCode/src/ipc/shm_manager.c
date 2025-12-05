/* TLS-Gate NX - Shared Memory Manager Implementation
 * Copyright (C) 2025 Torsten Jahnke
 *
 * Modern, thread-safe shared memory with C11 atomics and OpenSSL 3.0
 */

#include "shm_manager.h"
#include "../util/logger.h"

#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <limits.h>  /* PATH_MAX */

/* SHM names */
#define SHM_KEYPOOL_NAME "/tlsgateNG_keypool"
#define SHM_CERTCACHE_PREFIX "/tlsgateNG_certcache_"

/* Keypool SHM Initialization */

shm_error_t keypool_shm_init(bool is_keygen, keypool_shm_t **out_pool, int *out_fd) {
    if (!out_pool || !out_fd) {
        LOG_ERROR("Invalid arguments: out_pool=%p, out_fd=%p", (void*)out_pool, (void*)out_fd);
        return SHM_ERR_INVALID;
    }

    const size_t shm_size = sizeof(keypool_shm_t);
    keypool_shm_t *pool = NULL;
    int fd = -1;

    /* BUGFIX: Use iteration instead of recursion to prevent stack overflow on repeated race conditions */
    int max_retries = 10;
    int retry_count = 0;

    LOG_DEBUG("Initializing keypool SHM (is_keygen=%d, size=%zu)", is_keygen, shm_size);

retry_init:
    if (retry_count >= max_retries) {
        LOG_ERROR("Failed to initialize keypool SHM after %d retries (race conditions)", max_retries);
        return SHM_ERR_CREATE;
    }

    if (is_keygen || retry_count > 0) {
        /* KEYGEN MODE: Try attach first for sticky failover */
        fd = shm_open(SHM_KEYPOOL_NAME, O_RDWR, 0600);

        if (fd >= 0) {
            /* Existing SHM - try to attach */
            pool = mmap(NULL, shm_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
            if (pool == MAP_FAILED) {
                LOG_ERROR("Failed to mmap existing keypool SHM: %s", strerror(errno));
                close(fd);
                return SHM_ERR_ATTACH;
            }

            /* Validate magic */
            if (pool->magic != SHM_KEYPOOL_MAGIC) {
                LOG_WARN("Invalid keypool SHM magic: 0x%08x (expected 0x%08x)",
                        pool->magic, SHM_KEYPOOL_MAGIC);
                munmap(pool, shm_size);
                close(fd);
                shm_unlink(SHM_KEYPOOL_NAME);
                /* Fall through to create new SHM */
                fd = -1;
            } else {
                /* Check if another keygen is active (HA failover) */
                pid_t active_pid = atomic_load_explicit(&pool->keygen_pid, memory_order_acquire);
                time_t last_hb = atomic_load_explicit(&pool->last_keygen_heartbeat, memory_order_acquire);
                time_t now = time(NULL);

                /* Check if active keygen is alive and healthy */
                bool pid_alive = (active_pid > 0 && kill(active_pid, 0) == 0);
                bool hb_fresh = (last_hb > 0 && (now - last_hb) < 10);  /* 10s heartbeat */

                if (pid_alive && hb_fresh) {
                    /* Another keygen is active - become reader */
                    LOG_INFO("Another keygen instance (PID %d) is active, becoming reader", active_pid);
                    *out_pool = pool;
                    *out_fd = fd;
                    return SHM_OK;
                }

                /* Previous keygen died - try to take over atomically using CAS */
                LOG_WARN("Previous keygen (PID %d) died, attempting takeover", active_pid);

                /* Use compare-and-swap to atomically claim keygen role */
                pid_t expected_pid = active_pid;
                pid_t new_pid = getpid();
                if (atomic_compare_exchange_strong_explicit(&pool->keygen_pid,
                                                            &expected_pid,
                                                            new_pid,
                                                            memory_order_acq_rel,
                                                            memory_order_acquire)) {
                    /* Successfully claimed keygen role */
                    atomic_store_explicit(&pool->last_keygen_heartbeat, now, memory_order_release);
                    atomic_store_explicit(&pool->is_keygen, true, memory_order_release);
                    LOG_INFO("Successfully took over as keygen (PID %d)", new_pid);

                    *out_pool = pool;
                    *out_fd = fd;
                    return SHM_OK;
                } else {
                    /* Another process won the race - become reader */
                    LOG_INFO("Another process won takeover race (PID %d), becoming reader", expected_pid);
                    *out_pool = pool;
                    *out_fd = fd;
                    return SHM_OK;
                }
            }
        }

        /* Create new SHM */
        fd = shm_open(SHM_KEYPOOL_NAME, O_CREAT | O_EXCL | O_RDWR, 0600);
        if (fd < 0) {
            if (errno == EEXIST) {
                /* Race condition - retry attach (BUGFIX: use iteration instead of recursion) */
                LOG_DEBUG("SHM already exists (race condition #%d), retrying attach", retry_count + 1);
                retry_count++;
                goto retry_init;
            }
            LOG_ERROR("Failed to create keypool SHM: %s", strerror(errno));
            return SHM_ERR_CREATE;
        }

        /* Set size */
        if (ftruncate(fd, shm_size) < 0) {
            LOG_ERROR("Failed to set keypool SHM size: %s", strerror(errno));
            close(fd);
            shm_unlink(SHM_KEYPOOL_NAME);
            return SHM_ERR_CREATE;
        }

        /* Map into memory */
        pool = mmap(NULL, shm_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
        if (pool == MAP_FAILED) {
            LOG_ERROR("Failed to mmap new keypool SHM: %s", strerror(errno));
            close(fd);
            shm_unlink(SHM_KEYPOOL_NAME);
            return SHM_ERR_CREATE;
        }

        /* Initialize structure with C11 atomics */
        memset(pool, 0, shm_size);
        pool->magic = SHM_KEYPOOL_MAGIC;
        pool->version = SHM_VERSION;
        pool->capacity = KEY_POOL_SIZE_SHARED;

        atomic_init(&pool->available, 0);
        atomic_init(&pool->is_keygen, true);
        atomic_init(&pool->shutdown, false);
        atomic_init(&pool->backup_restored, false);  /* Initialize backup_restored flag */

        /* Initialize restore locks - ALL must be cleared before refill can start
         * Each lock is cleared after its respective operation (even if no file exists) */
        atomic_init(&pool->restore_lock_shm_backup, true);  /* Cleared after SHM backup restore */
        atomic_init(&pool->restore_lock_keybundle, true);   /* Cleared after keybundle load */
        atomic_init(&pool->restore_lock_prime, true);       /* Cleared after prime pool load */
        atomic_init(&pool->pem_write_cursor, 0);
        atomic_init(&pool->keygen_pid, getpid());
        atomic_init(&pool->last_keygen_heartbeat, time(NULL));
        atomic_init(&pool->is_secondary, false);

        /* Initialize all key slots */
        for (int i = 0; i < KEY_POOL_SIZE_SHARED; i++) {
            atomic_init(&pool->key_offsets[i], -1);   /* Empty */
            atomic_init(&pool->key_lengths[i], 0);
            atomic_init(&pool->key_algorithms[i], 0); /* No algorithm */
        }

        /* Initialize process-shared ROBUST mutex
         * ROBUST: If owner dies while holding lock, next locker gets EOWNERDEAD
         * and can recover the mutex with pthread_mutex_consistent() */
        pthread_mutexattr_t attr;
        if (pthread_mutexattr_init(&attr) != 0 ||
            pthread_mutexattr_setpshared(&attr, PTHREAD_PROCESS_SHARED) != 0 ||
            pthread_mutexattr_setrobust(&attr, PTHREAD_MUTEX_ROBUST) != 0 ||
            pthread_mutex_init(&pool->lock, &attr) != 0) {
            LOG_ERROR("Failed to initialize process-shared robust mutex");
            pthread_mutexattr_destroy(&attr);
            munmap(pool, shm_size);
            close(fd);
            shm_unlink(SHM_KEYPOOL_NAME);
            return SHM_ERR_LOCK;
        }
        pthread_mutexattr_destroy(&attr);

        LOG_INFO("Created keypool SHM (size=%zu, capacity=%d)", shm_size, KEY_POOL_SIZE_SHARED);

    } else {
        /* READER MODE: Attach to existing SHM */
        fd = shm_open(SHM_KEYPOOL_NAME, O_RDWR, 0600);
        if (fd < 0) {
            LOG_DEBUG("Keypool SHM not available (will use local pool): %s", strerror(errno));
            return SHM_ERR_ATTACH;
        }

        /* Map into memory */
        pool = mmap(NULL, shm_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
        if (pool == MAP_FAILED) {
            LOG_ERROR("Failed to mmap keypool SHM: %s", strerror(errno));
            close(fd);
            return SHM_ERR_ATTACH;
        }

        /* Validate magic */
        if (pool->magic != SHM_KEYPOOL_MAGIC) {
            LOG_ERROR("Invalid keypool SHM magic: 0x%08x", pool->magic);
            munmap(pool, shm_size);
            close(fd);
            return SHM_ERR_MAGIC;
        }

        LOG_DEBUG("Attached to keypool SHM (available=%d/%d)",
                 atomic_load_explicit(&pool->available, memory_order_acquire), pool->capacity);
    }

    *out_pool = pool;
    *out_fd = fd;
    return SHM_OK;
}

void keypool_shm_cleanup(keypool_shm_t *pool, int fd) {
    if (!pool || fd < 0) {
        return;
    }

    const size_t shm_size = sizeof(keypool_shm_t);

    /* Save values BEFORE munmap to avoid use-after-free */
    bool is_keygen = atomic_load_explicit(&pool->is_keygen, memory_order_acquire);
    pid_t keygen_pid = atomic_load_explicit(&pool->keygen_pid, memory_order_acquire);

    /* If we're the keygen instance, mark shutdown */
    if (is_keygen) {
        atomic_store(&pool->shutdown, true);
        LOG_DEBUG("Marked keypool SHM for shutdown");
    }

    munmap(pool, shm_size);
    close(fd);

    /* Only unlink if we're the last keygen instance */
    if (is_keygen && keygen_pid == getpid()) {
        shm_unlink(SHM_KEYPOOL_NAME);
        LOG_INFO("Unlinked keypool SHM");
    }
}

/* Certcache SHM Implementation */

void escape_path_to_shm_name(const char * restrict pem_dir,
                              char * restrict out, size_t out_len) {
    if (!pem_dir || !out || out_len == 0) {
        return;
    }

    size_t i = 0, j = 0;
    while (pem_dir[i] && j < out_len - 1) {
        char c = pem_dir[i++];
        /* Replace / with _ */
        out[j++] = (c == '/') ? '_' : c;
    }
    out[j] = '\0';
}

shm_error_t certcache_shm_init(const char *pem_dir, const char *pool_name,
                                size_t capacity,
                                certcache_shm_t **out_cache, int *out_fd,
                                char *out_name, size_t name_len) {
    if (!pem_dir || !out_cache || !out_fd) {
        LOG_ERROR("Invalid arguments");
        return SHM_ERR_INVALID;
    }

    /* Use default if capacity is 0 */
    if (capacity == 0) {
        capacity = CERT_CACHE_SIZE_DEFAULT;
    }

    char shm_name[128];
    const size_t shm_size = certcache_shm_size(capacity);

    /* Generate SHM name from pool name or path */
    if (pool_name && pool_name[0]) {
        snprintf(shm_name, sizeof(shm_name), "%s%s", SHM_CERTCACHE_PREFIX, pool_name);
    } else {
        snprintf(shm_name, sizeof(shm_name), "%s", SHM_CERTCACHE_PREFIX);
        escape_path_to_shm_name(pem_dir, shm_name + strlen(shm_name),
                                sizeof(shm_name) - strlen(shm_name));
    }

    if (out_name) {
        snprintf(out_name, name_len, "%s", shm_name);
    }

    /* Log size in human-readable format */
    if (shm_size >= 1024*1024*1024) {
        LOG_DEBUG("Initializing certcache SHM: %s (capacity=%zu, size=%.1fGB)",
                  shm_name, capacity, (double)shm_size / (1024*1024*1024));
    } else {
        LOG_DEBUG("Initializing certcache SHM: %s (capacity=%zu, size=%.1fMB)",
                  shm_name, capacity, (double)shm_size / (1024*1024));
    }

    /* Try attach first */
    int fd = shm_open(shm_name, O_RDWR, 0600);
    certcache_shm_t *cache = NULL;

    if (fd >= 0) {
        /* First map just the header to read capacity */
        cache = mmap(NULL, sizeof(certcache_shm_t), PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
        if (cache == MAP_FAILED) {
            LOG_ERROR("Failed to mmap certcache SHM header: %s", strerror(errno));
            close(fd);
            return SHM_ERR_ATTACH;
        }

        /* Validate magic */
        if (cache->magic != SHM_CERTCACHE_MAGIC) {
            LOG_WARN("Invalid certcache SHM magic, recreating");
            munmap(cache, sizeof(certcache_shm_t));
            close(fd);
            shm_unlink(shm_name);
            fd = -1;  /* Trigger creation below */
        } else {
            /* Remap with actual size based on stored capacity */
            size_t existing_size = certcache_shm_size(cache->capacity);
            munmap(cache, sizeof(certcache_shm_t));

            cache = mmap(NULL, existing_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
            if (cache == MAP_FAILED) {
                LOG_ERROR("Failed to mmap certcache SHM: %s", strerror(errno));
                close(fd);
                return SHM_ERR_ATTACH;
            }

            LOG_DEBUG("Attached to certcache SHM (%d certs, capacity=%d)",
                      atomic_load_explicit(&cache->count, memory_order_acquire), cache->capacity);
            *out_cache = cache;
            *out_fd = fd;
            return SHM_OK;
        }
    }

    /* Create new SHM */
    fd = shm_open(shm_name, O_CREAT | O_EXCL | O_RDWR, 0600);
    if (fd < 0) {
        if (errno == EEXIST) {
            /* Race - retry attach */
            return certcache_shm_init(pem_dir, pool_name, capacity, out_cache, out_fd, out_name, name_len);
        }
        LOG_ERROR("Failed to create certcache SHM: %s", strerror(errno));
        return SHM_ERR_CREATE;
    }

    if (ftruncate(fd, (off_t)shm_size) < 0) {
        LOG_ERROR("Failed to set certcache SHM size (%zu bytes): %s", shm_size, strerror(errno));
        close(fd);
        shm_unlink(shm_name);
        return SHM_ERR_CREATE;
    }

    cache = mmap(NULL, shm_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (cache == MAP_FAILED) {
        LOG_ERROR("Failed to mmap certcache SHM: %s", strerror(errno));
        close(fd);
        shm_unlink(shm_name);
        return SHM_ERR_CREATE;
    }

    /* Initialize */
    memset(cache, 0, shm_size);
    cache->magic = SHM_CERTCACHE_MAGIC;
    cache->version = SHM_VERSION;
    cache->capacity = (int)capacity;
    atomic_init(&cache->count, 0);

    /* Initialize master management fields */
    atomic_init(&cache->master_pid, 0);
    atomic_init(&cache->last_save_time, 0);
    atomic_init(&cache->dirty, false);

    /* Initialize all entry slots as invalid (for hash table use) */
    for (size_t i = 0; i < capacity; i++) {
        atomic_init(&cache->entries[i].valid, false);
        atomic_init(&cache->entries[i].algorithm, 0);
        atomic_init(&cache->entries[i].expiry_time, 0);
        atomic_init(&cache->entries[i].on_disk, false);
    }

    /* Process-shared ROBUST mutex */
    pthread_mutexattr_t attr;
    if (pthread_mutexattr_init(&attr) != 0 ||
        pthread_mutexattr_setpshared(&attr, PTHREAD_PROCESS_SHARED) != 0 ||
        pthread_mutexattr_setrobust(&attr, PTHREAD_MUTEX_ROBUST) != 0 ||
        pthread_mutex_init(&cache->lock, &attr) != 0) {
        LOG_ERROR("Failed to initialize certcache robust mutex");
        pthread_mutexattr_destroy(&attr);
        munmap(cache, shm_size);
        close(fd);
        shm_unlink(shm_name);
        return SHM_ERR_LOCK;
    }
    pthread_mutexattr_destroy(&attr);

    /* Log creation in human-readable format */
    if (shm_size >= 1024*1024*1024) {
        LOG_INFO("Created certcache SHM: %s (capacity=%zu, size=%.1fGB)",
                 shm_name, capacity, (double)shm_size / (1024*1024*1024));
    } else {
        LOG_INFO("Created certcache SHM: %s (capacity=%zu, size=%.1fMB)",
                 shm_name, capacity, (double)shm_size / (1024*1024));
    }

    *out_cache = cache;
    *out_fd = fd;
    return SHM_OK;
}

void certcache_shm_cleanup(certcache_shm_t *cache, int fd) {
    if (!cache || fd < 0) {
        return;
    }

    /* Calculate actual size from stored capacity */
    size_t shm_size = certcache_shm_size(cache->capacity);
    munmap(cache, shm_size);
    close(fd);
    /* Note: Don't unlink - other instances may still be using it */
}

/* Certcache Operations */

bool certcache_shm_lookup(const certcache_shm_t *cache, const char *cert_name,
                          certindex_entry_t *out_entry) {
    if (!cache || !cert_name) {
        return false;
    }

    robust_mutex_lock((pthread_mutex_t*)&cache->lock);

    int count = atomic_load_explicit(&cache->count, memory_order_acquire);
    bool found = false;

    /* Binary search (entries are sorted by name) */
    int left = 0, right = count - 1;
    while (left <= right) {
        int mid = left + (right - left) / 2;
        int cmp = strcmp(cert_name, cache->entries[mid].cert_name);

        if (cmp == 0) {
            /* Found */
            if (out_entry) {
                memcpy(out_entry, &cache->entries[mid], sizeof(certindex_entry_t));
            }
            found = true;
            break;
        } else if (cmp < 0) {
            right = mid - 1;
        } else {
            left = mid + 1;
        }
    }

    pthread_mutex_unlock((pthread_mutex_t*)&cache->lock);
    return found;
}

shm_error_t certcache_shm_insert(certcache_shm_t *cache, const char *cert_name,
                                  bool generation_in_progress) {
    if (!cache || !cert_name) {
        return SHM_ERR_INVALID;
    }

    robust_mutex_lock(&cache->lock);

    int count = atomic_load_explicit(&cache->count, memory_order_acquire);

    /* Find insertion point (keep sorted) */
    int insert_idx = 0;
    while (insert_idx < count &&
           strcmp(cache->entries[insert_idx].cert_name, cert_name) < 0) {
        insert_idx++;
    }

    /* Check if already exists */
    if (insert_idx < count &&
        strcmp(cache->entries[insert_idx].cert_name, cert_name) == 0) {
        /* Already exists, just update */
        atomic_store(&cache->entries[insert_idx].generation_in_progress, generation_in_progress);
        pthread_mutex_unlock(&cache->lock);
        return SHM_OK;
    }

    /* Check capacity */
    if (count >= cache->capacity) {
        pthread_mutex_unlock(&cache->lock);
        LOG_WARN("Certcache SHM full (%d entries)", count);
        return SHM_ERR_NOMEM;
    }

    /* Shift entries to make room */
    memmove(&cache->entries[insert_idx + 1], &cache->entries[insert_idx],
            (count - insert_idx) * sizeof(certindex_entry_t));

    /* Insert new entry */
    memset(&cache->entries[insert_idx], 0, sizeof(certindex_entry_t));
    strncpy(cache->entries[insert_idx].cert_name, cert_name, CERT_INDEX_ENTRY_NAME_LEN - 1);
    atomic_init(&cache->entries[insert_idx].last_use, 0);
    atomic_init(&cache->entries[insert_idx].reuse_count, 0);
    atomic_init(&cache->entries[insert_idx].generation_in_progress, generation_in_progress);
    atomic_init(&cache->entries[insert_idx].generator_pid, getpid());

    atomic_fetch_add(&cache->count, 1);

    pthread_mutex_unlock(&cache->lock);
    LOG_DEBUG("Inserted cert into SHM cache: %s (total=%d)", cert_name, count + 1);

    return SHM_OK;
}

/* ============================================================================
 * Extended Certcache Operations (with algorithm support)
 * Uses hash table with linear probing for O(1) lookups
 * ============================================================================ */

/* DJB2 hash function for (domain, algorithm) pair */
static uint32_t hash_cert_key(const char *domain, int algorithm) {
    uint32_t hash = 5381;
    int c;

    while ((c = *domain++)) {
        hash = ((hash << 5) + hash) + c; /* hash * 33 + c */
    }

    /* Mix in algorithm */
    hash = ((hash << 5) + hash) + (uint32_t)algorithm;

    return hash;
}

shm_error_t certcache_shm_insert_full(certcache_shm_t *cache,
                                       const char *cert_name,
                                       int algorithm,
                                       time_t expiry_time,
                                       bool on_disk) {
    if (!cache || !cert_name) {
        return SHM_ERR_INVALID;
    }

    uint32_t hash = hash_cert_key(cert_name, algorithm);
    uint32_t idx = hash % cache->capacity;
    uint32_t start_idx = idx;

    robust_mutex_lock(&cache->lock);

    /* Linear probing to find slot */
    do {
        certindex_entry_t *entry = &cache->entries[idx];

        /* Empty slot or matching entry */
        if (!atomic_load_explicit(&entry->valid, memory_order_acquire)) {
            /* Found empty slot - insert here */
            strncpy(entry->cert_name, cert_name, CERT_INDEX_ENTRY_NAME_LEN - 1);
            entry->cert_name[CERT_INDEX_ENTRY_NAME_LEN - 1] = '\0';
            atomic_store(&entry->algorithm, algorithm);
            atomic_store(&entry->expiry_time, (long long)expiry_time);
            atomic_store(&entry->on_disk, on_disk);
            atomic_store(&entry->generation_in_progress, false);
            atomic_store(&entry->generator_pid, getpid());
            atomic_store(&entry->last_use, (unsigned int)time(NULL));
            atomic_store(&entry->reuse_count, 1);
            atomic_store(&entry->valid, true);  /* Mark valid LAST */

            atomic_fetch_add(&cache->count, 1);
            atomic_store(&cache->dirty, true);

            pthread_mutex_unlock(&cache->lock);
            LOG_DEBUG("Inserted cert: %s (alg=%d, expiry=%lld)",
                      cert_name, algorithm, (long long)expiry_time);
            return SHM_OK;
        }

        /* Check if this is the same domain+algorithm */
        if (atomic_load_explicit(&entry->algorithm, memory_order_acquire) == algorithm &&
            strcmp(entry->cert_name, cert_name) == 0) {
            /* Update existing entry */
            atomic_store(&entry->expiry_time, (long long)expiry_time);
            atomic_store(&entry->on_disk, on_disk);
            atomic_store(&entry->last_use, (unsigned int)time(NULL));
            atomic_fetch_add(&entry->reuse_count, 1);
            atomic_store(&cache->dirty, true);

            pthread_mutex_unlock(&cache->lock);
            LOG_DEBUG("Updated cert: %s (alg=%d)", cert_name, algorithm);
            return SHM_OK;
        }

        /* Collision - try next slot */
        idx = (idx + 1) % cache->capacity;
    } while (idx != start_idx);

    /* Table full */
    pthread_mutex_unlock(&cache->lock);
    LOG_ERROR("Certcache SHM full - cannot insert %s", cert_name);
    return SHM_ERR_NOMEM;
}

bool certcache_shm_lookup_full(const certcache_shm_t *cache,
                                const char *cert_name,
                                int algorithm,
                                certindex_entry_t *out_entry) {
    if (!cache || !cert_name) {
        return false;
    }

    uint32_t hash = hash_cert_key(cert_name, algorithm);
    uint32_t idx = hash % cache->capacity;
    uint32_t start_idx = idx;

    /* RACE CONDITION FIX: Lock required for safe read
     * Without lock, entry could be deleted/modified between valid check
     * and strcmp/memcpy, causing use-after-free or corrupted data.
     * For high-performance scenarios, consider using pthread_rwlock_t. */
    robust_mutex_lock((pthread_mutex_t*)&cache->lock);

    do {
        const certindex_entry_t *entry = &cache->entries[idx];

        /* Check if slot is valid */
        if (!atomic_load_explicit(&entry->valid, memory_order_acquire)) {
            /* Empty slot - not found */
            pthread_mutex_unlock((pthread_mutex_t*)&cache->lock);
            return false;
        }

        /* Check if this is our entry */
        int entry_alg = atomic_load_explicit(&entry->algorithm, memory_order_acquire);
        if ((algorithm == -1 || entry_alg == algorithm) &&
            strcmp(entry->cert_name, cert_name) == 0) {
            /* Found! Copy out if requested */
            if (out_entry) {
                memcpy(out_entry, entry, sizeof(certindex_entry_t));
            }
            pthread_mutex_unlock((pthread_mutex_t*)&cache->lock);
            return true;
        }

        /* Collision - try next slot */
        idx = (idx + 1) % cache->capacity;
    } while (idx != start_idx);

    pthread_mutex_unlock((pthread_mutex_t*)&cache->lock);
    return false;
}

bool certcache_shm_update_expiry(certcache_shm_t *cache,
                                  const char *cert_name,
                                  int algorithm,
                                  time_t expiry_time) {
    if (!cache || !cert_name) {
        return false;
    }

    uint32_t hash = hash_cert_key(cert_name, algorithm);
    uint32_t idx = hash % cache->capacity;
    uint32_t start_idx = idx;

    robust_mutex_lock(&cache->lock);

    do {
        certindex_entry_t *entry = &cache->entries[idx];

        if (!atomic_load_explicit(&entry->valid, memory_order_acquire)) {
            pthread_mutex_unlock(&cache->lock);
            return false;
        }

        if (atomic_load_explicit(&entry->algorithm, memory_order_acquire) == algorithm &&
            strcmp(entry->cert_name, cert_name) == 0) {
            atomic_store(&entry->expiry_time, (long long)expiry_time);
            atomic_store(&cache->dirty, true);
            pthread_mutex_unlock(&cache->lock);
            return true;
        }

        idx = (idx + 1) % cache->capacity;
    } while (idx != start_idx);

    pthread_mutex_unlock(&cache->lock);
    return false;
}

bool certcache_shm_mark_on_disk(certcache_shm_t *cache,
                                 const char *cert_name,
                                 int algorithm) {
    if (!cache || !cert_name) {
        return false;
    }

    uint32_t hash = hash_cert_key(cert_name, algorithm);
    uint32_t idx = hash % cache->capacity;
    uint32_t start_idx = idx;

    /* RACE CONDITION FIX: Lock required for safe access
     * Without lock, entry could be deleted between valid check and write */
    robust_mutex_lock(&cache->lock);

    do {
        certindex_entry_t *entry = &cache->entries[idx];

        if (!atomic_load_explicit(&entry->valid, memory_order_acquire)) {
            pthread_mutex_unlock(&cache->lock);
            return false;
        }

        if (atomic_load_explicit(&entry->algorithm, memory_order_acquire) == algorithm &&
            strcmp(entry->cert_name, cert_name) == 0) {
            atomic_store(&entry->on_disk, true);
            atomic_store(&cache->dirty, true);
            pthread_mutex_unlock(&cache->lock);
            return true;
        }

        idx = (idx + 1) % cache->capacity;
    } while (idx != start_idx);

    pthread_mutex_unlock(&cache->lock);
    return false;
}

/* Disk persistence format */
#define CERTCACHE_FILE_MAGIC 0x43455254494E4458ULL  /* "CERTINDX" */
#define CERTCACHE_FILE_VERSION 1

typedef struct {
    uint64_t magic;
    uint32_t version;
    uint32_t entry_count;
    uint64_t timestamp;
    uint8_t reserved[488];  /* Pad to 512 bytes */
} __attribute__((packed)) certcache_file_header_t;

typedef struct {
    char cert_name[CERT_INDEX_ENTRY_NAME_LEN];
    int32_t algorithm;
    int64_t expiry_time;
    uint8_t on_disk;
    uint8_t reserved[243];  /* Pad to 512 bytes */
} __attribute__((packed)) certcache_file_entry_t;

shm_error_t certcache_shm_save(certcache_shm_t *cache, const char *filepath) {
    if (!cache || !filepath) {
        return SHM_ERR_INVALID;
    }

    /* Create temp file for atomic write */
    char tmp_path[512];
    snprintf(tmp_path, sizeof(tmp_path), "%s.tmp", filepath);

    FILE *fp = fopen(tmp_path, "wb");
    if (!fp) {
        LOG_ERROR("Failed to open certcache file for writing: %s (%s)",
                  tmp_path, strerror(errno));
        return SHM_ERR_CREATE;
    }

    robust_mutex_lock(&cache->lock);

    /* Count valid entries */
    uint32_t entry_count = 0;
    for (int i = 0; i < cache->capacity; i++) {
        if (atomic_load_explicit(&cache->entries[i].valid, memory_order_acquire)) {
            entry_count++;
        }
    }

    /* Write header */
    certcache_file_header_t header = {
        .magic = CERTCACHE_FILE_MAGIC,
        .version = CERTCACHE_FILE_VERSION,
        .entry_count = entry_count,
        .timestamp = (uint64_t)time(NULL)
    };

    if (fwrite(&header, sizeof(header), 1, fp) != 1) {
        LOG_ERROR("Failed to write certcache header");
        fclose(fp);
        unlink(tmp_path);
        pthread_mutex_unlock(&cache->lock);
        return SHM_ERR_CREATE;
    }

    /* Write entries */
    for (int i = 0; i < cache->capacity; i++) {
        const certindex_entry_t *entry = &cache->entries[i];
        if (!atomic_load_explicit(&entry->valid, memory_order_acquire)) {
            continue;
        }

        certcache_file_entry_t disk_entry = {0};
        strncpy(disk_entry.cert_name, entry->cert_name, CERT_INDEX_ENTRY_NAME_LEN - 1);
        disk_entry.algorithm = atomic_load_explicit(&entry->algorithm, memory_order_acquire);
        disk_entry.expiry_time = atomic_load_explicit(&entry->expiry_time, memory_order_acquire);
        disk_entry.on_disk = atomic_load_explicit(&entry->on_disk, memory_order_acquire) ? 1 : 0;

        if (fwrite(&disk_entry, sizeof(disk_entry), 1, fp) != 1) {
            LOG_ERROR("Failed to write certcache entry");
            fclose(fp);
            unlink(tmp_path);
            pthread_mutex_unlock(&cache->lock);
            return SHM_ERR_CREATE;
        }
    }

    fclose(fp);

    /* Atomic rename */
    if (rename(tmp_path, filepath) != 0) {
        LOG_ERROR("Failed to rename certcache file: %s", strerror(errno));
        unlink(tmp_path);
        pthread_mutex_unlock(&cache->lock);
        return SHM_ERR_CREATE;
    }

    atomic_store(&cache->dirty, false);
    atomic_store(&cache->last_save_time, (long long)time(NULL));

    pthread_mutex_unlock(&cache->lock);

    LOG_INFO("Saved certcache to disk: %s (%u entries)", filepath, entry_count);
    return SHM_OK;
}

shm_error_t certcache_shm_load(certcache_shm_t *cache, const char *filepath) {
    if (!cache || !filepath) {
        return SHM_ERR_INVALID;
    }

    FILE *fp = fopen(filepath, "rb");
    if (!fp) {
        if (errno == ENOENT) {
            LOG_INFO("No certcache file found, starting fresh: %s", filepath);
            return SHM_OK;  /* Not an error - just empty */
        }
        LOG_ERROR("Failed to open certcache file: %s (%s)", filepath, strerror(errno));
        return SHM_ERR_CREATE;
    }

    /* Read header */
    certcache_file_header_t header;
    if (fread(&header, sizeof(header), 1, fp) != 1) {
        LOG_ERROR("Failed to read certcache header");
        fclose(fp);
        return SHM_ERR_INVALID;
    }

    /* Validate header */
    if (header.magic != CERTCACHE_FILE_MAGIC) {
        LOG_ERROR("Invalid certcache file magic: 0x%016llx", (unsigned long long)header.magic);
        fclose(fp);
        return SHM_ERR_MAGIC;
    }

    if (header.version != CERTCACHE_FILE_VERSION) {
        LOG_WARN("Certcache version mismatch: %u (expected %u) - rebuilding",
                 header.version, CERTCACHE_FILE_VERSION);
        fclose(fp);
        return SHM_OK;  /* Will rebuild from certs on disk */
    }

    LOG_INFO("Loading certcache: %u entries from %s", header.entry_count, filepath);

    robust_mutex_lock(&cache->lock);

    /* Load entries */
    uint32_t loaded = 0;
    for (uint32_t i = 0; i < header.entry_count; i++) {
        certcache_file_entry_t disk_entry;
        if (fread(&disk_entry, sizeof(disk_entry), 1, fp) != 1) {
            LOG_ERROR("Failed to read certcache entry %u", i);
            break;
        }

        /* Insert into hash table */
        uint32_t hash = hash_cert_key(disk_entry.cert_name, disk_entry.algorithm);
        uint32_t idx = hash % cache->capacity;
        uint32_t start_idx = idx;

        do {
            certindex_entry_t *entry = &cache->entries[idx];

            if (!atomic_load_explicit(&entry->valid, memory_order_acquire)) {
                /* Found empty slot - use snprintf to avoid truncation warnings */
                snprintf(entry->cert_name, CERT_INDEX_ENTRY_NAME_LEN, "%s", disk_entry.cert_name);
                atomic_store(&entry->algorithm, disk_entry.algorithm);
                atomic_store(&entry->expiry_time, disk_entry.expiry_time);
                atomic_store(&entry->on_disk, disk_entry.on_disk != 0);
                atomic_store(&entry->generation_in_progress, false);
                atomic_store(&entry->last_use, 0);
                atomic_store(&entry->reuse_count, 0);
                atomic_store(&entry->valid, true);
                atomic_fetch_add(&cache->count, 1);
                loaded++;
                break;
            }

            idx = (idx + 1) % cache->capacity;
        } while (idx != start_idx);
    }

    pthread_mutex_unlock(&cache->lock);
    fclose(fp);

    LOG_INFO("Loaded %u certcache entries from disk", loaded);
    return SHM_OK;
}

/* ========== Worker Watchdog Implementation ========== */

#include <sys/wait.h>

/* Watchdog thread state */
static pthread_t watchdog_thread;
static atomic_bool watchdog_running = false;
static keypool_shm_t *watchdog_pool = NULL;
static char watchdog_binary[PATH_MAX];  /* Fallback binary path for restart */

/* Register worker in watchdog registry
 *
 * Uses CAS (compare-and-swap) to atomically claim a slot,
 * preventing race conditions when multiple workers start simultaneously.
 */
int worker_register(keypool_shm_t *pool, int argc, char **argv,
                    const char *listen_addr, int http_port, int https_port, int auto_port) {
    if (!pool || !argv) {
        return -1;
    }

    /* Build command line string from argv */
    char cmdline[WORKER_CMDLINE_MAX];
    size_t offset = 0;
    for (int i = 0; i < argc && offset < sizeof(cmdline) - 1; i++) {
        int written = snprintf(cmdline + offset, sizeof(cmdline) - offset,
                               "%s%s", i > 0 ? " " : "", argv[i]);
        if (written > 0) {
            offset += (size_t)written;
        }
    }

    pid_t my_pid = getpid();
    int slot = -1;
    int max_attempts = MAX_WATCHED_WORKERS * 2;  /* Allow retries on CAS failure */

    for (int attempt = 0; attempt < max_attempts && slot < 0; attempt++) {
        for (int i = 0; i < MAX_WATCHED_WORKERS; i++) {
            worker_entry_t *entry = &pool->workers[i];
            pid_t existing = atomic_load_explicit(&entry->pid, memory_order_acquire);

            /* Check if slot is empty */
            if (existing == 0) {
                /* Try to atomically claim this slot using CAS */
                pid_t expected = 0;
                if (atomic_compare_exchange_strong_explicit(&entry->pid,
                                                            &expected,
                                                            my_pid,
                                                            memory_order_acq_rel,
                                                            memory_order_acquire)) {
                    slot = i;
                    break;
                }
                /* CAS failed - another worker claimed it, continue searching */
                continue;
            }

            /* Check if existing PID is dead (reuse slot) */
            if (kill(existing, 0) != 0 && errno == ESRCH) {
                /* Try to atomically claim this dead slot */
                pid_t expected = existing;
                if (atomic_compare_exchange_strong_explicit(&entry->pid,
                                                            &expected,
                                                            my_pid,
                                                            memory_order_acq_rel,
                                                            memory_order_acquire)) {
                    slot = i;
                    break;
                }
                /* CAS failed - watchdog or another worker got it first */
                continue;
            }
        }
    }

    if (slot < 0) {
        LOG_ERROR("Worker registry full (%d workers)", MAX_WATCHED_WORKERS);
        return -1;
    }

    /* We now own this slot (pid is set) - populate other fields
     * Note: pid was already set via CAS above, so watchdog won't read garbage */
    worker_entry_t *entry = &pool->workers[slot];
    time_t now = time(NULL);

    /* Set all fields atomically where possible */
    atomic_store_explicit(&entry->last_heartbeat, (long long)now, memory_order_release);
    atomic_store_explicit(&entry->start_time, (long long)now, memory_order_release);
    atomic_store_explicit(&entry->restart_count, 0, memory_order_release);
    atomic_store_explicit(&entry->http_port, http_port, memory_order_release);
    atomic_store_explicit(&entry->https_port, https_port, memory_order_release);
    atomic_store_explicit(&entry->auto_port, auto_port, memory_order_release);

    /* Copy strings - these are not atomic but we already own the slot */
    snprintf(entry->cmdline, sizeof(entry->cmdline), "%s", cmdline);
    snprintf(entry->listen_addr, sizeof(entry->listen_addr), "%s",
             listen_addr ? listen_addr : "*");

    /* Memory barrier to ensure all writes are visible before marking healthy */
    atomic_thread_fence(memory_order_release);

    /* RACE CONDITION FIX: Increment worker count BEFORE marking healthy
     * This ensures watchdog sees consistent state:
     * - worker_count includes this worker when healthy is true
     * - Prevents brief window where healthy=true but count is old */
    atomic_fetch_add(&pool->worker_count, 1);

    /* Mark as healthy LAST - this signals the slot is fully initialized */
    atomic_store_explicit(&entry->healthy, true, memory_order_release);

    LOG_INFO("Worker registered: slot=%d, pid=%d, addr=%s, ports=%d/%d/%d",
             slot, my_pid, entry->listen_addr, http_port, https_port, auto_port);

    return slot;
}

/* Unregister worker (graceful shutdown) */
void worker_unregister(keypool_shm_t *pool, int slot) {
    if (!pool || slot < 0 || slot >= MAX_WATCHED_WORKERS) {
        return;
    }

    worker_entry_t *entry = &pool->workers[slot];
    pid_t pid = atomic_load_explicit(&entry->pid, memory_order_acquire);

    if (pid == getpid()) {
        /* Only unregister if we own this slot */
        atomic_store(&entry->pid, 0);
        atomic_store(&entry->healthy, false);
        atomic_fetch_sub(&pool->worker_count, 1);

        LOG_INFO("Worker unregistered: slot=%d, pid=%d (graceful)", slot, pid);
    }
}

/* Send heartbeat */
void worker_heartbeat(keypool_shm_t *pool, int slot) {
    if (!pool || slot < 0 || slot >= MAX_WATCHED_WORKERS) {
        return;
    }

    worker_entry_t *entry = &pool->workers[slot];
    atomic_store(&entry->last_heartbeat, (long long)time(NULL));
    atomic_store(&entry->healthy, true);
}

/* Check if worker is healthy */
bool worker_is_healthy(const keypool_shm_t *pool, int slot) {
    if (!pool || slot < 0 || slot >= MAX_WATCHED_WORKERS) {
        return false;
    }

    const worker_entry_t *entry = &pool->workers[slot];
    pid_t pid = atomic_load_explicit(&entry->pid, memory_order_acquire);

    if (pid == 0) {
        return false;  /* Empty slot */
    }

    /* Check if process exists */
    if (kill(pid, 0) != 0) {
        return false;  /* Process dead */
    }

    /* Check heartbeat age
     * CLOCK-JUMP FIX: Handle system time going backwards (NTP correction, suspend/resume)
     * If now < last_hb, clock jumped backwards - treat as healthy to avoid false restarts
     */
    time_t now = time(NULL);
    long long last_hb = atomic_load_explicit(&entry->last_heartbeat, memory_order_acquire);
    long long diff = (long long)now - last_hb;

    if (diff < 0) {
        /* Clock jumped backwards - update heartbeat to current time to prevent future issues */
        atomic_store_explicit(&entry->last_heartbeat, (long long)now, memory_order_release);
        return true;  /* Assume healthy during clock adjustment */
    }

    if (diff > WORKER_HEARTBEAT_TIMEOUT) {
        return false;  /* Heartbeat timeout */
    }

    return true;
}

/* Restart a dead worker */
static void restart_worker(keypool_shm_t *pool, int slot) {
    worker_entry_t *entry = &pool->workers[slot];
    pid_t old_pid = atomic_load_explicit(&entry->pid, memory_order_acquire);

    LOG_WARN("Restarting worker: slot=%d, old_pid=%d, addr=%s",
             slot, old_pid, entry->listen_addr);

    /* Kill if still running (stuck) */
    if (old_pid > 0 && kill(old_pid, 0) == 0) {
        LOG_WARN("Sending SIGTERM to stuck worker %d", old_pid);
        kill(old_pid, SIGTERM);
        usleep(500000);  /* Wait 500ms */

        if (kill(old_pid, 0) == 0) {
            LOG_WARN("Worker %d still alive, sending SIGKILL", old_pid);
            kill(old_pid, SIGKILL);
            usleep(100000);  /* Wait 100ms */
        }
    }

    /* Parse command line back into argv */
    char cmdline_copy[WORKER_CMDLINE_MAX];
    snprintf(cmdline_copy, sizeof(cmdline_copy), "%s", entry->cmdline);

    char *argv[128];
    int argc = 0;
    char *token = strtok(cmdline_copy, " ");
    while (token && argc < 127) {
        argv[argc++] = token;
        token = strtok(NULL, " ");
    }
    argv[argc] = NULL;

    if (argc == 0) {
        LOG_ERROR("Cannot restart worker: empty command line");
        return;
    }

    /* Determine binary path - use cmdline[0] or fallback to watchdog_binary */
    const char *binary = argv[0];
    if (access(binary, X_OK) != 0) {
        LOG_WARN("Binary '%s' not executable, using fallback: %s", binary, watchdog_binary);
        binary = watchdog_binary;
        if (access(binary, X_OK) != 0) {
            LOG_ERROR("Cannot restart worker: no valid binary (cmdline='%s', fallback='%s')",
                      argv[0], watchdog_binary);
            return;
        }
    }

    /* Fork and exec */
    pid_t pid = fork();

    if (pid < 0) {
        LOG_ERROR("Failed to fork for worker restart: %s", strerror(errno));
        return;
    }

    if (pid == 0) {
        /* Child: Execute worker using determined binary path */
        execv(binary, argv);
        /* If we get here, exec failed */
        LOG_ERROR("execv(%s) failed: %s", binary, strerror(errno));
        _exit(1);
    }

    /* Parent: Update registry */
    atomic_store(&entry->pid, pid);
    atomic_store(&entry->last_heartbeat, (long long)time(NULL));
    atomic_store(&entry->start_time, (long long)time(NULL));
    atomic_fetch_add(&entry->restart_count, 1);
    atomic_store(&entry->healthy, true);

    int restart_count = atomic_load_explicit(&entry->restart_count, memory_order_acquire);
    LOG_INFO("Worker restarted: slot=%d, new_pid=%d, restart_count=%d",
             slot, pid, restart_count);
}

/* Reap zombie child processes
 *
 * When we fork() to restart workers, the child processes become zombies
 * when they exit. This function reaps them to prevent resource leaks.
 */
static void reap_zombie_children(void) {
    int status;
    pid_t pid;

    /* Reap all available zombies (non-blocking) */
    while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {
        if (WIFEXITED(status)) {
            LOG_DEBUG("Reaped child process %d (exit code: %d)", pid, WEXITSTATUS(status));
        } else if (WIFSIGNALED(status)) {
            LOG_DEBUG("Reaped child process %d (killed by signal: %d)", pid, WTERMSIG(status));
        } else {
            LOG_DEBUG("Reaped child process %d", pid);
        }
    }
}

/* Watchdog thread function */
static void *watchdog_thread_func(void *arg) {
    (void)arg;

    LOG_INFO("Watchdog thread started (check interval: %ds)", WATCHDOG_CHECK_INTERVAL);

    while (atomic_load_explicit(&watchdog_running, memory_order_acquire)) {
        /* Sleep in smaller intervals to respond to shutdown quickly */
        for (int i = 0; i < WATCHDOG_CHECK_INTERVAL && atomic_load_explicit(&watchdog_running, memory_order_acquire); i++) {
            sleep(1);

            /* Reap zombies periodically during sleep (every 10 seconds) */
            if (i % 10 == 0) {
                reap_zombie_children();
            }
        }

        if (!atomic_load_explicit(&watchdog_running, memory_order_acquire)) {
            break;
        }

        /* Reap any zombie children before checking workers */
        reap_zombie_children();

        /* Check all registered workers */
        int checked = 0;
        int healthy = 0;
        int restarted = 0;

        for (int i = 0; i < MAX_WATCHED_WORKERS; i++) {
            worker_entry_t *entry = &watchdog_pool->workers[i];
            pid_t pid = atomic_load_explicit(&entry->pid, memory_order_acquire);

            if (pid == 0) {
                continue;  /* Empty slot */
            }

            checked++;

            /* Check if process is alive */
            bool alive = (kill(pid, 0) == 0);

            /* Check heartbeat
             * CLOCK-JUMP FIX: Handle system time going backwards (NTP correction, suspend/resume)
             */
            time_t now = time(NULL);
            long long last_hb = atomic_load_explicit(&entry->last_heartbeat, memory_order_acquire);
            long long diff = (long long)now - last_hb;
            bool hb_ok;

            if (diff < 0) {
                /* Clock jumped backwards - update heartbeat and treat as healthy */
                atomic_store_explicit(&entry->last_heartbeat, (long long)now, memory_order_release);
                hb_ok = true;
                LOG_DEBUG("Worker %d (slot %d) clock-jump detected, resetting heartbeat", pid, i);
            } else {
                hb_ok = (diff < WORKER_HEARTBEAT_TIMEOUT);
            }

            if (alive && hb_ok) {
                atomic_store(&entry->healthy, true);
                healthy++;
            } else {
                atomic_store(&entry->healthy, false);

                if (!alive) {
                    LOG_WARN("Worker %d (slot %d) is DEAD", pid, i);
                } else {
                    LOG_WARN("Worker %d (slot %d) heartbeat TIMEOUT (%llds)",
                             pid, i, diff);
                }

                /* Restart the worker */
                restart_worker(watchdog_pool, i);
                restarted++;
            }
        }

        if (checked > 0) {
            LOG_INFO("Watchdog check: %d workers, %d healthy, %d restarted",
                     checked, healthy, restarted);
        }
    }

    /* Final cleanup - reap any remaining zombies */
    reap_zombie_children();

    LOG_INFO("Watchdog thread stopped");
    return NULL;
}

/* Start watchdog */
int watchdog_start(keypool_shm_t *pool, const char *binary_path) {
    if (!pool || !binary_path) {
        return -1;
    }

    if (atomic_load_explicit(&watchdog_running, memory_order_acquire)) {
        LOG_WARN("Watchdog already running");
        return 0;
    }

    watchdog_pool = pool;
    snprintf(watchdog_binary, sizeof(watchdog_binary), "%s", binary_path);

    /* Enable watchdog in SHM */
    atomic_store(&pool->watchdog_enabled, true);

    /* Start watchdog thread */
    atomic_store(&watchdog_running, true);

    if (pthread_create(&watchdog_thread, NULL, watchdog_thread_func, NULL) != 0) {
        LOG_ERROR("Failed to create watchdog thread: %s", strerror(errno));
        atomic_store(&watchdog_running, false);
        return -1;
    }

    LOG_INFO("Watchdog started: monitoring up to %d workers", MAX_WATCHED_WORKERS);
    return 0;
}

/* Stop watchdog */
void watchdog_stop(void) {
    if (!atomic_load_explicit(&watchdog_running, memory_order_acquire)) {
        return;
    }

    LOG_INFO("Stopping watchdog...");
    atomic_store(&watchdog_running, false);

    /* Wait for thread to finish */
    pthread_join(watchdog_thread, NULL);

    if (watchdog_pool) {
        atomic_store(&watchdog_pool->watchdog_enabled, false);
    }

    LOG_INFO("Watchdog stopped");
}

/* ============================================================================
 * Second-Level TLD Storage (Shared Memory)
 * ============================================================================
 * Poolgen loads TLDs once, workers read from SHM
 * Format: newline-separated TLDs (e.g., ".co.uk\n.com.au\n...")
 * ============================================================================ */

/**
 * Load second-level TLDs from file into SHM
 *
 * Called by Poolgen during startup. Workers will read from SHM.
 * File format: one TLD per line, with or without leading dot
 *   .co.uk
 *   .com.au
 *   co.jp
 *
 * @param cache     Certcache SHM (must be writable)
 * @param filepath  Path to TLD file
 * @return          0 on success, -1 on error
 */
int certcache_shm_load_tlds(certcache_shm_t *cache, const char *filepath) {
    if (!cache || !filepath) {
        LOG_ERROR("certcache_shm_load_tlds: invalid arguments");
        return -1;
    }

    FILE *fp = fopen(filepath, "r");
    if (!fp) {
        if (errno == ENOENT) {
            LOG_WARN("TLD file not found: %s (wildcards may be incorrect)", filepath);
            return 0;  /* Not fatal - just no TLDs loaded */
        }
        LOG_ERROR("Failed to open TLD file: %s (%s)", filepath, strerror(errno));
        return -1;
    }

    /* Read file into buffer */
    char line[256];
    char *write_ptr = cache->tld_data;
    size_t remaining = SHM_TLD_MAX_STORAGE - 1;  /* Reserve 1 for null terminator */
    int tld_count = 0;

    while (fgets(line, sizeof(line), fp) && remaining > 0) {
        /* Strip newline and whitespace */
        char *p = line;
        while (*p && (*p == ' ' || *p == '\t')) p++;  /* Skip leading whitespace */

        /* Skip empty lines and comments */
        if (*p == '\0' || *p == '\n' || *p == '#') {
            continue;
        }

        /* Find end and strip trailing whitespace/newline */
        char *end = p + strlen(p) - 1;
        while (end > p && (*end == '\n' || *end == '\r' || *end == ' ' || *end == '\t')) {
            *end-- = '\0';
        }

        if (*p == '\0') {
            continue;
        }

        /* Ensure TLD starts with dot */
        size_t tld_len;
        if (*p != '.') {
            /* Add leading dot */
            if (remaining < strlen(p) + 2) {  /* +1 dot, +1 newline */
                LOG_WARN("TLD storage full at %d entries", tld_count);
                break;
            }
            *write_ptr++ = '.';
            remaining--;
            tld_len = strlen(p);
        } else {
            tld_len = strlen(p);
            if (remaining < tld_len + 1) {  /* +1 newline */
                LOG_WARN("TLD storage full at %d entries", tld_count);
                break;
            }
        }

        /* Copy TLD */
        memcpy(write_ptr, p, tld_len);
        write_ptr += tld_len;
        remaining -= tld_len;

        /* Add newline separator */
        *write_ptr++ = '\n';
        remaining--;

        tld_count++;
    }

    fclose(fp);

    /* Null-terminate */
    *write_ptr = '\0';

    /* Store length atomically */
    int data_len = (int)(write_ptr - cache->tld_data);
    atomic_store(&cache->tld_data_len, data_len);

    LOG_INFO("Loaded %d second-level TLDs into SHM (%d bytes)", tld_count, data_len);

    return 0;
}

/**
 * Get pointer to TLD data in SHM
 *
 * Called by Workers to read TLDs from SHM.
 *
 * @param cache    Certcache SHM (read-only access)
 * @param out_len  Output: length of TLD data (optional, can be NULL)
 * @return         Pointer to TLD data, or NULL if not loaded
 */
const char* certcache_shm_get_tld_data(const certcache_shm_t *cache, int *out_len) {
    if (!cache) {
        return NULL;
    }

    int len = atomic_load_explicit(&cache->tld_data_len, memory_order_acquire);

    if (out_len) {
        *out_len = len;
    }

    if (len == 0) {
        return NULL;  /* No TLDs loaded */
    }

    return cache->tld_data;
}

/* ============================================================================
 * Silent Blocker Storage (Hot-Reloadable via SIGHUP)
 * ============================================================================
 * Poolgen loads silent-blocks.conf, workers read from SHM
 * Workers poll silentblock_version to detect updates (hot-reload)
 * ============================================================================ */

/**
 * Load silent-block rules from file into SHM
 *
 * Called by Poolgen on startup and on SIGHUP for hot-reload.
 * Increments version counter so workers can detect the update.
 *
 * @param cache     Certcache SHM (must be writable)
 * @param filepath  Path to silent-blocks.conf
 * @return          0 on success, -1 on error
 */
int certcache_shm_load_silentblocks(certcache_shm_t *cache, const char *filepath) {
    if (!cache || !filepath) {
        LOG_ERROR("certcache_shm_load_silentblocks: invalid arguments");
        return -1;
    }

    FILE *fp = fopen(filepath, "r");
    if (!fp) {
        if (errno == ENOENT) {
            LOG_INFO("Silent-block file not found: %s (silent blocking disabled)", filepath);
            /* Clear existing data */
            atomic_store(&cache->silentblock_data_len, 0);
            cache->silentblock_data[0] = '\0';
            return 0;  /* Not fatal */
        }
        LOG_ERROR("Failed to open silent-block file: %s (%s)", filepath, strerror(errno));
        return -1;
    }

    /* Get file size */
    fseek(fp, 0, SEEK_END);
    long file_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    if (file_size < 0) {
        LOG_ERROR("Failed to get file size: %s", filepath);
        fclose(fp);
        return -1;
    }

    if ((size_t)file_size >= SHM_SILENTBLOCK_MAX_STORAGE) {
        LOG_ERROR("Silent-block file too large: %ld bytes (max %zu)",
                  file_size, (size_t)(SHM_SILENTBLOCK_MAX_STORAGE - 1));
        fclose(fp);
        return -1;
    }

    /* Read entire file into SHM buffer */
    size_t bytes_read = fread(cache->silentblock_data, 1, (size_t)file_size, fp);
    fclose(fp);

    if (bytes_read != (size_t)file_size) {
        LOG_ERROR("Failed to read silent-block file: expected %ld, got %zu",
                  file_size, bytes_read);
        return -1;
    }

    /* Null-terminate */
    cache->silentblock_data[bytes_read] = '\0';

    /* Count rules (non-empty, non-comment lines) */
    int rule_count = 0;
    const char *p = cache->silentblock_data;
    while (*p) {
        /* Skip whitespace */
        while (*p == ' ' || *p == '\t') p++;
        /* Count if not empty and not comment */
        if (*p && *p != '\n' && *p != '#') {
            rule_count++;
        }
        /* Skip to next line */
        while (*p && *p != '\n') p++;
        if (*p == '\n') p++;
    }

    /* Update atomically - set length THEN increment version
     * Workers will see version change and re-read data */
    atomic_store(&cache->silentblock_data_len, (int)bytes_read);

    /* Memory barrier to ensure data is visible before version bump */
    atomic_thread_fence(memory_order_release);

    /* Increment version (wraps around, but that's fine - workers just check for change) */
    int old_version = atomic_fetch_add(&cache->silentblock_version, 1);

    LOG_INFO("Loaded %d silent-block rules into SHM (%zu bytes, version %d → %d)",
             rule_count, bytes_read, old_version, old_version + 1);

    return 0;
}

/**
 * Get pointer to silent-block data in SHM
 *
 * Called by Workers to read rules from SHM.
 * Workers should compare out_version with their cached version
 * to detect hot-reloads.
 *
 * @param cache       Certcache SHM (read-only access)
 * @param out_len     Output: length of data (optional, can be NULL)
 * @param out_version Output: current version (optional, can be NULL)
 * @return            Pointer to data, or NULL if not loaded
 */
const char* certcache_shm_get_silentblock_data(const certcache_shm_t *cache,
                                                int *out_len,
                                                int *out_version) {
    if (!cache) {
        return NULL;
    }

    /* Read version first (acquire semantics) */
    int version = atomic_load_explicit(&cache->silentblock_version, memory_order_acquire);
    int len = atomic_load_explicit(&cache->silentblock_data_len, memory_order_acquire);

    if (out_version) {
        *out_version = version;
    }

    if (out_len) {
        *out_len = len;
    }

    if (len == 0) {
        return NULL;  /* No rules loaded */
    }

    return cache->silentblock_data;
}
