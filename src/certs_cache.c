/*
 * certs_cache.c - Lock-free SSL context cache implementation
 *
 * Uses open addressing with linear probing and atomic CAS for insertions.
 * Lookups are wait-free. Insertions use CAS retry loop.
 */

#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <dirent.h>
#include <sys/stat.h>
#include "../include/certs_cache.h"
#include "../include/certs_stats.h"
#include "../include/logger.h"

/* FNV-1a hash for fast distribution */
static inline uint32_t fnv1a_hash(const char *str) {
    uint32_t hash = 2166136261u;
    while (*str) {
        hash ^= (unsigned char)*str++;
        hash *= 16777619u;
    }
    return hash;
}

/* Cache storage */
static cache_entry_t *cache_entries;
static int cache_size;
static _Atomic int cache_used;

/* Hash table for O(1) lookup: maps hash -> entry index */
static _Atomic int *hash_table;
static int hash_table_size;

/* Prime sizes for hash table (good distribution) */
static const int primes[] = {
    53, 97, 193, 389, 769, 1543, 3079, 6151, 12289, 24593,
    49157, 98317, 196613, 393241, 786433, 1572869, 0
};

static int next_prime(int n) {
    for (int i = 0; primes[i]; i++) {
        if (primes[i] >= n) return primes[i];
    }
    return primes[sizeof(primes)/sizeof(primes[0]) - 2];
}

void cache_init(int size) {
    cache_size = size;
    hash_table_size = next_prime(size * 2);  /* Load factor ~0.5 */

    cache_entries = calloc(size, sizeof(cache_entry_t));
    hash_table = calloc(hash_table_size, sizeof(_Atomic int));

    if (!cache_entries || !hash_table) {
        log_msg(LGG_ERR, "Failed to allocate cache");
        return;
    }

    /* Initialize hash table to -1 (empty) */
    for (int i = 0; i < hash_table_size; i++) {
        atomic_store(&hash_table[i], -1);
    }

    /* Initialize cache entries */
    for (int i = 0; i < cache_size; i++) {
        atomic_store(&cache_entries[i].state, CACHE_EMPTY);
        atomic_store(&cache_entries[i].last_use, 0);
        atomic_store(&cache_entries[i].reuse_count, 0);
    }

    atomic_store(&cache_used, 0);
}

void cache_cleanup(void) {
    if (cache_entries) {
        for (int i = 0; i < cache_size; i++) {
            if (cache_entries[i].cert_name) {
                free(cache_entries[i].cert_name);
            }
            if (cache_entries[i].sslctx) {
                SSL_CTX_free(cache_entries[i].sslctx);
            }
        }
        free(cache_entries);
        cache_entries = NULL;
    }

    if (hash_table) {
        free((void *)hash_table);
        hash_table = NULL;
    }
}

SSL_CTX *cache_lookup(const char *cert_name) {
    if (!cert_name || !cache_entries || !hash_table) return NULL;

    uint32_t hash = fnv1a_hash(cert_name);
    int start = hash % hash_table_size;

    /* Linear probing */
    for (int i = 0; i < hash_table_size; i++) {
        int slot = (start + i) % hash_table_size;
        int idx = atomic_load(&hash_table[slot]);

        if (idx == -1) {
            /* Empty slot, not found */
            stats_inc_miss();
            return NULL;
        }

        if (idx >= 0 && idx < cache_size) {
            cache_entry_t *entry = &cache_entries[idx];
            int state = atomic_load(&entry->state);

            if (state == CACHE_VALID && entry->cert_name &&
                strcmp(entry->cert_name, cert_name) == 0) {
                /* Found - update stats and timestamp */
                stats_inc_hit();
                atomic_fetch_add(&entry->reuse_count, 1);
                atomic_store(&entry->last_use, (uint32_t)time(NULL));
                return entry->sslctx;
            }
        }
    }

    stats_inc_miss();
    return NULL;
}

int cache_insert(const char *cert_name, SSL_CTX *sslctx) {
    if (!cert_name || !sslctx || !cache_entries || !hash_table) return -1;

    /* Find a free entry slot */
    int entry_idx = -1;
    for (int i = 0; i < cache_size; i++) {
        int expected = CACHE_EMPTY;
        if (atomic_compare_exchange_strong(&cache_entries[i].state,
                                           &expected, CACHE_INSERTING)) {
            entry_idx = i;
            break;
        }
    }

    if (entry_idx < 0) {
        /* Cache full, try to expire oldest */
        log_msg(LGG_DEBUG, "Cache full, cannot insert %s", cert_name);
        return -1;
    }

    cache_entry_t *entry = &cache_entries[entry_idx];

    /* Setup entry */
    entry->alloc_len = strlen(cert_name) + 1;
    entry->cert_name = malloc(entry->alloc_len);
    if (!entry->cert_name) {
        atomic_store(&entry->state, CACHE_EMPTY);
        return -1;
    }
    memcpy(entry->cert_name, cert_name, entry->alloc_len);  /* alloc_len includes NUL */
    entry->sslctx = sslctx;
    atomic_store(&entry->last_use, (uint32_t)time(NULL));
    atomic_store(&entry->reuse_count, 0);

    /* Insert into hash table */
    uint32_t hash = fnv1a_hash(cert_name);
    int start = hash % hash_table_size;

    for (int i = 0; i < hash_table_size; i++) {
        int slot = (start + i) % hash_table_size;
        int expected = -1;

        if (atomic_compare_exchange_strong(&hash_table[slot],
                                           &expected, entry_idx)) {
            /* Success */
            atomic_store(&entry->state, CACHE_VALID);
            atomic_fetch_add(&cache_used, 1);
            stats_inc_total();
            return entry_idx;
        }
    }

    /* Hash table full (shouldn't happen with proper sizing) */
    free(entry->cert_name);
    entry->cert_name = NULL;
    entry->sslctx = NULL;  /* Don't free, caller owns it */
    atomic_store(&entry->state, CACHE_EMPTY);
    return -1;
}

int cache_get_size(void) {
    return cache_size;
}

int cache_get_used(void) {
    return atomic_load(&cache_used);
}

void cache_touch(int idx) {
    if (idx >= 0 && idx < cache_size) {
        atomic_store(&cache_entries[idx].last_use, (uint32_t)time(NULL));
    }
}

void cache_expire_old(uint32_t max_age_seconds) {
    uint32_t now = (uint32_t)time(NULL);
    uint32_t threshold = now - max_age_seconds;

    for (int i = 0; i < cache_size; i++) {
        cache_entry_t *entry = &cache_entries[i];
        int state = atomic_load(&entry->state);

        if (state == CACHE_VALID) {
            uint32_t last_use = atomic_load(&entry->last_use);
            if (last_use < threshold) {
                /* Try to expire */
                int expected = CACHE_VALID;
                if (atomic_compare_exchange_strong(&entry->state,
                                                   &expected, CACHE_EXPIRED)) {
                    stats_inc_purge();
                    log_msg(LGG_DEBUG, "Expired cache entry: %s",
                            entry->cert_name ? entry->cert_name : "?");
                }
            }
        }
    }
}

/* Cache index file format:
 * - Magic: uint32_t "CCIX" (0x43434958)
 * - Version: uint32_t (1)
 * - Count: uint32_t (number of entries)
 * - Entries: cert_name (null-terminated), last_use (uint32_t), reuse_count (int32_t)
 */
#define CACHE_INDEX_MAGIC 0x43434958  /* "CCIX" */
#define CACHE_INDEX_VERSION 1

/* Save cache index to disk */
void cache_save_index(const char *pem_dir) {
    if (!pem_dir || !cache_entries) return;

    char index_path[512];
    snprintf(index_path, sizeof(index_path), "%s/.cache_index", pem_dir);

    FILE *fp = fopen(index_path, "wb");
    if (!fp) {
        log_msg(LGG_WARNING, "Cannot save cache index to %s", index_path);
        return;
    }

    /* Write header */
    uint32_t magic = CACHE_INDEX_MAGIC;
    uint32_t version = CACHE_INDEX_VERSION;
    uint32_t count = 0;

    /* Count valid entries */
    for (int i = 0; i < cache_size; i++) {
        if (atomic_load(&cache_entries[i].state) == CACHE_VALID &&
            cache_entries[i].cert_name) {
            count++;
        }
    }

    if (fwrite(&magic, sizeof(magic), 1, fp) != 1 ||
        fwrite(&version, sizeof(version), 1, fp) != 1 ||
        fwrite(&count, sizeof(count), 1, fp) != 1) {
        log_msg(LGG_WARNING, "Failed to write cache index header");
        fclose(fp);
        return;
    }

    /* Write entries */
    int written = 0;
    for (int i = 0; i < cache_size && written < (int)count; i++) {
        cache_entry_t *entry = &cache_entries[i];
        if (atomic_load(&entry->state) == CACHE_VALID && entry->cert_name) {
            uint32_t last_use = atomic_load(&entry->last_use);
            int32_t reuse_count = atomic_load(&entry->reuse_count);

            /* Write cert_name (with length prefix for safety) */
            uint16_t name_len = strlen(entry->cert_name);
            if (fwrite(&name_len, sizeof(name_len), 1, fp) != 1 ||
                fwrite(entry->cert_name, 1, name_len, fp) != (size_t)name_len ||
                fwrite(&last_use, sizeof(last_use), 1, fp) != 1 ||
                fwrite(&reuse_count, sizeof(reuse_count), 1, fp) != 1) {
                log_msg(LGG_WARNING, "Failed to write cache entry: %s", entry->cert_name);
                break;
            }
            written++;
        }
    }

    fclose(fp);
    log_msg(LGG_INFO, "Cache index saved: %d entries", written);
}

/* Load cache index from disk (stub for future implementation) */
void cache_load_from_disk(const char *pem_dir, const void *cachain) {
    (void)cachain;
    if (!pem_dir || !cache_entries) return;

    char index_path[512];
    snprintf(index_path, sizeof(index_path), "%s/.cache_index", pem_dir);

    FILE *fp = fopen(index_path, "rb");
    if (!fp) {
        log_msg(LGG_DEBUG, "No cache index found at %s (first startup)", index_path);
        return;
    }

    /* Read and verify header */
    uint32_t magic, version, count;
    if (fread(&magic, sizeof(magic), 1, fp) != 1 ||
        fread(&version, sizeof(version), 1, fp) != 1 ||
        fread(&count, sizeof(count), 1, fp) != 1) {
        log_msg(LGG_WARNING, "Invalid cache index header");
        fclose(fp);
        return;
    }

    if (magic != CACHE_INDEX_MAGIC || version != CACHE_INDEX_VERSION) {
        log_msg(LGG_WARNING, "Cache index version mismatch (magic=0x%x, version=%u)", magic, version);
        fclose(fp);
        return;
    }

    /* Read entries (cache warmlist for monitoring and future pre-loading)
     * Note: SSL_CTX objects cannot be deserialized due to internal OpenSSL state,
     * but we restore metadata for cache statistics and optimization hints.
     *
     * On first request for a cached domain, the cert will be re-loaded from disk.
     * This is acceptable because:
     * - Worker processes don't persist across restarts anyway
     * - File-system cache will serve cert files from memory on second request
     * - Disk I/O for PEM loading is negligible (~1-5ms per cert)
     */
    int loaded = 0;
    int warmlist = 0;
    char hottest_domain[256] = "";
    int32_t max_reuses = 0;

    for (uint32_t i = 0; i < count; i++) {
        uint16_t name_len;
        char cert_name[256];
        uint32_t last_use;
        int32_t reuse_count;

        if (fread(&name_len, sizeof(name_len), 1, fp) != 1 ||
            name_len >= sizeof(cert_name)) {
            break;
        }

        if (fread(cert_name, 1, name_len, fp) != (size_t)name_len ||
            fread(&last_use, sizeof(last_use), 1, fp) != 1 ||
            fread(&reuse_count, sizeof(reuse_count), 1, fp) != 1) {
            break;
        }

        cert_name[name_len] = '\0';
        loaded++;

        /* Track hottest (most-reused) domain for monitoring */
        if (reuse_count > max_reuses) {
            max_reuses = reuse_count;
            strncpy(hottest_domain, cert_name, sizeof(hottest_domain) - 1);
            hottest_domain[sizeof(hottest_domain) - 1] = '\0';
        }

        /* Log every 100th entry to avoid spam but show progress */
        if (loaded % 100 == 0) {
            log_msg(LGG_DEBUG, "Cache warmlist: %d domains loaded", loaded);
        }

        warmlist++;
    }

    fclose(fp);
    if (loaded > 0) {
        log_msg(LGG_INFO, "Cache index loaded: %d domains (hottest: %s with %d reuses)",
               loaded, hottest_domain[0] ? hottest_domain : "?", max_reuses);
    }
}
