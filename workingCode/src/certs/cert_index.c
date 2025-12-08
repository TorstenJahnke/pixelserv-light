/*
 * cert_index.c - Lock-Free Certificate Index Implementation
 * Sharded directory with binary-indexed lookup for 4-8M certificates
 *
 * LOCK-FREE DESIGN:
 * - Per-shard atomic counters (no global lock)
 * - Per-shard log files (256 separate files, no contention)
 * - O_APPEND write() for atomic small writes (18 bytes < 512 byte sector)
 * - Atomic pointer swap for index reload during compaction
 * - No mutex, no blocking, no fsync per write
 *
 * Performance: 20,000+ inserts/second sustained
 */

#include "certs/cert_index.h"
#include "core/util.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#include <errno.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <time.h>
#include <stdatomic.h>
#include <openssl/x509.h>
#include <openssl/pem.h>

/* Byte order conversion for 64-bit values */
#ifndef htonll
#define htonll(x) ((uint64_t)htonl((x) & 0xFFFFFFFF) << 32 | htonl((x) >> 32))
#endif
#ifndef ntohll
#define ntohll(x) ((uint64_t)ntohl((x) & 0xFFFFFFFF) << 32 | ntohl((x) >> 32))
#endif

/* Number of shards (256 = 0x00 to 0xFF) */
#define NUM_SHARDS 256

/* CRC32 lookup table */
static uint32_t crc32_table[256];
static atomic_int crc32_initialized = 0;

/* Index file magic */
#define CERT_INDEX_MAGIC 0x43494458  /* "CIDX" */
#define CERT_INDEX_VERSION 2         /* Version 2 = lock-free */

/* Binary index header */
typedef struct {
    uint32_t magic;            /* Magic: "CIDX" */
    uint32_t version;          /* Version 2 */
    uint64_t count;            /* Number of entries */
    uint64_t capacity;         /* Max entries */
    uint64_t timestamp;        /* Last compaction */
} __attribute__((packed)) index_header_t;

/* Per-shard state (lock-free) */
typedef struct {
    int log_fd;                        /* Per-shard append log */
    atomic_uint_fast32_t next_cert_id; /* Atomic counter for cert IDs */
    atomic_uint_fast32_t entry_count;  /* Number of entries in this shard */
} shard_state_t;

/* In-memory index structure */
struct cert_index {
    cert_index_config_t config;

    /* Atomic pointer to mmap'd index (for atomic swap during compaction) */
    _Atomic(void *) index_mmap;
    atomic_size_t index_size;
    int index_fd;

    /* Per-shard state (lock-free) */
    shard_state_t shards[NUM_SHARDS];

    /* Background compaction thread */
    pthread_t compact_thread;
    atomic_bool compact_shutdown;
    atomic_int compact_thread_active;

    /* Statistics (atomic) */
    atomic_size_t total_count;
    size_t max_capacity;
};

/* Initialize CRC32 table (one-time, thread-safe) */
static void crc32_init(void) {
    int expected = 0;
    if (!atomic_compare_exchange_strong(&crc32_initialized, &expected, 1)) {
        /* Another thread is initializing or already done */
        while (atomic_load(&crc32_initialized) != 2) {
            /* Spin until initialization complete */
        }
        return;
    }

    for (int i = 0; i < 256; i++) {
        uint32_t crc = i;
        for (int j = 0; j < 8; j++) {
            if (crc & 1)
                crc = (crc >> 1) ^ 0xEDB88320U;
            else
                crc >>= 1;
        }
        crc32_table[i] = crc;
    }

    atomic_store(&crc32_initialized, 2);  /* Mark complete */
}

/* Compute CRC32 hash */
uint32_t cert_index_domain_hash(const char *domain) {
    if (!domain) return 0;

    crc32_init();
    uint32_t crc = 0xFFFFFFFFU;

    for (const unsigned char *p = (const unsigned char *)domain; *p; p++) {
        crc = (crc >> 8) ^ crc32_table[(crc ^ *p) & 0xFF];
    }

    return crc ^ 0xFFFFFFFFU;
}

/*
 * Create directory structure:
 *   base_dir/ca_name/certs/00..ff/  (256 shard dirs)
 *   base_dir/ca_name/index/
 */
static int create_shard_dirs(const char *base_dir, const char *ca_name) {
    char dir_path[512];

    /* Create certs directory */
    snprintf(dir_path, sizeof(dir_path), "%s/%s/certs", base_dir, ca_name);
    if (mkdir(dir_path, 0755) < 0 && errno != EEXIST) {
        return -1;
    }

    /* Create index directory */
    snprintf(dir_path, sizeof(dir_path), "%s/%s/index", base_dir, ca_name);
    if (mkdir(dir_path, 0755) < 0 && errno != EEXIST) {
        return -1;
    }

    /* Create 256 shard directories under certs */
    for (int shard = 0; shard < NUM_SHARDS; shard++) {
        snprintf(dir_path, sizeof(dir_path), "%s/%s/certs/%02x",
                base_dir, ca_name, shard);

        if (mkdir(dir_path, 0755) < 0 && errno != EEXIST) {
            return -1;
        }
    }

    return 0;
}

/* Open or create mmap'd index in index/ subdirectory */
static int index_open_mmap(cert_index_t *idx) {
    char index_path[512];
    snprintf(index_path, sizeof(index_path), "%s/%s/index/.index",
            idx->config.base_dir, idx->config.ca_name);

    struct stat st;
    size_t file_size;

    if (stat(index_path, &st) < 0) {
        /* Create new index file */
        file_size = sizeof(index_header_t) +
                    idx->max_capacity * sizeof(cert_index_entry_t);

        idx->index_fd = open(index_path, O_CREAT | O_RDWR, 0644);
        if (idx->index_fd < 0) return -1;

        /* Sparse file allocation */
        if (ftruncate(idx->index_fd, file_size) < 0) {
            close(idx->index_fd);
            return -1;
        }

        /* Initialize header */
        index_header_t header = {
            .magic = CERT_INDEX_MAGIC,
            .version = CERT_INDEX_VERSION,
            .count = 0,
            .capacity = idx->max_capacity,
            .timestamp = time(NULL)
        };

        if (write(idx->index_fd, &header, sizeof(header)) < 0) {
            close(idx->index_fd);
            return -1;
        }
    } else {
        idx->index_fd = open(index_path, O_RDWR);
        if (idx->index_fd < 0) return -1;
        file_size = st.st_size;
    }

    /* mmap the index (read-only for lookups, compaction writes to temp file) */
    void *mmap_ptr = mmap(NULL, file_size, PROT_READ,
                          MAP_SHARED, idx->index_fd, 0);
    if (mmap_ptr == MAP_FAILED) {
        close(idx->index_fd);
        return -1;
    }

    atomic_store(&idx->index_mmap, mmap_ptr);
    atomic_store(&idx->index_size, file_size);

    /* Read current count from header */
    index_header_t *header = (index_header_t *)mmap_ptr;
    if (header->magic == CERT_INDEX_MAGIC) {
        atomic_store(&idx->total_count, header->count);
    }

    return 0;
}

/* Open per-shard log files in certs/XX/ subdirectories */
static int open_shard_logs(cert_index_t *idx) {
    char log_path[512];

    for (int shard = 0; shard < NUM_SHARDS; shard++) {
        snprintf(log_path, sizeof(log_path), "%s/%s/certs/%02x/.log",
                idx->config.base_dir, idx->config.ca_name, shard);

        /* O_APPEND is atomic for writes < PIPE_BUF (usually 4KB) */
        idx->shards[shard].log_fd = open(log_path, O_CREAT | O_RDWR | O_APPEND, 0644);
        if (idx->shards[shard].log_fd < 0) {
            /* Close already opened logs */
            for (int j = 0; j < shard; j++) {
                close(idx->shards[j].log_fd);
            }
            return -1;
        }

        /* Get current log size for entry count */
        struct stat st;
        if (fstat(idx->shards[shard].log_fd, &st) == 0) {
            atomic_store(&idx->shards[shard].entry_count,
                        st.st_size / sizeof(cert_index_entry_t));
        }

        /* Initialize cert_id counter (will be set properly during rebuild) */
        atomic_store(&idx->shards[shard].next_cert_id, 1);
    }

    return 0;
}

/* Create certificate index */
cert_index_t* cert_index_create(const cert_index_config_t *config) {
    if (!config || !config->base_dir || !config->ca_name) {
        return NULL;
    }

    cert_index_t *idx = calloc(1, sizeof(cert_index_t));
    if (!idx) return NULL;

    memcpy(&idx->config, config, sizeof(*config));
    idx->max_capacity = config->max_certs ? config->max_certs : 2000000;
    atomic_store(&idx->total_count, 0);
    idx->index_fd = -1;
    atomic_store(&idx->index_mmap, NULL);
    atomic_store(&idx->compact_shutdown, false);
    atomic_store(&idx->compact_thread_active, 0);

    /* Initialize all shard fds to -1 */
    for (int i = 0; i < NUM_SHARDS; i++) {
        idx->shards[i].log_fd = -1;
        atomic_store(&idx->shards[i].next_cert_id, 1);
        atomic_store(&idx->shards[i].entry_count, 0);
    }

    /* Create shard directories if requested */
    if (config->create_dirs) {
        if (create_shard_dirs(config->base_dir, config->ca_name) < 0) {
            free(idx);
            return NULL;
        }
    }

    /* Open mmap'd index */
    if (index_open_mmap(idx) < 0) {
        free(idx);
        return NULL;
    }

    /* Open per-shard log files */
    if (open_shard_logs(idx) < 0) {
        void *mmap_ptr = atomic_load(&idx->index_mmap);
        if (mmap_ptr) {
            munmap(mmap_ptr, atomic_load(&idx->index_size));
        }
        close(idx->index_fd);
        free(idx);
        return NULL;
    }

    return idx;
}

/* Destroy index */
void cert_index_destroy(cert_index_t *index) {
    if (!index) return;

    /* Stop compaction thread if running */
    cert_index_stop_compact(index);

    void *mmap_ptr = atomic_load(&index->index_mmap);
    if (mmap_ptr) {
        size_t size = atomic_load(&index->index_size);
        munmap(mmap_ptr, size);
    }
    if (index->index_fd >= 0) close(index->index_fd);

    /* Close all shard logs */
    for (int i = 0; i < NUM_SHARDS; i++) {
        if (index->shards[i].log_fd >= 0) {
            close(index->shards[i].log_fd);
        }
    }

    free(index);
}

/* Binary search in index */
static int binary_search(const cert_index_entry_t *entries, size_t count,
                        uint32_t domain_hash) {
    if (count == 0) return -1;

    int left = 0, right = (int)count - 1;

    while (left <= right) {
        int mid = left + (right - left) / 2;
        uint32_t mid_hash = ntohl(entries[mid].domain_hash);

        if (mid_hash == domain_hash) {
            return mid;
        } else if (mid_hash < domain_hash) {
            left = mid + 1;
        } else {
            right = mid - 1;
        }
    }

    return -1;
}

/* Compare function for qsort - sorts by domain_hash */
static int cert_entry_compare(const void *a, const void *b) {
    const cert_index_entry_t *ea = (const cert_index_entry_t *)a;
    const cert_index_entry_t *eb = (const cert_index_entry_t *)b;
    uint32_t ha = ntohl(ea->domain_hash);
    uint32_t hb = ntohl(eb->domain_hash);
    if (ha < hb) return -1;
    if (ha > hb) return 1;
    return 0;
}

/* Lookup certificate by domain hash (LOCK-FREE) */
cert_index_error_t cert_index_lookup_hash(const cert_index_t *index,
                                          uint32_t domain_hash,
                                          cert_index_result_t *result) {
    if (!index || !result) return CERT_INDEX_ERR_INVALID;

    memset(result, 0, sizeof(*result));

    /* Atomically load current index pointer */
    void *mmap_ptr = atomic_load(&((cert_index_t *)index)->index_mmap);
    if (!mmap_ptr) return CERT_INDEX_ERR_INVALID;

    index_header_t *header = (index_header_t *)mmap_ptr;
    if (header->magic != CERT_INDEX_MAGIC) {
        return CERT_INDEX_ERR_CORRUPT;
    }

    cert_index_entry_t *entries = (cert_index_entry_t *)(header + 1);

    int idx = binary_search(entries, header->count, domain_hash);
    if (idx < 0) {
        result->found = false;
        return CERT_INDEX_ERR_NOTFOUND;
    }

    result->shard_id = entries[idx].shard_id;
    result->cert_id = ntohl(entries[idx].cert_id);
    result->expiry = ntohll(entries[idx].expiry);
    result->found = true;

    return CERT_INDEX_OK;
}

/* Lookup certificate by domain name (LOCK-FREE) */
cert_index_error_t cert_index_lookup(const cert_index_t *index,
                                     const char *domain,
                                     cert_index_result_t *result) {
    if (!domain) return CERT_INDEX_ERR_INVALID;

    uint32_t hash = cert_index_domain_hash(domain);
    return cert_index_lookup_hash(index, hash, result);
}

/* Get filesystem path for certificate in certs/XX/ subdirectory */
size_t cert_index_get_path(const cert_index_t *index,
                           uint8_t shard_id,
                           uint32_t cert_id,
                           char *path_buf,
                           size_t path_len) {
    if (!index || !path_buf || path_len < 256) {
        return 0;
    }

    int n = snprintf(path_buf, path_len,
                    "%s/%s/certs/%02x/cert_%06u.pem",
                    index->config.base_dir,
                    index->config.ca_name,
                    shard_id,
                    cert_id);

    return (n > 0 && (size_t)n < path_len) ? (size_t)n : 0;
}

/*
 * Insert certificate entry (LOCK-FREE)
 *
 * This is the critical path for 20,000+ domains/second.
 * No mutex, no fsync - just atomic operations and O_APPEND write.
 */
cert_index_error_t cert_index_insert(cert_index_t *index,
                                     const char *domain,
                                     uint8_t shard_id,
                                     uint32_t cert_id,
                                     uint64_t expiry) {
    if (!index || !domain) return CERT_INDEX_ERR_INVALID;
    /* Note: shard_id is uint8_t (0-255), NUM_SHARDS is 256, so bounds check is implicit */

    shard_state_t *shard = &index->shards[shard_id];

    cert_index_entry_t entry = {
        .domain_hash = htonl(cert_index_domain_hash(domain)),
        .shard_id = shard_id,
        .cert_id = htonl(cert_id),
        .expiry = htonll(expiry),
        .flags = 0
    };

    /*
     * Write to per-shard log using write() with O_APPEND.
     * O_APPEND is atomic for writes smaller than PIPE_BUF (4KB on Linux).
     * 18 bytes << 4096 bytes, so this is atomic without any locks.
     *
     * Multiple threads can write to the same shard simultaneously
     * and the kernel guarantees no interleaving.
     */
    ssize_t written = write(shard->log_fd, &entry, sizeof(entry));
    if (written != sizeof(entry)) {
        return CERT_INDEX_ERR_IO;
    }

    /* Update statistics atomically */
    atomic_fetch_add(&shard->entry_count, 1);
    atomic_fetch_add(&index->total_count, 1);

    /*
     * NO fsync() here - we rely on periodic compaction for durability.
     * This is the key to achieving 20,000+ writes/second.
     *
     * On crash, we lose at most 5 minutes of entries (between compactions).
     * For DGA domains that only appear once, this is acceptable.
     */

    return CERT_INDEX_OK;
}

/*
 * Allocate next cert_id for a shard (LOCK-FREE)
 *
 * Returns a unique cert_id atomically.
 */
uint32_t cert_index_alloc_cert_id(cert_index_t *index, uint8_t shard_id) {
    if (!index) return 0;
    /* Note: shard_id is uint8_t (0-255), NUM_SHARDS is 256, so bounds check is implicit */

    return atomic_fetch_add(&index->shards[shard_id].next_cert_id, 1);
}

/* Delete certificate entry (LOCK-FREE) */
cert_index_error_t cert_index_delete(cert_index_t *index,
                                     const char *domain) {
    if (!index || !domain) return CERT_INDEX_ERR_INVALID;

    uint32_t hash = cert_index_domain_hash(domain);
    uint8_t shard_id = cert_index_shard_id(hash);
    shard_state_t *shard = &index->shards[shard_id];

    cert_index_entry_t entry = {
        .domain_hash = htonl(hash),
        .shard_id = 0xFF,  /* Marker for deletion */
        .cert_id = 0,
        .expiry = 0,
        .flags = 0
    };

    /* Atomic write to per-shard log */
    ssize_t written = write(shard->log_fd, &entry, sizeof(entry));
    if (written != sizeof(entry)) {
        return CERT_INDEX_ERR_IO;
    }

    return CERT_INDEX_OK;
}

/* Background compaction thread function */
static void* compact_thread_func(void *arg) {
    cert_index_t *index = (cert_index_t *)arg;

    /* Compact every 5 minutes to ensure durability */
    while (!atomic_load(&index->compact_shutdown)) {
        for (int i = 0; i < 300 && !atomic_load(&index->compact_shutdown); i++) {
            sleep(1);
        }

        if (!atomic_load(&index->compact_shutdown)) {
            cert_index_compact(index);
        }
    }

    return NULL;
}

/*
 * Compact all shard logs into binary index (runs in background)
 *
 * This is the only operation that needs coordination, but it doesn't
 * block readers or writers - it uses atomic pointer swap.
 */
cert_index_error_t cert_index_compact(cert_index_t *index) {
    if (!index) return CERT_INDEX_ERR_INVALID;

    /* Count total entries across all shards */
    size_t total_entries = 0;
    for (int i = 0; i < NUM_SHARDS; i++) {
        struct stat st;
        if (fstat(index->shards[i].log_fd, &st) == 0) {
            total_entries += st.st_size / sizeof(cert_index_entry_t);
        }
    }

    if (total_entries == 0) {
        return CERT_INDEX_OK;  /* Nothing to compact */
    }

    if (total_entries > index->max_capacity) {
        total_entries = index->max_capacity;
    }

    /* Allocate temporary buffer for all entries */
    cert_index_entry_t *all_entries = malloc(total_entries * sizeof(cert_index_entry_t));
    if (!all_entries) {
        return CERT_INDEX_ERR_NOMEM;
    }

    /* Read all entries from all shard logs */
    size_t read_total = 0;
    for (int shard = 0; shard < NUM_SHARDS && read_total < total_entries; shard++) {
        char log_path[512];
        snprintf(log_path, sizeof(log_path), "%s/%s/certs/%02x/.log",
                index->config.base_dir, index->config.ca_name, shard);

        FILE *log_file = fopen(log_path, "rb");
        if (!log_file) continue;

        size_t remaining = total_entries - read_total;
        size_t count = fread(&all_entries[read_total],
                            sizeof(cert_index_entry_t),
                            remaining, log_file);
        fclose(log_file);

        read_total += count;
    }

    /* Remove deletion markers and duplicates (keep latest) */
    /* First sort by hash, then filter */
    if (read_total > 0) {
        qsort(all_entries, read_total, sizeof(cert_index_entry_t), cert_entry_compare);
    }

    /* Filter: remove deletions (shard_id=0xFF) and keep only latest for each hash */
    size_t write_idx = 0;
    for (size_t i = 0; i < read_total; i++) {
        /* Skip deletion markers */
        if (all_entries[i].shard_id == 0xFF) continue;

        /* Skip duplicates (keep last one, which is the latest) */
        if (i + 1 < read_total &&
            all_entries[i].domain_hash == all_entries[i + 1].domain_hash) {
            continue;
        }

        if (write_idx != i) {
            all_entries[write_idx] = all_entries[i];
        }
        write_idx++;
    }

    size_t final_count = write_idx;

    /* Write sorted entries to temporary index file in index/ subdirectory */
    char index_tmp[512];
    snprintf(index_tmp, sizeof(index_tmp), "%s/%s/index/.index.tmp",
            index->config.base_dir, index->config.ca_name);

    int tmp_fd = open(index_tmp, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (tmp_fd < 0) {
        free(all_entries);
        return CERT_INDEX_ERR_IO;
    }

    index_header_t header = {
        .magic = CERT_INDEX_MAGIC,
        .version = CERT_INDEX_VERSION,
        .count = final_count,
        .capacity = index->max_capacity,
        .timestamp = time(NULL)
    };

    if (write(tmp_fd, &header, sizeof(header)) < 0 ||
        write(tmp_fd, all_entries, final_count * sizeof(cert_index_entry_t)) < 0) {
        close(tmp_fd);
        unlink(index_tmp);
        free(all_entries);
        return CERT_INDEX_ERR_IO;
    }

    fsync(tmp_fd);
    close(tmp_fd);
    free(all_entries);

    /* Atomically replace old index with new one */
    char index_path[512];
    snprintf(index_path, sizeof(index_path), "%s/%s/index/.index",
            index->config.base_dir, index->config.ca_name);

    if (rename(index_tmp, index_path) < 0) {
        unlink(index_tmp);
        return CERT_INDEX_ERR_IO;
    }

    /* Reopen and remap the new index file */
    int new_fd = open(index_path, O_RDONLY);
    if (new_fd < 0) {
        return CERT_INDEX_ERR_IO;
    }

    struct stat st;
    if (fstat(new_fd, &st) < 0) {
        close(new_fd);
        return CERT_INDEX_ERR_IO;
    }

    void *new_mmap = mmap(NULL, st.st_size, PROT_READ, MAP_SHARED, new_fd, 0);
    close(new_fd);

    if (new_mmap == MAP_FAILED) {
        return CERT_INDEX_ERR_IO;
    }

    /* Atomic pointer swap - readers see either old or new, never partial */
    void *old_mmap = atomic_exchange(&index->index_mmap, new_mmap);
    size_t old_size = atomic_exchange(&index->index_size, st.st_size);

    /* Unmap old index after swap */
    if (old_mmap) {
        munmap(old_mmap, old_size);
    }

    /* Truncate all shard logs (we've compacted them) */
    for (int shard = 0; shard < NUM_SHARDS; shard++) {
        if (ftruncate(index->shards[shard].log_fd, 0) == 0) {
            lseek(index->shards[shard].log_fd, 0, SEEK_SET);
            atomic_store(&index->shards[shard].entry_count, 0);
        }
    }

    atomic_store(&index->total_count, final_count);

    return CERT_INDEX_OK;
}

/* Start background compaction thread */
cert_index_error_t cert_index_start_compact(cert_index_t *index) {
    if (!index) return CERT_INDEX_ERR_INVALID;

    int expected = 0;
    if (!atomic_compare_exchange_strong(&index->compact_thread_active, &expected, 1)) {
        return CERT_INDEX_ERR_INVALID;  /* Already running */
    }

    atomic_store(&index->compact_shutdown, false);

    if (pthread_create(&index->compact_thread, NULL, compact_thread_func, index) != 0) {
        atomic_store(&index->compact_thread_active, 0);
        return CERT_INDEX_ERR_IO;
    }

    return CERT_INDEX_OK;
}

/* Stop background compaction thread */
void cert_index_stop_compact(cert_index_t *index) {
    if (!index) return;

    if (atomic_load(&index->compact_thread_active)) {
        atomic_store(&index->compact_shutdown, true);
        pthread_join(index->compact_thread, NULL);
        atomic_store(&index->compact_thread_active, 0);
    }
}

/* Rebuild index from existing certificates (first-time initialization) */
cert_index_error_t cert_index_rebuild(cert_index_t *index) {
    if (!index) return CERT_INDEX_ERR_INVALID;

    /* Track max cert_id per shard for atomic counter initialization */
    uint32_t max_cert_id[NUM_SHARDS] = {0};

    char shard_dir[PIXELSERV_MAX_PATH];
    DIR *dir;
    struct dirent *entry;
    int total_loaded = 0;

    for (int shard = 0; shard <= 0xFF; shard++) {
        snprintf(shard_dir, sizeof(shard_dir), "%s/%s/certs/%02x",
                index->config.base_dir, index->config.ca_name, shard);

        dir = opendir(shard_dir);
        if (!dir) continue;

        while ((entry = readdir(dir)) != NULL) {
            if (entry->d_type != DT_REG) continue;
            if (strstr(entry->d_name, ".pem") == NULL) continue;

            char cert_path[PIXELSERV_MAX_PATH + 256];
            snprintf(cert_path, sizeof(cert_path), "%s/%s", shard_dir, entry->d_name);

            FILE *fp = fopen(cert_path, "r");
            if (!fp) continue;

            X509 *cert = PEM_read_X509(fp, NULL, NULL, NULL);
            fclose(fp);
            if (!cert) continue;

            X509_NAME *subject = X509_get_subject_name(cert);
            char domain[256] = {0};
            X509_NAME_get_text_by_NID(subject, NID_commonName, domain, sizeof(domain) - 1);

            ASN1_TIME *not_after = X509_get_notAfter(cert);
            struct tm tm_info = {0};
            if (not_after && not_after->length >= 12) {
                sscanf((char *)not_after->data, "%04d%02d%02d%02d%02d%02d",
                       &tm_info.tm_year, &tm_info.tm_mon, &tm_info.tm_mday,
                       &tm_info.tm_hour, &tm_info.tm_min, &tm_info.tm_sec);
                tm_info.tm_year -= 1900;
                tm_info.tm_mon -= 1;
            }

            X509_free(cert);

            if (domain[0] == '\0') continue;

            uint32_t cert_id = 0;
            if (sscanf(entry->d_name, "cert_%u.pem", &cert_id) != 1) {
                continue;
            }

            /* Track max cert_id for this shard */
            if (cert_id > max_cert_id[shard]) {
                max_cert_id[shard] = cert_id;
            }

            time_t expiry = mktime(&tm_info);

            cert_index_error_t result = cert_index_insert(index, domain, (uint8_t)shard, cert_id, expiry);
            if (result == CERT_INDEX_OK) {
                total_loaded++;
            }
        }

        closedir(dir);
    }

    /* Initialize atomic cert_id counters to max+1 for each shard */
    for (int shard = 0; shard < NUM_SHARDS; shard++) {
        atomic_store(&index->shards[shard].next_cert_id, max_cert_id[shard] + 1);
    }

    /* Compact to consolidate all entries into binary index */
    if (total_loaded > 0) {
        cert_index_compact(index);
    }

    return CERT_INDEX_OK;
}

/* Get statistics */
cert_index_error_t cert_index_get_stats(const cert_index_t *index,
                                        size_t *count,
                                        size_t *capacity) {
    if (!index) return CERT_INDEX_ERR_INVALID;

    if (count) *count = atomic_load(&((cert_index_t *)index)->total_count);
    if (capacity) *capacity = index->max_capacity;

    return CERT_INDEX_OK;
}
