/*
 * cert_index.c - Certificate Index Implementation
 * Sharded directory with binary-indexed lookup for 4-8M certificates
 */

#include "../include/cert_index.h"
#include "../include/util.h"
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

/* CRC32 lookup table */
static uint32_t crc32_table[256];
static int crc32_initialized = 0;

/* Index file magic */
#define CERT_INDEX_MAGIC 0x43494458  /* "CIDX" */
#define CERT_INDEX_VERSION 1

/* Binary index header */
typedef struct {
    uint32_t magic;            /* Magic: "CIDX" */
    uint32_t version;          /* Version 1 */
    uint64_t count;            /* Number of entries */
    uint64_t capacity;         /* Max entries */
    uint64_t timestamp;        /* Last compaction */
} __attribute__((packed)) index_header_t;

/* In-memory index structure */
struct cert_index {
    cert_index_config_t config;

    /* mmap'd index file */
    int index_fd;
    void *index_mmap;
    size_t index_size;

    /* Append-only log */
    int log_fd;
    char log_path[512];

    /* Thread safety for writes */
    pthread_mutex_t write_lock;

    /* Background compaction thread */
    pthread_t compact_thread;
    atomic_bool compact_shutdown;
    int compact_thread_active;

    /* Statistics */
    size_t current_count;
    size_t max_capacity;
};

/* Initialize CRC32 table */
static void crc32_init(void) {
    if (crc32_initialized) return;

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
    crc32_initialized = 1;
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

/* Create index directories */
static int create_shard_dirs(const char *base_dir, const char *ca_name) {
    char dir_path[512];

    for (int shard = 0; shard < 256; shard++) {
        snprintf(dir_path, sizeof(dir_path), "%s/%s/%02x",
                base_dir, ca_name, shard);

        if (mkdir(dir_path, 0755) < 0 && errno != EEXIST) {
            return -1;
        }
    }

    return 0;
}

/* Open or create mmap'd index */
static int index_open_mmap(cert_index_t *idx) {
    char index_path[512];
    snprintf(index_path, sizeof(index_path), "%s/.index_%s",
            idx->config.base_dir, idx->config.ca_name);

    struct stat st;
    if (stat(index_path, &st) < 0) {
        /* Create new index file */
        size_t size = sizeof(index_header_t) +
                      idx->config.max_certs * sizeof(cert_index_entry_t);

        idx->index_fd = open(index_path, O_CREAT | O_RDWR, 0644);
        if (idx->index_fd < 0) return -1;

        /* Sparse file allocation */
        if (ftruncate(idx->index_fd, size) < 0) {
            close(idx->index_fd);
            return -1;
        }

        /* Initialize header */
        index_header_t header = {
            .magic = CERT_INDEX_MAGIC,
            .version = CERT_INDEX_VERSION,
            .count = 0,
            .capacity = idx->config.max_certs,
            .timestamp = time(NULL)
        };

        if (write(idx->index_fd, &header, sizeof(header)) < 0) {
            close(idx->index_fd);
            return -1;
        }

        idx->index_size = size;
    } else {
        idx->index_fd = open(index_path, O_RDWR);
        if (idx->index_fd < 0) return -1;
        idx->index_size = st.st_size;
    }

    /* mmap the index */
    idx->index_mmap = mmap(NULL, idx->index_size, PROT_READ | PROT_WRITE,
                           MAP_SHARED, idx->index_fd, 0);
    if (idx->index_mmap == MAP_FAILED) {
        close(idx->index_fd);
        return -1;
    }

    /* Read current count from header */
    index_header_t *header = (index_header_t *)idx->index_mmap;
    if (header->magic == CERT_INDEX_MAGIC) {
        idx->current_count = header->count;
        idx->max_capacity = header->capacity;
    }

    return 0;
}

/* Create certificate index */
cert_index_t* cert_index_create(const cert_index_config_t *config) {
    if (!config || !config->base_dir || !config->ca_name) {
        return NULL;
    }

    cert_index_t *idx = malloc(sizeof(cert_index_t));
    if (!idx) return NULL;

    memcpy(&idx->config, config, sizeof(*config));
    idx->max_capacity = config->max_certs ? config->max_certs : 2000000;
    idx->current_count = 0;
    idx->index_fd = -1;
    idx->log_fd = -1;
    pthread_mutex_init(&idx->write_lock, NULL);
    atomic_init(&idx->compact_shutdown, false);
    idx->compact_thread_active = 0;

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

    /* Open append-only log */
    snprintf(idx->log_path, sizeof(idx->log_path), "%s/.log_%s",
            config->base_dir, config->ca_name);
    idx->log_fd = open(idx->log_path, O_CREAT | O_APPEND | O_WRONLY, 0644);
    if (idx->log_fd < 0) {
        munmap(idx->index_mmap, idx->index_size);
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

    if (index->index_mmap) {
        msync(index->index_mmap, index->index_size, MS_SYNC);
        munmap(index->index_mmap, index->index_size);
    }
    if (index->index_fd >= 0) close(index->index_fd);
    if (index->log_fd >= 0) close(index->log_fd);

    pthread_mutex_destroy(&index->write_lock);
    free(index);
}

/* Binary search in index */
static int binary_search(const cert_index_entry_t *entries, size_t count,
                        uint32_t domain_hash) {
    if (count == 0) return -1;

    int left = 0, right = count - 1;

    while (left <= right) {
        int mid = left + (right - left) / 2;
        uint32_t mid_hash = ntohl(entries[mid].domain_hash);
        uint32_t search_hash = domain_hash;

        if (mid_hash == search_hash) {
            return mid;
        } else if (mid_hash < search_hash) {
            left = mid + 1;
        } else {
            right = mid - 1;
        }
    }

    return -1;
}

/* Compare function for qsort - sorts by domain_hash */
static int _cert_index_entry_compare(const void *a, const void *b) {
    const cert_index_entry_t *ea = (const cert_index_entry_t *)a;
    const cert_index_entry_t *eb = (const cert_index_entry_t *)b;
    uint32_t ha = ntohl(ea->domain_hash);
    uint32_t hb = ntohl(eb->domain_hash);
    if (ha < hb) return -1;
    if (ha > hb) return 1;
    return 0;
}

/* Lookup certificate by domain hash */
cert_index_error_t cert_index_lookup_hash(const cert_index_t *index,
                                          uint32_t domain_hash,
                                          cert_index_result_t *result) {
    if (!index || !result) return CERT_INDEX_ERR_INVALID;

    memset(result, 0, sizeof(*result));

    index_header_t *header = (index_header_t *)index->index_mmap;
    if (header->magic != CERT_INDEX_MAGIC) {
        return CERT_INDEX_ERR_CORRUPT;
    }

    cert_index_entry_t *entries =
        (cert_index_entry_t *)(header + 1);

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

/* Lookup certificate by domain name */
cert_index_error_t cert_index_lookup(const cert_index_t *index,
                                     const char *domain,
                                     cert_index_result_t *result) {
    if (!domain) return CERT_INDEX_ERR_INVALID;

    uint32_t hash = cert_index_domain_hash(domain);
    return cert_index_lookup_hash(index, hash, result);
}

/* Get filesystem path for certificate */
size_t cert_index_get_path(const cert_index_t *index,
                           uint8_t shard_id,
                           uint32_t cert_id,
                           char *path_buf,
                           size_t path_len) {
    if (!index || !path_buf || path_len < 256) {
        return 0;
    }

    int n = snprintf(path_buf, path_len,
                    "%s/%s/%02x/cert_%06u.pem",
                    index->config.base_dir,
                    index->config.ca_name,
                    shard_id,
                    cert_id);

    return (n > 0 && (size_t)n < path_len) ? n : 0;
}

/* Insert certificate entry */
cert_index_error_t cert_index_insert(cert_index_t *index,
                                     const char *domain,
                                     uint8_t shard_id,
                                     uint32_t cert_id,
                                     uint64_t expiry) {
    if (!index || !domain) return CERT_INDEX_ERR_INVALID;

    pthread_mutex_lock(&index->write_lock);

    cert_index_entry_t entry = {
        .domain_hash = htonl(cert_index_domain_hash(domain)),
        .shard_id = shard_id,
        .cert_id = htonl(cert_id),
        .expiry = htonll(expiry),
        .flags = 0
    };

    /* Append to log */
    if (write(index->log_fd, &entry, sizeof(entry)) < 0) {
        pthread_mutex_unlock(&index->write_lock);
        return CERT_INDEX_ERR_IO;
    }

    fsync(index->log_fd);
    pthread_mutex_unlock(&index->write_lock);

    return CERT_INDEX_OK;
}

/* Delete certificate entry */
cert_index_error_t cert_index_delete(cert_index_t *index,
                                     const char *domain) {
    if (!index || !domain) return CERT_INDEX_ERR_INVALID;

    pthread_mutex_lock(&index->write_lock);

    cert_index_entry_t entry = {
        .domain_hash = htonl(cert_index_domain_hash(domain)),
        .shard_id = 0xFF,  /* Marker for deletion */
        .cert_id = 0,
        .expiry = 0,
        .flags = 0
    };

    if (write(index->log_fd, &entry, sizeof(entry)) < 0) {
        pthread_mutex_unlock(&index->write_lock);
        return CERT_INDEX_ERR_IO;
    }

    fsync(index->log_fd);
    pthread_mutex_unlock(&index->write_lock);

    return CERT_INDEX_OK;
}

/* Background compaction thread function */
static void* compact_thread_func(void *arg) {
    cert_index_t *index = (cert_index_t *)arg;

    /* Compact every 5 minutes to ensure durability on unexpected reboot */
    while (!atomic_load(&index->compact_shutdown)) {
        sleep(300);  /* 5 minutes */

        if (!atomic_load(&index->compact_shutdown)) {
            cert_index_compact(index);
        }
    }

    return NULL;
}

/* Compact append-only log into binary index */
cert_index_error_t cert_index_compact(cert_index_t *index) {
    if (!index) return CERT_INDEX_ERR_INVALID;

    pthread_mutex_lock(&index->write_lock);

    /* Read append-only log and rebuild sorted index */
    FILE *log_file = fopen(index->log_path, "rb");
    if (!log_file) {
        pthread_mutex_unlock(&index->write_lock);
        return CERT_INDEX_ERR_IO;
    }

    /* Count entries in log */
    fseek(log_file, 0, SEEK_END);
    long log_size = ftell(log_file);
    fseek(log_file, 0, SEEK_SET);

    size_t log_entries = log_size / sizeof(cert_index_entry_t);
    if (log_entries > (size_t)index->max_capacity) {
        log_entries = index->max_capacity;
    }

    /* Allocate temporary buffer for sorting */
    cert_index_entry_t *entries = malloc(log_entries * sizeof(cert_index_entry_t));
    if (!entries) {
        fclose(log_file);
        pthread_mutex_unlock(&index->write_lock);
        return CERT_INDEX_ERR_NOMEM;
    }

    /* Read all entries from log */
    size_t read_count = fread(entries, sizeof(cert_index_entry_t), log_entries, log_file);
    fclose(log_file);

    if (read_count != log_entries) {
        free(entries);
        pthread_mutex_unlock(&index->write_lock);
        return CERT_INDEX_ERR_IO;
    }

    /* Sort by domain_hash using qsort O(n log n) */
    if (read_count > 0) {
        qsort(entries, read_count, sizeof(cert_index_entry_t), _cert_index_entry_compare);
    }

    /* Write sorted entries to index file */
    index_header_t header = {
        .magic = CERT_INDEX_MAGIC,
        .version = CERT_INDEX_VERSION,
        .count = read_count,
        .capacity = index->max_capacity,
        .timestamp = time(NULL)
    };

    /* Write to temporary file first (atomic rename) */
    char index_tmp[512];
    snprintf(index_tmp, sizeof(index_tmp), "%s/.index_%s.tmp",
            index->config.base_dir, index->config.ca_name);

    int tmp_fd = open(index_tmp, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (tmp_fd < 0) {
        free(entries);
        pthread_mutex_unlock(&index->write_lock);
        return CERT_INDEX_ERR_IO;
    }

    if (write(tmp_fd, &header, sizeof(header)) < 0 ||
        write(tmp_fd, entries, read_count * sizeof(cert_index_entry_t)) < 0) {
        close(tmp_fd);
        unlink(index_tmp);
        free(entries);
        pthread_mutex_unlock(&index->write_lock);
        return CERT_INDEX_ERR_IO;
    }

    fsync(tmp_fd);
    close(tmp_fd);

    /* Atomically replace old index with new one */
    char index_path[512];
    snprintf(index_path, sizeof(index_path), "%s/.index_%s",
            index->config.base_dir, index->config.ca_name);

    if (rename(index_tmp, index_path) < 0) {
        unlink(index_tmp);
        free(entries);
        pthread_mutex_unlock(&index->write_lock);
        return CERT_INDEX_ERR_IO;
    }

    /* Truncate log (we've compacted it into index) */
    if (ftruncate(index->log_fd, 0) < 0) {
        free(entries);
        pthread_mutex_unlock(&index->write_lock);
        return CERT_INDEX_ERR_IO;
    }

    free(entries);
    pthread_mutex_unlock(&index->write_lock);
    return CERT_INDEX_OK;
}

/* Start background compaction thread */
cert_index_error_t cert_index_start_compact(cert_index_t *index) {
    if (!index || index->compact_thread_active) return CERT_INDEX_ERR_INVALID;

    atomic_store(&index->compact_shutdown, false);

    if (pthread_create(&index->compact_thread, NULL, compact_thread_func, index) != 0) {
        return CERT_INDEX_ERR_IO;
    }

    index->compact_thread_active = 1;
    return CERT_INDEX_OK;
}

/* Stop background compaction thread */
void cert_index_stop_compact(cert_index_t *index) {
    if (!index || !index->compact_thread_active) return;

    atomic_store(&index->compact_shutdown, true);
    pthread_join(index->compact_thread, NULL);
    index->compact_thread_active = 0;
}

/* Rebuild index from existing certificates (first-time initialization) */
cert_index_error_t cert_index_rebuild(cert_index_t *index) {
    if (!index) return CERT_INDEX_ERR_INVALID;

    /* Scan all shards (00-ff directories) and rebuild index from existing certs */
    char shard_dir[PIXELSERV_MAX_PATH];
    DIR *dir;
    struct dirent *entry;
    int total_loaded = 0;

    for (int shard = 0; shard <= 0xFF; shard++) {
        snprintf(shard_dir, sizeof(shard_dir), "%s/%s/%02x",
                index->config.base_dir, index->config.ca_name, shard);

        dir = opendir(shard_dir);
        if (!dir) continue;  /* Shard directory doesn't exist yet */

        while ((entry = readdir(dir)) != NULL) {
            if (entry->d_type != DT_REG) continue;  /* Skip non-files */
            if (strstr(entry->d_name, ".pem") == NULL) continue;  /* Only PEM files */

            char cert_path[PIXELSERV_MAX_PATH + 256];  /* shard_dir + "/" + d_name */
            snprintf(cert_path, sizeof(cert_path), "%s/%s", shard_dir, entry->d_name);

            /* Parse certificate file to extract domain and expiry */
            FILE *fp = fopen(cert_path, "r");
            if (!fp) continue;

            X509 *cert = PEM_read_X509(fp, NULL, NULL, NULL);
            fclose(fp);
            if (!cert) continue;

            /* Extract subject CN (domain name) */
            X509_NAME *subject = X509_get_subject_name(cert);
            char domain[256] = {0};
            X509_NAME_get_text_by_NID(subject, NID_commonName, domain, sizeof(domain) - 1);

            /* Extract expiry (notAfter) as unix timestamp */
            ASN1_TIME *not_after = X509_get_notAfter(cert);
            struct tm tm_info = {0};
            if (not_after && not_after->length >= 12) {
                sscanf((char *)not_after->data, "%04d%02d%02d%02d%02d%02d",
                       &tm_info.tm_year, &tm_info.tm_mon, &tm_info.tm_mday,
                       &tm_info.tm_hour, &tm_info.tm_min, &tm_info.tm_sec);
                tm_info.tm_year -= 1900;  /* Adjust for struct tm */
                tm_info.tm_mon -= 1;      /* Month is 0-11 in struct tm */
            }

            X509_free(cert);

            if (domain[0] == '\0') continue;  /* Skip if no domain found */

            /* Extract cert_id from filename (cert_000001.pem -> 1) */
            uint32_t cert_id = 0;
            if (sscanf(entry->d_name, "cert_%u.pem", &cert_id) != 1) {
                continue;  /* Skip if filename doesn't match expected format */
            }

            /* Get expiry timestamp */
            time_t expiry = mktime(&tm_info);

            /* Insert into index */
            cert_index_error_t result = cert_index_insert(index, domain, (uint8_t)shard, cert_id, expiry);
            if (result == CERT_INDEX_OK) {
                total_loaded++;
            }
        }

        closedir(dir);
    }

    /* Compact the index to consolidate append-only log */
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

    if (count) *count = index->current_count;
    if (capacity) *capacity = index->max_capacity;

    return CERT_INDEX_OK;
}
