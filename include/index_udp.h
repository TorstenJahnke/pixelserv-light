/*
 * index_udp.h - UDP Write Queue for Certificate Index
 *
 * High-performance asynchronous index updates via UDP.
 * Workers send fire-and-forget UDP datagrams to the master process.
 * Master batches and commits updates, achieving 100K+ updates/sec.
 *
 * Architecture:
 *   [Worker 1] --+
 *   [Worker 2] --+--> UDP Socket --> [Master Write Queue] --> [Index]
 *   [Worker N] --+
 *
 * Benefits:
 *   - Zero worker blocking (fire-and-forget)
 *   - Automatic batching in master
 *   - Lock-free from worker perspective
 *   - Survives worker crashes (UDP)
 */

#ifndef INDEX_UDP_H
#define INDEX_UDP_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/* cert_algo_t values (must match certs.h) */
#define CERT_ALG_RSA    0
#define CERT_ALG_ECDSA  1
#define CERT_ALG_SM2    2
#define CERT_ALG_LEGACY 3

/* UDP Port (configurable) */
#define INDEX_UDP_DEFAULT_PORT 19847

/* Protocol magic and version */
#define INDEX_UDP_MAGIC   0x49445855  /* "UDXI" */
#define INDEX_UDP_VERSION 1

/* Message types */
typedef enum {
    IDX_MSG_INSERT = 1,    /* Insert/update certificate */
    IDX_MSG_REMOVE = 2,    /* Remove certificate */
    IDX_MSG_BATCH  = 3,    /* Batch of operations */
    IDX_MSG_SYNC   = 4,    /* Request sync (flush pending writes) */
    IDX_MSG_PING   = 5,    /* Health check */
    IDX_MSG_PONG   = 6,    /* Health check response */
    IDX_MSG_STATS  = 7     /* Statistics request */
} index_udp_msg_type_t;

/*
 * UDP Message Header (8 bytes)
 */
typedef struct {
    uint32_t magic;        /* INDEX_UDP_MAGIC */
    uint8_t  version;      /* Protocol version */
    uint8_t  msg_type;     /* index_udp_msg_type_t */
    uint16_t payload_len;  /* Payload length */
} __attribute__((packed)) index_udp_header_t;

/*
 * Insert/Remove Payload (variable length)
 * Total: 20 bytes + domain_len
 */
typedef struct {
    uint32_t composite_hash;   /* Pre-computed hash */
    uint32_t cert_id;          /* Certificate ID */
    uint64_t expiry;           /* Expiration timestamp */
    uint8_t  algo;             /* cert_algo_t */
    uint8_t  domain_len;       /* Length of domain name */
    uint16_t reserved;
    /* char domain[domain_len] follows */
} __attribute__((packed)) index_udp_insert_t;

/*
 * Batch Payload Header
 */
typedef struct {
    uint16_t count;        /* Number of operations */
    uint16_t reserved;
    /* Operations follow */
} __attribute__((packed)) index_udp_batch_t;

/*
 * Statistics Payload
 */
typedef struct {
    uint64_t entries;      /* Total entries */
    uint64_t capacity;     /* Maximum capacity */
    uint64_t inserts;      /* Total inserts processed */
    uint64_t removes;      /* Total removes processed */
    uint64_t queue_depth;  /* Current queue depth */
    uint64_t queue_drops;  /* Dropped messages (queue full) */
} __attribute__((packed)) index_udp_stats_t;

/* Maximum UDP payload */
#define INDEX_UDP_MAX_PAYLOAD 1400  /* Safe for MTU */
#define INDEX_UDP_MAX_DOMAIN  253   /* DNS max */

/* ==========================================================================
 * Client API (Workers)
 * ========================================================================== */

/**
 * Initialize UDP client
 *
 * @param host  Master host (NULL for localhost)
 * @param port  Master port (0 for default)
 * @return 0 on success, -1 on error
 */
int index_udp_client_init(const char *host, uint16_t port);

/**
 * Shutdown UDP client
 */
void index_udp_client_shutdown(void);

/**
 * Send insert request (fire-and-forget)
 *
 * Non-blocking, returns immediately.
 * Uses pre-computed hash for zero client-side CPU.
 *
 * @param domain  Domain name
 * @param algo    Algorithm
 * @param cert_id Certificate ID
 * @param expiry  Expiration timestamp
 * @return 0 on success (send queued), -1 on error
 */
int index_udp_client_insert(const char *domain,
                            int algo,
                            uint32_t cert_id,
                            uint64_t expiry);

/**
 * Send remove request (fire-and-forget)
 *
 * @param domain  Domain name
 * @param algo    Algorithm (CERT_ALG_RSA, etc.)
 * @return 0 on success, -1 on error
 */
int index_udp_client_remove(const char *domain, int algo);

/**
 * Request sync (flush pending writes)
 *
 * Blocking call - waits for acknowledgment from master.
 *
 * @param timeout_ms  Timeout in milliseconds (0 = no wait)
 * @return 0 on success, -1 on timeout/error
 */
int index_udp_client_sync(int timeout_ms);

/**
 * Ping master (health check)
 *
 * @param timeout_ms  Timeout in milliseconds
 * @return Latency in microseconds, -1 on error
 */
int64_t index_udp_client_ping(int timeout_ms);

/* ==========================================================================
 * Server API (Master Process)
 * ========================================================================== */

/**
 * Server configuration
 */
typedef struct {
    uint16_t port;              /* UDP port (0 for default) */
    const char *bind_addr;      /* Bind address (NULL for any) */
    void *index;                /* Index handle for writes (cert_index_t*) */
    size_t batch_size;          /* Batch size before commit (default: 100) */
    int batch_timeout_ms;       /* Max wait time for batch (default: 50ms) */
    size_t queue_size;          /* Internal queue size (default: 10000) */
} index_udp_server_config_t;

/**
 * Initialize UDP server
 *
 * Starts background thread for processing incoming updates.
 *
 * @param config  Server configuration
 * @return 0 on success, -1 on error
 */
int index_udp_server_init(const index_udp_server_config_t *config);

/**
 * Shutdown UDP server
 *
 * Flushes pending writes before shutdown.
 */
void index_udp_server_shutdown(void);

/**
 * Get server statistics
 *
 * @param stats  Output statistics
 * @return 0 on success, -1 on error
 */
int index_udp_server_stats(index_udp_stats_t *stats);

/**
 * Force flush of pending writes
 *
 * @return Number of entries flushed
 */
size_t index_udp_server_flush(void);

/**
 * Set index operation callbacks
 *
 * Must be called before index_udp_server_init().
 * Allows server to work with any index implementation.
 *
 * @param insert_fn  Insert callback (idx, domain, algo, cert_id, expiry)
 * @param remove_fn  Remove callback (idx, domain, algo)
 */
void index_udp_set_callbacks(
    int (*insert_fn)(void *idx, const char *domain, int algo, uint32_t cert_id, uint64_t expiry),
    int (*remove_fn)(void *idx, const char *domain, int algo));

#endif /* INDEX_UDP_H */
