/*
 * certs_cache.h - Lock-free SSL context cache
 */

#ifndef _CERTS_CACHE_H_
#define _CERTS_CACHE_H_

#include <openssl/ssl.h>
#include "certs/certs_atomic.h"

/* Cache entry states */
typedef enum {
    CACHE_EMPTY = 0,
    CACHE_INSERTING,
    CACHE_VALID,
    CACHE_EXPIRED
} cache_state_t;

/* Lock-free cache entry */
typedef struct {
    _Atomic int state;              /* cache_state_t */
    _Atomic uint32_t last_use;      /* Timestamp of last use */
    _Atomic uint32_t expired_at;    /* Timestamp when entry was expired (for grace period) */
    _Atomic int reuse_count;        /* Number of reuses */
    int alloc_len;                  /* Allocated name length */
    char *cert_name;                /* Certificate name (domain) */
    SSL_CTX *sslctx;                /* SSL context (read-only after insert) */
} cache_entry_t;

/* Grace period in seconds before reclaiming expired entries (prevents use-after-free) */
#define CACHE_RECLAIM_GRACE_SECONDS 60

/* Initialize the cache with given size */
void cache_init(int size);

/* Cleanup the cache */
void cache_cleanup(void);

/* Lookup a certificate by name (lock-free) */
SSL_CTX *cache_lookup(const char *cert_name);

/* Insert a new entry (lock-free with CAS) */
int cache_insert(const char *cert_name, SSL_CTX *sslctx);

/* Get cache statistics */
int cache_get_size(void);
int cache_get_used(void);

/* Load existing certificates from disk into cache */
void cache_load_from_disk(const char *pem_dir, const void *cachain);

/* Save cache index to disk */
void cache_save_index(const char *pem_dir);

/* Expire old entries (marks them for later reclamation) */
void cache_expire_old(uint32_t max_age_seconds);

/* Reclaim expired entries after grace period (frees memory, clears hash table) */
void cache_reclaim_expired(void);

#endif /* _CERTS_CACHE_H_ */
