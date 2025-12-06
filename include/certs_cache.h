/*
 * certs_cache.h - Lock-free SSL context cache
 */

#ifndef _CERTS_CACHE_H_
#define _CERTS_CACHE_H_

#include <openssl/ssl.h>
#include "certs_atomic.h"

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
    _Atomic int reuse_count;        /* Number of reuses */
    int alloc_len;                  /* Allocated name length */
    char *cert_name;                /* Certificate name (domain) */
    SSL_CTX *sslctx;                /* SSL context (read-only after insert) */
} cache_entry_t;

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

/* Touch entry (update last_use timestamp) */
void cache_touch(int idx);

/* Load existing certificates from disk into cache */
void cache_load_from_disk(const char *pem_dir, const void *cachain);

/* Save cache index to disk */
void cache_save_index(const char *pem_dir);

/* Expire old entries */
void cache_expire_old(uint32_t max_age_seconds);

#endif /* _CERTS_CACHE_H_ */
