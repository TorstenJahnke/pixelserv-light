/*
 * index_client.h - Index Client API for Worker Processes
 */

#ifndef _INDEX_CLIENT_H_
#define _INDEX_CLIENT_H_

#include <stdint.h>
#include <stddef.h>

/* Initialize client connection to index master
 * socket_path: Unix socket path (e.g., /tmp/pixelserv-index.sock)
 * Returns 0 on success, -1 on error
 */
int index_client_init(const char *socket_path);

/* Close client connection */
void index_client_close(void);

/* Lookup certificate in master index
 * Returns 0 if found, -1 if not found or error
 */
int index_client_lookup(const char *domain, uint8_t *shard_id,
                        uint32_t *cert_id, uint64_t *expiry);

/* Insert certificate into master index
 * Returns 0 on success, -1 on error
 */
int index_client_insert(const char *domain, uint8_t shard_id,
                        uint32_t cert_id, uint64_t expiry);

/* Ping master to check connection
 * Returns 0 on success, -1 on error
 */
int index_client_ping(void);

/* Request index rescan from disk
 * Returns 0 on success, count contains number of certs
 */
int index_client_scan(size_t *count);

/* Check if client is connected */
int index_client_is_connected(void);

#endif /* _INDEX_CLIENT_H_ */
