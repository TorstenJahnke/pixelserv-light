/*
 * index_master.h - Index Master Server API
 */

#ifndef _INDEX_MASTER_H_
#define _INDEX_MASTER_H_

/* Initialize the index master server
 * socket_path: Unix socket path (e.g., /tmp/pixelserv-index.sock)
 * pem_dir: Certificate directory to scan
 * Returns 0 on success, -1 on error
 */
int index_master_init(const char *socket_path, const char *pem_dir);

/* Run the index master event loop (blocking) */
void index_master_run(void);

/* Shutdown the index master */
void index_master_shutdown(void);

/* Get statistics */
void index_master_get_stats(long *lookups, long *hits, long *misses, long *inserts);

#endif /* _INDEX_MASTER_H_ */
