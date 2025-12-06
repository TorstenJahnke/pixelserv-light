/*
 * certs_conn.h - Lock-free connection storage
 */

#ifndef _CERTS_CONN_H_
#define _CERTS_CONN_H_

#include "certs_atomic.h"
#include "certs.h"

/* Initialize connection storage with given capacity */
void conn_stor_init_lockfree(int slots);

/* Acquire a connection structure (lock-free pop) */
conn_tlstor_struct *conn_stor_acquire_lockfree(void);

/* Release a connection structure (lock-free push) */
void conn_stor_relinq_lockfree(conn_tlstor_struct *p);

/* Flush excess connections (lock-free) */
void conn_stor_flush_lockfree(void);

/* Cleanup all connections */
void conn_stor_cleanup_lockfree(void);

#endif /* _CERTS_CONN_H_ */
