/*
 * certs_conn.c - Lock-free connection storage implementation
 *
 * Uses atomic stack (LIFO) for O(1) acquire/release operations.
 * No mutexes, no blocking.
 */

#include <stdlib.h>
#include <string.h>
#include "certs/certs_conn.h"

/* Lock-free stack for connection storage */
static atomic_stack_t conn_stack;
static int conn_max_size;

void conn_stor_init_lockfree(int slots) {
    if (slots < 0) return;

    atomic_stack_init(&conn_stack);
    conn_max_size = slots;

    /* Pre-allocate connection structures */
    for (int i = 0; i < slots; i++) {
        conn_tlstor_struct *p = calloc(1, sizeof(conn_tlstor_struct));
        if (p) {
            atomic_stack_push(&conn_stack, p);
        }
    }
}

conn_tlstor_struct *conn_stor_acquire_lockfree(void) {
    conn_tlstor_struct *p = atomic_stack_pop(&conn_stack);

    if (!p) {
        /* Stack empty, allocate new */
        p = calloc(1, sizeof(conn_tlstor_struct));
    }

    return p;
}

void conn_stor_relinq_lockfree(conn_tlstor_struct *p) {
    if (!p) return;

    /* Reset the structure for reuse */
    if (p->ssl) {
        SSL_free(p->ssl);
        p->ssl = NULL;
    }
    if (p->early_data) {
        free(p->early_data);
        p->early_data = NULL;
    }

    /* Note: Don't free(p) here - the connection structure is managed
     * by pixelserv.c's connection pool (acquire_connection/release_connection).
     * We only clean up SSL and early_data resources here.
     */
}

void conn_stor_flush_lockfree(void) {
    /* Remove excess entries until at half capacity */
    int target = conn_max_size / 2;

    while (atomic_stack_size(&conn_stack) > target) {
        conn_tlstor_struct *p = atomic_stack_pop(&conn_stack);
        if (!p) {
            break;
        }
        if (p->ssl) SSL_free(p->ssl);
        if (p->early_data) free(p->early_data);
        free(p);
    }
}

void conn_stor_cleanup_lockfree(void) {
    conn_tlstor_struct *p;
    while ((p = atomic_stack_pop(&conn_stack)) != NULL) {
        if (p->ssl) SSL_free(p->ssl);
        if (p->early_data) free(p->early_data);
        free(p);
    }
}
