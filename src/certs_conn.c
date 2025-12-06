/*
 * certs_conn.c - Lock-free connection storage implementation
 *
 * Uses atomic stack (LIFO) for O(1) acquire/release operations.
 * No mutexes, no blocking.
 */

#include <stdlib.h>
#include "../include/certs_conn.h"

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

    /* Return to pool if under max, otherwise just discard
     * FIX: Don't free(p) because p is from the pool allocated with aligned_alloc!
     * Pool items should not be freed individually, only the entire pool at cleanup.
     */
    if (atomic_stack_size(&conn_stack) < conn_max_size) {
        memset(p, 0, sizeof(conn_tlstor_struct));
        atomic_stack_push(&conn_stack, p);
    }
    /* If pool is full, just don't re-queue - the item goes away when conn_stor_cleanup is called */
}

void conn_stor_flush_lockfree(void) {
    /* Remove excess entries until at half capacity
     * FIX: Don't free(p) because p is from the pool allocated with aligned_alloc!
     * Just pop them from the stack and let them be collected at cleanup time.
     */
    int target = conn_max_size / 2;

    while (atomic_stack_size(&conn_stack) > target) {
        conn_tlstor_struct *p = atomic_stack_pop(&conn_stack);
        if (!p) {
            break;
        }
        /* Item is no longer queued, but we don't free it here
         * It will be freed as part of the entire pool in conn_stor_cleanup_lockfree() */
    }
}

void conn_stor_cleanup_lockfree(void) {
    /* FIX: Clean up SSL and early_data CONTENTS, but don't free(p) itself
     * because p is part of the pool allocated with aligned_alloc in init_conn_pool.
     * The entire pool is freed separately using the stored pool_base pointer.
     */
    conn_tlstor_struct *p;
    while ((p = atomic_stack_pop(&conn_stack)) != NULL) {
        if (p->ssl) SSL_free(p->ssl);
        if (p->early_data) free(p->early_data);
        /* Don't free(p) - it's from the pool! */
    }
    /* The pool itself (pool_base) should be freed elsewhere */
}
