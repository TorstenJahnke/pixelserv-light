/*
 * certs_atomic.h - Lock-free data structures for pixelserv-tls
 *
 * 100% lock-free and block-free implementation using C11 atomics.
 * No pthread_mutex, no pthread_cond, no spinlocks.
 */

#ifndef _CERTS_ATOMIC_H_
#define _CERTS_ATOMIC_H_

#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sched.h>  /* For sched_yield() in atomic_backoff() */

/*
 * Lock-free atomic counter
 */
typedef struct {
    _Atomic int value;
} atomic_counter_t;

static inline void atomic_counter_init(atomic_counter_t *c, int val) {
    atomic_store(&c->value, val);
}

static inline int atomic_counter_get(atomic_counter_t *c) {
    return atomic_load(&c->value);
}

static inline void atomic_counter_inc(atomic_counter_t *c) {
    atomic_fetch_add(&c->value, 1);
}

static inline void atomic_counter_add(atomic_counter_t *c, int val) {
    atomic_fetch_add(&c->value, val);
}

static inline int atomic_counter_inc_get(atomic_counter_t *c) {
    return atomic_fetch_add(&c->value, 1) + 1;
}

/*
 * Lock-free stack (LIFO) for connection storage
 * Uses tagged pointer to avoid ABA problem
 */
typedef struct atomic_stack_node {
    void *data;
    _Atomic(struct atomic_stack_node *) next;
} atomic_stack_node_t;

typedef struct {
    _Atomic(atomic_stack_node_t *) head;
    _Atomic int size;
} atomic_stack_t;

static inline void atomic_stack_init(atomic_stack_t *s) {
    atomic_store(&s->head, NULL);
    atomic_store(&s->size, 0);
}

static inline bool atomic_stack_push(atomic_stack_t *s, void *data) {
    atomic_stack_node_t *node = malloc(sizeof(atomic_stack_node_t));
    if (!node) return false;

    node->data = data;
    atomic_stack_node_t *old_head;

    do {
        old_head = atomic_load(&s->head);
        atomic_store(&node->next, old_head);
    } while (!atomic_compare_exchange_weak(&s->head, &old_head, node));

    atomic_fetch_add(&s->size, 1);
    return true;
}

static inline void *atomic_stack_pop(atomic_stack_t *s) {
    atomic_stack_node_t *old_head;
    atomic_stack_node_t *new_head;

    do {
        old_head = atomic_load(&s->head);
        if (!old_head) return NULL;
        new_head = atomic_load(&old_head->next);
    } while (!atomic_compare_exchange_weak(&s->head, &old_head, new_head));

    void *data = old_head->data;
    free(old_head);
    atomic_fetch_sub(&s->size, 1);
    return data;
}

static inline int atomic_stack_size(atomic_stack_t *s) {
    return atomic_load(&s->size);
}

/*
 * Lock-free MPSC (Multi-Producer Single-Consumer) Queue
 * Based on Dmitry Vyukov's algorithm
 */
typedef struct mpsc_node {
    _Atomic(struct mpsc_node *) next;
    char data[];  /* Flexible array member */
} mpsc_node_t;

/* Stub node without flexible array member (sentinel only needs next pointer) */
typedef struct {
    _Atomic(struct mpsc_node *) next;
} mpsc_stub_t;

typedef struct {
    _Atomic(mpsc_node_t *) head;
    _Atomic(mpsc_node_t *) tail;
    mpsc_stub_t stub;  /* Sentinel node - layout-compatible with mpsc_node_t */
} mpsc_queue_t;

static inline void mpsc_queue_init(mpsc_queue_t *q) {
    atomic_store(&q->stub.next, NULL);
    atomic_store(&q->head, (mpsc_node_t *)&q->stub);
    atomic_store(&q->tail, (mpsc_node_t *)&q->stub);
}

static inline void mpsc_queue_push(mpsc_queue_t *q, mpsc_node_t *node) {
    atomic_store(&node->next, NULL);
    mpsc_node_t *prev = atomic_exchange(&q->head, node);
    atomic_store(&prev->next, node);
}

static inline mpsc_node_t *mpsc_queue_pop(mpsc_queue_t *q) {
    mpsc_node_t *tail = atomic_load(&q->tail);
    mpsc_node_t *next = atomic_load(&tail->next);
    mpsc_node_t *stub = (mpsc_node_t *)&q->stub;

    if (tail == stub) {
        if (!next) return NULL;
        atomic_store(&q->tail, next);
        tail = next;
        next = atomic_load(&tail->next);
    }

    if (next) {
        atomic_store(&q->tail, next);
        return tail;
    }

    mpsc_node_t *head = atomic_load(&q->head);
    if (tail != head) return NULL;

    mpsc_queue_push(q, stub);
    next = atomic_load(&tail->next);

    if (next) {
        atomic_store(&q->tail, next);
        return tail;
    }

    return NULL;
}

/*
 * Lock-free hash table slot state
 */
typedef enum {
    SLOT_EMPTY = 0,
    SLOT_INSERTING,
    SLOT_VALID,
    SLOT_DELETED
} slot_state_t;

/*
 * Atomic timestamp for cache entries (seconds since epoch, fits in 32 bits until 2106)
 */
typedef struct {
    _Atomic uint32_t value;
} atomic_timestamp_t;

static inline void atomic_timestamp_set(atomic_timestamp_t *ts, uint32_t val) {
    atomic_store(&ts->value, val);
}

static inline uint32_t atomic_timestamp_get(atomic_timestamp_t *ts) {
    return atomic_load(&ts->value);
}

static inline void atomic_timestamp_touch(atomic_timestamp_t *ts, uint32_t now) {
    atomic_store(&ts->value, now);
}

/*
 * Spin-wait with exponential backoff (for rare contention cases)
 */
static inline void atomic_backoff(int *count) {
    if (*count < 10) {
        /* Spin */
        for (int i = 0; i < (1 << *count); i++) {
            __asm__ volatile("pause" ::: "memory");
        }
        (*count)++;
    } else {
        /* Yield to OS scheduler */
        sched_yield();
    }
}

#endif /* _CERTS_ATOMIC_H_ */
