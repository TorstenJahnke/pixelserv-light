/*
 * certs_queue.c - Lock-free MPSC queue for certificate jobs
 *
 * Multi-Producer Single-Consumer queue using Dmitry Vyukov's algorithm.
 * No mutexes, no condition variables, no blocking.
 *
 * Producers: Multiple threads can push jobs concurrently
 * Consumer: Single worker thread pops jobs (uses spin-wait with backoff)
 */

#include <stdlib.h>
#include <string.h>
#include <sched.h>
#include "../include/certs_queue.h"

/* Queue state */
static _Atomic(cert_job_t *) queue_head;
static _Atomic(cert_job_t *) queue_tail;
static cert_job_t queue_stub;
static _Atomic int shutdown_flag;

void cert_queue_init(void) {
    atomic_store(&queue_stub.next, NULL);
    atomic_store(&queue_head, &queue_stub);
    atomic_store(&queue_tail, &queue_stub);
    atomic_store(&shutdown_flag, 0);
}

int cert_queue_push(const char *cert_name) {
    if (!cert_name || atomic_load(&shutdown_flag)) {
        return -1;
    }

    cert_job_t *job = malloc(sizeof(cert_job_t));
    if (!job) return -1;

    strncpy(job->cert_name, cert_name, CERT_NAME_MAX - 1);
    job->cert_name[CERT_NAME_MAX - 1] = '\0';
    atomic_store(&job->next, NULL);

    /* MPSC push: atomically exchange head, then link */
    cert_job_t *prev = atomic_exchange(&queue_head, job);
    atomic_store(&prev->next, job);

    return 0;
}

cert_job_t *cert_queue_pop(void) {
    cert_job_t *tail = atomic_load(&queue_tail);
    cert_job_t *next = atomic_load(&tail->next);

    /* Skip stub node */
    if (tail == &queue_stub) {
        if (!next) return NULL;
        atomic_store(&queue_tail, next);
        tail = next;
        next = atomic_load(&tail->next);
    }

    /* Normal case: return tail, advance to next */
    if (next) {
        atomic_store(&queue_tail, next);
        return tail;
    }

    /* Check if queue is truly empty or just slow producer */
    cert_job_t *head = atomic_load(&queue_head);
    if (tail != head) {
        /* Producer is slow, spin briefly */
        return NULL;
    }

    /* Queue is empty, re-insert stub */
    atomic_store(&queue_stub.next, NULL);
    cert_job_t *prev = atomic_exchange(&queue_head, &queue_stub);
    atomic_store(&prev->next, &queue_stub);

    /* Try again */
    next = atomic_load(&tail->next);
    if (next) {
        atomic_store(&queue_tail, next);
        return tail;
    }

    return NULL;
}

int cert_queue_empty(void) {
    cert_job_t *tail = atomic_load(&queue_tail);
    cert_job_t *head = atomic_load(&queue_head);

    if (tail == &queue_stub && head == &queue_stub) {
        return atomic_load(&tail->next) == NULL;
    }
    return 0;
}

void cert_queue_shutdown(void) {
    atomic_store(&shutdown_flag, 1);
}

int cert_queue_is_shutdown(void) {
    return atomic_load(&shutdown_flag);
}

void cert_job_free(cert_job_t *job) {
    if (job && job != &queue_stub) {
        free(job);
    }
}
