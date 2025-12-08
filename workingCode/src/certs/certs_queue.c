/*
 * certs_queue.c - Thread-safe certificate job queue
 *
 * Multi-Producer Multi-Consumer queue using mutex for thread safety.
 * Allows parallel certificate generation workers.
 */

#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include "certs/certs_queue.h"

/* Simple linked list queue with mutex */
static cert_job_t *queue_head = NULL;
static cert_job_t *queue_tail = NULL;
static pthread_mutex_t queue_mutex = PTHREAD_MUTEX_INITIALIZER;
static _Atomic int shutdown_flag;

void cert_queue_init(void) {
    pthread_mutex_lock(&queue_mutex);
    queue_head = NULL;
    queue_tail = NULL;
    atomic_store(&shutdown_flag, 0);
    pthread_mutex_unlock(&queue_mutex);
}

int cert_queue_push(const char *cert_name) {
    if (!cert_name || atomic_load(&shutdown_flag)) {
        return -1;
    }

    cert_job_t *job = malloc(sizeof(cert_job_t));
    if (!job) return -1;

    strncpy(job->cert_name, cert_name, CERT_NAME_MAX - 1);
    job->cert_name[CERT_NAME_MAX - 1] = '\0';
    job->next = NULL;

    pthread_mutex_lock(&queue_mutex);
    if (queue_tail) {
        queue_tail->next = job;
        queue_tail = job;
    } else {
        queue_head = queue_tail = job;
    }
    pthread_mutex_unlock(&queue_mutex);

    return 0;
}

cert_job_t *cert_queue_pop(void) {
    cert_job_t *job = NULL;

    pthread_mutex_lock(&queue_mutex);
    if (queue_head) {
        job = queue_head;
        queue_head = (cert_job_t *)job->next;
        if (!queue_head) {
            queue_tail = NULL;
        }
        job->next = NULL;
    }
    pthread_mutex_unlock(&queue_mutex);

    return job;
}

void cert_queue_shutdown(void) {
    atomic_store(&shutdown_flag, 1);
}

int cert_queue_is_shutdown(void) {
    return atomic_load(&shutdown_flag);
}

void cert_job_free(cert_job_t *job) {
    if (job) {
        free(job);
    }
}
