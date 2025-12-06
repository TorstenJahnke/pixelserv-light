/*
 * certs_queue.h - Lock-free certificate job queue
 */

#ifndef _CERTS_QUEUE_H_
#define _CERTS_QUEUE_H_

#include "certs_atomic.h"
#include "certs.h"

#define CERT_NAME_MAX 256

/* Certificate job structure */
typedef struct cert_job {
    _Atomic(struct cert_job *) next;
    char cert_name[CERT_NAME_MAX];
} cert_job_t;

/* Initialize the job queue */
void cert_queue_init(void);

/* Push a certificate generation job (lock-free, multiple producers) */
int cert_queue_push(const char *cert_name);

/* Pop a job (lock-free, single consumer) */
cert_job_t *cert_queue_pop(void);

/* Check if queue is empty */
int cert_queue_empty(void);

/* Signal shutdown to workers */
void cert_queue_shutdown(void);

/* Check if shutdown was signaled */
int cert_queue_is_shutdown(void);

/* Free a job after processing */
void cert_job_free(cert_job_t *job);

#endif /* _CERTS_QUEUE_H_ */
