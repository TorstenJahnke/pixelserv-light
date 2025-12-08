/*
 * certs_queue.h - Thread-safe certificate job queue (MPMC)
 */

#ifndef _CERTS_QUEUE_H_
#define _CERTS_QUEUE_H_

#include "certs/certs_atomic.h"
#include "certs/certs.h"

#define CERT_NAME_MAX 256

/* Certificate job structure */
typedef struct cert_job {
    struct cert_job *next;
    char cert_name[CERT_NAME_MAX];
} cert_job_t;

/* Initialize the job queue */
void cert_queue_init(void);

/* Push a certificate generation job (thread-safe, multiple producers) */
int cert_queue_push(const char *cert_name);

/* Pop a job (thread-safe, multiple consumers) */
cert_job_t *cert_queue_pop(void);

/* Signal shutdown to workers */
void cert_queue_shutdown(void);

/* Check if shutdown was signaled */
int cert_queue_is_shutdown(void);

/* Free a job after processing */
void cert_job_free(cert_job_t *job);

#endif /* _CERTS_QUEUE_H_ */
