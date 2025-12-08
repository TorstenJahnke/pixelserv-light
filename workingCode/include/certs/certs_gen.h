/*
 * certs_gen.h - Certificate generation module
 *
 * Lock-free certificate generation using external RSA primes + keypool for fast key acquisition.
 */

#ifndef _CERTS_GEN_H_
#define _CERTS_GEN_H_

#include <openssl/evp.h>
#include <openssl/x509.h>
#include "certs/certs.h"

/* Forward declare keypool type */
typedef struct keypool keypool_t;

/* Initialize certificate generator with cert storage */
void cert_gen_init(cert_tlstor_t *ct);

/* Set keypool for fast key acquisition (worker mode) */
void cert_gen_set_keypool(keypool_t *kp);

/* Shutdown certificate generation workers */
void cert_gen_shutdown(void);

/* Generate RSA-3072 certificate for given domain/IP */
void cert_gen_create(const char *cert_name,
                     const char *pem_dir,
                     X509_NAME *issuer,
                     EVP_PKEY *privkey,
                     const STACK_OF(X509_INFO) *cachain);

/* Generate ECDSA P-256 certificate for given domain/IP */
void cert_gen_create_ecdsa(const char *cert_name,
                           const char *pem_dir,
                           X509_NAME *issuer,
                           EVP_PKEY *privkey,
                           const STACK_OF(X509_INFO) *cachain);

/* Generate SM2 certificate for given domain/IP */
void cert_gen_create_sm2(const char *cert_name,
                         const char *pem_dir,
                         X509_NAME *issuer,
                         EVP_PKEY *privkey,
                         const STACK_OF(X509_INFO) *cachain);

/* Generate universal IP certificate */
void cert_gen_universal_ip(const char *pem_dir,
                           X509_NAME *issuer,
                           EVP_PKEY *privkey,
                           const STACK_OF(X509_INFO) *cachain);

/* Generate RSA key from external primes (fast path) */
EVP_PKEY *cert_gen_rsa_from_primes(cert_tlstor_t *ct);

/* Load external primes files */
int cert_gen_load_primes(cert_tlstor_t *ct);

/* Unload external primes */
void cert_gen_unload_primes(cert_tlstor_t *ct);

/* Check if address is IPv4 or IPv6 */
int cert_gen_is_ip(const char *addr);

/* Worker thread for processing certificate jobs (lock-free) */
void *cert_gen_worker(void *arg);

/* Enqueue a certificate job (lock-free push) */
void cert_gen_enqueue(const char *cert_name);

#endif /* _CERTS_GEN_H_ */
