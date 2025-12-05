#ifndef _CERTS_H_
#define _CERTS_H_

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <arpa/inet.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>

#define PIXEL_SSL_SESS_CACHE_SIZE 128*20
#define PIXEL_SSL_SESS_TIMEOUT 3600 /* seconds */
#define PIXEL_CERT_PIPE "/tmp/pixelcerts"
#define PIXEL_TLS_EARLYDATA_SIZE 16384
#ifndef DEFAULT_PEM_PATH
#define DEFAULT_PEM_PATH "/opt/var/cache/pixelserv"
#endif
#define PIXELSERV_MAX_PATH 1024
#define PIXELSERV_MAX_SERVER_NAME 255

/* Modern TLS 1.2 Cipher List (2024+)
   Priority: CHACHA20 for mobile/ARM, then AES-GCM, with ECDHE key exchange
   Compatibility: Android >= 4.4.2; Chrome >= 51; Firefox >= 49;
   IE 11 Win 10; Edge >= 13; Safari >= 9; iOS >= 9
   Legacy fallback for older clients included at end */
#define PIXELSERV_CIPHER_LIST \
  "ECDHE-ECDSA-CHACHA20-POLY1305:" \
  "ECDHE-RSA-CHACHA20-POLY1305:" \
  "ECDHE-ECDSA-AES256-GCM-SHA384:" \
  "ECDHE-RSA-AES256-GCM-SHA384:" \
  "ECDHE-ECDSA-AES128-GCM-SHA256:" \
  "ECDHE-RSA-AES128-GCM-SHA256:" \
  "DHE-RSA-AES256-GCM-SHA384:" \
  "DHE-RSA-AES128-GCM-SHA256:" \
  "ECDHE-RSA-AES128-SHA:" \
  "DHE-RSA-AES128-SHA:" \
  "AES128-GCM-SHA256:" \
  "AES256-GCM-SHA384:" \
  "AES128-SHA"

/* TLS 1.3 Cipher Suites (RFC 8446)
   All mandatory and recommended suites including SM4 for Tongchou/GM compliance */
#define PIXELSERV_TLSV1_3_CIPHERS \
  "TLS_AES_256_GCM_SHA384:" \
  "TLS_CHACHA20_POLY1305_SHA256:" \
  "TLS_AES_128_GCM_SHA256:" \
  "TLS_AES_128_CCM_SHA256:" \
  "TLS_AES_128_CCM_8_SHA256"

/* SM2/SM3/SM4 Cipher Suites for Tongchou (Chinese GM/T Standards)
   Requires OpenSSL 1.1.1+ compiled with enable-sm2 enable-sm3 enable-sm4
   SM2: Elliptic Curve (similar to ECDSA/ECDH)
   SM3: Hash function (256-bit, similar to SHA-256)
   SM4: Block cipher (128-bit, similar to AES-128)

   Detection priority:
   1. DISABLE_TONGCHOU - explicitly disabled via --disable-tongchou
   2. HAVE_TONGCHOU - autoconf detected full SM2/SM3/SM4 support
   3. HAVE_SM4 - autoconf detected at least SM4 support
   4. OPENSSL_NO_SM4 - OpenSSL compile-time flag (fallback) */

#if defined(DISABLE_TONGCHOU)
   /* Tongchou explicitly disabled */
#  define PIXELSERV_SM_CIPHERS ""
#  define PIXELSERV_TLSV1_3_SM_CIPHERS ""
#  define PIXELSERV_HAS_TONGCHOU 0
#elif defined(HAVE_TONGCHOU) || defined(HAVE_SM4)
   /* Tongchou support detected by autoconf */
#  define PIXELSERV_SM_CIPHERS \
  "ECDHE-SM2-SM4-GCM-SM3:" \
  "ECDHE-SM2-SM4-CBC-SM3:" \
  "ECC-SM2-SM4-GCM-SM3:" \
  "ECC-SM2-SM4-CBC-SM3"
#  define PIXELSERV_TLSV1_3_SM_CIPHERS \
  "TLS_SM4_GCM_SM3:" \
  "TLS_SM4_CCM_SM3"
#  define PIXELSERV_HAS_TONGCHOU 1
#elif defined(OPENSSL_NO_SM4)
   /* OpenSSL compiled without SM4 support */
#  define PIXELSERV_SM_CIPHERS ""
#  define PIXELSERV_TLSV1_3_SM_CIPHERS ""
#  define PIXELSERV_HAS_TONGCHOU 0
#else
   /* Unknown - try to enable, will fail gracefully at runtime */
#  define PIXELSERV_SM_CIPHERS \
  "ECDHE-SM2-SM4-GCM-SM3:" \
  "ECDHE-SM2-SM4-CBC-SM3:" \
  "ECC-SM2-SM4-GCM-SM3:" \
  "ECC-SM2-SM4-CBC-SM3"
#  define PIXELSERV_TLSV1_3_SM_CIPHERS \
  "TLS_SM4_GCM_SM3:" \
  "TLS_SM4_CCM_SM3"
#  define PIXELSERV_HAS_TONGCHOU 1
#endif

/* Combined cipher list with SM support */
#define PIXELSERV_CIPHER_LIST_FULL \
  PIXELSERV_CIPHER_LIST ":" PIXELSERV_SM_CIPHERS

#define PIXELSERV_TLSV1_3_CIPHERS_FULL \
  PIXELSERV_TLSV1_3_CIPHERS ":" PIXELSERV_TLSV1_3_SM_CIPHERS

/* ECDH Groups for key exchange, including SM2 curve for Tongchou */
#if PIXELSERV_HAS_TONGCHOU
#  define PIXELSERV_GROUPS "X25519:P-256:P-384:SM2"
#else
#  define PIXELSERV_GROUPS "X25519:P-256:P-384"
#endif
#define PIXELSERV_GROUPS_LEGACY "X25519:P-256"

#if defined(SSL_CTX_set_ecdh_auto)
# define PIXELSRV_SSL_HAS_ECDH_AUTO
#endif

typedef struct {
    const char* pem_dir;
    STACK_OF(X509_INFO) *cachain;
    X509_NAME *issuer;
    EVP_PKEY *privkey;
} cert_tlstor_t;

typedef enum {
    SSL_NOT_TLS,
    SSL_ERR,
    SSL_MISS,
    SSL_HIT,
    SSL_HIT_CLS,
    SSL_HIT_RTT0,
    SSL_UNKNOWN
} ssl_enum;

typedef struct {
    const char *tls_pem;
    const STACK_OF(X509_INFO) *cachain;
    char servername[65]; /* max legal domain name 63 chars; INET6_ADDRSTRLEN 46 bytes */
    char server_ip[INET6_ADDRSTRLEN];
    ssl_enum status;
    int sslctx_idx;
} tlsext_cb_arg_struct;

typedef struct {
    int new_fd;
    SSL *ssl;
    double init_time;
    tlsext_cb_arg_struct *tlsext_cb_arg;
    int allow_admin;
    char *early_data;
    tlsext_cb_arg_struct v;
} conn_tlstor_struct;

typedef struct {
    int alloc_len;
    char *cert_name;
    unsigned int last_use; /* seconds since process up */
    int reuse_count;
    SSL_CTX *sslctx;
    pthread_mutex_t lock;
} sslctx_cache_struct;

#define CONN_TLSTOR(p, e) ((conn_tlstor_struct*)p)->e

void ssl_init_locks();
void ssl_free_locks();
void cert_tlstor_init(const char *pem_dir, cert_tlstor_t *c);
void cert_tlstor_cleanup(cert_tlstor_t *c);
void *cert_generator(void *ptr);
void sslctx_tbl_init(int tbl_size);
void sslctx_tbl_cleanup();
void sslctx_tbl_load(const char* pem_dir, const STACK_OF(X509_INFO) *cachain);
void sslctx_tbl_save(const char* pem_dir);
void run_benchmark(const cert_tlstor_t *ct, const char *cert);
void sslctx_tbl_lock(int idx);
void sslctx_tbl_unlock(int idx);
int sslctx_tbl_get_cnt_total();
int sslctx_tbl_get_cnt_hit();
int sslctx_tbl_get_cnt_miss();
int sslctx_tbl_get_cnt_purge();
int sslctx_tbl_get_sess_cnt();
int sslctx_tbl_get_sess_hit();
int sslctx_tbl_get_sess_miss();
int sslctx_tbl_get_sess_purge();
SSL_CTX * create_default_sslctx(const char *pem_dir);
int is_ssl_conn(int fd, char *srv_ip, int srv_ip_len, const int *ssl_ports, int num_ssl_ports);
void conn_stor_init(int slots);
void conn_stor_relinq(conn_tlstor_struct *p);
conn_tlstor_struct* conn_stor_acquire();
void conn_stor_flush();
#ifdef TLS1_3_VERSION
int tls_clienthello_cb(SSL *ssl, int *ad, void *arg);
char* read_tls_early_data(SSL *ssl, int *err);
#endif
#endif
