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

/* =============================================================================
   COMPREHENSIVE TLS CIPHER SUITE COLLECTION
   Maximum compatibility - supports clients from Windows XP to modern browsers
   ============================================================================= */

/* --- TIER 1: Modern AEAD Ciphers (TLS 1.2) - Highest Priority --- */
#define PIXELSERV_CIPHERS_AEAD_ECDHE \
  "ECDHE-ECDSA-AES256-GCM-SHA384:" \
  "ECDHE-RSA-AES256-GCM-SHA384:" \
  "ECDHE-ECDSA-AES128-GCM-SHA256:" \
  "ECDHE-RSA-AES128-GCM-SHA256:" \
  "ECDHE-ECDSA-CHACHA20-POLY1305:" \
  "ECDHE-RSA-CHACHA20-POLY1305:" \
  "ECDHE-ECDSA-AES256-CCM:" \
  "ECDHE-ECDSA-AES128-CCM:" \
  "ECDHE-ECDSA-AES256-CCM8:" \
  "ECDHE-ECDSA-AES128-CCM8"

#define PIXELSERV_CIPHERS_AEAD_DHE \
  "DHE-RSA-AES256-GCM-SHA384:" \
  "DHE-RSA-AES128-GCM-SHA256:" \
  "DHE-RSA-CHACHA20-POLY1305:" \
  "DHE-RSA-AES256-CCM:" \
  "DHE-RSA-AES128-CCM:" \
  "DHE-RSA-AES256-CCM8:" \
  "DHE-RSA-AES128-CCM8"

/* --- TIER 2: CBC Ciphers with SHA-256/384 (BSI compliant) --- */
#define PIXELSERV_CIPHERS_CBC_SHA256 \
  "ECDHE-ECDSA-AES256-SHA384:" \
  "ECDHE-RSA-AES256-SHA384:" \
  "ECDHE-ECDSA-AES128-SHA256:" \
  "ECDHE-RSA-AES128-SHA256:" \
  "DHE-RSA-AES256-SHA256:" \
  "DHE-RSA-AES128-SHA256"

/* --- TIER 3: CBC Ciphers with SHA-1 (Legacy PFS) --- */
#define PIXELSERV_CIPHERS_CBC_SHA1 \
  "ECDHE-ECDSA-AES256-SHA:" \
  "ECDHE-RSA-AES256-SHA:" \
  "ECDHE-ECDSA-AES128-SHA:" \
  "ECDHE-RSA-AES128-SHA:" \
  "DHE-RSA-AES256-SHA:" \
  "DHE-RSA-AES128-SHA"

/* --- TIER 4: Non-PFS AEAD (Static RSA with GCM) --- */
#define PIXELSERV_CIPHERS_STATIC_AEAD \
  "AES256-GCM-SHA384:" \
  "AES128-GCM-SHA256:" \
  "AES256-CCM:" \
  "AES128-CCM:" \
  "AES256-CCM8:" \
  "AES128-CCM8"

/* --- TIER 5: Non-PFS CBC with SHA-256 --- */
#define PIXELSERV_CIPHERS_STATIC_SHA256 \
  "AES256-SHA256:" \
  "AES128-SHA256"

/* --- TIER 6: Non-PFS CBC with SHA-1 (Windows 7, Android 4.x) --- */
#define PIXELSERV_CIPHERS_STATIC_SHA1 \
  "AES256-SHA:" \
  "AES128-SHA"

/* --- TIER 7: ARIA Ciphers (Korean Standard KS X 1213) --- */
#define PIXELSERV_CIPHERS_ARIA \
  "ECDHE-ECDSA-ARIA256-GCM-SHA384:" \
  "ECDHE-RSA-ARIA256-GCM-SHA384:" \
  "ECDHE-ECDSA-ARIA128-GCM-SHA256:" \
  "ECDHE-RSA-ARIA128-GCM-SHA256:" \
  "DHE-RSA-ARIA256-GCM-SHA384:" \
  "DHE-RSA-ARIA128-GCM-SHA256:" \
  "ARIA256-GCM-SHA384:" \
  "ARIA128-GCM-SHA256:" \
  "ECDHE-ECDSA-ARIA256-SHA384:" \
  "ECDHE-RSA-ARIA256-SHA384:" \
  "ECDHE-ECDSA-ARIA128-SHA256:" \
  "ECDHE-RSA-ARIA128-SHA256:" \
  "DHE-RSA-ARIA256-SHA384:" \
  "DHE-RSA-ARIA128-SHA256:" \
  "ARIA256-SHA384:" \
  "ARIA128-SHA256"

/* --- TIER 8: Camellia Ciphers (Japanese/ISO Standard) --- */
#define PIXELSERV_CIPHERS_CAMELLIA \
  "ECDHE-ECDSA-CAMELLIA256-GCM-SHA384:" \
  "ECDHE-RSA-CAMELLIA256-GCM-SHA384:" \
  "ECDHE-ECDSA-CAMELLIA128-GCM-SHA256:" \
  "ECDHE-RSA-CAMELLIA128-GCM-SHA256:" \
  "DHE-RSA-CAMELLIA256-GCM-SHA384:" \
  "DHE-RSA-CAMELLIA128-GCM-SHA256:" \
  "CAMELLIA256-GCM-SHA384:" \
  "CAMELLIA128-GCM-SHA256:" \
  "ECDHE-ECDSA-CAMELLIA256-SHA384:" \
  "ECDHE-RSA-CAMELLIA256-SHA384:" \
  "ECDHE-ECDSA-CAMELLIA128-SHA256:" \
  "ECDHE-RSA-CAMELLIA128-SHA256:" \
  "DHE-RSA-CAMELLIA256-SHA384:" \
  "DHE-RSA-CAMELLIA128-SHA256:" \
  "DHE-RSA-CAMELLIA256-SHA:" \
  "DHE-RSA-CAMELLIA128-SHA:" \
  "CAMELLIA256-SHA384:" \
  "CAMELLIA128-SHA256:" \
  "CAMELLIA256-SHA:" \
  "CAMELLIA128-SHA"

/* --- TIER 9: SEED Cipher (Korean Standard KISA) --- */
#define PIXELSERV_CIPHERS_SEED \
  "DHE-RSA-SEED-SHA:" \
  "SEED-SHA"

/* --- TIER 10: DSS/DSA Ciphers --- */
#define PIXELSERV_CIPHERS_DSS \
  "DHE-DSS-AES256-GCM-SHA384:" \
  "DHE-DSS-AES128-GCM-SHA256:" \
  "DHE-DSS-AES256-SHA256:" \
  "DHE-DSS-AES128-SHA256:" \
  "DHE-DSS-AES256-SHA:" \
  "DHE-DSS-AES128-SHA"

/* --- TIER 11: 3DES (Very old clients - Windows XP, IE6) --- */
#define PIXELSERV_CIPHERS_3DES \
  "ECDHE-RSA-DES-CBC3-SHA:" \
  "ECDHE-ECDSA-DES-CBC3-SHA:" \
  "DHE-RSA-DES-CBC3-SHA:" \
  "DES-CBC3-SHA"

/* --- Combined Lists --- */

/* BSI TR-02102-2 / NIS2 compliant (recommended for EU) */
#define PIXELSERV_CIPHER_LIST_BSI \
  PIXELSERV_CIPHERS_AEAD_ECDHE ":" \
  PIXELSERV_CIPHERS_AEAD_DHE ":" \
  PIXELSERV_CIPHERS_CBC_SHA256

/* Standard list with legacy support */
#define PIXELSERV_CIPHER_LIST_LEGACY \
  PIXELSERV_CIPHERS_CBC_SHA1 ":" \
  PIXELSERV_CIPHERS_STATIC_AEAD ":" \
  PIXELSERV_CIPHERS_STATIC_SHA256 ":" \
  PIXELSERV_CIPHERS_STATIC_SHA1

/* International ciphers (ARIA, Camellia, SEED) */
#define PIXELSERV_CIPHER_LIST_INTL \
  PIXELSERV_CIPHERS_ARIA ":" \
  PIXELSERV_CIPHERS_CAMELLIA ":" \
  PIXELSERV_CIPHERS_SEED

/* DSS and 3DES for very old clients */
#define PIXELSERV_CIPHER_LIST_COMPAT \
  PIXELSERV_CIPHERS_DSS ":" \
  PIXELSERV_CIPHERS_3DES

/* DEFAULT: BSI + Legacy (covers Windows 7+, Android 4+, iOS 5+) */
#define PIXELSERV_CIPHER_LIST \
  PIXELSERV_CIPHER_LIST_BSI ":" \
  PIXELSERV_CIPHER_LIST_LEGACY

/* FULL: Everything including international ciphers */
#define PIXELSERV_CIPHER_LIST_ALL \
  PIXELSERV_CIPHER_LIST ":" \
  PIXELSERV_CIPHER_LIST_INTL ":" \
  PIXELSERV_CIPHER_LIST_COMPAT

/* Strict BSI-only mode (no legacy ciphers) */
#define PIXELSERV_CIPHER_LIST_STRICT PIXELSERV_CIPHER_LIST_BSI

/* =============================================================================
   TLS 1.3 CIPHER SUITES (RFC 8446)
   ============================================================================= */

/* Standard TLS 1.3 ciphers */
#define PIXELSERV_TLSV1_3_CIPHERS \
  "TLS_AES_256_GCM_SHA384:" \
  "TLS_AES_128_GCM_SHA256:" \
  "TLS_CHACHA20_POLY1305_SHA256:" \
  "TLS_AES_128_CCM_SHA256:" \
  "TLS_AES_128_CCM_8_SHA256"

/* =============================================================================
   SM2/SM3/SM4 CIPHER SUITES - Tongchou (Chinese GM/T Standards)
   Requires OpenSSL 1.1.1+ compiled with enable-sm2 enable-sm3 enable-sm4
   ============================================================================= */

#if defined(DISABLE_TONGCHOU)
#  define PIXELSERV_SM_CIPHERS ""
#  define PIXELSERV_TLSV1_3_SM_CIPHERS ""
#  define PIXELSERV_HAS_TONGCHOU 0
#elif defined(HAVE_TONGCHOU) || defined(HAVE_SM4)
#  define PIXELSERV_SM_CIPHERS \
  "ECDHE-SM2-SM4-GCM-SM3:" \
  "ECDHE-SM2-SM4-CBC-SM3:" \
  "ECC-SM2-SM4-GCM-SM3:" \
  "ECC-SM2-SM4-CBC-SM3:" \
  "SM4-GCM-SM3:" \
  "SM4-CCM-SM3:" \
  "SM4-CBC-SM3"
#  define PIXELSERV_TLSV1_3_SM_CIPHERS \
  "TLS_SM4_GCM_SM3:" \
  "TLS_SM4_CCM_SM3"
#  define PIXELSERV_HAS_TONGCHOU 1
#elif defined(OPENSSL_NO_SM4)
#  define PIXELSERV_SM_CIPHERS ""
#  define PIXELSERV_TLSV1_3_SM_CIPHERS ""
#  define PIXELSERV_HAS_TONGCHOU 0
#else
   /* Unknown - try to enable, will fail gracefully at runtime */
#  define PIXELSERV_SM_CIPHERS \
  "ECDHE-SM2-SM4-GCM-SM3:" \
  "ECDHE-SM2-SM4-CBC-SM3:" \
  "ECC-SM2-SM4-GCM-SM3:" \
  "ECC-SM2-SM4-CBC-SM3:" \
  "SM4-GCM-SM3:" \
  "SM4-CCM-SM3:" \
  "SM4-CBC-SM3"
#  define PIXELSERV_TLSV1_3_SM_CIPHERS \
  "TLS_SM4_GCM_SM3:" \
  "TLS_SM4_CCM_SM3"
#  define PIXELSERV_HAS_TONGCHOU 1
#endif

/* =============================================================================
   COMBINED CIPHER LISTS
   ============================================================================= */

/* FULL cipher list: ALL ciphers + SM (Tongchou) */
#define PIXELSERV_CIPHER_LIST_FULL \
  PIXELSERV_CIPHER_LIST_ALL ":" PIXELSERV_SM_CIPHERS

/* FULL TLS 1.3 cipher list with SM4 */
#define PIXELSERV_TLSV1_3_CIPHERS_FULL \
  PIXELSERV_TLSV1_3_CIPHERS ":" PIXELSERV_TLSV1_3_SM_CIPHERS

/* ECDH Groups for key exchange - BSI TR-02102-2 compliant

   BSI TR-02102-2 recommended curves:
   - brainpoolP256r1, brainpoolP384r1, brainpoolP512r1 (BSI preferred)
   - secp256r1 (P-256), secp384r1 (P-384) (NIST curves, widely supported)
   - X25519, X448 (modern, high performance)

   Note: Brainpool curves may not be supported by all clients */

/* Full BSI-compliant groups including Brainpool (if available) */
#if defined(HAVE_BRAINPOOL) && defined(HAVE_X448)
#  define PIXELSERV_GROUPS_BSI \
    "X25519:X448:P-256:P-384:P-521:" \
    "brainpoolP256r1:brainpoolP384r1:brainpoolP512r1"
#elif defined(HAVE_BRAINPOOL)
#  define PIXELSERV_GROUPS_BSI \
    "X25519:P-256:P-384:P-521:" \
    "brainpoolP256r1:brainpoolP384r1:brainpoolP512r1"
#elif defined(HAVE_X448)
#  define PIXELSERV_GROUPS_BSI "X25519:X448:P-256:P-384:P-521"
#else
#  define PIXELSERV_GROUPS_BSI "X25519:P-256:P-384:P-521"
#endif

/* Standard groups without Brainpool (wider compatibility) */
#if defined(HAVE_X448)
#  define PIXELSERV_GROUPS_STANDARD "X25519:X448:P-256:P-384:P-521"
#else
#  define PIXELSERV_GROUPS_STANDARD "X25519:P-256:P-384:P-521"
#endif

/* Groups with Tongchou SM2 support */
#if PIXELSERV_HAS_TONGCHOU
#  define PIXELSERV_GROUPS PIXELSERV_GROUPS_BSI ":SM2"
#  define PIXELSERV_GROUPS_FULL PIXELSERV_GROUPS_STANDARD ":SM2"
#else
#  define PIXELSERV_GROUPS PIXELSERV_GROUPS_BSI
#  define PIXELSERV_GROUPS_FULL PIXELSERV_GROUPS_STANDARD
#endif

/* Legacy groups for older OpenSSL versions */
#define PIXELSERV_GROUPS_LEGACY "X25519:P-256:P-384"

/* Select cipher list based on mode */
#if defined(BSI_STRICT_MODE)
#  define PIXELSERV_CIPHER_LIST_ACTIVE PIXELSERV_CIPHER_LIST_STRICT
#else
   /* Default: Use ALL ciphers for maximum compatibility */
#  define PIXELSERV_CIPHER_LIST_ACTIVE PIXELSERV_CIPHER_LIST_ALL
#endif

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
    /* Note: No per-entry lock - table uses lock-free seqlock pattern */
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
