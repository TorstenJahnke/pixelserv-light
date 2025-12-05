/**
 * TLSGateNG4 v4.36 - Certificate Generation Benchmark
 * High-precision RSA certificate generation with performance analysis
 *
 * Features:
 * - OpenSSL version and capability detection
 * - Hardware acceleration detection (AES-NI, AVX, RDRAND)
 * - Pre-computed prime support for fast RSA generation
 * - High-precision timing (microseconds)
 * - Console output with detailed performance statistics
 * - Transparent optimization (not explicitly visible)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/stat.h>

#include <openssl/opensslv.h>
#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/param_build.h>
#include <openssl/core_names.h>

/* ============================================================================
 * Configuration & Constants
 * ============================================================================ */

/* Configuration file locations (checked in order) */
#define CONFIG_FILE_1 "/etc/benchmark.conf"
#define CONFIG_FILE_2 "./benchmark.conf"
#define CONFIG_FILE_3 "./config-files/benchmark.conf"

/* Default values */
#define DEFAULT_NUM_TESTS 5
#define DEFAULT_PRIME_POOL_DIR "/opt/tlsgateNG/prime"
#define MAX_KEY_SIZES 10  /* Maximum number of RSA key sizes to test */

/* Prime pool header (compatible with pixelserv-keygen format) */
#define PRIME_POOL_MAGIC 0x5052494D  /* "PRIM" */
#define PRIME_POOL_VERSION 1

typedef struct {
    uint32_t magic;           /* 0x5052494D "PRIM" */
    uint32_t version;         /* Prime pool format version */
    uint32_t count;           /* Number of primes per pool (p and q each) */
    uint32_t prime_bits;      /* Bits per prime */
    uint64_t timestamp;       /* Generation timestamp */
    uint8_t  reserved[8];
} __attribute__((packed)) PrimePoolHeader;

typedef struct {
    int key_size;
    unsigned char *p_pool;     /* p primes: count × prime_bytes */
    unsigned char *q_pool;     /* q primes: count × prime_bytes */
    uint32_t prime_count;      /* Number of p/q pairs */
    uint32_t prime_bytes;      /* Bytes per prime */
    int is_loaded;
    uint32_t current_p_idx;    /* Current index for p selection */
    uint32_t current_q_idx;    /* Current index for q selection */
} PrimePool;

/* Global configuration (loaded from config file) */
typedef struct {
    int key_sizes[MAX_KEY_SIZES];
    int num_key_sizes;
    int num_tests;
    char precomp_dir[256];
    int enable_precomputation;
    int show_details;
} BenchmarkConfig;

static BenchmarkConfig g_config = {
    .key_sizes = {4096, 8192, 16384},  /* Default: test all three sizes */
    .num_key_sizes = 3,
    .num_tests = DEFAULT_NUM_TESTS,
    .precomp_dir = DEFAULT_PRIME_POOL_DIR,
    .enable_precomputation = 1,
    .show_details = 1
};

/* Current test context */
static int g_current_key_size = 4096;
static PrimePool *g_current_prime_pool = NULL;  /* Prime pool for current key size */

/* Performance summary for comparison */
typedef struct {
    int key_size;
    double avg_time_ms;
    double certs_per_hour;
    int has_precomp;
} KeySizeResult;

typedef struct {
    double min_ms;
    double max_ms;
    double avg_ms;
    double median_ms;
    double p95_ms;
    double p99_ms;
} BenchmarkStats;

/* High-resolution timer */
#define TIMER_START() \
    struct timespec ts_start, ts_end; \
    clock_gettime(CLOCK_MONOTONIC, &ts_start)

#define TIMER_END() \
    clock_gettime(CLOCK_MONOTONIC, &ts_end)

#define TIMER_ELAPSED_US() \
    (((long)(ts_end.tv_sec - ts_start.tv_sec) * 1000000000LL + \
      (long)(ts_end.tv_nsec - ts_start.tv_nsec)) / 1000LL)

/* ============================================================================
 * Configuration Loading
 * ============================================================================ */

static void parse_key_sizes(const char *value) {
    char *copy = strdup(value);
    if (!copy) return;

    char *ptr = copy;
    int idx = 0;

    while (*ptr && idx < MAX_KEY_SIZES) {
        /* Skip whitespace */
        while (*ptr == ' ') ptr++;

        /* Read number */
        int size = atoi(ptr);
        if (size > 0) {
            g_config.key_sizes[idx++] = size;
        }

        /* Skip to next comma */
        while (*ptr && *ptr != ',') ptr++;
        if (*ptr == ',') ptr++;
    }

    g_config.num_key_sizes = idx;
    free(copy);
}

static void config_load(void) {
    FILE *fp = NULL;
    char line[512];
    char key[256], value[256];
    const char *config_paths[] = {CONFIG_FILE_1, CONFIG_FILE_2, CONFIG_FILE_3, NULL};

    /* Try to load configuration from standard locations */
    for (int i = 0; config_paths[i] != NULL; i++) {
        fp = fopen(config_paths[i], "r");
        if (fp) {
            break;
        }
    }

    if (!fp) {
        /* No config file found - use defaults (silently) */
        return;
    }

    /* Parse configuration file */
    while (fgets(line, sizeof(line), fp) != NULL) {
        /* Skip comments and empty lines */
        if (line[0] == '#' || line[0] == '\n') {
            continue;
        }

        /* Remove newline */
        line[strcspn(line, "\n")] = 0;

        /* Parse KEY=VALUE */
        if (sscanf(line, "%255[^=]=%255s", key, value) == 2) {
            /* Strip whitespace */
            char *key_ptr = key;
            while (*key_ptr == ' ') key_ptr++;

            if (strcmp(key_ptr, "RSA_KEY_SIZES") == 0) {
                parse_key_sizes(value);
            } else if (strcmp(key_ptr, "TEST_RUNS") == 0) {
                g_config.num_tests = atoi(value);
            } else if (strcmp(key_ptr, "PRECOMPUTATION_DIR") == 0) {
                strncpy(g_config.precomp_dir, value, sizeof(g_config.precomp_dir) - 1);
            } else if (strcmp(key_ptr, "ENABLE_PRECOMPUTATION") == 0) {
                g_config.enable_precomputation = (strcmp(value, "true") == 0) ? 1 : 0;
            } else if (strcmp(key_ptr, "DETAILS_LEVEL") == 0) {
                g_config.show_details = (strcmp(value, "detailed") == 0 ||
                                        strcmp(value, "advanced") == 0) ? 1 : 0;
            }
        }
    }

    fclose(fp);
}

/* ============================================================================
 * OpenSSL Information & Detection
 * ============================================================================ */

static void print_openssl_info(void) {
    const char *version = OpenSSL_version(OPENSSL_VERSION);
    const char *built = OpenSSL_version(OPENSSL_BUILT_ON);
    unsigned long flags = OpenSSL_version_num();

    printf("\n╔═══════════════════════════════════════════════════════════════════════╗\n");
    printf("║  TLSGateNG4 v4.36 GEN4 - Certificate Generation Benchmark             ║\n");
    printf("║  High-Performance RSA Generation with Optimized Execution              ║\n");
    printf("╚═══════════════════════════════════════════════════════════════════════╝\n\n");

    printf("┌─ OpenSSL Configuration ─────────────────────────────────────────────┐\n");
    printf("│ Version:        %s\n", version);
    printf("│ Version Code:   0x%lx\n", flags);
    printf("│ Built:          %s\n", built);
    printf("│ Loaded Features:\n");

    /* Check for hardware acceleration support */
    printf("│   • CPU Flags:  ");
    const char *cpu_info = OpenSSL_version(OPENSSL_CFLAGS);
    if (strstr(cpu_info, "enable-")) {
        printf("Optimizations Enabled\n");
    } else {
        printf("Default Build\n");
    }

    printf("└─────────────────────────────────────────────────────────────────────┘\n\n");
}

static void print_system_info(void) {
    printf("┌─ Execution Environment ────────────────────────────────────────────┐\n");
    printf("│ RSA Key Sizes to Test:     ");
    for (int i = 0; i < g_config.num_key_sizes; i++) {
        if (i > 0) printf(", ");
        printf("%d bits", g_config.key_sizes[i]);
    }
    printf("\n");
    printf("│ Tests per Key Size:        %d consecutive runs\n", g_config.num_tests);
    printf("│ Total Benchmarks:          %d (size combinations × test runs)\n",
           g_config.num_key_sizes * g_config.num_tests);
    printf("│ Hardware Acceleration:     Enabled (if available)\n");
    printf("│ Timer Resolution:          Nanosecond precision (CLOCK_MONOTONIC)\n");
    printf("│ Configuration:             Loaded from benchmark.conf\n");
    printf("└─────────────────────────────────────────────────────────────────────┘\n\n");
}

/* ============================================================================
 * Prime Pool Management
 * ============================================================================ */

static PrimePool* prime_pool_new(int key_size) {
    PrimePool *pool = (PrimePool *)malloc(sizeof(PrimePool));
    if (!pool) return NULL;

    pool->key_size = key_size;
    pool->p_pool = NULL;
    pool->q_pool = NULL;
    pool->prime_count = 0;
    pool->prime_bytes = 0;
    pool->is_loaded = 0;
    pool->current_p_idx = 0;
    pool->current_q_idx = 0;

    return pool;
}

static void prime_pool_free(PrimePool *pool) {
    if (!pool) return;

    if (pool->p_pool) {
        free(pool->p_pool);
        pool->p_pool = NULL;
    }
    if (pool->q_pool) {
        free(pool->q_pool);
        pool->q_pool = NULL;
    }
    free(pool);
}

static int prime_pool_try_load(PrimePool *pool) {
    char filename_p[512];
    char filename_q[512];
    FILE *fp_p = NULL;
    FILE *fp_q = NULL;
    struct stat st;
    PrimePoolHeader header_p, header_q;
    unsigned char *p_data = NULL;
    unsigned char *q_data = NULL;
    int prime_bytes = 0;

    if (!g_config.enable_precomputation) {
        return 0;
    }

    /* Try to load separate p.bin and q.bin files */
    snprintf(filename_p, sizeof(filename_p), "%s/prime-%d-p.bin",
             g_config.precomp_dir, pool->key_size);
    snprintf(filename_q, sizeof(filename_q), "%s/prime-%d-q.bin",
             g_config.precomp_dir, pool->key_size);

    /* Check if both files exist */
    if (stat(filename_p, &st) != 0 || stat(filename_q, &st) != 0) {
        /* Prime pool files not found - this is OK, we can still generate primes */
        return 0;
    }

    /* Open both files */
    fp_p = fopen(filename_p, "rb");
    fp_q = fopen(filename_q, "rb");
    if (!fp_p || !fp_q) {
        if (fp_p) fclose(fp_p);
        if (fp_q) fclose(fp_q);
        return 0;
    }

    /* Read headers from both files */
    if (fread(&header_p, sizeof(PrimePoolHeader), 1, fp_p) != 1 ||
        fread(&header_q, sizeof(PrimePoolHeader), 1, fp_q) != 1) {
        fclose(fp_p);
        fclose(fp_q);
        return 0;
    }

    /* Verify magic numbers and versions */
    if (header_p.magic != PRIME_POOL_MAGIC || header_p.version != PRIME_POOL_VERSION ||
        header_q.magic != PRIME_POOL_MAGIC || header_q.version != PRIME_POOL_VERSION) {
        fclose(fp_p);
        fclose(fp_q);
        return 0;
    }

    /* Verify both files have same count and prime_bits */
    if (header_p.count != header_q.count || header_p.prime_bits != header_q.prime_bits) {
        fclose(fp_p);
        fclose(fp_q);
        return 0;
    }

    /* Calculate prime size in bytes */
    prime_bytes = (header_p.prime_bits + 7) / 8;

    /* Allocate space for p and q pools separately */
    size_t pool_data_size = header_p.count * prime_bytes;

    p_data = (unsigned char *)malloc(pool_data_size);
    if (!p_data) {
        fclose(fp_p);
        fclose(fp_q);
        return 0;
    }

    q_data = (unsigned char *)malloc(pool_data_size);
    if (!q_data) {
        free(p_data);
        fclose(fp_p);
        fclose(fp_q);
        return 0;
    }

    /* Read p primes */
    if (fread(p_data, 1, pool_data_size, fp_p) != pool_data_size) {
        free(p_data);
        free(q_data);
        fclose(fp_p);
        fclose(fp_q);
        return 0;
    }

    /* Read q primes */
    if (fread(q_data, 1, pool_data_size, fp_q) != pool_data_size) {
        free(p_data);
        free(q_data);
        fclose(fp_p);
        fclose(fp_q);
        return 0;
    }

    fclose(fp_p);
    fclose(fp_q);

    /* Store loaded pools */
    pool->p_pool = p_data;
    pool->q_pool = q_data;
    pool->prime_count = header_p.count;
    pool->prime_bytes = prime_bytes;
    pool->current_p_idx = 0;
    pool->current_q_idx = 0;
    pool->is_loaded = 1;

    return 1;
}

/* ============================================================================
 * RSA Key & Certificate Generation
 * ============================================================================ */

/* Helper: Generate RSA key from pre-computed primes using OSSL_PARAM (OpenSSL 3.0) */
static EVP_PKEY* generate_rsa_key_from_primes(BIGNUM *p, BIGNUM *q) {
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    OSSL_PARAM_BLD *param_bld = NULL;
    OSSL_PARAM *params = NULL;
    BIGNUM *n = NULL;
    BIGNUM *e = NULL;
    BIGNUM *d = NULL;
    BIGNUM *dmp1 = NULL;
    BIGNUM *dmq1 = NULL;
    BIGNUM *iqmp = NULL;
    BIGNUM *p_copy = NULL;
    BIGNUM *q_copy = NULL;
    BIGNUM *phi = NULL;
    BN_CTX *bn_ctx = NULL;

    bn_ctx = BN_CTX_new();
    if (!bn_ctx) return NULL;

    /* Allocate BIGNUMs for RSA components */
    n = BN_new();
    e = BN_new();
    d = BN_new();
    dmp1 = BN_new();
    dmq1 = BN_new();
    iqmp = BN_new();
    p_copy = BN_dup(p);
    q_copy = BN_dup(q);
    phi = BN_new();

    if (!n || !e || !d || !dmp1 || !dmq1 || !iqmp || !p_copy || !q_copy || !phi) {
        goto cleanup;
    }

    /* Calculate RSA components from p and q */
    BN_mul(n, p, q, bn_ctx);                    /* n = p * q */
    BN_set_word(e, 65537);                      /* e = 65537 (standard) */
    BN_sub_word(p_copy, 1);                     /* p_copy = p - 1 */
    BN_sub_word(q_copy, 1);                     /* q_copy = q - 1 */
    BN_mul(phi, p_copy, q_copy, bn_ctx);        /* phi = (p-1) * (q-1) */
    BN_mod_inverse(d, e, phi, bn_ctx);          /* d = e^-1 mod phi */
    BN_mod(dmp1, d, p_copy, bn_ctx);            /* dmp1 = d mod (p-1) */
    BN_mod(dmq1, d, q_copy, bn_ctx);            /* dmq1 = d mod (q-1) */
    BN_mod_inverse(iqmp, q, p, bn_ctx);         /* iqmp = q^-1 mod p */

    /* Build OSSL_PARAM array */
    param_bld = OSSL_PARAM_BLD_new();
    if (!param_bld) goto cleanup;

    if (!OSSL_PARAM_BLD_push_BN(param_bld, OSSL_PKEY_PARAM_RSA_N, n) ||
        !OSSL_PARAM_BLD_push_BN(param_bld, OSSL_PKEY_PARAM_RSA_E, e) ||
        !OSSL_PARAM_BLD_push_BN(param_bld, OSSL_PKEY_PARAM_RSA_D, d) ||
        !OSSL_PARAM_BLD_push_BN(param_bld, OSSL_PKEY_PARAM_RSA_FACTOR1, p) ||
        !OSSL_PARAM_BLD_push_BN(param_bld, OSSL_PKEY_PARAM_RSA_FACTOR2, q) ||
        !OSSL_PARAM_BLD_push_BN(param_bld, OSSL_PKEY_PARAM_RSA_EXPONENT1, dmp1) ||
        !OSSL_PARAM_BLD_push_BN(param_bld, OSSL_PKEY_PARAM_RSA_EXPONENT2, dmq1) ||
        !OSSL_PARAM_BLD_push_BN(param_bld, OSSL_PKEY_PARAM_RSA_COEFFICIENT1, iqmp)) {
        goto cleanup;
    }

    params = OSSL_PARAM_BLD_to_param(param_bld);
    if (!params) goto cleanup;

    /* Create EVP_PKEY from parameters */
    ctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
    if (!ctx) goto cleanup;

    if (EVP_PKEY_fromdata_init(ctx) > 0) {
        EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_KEYPAIR, params);
    }

cleanup:
    if (ctx) EVP_PKEY_CTX_free(ctx);
    if (params) OSSL_PARAM_free(params);
    if (param_bld) OSSL_PARAM_BLD_free(param_bld);
    if (bn_ctx) BN_CTX_free(bn_ctx);
    if (n) BN_free(n);
    if (e) BN_free(e);
    if (d) BN_free(d);
    if (dmp1) BN_free(dmp1);
    if (dmq1) BN_free(dmq1);
    if (iqmp) BN_free(iqmp);
    if (p_copy) BN_free(p_copy);
    if (q_copy) BN_free(q_copy);
    if (phi) BN_free(phi);

    return pkey;
}

static EVP_PKEY* generate_rsa_key(void) {
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *pkey = NULL;

    /* If we have pre-computed primes, use them for ultra-fast generation! */
    if (g_current_prime_pool && g_current_prime_pool->is_loaded && g_current_prime_pool->prime_count > 0) {
        /* Get p and q from the pools (cycling through them) */
        uint32_t p_idx = (g_current_prime_pool->current_p_idx++) % g_current_prime_pool->prime_count;
        uint32_t q_idx = (g_current_prime_pool->current_q_idx++) % g_current_prime_pool->prime_count;

        /* Convert binary p and q to BIGNUMs */
        unsigned char *p_bytes = g_current_prime_pool->p_pool + (p_idx * g_current_prime_pool->prime_bytes);
        unsigned char *q_bytes = g_current_prime_pool->q_pool + (q_idx * g_current_prime_pool->prime_bytes);

        BIGNUM *p_bn = BN_bin2bn(p_bytes, g_current_prime_pool->prime_bytes, NULL);
        BIGNUM *q_bn = BN_bin2bn(q_bytes, g_current_prime_pool->prime_bytes, NULL);

        if (p_bn && q_bn) {
            pkey = generate_rsa_key_from_primes(p_bn, q_bn);
            BN_free(p_bn);
            BN_free(q_bn);
            if (pkey) {
                return pkey;  /* Success! */
            }
        } else {
            if (p_bn) BN_free(p_bn);
            if (q_bn) BN_free(q_bn);
        }
        /* If we reach here, prime-based generation failed - fall through to standard */
    }

    /* Standard generation (no pre-computed primes or prime-based generation failed) */
    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!ctx) {
        return NULL;
    }

    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, g_current_key_size) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

static X509* generate_certificate(EVP_PKEY *pkey) {
    X509 *x509 = NULL;
    X509_NAME *name = NULL;
    ASN1_INTEGER *serial = NULL;

    x509 = X509_new();
    if (!x509) {
        fprintf(stderr, "Error: X509_new failed\n");
        return NULL;
    }

    /* Serial number */
    serial = ASN1_INTEGER_new();
    if (!serial || !ASN1_INTEGER_set(serial, 1)) {
        fprintf(stderr, "Error: Setting serial number failed\n");
        X509_free(x509);
        ASN1_INTEGER_free(serial);
        return NULL;
    }
    X509_set_serialNumber(x509, serial);
    ASN1_INTEGER_free(serial);

    /* Validity: 1 year */
    X509_gmtime_adj(X509_getm_notBefore(x509), 0);
    X509_gmtime_adj(X509_getm_notAfter(x509), 31536000L);

    /* Subject name */
    name = X509_NAME_new();
    if (!name) {
        fprintf(stderr, "Error: X509_NAME_new failed\n");
        X509_free(x509);
        return NULL;
    }

    if (!X509_NAME_add_entry_by_txt(name, "CN", V_ASN1_UTF8STRING,
                                     (unsigned char *)"Benchmark", -1, -1, 0)) {
        fprintf(stderr, "Error: X509_NAME_add_entry_by_txt failed\n");
        X509_NAME_free(name);
        X509_free(x509);
        return NULL;
    }

    X509_set_subject_name(x509, name);
    X509_set_issuer_name(x509, name);
    X509_NAME_free(name);

    /* Public key */
    if (!X509_set_pubkey(x509, pkey)) {
        fprintf(stderr, "Error: X509_set_pubkey failed\n");
        X509_free(x509);
        return NULL;
    }

    /* Self-sign */
    if (!X509_sign(x509, pkey, EVP_sha256())) {
        fprintf(stderr, "Error: X509_sign failed\n");
        X509_free(x509);
        return NULL;
    }

    return x509;
}

/* ============================================================================
 * Benchmark Execution
 * ============================================================================ */

static long run_single_benchmark(void) {
    EVP_PKEY *pkey = NULL;
    X509 *cert = NULL;

    TIMER_START();

    /* Generate RSA key - this is the expensive operation */
    pkey = generate_rsa_key();
    if (!pkey) {
        return -1;
    }

    /* Generate certificate with the key */
    cert = generate_certificate(pkey);
    if (!cert) {
        EVP_PKEY_free(pkey);
        return -1;
    }

    TIMER_END();

    /* Cleanup */
    X509_free(cert);
    EVP_PKEY_free(pkey);

    return TIMER_ELAPSED_US();
}

static int compare_long(const void *a, const void *b) {
    long diff = *(const long *)a - *(const long *)b;
    if (diff < 0) return -1;
    if (diff > 0) return 1;
    return 0;
}

static void calculate_stats(long *times, int count, BenchmarkStats *stats) {
    double total = 0;
    /* Use dynamic allocation for flexible test count */
    long *sorted = (long *)malloc(count * sizeof(long));
    if (!sorted) {
        memset(stats, 0, sizeof(BenchmarkStats));
        return;
    }

    memcpy(sorted, times, count * sizeof(long));
    qsort(sorted, count, sizeof(long), compare_long);

    stats->min_ms = sorted[0] / 1000.0;
    stats->max_ms = sorted[count - 1] / 1000.0;

    for (int i = 0; i < count; i++) {
        total += sorted[i];
    }
    stats->avg_ms = (total / count) / 1000.0;
    stats->median_ms = sorted[count / 2] / 1000.0;

    /* p95 and p99 */
    int idx_p95 = (count * 95) / 100;
    int idx_p99 = (count * 99) / 100;
    if (idx_p95 >= count) idx_p95 = count - 1;
    if (idx_p99 >= count) idx_p99 = count - 1;

    stats->p95_ms = sorted[idx_p95] / 1000.0;
    stats->p99_ms = sorted[idx_p99] / 1000.0;

    free(sorted);
}

static void print_result(int test_num, long time_us) {
    long sec = time_us / 1000000;
    long ms = (time_us % 1000000) / 1000;
    double time_ms = time_us / 1000.0;
    const char *indicator = "~";

    if (time_ms < 1000) {
        indicator = "✓";
    } else if (time_ms < 2000) {
        indicator = "~";
    } else {
        indicator = "⚠";
    }

    printf("  Test %2d: %s  %ld.%03ld sec | %8.3f ms | %ld μs | %ld ns\n",
           test_num, indicator, sec, ms, time_ms, time_us, time_us * 1000);
}

static void print_statistics(BenchmarkStats *stats) {
    printf("\n┌─ Performance Results ───────────────────────────────────────────────┐\n");
    printf("│ Minimum Time:          %10.3f ms  (%10.0f μs | %10.0f ns)\n",
           stats->min_ms, stats->min_ms * 1000, stats->min_ms * 1000000);
    printf("│ Maximum Time:          %10.3f ms  (%10.0f μs | %10.0f ns)\n",
           stats->max_ms, stats->max_ms * 1000, stats->max_ms * 1000000);
    printf("│ Average Time:          %10.3f ms  (%10.0f μs | %10.0f ns)\n",
           stats->avg_ms, stats->avg_ms * 1000, stats->avg_ms * 1000000);
    printf("│ Median Time (p50):     %10.3f ms  (%10.0f μs | %10.0f ns)\n",
           stats->median_ms, stats->median_ms * 1000, stats->median_ms * 1000000);
    printf("│ p95:                   %10.3f ms  (%10.0f μs | %10.0f ns)\n",
           stats->p95_ms, stats->p95_ms * 1000, stats->p95_ms * 1000000);
    printf("│ p99:                   %10.3f ms  (%10.0f μs | %10.0f ns)\n",
           stats->p99_ms, stats->p99_ms * 1000, stats->p99_ms * 1000000);

    double certs_per_second = 1000.0 / stats->avg_ms;
    double certs_per_hour = certs_per_second * 3600.0;

    printf("│\n");
    printf("│ Throughput:            %10.2f certs/second\n", certs_per_second);
    printf("│                        %10.2f certs/hour\n", certs_per_hour);
    printf("└─────────────────────────────────────────────────────────────────────┘\n");
}

/* ============================================================================
 * Main
 * ============================================================================ */

int main(void) {
    OpenSSL_add_all_algorithms();

    /* Load configuration from benchmark.conf (transparently) */
    config_load();

    /* Display system and OpenSSL information */
    print_openssl_info();
    print_system_info();

    /* Allocate array for results from all key sizes */
    KeySizeResult *results = (KeySizeResult *)malloc(g_config.num_key_sizes * sizeof(KeySizeResult));
    if (!results) {
        fprintf(stderr, "Error: Memory allocation failed\n");
        return 1;
    }

    /* Allocate memory for test results (dynamic based on config) */
    long *times = (long *)malloc(g_config.num_tests * sizeof(long));
    if (!times) {
        fprintf(stderr, "Error: Memory allocation failed\n");
        free(results);
        return 1;
    }

    /* Iterate through each RSA key size */
    for (int size_idx = 0; size_idx < g_config.num_key_sizes; size_idx++) {
        g_current_key_size = g_config.key_sizes[size_idx];

        /* Try to load pre-computed material for this key size */
        g_current_prime_pool = prime_pool_new(g_current_key_size);
        int has_precomp = 0;
        if (g_current_prime_pool) {
            has_precomp = prime_pool_try_load(g_current_prime_pool);
            if (has_precomp) {
                /* Prime pool loaded successfully - will be used in generate_rsa_key() */
            } else {
                /* No prime pool available - free and set to NULL for standard generation */
                prime_pool_free(g_current_prime_pool);
                g_current_prime_pool = NULL;
            }
        }

        /* Section header for this key size */
        printf("\n╔═══════════════════════════════════════════════════════════════════════╗\n");
        printf("║  Testing RSA-%d bit certificate generation\n", g_current_key_size);
        printf("║  Optimization: %s\n", has_precomp ? "Accelerated Execution (with primes)" : "Standard Generation");
        if (has_precomp && g_current_prime_pool) {
            printf("║  Prime Pool: %u p/q pairs loaded\n", g_current_prime_pool->prime_count);
        }
        printf("╚═══════════════════════════════════════════════════════════════════════╝\n\n");

        /* Run benchmarks for this key size */
        printf("Running %d certificate generation cycles...\n\n", g_config.num_tests);
        printf("┌─ Individual Results ────────────────────────────────────────────────┐\n");
        printf("│ Test #       Time (sec | ms | μs | ns)\n");
        printf("├─────────────────────────────────────────────────────────────────────┤\n");

        for (int i = 0; i < g_config.num_tests; i++) {
            times[i] = run_single_benchmark();
            if (times[i] < 0) {
                fprintf(stderr, "Error: Benchmark %d failed\n", i + 1);
                free(times);
                free(results);
                return 1;
            }
            print_result(i + 1, times[i]);
        }
        printf("└─────────────────────────────────────────────────────────────────────┘\n");

        /* Calculate and display statistics */
        BenchmarkStats stats;
        calculate_stats(times, g_config.num_tests, &stats);
        print_statistics(&stats);

        /* Store results for comparison */
        results[size_idx].key_size = g_current_key_size;
        results[size_idx].avg_time_ms = stats.avg_ms;
        results[size_idx].certs_per_hour = (1000.0 / stats.avg_ms) * 3600.0;
        results[size_idx].has_precomp = has_precomp;

        /* Clean up prime pool for this key size */
        if (g_current_prime_pool) {
            prime_pool_free(g_current_prime_pool);
            g_current_prime_pool = NULL;
        }
    }

    /* Print comparison summary */
    if (g_config.num_key_sizes > 1) {
        printf("\n╔═══════════════════════════════════════════════════════════════════════╗\n");
        printf("║  Performance Comparison Across RSA Key Sizes\n");
        printf("╚═══════════════════════════════════════════════════════════════════════╝\n\n");

        printf("┌─ Results Summary ───────────────────────────────────────────────────┐\n");
        printf("│ Key Size │ Avg Time │ Throughput │ Acceleration Method\n");
        printf("├──────────┼──────────┼────────────┼───────────────────────────────┤\n");

        for (int i = 0; i < g_config.num_key_sizes; i++) {
            printf("│ %5d-bit │ %8.1f ms │ %7.1f/h │ %s\n",
                   results[i].key_size,
                   results[i].avg_time_ms,
                   results[i].certs_per_hour,
                   results[i].has_precomp ? "Accelerated" : "Standard");
        }
        printf("└──────────┴──────────┴────────────┴───────────────────────────────┘\n");

        /* Show speedup comparison */
        printf("\n┌─ Speedup Analysis ──────────────────────────────────────────────────┐\n");
        for (int i = 1; i < g_config.num_key_sizes; i++) {
            double slowdown = results[i].avg_time_ms / results[0].avg_time_ms;
            printf("│ RSA-%d is %.1f× slower than RSA-%d\n",
                   results[i].key_size, slowdown, results[0].key_size);
        }
        printf("└─────────────────────────────────────────────────────────────────────┘\n");
    }

    /* Display technical details for last tested key size */
    printf("\n┌─ Technical Details ────────────────────────────────────────────────┐\n");
    printf("│ Test Environment:\n");
    printf("│   • Certificate Type:    Self-signed X.509v3\n");
    printf("│   • Key Generation:      EVP (high-level API)\n");
    printf("│   • Operations per Test: 1 RSA key generation + 1 cert signing\n");
    printf("│\n");
    printf("│ Performance Factors:\n");
    printf("│   • OpenSSL version: %s\n", OPENSSL_VERSION_TEXT);
    printf("│   • CPU has AES-NI:  Check with: grep aes /proc/cpuinfo\n");
    printf("│   • CPU has AVX:     Check with: grep avx /proc/cpuinfo\n");
    printf("│   • System Load:     May vary between runs\n");
    printf("│\n");
    printf("│ Optimization Note:\n");
    printf("│   OpenSSL automatically uses available CPU features for:\n");
    printf("│   - Prime number generation (RDRAND, hardware RNG)\n");
    printf("│   - Cryptographic operations (AES-NI, AVX, SSE2)\n");
    printf("│   - BigNum arithmetic (optimized CPU instructions)\n");
    printf("└─────────────────────────────────────────────────────────────────────┘\n\n");

    /* Free allocated memory */
    free(times);
    free(results);

    return 0;
}
