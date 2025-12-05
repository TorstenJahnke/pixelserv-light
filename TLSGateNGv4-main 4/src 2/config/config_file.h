/* TLSGateNX - Configuration File Parser
 * Copyright (C) 2025 Torsten Jahnke
 *
 * Master configuration: /etc/tlsgateNG/tlsgateNG.conf (Debian)
 *                       /usr/local/etc/tlsgateNG/tlsgateNG.conf (BSD)
 *
 * Format (INI-style):
 *   [version]
 *   2.0.0
 *   [prime]
 *   path=/usr/local/etc/TLSGateNX/server/primes
 *   [keypool]
 *   path=/usr/local/etc/TLSGateNX/server/keypool
 *   [license]
 *   key=... (optional, for commercial deployments)
 *
 * Critical: Version must match EXACTLY or server stops!
 * Empty paths = feature disabled (e.g., for testing)
 * If config missing = auto-create empty template
 */

#ifndef CONFIG_FILE_H
#define CONFIG_FILE_H

#include <stdbool.h>
#include <stddef.h>
#include "version.h"

/* None-SNI mode constants */
#define NONE_SNI_MODE_AUTO     0  /* default_domain = current SNI (realtime sync) */
#define NONE_SNI_MODE_STATIC   1  /* default_domain = fixed value from config */
#define NONE_SNI_MODE_DISABLED 2  /* SNI-less clients are rejected */

/* Configuration file data */
typedef struct {
    /* Version (from [version] section) */
    int version_major;
    int version_minor;
    int version_patch;
    int version_build;

    /* Prime pool (from [prime] section) */
    char prime_path[4096];        /* Empty = no prime pool */

    /* Keypool (from [keypool] section) */
    char keypool_path[4096];      /* Empty = no keypool */

    /* Backup (from [backup] section) */
    bool backup_enabled;          /* Enable automatic backup */
    bool backup_master;           /* Master for backup management (default: true) */
                                  /* Only ONE instance should run backups when running multiple servers */
    char backup_path[4096];       /* Backup directory (empty = disabled) */
    bool backup_encrypt;          /* Encrypt backups with AES-256-GCM */
    char backup_ca_key_path[4096]; /* CA private key path for encryption */
    unsigned int backup_curve;    /* Password extraction curve (LLPPXX format) */

    /* License (from [license] section - optional) */
    char license_key[512];        /* Commercial license key (empty = community edition) */

    /* Legacy (from [legacy] section) */
    bool legacy_crypto;           /* Enable legacy/weak crypto (RSA-1024/2048, SHA1) */

    /* None-SNI handling (from [none-sni] section) */
    int default_domain_mode;      /* 0=auto (SNI-sync), 1=static, 2=disabled */
    char default_domain[256];     /* Default domain for mode=static (e.g., "firma.local") */

    /* Certificate (from [certificate] section) */
    bool enable_wildcards;        /* Generate wildcard certificates (default: true) */
    bool enable_san;              /* Add Subject Alternative Names (default: true) */
    int validity_days;            /* Certificate validity period in days (default: 200, max: 398) */
    bool cache_certificates;      /* Enable certificate caching (default: true) */
    char second_level_tld_file[4096]; /* Path to 2nd-level TLDs config file (empty = auto) */
    char silent_block_file[4096]; /* Path to silent-blocks.conf (Poolgen loads into SHM) */

    /* HTML (from [html] section) */
    char default_html_path[4096];  /* Path to default HTML binary (empty = use compiled fallback) */
    bool any_responses;            /* If true: ALL responses get HTTP 200 + HTML (Anti-Phishing mode) */

    /* Server (from [server] section) */
    char listen_address[256];      /* IP address to bind to (default: 127.0.0.1) */
    int http_port;                 /* HTTP port (default: 80, 0 = disabled) */
    int https_port;                /* HTTPS port (default: 443, 0 = disabled) */
    int auto_port;                 /* AUTO port with MSG_PEEK (default: 8080, 0 = disabled) */
    int workers;                   /* Number of worker threads (default: 4) */
    int max_connections;           /* Max connections per worker (default: 1000) */

    /* Runtime (from [runtime] section) */
    bool daemonize;                /* Run in background (default: false) */
    bool verbose;                  /* Enable DEBUG logging (default: false) */
    char run_user[256];            /* Drop privileges to this user (empty = no drop) */
    char run_group[256];           /* Drop privileges to this group (empty = no drop) */

    /* Directories (from [directories] section) */
    char ca_dir[4096];             /* Base CA directory (e.g., /opt/TLSGateNX) */
    char cert_cache_dir[4096];     /* Certificate cache directory (optional override) */
    char bundles_dir[4096];        /* Pre-generated key bundles directory */

    /* Pool (from [pool] section) */
    int pool_size;                 /* Keypool size (default: 100, range: 1-10000000) */
    bool use_shm;                  /* Use shared memory keypool (default: false) */
    bool poolkeygen_mode;          /* Run as pure keypool generator (default: false) */
    char force_algorithm[64];      /* Force single algorithm (e.g., RSA-3072, ECDSA-P256) */
    size_t shm_certcache_capacity; /* SHM cert index capacity (default: 1000000 = 1M domains) */

    /* Algorithm distribution (percentages, must sum to 100) */
    int algo_rsa_3072_percent;     /* RSA-3072 percentage (default: 30) */
    int algo_ecdsa_p256_percent;   /* ECDSA-P256 percentage (default: 60) */
    int algo_sm2_percent;          /* SM2 percentage (default: 10) */

    /* Index (from [index] section) */
    bool index_master;             /* Master for index management (default: true) */
                                   /* Only ONE instance should be master when running multiple servers */

    /* Framework Logging (from [framework-logging] section) */
    bool security_logging;         /* Enable security intelligence logging (default: true) */
    char security_log_path[4096];  /* Framework log path (default: /var/log/tlsgateNG/framework) */
                                   /* Files: framework.0.log, framework.1.log, ... */

    /* Log rotation settings */
    size_t log_file_size;          /* Max size per log file in bytes (default: 100MB) */
    size_t log_total_size;         /* Max total size of all logs in bytes (default: 20GB) */
    int log_max_files;             /* Max number of log files (0 = use log_total_size) */

    /* Internal state */
    char config_path[4096];       /* Path where config was loaded from */
    bool loaded;                  /* Was config successfully loaded? */
} config_file_t;

/* Load configuration from file
 *
 * Loads from OS-specific path:
 *   - Linux/Debian: /etc/tlsgateNG/tlsgateNG.conf
 *   - BSD/FreeBSD:  /usr/local/etc/tlsgateNG/tlsgateNG.conf
 *
 * If file doesn't exist: Creates empty template automatically
 *
 * Parameters:
 *   allow_autofix - If true, automatically fix version mismatches
 *                   If false, exit on version mismatch
 *
 * Returns:
 *   config_file_t* on success
 *   NULL on parse error
 *
 * Exits immediately if:
 *   - Version mismatch (only if allow_autofix=false)
 *   - Cannot create config directory
 */
config_file_t* config_file_load(bool allow_autofix);

/* Load configuration from specific file path
 *
 * Parameters:
 *   path - Full path to config file (e.g., /etc/tlsgateNG/custom.conf)
 *   allow_autofix - If true, automatically fix version mismatches
 *
 * Returns:
 *   config_file_t* on success
 *   NULL on parse error
 */
config_file_t* config_file_load_path(const char *path, bool allow_autofix);

/* Free configuration */
void config_file_free(config_file_t *config);

/* Print configuration (for debugging) */
void config_file_print(const config_file_t *config);

/* Get OS-specific config directory */
const char* config_get_dir(void);

/* Get full config file path */
const char* config_get_path(void);

#endif /* CONFIG_FILE_H */
