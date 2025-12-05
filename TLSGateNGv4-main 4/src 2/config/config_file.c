/* TLSGateNX - Configuration File Parser
 * Copyright (C) 2025 Torsten Jahnke
 */

#include "config/config_file.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <limits.h>
#include <time.h>

/* Get OS-specific config directory */
const char* config_get_dir(void) {
    struct utsname u;
    uname(&u);

    /* BSD systems use /usr/local/etc */
    if (strstr(u.sysname, "BSD") || strcmp(u.sysname, "Darwin") == 0) {
        return "/usr/local/etc/tlsgateNG";
    }

    /* Linux/Debian use /etc */
    return "/etc/tlsgateNG";
}

/* Get full config file path */
const char* config_get_path(void) {
    static char path[4096];
    snprintf(path, sizeof(path), "%s/tlsgateNG.conf", config_get_dir());
    return path;
}

/* Create standard directory structure */
static void create_standard_directories(void) {
    const char *base_dir = config_get_dir();
    char path[4096];

    /* List of directories to create */
    const char *dirs[] = {
        "primes",
        "bundles",
        "backup",
        "working",
        NULL
    };

    for (int i = 0; dirs[i] != NULL; i++) {
        snprintf(path, sizeof(path), "%s/%s", base_dir, dirs[i]);

        /* Skip if already exists */
        if (access(path, F_OK) == 0) {
            continue;
        }

        /* Create directory */
        if (mkdir(path, 0755) == 0) {
            printf("INFO: Created directory: %s\n", path);
        } else {
            fprintf(stderr, "WARNING: Cannot create directory: %s\n", path);
        }
    }
}

/* Create certificate directory structure in working directory
 *
 * Structure:
 *   working/
 *   ├── RSA/
 *   │   ├── rootCA/    (CA certs - root:root 0700)
 *   │   ├── certs/     (generated certs - writable)
 *   │   └── index/     (cert index - writable)
 *   ├── ECDSA/
 *   │   └── ...
 *   ├── SM2/
 *   │   └── ...
 *   └── LEGACY/
 *       └── ...
 */
static void create_cert_directories(void) {
    const char *base_dir = config_get_dir();

    /* Validate base_dir length (max suffix: /working/LEGACY/rootCA = 21 chars) */
    size_t base_len = base_dir ? strlen(base_dir) : 0;
    if (base_len == 0 || base_len > 4096 - 32) {
        fprintf(stderr, "WARNING: Config directory path too long for cert structure\n");
        return;
    }

    /* Certificate algorithm types */
    const char *cert_types[] = { "RSA", "ECDSA", "SM2", "LEGACY", NULL };
    const char *subdirs[] = { "rootCA", "certs", "index", NULL };

    /* Base path: /etc/tlsgateNG/working */
    char working_dir[4096];
    snprintf(working_dir, sizeof(working_dir), "%s/working", base_dir);
    size_t working_len = strlen(working_dir);

    /* Check if RSA directory already exists (skip if structure already created) */
    char path[4096];
    if (working_len < sizeof(path) - 8) {
        snprintf(path, sizeof(path), "%s/RSA", working_dir);
        if (access(path, F_OK) == 0) {
            return;  /* Structure already exists */
        }
    }

    printf("INFO: Creating certificate directory structure...\n");

    for (int i = 0; cert_types[i] != NULL; i++) {
        /* Create algorithm directory (RSA/, ECDSA/, etc.) */
        int n = snprintf(path, sizeof(path), "%s/%s", working_dir, cert_types[i]);
        if (n < 0 || (size_t)n >= sizeof(path)) continue;

        if (mkdir(path, 0755) == 0) {
            printf("INFO: Created directory: %s\n", path);
        } else if (errno != EEXIST) {
            fprintf(stderr, "WARNING: Cannot create directory: %s\n", path);
            continue;
        }

        /* Create subdirectories (rootCA/, certs/, index/) */
        for (int j = 0; subdirs[j] != NULL; j++) {
            n = snprintf(path, sizeof(path), "%s/%s/%s", working_dir, cert_types[i], subdirs[j]);
            if (n < 0 || (size_t)n >= sizeof(path)) continue;

            if (mkdir(path, 0755) == 0) {
                /* Set appropriate permissions */
                if (strcmp(subdirs[j], "rootCA") == 0) {
                    chmod(path, 0700);  /* rootCA: restrictive for CA keys */
                } else {
                    chmod(path, 0755);  /* certs/index: readable */
                }
            } else if (errno != EEXIST) {
                fprintf(stderr, "WARNING: Cannot create directory: %s\n", path);
            }
        }
    }

    printf("INFO: Certificate structure created in: %s\n", working_dir);
    printf("      Install your CA certificates in the rootCA/ subdirectories.\n");
}

/* Create silent-blocks.conf template */
static int create_silent_blocks_template(void) {
    char path[4096];
    FILE *fp;
    const char *dir = config_get_dir();

    snprintf(path, sizeof(path), "%s/silent-blocks.conf", dir);

    /* Skip if file already exists */
    if (access(path, F_OK) == 0) {
        return 0;
    }

    fp = fopen(path, "w");
    if (!fp) {
        fprintf(stderr, "WARNING: Cannot create silent-blocks.conf: %s\n", path);
        return -1;
    }

    fprintf(fp, "# TLSGateNX Silent Blocker Configuration\n");
    fprintf(fp, "# Based on Mokku's Hard2Block approach\n");
    fprintf(fp, "#\n");
    fprintf(fp, "# Format: domain path-pattern delay(ms) status\n");
    fprintf(fp, "#\n");
    fprintf(fp, "# domain:       Exact domain or wildcard (*.example.com)\n");
    fprintf(fp, "# path-pattern: Path with (*) wildcards for segments\n");
    fprintf(fp, "# delay:        Delay in milliseconds before response (0 = instant)\n");
    fprintf(fp, "# status:       HTTP status code (usually 204 No Content)\n");
    fprintf(fp, "#\n");
    fprintf(fp, "# Pattern Syntax:\n");
    fprintf(fp, "#   (*) = matches one path segment (anything except /)\n");
    fprintf(fp, "#   /(*)/(*)/(*) = EXACTLY 3 path segments required\n");
    fprintf(fp, "#\n");
    fprintf(fp, "# Examples:\n");
    fprintf(fp, "#   /(*)/(*)/(*) → matches /a/b/c (3 segments, EXACT!)\n");
    fprintf(fp, "#   /(*)/(*)     → matches /a/b (2 segments, EXACT!)\n");
    fprintf(fp, "#   /(*)         → matches /a (1 segment, EXACT!)\n");
    fprintf(fp, "#\n");
    fprintf(fp, "# Wildcard Subdomains:\n");
    fprintf(fp, "#   *.example.com → matches any.example.com, sub.example.com, etc.\n");
    fprintf(fp, "#   example.com   → matches only example.com (not subdomains)\n\n");
    fprintf(fp, "# ============================================================================\n");
    fprintf(fp, "# Tracking Domains (Examples - uncomment to enable)\n");
    fprintf(fp, "# ============================================================================\n\n");
    fprintf(fp, "# html-load.com - Malvertising/Tracking\n");
    fprintf(fp, "# html-load.com /(*)/(*)/(*)/(*)/(*)/(*)/(*) 0 204\n");
    fprintf(fp, "# html-load.com /(*)/(*) 0 204\n\n");
    fprintf(fp, "# Wildcard subdomains for html-load.com\n");
    fprintf(fp, "# *.html-load.com /(*)/(*)/(*)/(*)/(*)/(*)/(*) 0 204\n");
    fprintf(fp, "# *.html-load.com /(*)/(*)/(*)/(*)/(*)/(*)/(*)/(*) 0 204\n\n");
    fprintf(fp, "# Google Analytics\n");
    fprintf(fp, "# google-analytics.com /(*) 0 204\n");
    fprintf(fp, "# google-analytics.com /(*)/(*) 0 204\n");
    fprintf(fp, "# *.google-analytics.com /(*) 0 204\n\n");
    fprintf(fp, "# Facebook Pixel\n");
    fprintf(fp, "# facebook.com /(*)/(*) 0 204\n\n");
    fprintf(fp, "# DoubleClick\n");
    fprintf(fp, "# doubleclick.net /(*) 0 204\n");
    fprintf(fp, "# doubleclick.net /(*)/(*) 0 204\n");
    fprintf(fp, "# *.doubleclick.net /(*) 0 204\n\n");
    fprintf(fp, "# ============================================================================\n");
    fprintf(fp, "# Notes\n");
    fprintf(fp, "# ============================================================================\n");
    fprintf(fp, "#\n");
    fprintf(fp, "# - Lines starting with # are comments\n");
    fprintf(fp, "# - Empty lines are ignored\n");
    fprintf(fp, "# - Maximum 1024 rules supported\n");
    fprintf(fp, "# - Rules are checked in order (first match wins)\n");
    fprintf(fp, "# - Segment count must match EXACTLY (no \"minimum\" matching)\n");
    fprintf(fp, "# - Config is loaded at startup, reload with SIGHUP or restart\n");
    fprintf(fp, "#\n");
    fprintf(fp, "# Usage:\n");
    fprintf(fp, "#   1. Uncomment rules you want to enable\n");
    fprintf(fp, "#   2. Add your own rules following the format above\n");
    fprintf(fp, "#   3. Restart TLSGateNX to load changes\n");
    fprintf(fp, "#\n");
    fprintf(fp, "# Debugging:\n");
    fprintf(fp, "#   Check logs for:\n");
    fprintf(fp, "#     \"Silent blocker: Loaded N rules from %s\"\n", path);
    fprintf(fp, "#     \"Silent blocker: Config file not found (...), disabled\"\n");
    fprintf(fp, "#\n");

    fclose(fp);

    printf("INFO: Created silent-blocks.conf template: %s\n", path);
    return 0;
}

/* Create empty second-level-tlds.conf template */
static int create_second_level_tlds_template(void) {
    char path[4096];
    FILE *fp;
    const char *dir = config_get_dir();

    snprintf(path, sizeof(path), "%s/second-level-tlds.conf", dir);

    /* Skip if file already exists */
    if (access(path, F_OK) == 0) {
        return 0;
    }

    fp = fopen(path, "w");
    if (!fp) {
        fprintf(stderr, "WARNING: Cannot create second-level-tlds.conf: %s\n", path);
        return -1;
    }

    fprintf(fp, "# TLSGateNX Second-Level TLD List\n");
    fprintf(fp, "# ==========================================\n");
    fprintf(fp, "#\n");
    fprintf(fp, "# This file contains all valid TLDs (both 1st-level and 2nd-level).\n");
    fprintf(fp, "# The server automatically filters and uses only 2nd-level TLDs\n");
    fprintf(fp, "# (those containing a dot, like .co.uk, .com.au, etc.)\n");
    fprintf(fp, "#\n");
    fprintf(fp, "# Format: One TLD per line, starting with a dot\n");
    fprintf(fp, "# Examples:\n");
    fprintf(fp, "#   .com        (1st-level TLD - will be skipped)\n");
    fprintf(fp, "#   .co.uk      (2nd-level TLD - will be loaded)\n");
    fprintf(fp, "#   .com.au     (2nd-level TLD - will be loaded)\n");
    fprintf(fp, "#\n");
    fprintf(fp, "# To populate this file with all TLDs:\n");
    fprintf(fp, "#   Download from IANA or copy from repository\n");
    fprintf(fp, "#\n");
    fprintf(fp, "# ==========================================\n");
    fprintf(fp, "\n");
    fprintf(fp, "# Add your TLDs below (one per line)\n");
    fprintf(fp, "# Uncomment and add as needed:\n");
    fprintf(fp, "\n");
    fprintf(fp, "# .co.uk\n");
    fprintf(fp, "# .com.au\n");
    fprintf(fp, "# .ac.uk\n");
    fprintf(fp, "# .gov.uk\n");
    fprintf(fp, "\n");

    fclose(fp);

    printf("INFO: Created second-level-tlds.conf template: %s\n", path);
    printf("      This file is currently empty. To use 2nd-level TLDs:\n");
    printf("      1. Download full TLD list from IANA\n");
    printf("      2. Or copy from repository: cp tld-liste %s/second-level-tlds.conf\n", dir);
    return 0;
}

/* Create empty config template */
static int create_empty_config(const char *path) {
    FILE *fp;
    const char *dir = config_get_dir();

    /* Create directory if needed */
    if (access(dir, F_OK) != 0) {
        if (mkdir(dir, 0755) != 0) {
            fprintf(stderr, "ERROR: Cannot create config directory: %s\n", dir);
            fprintf(stderr, "Try: sudo mkdir -p %s\n", dir);
            exit(1);
        }
        printf("INFO: Created config directory: %s\n", dir);
    }

    /* Create empty config file */
    fp = fopen(path, "w");
    if (!fp) {
        fprintf(stderr, "ERROR: Cannot create config file: %s\n", path);
        fprintf(stderr, "Try: sudo touch %s && sudo chmod 644 %s\n", path, path);
        exit(1);
    }

    fprintf(fp, "# TLSGate NG Master Configuration\n");
    fprintf(fp, "# Auto-generated empty template\n");
    fprintf(fp, "# ==========================================\n\n");

    fprintf(fp, "[version]\n");
    fprintf(fp, "# Format: MAJOR.MINOR.PATCH.BUILD (must match exactly!)\n");
    fprintf(fp, "# Leave empty to skip version check (not recommended)\n");
    fprintf(fp, "#%d.%d.%d.%d\n\n",
            TLSGATENG_VERSION_MAJOR, TLSGATENG_VERSION_MINOR,
            TLSGATENG_VERSION_PATCH, TLSGATENG_VERSION_BUILD);

    fprintf(fp, "[prime]\n");
    fprintf(fp, "# Prime pool directory (leave empty to disable)\n");
    fprintf(fp, "# Auto-created at: %s/primes\n", dir);
    fprintf(fp, "#path=%s/primes\n\n", dir);

    fprintf(fp, "[keypool]\n");
    fprintf(fp, "# Keypool directory (leave empty to disable)\n");
    fprintf(fp, "# Auto-created at: %s/bundles\n", dir);
    fprintf(fp, "#path=%s/bundles\n\n", dir);

    fprintf(fp, "[backup]\n");
    fprintf(fp, "# Automatic keypool backup (every 30 minutes)\n");
    fprintf(fp, "# Enable: Set to 'true' or disable it with 'false'\n");
    fprintf(fp, "#enable=false\n\n");
    fprintf(fp, "# Backup directory path (required if enabled)\n");
    fprintf(fp, "# Auto-created at: %s/backup\n", dir);
    fprintf(fp, "#path=%s/backup\n\n", dir);
    fprintf(fp, "# Encryption: Encrypt backups with AES-256-GCM\n");
    fprintf(fp, "# Set to 'true' or 'false' (requires ca_key and secret)\n");
    fprintf(fp, "#encrypt=false\n\n");
    fprintf(fp, "# CA private key path (for backup encryption)\n");
    fprintf(fp, "# Usually same as server CA key\n");
    fprintf(fp, "#ca_key=/etc/tlsgateNG/certs/ca-key.pem\n\n");
    fprintf(fp, "# Elliptic curve parameter for key derivation (format: LLPPXX)\n");
    fprintf(fp, "# LL=line (2-9), PP=position (5-30), XX=length (16-24)\n");
    fprintf(fp, "# Example: 30916 = Line 3, Position 09, Length 16\n");
    fprintf(fp, "# Generate: python3 -c 'import random; l=random.randint(2,9); p=random.randint(5,30); n=random.randint(16,24); print(f\"{l*10000+p*100+n}\")'\n");
    fprintf(fp, "#curve=0\n\n");

    fprintf(fp, "[legacy]\n");
    fprintf(fp, "# Legacy/Weak Cryptography Support\n");
    fprintf(fp, "# WARNING: Enables insecure algorithms (RSA-1024/2048, SHA1)\n");
    fprintf(fp, "# Only use for: legacy clients, honeypot, testing\n");
    fprintf(fp, "# If false, legacy crypto is completely disabled (default)\n");
    fprintf(fp, "#legacy-crypto=false\n\n");
    fprintf(fp, "# Default domain for legacy clients without SNI support\n");
    fprintf(fp, "# Used when client doesn't send Server Name Indication (SNI)\n");
    fprintf(fp, "# Required for: MS-DOS, Windows 95/98, old browsers, AS/400\n");
    fprintf(fp, "#default-domain=default.local\n\n");

    /* Certificate Generation Options */
    fprintf(fp, "[certificate]\n");
    fprintf(fp, "# Certificate Generation Options\n");
    fprintf(fp, "# These settings control how on-demand certificates are generated\n\n");
    fprintf(fp, "# Enable Wildcard Certificates\n");
    fprintf(fp, "# When enabled: www.example.com → generates WILDCARD cert for *.example.com\n");
    fprintf(fp, "#               CN=example.com, SAN=DNS:example.com,DNS:*.example.com\n");
    fprintf(fp, "# When disabled: www.example.com → generates EXACT cert for www.example.com\n");
    fprintf(fp, "#                CN=www.example.com, SAN=DNS:www.example.com\n");
    fprintf(fp, "# NOTE: If wildcard generation fails, each subdomain needs separate cert\n");
    fprintf(fp, "# Default: true\n");
    fprintf(fp, "#enable-wildcards=true\n\n");
    fprintf(fp, "# Enable Subject Alternative Names (SAN)\n");
    fprintf(fp, "# When enabled: Adds DNS entries for all domain variations\n");
    fprintf(fp, "#   Example: www.example.com → DNS:www.example.com,DNS:*.example.com\n");
    fprintf(fp, "# When disabled: Only CN is set, no SAN extension (VERY OLD CLIENTS ONLY)\n");
    fprintf(fp, "# WARNING: Modern browsers REQUIRE SAN - only disable for legacy systems!\n");
    fprintf(fp, "# Default: true\n");
    fprintf(fp, "#enable-san=true\n\n");
    fprintf(fp, "# Certificate Validity Period (in days)\n");
    fprintf(fp, "# Browser CA Baseline: 398 days maximum (enforced since 2020)\n");
    fprintf(fp, "# Examples:\n");
    fprintf(fp, "#   90   = 3 months (good for frequently regenerated certs)\n");
    fprintf(fp, "#   200  = Conservative, browser compatible (default)\n");
    fprintf(fp, "#   365  = 1 year (long-lived certificates)\n");
    fprintf(fp, "# Range: 1-398\n");
    fprintf(fp, "# Default: 200\n");
    fprintf(fp, "#validity-days=200\n\n");
    fprintf(fp, "# 2nd-Level TLD Database\n");
    fprintf(fp, "# Used to properly handle domains like .co.uk, .com.au, .org.br\n");
    fprintf(fp, "#   api.example.co.uk → creates wildcard for *.example.co.uk\n");
    fprintf(fp, "#   (NOT for *.co.uk which would be wrong)\n");
    fprintf(fp, "# Default: /etc/tlsgateNG/second-level-tlds.conf (auto-loaded if exists)\n");
    fprintf(fp, "#second-level-tld-file=/etc/tlsgateNG/second-level-tlds.conf\n\n");
    fprintf(fp, "# Certificate Caching\n");
    fprintf(fp, "# When enabled: Reuse previously generated certificates (huge perf boost)\n");
    fprintf(fp, "# When disabled: Generate new cert for every domain request (slower)\n");
    fprintf(fp, "# Default: true\n");
    fprintf(fp, "#cache-certificates=true\n\n");

    /* HTML Configuration */
    fprintf(fp, "[html]\n");
    fprintf(fp, "# Default HTML Content for Web Responses\n");
    fprintf(fp, "# Path to binary HTML file for dynamic responses\n");
    fprintf(fp, "# When specified: Loads HTML from this file at runtime (allows live updates)\n");
    fprintf(fp, "# When empty: Uses compiled-in fallback HTML\n");
    fprintf(fp, "# NOTE: The HTML binary should contain %%s placeholder for timestamp injection\n");
    fprintf(fp, "#\n");
    fprintf(fp, "# HTML TEMPLATE EXAMPLE:\n");
    fprintf(fp, "# Add this as the FIRST line of your HTML file:\n");
    fprintf(fp, "#   <!-- Generated at %%s -->\n");
    fprintf(fp, "# The %%s will be replaced with current timestamp at runtime\n");
    fprintf(fp, "# This is invisible to users but helps anti-detection systems\n");
    fprintf(fp, "#\n");
    fprintf(fp, "# EXAMPLES:\n");
    fprintf(fp, "#   default-html=/etc/tlsgateNG/html/index.html.bin\n");
    fprintf(fp, "#   default-html=/var/lib/tlsgateNG/custom.html.bin\n");
    fprintf(fp, "# BENEFIT: Change HTML without recompiling - just update the file!\n");
    fprintf(fp, "# default-html=\n");
    fprintf(fp, "#\n");
    fprintf(fp, "# Anti-Phishing Mode (ALL responses return same HTML page)\n");
    fprintf(fp, "# When enabled: EVERY request gets HTTP 200 + default_html (no 404, no variations)\n");
    fprintf(fp, "# When disabled: Normal responses (404 for missing, etc.)\n");
    fprintf(fp, "any-responses=false\n\n");

    /* Server Configuration */
    fprintf(fp, "# ============================================================================\n");
    fprintf(fp, "# SERVER CONFIGURATION\n");
    fprintf(fp, "# ============================================================================\n");
    fprintf(fp, "# Network and worker settings - can also be set via command line\n");
    fprintf(fp, "# Command line options OVERRIDE config file settings\n");
    fprintf(fp, "#\n");
    fprintf(fp, "[server]\n");
    fprintf(fp, "# IP address to bind to\n");
    fprintf(fp, "# WARNING: Do NOT use 0.0.0.0 or :: for security reasons!\n");
    fprintf(fp, "# Default: 127.0.0.1 (localhost only)\n");
    fprintf(fp, "#listen-address=127.0.0.1\n\n");
    fprintf(fp, "# HTTP port (plaintext)\n");
    fprintf(fp, "# Set to 0 to disable HTTP listener\n");
    fprintf(fp, "# Default: 80\n");
    fprintf(fp, "#http-port=80\n\n");
    fprintf(fp, "# HTTPS port (TLS encrypted)\n");
    fprintf(fp, "# Set to 0 to disable HTTPS listener\n");
    fprintf(fp, "# Default: 443\n");
    fprintf(fp, "#https-port=443\n\n");
    fprintf(fp, "# AUTO port (MSG_PEEK protocol detection)\n");
    fprintf(fp, "# Automatically detects HTTP vs HTTPS on same port\n");
    fprintf(fp, "# Set to 0 to disable AUTO listener\n");
    fprintf(fp, "# Default: 8080\n");
    fprintf(fp, "#auto-port=8080\n\n");
    fprintf(fp, "# Number of worker threads\n");
    fprintf(fp, "# Recommended: Number of CPU cores\n");
    fprintf(fp, "# Range: 1-256\n");
    fprintf(fp, "# Default: 4\n");
    fprintf(fp, "#workers=4\n\n");
    fprintf(fp, "# Maximum connections per worker\n");
    fprintf(fp, "# Total max connections = workers × max_connections\n");
    fprintf(fp, "# Range: 1-100000\n");
    fprintf(fp, "# Default: 1000\n");
    fprintf(fp, "#max-connections=1000\n\n");

    /* Runtime Configuration */
    fprintf(fp, "# ============================================================================\n");
    fprintf(fp, "# RUNTIME CONFIGURATION\n");
    fprintf(fp, "# ============================================================================\n");
    fprintf(fp, "# Process execution settings\n");
    fprintf(fp, "#\n");
    fprintf(fp, "[runtime]\n");
    fprintf(fp, "# Run as daemon (background process)\n");
    fprintf(fp, "# Default: false\n");
    fprintf(fp, "#daemonize=false\n\n");
    fprintf(fp, "# Enable verbose/debug logging\n");
    fprintf(fp, "# Default: false\n");
    fprintf(fp, "#verbose=false\n\n");
    fprintf(fp, "# Drop privileges to this user after startup\n");
    fprintf(fp, "# Recommended for security! Create user with:\n");
    fprintf(fp, "#   useradd --system --no-create-home tlsgate\n");
    fprintf(fp, "# Leave empty to run as started user (not recommended for root)\n");
    fprintf(fp, "#user=tlsgate\n\n");
    fprintf(fp, "# Drop privileges to this group after startup\n");
    fprintf(fp, "# If not specified, uses user's primary group\n");
    fprintf(fp, "# Create group with: groupadd --system tlsgate\n");
    fprintf(fp, "#group=tlsgate\n\n");

    /* Directories Configuration */
    fprintf(fp, "# ============================================================================\n");
    fprintf(fp, "# DIRECTORIES CONFIGURATION\n");
    fprintf(fp, "# ============================================================================\n");
    fprintf(fp, "# Path settings for CA, certificates, and key bundles\n");
    fprintf(fp, "#\n");
    fprintf(fp, "[directories]\n");
    fprintf(fp, "# Base CA directory containing rootCA/, certs/, index/ subdirectories\n");
    fprintf(fp, "# Structure:\n");
    fprintf(fp, "#   ca_dir/\n");
    fprintf(fp, "#   ├── rootCA/          (CA certs & keys - root:root 0755)\n");
    fprintf(fp, "#   │   ├── RSA/\n");
    fprintf(fp, "#   │   ├── ECDSA/\n");
    fprintf(fp, "#   │   └── SM2/\n");
    fprintf(fp, "#   ├── certs/           (generated certs - user:group writable)\n");
    fprintf(fp, "#   │   ├── RSA/\n");
    fprintf(fp, "#   │   ├── ECDSA/\n");
    fprintf(fp, "#   │   └── SM2/\n");
    fprintf(fp, "#   └── index/           (cert index - user:group writable)\n");
    fprintf(fp, "#       ├── RSA/\n");
    fprintf(fp, "#       ├── ECDSA/\n");
    fprintf(fp, "#       └── SM2/\n");
    fprintf(fp, "# Default: auto-detect based on algorithm-specific [ca-*] sections\n");
    fprintf(fp, "#ca-dir=/opt/TLSGateNX\n\n");
    fprintf(fp, "# Certificate cache directory (override for certs/)\n");
    fprintf(fp, "# If empty, uses ca_dir/certs/\n");
    fprintf(fp, "#cert-cache-dir=\n\n");
    fprintf(fp, "# Pre-generated key bundles directory\n");
    fprintf(fp, "# For faster startup with pre-computed RSA/ECDSA keys\n");
    fprintf(fp, "# Leave empty to disable bundle loading\n");
    fprintf(fp, "#bundles-dir=\n\n");

    /* Pool Configuration */
    fprintf(fp, "# ============================================================================\n");
    fprintf(fp, "# KEY POOL CONFIGURATION\n");
    fprintf(fp, "# ============================================================================\n");
    fprintf(fp, "# Settings for the cryptographic key pool\n");
    fprintf(fp, "#\n");
    fprintf(fp, "[pool]\n");
    fprintf(fp, "# Keypool size (number of pre-generated keys)\n");
    fprintf(fp, "# Larger pools = more memory, faster cert generation\n");
    fprintf(fp, "# Range: 1-10000000\n");
    fprintf(fp, "# Default: 100\n");
    fprintf(fp, "#pool-size=100\n\n");
    fprintf(fp, "# Use shared memory for keypool\n");
    fprintf(fp, "# Allows sharing keys between multiple server instances\n");
    fprintf(fp, "# Requires: poolkeygen_mode instance running separately\n");
    fprintf(fp, "# Default: false\n");
    fprintf(fp, "#use-shm=false\n\n");
    fprintf(fp, "# Run as pure keypool generator (no network)\n");
    fprintf(fp, "# Used with use-shm=true for dedicated key generation process\n");
    fprintf(fp, "# Default: false\n");
    fprintf(fp, "#poolkeygen-mode=false\n\n");
    fprintf(fp, "# Force single algorithm (disable multi-algorithm support)\n");
    fprintf(fp, "# Valid values: RSA-2048, RSA-3072, RSA-4096, ECDSA-P256, ECDSA-P384, SM2\n");
    fprintf(fp, "# Leave empty for all algorithms (default)\n");
    fprintf(fp, "#force-algorithm=\n\n");
    fprintf(fp, "# SHM certificate index capacity (number of domain entries)\n");
    fprintf(fp, "# IMPORTANT: M = Million entries, NOT Megabytes!\n");
    fprintf(fp, "#\n");
    fprintf(fp, "# Valid values (K/M suffixes = thousands/millions of entries):\n");
    fprintf(fp, "#   Value    Entries        SHM Size\n");
    fprintf(fp, "#   -----    -------        --------\n");
    fprintf(fp, "#   1M       1,000,000      ~320MB\n");
    fprintf(fp, "#   10M      10,000,000     ~3.2GB\n");
    fprintf(fp, "#   30M      30,000,000     ~9.6GB\n");
    fprintf(fp, "#   100M     100,000,000    ~32GB   (maximum)\n");
    fprintf(fp, "#\n");
    fprintf(fp, "# Range: 1K - 100M (default: 1M)\n");
    fprintf(fp, "# Only used when use-shm=true\n");
    fprintf(fp, "#certcache-capacity=1M\n\n");

    /* Index Configuration */
    fprintf(fp, "# ============================================================================\n");
    fprintf(fp, "# INDEX CONFIGURATION\n");
    fprintf(fp, "# ============================================================================\n");
    fprintf(fp, "# Certificate index management for multi-instance deployments\n");
    fprintf(fp, "#\n");
    fprintf(fp, "[index]\n");
    fprintf(fp, "# Master mode for certificate index management\n");
    fprintf(fp, "# When running MULTIPLE tlsgateNG instances (e.g., IPv4 + IPv6):\n");
    fprintf(fp, "#   - Set master=true on ONE instance only\n");
    fprintf(fp, "#   - Set master=false on all other instances\n");
    fprintf(fp, "#\n");
    fprintf(fp, "# Master instance responsibilities:\n");
    fprintf(fp, "#   - Writes to certificate index\n");
    fprintf(fp, "#   - Runs certificate renewal scans\n");
    fprintf(fp, "#   - Saves index to disk periodically\n");
    fprintf(fp, "#\n");
    fprintf(fp, "# Slave instances (master=false):\n");
    fprintf(fp, "#   - Read-only access to index\n");
    fprintf(fp, "#   - No renewal scans (avoids conflicts)\n");
    fprintf(fp, "#   - Can still generate new certificates\n");
    fprintf(fp, "#\n");
    fprintf(fp, "# WARNING: Multiple masters will cause index corruption!\n");
    fprintf(fp, "# Default: true (single instance assumed)\n");
    fprintf(fp, "master=true\n\n");

    /* Framework Logging Section */
    fprintf(fp, "# ============================================================================\n");
    fprintf(fp, "# FRAMEWORK-LOGGING (Security Intelligence)\n");
    fprintf(fp, "# ============================================================================\n");
    fprintf(fp, "# Protokolliert verdächtige Aktivitäten für Security-Analyse:\n");
    fprintf(fp, "#   - Unbekannte/verdächtige SNI (Server Name Indication)\n");
    fprintf(fp, "#   - Malformed TLS Requests\n");
    fprintf(fp, "#   - Ungültige Zertifikat-Anfragen\n");
    fprintf(fp, "#   - Potenzielle Angriffsmuster (IDN homograph, etc.)\n");
    fprintf(fp, "#\n");
    fprintf(fp, "# Die Logs können in SIEM-Systeme (Splunk, ELK, etc.) eingespeist werden.\n");
    fprintf(fp, "#\n");
    fprintf(fp, "[framework-logging]\n");
    fprintf(fp, "# Security Intelligence Logging aktivieren\n");
    fprintf(fp, "enabled=true\n\n");
    fprintf(fp, "# Log-Pfad (ohne Extension)\n");
    fprintf(fp, "# Dateien: framework.0.log, framework.1.log, ... (Auto-Rotation)\n");
    fprintf(fp, "log-path=/var/log/tlsgateNG/framework\n\n");

    /* CA Configuration (Algorithm-Specific) - documented but commented by default */
    fprintf(fp, "# CA Configuration (Algorithm-Specific)\n");
    fprintf(fp, "# OPTIONAL: Configure CA paths per algorithm\n");
    fprintf(fp, "# If not specified, falls back to directory auto-detection\n");
    fprintf(fp, "#\n");
    fprintf(fp, "# Supported algorithms: RSA, ECDSA, SM2, LEGACY\n");
    fprintf(fp, "# Format:\n");
    fprintf(fp, "#   [ca-ALGORITHM]\n");
    fprintf(fp, "#   sub_cert_path = /path/to/subca.crt\n");
    fprintf(fp, "#   sub_key_path = /path/to/subca.key\n");
    fprintf(fp, "#   root_cert_path = /path/to/rootca.crt\n");
    fprintf(fp, "#   sub_cs_cert_path = /path/to/subca.cs.crt (optional - cross-signed)\n");
    fprintf(fp, "#\n");
    fprintf(fp, "# Example - Algorithm-specific sections (RECOMMENDED for multi-algorithm):\n");
    fprintf(fp, "#\n");
    fprintf(fp, "# [ca-RSA]\n");
    fprintf(fp, "# sub_cert_path = /opt/TLSGateNX/certs/RSA/subca.crt\n");
    fprintf(fp, "# sub_key_path = /opt/TLSGateNX/certs/RSA/subca.key\n");
    fprintf(fp, "# root_cert_path = /opt/TLSGateNX/certs/RSA/rootca.crt\n");
    fprintf(fp, "#\n");
    fprintf(fp, "# [ca-ECDSA]\n");
    fprintf(fp, "# sub_cert_path = /opt/TLSGateNX/certs/ECDSA/subca.crt\n");
    fprintf(fp, "# sub_key_path = /opt/TLSGateNX/certs/ECDSA/subca.key\n");
    fprintf(fp, "# root_cert_path = /opt/TLSGateNX/certs/ECDSA/rootca.crt\n");
    fprintf(fp, "#\n");
    fprintf(fp, "# [ca-SM2]\n");
    fprintf(fp, "# sub_cert_path = /opt/TLSGateNX/certs/SM2/subca.crt\n");
    fprintf(fp, "# sub_key_path = /opt/TLSGateNX/certs/SM2/subca.key\n");
    fprintf(fp, "# root_cert_path = /opt/TLSGateNX/certs/SM2/rootca.crt\n");
    fprintf(fp, "#\n");
    fprintf(fp, "# [ca-LEGACY]\n");
    fprintf(fp, "# sub_cert_path = /opt/TLSGateNX/certs/Legacy/subca.crt\n");
    fprintf(fp, "# sub_key_path = /opt/TLSGateNX/certs/Legacy/subca.key\n");
    fprintf(fp, "# root_cert_path = /opt/TLSGateNX/certs/Legacy/rootca.crt\n");
    fprintf(fp, "#\n");
    fprintf(fp, "# Generic fallback (DEPRECATED - use algorithm-specific sections above):\n");
    fprintf(fp, "#\n");
    fprintf(fp, "# [ca]\n");
    fprintf(fp, "# sub_cert_path = /opt/TLSGateNX/certs/subca.crt\n");
    fprintf(fp, "# sub_key_path = /opt/TLSGateNX/certs/subca.key\n");
    fprintf(fp, "# root_cert_path = /opt/TLSGateNX/certs/rootca.crt\n\n");

    /* TEST configuration (active by default for development) */
    fprintf(fp, "# TEST Configuration (Algorithm-Specific)\n");
    fprintf(fp, "# This section is active for testing with Makefile's setup-test-ca target\n");
    fprintf(fp, "# In production, comment this out and configure your own CA paths\n");
    fprintf(fp, "[ca-TEST]\n");
    fprintf(fp, "sub_cert_path = /tmp/testca/RSA/rootCA/subca.crt\n");
    fprintf(fp, "sub_key_path = /tmp/testca/RSA/rootCA/subca.key\n");
    fprintf(fp, "root_cert_path = /tmp/testca/RSA/rootCA/rootca.crt\n\n");

    fprintf(fp, "[license]\n");
    fprintf(fp, "# Reserved for future use\n");
    fprintf(fp, "#key=\n");

    fclose(fp);

    printf("INFO: Created empty config template: %s\n", path);
    printf("      Edit this file and restart TLSGate NG.\n");

    /* Create standard directory structure */
    create_standard_directories();

    /* Create certificate directory structure (RSA/, ECDSA/, SM2/, LEGACY/) */
    create_cert_directories();

    /* Create additional config templates */
    create_silent_blocks_template();
    create_second_level_tlds_template();

    return 0;
}

/* Trim whitespace from both ends */
static char* trim(char *str) {
    char *end;
    while (isspace((unsigned char)*str)) str++;
    if (*str == 0) return str;
    end = str + strlen(str) - 1;
    while (end > str && isspace((unsigned char)*end)) end--;
    end[1] = '\0';
    return str;
}

/* Parse version string "2.0.0.0" into components */
static int parse_version(const char *version_str, config_file_t *config) {
    int count = sscanf(version_str, "%d.%d.%d.%d",
                       &config->version_major, &config->version_minor,
                       &config->version_patch, &config->version_build);

    if (count < 3) {
        fprintf(stderr, "ERROR: Invalid version format: %s\n", version_str);
        fprintf(stderr, "       Expected: MAJOR.MINOR.PATCH[.BUILD]\n");
        return -1;
    }

    if (count == 3) {
        config->version_build = 0;  /* Default build number */
    }

    return 0;
}

/* Parse size value with K/M/G suffix (e.g., "100M", "5G", "1024K")
 * Returns size in bytes, or 0 on error */
static size_t parse_size(const char *str) {
    if (!str || !str[0]) return 0;

    char *endptr;
    double val = strtod(str, &endptr);
    if (endptr == str || val < 0) return 0;

    /* Check suffix */
    size_t multiplier = 1;
    if (*endptr) {
        switch (*endptr) {
            case 'k': case 'K': multiplier = 1024ULL; break;
            case 'm': case 'M': multiplier = 1024ULL * 1024; break;
            case 'g': case 'G': multiplier = 1024ULL * 1024 * 1024; break;
            case 't': case 'T': multiplier = 1024ULL * 1024 * 1024 * 1024; break;
            default:
                /* Unknown suffix - check if it's just whitespace */
                while (*endptr && isspace(*endptr)) endptr++;
                if (*endptr) return 0;  /* Invalid suffix */
        }
    }

    return (size_t)(val * multiplier);
}

/* Load configuration from default path */
config_file_t* config_file_load(bool allow_autofix) {
    return config_file_load_path(config_get_path(), allow_autofix);
}

/* Load configuration from specific file path */
config_file_t* config_file_load_path(const char *path, bool allow_autofix) {
    FILE *fp;
    char line[8192];
    char current_section[256] = "";
    int line_num = 0;

    /* Allocate config structure */
    config_file_t *config = calloc(1, sizeof(config_file_t));
    if (!config) {
        fprintf(stderr, "ERROR: Failed to allocate config structure\n");
        return NULL;
    }

    /* Initialize defaults */
    config->version_major = 0;
    config->version_minor = 0;
    config->version_patch = 0;
    config->version_build = 0;
    config->prime_path[0] = '\0';
    config->keypool_path[0] = '\0';
    config->backup_enabled = false;
    config->backup_master = true;  /* Default: this instance runs backups */
    config->backup_path[0] = '\0';
    config->backup_encrypt = false;
    config->backup_ca_key_path[0] = '\0';
    config->backup_curve = 0;
    config->license_key[0] = '\0';
    config->legacy_crypto = false;

    /* None-SNI defaults */
    config->default_domain_mode = NONE_SNI_MODE_AUTO;  /* Default: SNI-sync realtime */
    config->default_domain[0] = '\0';  /* Empty for auto mode, set value for static mode */

    /* Certificate generation defaults */
    config->enable_wildcards = true;
    config->enable_san = true;
    config->validity_days = 200;
    config->cache_certificates = true;
    config->second_level_tld_file[0] = '\0';  /* Empty = auto-detect */
    config->silent_block_file[0] = '\0';      /* Empty = disabled */

    /* HTML defaults */
    config->default_html_path[0] = '\0';  /* Empty = no external HTML */
    config->any_responses = false;        /* Default: normal mode (not anti-phishing) */

    /* Server defaults */
    strncpy(config->listen_address, "127.0.0.1", sizeof(config->listen_address) - 1);
    config->listen_address[sizeof(config->listen_address) - 1] = '\0';
    config->http_port = 80;
    config->https_port = 443;
    config->auto_port = 8080;
    config->workers = 4;
    config->max_connections = 1000;

    /* Runtime defaults */
    config->daemonize = false;
    config->verbose = false;
    config->run_user[0] = '\0';           /* Empty = no privilege drop */
    config->run_group[0] = '\0';          /* Empty = no privilege drop */

    /* Directory defaults */
    config->ca_dir[0] = '\0';             /* Empty = auto-detect */
    config->cert_cache_dir[0] = '\0';     /* Empty = use ca_dir/certs */
    config->bundles_dir[0] = '\0';        /* Empty = disabled */

    /* Pool defaults */
    config->pool_size = 100;
    config->use_shm = false;
    config->poolkeygen_mode = false;
    config->force_algorithm[0] = '\0';    /* Empty = all algorithms */
    config->shm_certcache_capacity = 1000000;  /* 1M domains default (~320MB SHM) */

    /* Algorithm distribution defaults (must sum to 100) */
    config->algo_rsa_3072_percent = 30;
    config->algo_ecdsa_p256_percent = 60;
    config->algo_sm2_percent = 10;

    /* Index defaults */
    config->index_master = true;          /* Default: act as index master */

    /* Security defaults */
    config->security_logging = true;      /* Default: enable security logging */
    strncpy(config->security_log_path, "/var/log/tlsgateNG/security",
            sizeof(config->security_log_path) - 1);

    /* Log rotation defaults */
    config->log_file_size = 100 * 1024 * 1024;        /* 100 MB per file */
    config->log_total_size = 5ULL * 1024 * 1024 * 1024; /* 5 GB total */
    config->log_max_files = 0;                        /* 0 = use log_total_size */

    config->loaded = false;
    snprintf(config->config_path, sizeof(config->config_path), "%s", path);

    /* Check if config file exists */
    if (access(path, R_OK) != 0) {
        /* Create empty template */
        create_empty_config(path);
        /* Return empty config (all features disabled) */
        return config;
    }

    /* Open config file */
    fp = fopen(path, "r");
    if (!fp) {
        fprintf(stderr, "ERROR: Cannot open config file: %s\n", path);
        free(config);
        return NULL;
    }

    /* Parse config file */
    while (fgets(line, sizeof(line), fp)) {
        line_num++;

        /* Remove newline */
        line[strcspn(line, "\r\n")] = '\0';

        /* Trim whitespace */
        char *trimmed = trim(line);

        /* Skip empty lines and comments */
        if (trimmed[0] == '\0' || trimmed[0] == '#') {
            continue;
        }

        /* Check for section header [name] */
        if (trimmed[0] == '[') {
            char *end = strchr(trimmed, ']');
            if (!end) {
                fprintf(stderr, "ERROR: Invalid section header at line %d: %s\n", line_num, trimmed);
                fclose(fp);
                free(config);
                return NULL;
            }
            *end = '\0';
            strncpy(current_section, trimmed + 1, sizeof(current_section) - 1);
            current_section[sizeof(current_section) - 1] = '\0';  /* SECURITY FIX: Ensure null-termination */
            continue;
        }

        /* Parse based on current section */
        if (strcmp(current_section, "version") == 0) {
            /* Version line (no key=value, just the version string) */
            if (parse_version(trimmed, config) != 0) {
                fclose(fp);
                free(config);
                return NULL;
            }
        } else if (strcmp(current_section, "prime") == 0) {
            /* Prime section: path=... */
            if (strncmp(trimmed, "path=", 5) == 0) {
                strncpy(config->prime_path, trimmed + 5, sizeof(config->prime_path) - 1);
                config->prime_path[sizeof(config->prime_path) - 1] = '\0';  /* SECURITY FIX: Ensure null-termination */
            }
        } else if (strcmp(current_section, "keypool") == 0) {
            /* Keypool section: path=... */
            if (strncmp(trimmed, "path=", 5) == 0) {
                strncpy(config->keypool_path, trimmed + 5, sizeof(config->keypool_path) - 1);
                config->keypool_path[sizeof(config->keypool_path) - 1] = '\0';  /* SECURITY FIX: Ensure null-termination */
            }
        } else if (strcmp(current_section, "backup") == 0) {
            /* Backup section */
            if (strncmp(trimmed, "enable=", 7) == 0) {
                const char *val = trimmed + 7;
                config->backup_enabled = (strcmp(val, "true") == 0 || strcmp(val, "1") == 0);
            } else if (strncmp(trimmed, "path=", 5) == 0) {
                strncpy(config->backup_path, trimmed + 5, sizeof(config->backup_path) - 1);
                config->backup_path[sizeof(config->backup_path) - 1] = '\0';  /* SECURITY FIX: Ensure null-termination */
            } else if (strncmp(trimmed, "encrypt=", 8) == 0) {
                const char *val = trimmed + 8;
                config->backup_encrypt = (strcmp(val, "true") == 0 || strcmp(val, "1") == 0);
            } else if (strncmp(trimmed, "ca-key=", 7) == 0) {
                strncpy(config->backup_ca_key_path, trimmed + 7, sizeof(config->backup_ca_key_path) - 1);
                config->backup_ca_key_path[sizeof(config->backup_ca_key_path) - 1] = '\0';  /* SECURITY FIX: Ensure null-termination */
            } else if (strncmp(trimmed, "curve=", 6) == 0) {
                char *endptr;
                long curve_val = strtol(trimmed + 6, &endptr, 10);
                if (endptr == trimmed + 6 || curve_val < 0 || curve_val > UINT_MAX) {
                    fprintf(stderr, "WARNING: Invalid curve value in config: %s (using default)\n", trimmed + 6);
                } else {
                    config->backup_curve = (unsigned int)curve_val;
                }
            } else if (strncmp(trimmed, "master=", 7) == 0) {
                const char *val = trimmed + 7;
                config->backup_master = (strcmp(val, "true") == 0 || strcmp(val, "1") == 0);
            }
        } else if (strcmp(current_section, "legacy") == 0) {
            /* Legacy crypto section - if legacy-crypto=false, legacy is disabled */
            if (strncmp(trimmed, "legacy-crypto=", 14) == 0) {
                const char *val = trimmed + 14;
                config->legacy_crypto = (strcmp(val, "true") == 0 || strcmp(val, "1") == 0);
            }
            /* NOTE: default-domain moved to [none-sni] section */
        } else if (strcmp(current_section, "none-sni") == 0) {
            /* None-SNI handling section - controls behavior for clients without SNI */
            if (strncmp(trimmed, "mode=", 5) == 0) {
                const char *val = trimmed + 5;
                if (strcmp(val, "auto") == 0) {
                    config->default_domain_mode = NONE_SNI_MODE_AUTO;
                } else if (strcmp(val, "static") == 0) {
                    config->default_domain_mode = NONE_SNI_MODE_STATIC;
                } else if (strcmp(val, "disabled") == 0) {
                    config->default_domain_mode = NONE_SNI_MODE_DISABLED;
                } else {
                    fprintf(stderr, "WARNING: Invalid none-sni mode '%s' (using 'auto')\n", val);
                    config->default_domain_mode = NONE_SNI_MODE_AUTO;
                }
            } else if (strncmp(trimmed, "default-domain=", 15) == 0) {
                /* Static domain for mode=static */
                strncpy(config->default_domain, trimmed + 15, sizeof(config->default_domain) - 1);
                config->default_domain[sizeof(config->default_domain) - 1] = '\0';
            }
        } else if (strcmp(current_section, "certificate") == 0) {
            /* Certificate generation options section */
            printf("DEBUG CONFIG [certificate]: Parsing line: '%s'\n", trimmed);
            if (strncmp(trimmed, "enable-wildcards=", 17) == 0) {
                const char *val = trimmed + 17;
                config->enable_wildcards = (strcmp(val, "true") == 0 || strcmp(val, "1") == 0);
            } else if (strncmp(trimmed, "enable-san=", 11) == 0) {
                const char *val = trimmed + 11;
                config->enable_san = (strcmp(val, "true") == 0 || strcmp(val, "1") == 0);
            } else if (strncmp(trimmed, "validity-days=", 14) == 0) {
                char *endptr;
                long days_val = strtol(trimmed + 14, &endptr, 10);
                if (endptr != trimmed + 14 && days_val > 0 && days_val <= 398) {
                    config->validity_days = (int)days_val;
                } else {
                    fprintf(stderr, "WARNING: Invalid validity_days value in config: %s (must be 1-398, using default 200)\n",
                            trimmed + 14);
                }
            } else if (strncmp(trimmed, "cache-certificates=", 19) == 0) {
                const char *val = trimmed + 19;
                config->cache_certificates = (strcmp(val, "true") == 0 || strcmp(val, "1") == 0);
            } else if (strncmp(trimmed, "second-level-tld-file=", 22) == 0) {
                strncpy(config->second_level_tld_file, trimmed + 22, sizeof(config->second_level_tld_file) - 1);
                config->second_level_tld_file[sizeof(config->second_level_tld_file) - 1] = '\0';
            } else if (strncmp(trimmed, "silent-block-file=", 18) == 0) {
                strncpy(config->silent_block_file, trimmed + 18, sizeof(config->silent_block_file) - 1);
                config->silent_block_file[sizeof(config->silent_block_file) - 1] = '\0';
                printf("DEBUG CONFIG: Parsed silent-block-file='%s'\n", config->silent_block_file);
            }
        } else if (strcmp(current_section, "license") == 0) {
            /* License section: key=... (optional - commercial deployments) */
            if (strncmp(trimmed, "key=", 4) == 0) {
                strncpy(config->license_key, trimmed + 4, sizeof(config->license_key) - 1);
                config->license_key[sizeof(config->license_key) - 1] = '\0';  /* SECURITY FIX: Ensure null-termination */
            }
        } else if (strcmp(current_section, "html") == 0) {
            /* HTML section */
            if (strncmp(trimmed, "default-html=", 13) == 0) {
                strncpy(config->default_html_path, trimmed + 13, sizeof(config->default_html_path) - 1);
                config->default_html_path[sizeof(config->default_html_path) - 1] = '\0';  /* SECURITY FIX: Ensure null-termination */
            } else if (strncmp(trimmed, "html-path=", 10) == 0) {
                /* Alternative key name (used in examples) */
                strncpy(config->default_html_path, trimmed + 10, sizeof(config->default_html_path) - 1);
                config->default_html_path[sizeof(config->default_html_path) - 1] = '\0';
            } else if (strncmp(trimmed, "any-responses=", 14) == 0) {
                const char *val = trimmed + 14;
                config->any_responses = (strcmp(val, "true") == 0 || strcmp(val, "1") == 0);
            }
        } else if (strcmp(current_section, "server") == 0) {
            /* Server section */
            if (strncmp(trimmed, "listen-address=", 15) == 0) {
                strncpy(config->listen_address, trimmed + 15, sizeof(config->listen_address) - 1);
                config->listen_address[sizeof(config->listen_address) - 1] = '\0';
            } else if (strncmp(trimmed, "http-port=", 10) == 0) {
                char *endptr;
                long port_val = strtol(trimmed + 10, &endptr, 10);
                if (endptr != trimmed + 10 && port_val >= 0 && port_val <= 65535) {
                    config->http_port = (int)port_val;
                } else {
                    fprintf(stderr, "WARNING: Invalid http_port in config: %s (using default 80)\n", trimmed + 10);
                }
            } else if (strncmp(trimmed, "https-port=", 11) == 0) {
                char *endptr;
                long port_val = strtol(trimmed + 11, &endptr, 10);
                if (endptr != trimmed + 11 && port_val >= 0 && port_val <= 65535) {
                    config->https_port = (int)port_val;
                } else {
                    fprintf(stderr, "WARNING: Invalid https_port in config: %s (using default 443)\n", trimmed + 11);
                }
            } else if (strncmp(trimmed, "auto-port=", 10) == 0) {
                char *endptr;
                long port_val = strtol(trimmed + 10, &endptr, 10);
                if (endptr != trimmed + 10 && port_val >= 0 && port_val <= 65535) {
                    config->auto_port = (int)port_val;
                } else {
                    fprintf(stderr, "WARNING: Invalid auto_port in config: %s (using default 8080)\n", trimmed + 10);
                }
            } else if (strncmp(trimmed, "workers=", 8) == 0) {
                char *endptr;
                long workers_val = strtol(trimmed + 8, &endptr, 10);
                if (endptr != trimmed + 8 && workers_val >= 1 && workers_val <= 256) {
                    config->workers = (int)workers_val;
                } else {
                    fprintf(stderr, "WARNING: Invalid workers in config: %s (using default 4)\n", trimmed + 8);
                }
            } else if (strncmp(trimmed, "max-connections=", 16) == 0) {
                char *endptr;
                long max_val = strtol(trimmed + 16, &endptr, 10);
                if (endptr != trimmed + 16 && max_val >= 1 && max_val <= 100000) {
                    config->max_connections = (int)max_val;
                } else {
                    fprintf(stderr, "WARNING: Invalid max_connections in config: %s (using default 1000)\n", trimmed + 16);
                }
            }
        } else if (strcmp(current_section, "runtime") == 0) {
            /* Runtime section */
            if (strncmp(trimmed, "daemonize=", 10) == 0) {
                const char *val = trimmed + 10;
                config->daemonize = (strcmp(val, "true") == 0 || strcmp(val, "1") == 0);
            } else if (strncmp(trimmed, "verbose=", 8) == 0) {
                const char *val = trimmed + 8;
                config->verbose = (strcmp(val, "true") == 0 || strcmp(val, "1") == 0);
            } else if (strncmp(trimmed, "user=", 5) == 0) {
                strncpy(config->run_user, trimmed + 5, sizeof(config->run_user) - 1);
                config->run_user[sizeof(config->run_user) - 1] = '\0';
            } else if (strncmp(trimmed, "group=", 6) == 0) {
                strncpy(config->run_group, trimmed + 6, sizeof(config->run_group) - 1);
                config->run_group[sizeof(config->run_group) - 1] = '\0';
            }
        } else if (strcmp(current_section, "directories") == 0) {
            /* Directories section */
            if (strncmp(trimmed, "ca-dir=", 7) == 0) {
                strncpy(config->ca_dir, trimmed + 7, sizeof(config->ca_dir) - 1);
                config->ca_dir[sizeof(config->ca_dir) - 1] = '\0';
            } else if (strncmp(trimmed, "cert-cache-dir=", 15) == 0) {
                strncpy(config->cert_cache_dir, trimmed + 15, sizeof(config->cert_cache_dir) - 1);
                config->cert_cache_dir[sizeof(config->cert_cache_dir) - 1] = '\0';
            } else if (strncmp(trimmed, "bundles-dir=", 12) == 0) {
                strncpy(config->bundles_dir, trimmed + 12, sizeof(config->bundles_dir) - 1);
                config->bundles_dir[sizeof(config->bundles_dir) - 1] = '\0';
            }
        } else if (strcmp(current_section, "pool") == 0) {
            /* Pool section */
            if (strncmp(trimmed, "pool-size=", 10) == 0) {
                char *endptr;
                long size_val = strtol(trimmed + 10, &endptr, 10);
                if (endptr != trimmed + 10 && size_val >= 1 && size_val <= 10000000) {
                    config->pool_size = (int)size_val;
                } else {
                    fprintf(stderr, "WARNING: Invalid pool_size in config: %s (using default 100)\n", trimmed + 10);
                }
            } else if (strncmp(trimmed, "use-shm=", 8) == 0) {
                const char *val = trimmed + 8;
                config->use_shm = (strcmp(val, "true") == 0 || strcmp(val, "1") == 0);
            } else if (strncmp(trimmed, "poolkeygen-mode=", 16) == 0) {
                const char *val = trimmed + 16;
                config->poolkeygen_mode = (strcmp(val, "true") == 0 || strcmp(val, "1") == 0);
            } else if (strncmp(trimmed, "force-algorithm=", 16) == 0) {
                strncpy(config->force_algorithm, trimmed + 16, sizeof(config->force_algorithm) - 1);
                config->force_algorithm[sizeof(config->force_algorithm) - 1] = '\0';
            } else if (strncmp(trimmed, "certcache-capacity=", 19) == 0) {
                size_t cap = parse_size(trimmed + 19);
                if (cap >= 1000 && cap <= 100000000) {  /* 1K to 100M */
                    config->shm_certcache_capacity = cap;
                } else {
                    fprintf(stderr, "WARNING: Invalid certcache_capacity in config: %s (using default 1M)\n", trimmed + 19);
                }
            } else if (strncmp(trimmed, "rsa-3072-percent=", 17) == 0) {
                int pct = atoi(trimmed + 17);
                if (pct >= 0 && pct <= 100) {
                    config->algo_rsa_3072_percent = pct;
                }
            } else if (strncmp(trimmed, "ecdsa-p256-percent=", 19) == 0) {
                int pct = atoi(trimmed + 19);
                if (pct >= 0 && pct <= 100) {
                    config->algo_ecdsa_p256_percent = pct;
                }
            } else if (strncmp(trimmed, "sm2-percent=", 12) == 0) {
                int pct = atoi(trimmed + 12);
                if (pct >= 0 && pct <= 100) {
                    config->algo_sm2_percent = pct;
                }
            }
        } else if (strcmp(current_section, "index") == 0) {
            /* Index section */
            if (strncmp(trimmed, "master=", 7) == 0) {
                const char *val = trimmed + 7;
                config->index_master = (strcmp(val, "true") == 0 || strcmp(val, "1") == 0);
            }
        } else if (strcmp(current_section, "framework-logging") == 0 ||
                   strcmp(current_section, "security") == 0) {  /* backward compat */
            /* Framework Logging section (Security Intelligence) */
            if (strncmp(trimmed, "enabled=", 8) == 0) {
                const char *val = trimmed + 8;
                config->security_logging = (strcmp(val, "true") == 0 || strcmp(val, "1") == 0);
            } else if (strncmp(trimmed, "log-path=", 9) == 0) {
                strncpy(config->security_log_path, trimmed + 9, sizeof(config->security_log_path) - 1);
                config->security_log_path[sizeof(config->security_log_path) - 1] = '\0';
            } else if (strncmp(trimmed, "log-file-size=", 14) == 0) {
                size_t size = parse_size(trimmed + 14);
                if (size > 0) config->log_file_size = size;
            } else if (strncmp(trimmed, "log-total-size=", 15) == 0) {
                size_t size = parse_size(trimmed + 15);
                if (size > 0) config->log_total_size = size;
            } else if (strncmp(trimmed, "log-max-files=", 14) == 0) {
                int val = atoi(trimmed + 14);
                if (val > 0) config->log_max_files = val;
            }
        }
    }

    /* SECURITY FIX: Check if fgets() loop ended due to I/O error or EOF */
    if (ferror(fp)) {
        fprintf(stderr, "ERROR: I/O error reading config file: %s\n", path);
        fclose(fp);
        free(config);
        return NULL;
    }

    fclose(fp);

    /* Check version (MUST match exactly!) */
    if (config->version_major != 0 || config->version_minor != 0) {
        /* Version was specified - check it */
        if (config->version_major != TLSGATENG_VERSION_MAJOR ||
            config->version_minor != TLSGATENG_VERSION_MINOR ||
            config->version_patch != TLSGATENG_VERSION_PATCH ||
            config->version_build != TLSGATENG_VERSION_BUILD) {

            fprintf(stderr, "\n");

            /* Check if auto-fix is allowed (only for keygen) */
            if (!allow_autofix) {
                /* Regular binary (IPv4/IPv6) - strict version check */
                fprintf(stderr, "╔═══════════════════════════════════════════════════════════════╗\n");
                fprintf(stderr, "║  ❌ ERROR: Config version mismatch                           ║\n");
                fprintf(stderr, "╚═══════════════════════════════════════════════════════════════╝\n");
                fprintf(stderr, "\n");
                fprintf(stderr, "Config file: %s\n", path);
                fprintf(stderr, "Config version: %d.%d.%d.%d\n",
                        config->version_major, config->version_minor,
                        config->version_patch, config->version_build);
                fprintf(stderr, "Expected version: %d.%d.%d.%d\n",
                        TLSGATENG_VERSION_MAJOR, TLSGATENG_VERSION_MINOR,
                        TLSGATENG_VERSION_PATCH, TLSGATENG_VERSION_BUILD);
                fprintf(stderr, "\n");
                fprintf(stderr, "Version MUST match EXACTLY to prevent server chaos!\n");
                fprintf(stderr, "Please run tlsgateNG-poolgen first to auto-update config.\n");
                fprintf(stderr, "\n");
                free(config);
                exit(1);  /* CRITICAL: Stop server immediately! */
            }

            /* Keygen binary - auto-fix allowed */
            fprintf(stderr, "╔═══════════════════════════════════════════════════════════════╗\n");
            fprintf(stderr, "║  ⚠️  WARNING: Config version mismatch - Auto-fixing          ║\n");
            fprintf(stderr, "╚═══════════════════════════════════════════════════════════════╝\n");
            fprintf(stderr, "\n");
            fprintf(stderr, "Config file: %s\n", path);
            fprintf(stderr, "Old version: %d.%d.%d.%d\n",
                    config->version_major, config->version_minor,
                    config->version_patch, config->version_build);
            fprintf(stderr, "New version: %d.%d.%d.%d\n",
                    TLSGATENG_VERSION_MAJOR, TLSGATENG_VERSION_MINOR,
                    TLSGATENG_VERSION_PATCH, TLSGATENG_VERSION_BUILD);
            fprintf(stderr, "\n");

            /* Auto-fix: Update config file with correct version */
            FILE *in_fp = fopen(path, "r");
            if (!in_fp) {
                fprintf(stderr, "ERROR: Cannot open config for reading: %s\n", path);
                free(config);
                exit(1);
            }

            /* SECURITY FIX: Use mkstemp() for secure temporary file creation
             * This atomically creates a file with O_EXCL, preventing TOCTOU races */
            char tmp_path[8192];
            snprintf(tmp_path, sizeof(tmp_path), "%s.tmp.XXXXXX", path);

            int tmp_fd = mkstemp(tmp_path);
            if (tmp_fd < 0) {
                fprintf(stderr, "ERROR: Cannot create secure temporary config: %s\n", strerror(errno));
                fclose(in_fp);
                free(config);
                exit(1);
            }

            /* Convert fd to FILE* for easier writing */
            FILE *out_fp = fdopen(tmp_fd, "w");
            if (!out_fp) {
                fprintf(stderr, "ERROR: Cannot open temporary config for writing: %s\n", strerror(errno));
                close(tmp_fd);
                unlink(tmp_path);
                fclose(in_fp);
                free(config);
                exit(1);
            }

            /* Copy config line by line, replacing version */
            char update_line[8192];
            int in_version_section = 0;
            int version_updated = 0;
            while (fgets(update_line, sizeof(update_line), in_fp)) {
                char *trimmed = trim(update_line);

                /* Track [version] section */
                if (strcmp(trimmed, "[version]") == 0) {
                    in_version_section = 1;
                    fputs(update_line, out_fp);
                    continue;
                } else if (trimmed[0] == '[') {
                    in_version_section = 0;
                }

                /* Replace version line in [version] section */
                if (in_version_section && !version_updated && trimmed[0] != '\0' && trimmed[0] != '#') {
                    /* This is the version line - replace it */
                    fprintf(out_fp, "%d.%d.%d.%d\n",
                            TLSGATENG_VERSION_MAJOR, TLSGATENG_VERSION_MINOR,
                            TLSGATENG_VERSION_PATCH, TLSGATENG_VERSION_BUILD);
                    version_updated = 1;
                    continue;
                }

                /* Copy all other lines unchanged */
                fputs(update_line, out_fp);
            }

            fclose(in_fp);
            fclose(out_fp);

            /* Replace original with updated file */
            if (rename(tmp_path, path) != 0) {
                fprintf(stderr, "ERROR: Cannot update config file: %s\n", path);
                unlink(tmp_path);
                free(config);
                exit(1);
            }

            fprintf(stderr, "✅ Config version auto-updated successfully!\n");
            fprintf(stderr, "\n");

            /* Update config structure with correct version */
            config->version_major = TLSGATENG_VERSION_MAJOR;
            config->version_minor = TLSGATENG_VERSION_MINOR;
            config->version_patch = TLSGATENG_VERSION_PATCH;
            config->version_build = TLSGATENG_VERSION_BUILD;
        }
    }

    /* Auto-derive index_master from use_shm (simplifies config)
     * - use_shm=true  → Worker mode, poolgen is master → index_master=false
     * - use_shm=false → Standalone mode, self is master → index_master=true
     * - Poolgen binary (allow_autofix=true OR poolkeygen_mode=true) always stays master
     */
    if (!allow_autofix && !config->poolkeygen_mode) {  /* Not poolgen */
        config->index_master = !config->use_shm;
    }

    config->loaded = true;
    return config;
}

/* Free configuration */
void config_file_free(config_file_t *config) {
    if (config) {
        free(config);
    }
}

/* Print configuration (for debugging) */
void config_file_print(const config_file_t *config) {
    if (!config) return;

    printf("Master Configuration:\n");
    printf("  Config file: %s\n", config->config_path);

    if (config->loaded) {
        printf("  Status: Loaded\n");
    } else {
        printf("  Status: Empty template (all features disabled)\n");
        return;
    }

    printf("  Version: %d.%d.%d.%d\n",
           config->version_major, config->version_minor,
           config->version_patch, config->version_build);

    if (config->prime_path[0]) {
        printf("  Prime pool: %s\n", config->prime_path);
    } else {
        printf("  Prime pool: disabled\n");
    }

    if (config->keypool_path[0]) {
        printf("  Keypool: %s\n", config->keypool_path);
    } else {
        printf("  Keypool: disabled\n");
    }

    if (config->backup_enabled && config->backup_path[0]) {
        printf("  Backup: enabled (%s)%s\n", config->backup_path,
               config->backup_master ? " [MASTER]" : "");
        if (config->backup_encrypt) {
            printf("    Encryption: AES-256-GCM (curve: %u)\n", config->backup_curve);
            printf("    CA key: %s\n", config->backup_ca_key_path[0] ? config->backup_ca_key_path : "not set");
        } else {
            printf("    Encryption: disabled (plain gzip)\n");
        }
    } else {
        printf("  Backup: disabled\n");
    }

    if (config->license_key[0]) {
        printf("  License: %s\n", config->license_key);
    } else {
        printf("  License: not configured\n");
    }

    if (config->default_html_path[0]) {
        printf("  HTML: %s (runtime loaded)\n", config->default_html_path);
    } else {
        printf("  HTML: using compiled-in fallback\n");
    }

    /* Server settings */
    printf("\nServer Settings:\n");
    printf("  Listen address: %s\n", config->listen_address);
    printf("  HTTP port: %d%s\n", config->http_port, config->http_port == 0 ? " (disabled)" : "");
    printf("  HTTPS port: %d%s\n", config->https_port, config->https_port == 0 ? " (disabled)" : "");
    printf("  AUTO port: %d%s\n", config->auto_port, config->auto_port == 0 ? " (disabled)" : "");
    printf("  Workers: %d\n", config->workers);
    printf("  Max connections: %d (total: %d)\n", config->max_connections, config->workers * config->max_connections);

    /* Runtime settings */
    printf("\nRuntime Settings:\n");
    printf("  Daemonize: %s\n", config->daemonize ? "yes" : "no");
    printf("  Verbose: %s\n", config->verbose ? "yes" : "no");
    if (config->run_user[0]) {
        printf("  Run as user: %s\n", config->run_user);
    } else {
        printf("  Run as user: (no privilege drop)\n");
    }
    if (config->run_group[0]) {
        printf("  Run as group: %s\n", config->run_group);
    } else {
        printf("  Run as group: (use user's primary group)\n");
    }

    /* Directory settings */
    printf("\nDirectory Settings:\n");
    if (config->ca_dir[0]) {
        printf("  CA directory: %s\n", config->ca_dir);
    } else {
        printf("  CA directory: (auto-detect)\n");
    }
    if (config->cert_cache_dir[0]) {
        printf("  Cert cache: %s\n", config->cert_cache_dir);
    } else {
        printf("  Cert cache: (use ca_dir/certs)\n");
    }
    if (config->bundles_dir[0]) {
        printf("  Bundles: %s\n", config->bundles_dir);
    } else {
        printf("  Bundles: disabled\n");
    }

    /* Pool settings */
    printf("\nPool Settings:\n");
    printf("  Pool size: %d\n", config->pool_size);
    printf("  Use SHM: %s\n", config->use_shm ? "yes" : "no");
    printf("  Poolkeygen mode: %s\n", config->poolkeygen_mode ? "yes" : "no");
    if (config->force_algorithm[0]) {
        printf("  Force algorithm: %s\n", config->force_algorithm);
    } else {
        printf("  Force algorithm: (all algorithms enabled)\n");
    }
    if (config->use_shm) {
        /* Show SHM capacity in human-readable format */
        size_t cap = config->shm_certcache_capacity;
        size_t shm_size = cap * 320;  /* ~320 bytes per entry */
        if (cap >= 1000000) {
            printf("  Certcache capacity: %zuM domains (~%.1fGB SHM)\n",
                   cap / 1000000, (double)shm_size / (1024*1024*1024));
        } else {
            printf("  Certcache capacity: %zuK domains (~%.1fMB SHM)\n",
                   cap / 1000, (double)shm_size / (1024*1024));
        }
        /* SHM data files (Poolgen loads these into SHM) */
        if (config->second_level_tld_file[0]) {
            printf("  2nd-Level TLD file: %s (loaded into SHM)\n", config->second_level_tld_file);
        }
        if (config->silent_block_file[0]) {
            printf("  Silent-block file: %s (loaded into SHM, hot-reload)\n", config->silent_block_file);
        }
    }

    /* Index settings */
    printf("\nIndex Settings:\n");
    printf("  Index master: %s\n", config->index_master ? "yes (manages index, runs renewals)" : "no (read-only, no renewals)");

    /* Security settings */
    printf("\nSecurity Settings:\n");
    printf("  Security logging: %s\n", config->security_logging ? "enabled" : "disabled");
    printf("  Log path: %s.N.log\n", config->security_log_path);
}
