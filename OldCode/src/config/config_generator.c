/* TLSGateNX - Interactive Configuration Generator
 * Copyright (C) 2025 Torsten Jahnke
 */

#include "config_generator.h"
#include "config_file.h"
#include "version.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <limits.h>
#include <sys/sysinfo.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pwd.h>
#include <grp.h>
#include "../util/address_validation.h"

/* ANSI colors for terminal output */
#define COLOR_RESET   "\033[0m"
#define COLOR_BOLD    "\033[1m"
#define COLOR_GREEN   "\033[32m"
#define COLOR_YELLOW  "\033[33m"
#define COLOR_BLUE    "\033[34m"
#define COLOR_CYAN    "\033[36m"
#define COLOR_RED     "\033[31m"

/* System information */
typedef struct {
    char os_name[256];
    char os_version[256];
    char hostname[256];
    int cpu_cores;
    long total_ram_mb;
} system_info_t;

/* Configuration data */
typedef struct {
    char binary_path[PATH_MAX];
    char ipv4[256];
    char ipv6[256];
    int backend_count;
    int start_port_http;
    int start_port_https;
    int start_port_auto;
    char instance_dir[PATH_MAX];
    char ca_dir[PATH_MAX + 32];  /* Extra space for path suffix */
    bool create_ca_dir;

    /* Keypool configuration */
    char bundle_dir[PATH_MAX];
    char prime_dir[PATH_MAX];

    /* Per-instance certificate cache */
    char cert_dir_prefix[PATH_MAX];  /* Base path, e.g., /opt/tlsgateNG/certcache */
    bool use_cert_cache;

    /* Security */
    char drop_user[256];
    char drop_group[256];

    /* Performance */
    int worker_count;
    int max_connections;

    /* Master config options */
    bool legacy_crypto;

    /* Runtime */
    bool verbose;
    bool daemonize;
} config_data_t;

/* Helper: Read line from stdin with default value */
static char* read_line_with_default(const char *prompt, const char *default_value, char *buf, size_t size) {
    if (default_value && default_value[0] != '\0') {
        printf("%s [%s]: ", prompt, default_value);
    } else {
        printf("%s: ", prompt);
    }

    fflush(stdout);

    if (!fgets(buf, size, stdin)) {
        return NULL;
    }

    /* Remove trailing newline */
    buf[strcspn(buf, "\r\n")] = '\0';

    /* Use default if empty */
    if (buf[0] == '\0' && default_value) {
        strncpy(buf, default_value, size - 1);
        buf[size - 1] = '\0';
    }

    return buf;
}

/* Helper: Read yes/no with default */
static bool read_yes_no(const char *prompt, bool default_value) {
    char buf[16];
    const char *default_str = default_value ? "Y/n" : "y/N";

    printf("%s [%s]: ", prompt, default_str);
    fflush(stdout);

    if (!fgets(buf, sizeof(buf), stdin)) {
        return default_value;
    }

    /* Remove trailing newline */
    buf[strcspn(buf, "\r\n")] = '\0';

    /* Empty = default */
    if (buf[0] == '\0') {
        return default_value;
    }

    /* Check first character */
    char c = tolower(buf[0]);
    return (c == 'y' || c == 'j');  /* j for German "ja" */
}

/* Helper: Read integer with default and range */
static int read_int(const char *prompt, int default_value, int min, int max) {
    char buf[64];
    char default_str[32];

    snprintf(default_str, sizeof(default_str), "%d", default_value);

    while (1) {
        if (!read_line_with_default(prompt, default_str, buf, sizeof(buf))) {
            return default_value;
        }

        int value = atoi(buf);

        if (value < min || value > max) {
            printf("  " COLOR_YELLOW "⚠ Value must be between %d and %d" COLOR_RESET "\n", min, max);
            continue;
        }

        return value;
    }
}

/* Helper: Check if directory exists */
static bool dir_exists(const char *path) {
    struct stat st;
    return (stat(path, &st) == 0 && S_ISDIR(st.st_mode));
}

/* Helper: Check if file exists */
static bool file_exists(const char *path) {
    struct stat st;
    return (stat(path, &st) == 0 && S_ISREG(st.st_mode));
}

/* Helper: Check if port is available on IPv4 */
static bool check_port_available_ipv4(const char *ip, int port) {
    int sock;
    struct sockaddr_in addr;
    int reuse = 1;

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        return false;
    }

    /* Set SO_REUSEADDR to avoid "Address already in use" for recently closed sockets */
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);

    /* Parse IP address */
    if (strcmp(ip, "0.0.0.0") == 0 || strcmp(ip, "*") == 0) {
        addr.sin_addr.s_addr = INADDR_ANY;
    } else {
        if (!is_valid_ipv4(ip, &addr.sin_addr)) {
            close(sock);
            return false;
        }
    }

    /* Try to bind */
    int result = bind(sock, (struct sockaddr*)&addr, sizeof(addr));
    close(sock);

    return (result == 0);
}

/* Helper: Check if port is available on IPv6 */
static bool check_port_available_ipv6(const char *ip, int port) {
    int sock;
    struct sockaddr_in6 addr;
    int reuse = 1;

    sock = socket(AF_INET6, SOCK_STREAM, 0);
    if (sock < 0) {
        return false;
    }

    /* Set SO_REUSEADDR */
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

    memset(&addr, 0, sizeof(addr));
    addr.sin6_family = AF_INET6;
    addr.sin6_port = htons(port);

    /* Parse IP address */
    if (strcmp(ip, "::") == 0 || strcmp(ip, "*") == 0) {
        addr.sin6_addr = in6addr_any;
    } else {
        if (!is_valid_ipv6(ip, &addr.sin6_addr)) {
            close(sock);
            return false;
        }
    }

    /* Try to bind */
    int result = bind(sock, (struct sockaddr*)&addr, sizeof(addr));
    close(sock);

    return (result == 0);
}

/* Helper: Create directory recursively */
static int mkdir_recursive(const char *path) {
    char tmp[PATH_MAX];
    char *p = NULL;
    size_t len;

    snprintf(tmp, sizeof(tmp), "%s", path);
    len = strlen(tmp);
    if (tmp[len - 1] == '/')
        tmp[len - 1] = 0;

    for (p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = 0;
            if (!dir_exists(tmp)) {
                if (mkdir(tmp, 0755) != 0 && errno != EEXIST) {
                    return -1;
                }
            }
            *p = '/';
        }
    }

    if (!dir_exists(tmp)) {
        if (mkdir(tmp, 0755) != 0 && errno != EEXIST) {
            return -1;
        }
    }

    return 0;
}

/* Create certificate directory structure template
 * Creates subdirectories and placeholder files:
 *
 *   instance_dir/
 *   ├── RSA/
 *   │   ├── rootCA/           root:root 0700 (CA certs, read at startup)
 *   │   │   ├── ca.pem
 *   │   │   ├── subca.pem
 *   │   │   └── subca.cs.pem  (cross-signed)
 *   │   ├── certs/            tlsgateNG:tlsgateNG 0755 (workers WRITE generated certs)
 *   │   └── index/            root:root 0755 (poolgen WRITES, workers READ)
 *   ├── ECDSA/
 *   │   ├── rootCA/           root:root 0700
 *   │   ├── certs/            tlsgateNG:tlsgateNG 0755
 *   │   └── index/            root:root 0755
 *   ├── SM2/
 *   │   ├── rootCA/           root:root 0700
 *   │   ├── certs/            tlsgateNG:tlsgateNG 0755
 *   │   └── index/            root:root 0755
 *   └── LEGACY/               (NO cross-signed!)
 *       ├── rootCA/           root:root 0700
 *       │   ├── ca.pem
 *       │   └── subca.pem
 *       ├── certs/            tlsgateNG:tlsgateNG 0755
 *       └── index/            root:root 0755
 */

/* Helper: Touch file with root-only permissions (0600) */
static int touch_cert_file(const char *path) {
    FILE *fp = fopen(path, "a");
    if (!fp) return -1;
    fclose(fp);

    /* CA certificates are read BEFORE privilege drop - keep root:root 0600 */
    chmod(path, 0600);
    return 0;
}

/* Maximum suffix length: "/LEGACY/rootCA/subca.cs.pem" = 27 chars + NUL */
#define CERT_PATH_SUFFIX_MAX 32

static int create_cert_structure(const char *base_dir, const char *drop_user, const char *drop_group) {
    char path[PATH_MAX];
    uid_t cert_uid = 0;
    gid_t cert_gid = 0;
    bool can_chown = false;

    /* Validate base_dir length to prevent path truncation */
    size_t base_len = base_dir ? strlen(base_dir) : 0;
    if (base_len == 0 || base_len > PATH_MAX - CERT_PATH_SUFFIX_MAX) {
        fprintf(stderr, COLOR_RED "✗ Base directory path too long (max %d chars)" COLOR_RESET "\n",
                (int)(PATH_MAX - CERT_PATH_SUFFIX_MAX));
        return -1;
    }

    /* Try to get tlsgateNG user/group IDs for certs/ directory */
    const char *user = (drop_user && drop_user[0]) ? drop_user : "tlsgateNG";
    const char *group = (drop_group && drop_group[0]) ? drop_group : "tlsgateNG";

    struct passwd *pwd = getpwnam(user);
    struct group *grp = getgrnam(group);

    if (pwd && grp) {
        cert_uid = pwd->pw_uid;
        cert_gid = grp->gr_gid;
        can_chown = true;
    }

    /* Certificate types with cross-signing support */
    const char *cert_types_cs[] = { "RSA", "ECDSA", "SM2", NULL };

    /* LEGACY has no cross-signing (weak crypto, not for modern chains) */
    const char *cert_types_no_cs[] = { "LEGACY", NULL };

    /* Create structure for types WITH cross-signing */
    for (int i = 0; cert_types_cs[i] != NULL; i++) {
        /* Create main type directory */
        snprintf(path, sizeof(path), "%s/%s", base_dir, cert_types_cs[i]);
        if (mkdir_recursive(path) != 0) {
            fprintf(stderr, COLOR_RED "✗ Cannot create: %s" COLOR_RESET "\n", path);
            return -1;
        }
        chmod(path, 0755);

        /* Create rootCA/ subdirectory (root:root 0700) */
        snprintf(path, sizeof(path), "%s/%s/rootCA", base_dir, cert_types_cs[i]);
        if (mkdir_recursive(path) != 0) {
            fprintf(stderr, COLOR_RED "✗ Cannot create: %s" COLOR_RESET "\n", path);
            return -1;
        }
        chmod(path, 0700);
        /* Already root:root if created by root */

        /* Touch CA placeholder files */
        snprintf(path, sizeof(path), "%s/%s/rootCA/ca.pem", base_dir, cert_types_cs[i]);
        touch_cert_file(path);

        snprintf(path, sizeof(path), "%s/%s/rootCA/subca.pem", base_dir, cert_types_cs[i]);
        touch_cert_file(path);

        snprintf(path, sizeof(path), "%s/%s/rootCA/subca.cs.pem", base_dir, cert_types_cs[i]);
        touch_cert_file(path);

        /* Create certs/ subdirectory (tlsgateNG:tlsgateNG 0755) - workers WRITE here */
        snprintf(path, sizeof(path), "%s/%s/certs", base_dir, cert_types_cs[i]);
        if (mkdir_recursive(path) != 0) {
            fprintf(stderr, COLOR_RED "✗ Cannot create: %s" COLOR_RESET "\n", path);
            return -1;
        }
        chmod(path, 0755);
        if (can_chown) {
            if (chown(path, cert_uid, cert_gid) != 0) {
                fprintf(stderr, COLOR_YELLOW "  ⚠ chown failed for %s: %s" COLOR_RESET "\n", path, strerror(errno));
            }
        }

        /* Create index/ subdirectory (root:root 0755) - poolgen WRITES, workers READ */
        snprintf(path, sizeof(path), "%s/%s/index", base_dir, cert_types_cs[i]);
        if (mkdir_recursive(path) != 0) {
            fprintf(stderr, COLOR_RED "✗ Cannot create: %s" COLOR_RESET "\n", path);
            return -1;
        }
        chmod(path, 0755);
        /* Keep root:root - poolgen writes index, workers only read */

        printf(COLOR_GREEN "    ✓ %s/" COLOR_RESET "\n", cert_types_cs[i]);
        printf("        rootCA/ " COLOR_CYAN "[root:root 0700]" COLOR_RESET " ca.pem, subca.pem, subca.cs.pem\n");
        if (can_chown) {
            printf("        certs/  " COLOR_CYAN "[%s:%s 0755]" COLOR_RESET " (workers write)\n", user, group);
        } else {
            printf("        certs/  " COLOR_YELLOW "[chown to %s:%s!]" COLOR_RESET " (workers write)\n", user, group);
        }
        printf("        index/  " COLOR_CYAN "[root:root 0755]" COLOR_RESET " (poolgen writes, workers read)\n");
    }

    /* Create structure for types WITHOUT cross-signing */
    for (int i = 0; cert_types_no_cs[i] != NULL; i++) {
        /* Create main type directory */
        snprintf(path, sizeof(path), "%s/%s", base_dir, cert_types_no_cs[i]);
        if (mkdir_recursive(path) != 0) {
            fprintf(stderr, COLOR_RED "✗ Cannot create: %s" COLOR_RESET "\n", path);
            return -1;
        }
        chmod(path, 0755);

        /* Create rootCA/ subdirectory (root:root 0700) */
        snprintf(path, sizeof(path), "%s/%s/rootCA", base_dir, cert_types_no_cs[i]);
        if (mkdir_recursive(path) != 0) {
            fprintf(stderr, COLOR_RED "✗ Cannot create: %s" COLOR_RESET "\n", path);
            return -1;
        }
        chmod(path, 0700);

        /* Touch CA placeholder files - NO cross-signed for LEGACY! */
        snprintf(path, sizeof(path), "%s/%s/rootCA/ca.pem", base_dir, cert_types_no_cs[i]);
        touch_cert_file(path);

        snprintf(path, sizeof(path), "%s/%s/rootCA/subca.pem", base_dir, cert_types_no_cs[i]);
        touch_cert_file(path);

        /* Create certs/ subdirectory (tlsgateNG:tlsgateNG 0755) - workers WRITE here */
        snprintf(path, sizeof(path), "%s/%s/certs", base_dir, cert_types_no_cs[i]);
        if (mkdir_recursive(path) != 0) {
            fprintf(stderr, COLOR_RED "✗ Cannot create: %s" COLOR_RESET "\n", path);
            return -1;
        }
        chmod(path, 0755);
        if (can_chown) {
            if (chown(path, cert_uid, cert_gid) != 0) {
                fprintf(stderr, COLOR_YELLOW "  ⚠ chown failed for %s: %s" COLOR_RESET "\n", path, strerror(errno));
            }
        }

        /* Create index/ subdirectory (root:root 0755) - poolgen WRITES, workers READ */
        snprintf(path, sizeof(path), "%s/%s/index", base_dir, cert_types_no_cs[i]);
        if (mkdir_recursive(path) != 0) {
            fprintf(stderr, COLOR_RED "✗ Cannot create: %s" COLOR_RESET "\n", path);
            return -1;
        }
        chmod(path, 0755);
        /* Keep root:root - poolgen writes index, workers only read */

        printf(COLOR_GREEN "    ✓ %s/" COLOR_RESET " " COLOR_YELLOW "(no cross-sign)" COLOR_RESET "\n", cert_types_no_cs[i]);
        printf("        rootCA/ " COLOR_CYAN "[root:root 0700]" COLOR_RESET " ca.pem, subca.pem\n");
        if (can_chown) {
            printf("        certs/  " COLOR_CYAN "[%s:%s 0755]" COLOR_RESET " (workers write)\n", user, group);
        } else {
            printf("        certs/  " COLOR_YELLOW "[chown to %s:%s!]" COLOR_RESET " (workers write)\n", user, group);
        }
        printf("        index/  " COLOR_CYAN "[root:root 0755]" COLOR_RESET " (poolgen writes, workers read)\n");
    }

    return 0;
}

/* Print header */
static void print_header(void) {
    printf("\n");
    printf(COLOR_BOLD COLOR_CYAN);
    printf("═══════════════════════════════════════════════════════════════════════\n");
    printf("  TLSGate NG v%s - Interactive Configuration Generator\n", TLSGATENG_VERSION_STRING);
    printf("═══════════════════════════════════════════════════════════════════════\n");
    printf(COLOR_RESET);
    printf("\n");
}

/* Print section header */
static void print_section(const char *title) {
    printf("\n");
    printf(COLOR_BOLD COLOR_BLUE "━━━ %s ━━━" COLOR_RESET "\n", title);
    printf("\n");
}

/* Get system information */
static void get_system_info(system_info_t *info) {
    struct utsname u;
    struct sysinfo si;

    uname(&u);
    sysinfo(&si);

    snprintf(info->os_name, sizeof(info->os_name), "%s", u.sysname);
    snprintf(info->os_version, sizeof(info->os_version), "%s", u.release);
    snprintf(info->hostname, sizeof(info->hostname), "%s", u.nodename);
    info->cpu_cores = sysconf(_SC_NPROCESSORS_ONLN);
    info->total_ram_mb = si.totalram / (1024 * 1024);
}

/* Display system information */
static void display_system_info(const system_info_t *info) {
    print_section("SYSTEM INFORMATION");

    printf("  OS:        %s %s\n", info->os_name, info->os_version);
    printf("  Hostname:  %s\n", info->hostname);
    printf("  CPU Cores: %d\n", info->cpu_cores);
    printf("  RAM:       %ld MB\n", info->total_ram_mb);
}

/* Generate poolgen startup script */
static void generate_poolgen_script(FILE *fp, const config_data_t *config) {
    fprintf(fp, "# Keypool Generator + Watchdog (tlsgateNG-poolgen)\n");
    fprintf(fp, "#\n");
    fprintf(fp, "# IMPORTANT: Poolgen MUST run as ROOT for:\n");
    fprintf(fp, "#   1. SHM creation (mmap)\n");
    fprintf(fp, "#   2. Watchdog: Monitors workers and restarts them on crash\n");
    fprintf(fp, "#\n");
    fprintf(fp, "# Poolgen has NO network ports - no security risk!\n");
    fprintf(fp, "#\n");
    fprintf(fp, "%s/tlsgateNG-poolgen \\\n", config->binary_path);
    fprintf(fp, "  --poolkeygen --shm \\\n");
    fprintf(fp, "  -b %s \\\n", config->bundle_dir);
    fprintf(fp, "  -r %s \\\n", config->prime_dir);
    fprintf(fp, "  -D %s", config->ca_dir);

    /* NO privilege drop for poolgen - needs root for watchdog! */

    /* Runtime options */
    if (config->verbose) {
        fprintf(fp, " \\\n  -v");
    }

    fprintf(fp, " &\n\n");
}

/* Generate startup script for one instance */
static void generate_instance_script(FILE *fp, const config_data_t *config, const char *ip,
                                     int http_port, int https_port, int auto_port,
                                     bool is_ipv6, int instance_num) {
    const char *bin_name = is_ipv6 ? "tlsgateNGv6" : "tlsgateNGv4";

    fprintf(fp, "# Instance %d: %s (auto-registered with Watchdog)\n", instance_num, ip);
    fprintf(fp, "%s/%s \\\n", config->binary_path, bin_name);
    fprintf(fp, "  -l %s \\\n", ip);
    fprintf(fp, "  -p %d \\\n", http_port);
    fprintf(fp, "  -s %d \\\n", https_port);
    fprintf(fp, "  -a %d \\\n", auto_port);
    fprintf(fp, "  -D %s \\\n", config->ca_dir);

    /* Per-instance certificate cache */
    if (config->use_cert_cache && config->cert_dir_prefix[0] != '\0') {
        fprintf(fp, "  -C %s/%s%d \\\n", config->cert_dir_prefix,
                is_ipv6 ? "v6-" : "v4-", instance_num);
    }

    /* All instances read from shared memory pool */
    fprintf(fp, "  --shm \\\n");
    fprintf(fp, "  -w %d -m %d", config->worker_count, config->max_connections);

    /* Security options */
    if (config->drop_user[0] != '\0') {
        fprintf(fp, " \\\n  -u %s", config->drop_user);
    }
    if (config->drop_group[0] != '\0') {
        fprintf(fp, " \\\n  -g %s", config->drop_group);
    }

    /* Runtime options */
    if (config->verbose) {
        fprintf(fp, " \\\n  -v");
    }
    if (config->daemonize) {
        fprintf(fp, " \\\n  -d");
    }

    fprintf(fp, " &\n\n");
}

/* Generate master configuration file */
static int generate_master_config(const config_data_t *config) {
    const char *config_path = config_get_path();
    const char *config_dir = config_get_dir();
    FILE *fp;

    /* Create config directory if needed */
    if (access(config_dir, F_OK) != 0) {
        if (mkdir(config_dir, 0755) != 0) {
            fprintf(stderr, COLOR_RED "✗ Cannot create config directory: %s" COLOR_RESET "\n", config_dir);
            fprintf(stderr, "  Try running with sudo: sudo mkdir -p %s\n", config_dir);
            return 1;
        }
        printf(COLOR_GREEN "  ✓ Created config directory: %s" COLOR_RESET "\n", config_dir);
    }

    /* Open config file for writing */
    fp = fopen(config_path, "w");
    if (!fp) {
        fprintf(stderr, COLOR_RED "✗ Cannot create master config: %s" COLOR_RESET "\n", config_path);
        fprintf(stderr, "  Try running with sudo: sudo touch %s && sudo chmod 644 %s\n",
                config_path, config_path);
        return 1;
    }

    /* Write header */
    fprintf(fp, "# TLSGate NG Master Configuration\n");
    fprintf(fp, "# Generated by --generate-config\n");
    fprintf(fp, "# Location: %s\n", config_path);
    fprintf(fp, "# ==========================================\n\n");

    /* [version] section */
    fprintf(fp, "[version]\n");
    fprintf(fp, "# Format: MAJOR.MINOR.PATCH.BUILD (must match binary version!)\n");
    fprintf(fp, "%d.%d.%d.%d\n\n",
            TLSGATENG_VERSION_MAJOR, TLSGATENG_VERSION_MINOR,
            TLSGATENG_VERSION_PATCH, TLSGATENG_VERSION_BUILD);

    /* [prime] section */
    fprintf(fp, "[prime]\n");
    fprintf(fp, "# Prime pool directory for RSA acceleration\n");
    fprintf(fp, "# Shared across ALL instances on same physical server\n");
    fprintf(fp, "# Generate with: tlsgateNG-poolgen --generate-primes\n");
    fprintf(fp, "# Auto-created at: %s/primes\n", config_get_dir());
    if (config->prime_dir[0] != '\0') {
        fprintf(fp, "path=%s\n\n", config->prime_dir);
    } else {
        fprintf(fp, "#path=%s/primes\n\n", config_get_dir());
    }

    /* [keypool] section */
    fprintf(fp, "[keypool]\n");
    fprintf(fp, "# Keypool directory for pre-generated key bundles\n");
    fprintf(fp, "# Used by --poolkeygen to load bundles into shared memory\n");
    fprintf(fp, "# Auto-created at: %s/bundles\n", config_get_dir());
    if (config->bundle_dir[0] != '\0') {
        fprintf(fp, "path=%s\n\n", config->bundle_dir);
    } else {
        fprintf(fp, "#path=%s/bundles\n\n", config_get_dir());
    }

    /* [backup] section */
    fprintf(fp, "[backup]\n");
    fprintf(fp, "# Automatic backup (by index_master)\n");
    fprintf(fp, "enable=false\n");
    fprintf(fp, "# Master for backup - only ONE instance should be master!\n");
    fprintf(fp, "#master=true\n");
    fprintf(fp, "#path=%s/backup\n", config_get_dir());
    fprintf(fp, "#encrypt=false\n");
    fprintf(fp, "#ca_key=/etc/tlsgateNG/certs/ca-key.pem\n");
    fprintf(fp, "#curve=0\n\n");

    /* [index] section */
    fprintf(fp, "[index]\n");
    fprintf(fp, "# Master for certificate index management\n");
    fprintf(fp, "# Only ONE instance should be master!\n");
    fprintf(fp, "# Master handles: cert renewal, cleanup, index persistence\n");
    fprintf(fp, "#master=true\n\n");

    /* [pool] section */
    fprintf(fp, "[pool]\n");
    fprintf(fp, "# Shared memory for keypool\n");
    fprintf(fp, "use-shm=true\n");
    fprintf(fp, "# Poolgen mode (only for tlsgateNG-poolgen binary)\n");
    fprintf(fp, "#poolkeygen-mode=false\n");
    fprintf(fp, "# SHM cert cache capacity (1M = 1 million domains)\n");
    fprintf(fp, "#certcache-capacity=1M\n\n");

    /* [legacy] section */
    fprintf(fp, "[legacy]\n");
    fprintf(fp, "# Legacy/Weak Cryptography Support\n");
    fprintf(fp, "# Enables older algorithms (RSA-1024/2048, SHA1)\n");
    fprintf(fp, "# Use for: legacy clients (MS-DOS, OS/2, Win95, AS/400), industrial systems\n");
    fprintf(fp, "legacy-crypto=%s\n\n", config->legacy_crypto ? "true" : "false");

    /* [license] section */
    fprintf(fp, "[license]\n");
    fprintf(fp, "# Hardware-bound license (future feature)\n");
    fprintf(fp, "#key=\n");

    fclose(fp);

    printf(COLOR_GREEN "  ✓ Created master config: %s" COLOR_RESET "\n", config_path);
    return 0;
}

/* Generate systemd service file */
static void generate_systemd_service(const char *output_dir, const char *script_name,
                                     const char *description, bool is_ipv6) {
    char service_path[PATH_MAX];
    FILE *fp;

    snprintf(service_path, sizeof(service_path), "%s/tlsgateNG-%s.service",
             output_dir, is_ipv6 ? "ipv6" : "ipv4");

    fp = fopen(service_path, "w");
    if (!fp) {
        fprintf(stderr, COLOR_RED "✗ Cannot create service file: %s" COLOR_RESET "\n", service_path);
        return;
    }

    fprintf(fp, "[Unit]\n");
    fprintf(fp, "Description=%s\n", description);
    fprintf(fp, "After=network.target\n");
    fprintf(fp, "Wants=network-online.target\n\n");

    fprintf(fp, "[Service]\n");
    fprintf(fp, "Type=forking\n");
    fprintf(fp, "ExecStart=/bin/bash %s/%s\n", output_dir, script_name);
    fprintf(fp, "ExecStop=/usr/bin/pkill -f tlsgateNG\n");
    fprintf(fp, "Restart=on-failure\n");
    fprintf(fp, "RestartSec=5s\n");
    fprintf(fp, "StandardOutput=journal\n");
    fprintf(fp, "StandardError=journal\n\n");

    fprintf(fp, "[Install]\n");
    fprintf(fp, "WantedBy=multi-user.target\n");

    fclose(fp);

    printf(COLOR_GREEN "  ✓ Created: %s" COLOR_RESET "\n", service_path);
}

/* Generate configuration scripts */
static int generate_scripts(const config_data_t *config) {
    char output_dir[PATH_MAX];
    char script_ipv4[PATH_MAX + 32];  /* Extra space for filename suffix */
    char script_ipv6[PATH_MAX + 32];  /* Extra space for filename suffix */
    FILE *fp_ipv4 = NULL;
    FILE *fp_ipv6 = NULL;
    bool has_ipv4 = (config->ipv4[0] != '\0');
    bool has_ipv6 = (config->ipv6[0] != '\0');

    /* Create output directory */
    snprintf(output_dir, sizeof(output_dir), "/tmp/tlsgateNG");

    if (!dir_exists(output_dir)) {
        if (mkdir_recursive(output_dir) != 0) {
            fprintf(stderr, COLOR_RED "✗ Cannot create output directory: %s" COLOR_RESET "\n", output_dir);
            return 1;
        }
    }

    printf("\n");
    printf(COLOR_GREEN "Creating configuration scripts in: %s" COLOR_RESET "\n\n", output_dir);

    /* Generate IPv4 script */
    if (has_ipv4) {
        snprintf(script_ipv4, sizeof(script_ipv4), "%s/start-tlsgateNG-ipv4.sh", output_dir);
        fp_ipv4 = fopen(script_ipv4, "w");
        if (!fp_ipv4) {
            fprintf(stderr, COLOR_RED "✗ Cannot create IPv4 script: %s" COLOR_RESET "\n", script_ipv4);
            return 1;
        }

        fprintf(fp_ipv4, "#!/bin/bash\n");
        fprintf(fp_ipv4, "# TLSGate NG IPv4 Startup Script\n");
        fprintf(fp_ipv4, "# Generated: %s\n", __DATE__);
        fprintf(fp_ipv4, "# ==========================================\n\n");

        /* Start poolgen FIRST (generates keys for shared pool) */
        fprintf(fp_ipv4, "# Start keypool generator (fills shared memory pool)\n");
        fprintf(fp_ipv4, "echo \"Starting keypool generator...\"\n");
        generate_poolgen_script(fp_ipv4, config);
        fprintf(fp_ipv4, "# Wait for poolgen to initialize\n");
        fprintf(fp_ipv4, "sleep 2\n\n");

        /* Then start all reader instances */
        fprintf(fp_ipv4, "# Start reader instances (consume from shared pool)\n");
        for (int i = 0; i < config->backend_count; i++) {
            int http_port = config->start_port_http + i + 1;
            int https_port = config->start_port_https + i + 1;
            int auto_port = config->start_port_auto + i + 1;

            generate_instance_script(fp_ipv4, config, config->ipv4,
                                    http_port, https_port, auto_port,
                                    false, i + 1);
        }

        fprintf(fp_ipv4, "echo \"TLSGate NG IPv4 started\"\n");
        fprintf(fp_ipv4, "echo \"Poolgen: tlsgateNG-poolgen (key generator + watchdog)\"\n");
        fprintf(fp_ipv4, "echo \"Workers: %d instances (monitored by watchdog)\"\n", config->backend_count);
        fprintf(fp_ipv4, "echo \"Port ranges: HTTP:%d-%d, HTTPS:%d-%d, AUTO:%d-%d\"\n",
                config->start_port_http + 1, config->start_port_http + config->backend_count,
                config->start_port_https + 1, config->start_port_https + config->backend_count,
                config->start_port_auto + 1, config->start_port_auto + config->backend_count);

        fclose(fp_ipv4);
        chmod(script_ipv4, 0755);

        printf(COLOR_GREEN "  ✓ Created: %s" COLOR_RESET "\n", script_ipv4);

        /* Generate systemd service for IPv4 */
        generate_systemd_service(output_dir, "start-tlsgateNG-ipv4.sh",
                                "TLSGate NG IPv4 Instances", false);
    }

    /* Generate IPv6 script */
    if (has_ipv6) {
        snprintf(script_ipv6, sizeof(script_ipv6), "%s/start-tlsgateNG-ipv6.sh", output_dir);
        fp_ipv6 = fopen(script_ipv6, "w");
        if (!fp_ipv6) {
            fprintf(stderr, COLOR_RED "✗ Cannot create IPv6 script: %s" COLOR_RESET "\n", script_ipv6);
            return 1;
        }

        fprintf(fp_ipv6, "#!/bin/bash\n");
        fprintf(fp_ipv6, "# TLSGate NG IPv6 Startup Script\n");
        fprintf(fp_ipv6, "# Generated: %s\n", __DATE__);
        fprintf(fp_ipv6, "# ==========================================\n\n");

        /* Start poolgen FIRST (generates keys for shared pool) */
        fprintf(fp_ipv6, "# Start keypool generator (fills shared memory pool)\n");
        fprintf(fp_ipv6, "echo \"Starting keypool generator...\"\n");
        generate_poolgen_script(fp_ipv6, config);
        fprintf(fp_ipv6, "# Wait for poolgen to initialize\n");
        fprintf(fp_ipv6, "sleep 2\n\n");

        /* Then start all reader instances */
        fprintf(fp_ipv6, "# Start reader instances (consume from shared pool)\n");
        for (int i = 0; i < config->backend_count; i++) {
            int http_port = config->start_port_http + i + 1;
            int https_port = config->start_port_https + i + 1;
            int auto_port = config->start_port_auto + i + 1;

            generate_instance_script(fp_ipv6, config, config->ipv6,
                                    http_port, https_port, auto_port,
                                    true, i + 1);
        }

        fprintf(fp_ipv6, "echo \"TLSGate NG IPv6 started\"\n");
        fprintf(fp_ipv6, "echo \"Poolgen: tlsgateNG-poolgen (key generator + watchdog)\"\n");
        fprintf(fp_ipv6, "echo \"Workers: %d instances (monitored by watchdog)\"\n", config->backend_count);
        fprintf(fp_ipv6, "echo \"Port ranges: HTTP:%d-%d, HTTPS:%d-%d, AUTO:%d-%d\"\n",
                config->start_port_http + 1, config->start_port_http + config->backend_count,
                config->start_port_https + 1, config->start_port_https + config->backend_count,
                config->start_port_auto + 1, config->start_port_auto + config->backend_count);

        fclose(fp_ipv6);
        chmod(script_ipv6, 0755);

        printf(COLOR_GREEN "  ✓ Created: %s" COLOR_RESET "\n", script_ipv6);

        /* Generate systemd service for IPv6 */
        generate_systemd_service(output_dir, "start-tlsgateNG-ipv6.sh",
                                "TLSGate NG IPv6 Instances", true);
    }

    printf("\n");

    /* Generate master configuration file */
    printf("Generating master configuration file...\n");
    if (generate_master_config(config) != 0) {
        fprintf(stderr, COLOR_YELLOW "⚠ Warning: Failed to create master config" COLOR_RESET "\n");
        fprintf(stderr, "  You may need to create it manually with sudo\n");
    }

    printf("\n");
    printf(COLOR_GREEN "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    printf("Configuration files created successfully!" COLOR_RESET "\n\n");

    printf("Next steps:\n");
    printf("  1. Review the generated scripts in: %s\n", output_dir);
    printf("  2. Install systemd services:\n");
    if (has_ipv4) {
        printf("     sudo cp %s/tlsgateNG-ipv4.service /etc/systemd/system/\n", output_dir);
        printf("     sudo systemctl enable tlsgateNG-ipv4\n");
        printf("     sudo systemctl start tlsgateNG-ipv4\n");
    }
    if (has_ipv6) {
        printf("     sudo cp %s/tlsgateNG-ipv6.service /etc/systemd/system/\n", output_dir);
        printf("     sudo systemctl enable tlsgateNG-ipv6\n");
        printf("     sudo systemctl start tlsgateNG-ipv6\n");
    }
    printf("  3. Review master configuration:\n");
    printf("     %s\n", config_get_path());
    printf("  4. Check status:\n");
    printf("     sudo systemctl status tlsgateNG-ipv4\n");
    printf("     sudo systemctl status tlsgateNG-ipv6\n");
    printf("\n");

    return 0;
}

/* Interactive configuration generator */
int generate_config_interactive(void) {
    system_info_t sysinfo;
    config_data_t config = {0};

    print_header();

    /* Step 1: Get and display system information */
    get_system_info(&sysinfo);
    display_system_info(&sysinfo);

    /* Step 2: Binary location */
    print_section("BINARY LOCATION");

    /* Limit path length to allow for suffix */
    read_line_with_default("Path to TLSGate NG binaries", "/usr/local/bin", config.binary_path, sizeof(config.binary_path) - 32);

    /* Check if binaries exist */
    char binary_check[PATH_MAX + 32];  /* Extra space for "/tlsgateNG" */
    snprintf(binary_check, sizeof(binary_check), "%s/tlsgateNG", config.binary_path);

    if (!file_exists(binary_check)) {
        fprintf(stderr, COLOR_RED "✗ Error: Binary not found: %s" COLOR_RESET "\n", binary_check);
        fprintf(stderr, "  Please install TLSGate NG binaries first.\n");
        return 1;
    }

    printf(COLOR_GREEN "  ✓ Found: %s" COLOR_RESET "\n", binary_check);

    /* Check for poolgen binary (REQUIRED for shared keypool) */
    char poolgen_check[PATH_MAX + 32];
    snprintf(poolgen_check, sizeof(poolgen_check), "%s/tlsgateNG-poolgen", config.binary_path);

    if (!file_exists(poolgen_check)) {
        fprintf(stderr, COLOR_RED "✗ Error: Poolgen binary not found: %s" COLOR_RESET "\n", poolgen_check);
        fprintf(stderr, "  This binary is REQUIRED for shared memory keypool.\n");
        fprintf(stderr, "  Please install all TLSGate NG binaries (tlsgateNGv4, tlsgateNGv6, tlsgateNG-poolgen).\n");
        return 1;
    }

    printf(COLOR_GREEN "  ✓ Found: %s" COLOR_RESET "\n", poolgen_check);

    /* Step 3: IPv4 address */
    print_section("NETWORK CONFIGURATION");

    if (read_yes_no("Configure IPv4", true)) {
        read_line_with_default("IPv4 address", "0.0.0.0", config.ipv4, sizeof(config.ipv4));
    }

    /* Step 4: IPv6 address */
    if (read_yes_no("Configure IPv6", false)) {
        read_line_with_default("IPv6 address", "::", config.ipv6, sizeof(config.ipv6));
    }

    if (config.ipv4[0] == '\0' && config.ipv6[0] == '\0') {
        fprintf(stderr, COLOR_RED "✗ Error: At least one IP address (IPv4 or IPv6) must be configured" COLOR_RESET "\n");
        return 1;
    }

    /* Step 5: Backend server count */
    config.backend_count = read_int("Number of backend servers (2-10)", 3, 2, 10);

    /* Step 6: Start ports with availability check */
    bool ports_ok = false;
    while (!ports_ok) {
        print_section("PORT CONFIGURATION");

        config.start_port_http = read_int("HTTP start port", 30800, 1024, 65000);
        config.start_port_https = read_int("HTTPS start port", 34330, 1024, 65000);
        config.start_port_auto = read_int("AUTO start port", 38080, 1024, 65000);

        /* Check port availability */
        printf("\n");
        printf("Checking port availability for %d instances...\n", config.backend_count);

        bool has_conflicts = false;
        int conflict_count = 0;

        for (int i = 0; i < config.backend_count; i++) {
            int http_port = config.start_port_http + i + 1;
            int https_port = config.start_port_https + i + 1;
            int auto_port = config.start_port_auto + i + 1;

            /* Check IPv4 ports */
            if (config.ipv4[0] != '\0') {
                if (!check_port_available_ipv4(config.ipv4, http_port)) {
                    printf(COLOR_RED "  ✗ Port conflict: %s:%d (HTTP, Instance %d)" COLOR_RESET "\n",
                           config.ipv4, http_port, i + 1);
                    has_conflicts = true;
                    conflict_count++;
                }
                if (!check_port_available_ipv4(config.ipv4, https_port)) {
                    printf(COLOR_RED "  ✗ Port conflict: %s:%d (HTTPS, Instance %d)" COLOR_RESET "\n",
                           config.ipv4, https_port, i + 1);
                    has_conflicts = true;
                    conflict_count++;
                }
                if (!check_port_available_ipv4(config.ipv4, auto_port)) {
                    printf(COLOR_RED "  ✗ Port conflict: %s:%d (AUTO, Instance %d)" COLOR_RESET "\n",
                           config.ipv4, auto_port, i + 1);
                    has_conflicts = true;
                    conflict_count++;
                }
            }

            /* Check IPv6 ports */
            if (config.ipv6[0] != '\0') {
                if (!check_port_available_ipv6(config.ipv6, http_port)) {
                    printf(COLOR_RED "  ✗ Port conflict: [%s]:%d (HTTP, Instance %d)" COLOR_RESET "\n",
                           config.ipv6, http_port, i + 1);
                    has_conflicts = true;
                    conflict_count++;
                }
                if (!check_port_available_ipv6(config.ipv6, https_port)) {
                    printf(COLOR_RED "  ✗ Port conflict: [%s]:%d (HTTPS, Instance %d)" COLOR_RESET "\n",
                           config.ipv6, https_port, i + 1);
                    has_conflicts = true;
                    conflict_count++;
                }
                if (!check_port_available_ipv6(config.ipv6, auto_port)) {
                    printf(COLOR_RED "  ✗ Port conflict: [%s]:%d (AUTO, Instance %d)" COLOR_RESET "\n",
                           config.ipv6, auto_port, i + 1);
                    has_conflicts = true;
                    conflict_count++;
                }
            }
        }

        if (has_conflicts) {
            printf("\n");
            printf(COLOR_RED "✗ Found %d port conflict(s)!" COLOR_RESET "\n", conflict_count);
            printf(COLOR_YELLOW "  These ports are already in use and will cause HAProxy to fail." COLOR_RESET "\n");
            printf(COLOR_YELLOW "  Please choose different start ports." COLOR_RESET "\n");
            printf("\n");

            if (!read_yes_no("Reconfigure ports", true)) {
                printf(COLOR_YELLOW "⚠ Aborted by user" COLOR_RESET "\n");
                return 1;
            }
            /* Loop back to port configuration */
        } else {
            printf(COLOR_GREEN "  ✓ All ports available!" COLOR_RESET "\n");
            ports_ok = true;
        }
    }

    /* Step 7: Instance directory */
    print_section("STORAGE CONFIGURATION");

    read_line_with_default("Local storage path for instance", "/usr/local/etc/tlsgateNG",
                          config.instance_dir, sizeof(config.instance_dir) - 32);

    /* Step 8: Certificate directory structure check */
    /* New structure: instance_dir/{RSA,ECDSA,SM2,LEGACY}/{rootCA,certs}/ */
    /* Note: instance_dir is limited to PATH_MAX-32 by read_line_with_default above */
    char rsa_dir[PATH_MAX];
    if (strlen(config.instance_dir) < PATH_MAX - 8) {
        snprintf(rsa_dir, sizeof(rsa_dir), "%s/RSA", config.instance_dir);
    } else {
        fprintf(stderr, COLOR_RED "✗ Instance directory path too long" COLOR_RESET "\n");
        return 1;
    }

    if (!dir_exists(rsa_dir)) {
        printf(COLOR_YELLOW "  ⚠ Certificate directories do not exist in: %s" COLOR_RESET "\n", config.instance_dir);

        if (read_yes_no("Create certificate directory structure", true)) {
            config.create_ca_dir = true;

            /* Create base instance directory if needed */
            if (mkdir_recursive(config.instance_dir) != 0) {
                fprintf(stderr, COLOR_RED "✗ Error: Cannot create instance directory: %s" COLOR_RESET "\n", config.instance_dir);
                fprintf(stderr, "  Try running with sudo or create manually\n");
                return 1;
            }

            printf(COLOR_GREEN "  ✓ Created: %s" COLOR_RESET "\n", config.instance_dir);

            /* Create certificate type subdirectories with placeholder files */
            printf("  Creating certificate structure template...\n");
            /* Note: drop_user/drop_group not yet set, use defaults (tlsgateNG) */
            if (create_cert_structure(config.instance_dir, NULL, NULL) != 0) {
                fprintf(stderr, COLOR_RED "✗ Error: Cannot create certificate structure" COLOR_RESET "\n");
                return 1;
            }

            printf(COLOR_YELLOW "\n  ⚠ Install your CA certificates in the rootCA/ subdirectories:" COLOR_RESET "\n");
            printf("    RSA/rootCA/ca.pem       - RSA Root CA certificate\n");
            printf("    RSA/rootCA/subca.pem    - RSA Sub-CA certificate\n");
            printf("    RSA/rootCA/subca.cs.pem - RSA Sub-CA cross-signed\n");
            printf("    (same pattern for ECDSA/, SM2/, LEGACY/)\n");
            printf(COLOR_CYAN "  Generated certs will be written to {type}/certs/ directories" COLOR_RESET "\n");
        } else {
            fprintf(stderr, COLOR_RED "✗ Aborted: Certificate directory structure required" COLOR_RESET "\n");
            return 1;
        }
    } else {
        printf(COLOR_GREEN "  ✓ Certificate directories exist in: %s" COLOR_RESET "\n", config.instance_dir);
    }

    /* ca_dir points to instance_dir for -D parameter */
    strncpy(config.ca_dir, config.instance_dir, sizeof(config.ca_dir));

    /* Step 8a: Keypool configuration (CRITICAL for --poolkeygen) */
    print_section("KEYPOOL CONFIGURATION");

    /* Generate default paths based on OS */
    char default_bundles[PATH_MAX];
    char default_primes[PATH_MAX];
    snprintf(default_bundles, sizeof(default_bundles), "%s/bundles", config_get_dir());
    snprintf(default_primes, sizeof(default_primes), "%s/primes", config_get_dir());

    read_line_with_default("Key bundles directory", default_bundles,
                          config.bundle_dir, sizeof(config.bundle_dir));

    if (config.bundle_dir[0] != '\0' && !dir_exists(config.bundle_dir)) {
        printf(COLOR_YELLOW "  ⚠ Bundle directory does not exist: %s" COLOR_RESET "\n", config.bundle_dir);
        printf(COLOR_YELLOW "  ⚠ You must create it and run tlsgateNG-poolgen to generate bundles" COLOR_RESET "\n");
    } else if (config.bundle_dir[0] != '\0') {
        printf(COLOR_GREEN "  ✓ Bundle directory exists: %s" COLOR_RESET "\n", config.bundle_dir);
    }

    read_line_with_default("Prime pool directory", default_primes,
                          config.prime_dir, sizeof(config.prime_dir));

    if (config.prime_dir[0] != '\0' && !dir_exists(config.prime_dir)) {
        printf(COLOR_YELLOW "  ⚠ Prime directory does not exist: %s" COLOR_RESET "\n", config.prime_dir);
        printf(COLOR_YELLOW "  ⚠ You must create it and run tlsgateNG-poolgen --generate-primes" COLOR_RESET "\n");
    } else if (config.prime_dir[0] != '\0') {
        printf(COLOR_GREEN "  ✓ Prime directory exists: %s" COLOR_RESET "\n", config.prime_dir);
    }

    /* Step 8b: Performance configuration */
    print_section("PERFORMANCE TUNING");

    config.worker_count = read_int("Worker threads (recommended: 1-2 per CPU core)",
                                    sysinfo.cpu_cores, 1, 64);
    config.max_connections = read_int("Max connections per worker", 50000, 100, 100000);

    /* Step 8c: Certificate cache (optional) */
    print_section("CERTIFICATE CACHE (OPTIONAL)");

    printf("Per-instance certificate cache directories improve warm-start performance.\n");
    printf("Each instance will get its own subdirectory (e.g., v4-1, v4-2, v6-1, v6-2).\n\n");

    config.use_cert_cache = read_yes_no("Enable per-instance certificate cache", true);

    if (config.use_cert_cache) {
        read_line_with_default("Certificate cache base directory", "/opt/tlsgateNG/certcache",
                              config.cert_dir_prefix, sizeof(config.cert_dir_prefix));

        if (!dir_exists(config.cert_dir_prefix)) {
            printf(COLOR_YELLOW "  ⚠ Cache directory does not exist: %s" COLOR_RESET "\n", config.cert_dir_prefix);

            if (read_yes_no("Create cache directory", true)) {
                if (mkdir_recursive(config.cert_dir_prefix) != 0) {
                    fprintf(stderr, COLOR_RED "✗ Error: Cannot create cache directory: %s" COLOR_RESET "\n",
                            config.cert_dir_prefix);
                    fprintf(stderr, "  Try running with sudo or create manually\n");
                    config.use_cert_cache = false;
                } else {
                    printf(COLOR_GREEN "  ✓ Created: %s" COLOR_RESET "\n", config.cert_dir_prefix);
                }
            } else {
                config.use_cert_cache = false;
            }
        } else {
            printf(COLOR_GREEN "  ✓ Cache directory exists: %s" COLOR_RESET "\n", config.cert_dir_prefix);
        }
    }

    /* Step 8d: Security configuration */
    print_section("SECURITY OPTIONS");

    printf("For security, TLSGate NG can drop privileges after binding to privileged ports.\n");
    printf("This limits damage if the process is compromised.\n\n");

    if (read_yes_no("Drop privileges to non-root user", true)) {
        read_line_with_default("User to drop privileges to", "tlsgateNG",
                              config.drop_user, sizeof(config.drop_user));
        read_line_with_default("Group to drop privileges to", "tlsgateNG",
                              config.drop_group, sizeof(config.drop_group));
    } else {
        config.drop_user[0] = '\0';
        config.drop_group[0] = '\0';
    }

    /* Step 8e: Master config options */
    print_section("MASTER CONFIGURATION");

    printf("Legacy crypto support enables weak algorithms (RSA-1024/2048, SHA1)\n");
    printf("for old clients (MS-DOS, OS/2, Win3.11, Win95, AS/400).\n");
    printf(COLOR_YELLOW "WARNING: Cryptographically weak - only enable for legacy systems!" COLOR_RESET "\n\n");

    config.legacy_crypto = read_yes_no("Enable legacy crypto support", false);

    /* Step 8f: Runtime options */
    print_section("RUNTIME OPTIONS");

    printf("Verbose mode shows detailed logs (DEBUG level).\n");
    printf(COLOR_YELLOW "WARNING: High overhead - only use for debugging!" COLOR_RESET "\n\n");

    config.verbose = read_yes_no("Enable verbose logging", false);

    printf("\nDaemonize mode runs the process in the background.\n");
    printf("Note: systemd services typically don't need this (Type=forking).\n\n");

    config.daemonize = read_yes_no("Enable daemonize mode", true);

    /* Step 9: Summary and confirmation */
    print_section("CONFIGURATION SUMMARY");

    printf("System:\n");
    printf("  OS:           %s %s\n", sysinfo.os_name, sysinfo.os_version);
    printf("  CPU Cores:    %d\n", sysinfo.cpu_cores);
    printf("  RAM:          %ld MB\n", sysinfo.total_ram_mb);
    printf("\n");
    printf("Binary:\n");
    printf("  Path:         %s\n", config.binary_path);
    printf("\n");
    printf("Network:\n");
    if (config.ipv4[0]) {
        printf("  IPv4:         %s\n", config.ipv4);
    }
    if (config.ipv6[0]) {
        printf("  IPv6:         %s\n", config.ipv6);
    }
    printf("\n");
    printf("Architecture:\n");
    printf("  Poolgen:      1× tlsgateNG-poolgen (--poolkeygen --shm)\n");
    printf("                - Generates keys for shared memory pool\n");
    printf("                - WATCHDOG: Monitors workers, auto-restart on crash\n");
    printf("                - Runs as ROOT (no network ports)\n");
    printf("  Workers:      %d× server instances (--shm only)\n", config.backend_count);
    printf("                - Consume keys from shared pool\n");
    printf("                - Send heartbeat every 30s to poolgen\n");
    printf("  Port ranges:  HTTP:%d-%d, HTTPS:%d-%d, AUTO:%d-%d\n",
           config.start_port_http + 1, config.start_port_http + config.backend_count,
           config.start_port_https + 1, config.start_port_https + config.backend_count,
           config.start_port_auto + 1, config.start_port_auto + config.backend_count);
    printf("\n");
    printf("Storage:\n");
    printf("  Instance:     %s\n", config.instance_dir);
    printf("  Certs:        {RSA,ECDSA,SM2,LEGACY}/rootCA/ + certs/ + index/\n");
    printf("\n");
    printf("Keypool:\n");
    printf("  Bundles:      %s\n", config.bundle_dir[0] ? config.bundle_dir : "not configured");
    printf("  Primes:       %s\n", config.prime_dir[0] ? config.prime_dir : "not configured");
    printf("\n");
    printf("Performance:\n");
    printf("  Workers:      %d threads\n", config.worker_count);
    printf("  Max Conn:     %d per worker\n", config.max_connections);
    printf("\n");
    if (config.use_cert_cache) {
        printf("Certificate Cache:\n");
        printf("  Enabled:      Yes\n");
        printf("  Base Path:    %s\n", config.cert_dir_prefix);
        printf("  Per-instance: v4-1, v4-2, ..., v6-1, v6-2, ...\n");
        printf("\n");
    }
    if (config.drop_user[0] != '\0' || config.drop_group[0] != '\0') {
        printf("Security:\n");
        if (config.drop_user[0]) {
            printf("  Drop User:    %s\n", config.drop_user);
        }
        if (config.drop_group[0]) {
            printf("  Drop Group:   %s\n", config.drop_group);
        }
        printf("\n");
    }
    printf("Options:\n");
    printf("  Legacy Crypto: %s\n", config.legacy_crypto ? "enabled" : "disabled");
    printf("  Verbose:      %s\n", config.verbose ? "enabled" : "disabled");
    printf("  Daemonize:    %s\n", config.daemonize ? "enabled" : "disabled");
    printf("\n");
    printf("Output:\n");
    printf("  Scripts:      /tmp/tlsgateNG/\n");
    printf("  Services:     /tmp/tlsgateNG/*.service\n");
    printf("  Master Cfg:   %s\n", config_get_path());
    printf("\n");

    if (!read_yes_no("Generate configuration", true)) {
        printf(COLOR_YELLOW "⚠ Aborted by user" COLOR_RESET "\n");
        return 1;
    }

    /* Step 10-14: Generate scripts */
    return generate_scripts(&config);
}
