/**
 * TLSGateNG4 - Version Management & Help Functions
 * Copyright (C) 2026 Torsten Jahnke
 *
 * This module handles:
 * - Version information display
 * - Help/usage documentation
 * - About/credits screen
 *
 * Extracted from main tlsgateNG.c to reduce file size and improve maintainability.
 */

#include <stdio.h>
#include <openssl/opensslv.h>
#include "version.h"

/**
 * Display comprehensive help and usage information
 * Organized into logical sections: Network, TLS/PKI, Keypool, Security, Runtime, Utility, Examples
 */
void print_usage(const char *prog) {
    printf("TLSGate NG v%s GEN4 (2026) - High-Performance TLS Termination Wrapper Service\n\n", TLSGATENG_VERSION_STRING);
    printf("Usage: %s [options]\n\n", prog);

    printf("═══════════════════════════════════════════════════════════════════════\n");
    printf("  CONFIGURATION FILE\n");
    printf("═══════════════════════════════════════════════════════════════════════\n");
    printf("  ALL settings can be configured in: /etc/tlsgateNG/tlsgateNG.conf\n");
    printf("  Command-line options OVERRIDE config file settings.\n");
    printf("\n");
    printf("  Minimal startup (all settings from config file):\n");
    printf("    %s\n", prog);
    printf("\n");
#ifdef POOLGEN_ONLY
    printf("  Config file sections (Poolgen):\n");
    printf("    [directories] - ca-dir\n");
    printf("    [prime]       - path (Sophie-Germain primes for RSA)\n");
    printf("    [keypool]     - path (generated key bundles)\n");
    printf("    [backup]      - path (automatic backups)\n");
    printf("    [server]      - workers (generation threads)\n");
    printf("    [runtime]     - daemonize, verbose\n");
    printf("    [pool]        - pool-size, use-shm, certcache-capacity, force-algorithm\n");
    printf("                    rsa-3072-percent, ecdsa-p256-percent, sm2-percent\n");
    printf("    [certificate] - second-level-tld-file, silent-block-file\n");
    printf("                    (Poolgen loads both into SHM for Workers)\n");
    printf("    [ca-RSA/ECDSA/SM2/LEGACY] - Algorithm-specific CA paths\n");
    printf("\n");
#else
    printf("  Config file sections (Worker):\n");
    printf("    [server]      - listen-address, http-port, https-port, auto-port, workers, max-connections\n");
    printf("    [runtime]     - daemonize, verbose, user, group\n");
    printf("    [directories] - ca-dir\n");
    printf("    [pool]        - use-shm=true, certcache-capacity (must match poolgen)\n");
    printf("    [legacy]      - legacy-crypto, default-domain\n");
    printf("    [certificate] - enable-wildcards, enable-san, validity-days, cache-certificates\n");
    printf("    [html]        - html-path, any-responses\n");
    printf("    [framework-logging] - enabled, log-path, log-file-size, log-total-size\n");
    printf("    [ca-RSA/ECDSA/SM2/LEGACY] - Algorithm-specific CA paths\n");
    printf("\n");
    printf("  Worker reads from SHM (Poolgen manages everything):\n");
    printf("    - Keys: Consumed from SHM keypool\n");
    printf("    - Certificates: Read/write via SHM cert index\n");
    printf("    - Poolgen handles: Key generation, backups, index management\n");
    printf("\n");
#endif

    printf("═══════════════════════════════════════════════════════════════════════\n");
    printf("  NETWORK OPTIONS\n");
    printf("═══════════════════════════════════════════════════════════════════════\n");
    printf("  -l ADDR           Listen address (default: * = all interfaces)\n");
    printf("                      IPv4: 0.0.0.0 or specific IP (e.g., 192.168.1.100)\n");
    printf("                      IPv6: :: or specific IP (e.g., 2001:db8::1)\n");
    printf("                      Note: Auto-detects IPv4 vs IPv6 based on address\n");
    printf("\n");
    printf("  -p PORT           HTTP port (default: 80)\n");
    printf("                      Port 0: Disable HTTP port\n");
    printf("                      Standard: 80, 8080, 8000\n");
    printf("                      Serves: Favicon, HTML template, CORS headers\n");
    printf("\n");
    printf("  -s PORT           HTTPS port (default: 443)\n");
    printf("                      Port 0: Disable HTTPS port\n");
    printf("                      Standard: 443, 8443\n");
    printf("                      Features: Dynamic cert generation, SNI matching\n");
    printf("\n");
    printf("  -a PORT           AUTO port with MSG_PEEK SSL detection (default: 8080)\n");
    printf("                      Port 0: Disable AUTO port\n");
    printf("                      TCP: MSG_PEEK detects TLS ClientHello vs HTTP GET\n");
    printf("                      UDP: QUIC/HTTP3 support (HAProxy/firewall controlled)\n");
    printf("                      Note: Opens BOTH TCP and UDP sockets on same port\n");
    printf("\n");
    printf("  -w NUM            Worker threads (default: 4)\n");
    printf("                      Recommended: 1-2 per CPU core\n");
    printf("                      Range: 1-64 workers\n");
    printf("\n");
    printf("  -m NUM            Max connections per worker (default: 1000)\n");
    printf("                      Production: 50,000 per worker (200K total @ 4 workers)\n");
    printf("                      Note: Requires ulimit -n adjustment\n");
    printf("\n");
    printf("═══════════════════════════════════════════════════════════════════════\n");
    printf("  TLS/PKI OPTIONS\n");
    printf("═══════════════════════════════════════════════════════════════════════\n");
    printf("  -D, --ca-dir DIR  CA base directory (e.g., /etc/tlsgateNG/poolgen)\n");
    printf("                      Per-algorithm structure:\n");
    printf("                        DIR/RSA/rootCA/    - rootca.crt, subca.crt, subca.key\n");
    printf("                        DIR/RSA/certs/     - Generated certificates\n");
    printf("                        DIR/RSA/index/     - Certificate index\n");
    printf("                        DIR/ECDSA/rootCA/  - (same structure)\n");
    printf("                        DIR/SM2/rootCA/    - (same structure)\n");
    printf("                      PKI Hierarchy:\n");
    printf("                        rootca.crt = Root CA (trust anchor, install in browsers)\n");
    printf("                        subca.crt  = Sub CA certificate (signs end-entity certs)\n");
    printf("                        subca.key  = Sub CA private key (protected, root:root 0600)\n");
    printf("\n");
    printf("  -b, --bundles DIR   Pre-generated key bundle directory\n");
    printf("                      Example: /opt/tlsgateNG/bundles\n");
    printf("                      Formats:\n");
    printf("                        RSA:     keys.rsa.{1024-8192}[.NNN].bundle.gz\n");
    printf("                        ECDSA:   keys.ec.{256,384,521}[.NNN].bundle.gz\n");
    printf("                        Ed25519: keys.ed.25519[.NNN].bundle.gz\n");
    printf("                      Speed: 100× faster than on-demand generation\n");
    printf("                      Note: Generated with tlsgateNG-poolgen\n");
    printf("\n");
    printf("  -r, --prime-dir DIR Prime pool directory (RSA acceleration)\n");
    printf("                      Example: /opt/tlsgateNG/prime/primes\n");
    printf("                      Files: prime-{1024,2048,3072,4096,8192,16384}.bin\n");
    printf("                      Speed: 20-200× faster RSA generation\n");
    printf("                      Shared: Across ALL instances on same physical server\n");
    printf("                      Generate: tlsgateNG-poolgen --generate-primes\n");
    printf("                      Formats: prime-{size}.bin (combined p+q)\n");
    printf("                               prime-{size}-p.bin + prime-{size}-q.bin (separate)\n");
    printf("\n");
    printf("  --force-algorithm ALG Force single algorithm for all certificates (DEMO/TEST)\n");
    printf("                      Algorithms: RSA-3072, RSA-4096, RSA-8192, RSA-16384,\n");
    printf("                                  ECDSA-P256, ECDSA-P384, ECDSA-P521, SM2\n");
    printf("                      Use case: Demos, testing, per-IP algorithm assignment\n");
    printf("                      Example: --force-algorithm RSA-16384\n");
    printf("                      Note: Overrides multi-algorithm pool, uses ONLY specified algorithm\n");
    printf("\n");
    printf("  --pool-size NUM     Set keypool size (number of pre-generated keys)\n");
    printf("                      Range: 1-10000000 (1 to 10 million keys)\n");
    printf("                      Default: 6400 (local), 1280000 (SHM)\n");
    printf("                      Use case: Control RAM usage vs startup time tradeoff\n");
    printf("                      Examples: --pool-size 10000  (small demo)\n");
    printf("                                --pool-size 500000 (medium production)\n");
    printf("                                --pool-size 5000000 (large production)\n");
    printf("                      Note: Larger pools = more RAM, faster startup recovery\n");
    printf("\n");
    printf("═══════════════════════════════════════════════════════════════════════\n");
    printf("  KEYPOOL OPTIONS (Multi-Instance Deployment)\n");
    printf("═══════════════════════════════════════════════════════════════════════\n");
    printf("  --shm             Use shared memory keypool (server-wide)\n");
    printf("                      Purpose: Share pre-generated keys across instances\n");
    printf("                      Benefit: Eliminates per-instance key generation\n");
    printf("                      Required: For both --poolkeygen and reader instances\n");
    printf("\n");
    printf("  --ha-role ROLE    High Availability role for poolgen (primary|backup)\n");
    printf("                      Modes:\n");
    printf("                        primary - Tries to become active leader immediately\n");
    printf("                        backup  - Waits in standby until primary fails\n");
    printf("                      Uses flock() on /var/run/tlsgateNG/tlsgateNG-poolgen.lock\n");
    printf("                      Only ONE poolgen is active at a time:\n");
    printf("                        - Active: Runs keypool, watchdog, maintenance\n");
    printf("                        - Standby: Waits for lock, no work performed\n");
    printf("                      Failover: Automatic when active poolgen crashes/exits\n");
    printf("                      Example:\n");
    printf("                        Primary: tlsgateNG-poolgen --poolkeygen --shm --ha-role=primary\n");
    printf("                        Backup:  tlsgateNG-poolgen --poolkeygen --shm --ha-role=backup\n");
    printf("\n");
    printf("═══════════════════════════════════════════════════════════════════════\n");
    printf("  SECURITY OPTIONS\n");
    printf("═══════════════════════════════════════════════════════════════════════\n");
    printf("  -u USER           Drop privileges to USER after socket binding\n");
    printf("                      Example: -u nobody\n");
    printf("                      Security: Limits damage if process compromised\n");
    printf("                      Note: Must start as root to bind ports < 1024\n");
    printf("\n");
    printf("  -g GROUP          Drop privileges to GROUP after socket binding\n");
    printf("                      Example: -g nogroup\n");
    printf("                      Recommended: Use with -u for defense-in-depth\n");
    printf("\n");
    printf("  Legacy Crypto     Enable RSA-1024/2048 + SHA1 for legacy clients\n");
    printf("                      Config: Set legacy-crypto=true in [legacy] section\n");
    printf("                      Use case: MS-DOS, OS/2, Win3.11, Win95, AS/400\n");
    printf("                      Warning: Cryptographically weak - use only for legacy systems\n");
    printf("\n");
    printf("═══════════════════════════════════════════════════════════════════════\n");
    printf("  RUNTIME OPTIONS\n");
    printf("═══════════════════════════════════════════════════════════════════════\n");
    printf("  -d                Daemonize (run in background)\n");
    printf("                      Detaches from terminal\n");
    printf("                      Recommended: Use with systemd instead\n");
    printf("\n");
    printf("  -v                Verbose logging (DEBUG level)\n");
    printf("                      Shows: SSL detection, cert generation, connection details\n");
    printf("                      Warning: High overhead - use only for debugging\n");
    printf("                      Production: Omit this flag for SILENT mode\n");
    printf("\n");
    printf("═══════════════════════════════════════════════════════════════════════\n");
    printf("  UTILITY OPTIONS\n");
    printf("═══════════════════════════════════════════════════════════════════════\n");
    printf("  --generate-config, -G  Interactive configuration wizard\n");
    printf("                      Creates: Master config (/etc/tlsgateNG/tlsgateNG.conf)\n");
    printf("                      Creates: Startup scripts (poolkeygen + reader instances)\n");
    printf("                      Creates: systemd service files for IPv4/IPv6\n");
    printf("                      Output: /tmp/tlsgateNG/ (copy to system locations)\n");
    printf("                      Interactive: Asks for IPs, ports, paths, security settings\n");
    printf("\n");
    printf("  --test, -T        Test configuration (full validation + CA loading test)\n");
    printf("                      Validates: Files, directories, permissions, CA certs\n");
    printf("                      Tests: Actually loads and validates CA certificate chain\n");
    printf("                      Exit code: 0 = success, 1 = errors found\n");
    printf("\n");
    printf("  --checkconfig, -Q Quick configuration check (file existence only)\n");
    printf("                      Checks: CA files, directories, config sections, paths\n");
    printf("                      Shows: Which files exist/missing, algorithm-specific CAs\n");
    printf("                      Faster: Does not load/validate certificates\n");
    printf("                      Exit code: 0 = ready to start, 1 = missing files\n");
    printf("\n");
    printf("  --status          Show system status\n");
    printf("                      Displays: Config, prime pools, keypool, CA info\n");
    printf("                      Use: Before starting production instances\n");
    printf("\n");
    printf("  --shm-status      Show SHM keypool fill level\n");
    printf("                      Displays: Available keys, capacity, algorithm breakdown\n");
    printf("                      Use: Monitor keypool after reboot or during operation\n");
    printf("\n");
    printf("  --about           Show build information and active components\n");
    printf("                      Displays: Compiler flags, SIMD, io_uring, libcurl status\n");
    printf("                      Use: To verify build configuration and features\n");
    printf("\n");
    printf("  -V, --version     Show version information\n");
    printf("                      Displays: TLSGate NG version, build info\n");
    printf("\n");
    printf("  -h, --help        Show this help\n");
    printf("\n");
    printf("═══════════════════════════════════════════════════════════════════════\n");
    printf("  EXAMPLES\n");
    printf("═══════════════════════════════════════════════════════════════════════\n");
    printf("  Single instance (standalone):\n");
    printf("    %s -l 192.168.1.100 -p 80 -s 443 -a 8080 \\\n", prog);
    printf("              -D /opt/tlsgateNG -w 4 -m 50000\n");
    printf("\n");
    printf("  IPv6 instance:\n");
    printf("    %s -l 2001:db8::1 -p 80 -s 443 -a 8080 \\\n", prog);
    printf("              -D /opt/tlsgateNG\n");
    printf("\n");
    printf("  Disable HTTP, HTTPS only:\n");
    printf("    %s -p 0 -s 443 -a 0 -D /opt/tlsgateNG\n", prog);
    printf("\n");
    printf("  Multi-instance deployment:\n");
    printf("    # Reader instances (many per server):\n");
    printf("    %s --shm -l 192.168.1.100 -s 443 \\\n", prog);
    printf("              -C /opt/tlsgateNG/certcache/term1 -w 4\n");
    printf("    %s --shm -l 192.168.1.101 -s 443 \\\n", prog);
    printf("              -C /opt/tlsgateNG/certcache/term2 -w 4\n");
    printf("\n");
    printf("  Drop privileges:\n");
    printf("    %s -p 80 -s 443 -D /opt/tlsgateNG \\\n", prog);
    printf("              -u nobody -g nogroup\n");
    printf("\n");
    printf("  Force single algorithm (DEMO/TEST):\n");
    printf("    # IP 1: RSA-3072 only\n");
    printf("    %s -l 192.168.1.1 -s 443 -r /ramdisk/primes/ \\\n", prog);
    printf("              --force-algorithm RSA-3072\n");
    printf("\n");
    printf("    # IP 2: RSA-4096 only\n");
    printf("    %s -l 192.168.1.2 -s 443 -r /ramdisk/primes/ \\\n", prog);
    printf("              --force-algorithm RSA-4096\n");
    printf("\n");
    printf("    # IP 3: RSA-8192 only\n");
    printf("    %s -l 192.168.1.3 -s 443 -r /ramdisk/primes/ \\\n", prog);
    printf("              --force-algorithm RSA-8192\n");
    printf("\n");
    printf("    # IP 4: RSA-16384 only (VERY SLOW - demo only!)\n");
    printf("    %s -l 192.168.1.4 -s 443 -r /ramdisk/primes/ \\\n", prog);
    printf("              --force-algorithm RSA-16384\n");
    printf("\n");
    printf("  Custom pool sizes (optimize RAM vs startup time):\n");
    printf("    # Small demo: 10K keys (~12 seconds startup with RSA-3072)\n");
    printf("    %s --poolkeygen --shm -r /ramdisk/3072/ \\\n", prog);
    printf("              --force-algorithm RSA-3072 --pool-size 10000\n");
    printf("\n");
    printf("    # Medium production: 500K keys (~100 seconds startup)\n");
    printf("    %s --poolkeygen --shm -r /ramdisk/3072/ \\\n", prog);
    printf("              --force-algorithm RSA-3072 --pool-size 500000\n");
    printf("\n");
    printf("    # Large production: 5M keys (~1000 seconds = ~17 min startup)\n");
    printf("    %s --poolkeygen --shm -r /ramdisk/3072/ \\\n", prog);
    printf("              --force-algorithm RSA-3072 --pool-size 5000000\n");
    printf("\n");
    printf("═══════════════════════════════════════════════════════════════════════\n");
    printf("  DEPLOYMENT ARCHITECTURE\n");
    printf("═══════════════════════════════════════════════════════════════════════\n");
    printf("  Recommended: 4-6 IPs × 5-10 instances = 20-60 instances per server\n");
    printf("\n");
    printf("  Physical Server:\n");
    printf("    - 20-60× Reader Instances (consume from SHM keypool)\n");
    printf("    - Separate binaries: tlsgateNGv4 (IPv4), tlsgateNGv6 (IPv6)\n");
    printf("      Note: Binaries are identical, different names for HAProxy backend separation\n");
    printf("\n");
    printf("  Performance Targets:\n");
    printf("    - 500,000+ req/s HTTPS (io_uring)\n");
    printf("    - 50,000+ req/s HTTPS (epoll fallback)\n");
    printf("    - < 1ms latency (p99)\n");
    printf("    - 100× faster cert generation (ECDSA pre-generated)\n");
    printf("    - 16× faster HTTP parsing (SIMD)\n");
    printf("    - Zero logging overhead (SILENT mode)\n");
    printf("\n");
    printf("═══════════════════════════════════════════════════════════════════════\n");
    printf("  PORT FEATURES\n");
    printf("═══════════════════════════════════════════════════════════════════════\n");
    printf("  HTTP Port (-p):\n");
    printf("    - Always serves HTTP (no TLS)\n");
    printf("    - Favicon: 9,462 bytes (real ICO format)\n");
    printf("    - HTML template: Configurable in include/html_index.h (compile-time)\n");
    printf("    - Timestamp: %%s placeholder replaced with UTC time\n");
    printf("    - CORS: Access-Control-Allow-Origin: *\n");
    printf("    - Anti-AdBlock: Timing jitter, browser detection\n");
    printf("\n");
    printf("  HTTPS Port (-s):\n");
    printf("    - Always serves HTTPS (TLS required)\n");
    printf("    - Dynamic cert generation matching SNI\n");
    printf("    - Same content as HTTP port (favicon, template, CORS)\n");
    printf("\n");
    printf("  AUTO Port (-a):\n");
    printf("    - TCP: MSG_PEEK detection (4 bytes, EAGAIN safe)\n");
    printf("      Detects: 0x16 0x03 0x0X 0x?? = TLS ClientHello → HTTPS\n");
    printf("      Detects: 'G' 'E' 'T' ' ' = HTTP GET → HTTP\n");
    printf("    - UDP: QUIC/HTTP3 ready (HAProxy/firewall controlled)\n");
    printf("    - Same features as HTTP/HTTPS ports\n");
    printf("    - Use case: Single port for both HTTP and HTTPS\n");
    printf("\n");
    printf("  Disable Ports:\n");
    printf("    - Set port=0 to disable: -p 0 (no HTTP), -s 0 (no HTTPS), -a 0 (no AUTO)\n");
    printf("    - Validation: At least one port must be enabled\n");
    printf("\n");
    printf("For more information, see README.md or visit:\n");
    printf("  https://github.com/TorstenJahnke/TLSGateNGv4\n");
    printf("\n");
}

/**
 * Display version information
 */
void print_version(void) {
    printf("TLSGate NG v%s\n", TLSGATENG_VERSION_STRING);
    printf("%s\n", TLSGATENG_VERSION_FULL);
    printf("%s\n", TLSGATENG_COPYRIGHT);
    printf("\n");
    printf("%s\n", TLSGATENG_BUILD_INFO);
}

/**
 * Display about information with build details and active components
 */
void print_about(void) {
    printf("╔═══════════════════════════════════════════════════════════════╗\n");
    printf("║  %s - Build Information                              ║\n", TLSGATENG_PROJECT_NAME);
    printf("╚═══════════════════════════════════════════════════════════════╝\n");
    printf("\n");

    /* Version & Build Info */
    printf("Version:      %s\n", TLSGATENG_VERSION_FULL);
    printf("Build Date:   %s %s\n", TLSGATENG_BUILD_DATE, TLSGATENG_BUILD_TIME);
    printf("Compiler:     GCC %s\n", __VERSION__);
    printf("\n");

    /* Binary Type */
    printf("Binary Type:  ");
#ifdef POOLGEN_ONLY
    printf("Keypool Generator (no network)\n");
#elif defined(IPV4_OPTIMIZED)
    printf("IPv4-Optimized Network Server\n");
#elif defined(IPV6_OPTIMIZED)
    printf("IPv6-Optimized Network Server\n");
#else
    printf("Standard (IPv4/IPv6 Auto-Detect)\n");
#endif
    printf("\n");

    /* Active Components */
    printf("═══════════════════════════════════════════════════════════════\n");
    printf("ACTIVE COMPONENTS\n");
    printf("═══════════════════════════════════════════════════════════════\n");

    /* I/O Backend */
#ifdef HAVE_IOURING
    printf("  ✅ io_uring:       ENABLED (high-performance I/O)\n");
#else
    printf("  ❌ io_uring:       DISABLED (using epoll fallback)\n");
#endif

#ifdef HAVE_KQUEUE
    printf("  ✅ kqueue:         ENABLED (BSD/macOS I/O backend)\n");
#endif

    /* libcurl */
#ifdef HAVE_CURL
    printf("  ✅ libcurl:        ENABLED (reverse proxy feature)\n");
#else
    printf("  ❌ libcurl:        DISABLED (reverse proxy not available)\n");
#endif

    /* SSL/TLS */
    printf("  ✅ OpenSSL:        ENABLED (TLS/certificate generation)\n");

#ifdef OPENSSL_VERSION_TEXT
    /* Show OpenSSL version and SM2 support */
    printf("                     Version: %s\n", OPENSSL_VERSION_TEXT);

    /* Runtime check for SM2/SM3/SM4 support */
    #if OPENSSL_VERSION_NUMBER >= 0x30000000L
    /* OpenSSL 3.0+ has SM2/SM3/SM4 built-in */
    printf("                     SM2/SM3/SM4: Available (OpenSSL 3.x)\n");
    #elif OPENSSL_VERSION_NUMBER >= 0x10100000L
    /* OpenSSL 1.1.1+ may have SM2 if compiled with enable-ec_sm2 */
    printf("                     SM2/SM3/SM4: Check with 'openssl list -algorithms'\n");
    #else
    printf("                     SM2/SM3/SM4: Not available (OpenSSL too old)\n");
    #endif
#endif

    printf("\n");

    /* Compiler Optimizations */
    printf("═══════════════════════════════════════════════════════════════\n");
    printf("COMPILER OPTIMIZATIONS\n");
    printf("═══════════════════════════════════════════════════════════════\n");

    /* Build Mode */
#ifdef NDEBUG
    printf("  ✅ Build Mode:     PRODUCTION (NDEBUG, optimized)\n");
#else
    printf("  ⚠️  Build Mode:     DEBUG (assertions enabled)\n");
#endif

    /* LTO */
#ifdef __OPTIMIZE__
    printf("  ✅ Optimization:   -O%d (aggressive optimization)\n", __OPTIMIZE__);
#endif

    /* SIMD */
#if defined(__AVX2__)
    printf("  ✅ SIMD:           AVX2 + AVX + SSE4.2 + FMA\n");
#elif defined(__AVX__)
    printf("  ✅ SIMD:           AVX + SSE4.2\n");
#elif defined(__SSE4_2__)
    printf("  ✅ SIMD:           SSE4.2\n");
#else
    printf("  ⚠️  SIMD:           Not enabled\n");
#endif

    /* Security Features */
#ifdef _FORTIFY_SOURCE
    printf("  ✅ Security:       FORTIFY_SOURCE=%d (buffer overflow protection)\n", _FORTIFY_SOURCE);
#endif

#ifdef __SSP_STRONG__
    printf("  ✅ Stack Guard:    Strong stack protection enabled\n");
#elif defined(__SSP__)
    printf("  ✅ Stack Guard:    Stack protection enabled\n");
#endif

    /* PIE */
#ifdef __PIE__
    printf("  ✅ PIE:            Position Independent Executable\n");
#endif

    printf("\n");

    /* Architecture */
    printf("═══════════════════════════════════════════════════════════════\n");
    printf("ARCHITECTURE\n");
    printf("═══════════════════════════════════════════════════════════════\n");
    printf("  Platform:      %s\n", TLSGATENG_PLATFORM);
#if defined(__x86_64__) || defined(_M_X64)
    printf("  CPU Arch:      x86_64 (64-bit)\n");
#elif defined(__i386__) || defined(_M_IX86)
    printf("  CPU Arch:      x86 (32-bit)\n");
#elif defined(__aarch64__)
    printf("  CPU Arch:      ARM64 (64-bit)\n");
#elif defined(__arm__)
    printf("  CPU Arch:      ARM (32-bit)\n");
#else
    printf("  CPU Arch:      Unknown\n");
#endif

    printf("\n");
    printf("%s\n", TLSGATENG_COPYRIGHT);
    printf("License: %s\n", TLSGATENG_LICENSE);
    printf("\n");
}
