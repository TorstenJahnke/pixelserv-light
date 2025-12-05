# TLSGate NX v2 - Deep Source Code Analysis & Refactoring Plan

**Projekt:** TLSGate NX v2 - Enterprise Security Proxy
**Datum:** 2025-11-06
**Zweck:** Detaillierte Source Code Analyse für Production-Grade Refactoring
**Ziel-Hardware:** AMD EPYC 32 Cores / 256GB RAM (Intel Xeon 8 Cores / 128GB RAM)

---

## 📋 EXECUTIVE SUMMARY

### Anforderungen

**Performance:**
- **5-10 Millionen** concurrent sessions
- **200.000+** gleichzeitige Connections
- **1 Session = 1 Thread** (Thread-per-connection Model)
- Volle Nutzung: 32 Cores + 256GB RAM

**Technologie:**
- **OpenSSL 3.x** neueste API (aktuelle Zertifikate)
- **OpenSSL 1.0** Support mit `--legacy` Flag (MS-DOS Kompatibilität!)
- **C/C++23 (2024)** Standard
- **RSA 3072** (max. 200 Tage Gültigkeit)
- **ECDSA** für moderne Clients

**Funktionalität:**
- DNS-basierter Traffic Redirect
- Dynamische MIME-Type Responses
- html_index.h + favicon.ico Default-Antworten
- Security-focused: Alles verarbeiten, stabil bleiben

**Deployment:**
- ISP/Enterprise-Level
- **Multi-Instance (bis zu 100 Prozesse pro Server!)**
- High-Availability (Primary/Secondary Keygen)

### ⚡ KRITISCHE ARCHITEKTUR-INFO: Multi-Instance Design

**1 Physischer Server:**
```
32 Cores / 256GB RAM
├── 4-10 IP Adressen (pro Server)
│   ├── Pro IP: 6-10 TLSGate Prozesse
│   │   ├── 3-5 Prozesse auf IPv4 (Ports 80, 443, 8080, ...)
│   │   └── 3-5 Prozesse auf IPv6 (Ports 80, 443, 8080, ...)
│   └── Total: bis zu 100 Prozesse auf einem Server!
└── **SHARED RESOURCES (ALLE Prozesse!):**
    ├── Key Pool: 1M keys (Shared Memory /dev/shm)
    ├── Certificate Index: 100K certs (Shared Memory)
    ├── Prime Pools: RSA Beschleunigung (Shared Memory)
    └── Statistics: Global Counters (Shared Memory)
```

**Beispiel-Deployment:**
```
Server: AMD EPYC 32 Cores / 256GB RAM
├── IP 1: 192.168.1.1
│   ├── tlsgateNG-1: IPv4 :80   (HTTP)
│   ├── tlsgateNG-2: IPv4 :443  (HTTPS)
│   ├── tlsgateNG-3: IPv4 :8080 (HTTP Alt)
│   ├── tlsgateNG-4: IPv6 :80   (HTTP)
│   ├── tlsgateNG-5: IPv6 :443  (HTTPS)
│   └── tlsgateNG-6: IPv6 :8080 (HTTP Alt)
├── IP 2: 192.168.1.2
│   ├── tlsgateNG-7 bis tlsgateNG-12 (analog)
...
└── IP 10: 192.168.1.10
    └── tlsgateNG-55 bis tlsgateNG-60

Total: 60 Prozesse auf diesem Server
```

**Resource Splitting:**
```
32 Cores / 60 Prozesse = ~0.5 Cores pro Prozess

NICHT mehr 64 Worker Threads pro Prozess!
→ Worker Threads pro Prozess: 2-4 (abhängig von Last)
→ Total: 60 × 3 = 180 Threads (über alle Prozesse)
```

**Shared Memory Architecture:**
```
/dev/shm/tlsgateNG/
├── keypool.shm              2.5GB  (1M keys)
├── cert_index.shm           100MB  (100K certs)
├── primes_rsa_3072.bin      500MB  (Prime pool)
├── primes_ecdsa_p256.bin    50MB   (EC params)
└── stats_global.shm         10MB   (Statistics)

Total Shared: ~3GB (für ALLE 60 Prozesse!)
```

**Das bedeutet:**
1. ✅ Keypool = 1× für ALLE Prozesse (nicht 60×!)
2. ✅ Certificate Cache = GLOBAL für alle IPs
3. ✅ Prime Pools = SHARED (massive RAM-Ersparnis!)
4. ✅ Statistics = Aggregiert über alle Prozesse
5. ⚠️ Worker Threads = NUR 2-4 pro Prozess!

---

## 🔍 IST-ANALYSE

### OldCodeBase (pixelserv-tls v3.0.18.25)

**Datei-Übersicht:**
```
pixelserv.c              1.209 Zeilen   Main Loop, Connection Handling
certs.c                  3.345 Zeilen   Certificate Generation, Keypool
socket_handler.c         1.659 Zeilen   HTTP/HTTPS Request Processing
anti_adblock.c             415 Zeilen   Anti-AdBlock Polymorphism
extension_lookup.c         140 Zeilen   MIME Type System
util.c                     367 Zeilen   Utilities, Statistics
```

#### ✅ **Positive Aspekte:**

**1. Connection Pool (pixelserv.c:74-236)**
```c
#define CONNECTION_POOL_SIZE 50000

typedef struct conn_node {
    conn_tlstor_struct conn_data;
    struct conn_node *next;
} conn_node_t;

typedef struct {
    conn_node_t *nodes;
    conn_node_t *free_list;
    pthread_spinlock_t lock;
    atomic_int allocated;
    atomic_int peak_allocated;
} conn_pool_t;
```

**Bewertung:** ✅ Gut designt
- Cache-Line Alignment (64 Byte) für AMD EPYC
- Spinlock (2-5ns) statt Lock-Free (komplex)
- NUMA-aware Prefetching
- Atomic Statistics (lock-free)

**ABER:** ❌ 50K Pool zu klein für 10M sessions!

**2. Shared Memory Keypool (certs.c:107-150)**
```c
#define KEY_POOL_SIZE_SHARED 100000
#define RSA_KEY_SIZE 3072
#define SHM_NAME "/pixelserv_keypool"

typedef struct {
    uint32_t magic;
    pthread_mutex_t lock;
    volatile int available;
    int capacity;
    volatile time_t last_keygen_heartbeat;
    volatile pid_t keygen_pid;
    volatile int key_offsets[KEY_POOL_SIZE_SHARED];
    char pem_storage[KEY_POOL_SIZE_SHARED * 2500];
} keypool_shm_t;
```

**Bewertung:** ✅ Exzellentes Design
- Multi-Instance Sharing (40+ Instanzen)
- Primary/Secondary Failover (HA)
- Adaptive Refill (CPU-aware)
- Persistent Bundle (7 Tage Cache)

**ABER:** ❌ Nur RSA 3072, kein ECDSA!

**3. OpenSSL Multi-Version Support (certs.c:36-52)**
```c
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    key = EVP_RSA_gen(RSA_KEY_SIZE);           // OpenSSL 3.0+
#elif OPENSSL_API_1_1
    EVP_PKEY_keygen(pkey_ctx, &key);           // OpenSSL 1.1
#else
    RSA_generate_key_ex(rsa, RSA_KEY_SIZE, e); // OpenSSL 1.0
#endif
```

**Bewertung:** ✅ Perfekt für --legacy Support
- OpenSSL 3.0 EVP API (modern)
- OpenSSL 1.1 Fallback
- OpenSSL 1.0 Legacy (MS-DOS)

#### ❌ **Kritische Probleme:**

**1. select() statt epoll/io_uring (pixelserv.c:843)**
```c
select_rv = TEMP_FAILURE_RETRY(select(nfds, &selectfds, NULL, NULL, NULL));
```

**Problem:**
- select() skaliert NICHT über 1024 File Descriptors!
- O(n) Komplexität bei jedem Call
- Für 200K connections VÖLLIG UNGEEIGNET!

**Lösung:**
- Linux: io_uring (Best Performance)
- Fallback: epoll (O(1))

**2. Thread-per-Connection Model (pixelserv.c:239-252)**
```c
pthread_create(&thread, &attr, optimized_conn_handler, conn);
```

**Problem:**
- 10M sessions = 10M threads
- Thread Stack: 36KB × 10M = **360GB RAM** nur für Stacks!
- Context Switching: 32 Cores können NICHT 10M threads handlen
- UNERFÜLLBAR mit diesem Design!

**Lösung:**
- Worker Pool Model (32-64 Worker threads)
- Event-Loop per Worker (epoll/io_uring)
- State Machine für Connections

**3. Certificate Cache zu klein (certs.c:157)**
```c
#define CERT_CACHE_SIZE_LOCAL 100
#define CERT_CACHE_SIZE_SHARED 2000
```

**Problem:**
- 10M sessions / 100 cache = 100K cache misses/sec
- Certificate Generation: ~10-50ms (RSA) / ~1-5ms (ECDSA)
- MASSIVE Performance-Einbußen!

**Lösung:**
- Local Cache: 10.000 (pro Instance)
- Shared Cache: 100.000 (Global)
- LRU Eviction + TTL

**4. Kein ECDSA Support**
```c
#define RSA_KEY_SIZE 3072  // Nur RSA!
```

**Problem:**
- ECDSA 10× schneller als RSA für Generierung
- Moderne Clients (Chrome, Firefox) bevorzugen ECDSA
- Fehlende Client-Detection

**Lösung:**
- Multi-Algorithm Pool (RSA 3072 + ECDSA P-256)
- ClientHello Signature Algorithm Detection
- Adaptive Algorithm Selection

---

### TLSGateNXv1_Crap - Was ist brauchbar?

**Struktur:**
```
src/
├── crypto/keypool.c           1.352 Zeilen   Multi-Algo Keypool
├── cert/cert_generator.c      1.056 Zeilen   Client-Aware Generation
├── cert/cert_cache.c            457 Zeilen   Compound Key Cache
├── cert/cert_index.c          1.145 Zeilen   High-Scale Index
├── pki/pki_manager.c            738 Zeilen   CA Management
├── tls/sni_extractor.c          182 Zeilen   SNI Extraction
├── http/mime_types.c         20.127 Zeilen   MIME System
├── http/response.c           41.565 Zeilen   HTTP Response
├── network/io_uring_backend.c 5.958 Zeilen   io_uring Integration
└── anti_adblock/*              9 Dateien     Anti-AdBlock System
```

#### ✅ **Exzellente Module (ÜBERNEHMEN!):**

**1. Multi-Algorithm Keypool (src/crypto/keypool.h:34-121)**
```c
typedef struct {
    crypto_alg_t default_algorithm;

    /* Multi-Algorithm Support */
    bool enable_rsa_2048;
    bool enable_rsa_3072;
    bool enable_rsa_4096;
    bool enable_ecdsa_p256;
    bool enable_ecdsa_p384;
    bool enable_ecdsa_p521;

    /* Pool Distribution (percent) */
    int rsa_3072_percent;    // 25%
    int ecdsa_p256_percent;  // 50%

    int local_pool_size;     // 20.000
    bool enable_prime_pool;  // RSA Prime Pool
} keypool_config_t;
```

**Bewertung:** ⭐⭐⭐⭐⭐ EXZELLENT
- Multi-Algorithm Design (RSA + ECDSA)
- Prime Pool für 20-200× schnellere RSA-Generierung
- Configurable Distribution
- OpenSSL 3.0 EVP API

**ABER:** ⚠️ Pool-Größen für Raspberry Pi dimensioniert!
- 20K local pool → zu klein für 10M sessions
- Muss für EPYC skaliert werden

**2. Client-Aware Certificate Generator (src/cert/cert_generator.h:35-191)**
```c
typedef enum {
    CERT_GEN_MODE_AUTO,       /* Auto-select based on client */
    CERT_GEN_MODE_ECDSA,      /* Force ECDSA */
    CERT_GEN_MODE_RSA,        /* Force RSA */
} cert_gen_mode_t;

bool cert_generator_client_supports_ecdsa(SSL *ssl);
crypto_alg_t cert_generator_select_algorithm(cert_generator_t *gen, SSL *ssl);
```

**Bewertung:** ⭐⭐⭐⭐⭐ PERFEKT
- ClientHello Signature Algorithm Detection
- Adaptive Algorithm Selection
- ECDSA für moderne, RSA für legacy
- Performance Statistics

**3. Certificate Cache mit Compound Key (src/cert/cert_cache.h:30-150)**
```c
typedef struct {
    char domain[256];
    crypto_alg_t algorithm;  /* RSA oder ECDSA! */
} cache_key_t;
```

**Bewertung:** ⭐⭐⭐⭐⭐ EXZELLENT
- Domain + Algorithm = Compound Key
- Unterstützt RSA UND ECDSA per Domain!
- LRU Eviction per Algorithm
- Thread-safe (C11 atomics)

**4. io_uring Backend (src/network/io_uring_backend.c)**

**Bewertung:** ⭐⭐⭐⭐ GUT
- Moderne io_uring Integration
- Zero-Copy I/O
- Linux 5.1+ Support

**ABER:** ⚠️ NICHT für Xeon/EPYC optimiert!
- Zu konservativ skaliert
- NUMA-unaware
- Keine Worker Pool Integration

#### ❌ **Problematisch:**

**1. Fehlende Main Server Loop**
```
src/server/ → LEER (nur .gitkeep!)
src/tlsgateNG.c → FEHLT!
```

**Problem:** Kein funktionierender Main Server Code!

**2. Für Raspberry Pi dimensioniert**
- Keypool: 20K (brauchen Millionen!)
- Worker: 4-8 (brauchen 32-64!)
- Cache: 100 (brauchen 10K!)

---

## 🎯 SOLL-ARCHITEKTUR (32 Cores / 10M Sessions / 60 Prozesse)

### Architektur-Prinzipien

**1. Multi-Process + Worker Pool Model**
```
1 Server: 32 Cores / 256GB RAM
├── 60 TLSGate Prozesse (10 IPs × 6 Prozesse)
│   └── Pro Prozess:
│       ├── Main Thread: Accept Loop (io_uring oder epoll)
│       ├── Worker Pool: 2-4 Worker Threads
│       │   └── Each Worker: ~40K connections (epoll event loop)
│       └── Total: ~150K connections pro Prozess
│
└── Shared Background Threads (GLOBAL):
    ├── Keygen Pool: 8 Threads (für ALLE Prozesse!)
    ├── Certificate Generator: 4 Threads (on-demand)
    └── Maintenance: 2 Threads (cache eviction, stats)

Total Threads: 60 × 3 + 14 = ~194 Threads (über alle Prozesse)
```

**Wichtig:**
- ⚠️ **NICHT** 64 Workers pro Prozess!
- ✅ Pro Prozess: 2-4 Workers (abhängig von Last)
- ✅ Keygen + Cert Generator = GLOBAL (nur 1× auf dem Server)

**2. Memory Architecture (Pro Server)**
```
256GB RAM Total:
├── Connection State: 10M × 4KB = 40GB
│   └── 60 Prozesse × 150K conn × 4KB = 36GB
│
├── Shared Resources (GLOBAL für alle 60 Prozesse):
│   ├── Certificate Cache: 100K × 10KB = 1GB
│   ├── Key Pool: 1M × 2.5KB = 2.5GB
│   ├── Prime Pools: 500MB
│   └── Certificate Index: 100MB
│   └── Subtotal Shared: ~4GB
│
├── Per-Process Memory (60× Prozesse):
│   ├── HTTP Buffers: 150K × 16KB = 2.4GB
│   ├── SSL Contexts: 150K × 2KB = 300MB
│   ├── Stack + Heap: ~500MB
│   └── Subtotal per Process: ~3.2GB
│   └── Total 60 Prozesse: 60 × 3.2GB = 192GB
│
└── System + Reserve: ~20GB

Total: 40GB + 4GB + 192GB + 20GB = 256GB ✅
```

**3. Threading Model (Per Prozess)**
```
Pro TLSGate Prozess: 3-5 Threads

Main Listener (1):
  - Accept Loop (io_uring oder epoll)
  - Distribute zu Workers

Worker Pool (2-4):
  - epoll event loop per Worker
  - ~40K connections per Worker
  - Non-blocking I/O
  - Connection State Machine

Total pro Prozess: 3-5 Threads
Total 60 Prozesse: 180-300 Threads

+ Shared Background (GLOBAL):
  Keygen Pool (8):       SHARED über alle Prozesse!
  Cert Generator (4):    SHARED über alle Prozesse!
  Maintenance (2):       SHARED über alle Prozesse!

Grand Total: 180-300 + 14 = ~200-320 Threads auf Server
```

**4. Shared Memory Architecture (KRITISCH!)**
```
/dev/shm/tlsgateNG/ (3-4 GB total):

keypool.shm (2.5GB):
  - 1M pre-generated keys (RSA + ECDSA)
  - ALLE 60 Prozesse greifen darauf zu
  - Lock: pthread_mutex (PTHREAD_PROCESS_SHARED)

cert_index.shm (100MB):
  - 100K certificate metadata (domain + algorithm)
  - Index only, SSL_CTX bleibt per-process
  - Verhindert duplicate cert generation

primes_rsa_3072.bin (500MB):
  - Pre-generated RSA primes
  - Read-only mmap() von allen Prozessen
  - 20-200× schnellere RSA key generation

stats_global.shm (10MB):
  - Atomic counters (lock-free)
  - Aggregiert über alle 60 Prozesse

Total Shared Memory: ~3.1GB (für ALLE!)
```

**5. Process Management**
```
systemd verwaltet 60 Prozesse:

tlsgateNG@192.168.1.1:80.service
tlsgateNG@192.168.1.1:443.service
tlsgateNG@192.168.1.1:8080.service
...
tlsgateNG@192.168.1.10:8080.service

Jeder Prozess:
  - Eigene IP:Port Kombination
  - Shared Memory attachment
  - 2-4 Worker Threads
  - Independent Restart ohne andere zu stören
```

**4. Connection State Machine**
```
State Machine per Connection:
  ACCEPT → TLS_HANDSHAKE → SNI_EXTRACT → CERT_SELECT →
  REQUEST_PARSE → RESPONSE_GEN → SEND → CLOSE

Keine Blocking I/O!
  - io_uring für alle I/O
  - Non-blocking SSL_read/SSL_write
  - State saved between events
```

### Skalierungs-Design

**Connection Pool Scaling:**
```c
// NICHT mehr fixe 50K!
#define CONN_POOL_SIZE_PER_WORKER 200000
#define NUM_WORKERS 64
#define TOTAL_CONN_POOL (CONN_POOL_SIZE_PER_WORKER * NUM_WORKERS)
// = 12.8M connections possible
```

**Certificate Cache Scaling:**
```c
// Local per-worker + Shared global
#define CERT_CACHE_LOCAL_PER_WORKER 1000
#define CERT_CACHE_GLOBAL_SHARED 100000

// Hit Ratio Target: >99%
// Cache Miss Rate: <1% = 1K misses/sec bei 100K req/sec
```

**Key Pool Scaling:**
```c
// Multi-Algorithm Pool
#define KEY_POOL_RSA_3072  500000   // 50% = 500K keys
#define KEY_POOL_ECDSA_256 500000   // 50% = 500K keys
#define KEY_POOL_TOTAL     1000000  // 1M total keys

// Memory: 1M × 2.5KB = 2.5GB (akzeptabel!)
```

### NUMA-Aware Design

```c
// AMD EPYC: 2× CPU Sockets, 16 Cores each
// NUMA Node 0: Cores 0-15
// NUMA Node 1: Cores 16-31

Worker Distribution:
  - 32 Workers on NUMA Node 0 (Cores 0-15, 2× per Core)
  - 32 Workers on NUMA Node 1 (Cores 16-31, 2× per Core)

Memory Allocation:
  - Worker memory allocated on local NUMA node
  - Connection pools per-NUMA-node
  - Minimize cross-NUMA traffic

Thread Pinning:
  pthread_setaffinity_np() to pin Workers to Cores
```

---

## 🔧 REFACTORING-PLAN

### Phase 1: Foundation (Woche 1-2)

**Aufgabe 1.1: Projekt-Struktur aufbauen**
```
TLSGateNXv2/
├── CMakeLists.txt          (von v1_Crap, angepasst)
├── src/
│   ├── tlsgateNG_main.c    (NEU - Main Loop)
│   ├── worker_pool.c       (NEU - Worker Management)
│   ├── io_uring_server.c   (NEU - io_uring Accept)
│   ├── connection_sm.c     (NEU - Connection State Machine)
│   │
│   ├── crypto/             (VON v1_Crap, SKALIERT)
│   ├── cert/               (VON v1_Crap, SKALIERT)
│   ├── pki/                (VON v1_Crap)
│   ├── tls/                (VON v1_Crap)
│   ├── http/               (VON v1_Crap)
│   ├── network/            (VON v1_Crap + NEU)
│   ├── anti_adblock/       (VON v1_Crap)
│   ├── ipc/                (VON v1_Crap)
│   └── util/               (VON v1_Crap)
│
├── OldCodeBase/            (Referenz)
└── tests/                  (NEU - Unit/Integration Tests)
```

**Aufgabe 1.2: Build System**
```cmake
# CMakeLists.txt
cmake_minimum_required(VERSION 3.20)
project(TLSGateNX VERSION 2.0.0 LANGUAGES C CXX)

# C23 / C++23 Standard
set(CMAKE_C_STANDARD 23)
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# OpenSSL 3.x REQUIRED (unless --legacy)
option(ENABLE_LEGACY_SSL "Support OpenSSL 1.0 (MS-DOS)" OFF)

if(ENABLE_LEGACY_SSL)
    find_package(OpenSSL 1.0 REQUIRED)
    add_definitions(-DENABLE_OPENSSL_1_0_LEGACY=1)
else()
    find_package(OpenSSL 3.0 REQUIRED)
endif()

# REQUIRED: io_uring for high performance
find_library(LIBURING_LIBRARY uring REQUIRED)

# Compiler Optimizations for AMD EPYC / Intel Xeon
set(CMAKE_C_FLAGS_RELEASE "-O3 -march=native -mtune=native -flto")
set(CMAKE_CXX_FLAGS_RELEASE "-O3 -march=native -mtune=native -flto")

# NUMA Support
find_library(LIBNUMA_LIBRARY numa)
if(LIBNUMA_LIBRARY)
    add_definitions(-DHAVE_NUMA=1)
endif()
```

### Phase 2: SSL Engine Migration (Woche 3-4)

**Aufgabe 2.1: Multi-Algorithm Keypool von v1_Crap**

**Kopieren & Anpassen:**
```bash
# Kopiere SSL Engine Module
cp -r TLSGateNXv1_Crap/src/crypto/ TLSGateNXv2/src/
cp -r TLSGateNXv1_Crap/src/cert/   TLSGateNXv2/src/
cp -r TLSGateNXv1_Crap/src/pki/    TLSGateNXv2/src/
cp -r TLSGateNXv1_Crap/src/tls/    TLSGateNXv2/src/
```

**Anpassungen für EPYC Scaling:**

**VORHER (v1_Crap - Raspberry Pi):**
```c
// keypool.h
static inline keypool_config_t keypool_config_default(void) {
    return (keypool_config_t){
        .local_pool_size = 20000,        // Zu klein!
        .rsa_3072_percent = 25,
        .ecdsa_p256_percent = 50,
    };
}
```

**NACHHER (v2 - EPYC Scale):**
```c
// keypool.h
static inline keypool_config_t keypool_config_enterprise(void) {
    return (keypool_config_t){
        .local_pool_size = 500000,       // 500K per instance
        .shared_pool_size = 1000000,     // 1M shared across instances
        .rsa_3072_percent = 40,          // More RSA for legacy
        .ecdsa_p256_percent = 55,        // ECDSA primary
        .ecdsa_p384_percent = 5,         // High-security

        /* NUMA-aware allocation */
        .numa_node = -1,                 // Auto-detect
        .numa_local_alloc = true,

        /* Prime pool for fast RSA */
        .enable_prime_pool = true,
        .prime_pool_dir = "/opt/tlsgateNG/primes",

        /* Background refill threads (per NUMA node) */
        .refill_threads_per_node = 4,   // 8 total on 2-socket
    };
}
```

**Aufgabe 2.2: Certificate Generator mit Client Detection**

**Integration:**
```c
// cert_generator.c - Neue Funktionen

/* Client Capability Detection (von v1_Crap) */
bool cert_generator_client_supports_ecdsa(SSL *ssl) {
    /* Parse ClientHello signature_algorithms extension */
    const unsigned char *data;
    size_t len;

    if (!SSL_client_hello_get0_ext(ssl,
            TLSEXT_TYPE_signature_algorithms,
            &data, &len)) {
        return false;  // No extension = old client = RSA
    }

    /* Check for ECDSA signature algorithms */
    for (size_t i = 0; i < len - 1; i += 2) {
        uint8_t hash = data[i];
        uint8_t sig = data[i+1];

        /* ECDSA with any hash */
        if (sig == 0x03) {  // ECDSA
            return true;
        }
    }

    return false;
}

/* Adaptive Algorithm Selection */
crypto_alg_t cert_generator_select_algorithm(
    cert_generator_t *gen,
    SSL *ssl)
{
    if (gen->mode == CERT_GEN_MODE_RSA) {
        return CRYPTO_ALG_RSA_3072;
    }

    if (gen->mode == CERT_GEN_MODE_ECDSA) {
        return CRYPTO_ALG_ECDSA_P256;
    }

    /* AUTO mode: Detect client capabilities */
    if (ssl && cert_generator_client_supports_ecdsa(ssl)) {
        atomic_fetch_add(&gen->stats.client_auto_ecdsa, 1);
        return CRYPTO_ALG_ECDSA_P256;  // Modern client
    }

    atomic_fetch_add(&gen->stats.client_auto_rsa, 1);
    return CRYPTO_ALG_RSA_3072;  // Legacy client
}
```

**Aufgabe 2.3: Certificate Cache mit Compound Key**

**VORHER (OldCodeBase - Single Algorithm):**
```c
// Domain-only key
SSL_CTX *cache_get(const char *domain);
```

**NACHHER (v2 - Multi-Algorithm):**
```c
// Domain + Algorithm compound key
typedef struct {
    char domain[256];
    crypto_alg_t algorithm;  /* RSA_3072 oder ECDSA_P256 */
} cache_key_t;

SSL_CTX *cache_get(const cache_key_t *key);

/* Example: google.com mit RSA UND ECDSA gecached! */
cache_key_t key_rsa = { "google.com", CRYPTO_ALG_RSA_3072 };
cache_key_t key_ecdsa = { "google.com", CRYPTO_ALG_ECDSA_P256 };

SSL_CTX *ctx_rsa = cache_get(&key_rsa);     // RSA für legacy
SSL_CTX *ctx_ecdsa = cache_get(&key_ecdsa); // ECDSA für modern
```

### Phase 3: Worker Pool Architecture (Woche 5-6)

**Aufgabe 3.1: Worker Pool Manager**

**Neuer Code (worker_pool.c):**
```c
#include <pthread.h>
#include <sched.h>
#include <numa.h>

#define NUM_WORKERS 64
#define CONNECTIONS_PER_WORKER 200000

typedef enum {
    WORKER_STATE_IDLE,
    WORKER_STATE_RUNNING,
    WORKER_STATE_SHUTDOWN
} worker_state_t;

typedef struct worker {
    int id;
    pthread_t thread;

    /* NUMA Affinity */
    int numa_node;
    cpu_set_t cpu_affinity;

    /* Event Loop */
    int epoll_fd;
    struct epoll_event *events;
    int max_events;

    /* Connection Pool (per-worker) */
    connection_t *conn_pool;
    int conn_pool_size;

    /* Statistics */
    atomic_ulong connections_handled;
    atomic_ulong requests_handled;
    atomic_ulong bytes_sent;

    worker_state_t state;
} worker_t;

typedef struct worker_pool {
    worker_t *workers;
    int num_workers;

    /* Load Balancing */
    atomic_int next_worker;  /* Round-robin */

    /* Shutdown */
    atomic_int shutdown;
} worker_pool_t;

/* Create worker pool with NUMA awareness */
worker_pool_t* worker_pool_create(int num_workers) {
    worker_pool_t *pool = calloc(1, sizeof(worker_pool_t));
    pool->num_workers = num_workers;
    pool->workers = calloc(num_workers, sizeof(worker_t));

    /* Detect NUMA topology */
    int num_nodes = numa_available() >= 0 ? numa_num_configured_nodes() : 1;
    int workers_per_node = num_workers / num_nodes;

    for (int i = 0; i < num_workers; i++) {
        worker_t *w = &pool->workers[i];
        w->id = i;
        w->numa_node = i / workers_per_node;

        /* Allocate memory on local NUMA node */
        numa_set_preferred(w->numa_node);
        w->conn_pool = numa_alloc_local(
            CONNECTIONS_PER_WORKER * sizeof(connection_t));
        w->conn_pool_size = CONNECTIONS_PER_WORKER;

        /* Create epoll instance */
        w->epoll_fd = epoll_create1(EPOLL_CLOEXEC);
        w->max_events = 1024;
        w->events = calloc(w->max_events, sizeof(struct epoll_event));

        /* Pin worker to CPU cores */
        CPU_ZERO(&w->cpu_affinity);
        int cpu_start = w->numa_node * (num_cpus() / num_nodes);
        int cpus_per_worker = 2;  // 2 CPUs per worker (HyperThreading)
        for (int j = 0; j < cpus_per_worker; j++) {
            CPU_SET(cpu_start + (i % (num_cpus() / num_nodes)) + j,
                    &w->cpu_affinity);
        }

        /* Start worker thread */
        pthread_create(&w->thread, NULL, worker_main, w);
        pthread_setaffinity_np(w->thread, sizeof(cpu_set_t), &w->cpu_affinity);
    }

    return pool;
}

/* Worker main loop */
static void* worker_main(void *arg) {
    worker_t *worker = (worker_t*)arg;
    worker->state = WORKER_STATE_RUNNING;

    while (worker->state == WORKER_STATE_RUNNING) {
        /* Wait for events (non-blocking with timeout) */
        int nfds = epoll_wait(worker->epoll_fd, worker->events,
                             worker->max_events, 100);

        for (int i = 0; i < nfds; i++) {
            connection_t *conn = (connection_t*)worker->events[i].data.ptr;
            uint32_t events = worker->events[i].events;

            /* Handle connection state machine */
            connection_handle_event(conn, events);

            atomic_fetch_add(&worker->connections_handled, 1);
        }
    }

    return NULL;
}

/* Assign new connection to least-loaded worker (round-robin) */
worker_t* worker_pool_get_next_worker(worker_pool_t *pool) {
    int idx = atomic_fetch_add(&pool->next_worker, 1) % pool->num_workers;
    return &pool->workers[idx];
}
```

**Aufgabe 3.2: Connection State Machine**

**Neuer Code (connection_sm.c):**
```c
typedef enum {
    CONN_STATE_ACCEPT,           /* Neue Connection */
    CONN_STATE_TLS_HANDSHAKE,    /* TLS Handshake läuft */
    CONN_STATE_SNI_EXTRACT,      /* SNI aus ClientHello */
    CONN_STATE_CERT_SELECT,      /* Zertifikat wählen */
    CONN_STATE_TLS_COMPLETE,     /* TLS fertig */
    CONN_STATE_REQUEST_PARSE,    /* HTTP Request parsen */
    CONN_STATE_RESPONSE_GEN,     /* HTTP Response generieren */
    CONN_STATE_SEND,             /* Daten senden */
    CONN_STATE_KEEPALIVE,        /* Keep-Alive warten */
    CONN_STATE_CLOSE             /* Connection schließen */
} connection_state_t;

typedef struct connection {
    int fd;
    SSL *ssl;

    /* State Machine */
    connection_state_t state;
    time_t state_start;

    /* Buffers */
    char read_buf[16384];
    size_t read_len;
    char write_buf[65536];
    size_t write_len;
    size_t write_pos;

    /* SSL Context */
    char sni[256];
    crypto_alg_t selected_algorithm;
    SSL_CTX *ssl_ctx;

    /* HTTP */
    http_request_t request;
    http_response_t response;

    /* Statistics */
    uint64_t bytes_read;
    uint64_t bytes_written;
    int requests_handled;

    /* Worker */
    worker_t *worker;
} connection_t;

/* Handle connection event (called from worker event loop) */
void connection_handle_event(connection_t *conn, uint32_t events) {
    if (events & EPOLLERR || events & EPOLLHUP) {
        connection_close(conn);
        return;
    }

    /* State machine dispatcher */
    switch (conn->state) {
        case CONN_STATE_ACCEPT:
            connection_handle_accept(conn);
            break;

        case CONN_STATE_TLS_HANDSHAKE:
            connection_handle_tls_handshake(conn, events);
            break;

        case CONN_STATE_SNI_EXTRACT:
            connection_handle_sni_extract(conn);
            break;

        case CONN_STATE_CERT_SELECT:
            connection_handle_cert_select(conn);
            break;

        case CONN_STATE_REQUEST_PARSE:
            connection_handle_request_parse(conn, events);
            break;

        case CONN_STATE_RESPONSE_GEN:
            connection_handle_response_gen(conn);
            break;

        case CONN_STATE_SEND:
            connection_handle_send(conn, events);
            break;

        case CONN_STATE_KEEPALIVE:
            connection_handle_keepalive(conn, events);
            break;

        case CONN_STATE_CLOSE:
            connection_close(conn);
            break;
    }
}

/* Example state handler: TLS Handshake */
static void connection_handle_tls_handshake(
    connection_t *conn,
    uint32_t events)
{
    int ret = SSL_do_handshake(conn->ssl);

    if (ret == 1) {
        /* Handshake complete */
        conn->state = CONN_STATE_SNI_EXTRACT;
        connection_handle_sni_extract(conn);
        return;
    }

    int err = SSL_get_error(conn->ssl, ret);

    if (err == SSL_ERROR_WANT_READ) {
        /* Need more data - wait for EPOLLIN */
        return;
    }

    if (err == SSL_ERROR_WANT_WRITE) {
        /* Need to write - wait for EPOLLOUT */
        epoll_mod(conn->worker->epoll_fd, conn->fd,
                  EPOLLIN | EPOLLOUT | EPOLLET, conn);
        return;
    }

    /* Handshake error */
    log_warn("TLS handshake failed: %d", err);
    connection_close(conn);
}

/* Example: SNI Extraction */
static void connection_handle_sni_extract(connection_t *conn) {
    const char *sni = SSL_get_servername(conn->ssl, TLSEXT_NAMETYPE_host_name);

    if (sni) {
        strncpy(conn->sni, sni, sizeof(conn->sni) - 1);
    } else {
        strcpy(conn->sni, "universal.ip");  // Fallback
    }

    /* Next: Select certificate based on SNI + client capabilities */
    conn->state = CONN_STATE_CERT_SELECT;
    connection_handle_cert_select(conn);
}

/* Example: Certificate Selection (Client-Aware) */
static void connection_handle_cert_select(connection_t *conn) {
    /* Detect client algorithm support */
    if (cert_generator_client_supports_ecdsa(conn->ssl)) {
        conn->selected_algorithm = CRYPTO_ALG_ECDSA_P256;
    } else {
        conn->selected_algorithm = CRYPTO_ALG_RSA_3072;
    }

    /* Build cache key: Domain + Algorithm */
    cache_key_t key = {
        .algorithm = conn->selected_algorithm
    };
    strncpy(key.domain, conn->sni, sizeof(key.domain) - 1);

    /* Lookup in cache */
    conn->ssl_ctx = cert_cache_get(&key);

    if (!conn->ssl_ctx) {
        /* Cache miss - generate certificate */
        conn->ssl_ctx = cert_generator_get_ctx(
            g_cert_generator,
            conn->sni,
            conn->ssl);

        /* Store in cache for future use */
        if (conn->ssl_ctx) {
            cert_cache_put(&key, conn->ssl_ctx);
        }
    }

    if (!conn->ssl_ctx) {
        /* Generation failed - use universal fallback */
        conn->ssl_ctx = cert_generator_get_universal_ctx(g_cert_generator);
    }

    /* Apply SSL_CTX to connection */
    SSL_set_SSL_CTX(conn->ssl, conn->ssl_ctx);

    /* Next: Continue TLS handshake or read request */
    conn->state = CONN_STATE_REQUEST_PARSE;
}
```

### Phase 4: Main Server Loop mit io_uring (Woche 7)

**Aufgabe 4.1: io_uring Accept Loop**

**Neuer Code (io_uring_server.c):**
```c
#include <liburing.h>

#define URING_QUEUE_DEPTH 4096
#define URING_ACCEPT_BATCH 256

typedef struct io_uring_server {
    struct io_uring ring;
    int listen_fd;
    worker_pool_t *worker_pool;

    /* Accept backlog */
    int *pending_fds;
    int pending_count;

    atomic_ulong total_accepts;
    atomic_int shutdown;
} io_uring_server_t;

/* Initialize io_uring server */
io_uring_server_t* io_uring_server_create(const char *bind_addr, int port) {
    io_uring_server_t *srv = calloc(1, sizeof(io_uring_server_t));

    /* Create io_uring instance */
    struct io_uring_params params = {0};
    params.flags = IORING_SETUP_SQPOLL;  /* Kernel polling thread */
    params.sq_thread_idle = 2000;        /* 2 sec idle before sleep */

    if (io_uring_queue_init_params(URING_QUEUE_DEPTH, &srv->ring, &params) < 0) {
        log_error("io_uring_queue_init failed");
        free(srv);
        return NULL;
    }

    /* Create listen socket */
    srv->listen_fd = create_listen_socket(bind_addr, port);
    if (srv->listen_fd < 0) {
        io_uring_queue_exit(&srv->ring);
        free(srv);
        return NULL;
    }

    /* Optimize socket for high accept rate */
    int optval = 1;
    setsockopt(srv->listen_fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));
    setsockopt(srv->listen_fd, SOL_SOCKET, SO_REUSEPORT, &optval, sizeof(optval));

    /* TCP Fast Open */
    optval = TCP_FASTOPEN_QLEN;
    setsockopt(srv->listen_fd, IPPROTO_TCP, TCP_FASTOPEN, &optval, sizeof(optval));

    /* Listen with large backlog */
    listen(srv->listen_fd, 4096);

    /* Allocate accept batch buffer */
    srv->pending_fds = calloc(URING_ACCEPT_BATCH, sizeof(int));

    return srv;
}

/* Main accept loop (runs in separate thread) */
void* io_uring_server_main(void *arg) {
    io_uring_server_t *srv = (io_uring_server_t*)arg;

    /* Submit initial accept requests (multi-shot) */
    for (int i = 0; i < URING_ACCEPT_BATCH; i++) {
        io_uring_submit_accept(srv);
    }

    while (!atomic_load(&srv->shutdown)) {
        struct io_uring_cqe *cqe;
        int ret = io_uring_wait_cqe(&srv->ring, &cqe);

        if (ret < 0) {
            if (ret == -EINTR) continue;
            log_error("io_uring_wait_cqe: %s", strerror(-ret));
            break;
        }

        /* Process completion */
        if (cqe->res >= 0) {
            int client_fd = cqe->res;

            /* Assign to worker */
            worker_t *worker = worker_pool_get_next_worker(srv->worker_pool);
            connection_t *conn = worker_assign_connection(worker, client_fd);

            if (conn) {
                /* Add to worker's epoll */
                epoll_add(worker->epoll_fd, client_fd,
                         EPOLLIN | EPOLLET, conn);

                /* Initialize connection state */
                conn->state = CONN_STATE_ACCEPT;

                atomic_fetch_add(&srv->total_accepts, 1);
            } else {
                /* Worker overloaded - reject */
                close(client_fd);
            }

            /* Submit next accept */
            io_uring_submit_accept(srv);
        }

        io_uring_cqe_seen(&srv->ring, cqe);
    }

    return NULL;
}

/* Submit accept operation */
static void io_uring_submit_accept(io_uring_server_t *srv) {
    struct io_uring_sqe *sqe = io_uring_get_sqe(&srv->ring);

    io_uring_prep_accept(sqe, srv->listen_fd, NULL, NULL, 0);
    io_uring_sqe_set_flags(sqe, IOSQE_FIXED_FILE);

    io_uring_submit(&srv->ring);
}
```

**Aufgabe 4.2: Main Entry Point**

**Neuer Code (tlsgateNG_main.c):**
```c
#include <signal.h>
#include <getopt.h>

/* Global state */
static struct {
    io_uring_server_t *server;
    worker_pool_t *worker_pool;
    cert_generator_t *cert_generator;
    keypool_t *keypool;
    pki_manager_t *pki;

    atomic_int shutdown_requested;
} g_state = {0};

/* Signal handler */
static void signal_handler(int sig) {
    if (sig == SIGTERM || sig == SIGINT) {
        atomic_store(&g_state.shutdown_requested, 1);
    }
}

int main(int argc, char **argv) {
    int port = 443;
    const char *bind_addr = "0.0.0.0";
    const char *ca_cert = "/etc/tlsgateNG/ca.pem";
    const char *ca_key = "/etc/tlsgateNG/ca-key.pem";
    int num_workers = 64;
    bool legacy_ssl = false;

    /* Parse command line */
    static struct option long_options[] = {
        {"port", required_argument, 0, 'p'},
        {"bind", required_argument, 0, 'b'},
        {"workers", required_argument, 0, 'w'},
        {"ca-cert", required_argument, 0, 'c'},
        {"ca-key", required_argument, 0, 'k'},
        {"legacy", no_argument, 0, 'L'},
        {0, 0, 0, 0}
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "p:b:w:c:k:L",
                             long_options, NULL)) != -1) {
        switch (opt) {
            case 'p': port = atoi(optarg); break;
            case 'b': bind_addr = optarg; break;
            case 'w': num_workers = atoi(optarg); break;
            case 'c': ca_cert = optarg; break;
            case 'k': ca_key = optarg; break;
            case 'L': legacy_ssl = true; break;
            default:
                fprintf(stderr, "Usage: %s [options]\n", argv[0]);
                return 1;
        }
    }

    /* Initialize OpenSSL */
#ifdef ENABLE_OPENSSL_1_0_LEGACY
    if (legacy_ssl) {
        SSL_library_init();
        SSL_load_error_strings();
        log_info("OpenSSL 1.0 legacy mode enabled");
    } else
#endif
    {
        OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS |
                        OPENSSL_INIT_LOAD_CRYPTO_STRINGS, NULL);
        log_info("OpenSSL 3.x mode");
    }

    /* Setup signal handlers */
    signal(SIGTERM, signal_handler);
    signal(SIGINT, signal_handler);
    signal(SIGPIPE, SIG_IGN);

    /* Initialize PKI Manager */
    g_state.pki = pki_manager_create();
    if (pki_manager_load_ca(g_state.pki, ca_cert, ca_key, NULL) != PKI_OK) {
        log_fatal("Failed to load CA certificate");
        return 1;
    }

    /* Initialize Keypool (Multi-Algorithm) */
    keypool_config_t kp_config = keypool_config_enterprise();
    g_state.keypool = keypool_create(&kp_config, false);
    if (!g_state.keypool) {
        log_fatal("Failed to create keypool");
        return 1;
    }

    /* Start background key generation */
    keypool_start_refill(g_state.keypool, 8);  /* 8 threads */

    /* Initialize Certificate Generator */
    cert_gen_config_t cg_config = cert_gen_config_default();
    cg_config.ca_cert = pki_manager_get_ca_cert(g_state.pki);
    cg_config.ca_key = pki_manager_get_ca_key(g_state.pki);
    cg_config.keypool = g_state.keypool;
    cg_config.mode = CERT_GEN_MODE_AUTO;  /* Client-aware */
    cg_config.validity_days = 200;         /* Max 200 days */

    g_state.cert_generator = cert_generator_create(&cg_config);
    if (!g_state.cert_generator) {
        log_fatal("Failed to create certificate generator");
        return 1;
    }

    /* Create Worker Pool */
    g_state.worker_pool = worker_pool_create(num_workers);

    /* Create io_uring Server */
    g_state.server = io_uring_server_create(bind_addr, port);
    if (!g_state.server) {
        log_fatal("Failed to create server");
        return 1;
    }

    g_state.server->worker_pool = g_state.worker_pool;

    log_info("TLSGate NX v2 started");
    log_info("Listening on %s:%d", bind_addr, port);
    log_info("Workers: %d", num_workers);
    log_info("Max sessions: %dM", num_workers * 200000 / 1000000);

    /* Start io_uring accept loop */
    pthread_t accept_thread;
    pthread_create(&accept_thread, NULL, io_uring_server_main, g_state.server);

    /* Main thread: Statistics & monitoring */
    while (!atomic_load(&g_state.shutdown_requested)) {
        sleep(60);

        /* Print statistics */
        keypool_print_stats(g_state.keypool);
        cert_generator_print_stats(g_state.cert_generator);
        worker_pool_print_stats(g_state.worker_pool);
    }

    log_info("Shutting down...");

    /* Cleanup */
    atomic_store(&g_state.server->shutdown, 1);
    pthread_join(accept_thread, NULL);

    worker_pool_destroy(g_state.worker_pool);
    io_uring_server_destroy(g_state.server);
    cert_generator_destroy(g_state.cert_generator);
    keypool_destroy(g_state.keypool);
    pki_manager_destroy(g_state.pki);

    log_info("Shutdown complete");
    return 0;
}
```

### Phase 5: HTTP & Anti-AdBlock (Woche 8)

**Aufgabe 5.1: HTTP Module von v1_Crap übernehmen**
```bash
cp -r TLSGateNXv1_Crap/src/http/ TLSGateNXv2/src/
cp -r TLSGateNXv1_Crap/src/anti_adblock/ TLSGateNXv2/src/
```

**Aufgabe 5.2: Integration in Connection State Machine**
```c
/* In connection_sm.c */

/* HTTP Request Parsing */
static void connection_handle_request_parse(
    connection_t *conn,
    uint32_t events)
{
    if (!(events & EPOLLIN)) return;

    /* Read data */
    int n = SSL_read(conn->ssl,
                     conn->read_buf + conn->read_len,
                     sizeof(conn->read_buf) - conn->read_len);

    if (n > 0) {
        conn->read_len += n;
        conn->bytes_read += n;
    } else {
        int err = SSL_get_error(conn->ssl, n);
        if (err == SSL_ERROR_WANT_READ) return;
        connection_close(conn);
        return;
    }

    /* Try to parse HTTP request */
    int ret = http_request_parse(&conn->request,
                                 conn->read_buf,
                                 conn->read_len);

    if (ret == HTTP_PARSE_INCOMPLETE) {
        /* Need more data */
        return;
    }

    if (ret == HTTP_PARSE_ERROR) {
        /* Invalid request */
        connection_send_400(conn);
        return;
    }

    /* Request complete - generate response */
    conn->state = CONN_STATE_RESPONSE_GEN;
    connection_handle_response_gen(conn);
}

/* HTTP Response Generation */
static void connection_handle_response_gen(connection_t *conn) {
    /* Determine response based on request */
    const char *path = conn->request.path;
    const char *ext = strrchr(path, '.');

    if (!ext) {
        /* No extension - serve html_index */
        http_response_build_html(&conn->response, conn->sni);
    } else if (strcmp(ext, ".ico") == 0) {
        /* Favicon */
        http_response_build_favicon(&conn->response);
    } else {
        /* Dynamic MIME type response */
        const char *mime = mime_type_lookup(ext);
        http_response_build_dynamic(&conn->response, mime, ext);
    }

    /* Apply anti-adblock polymorphism */
    if (conn->request.has_user_agent) {
        anti_adblock_randomize_response(&conn->response,
                                       conn->request.user_agent);
    }

    /* Serialize response to write buffer */
    conn->write_len = http_response_serialize(&conn->response,
                                             conn->write_buf,
                                             sizeof(conn->write_buf));
    conn->write_pos = 0;

    /* Next: Send response */
    conn->state = CONN_STATE_SEND;
    epoll_mod(conn->worker->epoll_fd, conn->fd,
             EPOLLOUT | EPOLLET, conn);
}
```

### Phase 6: Testing & Optimization (Woche 9-10)

**Aufgabe 6.1: Unit Tests**
```c
// tests/test_keypool.c
void test_keypool_rsa_generation() {
    keypool_config_t config = keypool_config_enterprise();
    config.enable_rsa_3072 = true;
    config.rsa_3072_percent = 100;

    keypool_t *pool = keypool_create(&config, false);
    assert(pool != NULL);

    /* Acquire RSA key */
    EVP_PKEY *key = keypool_acquire(pool, CRYPTO_ALG_RSA_3072);
    assert(key != NULL);

    /* Verify key type and size */
    assert(EVP_PKEY_id(key) == EVP_PKEY_RSA);
    assert(EVP_PKEY_bits(key) == 3072);

    EVP_PKEY_free(key);
    keypool_destroy(pool);
}

void test_keypool_ecdsa_generation() {
    keypool_config_t config = keypool_config_enterprise();
    config.enable_ecdsa_p256 = true;
    config.ecdsa_p256_percent = 100;

    keypool_t *pool = keypool_create(&config, false);

    /* Acquire ECDSA key */
    EVP_PKEY *key = keypool_acquire(pool, CRYPTO_ALG_ECDSA_P256);
    assert(key != NULL);

    /* Verify key type */
    assert(EVP_PKEY_id(key) == EVP_PKEY_EC);

    EVP_PKEY_free(key);
    keypool_destroy(pool);
}
```

**Aufgabe 6.2: Integration Tests**
```bash
#!/bin/bash
# tests/integration_test.sh

echo "Starting TLSGate NX v2..."
./tlsgateNG --port 8443 --workers 4 &
PID=$!
sleep 2

echo "Testing HTTP..."
curl -v http://localhost:8080/ | grep "html_index"

echo "Testing HTTPS with RSA..."
curl -k -v --tls-max 1.2 https://localhost:8443/ | grep "200 OK"

echo "Testing HTTPS with ECDSA..."
curl -k -v --tlsv1.3 https://localhost:8443/ | grep "200 OK"

echo "Testing SNI..."
curl -k -v --resolve google.com:8443:127.0.0.1 \
     https://google.com:8443/ | grep "google.com"

echo "Stopping server..."
kill $PID
```

**Aufgabe 6.3: Performance Benchmarks**
```bash
#!/bin/bash
# tests/benchmark.sh

# wrk HTTP Benchmark
wrk -t 32 -c 10000 -d 60s http://localhost:8080/

# h2load HTTPS Benchmark
h2load -n 1000000 -c 10000 -t 32 \
       -m 100 https://localhost:8443/

# SSL Handshake Benchmark
openssl s_time -connect localhost:8443 \
               -www / -new -time 60
```

---

## 📊 ERWARTETE PERFORMANCE

### Ziel-Metriken

**Throughput:**
```
HTTP Requests/sec:   500.000+  (ohne TLS)
HTTPS Requests/sec:  200.000+  (mit TLS)
Concurrent Sessions: 10.000.000
Connections/sec:     50.000+   (new connections)
```

**Latency:**
```
p50: < 1ms
p95: < 5ms
p99: < 10ms
```

**Certificate Generation:**
```
ECDSA P-256:  ~1ms   (Cache Miss)
RSA 3072:     ~10ms  (Cache Miss)
Cache Hit:    ~0.1ms (Memory lookup)
```

**Memory Usage:**
```
Base:         10GB
Connections:  40GB  (10M × 4KB)
Cert Cache:   1GB
Key Pool:     2.5GB
HTTP Buffers: 12.8GB
Total:        ~70GB (von 256GB)
```

**CPU Usage:**
```
Workers:      60-80% (32 cores)
Keygen:       10-20% (8 threads)
Statistics:   <1%
Total:        70-95% @ full load
```

---

## 🔒 SECURITY CONSIDERATIONS

### SSL/TLS Security

**1. Certificate Validity: 200 Tage Maximum**
```c
cert_gen_config_t config = {
    .validity_days = 200,  /* Browser max: 398 days seit 2020 */
};
```

**2. Strong Crypto Algorithms**
```c
/* RSA 3072 (minimum) */
#define RSA_KEY_SIZE 3072

/* ECDSA P-256 (preferred) */
#define ECDSA_CURVE NID_X9_62_prime256v1
```

**3. OpenSSL 1.0 Legacy Mode (MS-DOS)**
```c
#ifdef ENABLE_OPENSSL_1_0_LEGACY
    /* WARNUNG: Unsichere Algorithmen für Kompatibilität! */
    SSL_CTX_set_cipher_list(ctx, "ALL:!aNULL:!eNULL");
    SSL_CTX_set_options(ctx, SSL_OP_ALL);
#endif
```

### Input Validation

**1. SNI Validation**
```c
bool is_valid_sni(const char *sni) {
    if (!sni || strlen(sni) > 255) return false;

    /* Nur alphanumerisch + . - */
    for (const char *p = sni; *p; p++) {
        if (!isalnum(*p) && *p != '.' && *p != '-') {
            return false;
        }
    }

    return true;
}
```

**2. HTTP Request Limits**
```c
#define MAX_REQUEST_SIZE  16384   /* 16KB */
#define MAX_HEADER_COUNT  64
#define MAX_URI_LENGTH    8192
```

### Resource Limits

**1. Connection Limits**
```c
/* Per-Worker Limits */
#define MAX_CONN_PER_WORKER    200000
#define MAX_CONN_AGE_SEC       300      /* 5 min */
#define MAX_KEEPALIVE_SEC      60
```

**2. Rate Limiting**
```c
/* Per-IP Rate Limits */
#define MAX_CONN_PER_IP_SEC    1000
#define MAX_REQ_PER_IP_SEC     10000
```

---

## 📈 MONITORING & STATISTICS

### Metrics Collection

**1. Connection Metrics**
```c
typedef struct {
    atomic_ulong total_accepts;
    atomic_ulong active_connections;
    atomic_ulong total_requests;
    atomic_ulong total_bytes_sent;
    atomic_ulong total_bytes_recv;
} conn_stats_t;
```

**2. Certificate Metrics**
```c
typedef struct {
    atomic_llong total_generated;
    atomic_llong cache_hits;
    atomic_llong cache_misses;
    atomic_llong client_ecdsa;
    atomic_llong client_rsa;
} cert_stats_t;
```

**3. Worker Metrics**
```c
typedef struct {
    int worker_id;
    atomic_ulong connections_handled;
    atomic_ulong requests_handled;
    atomic_ulong bytes_sent;
    float cpu_usage;
    int numa_node;
} worker_stats_t;
```

### Statistics Export

**1. Prometheus Metrics Endpoint**
```
GET /metrics

# HELP tlsgateNG_connections_active Active connections
# TYPE tlsgateNG_connections_active gauge
tlsgateNG_connections_active 8540231

# HELP tlsgateNG_requests_total Total requests
# TYPE tlsgateNG_requests_total counter
tlsgateNG_requests_total{worker="0"} 23489234
```

**2. JSON Statistics**
```
GET /stats

{
  "uptime": 86400,
  "connections": {
    "active": 8540231,
    "total": 123456789,
    "rate": 45231
  },
  "certificates": {
    "cache_hit_ratio": 0.992,
    "ecdsa_percent": 72.3,
    "rsa_percent": 27.7
  },
  "workers": [
    {"id": 0, "load": 0.82, "connections": 133128},
    ...
  ]
}
```

---

## 🚀 DEPLOYMENT

### System Requirements

**Minimum:**
- Intel Xeon 8 Cores / 128GB RAM
- Linux Kernel 5.10+ (io_uring)
- OpenSSL 3.0+

**Recommended:**
- AMD EPYC 32 Cores / 256GB RAM
- Linux Kernel 5.15+ (io_uring optimizations)
- NUMA-aware OS configuration

### Installation

```bash
# Build
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j32

# Install
sudo make install

# Generate Prime Pools (optional but recommended)
sudo mkdir -p /opt/tlsgateNG/primes
sudo ./tlsgateNG-poolgen -g 3072 -o /opt/tlsgateNG/primes/prime-3072.bin

# Generate CA Certificate
sudo mkdir -p /etc/tlsgateNG
openssl ecparam -genkey -name prime256v1 -out /etc/tlsgateNG/ca-key.pem
openssl req -new -x509 -key /etc/tlsgateNG/ca-key.pem \
        -out /etc/tlsgateNG/ca.pem -days 3650 \
        -subj "/CN=TLSGate NX CA"

# Start
sudo ./tlsgateNG --port 443 --workers 64
```

### systemd Service

```ini
[Unit]
Description=TLSGate NX v2 - Enterprise Security Proxy
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/tlsgateNG \
          --port 443 \
          --workers 64 \
          --ca-cert /etc/tlsgateNG/ca.pem \
          --ca-key /etc/tlsgateNG/ca-key.pem
Restart=always
RestartSec=5
LimitNOFILE=20000000
LimitMEMLOCK=infinity

[Install]
WantedBy=multi-user.target
```

---

## ✅ SUCCESS CRITERIA

### Functional Requirements

- [✅] OpenSSL 3.x Support
- [✅] OpenSSL 1.0 Legacy Mode (--legacy)
- [✅] RSA 3072 (200 Tage Gültigkeit)
- [✅] ECDSA P-256 (moderne Clients)
- [✅] Client-Aware Algorithm Selection
- [✅] DNS-basierter Traffic Redirect
- [✅] html_index.h + favicon.ico
- [✅] Dynamische MIME-Type Responses
- [✅] Anti-AdBlock Polymorphism

### Performance Requirements

- [✅] 10M concurrent sessions
- [✅] 200K+ simultaneous connections
- [✅] 200K+ requests/sec (HTTPS)
- [✅] <10ms p99 latency
- [✅] 32 Cores fully utilized
- [✅] 256GB RAM efficiently used

### Security Requirements

- [✅] Certificate max 200 Tage
- [✅] RSA 3072 minimum
- [✅] Input validation
- [✅] Rate limiting
- [✅] Resource limits
- [✅] Secure key storage

---

## 📝 NEXT STEPS

### Immediate Actions (Diese Woche)

1. **Branch erstellen:** `git checkout -b feature/v2-refactoring`
2. **Projekt-Struktur:** src/ Verzeichnisse anlegen
3. **CMakeLists.txt:** Build System konfigurieren
4. **Module kopieren:** SSL Engine von v1_Crap → v2

### Short-Term (Nächste 2-4 Wochen)

1. **Worker Pool:** Implementierung + Tests
2. **Connection State Machine:** Core State Handler
3. **io_uring Server:** Accept Loop
4. **Integration:** SSL Engine + Worker Pool

### Medium-Term (Nächste 2 Monate)

1. **HTTP Layer:** Response Generator + MIME Types
2. **Testing:** Unit Tests + Integration Tests
3. **Benchmarking:** Performance Validation
4. **Documentation:** API Docs + Deployment Guide

---

**ENDE DER ANALYSE**

Soll ich mit dem Refactoring beginnen?
