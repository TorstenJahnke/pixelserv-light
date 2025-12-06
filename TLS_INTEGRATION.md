# TLSGate TLS Integration - Implementierungsplan

## Übersicht

TLSGate ist ein Ultra-Scale TLS Pixel Server für 10M+ gleichzeitige Verbindungen.
Dieses Dokument beschreibt den aktuellen Stand und die noch offenen Aufgaben.

## Architektur

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              TLSGate Server                                  │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │                        Worker Threads (N)                            │    │
│  │  ┌─────────┐ ┌─────────┐ ┌─────────┐         ┌─────────┐            │    │
│  │  │Worker 0 │ │Worker 1 │ │Worker 2 │  ...    │Worker N │            │    │
│  │  │ epoll   │ │ epoll   │ │ epoll   │         │ epoll   │            │    │
│  │  │ 500K    │ │ 500K    │ │ 500K    │         │ 500K    │            │    │
│  │  │ conns   │ │ conns   │ │ conns   │         │ conns   │            │    │
│  │  └────┬────┘ └────┬────┘ └────┬────┘         └────┬────┘            │    │
│  │       │           │           │                   │                  │    │
│  │       └───────────┴───────────┴───────────────────┘                  │    │
│  │                           │                                           │    │
│  └───────────────────────────┼───────────────────────────────────────────┘    │
│                              │                                                │
│  ┌───────────────────────────┼───────────────────────────────────────────┐    │
│  │                    Shared Resources                                    │    │
│  │                           │                                           │    │
│  │  ┌────────────────────────▼────────────────────────┐                  │    │
│  │  │              Unified Cert Index                  │                  │    │
│  │  │  - mmap'd binary file                           │                  │    │
│  │  │  - Composite key: hash(domain + algo)           │                  │    │
│  │  │  - O(log n) lookup mit prefetch                 │                  │    │
│  │  │  - 12M+ Einträge, ~204 MB                       │                  │    │
│  │  └──────────────────────────────────────────────────┘                  │    │
│  │                                                                        │    │
│  │  ┌────────────────────────────────────────────────┐                   │    │
│  │  │                  Key Pool                       │                   │    │
│  │  │  ┌──────────────┬──────────────┬─────────────┐ │                   │    │
│  │  │  │   RSA-3072   │  ECDSA-P256  │     SM2     │ │                   │    │
│  │  │  │  (Primes)    │   (Agent)    │   (Agent)   │ │                   │    │
│  │  │  │   10K keys   │   10K keys   │   5K keys   │ │                   │    │
│  │  │  └──────────────┴──────────────┴─────────────┘ │                   │    │
│  │  │  Lock-free Treiber Stack                       │                   │    │
│  │  └────────────────────────────────────────────────┘                   │    │
│  │                                                                        │    │
│  │  ┌─────────────────┐  ┌─────────────────┐                             │    │
│  │  │  RSA Primes     │  │  Agent Threads  │                             │    │
│  │  │  (mmap'd)       │  │  ECDSA: 1       │                             │    │
│  │  │  1.1M+ pairs    │  │  SM2: 1         │                             │    │
│  │  └─────────────────┘  └─────────────────┘                             │    │
│  └────────────────────────────────────────────────────────────────────────┘    │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Aktueller Stand (Fertig)

### 1. Core Event-Loop (`src/worker.c`, `include/worker.h`)
- [x] epoll-basierte Event-Schleife
- [x] Edge-triggered Events (EPOLLET)
- [x] EPOLLEXCLUSIVE für Accept-Distribution
- [x] CPU-Affinity für Cache-Lokalität
- [x] Connection State Machine
- [x] Timeout-Handling

### 2. Connection Management (`src/connection.c`, `include/connection.h`)
- [x] Lock-free Connection Pool (Treiber Stack)
- [x] Hot/Cold Data Separation (Cache-optimiert)
- [x] State Machine für HTTP
- [x] Keep-Alive Support

### 3. Buffer Pool (`src/buffer_pool.c`, `include/buffer_pool.h`)
- [x] Pre-allocated Buffer Pool
- [x] Lock-free Alloc/Free
- [x] Small (4K) und Large (64K) Buffers

### 4. HTTP Response System (`src/response.c`, `include/response.h`)
- [x] 273 Extension Hash Table (FNV-1a)
- [x] O(log n) Binary Search Lookup
- [x] Pre-built Static Responses
- [x] 288KB Multi-Icon Favicon
- [x] CORS Headers

### 5. Certificate Index (`src/cert_index.c`, `include/cert_index.h`)
- [x] Unified Index mit Composite Keys (domain + algo)
- [x] mmap'd Binary Search mit Prefetch
- [x] O(log n) Lookup (~24 Vergleiche für 12M Certs)
- [x] Lock-free Reads
- [x] 16-Byte Cache-aligned Entries

### 6. Key Pool (`src/keypool.c`, `include/keypool.h`)
- [x] Lock-free Treiber Stack
- [x] RSA-3072 aus mmap'd Primes (1 μs/Key)
- [x] ECDSA/SM2 Background Agent Threads
- [x] Atomic Statistics

## Noch Offen (TODO)

### 1. SNI Parser (`include/sni.h`, `src/sni.c`)

**Zweck:** Server Name Indication aus TLS ClientHello extrahieren

**Features:**
- [ ] ClientHello Parsing (TLS 1.2 + 1.3)
- [ ] SNI Extension extrahieren
- [ ] Wildcard-Logik für Domains:
  - `example.com` → exakter Match
  - `www.example.com` → `_.example.com`
  - `www.example.co.uk` → `_.example.co.uk`
  - Second-Level TLDs erkennen (github.io, co.uk, etc.)
- [ ] IP-Adress Erkennung → Universal IP Cert

**API:**
```c
typedef struct {
    char server_name[256];
    bool is_ip_address;
    char wildcard_name[256];  // Für Cert-Lookup
} sni_result_t;

int sni_parse_client_hello(const uint8_t *data, size_t len, sni_result_t *result);
int sni_compute_cert_name(const char *server_name, char *cert_name, size_t len);
```

### 2. TLS State Machine (`include/tls.h`, `src/tls.c`)

**Zweck:** Non-blocking TLS Handshake Integration

**Features:**
- [ ] SSL_CTX Pool (pro Algo: RSA, ECDSA, SM2)
- [ ] Per-Connection SSL State
- [ ] Non-blocking SSL_accept():
  - SSL_ERROR_WANT_READ → EPOLLIN
  - SSL_ERROR_WANT_WRITE → EPOLLOUT
- [ ] SNI Callback Integration
- [ ] Cert Lookup/Generation Flow
- [ ] SSL Session Cache (shared, sharded)
- [ ] TLS 1.3 Support mit 0-RTT

**Neue Connection States:**
```c
CONN_STATE_TLS_HANDSHAKE,     // SSL_accept in progress
CONN_STATE_TLS_WANT_READ,     // Waiting for client data
CONN_STATE_TLS_WANT_WRITE,    // Waiting to send data
CONN_STATE_CERT_PENDING,      // Waiting for cert generation
```

**API:**
```c
typedef struct tls_ctx tls_ctx_t;

tls_ctx_t *tls_ctx_create(const tls_config_t *config);
void tls_ctx_destroy(tls_ctx_t *ctx);

int tls_conn_init(connection_t *conn, tls_ctx_t *ctx);
int tls_conn_handshake(connection_t *conn);  // Non-blocking
int tls_conn_read(connection_t *conn, void *buf, size_t len);
int tls_conn_write(connection_t *conn, const void *buf, size_t len);
void tls_conn_shutdown(connection_t *conn);
```

### 3. Cert Generator (`include/cert_gen.h`, `src/cert_gen.c`)

**Zweck:** On-Demand Zertifikatsgenerierung

**Features:**
- [ ] X.509 Cert Generation mit OpenSSL
- [ ] CA Chain Handling (Root, SubCA, CrossSigned)
- [ ] Validity Period (z.B. 1 Jahr)
- [ ] SAN (Subject Alternative Names) für Wildcards
- [ ] Async Generation via Lock-free Queue
- [ ] Disk Persistence in Sharded Directories

**API:**
```c
typedef struct {
    const char *domain;
    cert_algo_t algo;
    EVP_PKEY *key;          // Aus Keypool
    X509 *issuer_cert;      // CA Cert
    EVP_PKEY *issuer_key;   // CA Key
    int validity_days;
} cert_gen_request_t;

X509 *cert_gen_create(const cert_gen_request_t *req);
int cert_gen_save(X509 *cert, EVP_PKEY *key, const char *path);
```

### 4. SSL Context Cache (`include/ssl_cache.h`, `src/ssl_cache.c`)

**Zweck:** SSL_CTX Caching für schnellen Zugriff

**Features:**
- [ ] LRU Cache für SSL_CTX Objekte
- [ ] Sharded für Lock-Contention Reduktion
- [ ] Expiry Tracking
- [ ] Atomic Reference Counting
- [ ] Memory Limit mit Eviction

**API:**
```c
typedef struct ssl_cache ssl_cache_t;

ssl_cache_t *ssl_cache_create(size_t max_entries, int num_shards);
SSL_CTX *ssl_cache_get(ssl_cache_t *cache, const char *cert_name);
void ssl_cache_put(ssl_cache_t *cache, const char *cert_name, SSL_CTX *ctx);
void ssl_cache_invalidate(ssl_cache_t *cache, const char *cert_name);
```

### 5. Second-Level TLD Set (`include/tld_set.h`, `src/tld_set.c`)

**Zweck:** Erkennung von Second-Level TLDs für Wildcard-Logik

**Beispiele:**
- `co.uk`, `com.au`, `co.jp` → ccTLD Second-Level
- `github.io`, `blogspot.com`, `herokuapp.com` → Hosting Platforms

**API:**
```c
typedef struct tld_set tld_set_t;

tld_set_t *tld_set_load(const char *path);  // Public Suffix List
bool tld_set_contains(const tld_set_t *set, const char *domain);
```

### 6. Worker Integration

**Änderungen in `src/worker.c`:**
- [ ] TLS Context initialisieren
- [ ] SSL State in Connection einbinden
- [ ] TLS Handshake in Event-Loop integrieren
- [ ] Non-blocking SSL_read/SSL_write
- [ ] Cert-Pending State Handling

### 7. Makefile Updates

```makefile
# Neue TLS Source Files
TLSGATE_TLS_SRC = \
    src/sni.c \
    src/tls.c \
    src/cert_gen.c \
    src/ssl_cache.c \
    src/tld_set.c

# Linker Flags
LDFLAGS += -lssl -lcrypto -lpthread
```

## Directory Structure

```
pem_dir/
├── index                    # Unified Cert Index (mmap'd)
├── index.log               # Append-only Write Log
├── primes/
│   ├── rsa3072_p.bin       # RSA P Primes (mmap'd)
│   └── rsa3072_q.bin       # RSA Q Primes (mmap'd)
├── RSA/
│   ├── rootCA/
│   │   ├── ca.crt          # Root CA Certificate
│   │   └── ca.key          # Root CA Private Key
│   └── certs/
│       ├── 00/             # Shard 0x00
│       │   ├── cert_00000001.pem
│       │   └── ...
│       ├── 01/             # Shard 0x01
│       └── ff/             # Shard 0xff
├── ECDSA/
│   ├── rootCA/
│   └── certs/
│       └── {00-ff}/
└── SM2/
    ├── rootCA/
    └── certs/
        └── {00-ff}/
```

## Performance Ziele

| Metrik | Ziel |
|--------|------|
| Concurrent Connections | 10M+ |
| TLS Handshakes/sec | 100K+ |
| Cert Lookup Latency | < 5 μs |
| RSA Key from Primes | < 2 μs |
| Memory per Connection | < 2 KB |
| CPU Cores | 32 (EPYC) |

## Performance Optimierungen (bereits implementiert)

1. **Lock-free Data Structures**
   - Treiber Stack für Connection/Buffer Pool
   - Atomic Operations für Statistics

2. **Memory Optimization**
   - mmap für Index und Primes
   - MAP_POPULATE für Prefaulting
   - Huge Pages Support
   - Cache-aligned Structures

3. **CPU Optimization**
   - __builtin_prefetch in Binary Search
   - CPU Affinity für Workers
   - Hot/Cold Data Separation

4. **I/O Optimization**
   - Edge-triggered epoll
   - EPOLLEXCLUSIVE für Accept Distribution
   - Non-blocking sockets
   - TCP_NODELAY, TCP_QUICKACK

## Nächste Schritte (Priorisiert)

1. **SNI Parser** - Kritisch für TLS
2. **TLS State Machine** - Core TLS Integration
3. **Cert Generator** - On-Demand Certs
4. **Worker Integration** - Alles zusammenführen
5. **Testing** - Load Tests mit wrk/h2load

## Referenzen

- OpenSSL Dokumentation: https://www.openssl.org/docs/
- TLS 1.3 RFC 8446: https://tools.ietf.org/html/rfc8446
- Public Suffix List: https://publicsuffix.org/
- epoll Manpage: https://man7.org/linux/man-pages/man7/epoll.7.html
