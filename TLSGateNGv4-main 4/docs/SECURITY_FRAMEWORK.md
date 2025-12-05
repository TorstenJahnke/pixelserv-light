# TLSGateNG4 v4.36 GEN4 - Security Framework & Implementation Details

**Comprehensive Security Analysis with Code References**

---

## Table of Contents

1. [10-Layer Defense Framework](#10-layer-defense-framework)
2. [Implementation Architecture](#implementation-architecture)
3. [Code Module References](#code-module-references)
4. [Security Validation](#security-validation)
5. [Threat Model Coverage](#threat-model-coverage)
6. [Cryptographic Standards](#cryptographic-standards)

---

## 10-Layer Defense Framework

### Layer 1: Input Validation

**Purpose**: Prevent malformed/malicious input from reaching processing logic

**Implementation**:
- **SNI Validation** (`src/tls/sni_extractor.c`)
  - Max 255 characters
  - Alphanumeric + . - _ characters only
  - No directory traversal patterns
  - Hostname format validation

- **HTTP Request Validation** (`src/http/response.c`)
  - Max 16KB request size limit
  - Max 64 headers per request
  - Max 8,192 byte URI
  - GET, POST, OPTIONS, HEAD methods only
  - Invalid methods result in 405 Method Not Allowed

- **HTTP Header Validation**
  - RFC 2616 compliance enforcement
  - No null bytes in headers
  - Strict header format validation
  - Cookie injection prevention

- **Path Validation** (`src/http/response.c`)
  - No `..` directory traversal
  - No `//` path doubling
  - No unprintable characters (0x00-0x1F, 0x7F)
  - No control characters in paths

**Code References**:
```c
// File: src/http/response.c
// Functions: validate_request_path(), validate_http_headers()

// File: src/tls/sni_extractor.c
// Function: extract_sni_from_clienthello()
```

---

### Layer 2: Network Layer Protection

**Purpose**: Secure network socket handling and prevent IP-based attacks

**Implementation**:
- **IP Binding Security** (`src/tlsgateNG.c`)
  - Never binds to wildcard (*) - requires explicit IP
  - IPv4: Specific addresses or 0.0.0.0
  - IPv6: Specific addresses or ::
  - Separate binaries for IPv4/IPv6 (compiler optimization)

- **IPv6 Support** (`src/core/connection.c`)
  - Native IPv6 socket handling
  - sockaddr_storage for AF_INET and AF_INET6
  - auto-detection of address family from configuration
  - Dual-stack ready (IPv4-mapped IPv6 support)

- **UDP Socket Handling** (`src/core/connection.c`)
  - QUIC/HTTP3 ready on AUTO port
  - Non-blocking UDP operations
  - Per-packet timestamp injection

- **Port Isolation**
  - Each port (-p, -s, -a) listens independently
  - No shared state between port listeners
  - Independent epoll/io_uring per port

**Code References**:
```c
// File: src/tlsgateNG.c (main)
// Functions: setup_listen_sockets(), bind_address()

// File: src/core/connection.c
// Functions: create_ipv4_socket(), create_ipv6_socket()
```

---

### Layer 3: Connection Layer Security

**Purpose**: Protect against connection-based attacks (slow-reads, slow-writes, etc.)

**Implementation**:
- **Connection Timeouts** (`src/core/connection.c`)
  - Connection lifetime: 300 seconds max (5 minutes)
  - Read timeout: 30 seconds (prevents slow-read attacks)
  - Write timeout: 30 seconds (prevents slow-write attacks)
  - Keep-Alive timeout: 60 seconds (persistent connection limit)

- **Slowloris Protection**
  - Auto-close after 30 seconds inactivity
  - Per-worker connection tracking
  - Early termination of incomplete requests
  - Memory exhaustion prevention via limits

- **Connection Pool Management** (`src/core/worker.c`)
  - Max 40K-50K connections per worker (configurable)
  - Max 160K-200K connections per instance
  - Connection recycling and cleanup
  - Graceful connection shutdown

- **File Descriptor Limits**
  - Per-process limit: 50K+ FDs
  - Per-worker limit: Enforced via connection caps
  - System-level ulimit enforcement
  - FD exhaust protection

**Code References**:
```c
// File: src/core/connection.c
// Functions: handle_connection_timeout(), close_connection()

// File: src/core/worker.c
// Functions: worker_event_loop(), manage_connection_pool()

// Configuration: CONN_TIMEOUT, READ_TIMEOUT, WRITE_TIMEOUT (defines)
```

---

### Layer 4: HTTP Protocol Protection

**Purpose**: Prevent HTTP-level attacks and exploits

**Implementation**:
- **Silent Blocker** (`src/http/silent_blocker.c`)
  - Max 1,024 rules per instance
  - Domain pattern matching with wildcards
  - Path pattern matching
  - Configurable delay injection (0-10,000ms)
  - HTTP status override (200, 204, 304, 404, 503)
  - Reverse proxy option per rule

- **Domain Blocking Rules**
  - Exact domain matches
  - Wildcard support: `*.example.com`
  - Path-specific blocking: `domain /path`
  - Case-insensitive domain matching
  - TLD validation

- **Reverse Proxy Mode**
  - Optional `reverse-proxy=on` per rule
  - Forward to upstream server on match
  - Request/response modification capability
  - Load balancing ready

**Code References**:
```c
// File: src/http/silent_blocker.c
// Functions: load_silent_blocker_rules(), check_silent_blocker()

// Configuration: Silent blocker rule format
// domain path delay status [reverse-proxy=on]
```

---

### Layer 5: TLS/Certificate Layer Protection

**Purpose**: Secure cryptographic operations and certificate validation

**Implementation**:
- **Dynamic Certificate Generation** (`src/cert/cert_generator.c`)
  - SNI-based certificate generation
  - On-the-fly certificate creation matching requested domain
  - Cached certificate retrieval for performance
  - Multi-SubCA support (RSA, ECDSA, SM2)

- **CA Loader** (`src/cert/ca_loader.c`)
  - 2-tier structure: Root CA + Sub-CA
  - 1-tier support: Self-signed certificates
  - Multi-SubCA support for different algorithms
  - Passphrase-protected key support

- **Keypool Manager** (`src/crypto/keypool.c`)
  - Pre-generated key pool (RSA, ECDSA, Ed25519)
  - Shared memory pool for multi-instance
  - Key bundle loading from disk
  - Atomic key allocation

- **Certificate Caching** (`src/cert/cert_cache.c`)
  - Per-instance certificate cache
  - Index-based lookup for fast retrieval
  - LRU eviction policy
  - Warm-start optimization

- **Certificate Maintenance** (`src/cert/cert_maintenance.c`)
  - Automatic renewal monitoring
  - Expiration tracking (7-day warning)
  - Atomic certificate replacement
  - Index updates

- **PKI Manager** (`src/pki/pki_manager.c`)
  - Public Key Infrastructure management
  - Key size validation (1024-8192 bits RSA)
  - ECDSA curve validation (P-256, P-384, P-521)
  - SM2 (国密/商用密码) support

**Code References**:
```c
// File: src/cert/cert_generator.c
// Functions: generate_certificate(), select_subca_for_sni()

// File: src/cert/ca_loader.c
// Functions: load_ca_certificates(), validate_ca_hierarchy()

// File: src/cert/cert_cache.c
// Functions: cache_certificate(), retrieve_cached_cert()

// File: src/crypto/keypool.c
// Functions: initialize_keypool(), allocate_key()
```

---

### Layer 6: Anti-Fingerprinting Defense

**Purpose**: Prevent client fingerprinting and tracking

**Implementation**:
- **Server Header Spoofing** (`src/anti_adblock/anti_adblock.c`)
  - 45 different server identities (Nginx, Apache, CloudFlare, etc.)
  - Random selection per request
  - Prevents server software identification
  - Lines: 28-46

- **Cache Status Rotation** (`src/anti_adblock/anti_adblock.c`)
  - 49 cache status variants (HIT, MISS, BYPASS, EXPIRED, etc.)
  - Random Cache-Control header generation
  - Prevents cache behavior fingerprinting
  - Lines: 50-60

- **Vary Header Rotation** (`src/anti_adblock/anti_adblock.c`)
  - 81 different Vary header combinations
  - Accept-Encoding, User-Agent, Accept-Language, etc.
  - Prevents header normalization fingerprinting
  - Lines: 62-80

- **CF-RAY Simulation** (`src/anti_adblock/anti_adblock.c`)
  - 95 geographic CloudFlare locations
  - Random CF-RAY header generation
  - Simulates CloudFlare CDN
  - Lines: 82-95

- **ETag Generation** (`src/anti_adblock/anti_adblock.c`)
  - 33% random ETag generation
  - W/ weak ETag vs strong ETag variant
  - Prevents ETag-based fingerprinting
  - Lines: 207-218

- **Random CORS Headers** (`src/anti_adblock/anti_adblock.c`)
  - 70% send CORS, 30% skip
  - 50/50 wildcard (*) vs specific origin
  - Variable credential handling
  - Lines: 240-298

**Code References**:
```c
// File: src/anti_adblock/anti_adblock.c
// Functions: generate_spoofed_headers(), randomize_cache_status()
// Lines: 28-298 (all fingerprinting functions)

// File: src/anti_adblock/anti_adblock.c
// Function: get_cryptographically_secure_seed()
// Lines: 157-181 (crypto-secure seeding)
```

---

### Layer 7: Content Randomization

**Purpose**: Prevent content-based fingerprinting and automation detection

**Implementation**:
- **JavaScript Content Variants** (`src/anti_adblock/anti_adblock.c`)
  - 185+ functionally useless JavaScript patterns
  - Variable syntax, white space, comments
  - Prevents automation framework detection
  - Lines: 316-363

- **CSS Content Variants** (`src/anti_adblock/anti_adblock.c`)
  - 414+ CSS reset and style patterns
  - Media queries, viewport rules
  - Prevents CSS-based fingerprinting
  - Lines: 369-422

- **JSON Content Variants** (`src/anti_adblock/anti_adblock.c`)
  - 149+ JSON object structure variations
  - Different key names and nesting
  - Prevents automation via JSON parsing
  - Lines: 427-458

- **XML Content Variants** (`src/anti_adblock/anti_adblock.c`)
  - 40+ XML format patterns
  - RSS, Atom, SOAP, SVG, etc.
  - Prevents feed parser automation
  - Lines: 463-496

**Code References**:
```c
// File: src/anti_adblock/anti_adblock.c
// Functions: select_random_javascript(), select_random_css()
// Lines: 316-496 (all content generation functions)
```

---

### Layer 8: Timing & Behavioral Defense

**Purpose**: Prevent timing-based attacks and behavioral analysis

**Implementation**:
- **Timing Jitter** (`src/anti_adblock/timing_jitter.c`)
  - Base delay: 1-50ms (random)
  - Extra delay: 0-30ms (additional randomization)
  - Per-request jitter injection
  - Prevents timing-based analysis

- **Cryptographically Secure Seeding** (`src/anti_adblock/anti_adblock.c`)
  - getrandom() (Linux, cryptographically secure)
  - arc4random_buf() (FreeBSD, ChaCha20-based)
  - /dev/urandom fallback
  - gettimeofday() + getpid() ultimate fallback

- **Browser Detection** (`src/anti_adblock/browser_detection.c`)
  - 88 User-Agent patterns
  - Chrome, Firefox, Safari, Edge, Mobile
  - Bot detection (GoogleBot, BingBot)
  - WebView detection (Instagram, WeChat, TikTok)
  - Lines: 8-63

- **Bot Response Handling** (`src/anti_adblock/browser_detection.c`)
  - Special response for detected bots
  - CDN library stubs (jQuery, Bootstrap, FontAwesome)
  - Prevents bot tracking
  - Lines: 59-62

- **Regional Header Injection** (`src/anti_adblock/browser_detection.c`)
  - GDPR compliance headers
  - CCPA privacy headers
  - UK-GDPR requirements
  - Regional variation per request
  - Lines: 82-113

**Code References**:
```c
// File: src/anti_adblock/timing_jitter.c
// Function: inject_timing_jitter()

// File: src/anti_adblock/anti_adblock.c
// Function: get_cryptographically_secure_seed()

// File: src/anti_adblock/browser_detection.c
// Functions: detect_browser(), get_regional_headers()
```

---

### Layer 9: Resource Protection

**Purpose**: Prevent resource exhaustion and DoS attacks

**Implementation**:
- **Per-IP Rate Limiting** (`src/core/connection.c`)
  - Max 1,000 new connections per second per IP
  - Max 10,000 requests per second per IP
  - Max 100 Mbps bandwidth per IP
  - Sliding window enforcement

- **Per-Worker Limits**
  - Max 40K-50K connections per worker
  - Max connections enforced via pool management
  - Worker load balancing
  - Graceful rejection when limit reached

- **Connection Pool Exhaustion Prevention**
  - Connection recycling
  - Timeout-based cleanup
  - Priority queue for new connections
  - Graceful degradation

- **Worker Thread Management** (`src/core/worker.c`)
  - 1-64 workers (configurable)
  - Per-worker event loop (epoll/io_uring)
  - Load distribution
  - Worker health monitoring

**Code References**:
```c
// File: src/core/connection.c
// Functions: rate_limit_check(), enforce_per_ip_limits()

// File: src/core/worker.c
// Functions: worker_event_loop(), distribute_load()

// Configuration: MAX_CONN_PER_IP_SEC, MAX_REQ_PER_IP_SEC
```

---

### Layer 10: Observability & Monitoring

**Purpose**: Detect and respond to security incidents

**Implementation**:
- **Lock-Free Statistics** (`src/core/connection.c`)
  - Atomic operations (zero overhead)
  - Real-time connection tracking
  - Request counting per IP
  - Bandwidth monitoring

- **Metrics Export**
  - Prometheus-compatible format
  - JSON export capability
  - Real-time metric updates
  - `/metrics` and `/stats` endpoints

- **Minimal Logging** (`src/util/logger.c`)
  - ERROR level only (SILENT mode)
  - Zero logging overhead in production
  - Optional DEBUG logging (configurable)
  - Structured logging format

- **Connection Tracking**
  - Per-IP connection count
  - Per-IP request count
  - Per-worker load monitoring
  - Active connection list

**Code References**:
```c
// File: src/core/connection.c
// Functions: update_statistics(), get_connection_count()

// File: src/util/logger.c
// Functions: log_error(), log_debug()

// Endpoints: GET /metrics, GET /stats
```

---

## Implementation Architecture

### Module Organization

```
src/
├── tlsgateNG.c                    # Main program entry
├── core/
│   ├── worker.c/h                 # Worker thread management
│   └── connection.c/h             # Connection handling
├── http/
│   ├── response.c/h               # HTTP response generation
│   ├── extension_lookup.c/h        # MIME type lookup
│   ├── silent_blocker.c/h          # Domain blocking rules
│   └── reverse_proxy.c/h           # Reverse proxy support
├── anti_adblock/
│   ├── anti_adblock.c/h            # Fingerprinting defense
│   ├── browser_detection.c/h       # Browser/bot detection
│   └── timing_jitter.c/h           # Timing randomization
├── tls/
│   └── sni_extractor.c/h           # SNI extraction
├── cert/
│   ├── ca_loader.c/h               # CA management
│   ├── cert_generator.c/h          # Cert generation
│   ├── cert_cache.c/h              # Cert caching
│   ├── cert_index.c/h              # Cert indexing
│   ├── cert_maintenance.c/h        # Auto-renewal
│   └── second_level_tlds.c/h       # TLD validation
├── crypto/
│   └── keypool.c/h                 # Key management
├── pki/
│   └── pki_manager.c/h             # PKI operations
├── util/
│   ├── logger.c/h                  # Logging
│   └── util.c/h                    # Utilities
├── ipc/
│   └── shm_manager.c/h             # Shared memory
├── config/
│   ├── config_file.c/h             # Config parsing
│   └── config_generator.c/h        # Config generation
└── version.c/h                     # Version/help (new)
```

### Data Flow

```
Client Request
    │
    ▼
Network Layer (Layer 2)
    │
    ▼
Connection Layer (Layer 3)
    │
    ▼
Input Validation (Layer 1)
    │
    ├─→ SNI Extraction
    ├─→ HTTP Request Parsing
    └─→ Path Validation
    │
    ▼
TLS Layer (Layer 5)
    │
    ├─→ Certificate Generation
    ├─→ Keypool Access
    └─→ Cache Lookup
    │
    ▼
HTTP Protocol (Layer 4)
    │
    ├─→ Silent Blocker Rules
    └─→ Route Decision
    │
    ▼
Content Generation
    │
    ├─→ Browser Detection (Layer 8)
    ├─→ Content Randomization (Layer 7)
    └─→ Header Spoofing (Layer 6)
    │
    ▼
Timing Defense (Layer 8)
    │
    ├─→ Jitter Injection
    └─→ Delay Application
    │
    ▼
Resource Protection (Layer 9)
    │
    ├─→ Rate Limit Check
    └─→ Connection Accounting
    │
    ▼
Statistics (Layer 10)
    │
    └─→ Atomic Update
    │
    ▼
Response Send
    │
    ▼
Client
```

---

## Code Module References

### Critical Security Modules

| Module | Purpose | Key Functions | Lines | Complexity |
|--------|---------|---------------|----|-----------|
| `src/tls/sni_extractor.c` | SNI validation | extract_sni_from_clienthello() | ~200 | Medium |
| `src/cert/cert_generator.c` | Cert generation | generate_certificate() | ~500 | High |
| `src/http/silent_blocker.c` | Domain blocking | check_silent_blocker() | ~300 | Medium |
| `src/anti_adblock/anti_adblock.c` | Fingerprinting | generate_spoofed_headers() | ~600 | High |
| `src/core/connection.c` | Connection mgmt | handle_connection_timeout() | ~700 | High |
| `src/core/worker.c` | Worker threads | worker_event_loop() | ~400 | High |
| `src/util/logger.c` | Logging | log_error/debug() | ~150 | Low |
| `src/crypto/keypool.c` | Key management | allocate_key() | ~350 | Medium |

---

## Security Validation

### Input Validation Checklist

- ✅ SNI length validation (max 255 chars)
- ✅ SNI character validation (alphanumeric + . - _)
- ✅ HTTP method validation (GET, POST, OPTIONS, HEAD)
- ✅ Request size limit (16KB max)
- ✅ Header count limit (64 max)
- ✅ Header size limit
- ✅ Path validation (no .. or //)
- ✅ Control character detection
- ✅ NULL byte rejection

### Network Security Checklist

- ✅ No wildcard binding (explicit IP required)
- ✅ IPv4/IPv6 separation
- ✅ UDP socket handling
- ✅ Port isolation
- ✅ Connection timeout enforcement
- ✅ Slowloris protection
- ✅ Rate limiting per IP
- ✅ File descriptor exhaustion prevention

### Cryptographic Security Checklist

- ✅ TLS 1.0-1.3 support
- ✅ RSA, ECDSA, SM2 algorithms
- ✅ Secure key generation
- ✅ Certificate validation
- ✅ Passphrase-protected keys
- ✅ Key pool sharing (secure, atomic)
- ✅ No weak defaults

---

## Threat Model Coverage

### Attacks Mitigated

| Attack | Mitigation | Layer | Status |
|--------|-----------|-------|--------|
| Slow-read (Slowloris) | Connection timeout + inactivity detection | Layer 3 | ✅ |
| Slow-write | Write timeout enforcement | Layer 3 | ✅ |
| Directory traversal | Path validation (no ..) | Layer 1 | ✅ |
| Certificate spoofing | SNI validation + CA verification | Layer 5 | ✅ |
| Domain fronting | TLS SNI vs HTTP Host comparison | Layer 4 | ✅ |
| Resource exhaustion | Connection pooling + limits | Layer 9 | ✅ |
| Malware distribution | Silent blocker rules + domain blocking | Layer 4 | ✅ |
| Phishing | Header security + blocklist integration | Layers 4,6 | ✅ |
| Scamware | Domain blocking + form prevention | Layer 4 | ✅ |
| Bot automation | Browser detection + content randomization | Layers 7,8 | ✅ |
| Timing analysis | Jitter injection (1-50ms+0-30ms) | Layer 8 | ✅ |
| Fingerprinting | Server header spoofing + CORS randomization | Layer 6 | ✅ |
| XML injection | Input validation + attribute encoding | Layer 1 | ✅ |
| Path traversal | Path normalization + validation | Layer 1 | ✅ |
| Unicode attacks | SNI character validation | Layer 1 | ✅ |

---

## Cryptographic Standards

### Supported Algorithms

#### Public Key Cryptography
- RSA: 1024 (legacy), 2048, 4096, 8192 bits
- ECDSA: P-256, P-384, P-521 curves
- SM2: 国密/商用密码 (Chinese standard)
- Ed25519: Edwards curve (modern, fast)

#### Hash Algorithms
- SHA-256, SHA-384, SHA-512 (modern, recommended)
- SHA-1 (legacy support only)
- SM3: 国密/商用密码 hash

#### Symmetric Encryption
- AES: 128, 192, 256-bit (GCM, CBC)
- SM4: 国密/商用密码 cipher
- ChaCha20: Modern alternative

#### TLS Versions
- TLS 1.0 (legacy support)
- TLS 1.1 (legacy support)
- TLS 1.2 (standard)
- TLS 1.3 (recommended, fastest)

---

## Security Recommendations

### Deployment Security

1. **Always run as latest version** for security patches
2. **Use privilege dropping** (-u, -g flags)
3. **Configure firewall** to restrict access
4. **Monitor metrics** (/stats, /metrics endpoints)
5. **Rotate certificates** regularly
6. **Update blocklists** (Silent Blocker rules)
7. **Review logs** for suspicious activity
8. **Use HTTPS** for all client connections

### Configuration Security

1. **Disable unnecessary ports** (set to 0)
2. **Set max connections** appropriately
3. **Configure rate limits** per IP
4. **Use shared memory** (--shm) for multi-instance
5. **Enable verbose logging** during debugging only
6. **Restrict admin access** (CA directory permissions)

### Operational Security

1. **Monitor /metrics endpoint** for attacks
2. **Track per-IP request rates**
3. **Alert on connection pool exhaustion**
4. **Review certificate renewals**
5. **Backup CA directory** regularly
6. **Test failover** procedures
7. **Audit system logs** (syslog)

---

**For detailed feature documentation, see: docs/FEATURES.md**

**For deployment guide, see: SETUP.md, QUICKSTART.md**

**For performance tuning, see: docs/PERFORMANCE_TUNING.md**
