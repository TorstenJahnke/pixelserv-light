# TLSGate NG v4.36 GEN4 (2026 - with SM Algorithms 国密/商用密码)

**Enterprise-Grade Abyss Endpoint Controller (AEC)**

Universal Traffic Processing Engine with Multi-Instance Orchestration

## 1. Executive Summary

TLSGate-NG (GEN 4) is a high-performance IP-termination server representing the next evolution in Abyss Endpoint Controller Technologie (AEC). Unlike traditional firewalls that filter traffic or simple sinkholes that reject it, TLSGate-NG acts as a "Universal Abyss": it accepts, processes ("crunches"), and intelligently responds to every packet on every port (TCP/UDP 1–65535).

The system achieves 240,000+ requests per second by running a hybrid cryptographic stack: Tongsuo (SM algorithms for Asian markets) and OpenSSL 3.5 (International standards) operate in parallel. The engine automatically selects the optimal cryptographic suite based on the client's capabilities during the TLS handshake, ensuring global compliance without manual configuration.

### Core Capabilities

✅ **240,000+ Requests/Second** – Measured production throughput

✅ **Automatic Cryptographic Negotiation** – Tongsuo + OpenSSL 3.5 parallel, client-based selection

✅ **Global Market Support** – SM algorithms (Asia), OpenSSL 3.5 (International, Europe, Americas)

✅ **Native Dual-Stack IP** – IPv4 and IPv6 independently processed, no translation

✅ **Zero Configuration** – Automatic cipher suite selection based on client capabilities

✅ **Enterprise TLS** – TLS 1.0, 1.2, 1.3 support

✅ **Privacy-by-Design** – Response randomization, header obfuscation, anti-fingerprinting

✅ **Accepts** all TCP/UDP connections

✅ **Responds** on all ports simultaneously (1 to 65535)

✅ **Processes** ("crunches") all incoming traffic

✅ **Scales** to 10M+ concurrent connections on a single server

✅ **Maintains** zero-copy operations and lock-free architecture

✅ **Multi-Platform** – Optimized for Debian GNU/Linux and BSD (NetBSD, FreeBSD)

---

## 2. AEC Technologie: The Core Innovation

**Abyss Endpoint Controller Technologie (AEC)** is a unified control framework for deploying and scaling Abyss Endpoints - public IP addresses that respond to and process all incoming traffic.

### What is AEC?

Unlike traditional DNS sinkholes that merely block with non-routable addresses (0.0.0.0, 127.0.0.1), TLSGateNG4 provides a public IP address (e.g., 178.162.203.162) that transparently handles **every packet** sent to it.

```
┌─────────────────────────────────────────────────────────────┐
│                     AEC TECHNOLOGIE                         │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ABYSS ENDPOINT (The Public IP)                             │
│  ├─ TCP:80, 443, 8080, 9090, ... → Responds                 │
│  ├─ UDP:53, 123, 5353, ... → Responds                       │
│  └─ ALL TRAFFIC → Gets CRUNCHED                             │
│                                                             │
│  CONTROLLER (The Orchestration Layer)                       │
│  ├─ 60-100 Independent Processes (per IP)                   │
│  ├─ Shared Memory (Keypool & Cert Cache)                    │
│  ├─ Per-Process Worker Pool (2-4 epoll threads)             │
│  ├─ Dynamic Certificate Generation (SNI-based)              │
│  ├─ SSL CryptoEngine (ACT) (16k RSA in <2ms)                │
│  ├─ Polymorphic Response Generation                         │
│  └─ Lock-Free Statistics & Coordination                     │
│                                                             │
│  SCALE                                                      │
│  └─ 10M+ concurrent connections per server                  │
│  └─ 200K+ requests/sec per server                           │
│  └─ Zero single-point-of-failure (process independent)      │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### How It Works: The AEC Flow

```
┌─────────────────────────────────────────────────────────────┐
│               INCOMING REQUEST (ANY PORT/PROTOCOL)          │
└────────────────────┬────────────────────────────────────────┘
                     │
                     ▼
          ┌───────────────────────────────────┐
          │  ABYSS ENDPOINT (178.162.203.162) │
          │  Listen on ALL TCP/UDP Ports      │
          └────────────┬──────────────────────┘
                       │
    ┌──────────────────┼────────────────────┐
    ▼                  ▼                    ▼
 TCP:80             TCP:443              TCP:ANY
 HTTP               HTTPS                Raw Port
 │                  │                    │
 └──────────────────┼────────────────────┘
                    ▼
    ┌───────────────────────────────────────┐
    │ AEC CONTROLLER (60-100 Processes)     │
    │                                       │
    │ Process 1: Instance A IPv4            │
    │ ...                                   │
    │ Process 60: Instance Z IPv6           │
    │                                       │
    │ Shared: Keypool (1M keys)             │
    │ Shared: Cert Generator (8 threads)    │
    └────────────┬──────────────────────────┘
                 │
    ┌────────────┴─────────────┬──────────────────┐
    ▼                          ▼                  ▼
HTTP Response             TLS Handshake       UDP Response
(200 OK)              (SNI-based Cert)    (DNS/NTP/etc)
```

---

## 3. Key Features

### ✅ Universal Port Response

- **HTTP** (port 80) - Plain HTTP responses
- **HTTPS** (port 443) - Full TLS 1.0-1.3 with dynamic certificates
- **AUTO** (port 8080) - MSG_PEEK protocol detection (auto-routes HTTP/HTTPS)
- **QUIC/HTTP3** - UDP support (ready for firewall integration)
- **All-Port Response** - Responds to ANY TCP/UDP port

### ✅ Performance & Scalability

- **200K+ concurrent connections** per instance
- **Multi-instance deployment** (60-100 processes per server)
- **10M+ total concurrent connections** per physical server
- **io_uring** backend (Linux 5.1+) with epoll fallback
- **Zero-copy** operations where possible
- **Non-blocking I/O** throughout

### ✅ Traffic Processing

- **Dynamic Certificate Generation** - On-the-fly certs matching requested SNI
- **Anti-AdBlock Technology** - Polymorphic responses, timing jitter, browser detection
- **MIME Type System** - 265+ file types with intelligent response generation
- **Security Headers** - CORS/CSP neutralization for maximum compatibility
- **Privilege Separation** - Drops to non-root user after port binding

---

## 4. Advanced Security Framework (10-Layer Defense)

The core of AEC Technologie is a 10-layer defense framework that analyzes and neutralizes threats at Layer-7. Below is the detailed breakdown with code references.

### Layer 1: Input Validation

**Purpose:** Prevent malformed/malicious input from reaching processing logic.

**SNI Validation** (`src/tls/sni_extractor.c`):
- Max 255 characters, alphanumeric + `.` `-` `_` only.
- No directory traversal patterns or control characters.

**HTTP Request Validation** (`src/http/response.c`):
- Max 16KB request size, max 64 headers.
- Enforce GET, POST, OPTIONS, HEAD only (others return 405).

**Path Validation:**
- No `..` directory traversal, no `//` path doubling.
- Rejection of unprintable characters (0x00-0x1F).

### Layer 2: Network Layer Protection

**Purpose:** Secure network socket handling and prevent IP-based attacks.

**IP Binding Security** (`src/tlsgateNG.c`):
- Never binds to wildcard `*` - requires explicit IP.
- Separate binaries for IPv4/IPv6 (compiler optimization).

**Port Isolation:**
- Each port (`-p`, `-s`, `-a`) listens independently with its own epoll/io_uring instance.

### Layer 3: Connection Layer Security

**Purpose:** Protect against connection-based attacks (slow-reads, slow-writes).

**Timeouts** (`src/core/connection.c`):
- Connection Max Age: 300s (5 min).
- Read/Write Timeout: 30s (Prevents Slowloris).
- Keep-Alive: 60s.

**Pool Management** (`src/core/worker.c`):
- Max 40K-50K connections per worker.
- Graceful connection shutdown and recycling.

### Layer 4: HTTP Protocol & Threat Protection

**Purpose:** Prevent HTTP-level attacks and exploits via the Silent Blocker.

**Silent Blocker Engine** (`src/http/silent_blocker.c`):
- Max 1,024 rules per instance with wildcard support (`*.example.com`).
- Capabilities: Configurable delay injection (0-10,000ms) to "tarpit" attackers.
- Optional Origin Forwarding: Forward requests to upstream servers for analysis.

**Threat Mitigation:**
- **Polyglot Detection:** Detects embedded payloads in URLs (`data:text/html`).
- **Domain Fronting:** Compares TLS SNI vs HTTP Host header.
- **Redirect Analysis:** Tracks multi-hop redirects to prevent browser exploitation.

### Layer 5: TLS/Certificate Layer Protection

**Purpose:** Secure cryptographic operations.

**Dynamic Cert Generation** (`src/cert/cert_generator.c`):
- On-the-fly SNI-based certificate creation.
- Multi-SubCA support (RSA, ECDSA, SM2).

**Keypool Manager** (`src/crypto/keypool.c`):
- Shared memory pool for multi-instance key access.
- Atomic key allocation preventing race conditions.

### Layer 6: Anti-Fingerprinting Defense

**Purpose:** Prevent client fingerprinting and tracking.

**Server Header Spoofing** (`src/anti_adblock/anti_adblock.c`):
- Rotates 45 different server identities (Nginx, Apache, CloudFlare, etc.).

**Header Rotation:**
- Randomizes Vary, ETag, and Cache-Control headers.
- Simulates CF-RAY headers to mimic CloudFlare infrastructure.

**CORS Randomization:**
- 70% send CORS, 30% skip; 50/50 wildcard vs specific origin.

### Layer 7: Content Randomization

**Purpose:** Prevent content-based fingerprinting and automation detection.

**Polymorphic Content** (`src/anti_adblock/anti_adblock.c`):
- **JS:** 185+ functionally useless JavaScript patterns.
- **CSS:** 414+ CSS reset and style patterns.
- **JSON/XML:** 149+ JSON and 40+ XML structure variations.

**Result:** Every response looks different to a scraper/bot.

### Layer 8: Timing & Behavioral Defense

**Purpose:** Prevent timing-based attacks and behavioral analysis.

**Timing Jitter** (`src/anti_adblock/timing_jitter.c`):
- Injects random delays (Base 1-50ms + Extra 0-30ms) per request.

**Browser Detection** (`src/anti_adblock/browser_detection.c`):
- Identifies 88 User-Agent patterns.
- Detects WebViews (Instagram/TikTok) and Bots (GoogleBot).
- Injects regional compliance headers (GDPR/CCPA) based on request.

### Layer 9: Resource Protection

**Purpose:** Prevent resource exhaustion and DoS attacks.

**Rate Limiting** (`src/core/connection.c`):
- Max 1,000 connections/sec per IP.
- Max 10,000 requests/sec per IP.
- Max 100 Mbps bandwidth per IP.

**Worker Limits:**
- Enforced connection caps per worker thread to prevent process crash.

### Layer 10: Observability & Monitoring

**Purpose:** Detect and respond to security incidents.

**Lock-Free Statistics:**
- Atomic operations for zero-overhead monitoring.
- Real-time export via `/metrics` (Prometheus) and `/stats` (HTML).

**Minimal Logging:**
- ERROR level only in production (zero I/O overhead).

---

## 5. Implementation Architecture

### Module Organization

```
src/
├── tlsgateNG.c                    # Main program entry
├── core/
│   ├── worker.c/h                 # Worker thread management
│   └── connection.c/h             # Connection handling
├── http/
│   ├── response.c/h               # HTTP response generation
│   ├── silent_blocker.c/h         # Domain blocking rules
│   └── reverse_proxy.c/h          # Optional origin forwarding
├── anti_adblock/
│   ├── anti_adblock.c/h           # Fingerprinting defense
│   ├── browser_detection.c/h      # Browser/bot detection
│   └── timing_jitter.c/h          # Timing randomization
├── tls/
│   └── sni_extractor.c/h          # SNI extraction
├── cert/
│   ├── cert_generator.c/h         # Cert generation
│   ├── cert_cache.c/h             # Cert caching
│   └── cert_maintenance.c/h       # Auto-renewal
├── crypto/
│   └── keypool.c/h                # Key management (Shared Memory)
├── ipc/
│   └── shm_manager.c/h            # Shared memory manager
└── util/
    └── logger.c/h                 # Logging
```

### Data Flow

```
Client Request
    │
    ▼
Network Layer (Layer 2) → Connection Layer (Layer 3)
    │
    ▼
Input Validation (Layer 1) → (SNI Extraction / Path Check)
    │
    ▼
TLS Layer (Layer 5) → (Cert Gen / Keypool / Cache)
    │
    ▼
HTTP Protocol (Layer 4) → (Silent Blocker / Route Decision)
    │
    ▼
Content Gen (Layer 6/7) → (Anti-Fingerprint / Polymorphic Content)
    │
    ▼
Timing Defense (Layer 8) → (Jitter Injection)
    │
    ▼
Resource Protection (Layer 9) → (Rate Limit Check)
    │
    ▼
Statistics (Layer 10) → Response Send
```

---

## 6. Security Validation & Threat Model

### Security Checklist

✅ **Input:** SNI max 255 chars, Req max 16KB, No NULL bytes.

✅ **Network:** No wildcard binding, Port isolation, File descriptor limits.

✅ **Crypto:** TLS 1.0-1.3, Secure key generation (RSA/ECDSA/SM2).

### Threat Model Coverage

| Attack | Mitigation | Layer |
|--------|-----------|-------|
| Slowloris | Connection timeout (30s) + inactivity check | Layer 3 |
| Certificate Spoofing | SNI validation + CA verification | Layer 5 |
| Domain Fronting | TLS SNI vs HTTP Host comparison | Layer 4 |
| Resource Exhaustion | Connection pooling + Per-IP limits | Layer 9 |
| Bot Automation | Browser detection + Content randomization | Layer 7/8 |
| Timing Analysis | Jitter injection (1-50ms+0-30ms) | Layer 8 |
| Fingerprinting | Server header spoofing + CORS randomization | Layer 6 |

---

## 7. Global Cryptographic Support

TLSGate-NG is the first system to offer **Automatic Cryptographic Negotiation** for global markets.

### Country-Based Cryptographic Support

| Region / Market | Primary Algorithm Stack | Fallback | Selection Method |
|----------------|------------------------|----------|------------------|
| China / Asia | Tongsuo (SM2 / SM3 / SM4) | OpenSSL 3.5 | ✅ Automatic (Client Hello) |
| Europe (EU) | OpenSSL 3.5 (AES-GCM / ChaCha20) | Tongsuo | ✅ Automatic (Client Hello) |
| Americas | OpenSSL 3.5 (NIST Curves) | Tongsuo | ✅ Automatic (Client Hello) |

### Supported Algorithms

- **Public Key:** RSA (1024-8192 bits), ECDSA (P-256/P-384/P-521), SM2 (China), Ed25519.
- **Symmetric:** AES-GCM (128/256), SM4 (China), ChaCha20.
- **Hash:** SHA-256/384/512, SM3 (China).

---

## 8. System Tuning & Prerequisites (Critical)

To achieve 10M+ concurrent connections, the operating system requires significant tuning.

### Dependencies

**Debian/Ubuntu:**
```bash
apt-get install build-essential autoconf automake libssl-dev pkg-config liburing-dev
```

**FreeBSD:**
```bash
pkg install autoconf automake openssl pkgconf gmake
```

### Kernel Optimization (`/etc/sysctl.conf`)

```bash
# Maximize connection tracking and backlog
net.core.somaxconn = 65535
net.core.netdev_max_backlog = 65535
net.ipv4.tcp_max_syn_backlog = 65535

# Optimize TCP timeouts and reuse
net.ipv4.tcp_fin_timeout = 30
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_slow_start_after_idle = 0

# Port range and keepalives
net.ipv4.ip_local_port_range = 1024 65535
net.ipv4.tcp_keepalive_time = 60
net.ipv4.tcp_keepalive_intvl = 10
net.ipv4.tcp_keepalive_probes = 6

# Congestion control
net.ipv4.tcp_congestion_control = bbr
```

### File Descriptor Limits (`/etc/security/limits.conf`)

```bash
* soft    nofile    1000000
* hard    nofile    1000000
root       soft    nofile    1000000
root       hard    nofile    1000000
```

---

## 9. Installation & Build

### Quick Build (Linux)

The build system automatically detects available instruction sets (AVX2/AES-NI) and compiles two separate binaries for IPv4/IPv6 optimization.

```bash
cd TLSGateNXv3
make clean && make
# Output: build/tlsgateNGv4 AND build/tlsgateNGv6
```

### Advanced Configure Options

```bash
./configure \
    --enable-native-arch \   # AVX2/AES-NI optimizations
    --enable-lto \           # Link-Time Optimization
    --enable-tcp-fastopen \  # TCP Fast Open support
    --enable-uring \         # Force io_uring backend
    --enable-static          # Static binary compilation
```

### Custom OpenSSL Configuration

TLSGate NG supports compilation against custom OpenSSL installations (e.g., OpenSSL 3.6.0 with enhanced SM2/SM3/SM4 support).

#### Default Behavior

The build system automatically uses OpenSSL from `/opt/openssl-3.6.0` if available, otherwise falls back to system OpenSSL.

```bash
# Standard build (uses /opt/openssl-3.6.0 automatically)
make clean
make production

# Verify OpenSSL version in compiled binary
./build/tlsgateNGv4 --about
```

#### Custom OpenSSL Path

Override the OpenSSL installation path at build time:

```bash
# Build with custom OpenSSL location
make OPENSSL_DIR=/usr/local/openssl-3.7 production

# Build with system OpenSSL (disable custom path)
make OPENSSL_DIR=/usr production
```

#### Updating OpenSSL Versions

**Scenario 1: Update in-place (e.g., 3.6 → 3.7 at same location)**

If you update OpenSSL at the same installation path (e.g., `/opt/openssl-3.6.0`), just rebuild:

```bash
make clean
make production
```

**Scenario 2: New installation path (e.g., `/opt/openssl-3.7`)**

Option A - Temporary override (no Makefile changes):
```bash
make clean
make OPENSSL_DIR=/opt/openssl-3.7 production
```

Option B - Permanent change (edit Makefile line 17):
```makefile
OPENSSL_DIR ?= /opt/openssl-3.7    # Update to new path
```

Then rebuild:
```bash
make clean
make production
```

#### Technical Details

The build system:
- Adds `-I/opt/openssl-3.6.0/include` for OpenSSL headers
- Links with `-L/opt/openssl-3.6.0/lib -Wl,-rpath,/opt/openssl-3.6.0/lib`
- Embeds library path using RPATH (no `LD_LIBRARY_PATH` needed at runtime)
- Applies to all build targets (dev, production, sanitizers, benchmarks)

---

## 10. Runtime Configuration

### Command-Line Options

**Usage:** `tlsgateNGv4 [options]`

| Option | Default | Description |
|--------|---------|-------------|
| `-l ADDR` | 0.0.0.0 | Listen IP address (Required for Multi-Instance) |
| `-p PORT` | 80 | HTTP port (Repeatable, 0 to disable) |
| `-s PORT` | 443 | HTTPS port (Repeatable, 0 to disable) |
| `-a PORT` | 8080 | Auto-detect port (TCP+UDP) |
| `-T NUM` | 4 | Worker threads per process |
| `-m NUM` | 1000 | Max connections per worker |
| `-D PATH` | ./ca | Directory for CA root and keys |
| `--shm` | - | Enable Shared Memory Keypool |
| `--poolkeygen` | - | Run as Master Keypool Generator |
| `-u USER` | nobody | Drop privileges to user |
| `-d` | - | Run in background (Daemon) |

### CA Directory Structure

```
/opt/keweonCA/
├── rootCA/
│   ├── ca.crt            # Root CA certificate
│   └── ca.key            # Private key
├── certs/                # Generated certificates (cached)
└── bundles/              # Pre-generated key bundles
```

---

## 11. Production Deployment (Multi-Instance)

### Architecture: Multi-Instance Design

**Single Server:** 32 Cores / 256GB RAM

**Orchestration:** 60-100 independent processes

**Shared Resources:** Keypool, Cert Cache, Statistics (via Shared Memory)

### Start Script Example

```bash
# 1. Start Keypool Generator (Once per server)
./build/tlsgateNGv4 --poolkeygen --shm -D /opt/keweonCA &

# 2. Start IPv4 Instances (e.g., 10 processes)
for i in {1..10}; do
  ./build/tlsgateNGv4 -l 178.162.203.162 -p $((8000+i)) \
    -D /opt/keweonCA -u sslgate --shm -d
done

# 3. Start IPv6 Instances (e.g., 10 processes)
for i in {1..10}; do
  ./build/tlsgateNGv6 -l 2a00:c98:2050:a02a:4::162 -p $((8000+i)) \
    -D /opt/keweonCA -u sslgate --shm -d
done
```

### Systemd Integration

**Keypool Service** (`/etc/systemd/system/tlsgateNG-poolgen.service`):

```ini
[Unit]
Description=TLSGate NG - Keypool Generator
After=network.target

[Service]
Type=simple
User=tlsgateNG
ExecStart=/opt/TLSGateNGv3/build/tlsgateNGv4 --poolkeygen --shm -D /opt/tlsgateNG
Restart=always
```

**Instance Service Template** (`/etc/systemd/system/tlsgateNG-instance@.service`):

```ini
[Unit]
Description=TLSGate NG - Instance %i
After=tlsgateNG-poolgen.service

[Service]
Type=simple
User=tlsgateNG
EnvironmentFile=/etc/tlsgateNG/instance%i.env
ExecStart=/opt/TLSGateNGv3/build/${BINARY} --shm -p 80 -s 443 -D /opt/tlsgateNG -l ${BIND_IP}
Restart=always
```

---

## 12. Monitoring & Statistics

TLSGate NG provides a lock-free statistics engine accessible via HTTP.

### Endpoints:

- **HTML:** `http://<IP>:80/servstats`
- **Text (Prometheus):** `http://<IP>:80/servstats.txt`

### Key Metrics:

| Metric | Description |
|--------|-------------|
| `req` | Total requests processed |
| `kcc` | Current active concurrent connections |
| `kmx` | Peak concurrent connections |
| `v13` | TLS 1.3 handshakes |
| `sm2` | SM/Tongsuo connections |
| `avg` | Average processing time (µs) |

---

## 13. Use Cases & Integrations

### DNS Sinkhole (Pi-hole / Unbound)

Redirect malicious domains to TLSGate-NG instead of blocking them.

**Outcome:** User sees a valid empty page (HTTP 200) instead of browser errors.

**Config:** `address=/ads.example.com/178.162.203.162`

### HAProxy Load Balancing

Because IPv4 and IPv6 use separate optimized binaries, HAProxy can health-check them independently.

```haproxy
backend aec_pool_ipv4
    balance roundrobin
    server ipv4_1 178.162.203.162:8001 check process tlsgateNGv4

backend aec_pool_ipv6
    balance roundrobin
    server ipv6_1 [2a00:c98:2050:a02a:4::162]:8011 check process tlsgateNGv6
```

---

## 14. Version History & Credits

### v4.36.0 GEN4 (2026)

- Full AEC Technologie Implementation
- Separate optimized binaries: `tlsgateNGv4` / `tlsgateNGv6`
- Multi-Instance Support (60-100 processes)
- Shared Memory Keypool & Dynamic Cert Generation
- Enhanced SM Algorithms (国密/商用密码)

---

## What TLSGateNG4 IS NOT:

❌ **DNS Server, Forward Proxy, Reverse Proxy, Firewall.**

## What TLSGateNG4 IS:

✅ **Abyss Endpoint, Traffic Cruncher, Universal Terminator.**

**Process ALL traffic. Scale to millions. Protect everything.**
