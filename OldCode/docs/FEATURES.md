# TLSGateNG4 v4.36 GEN4 - Complete Feature Documentation

**TLS Gateway Next Generation - Enterprise-Grade Abyss Endpoint Controller Technologie (AEC)**

---

## Table of Contents

1. [Core Network Features](#core-network-features)
2. [Security & Defense Frameworks](#security--defense-frameworks)
3. [Anti-Malware Capabilities](#anti-malware-capabilities)
4. [Anti-Phishing Features](#anti-phishing-features)
5. [Anti-Scamware Protection](#anti-scamware-protection)
6. [Performance & Scalability](#performance--scalability)
7. [Cryptography & PKI](#cryptography--pki)
8. [Traffic Processing](#traffic-processing)
9. [Deployment Modes](#deployment-modes)

---

## Core Network Features

### Port Management
- **HTTP Port (-p)**: Plain HTTP (port 80 default)
- **HTTPS Port (-s)**: TLS 1.0-1.3 (port 443 default)
- **AUTO Port (-a)**: MSG_PEEK protocol detection (port 8080 default)
  - TCP: Detects TLS ClientHello vs HTTP GET in 4 bytes
  - UDP: QUIC/HTTP3 ready (HAProxy/firewall controlled)
  - Same response content as HTTP/HTTPS
- **Port Configuration**: Set port=0 to disable any port

### Listen Address
- **IPv4 Support**: Specific IPs or 0.0.0.0 (all interfaces)
- **IPv6 Support**: Specific addresses or :: (all interfaces)
- **Auto-Detection**: Automatically detects IPv4 vs IPv6 format
- **Separate Binaries**: tlsgateNGv4 (IPv4-optimized), tlsgateNGv6 (IPv6-optimized)

### Worker Architecture
- **Multi-Threaded**: 1-64 workers (default: 4)
- **Per-Worker Connections**: 40,000-50,000 active connections
- **Connection Pooling**: Max connections per worker configurable
- **Load Distribution**: Epoll/io_uring event loop per worker

---

## Security & Defense Frameworks

### 10-Layer Defense System (Multi-Layer Protection)

#### Layer 1: Input Validation
- **SNI Validation**: Max 255 chars, alphanumeric + . - _
- **HTTP Request Validation**:
  - Max 16KB request size
  - Max 64 headers per request
  - Max 8,192 byte URI
  - GET, POST, OPTIONS, HEAD methods only
- **Path Validation**: No directory traversal (..), //, unprintable characters
- **Header Validation**: Strict RFC compliance

#### Layer 2: Network Layer Protection
- **IP Binding**: Never binds to wildcard (*) - only specific IPs
- **IPv6 Support**: Native support with separate optimizations
- **UDP Socket Handling**: QUIC/HTTP3 ready
- **Port Isolation**: Each port listens independently

#### Layer 3: Connection Layer Security
- **Connection Timeouts**: 300 seconds (5 minutes max)
- **Read Timeout**: 30 seconds
- **Write Timeout**: 30 seconds
- **Keep-Alive**: 60 seconds
- **Slowloris Protection**: Auto-close after 30 seconds inactivity
- **File Descriptor Limits**: 50K+ per process

#### Layer 4: HTTP Protocol Protection
- **Silent Blocker**: Pattern-matching with 1,024+ rules
- **Wildcard Domains**: *.example.com support
- **Reverse Proxy Option**: reverse-proxy=on per rule
- **Domain Blocking**: Configurable rule format: `domain path-pattern delay status [options]`

#### Layer 5: TLS/Certificate Layer
- **Dynamic Certificate Generation**: SNI-based on-the-fly
- **Multi-SubCA Support**: RSA, ECDSA, SM2 (国密/商用密码)
- **Certificate Caching**: Per-instance cache with warm starts
- **Certificate Index**: Automatic indexing for fast lookups
- **Auto-Renewal**: Expiration monitoring every 12 hours

#### Layer 6: Anti-Fingerprinting Defense
- **Server Header Spoofing**: 45 different server identities
- **Cache Status Rotation**: 49 cache status variants
- **Vary Header Rotation**: 81 different Vary headers
- **CF-RAY Simulation**: 95 geographic locations
- **Random ETag**: 33% chance with format variation
- **CORS Randomization**: 70% send, 30% skip random credentials

#### Layer 7: Content Randomization
- **JS Variants**: 185+ functionally useless JavaScript patterns
- **CSS Variants**: 414+ CSS patterns (resets, media queries, etc.)
- **JSON Variants**: 149+ JSON structure variations
- **XML Variants**: 40+ XML formats (RSS, Atom, SOAP, SVG, etc.)
- **HTML Template**: Compile-time embedded, configurable

#### Layer 8: Timing & Behavioral Defense
- **Timing Jitter**: 1-50ms base + 0-30ms extra randomization
- **Random Seed**: Crypto-secure (getrandom/arc4random/urandom)
- **Browser Detection**: 88 User-Agent patterns
- **Bot Detection**: Special handling for GoogleBot, BingBot, etc.
- **WebView Detection**: Instagram, Facebook, WeChat, TikTok, etc.

#### Layer 9: Resource Protection
- **Per-IP Rate Limiting**:
  - 1,000 new connections/second max
  - 10,000 requests/second max
  - 100 Mbps bandwidth max
- **Connection Pool Exhaustion**: Prevents memory attacks
- **File Descriptor Management**: Per-process limits
- **Worker Load Balancing**: Even distribution across workers

#### Layer 10: Observability & Monitoring
- **Lock-Free Statistics**: Atomic operations (zero overhead)
- **Real-Time Metrics**: Prometheus + JSON export
- **Minimal Logging**: ERROR level only (SILENT mode)
- **/stats Endpoint**: Real-time connection/request counts
- **/metrics Endpoint**: Prometheus-compatible metrics

---

## Anti-Malware Capabilities

### Malware Protection Strategy

TLSGateNG4 is **not a malware scanner**, but functions as a **DNS Sinkhole Response Engine** that blocks malware distribution channels:

#### 1. Domain-Based Blocking
- **Blocklist Integration**: Works with Pi-hole, Unbound, dnsmasq
- **Malware C&C Prevention**: Blocks known malware command & control domains
- **Botnet Protection**: Prevents botnet communication
- **Payload Download Prevention**: Blocks known malware distribution domains
- **Crypto-Miner Blocking**: Prevents cryptominer script distribution

#### 2. Silent Blocker Rules
- **Domain Patterns**: Exact matches, wildcards (*.evil.com)
- **Path Patterns**: Resource-specific blocking (e.g., /admin/payload.exe)
- **Delay Injection**: Configurable delays per rule (0-10000ms)
- **Status Override**: Return custom HTTP status (200, 204, 404, etc.)
- **Rule Limit**: Up to 1,024 rules per instance

#### 3. Indirection Prevention
- **Poly glot Attack Detection**:
  - Detects embedded payloads: `data:text/html,<script>...</script>`
  - Identifies JavaScript handlers: `javascript:eval(...)`
  - Analyzes Unicode obfuscation: `\u0068\u0074\u0074\u0070` → `http`
  - Prevents protocol handler abuse

#### 4. Redirect Chain Analysis
- **Multi-Hop Detection**: Tracks 301/302/307/308 redirects
- **Redirect Loop Prevention**: Limits redirect depth
- **Covert Channel Blocking**: Detects domain-fronting attacks

#### 5. Browser Exploitation Prevention
- **Browser Detection**: 88 User-Agent patterns
- **Bot Fingerprinting**: Distinguishes real browsers from automation
- **WebView Blocking**: Prevents embedded webview attacks (Instagram, WeChat, TikTok, etc.)
- **Legacy Browser Support**: Graceful handling of old clients

---

## Anti-Phishing Features

### Phishing Attack Mitigation

#### 1. Domain Validation
- **SNI Validation**: Strict certificate matching
- **Domain Matching**: Prevents domain confusion attacks
- **Typosquatting Prevention**: Blocklist integration for known typosquats
- **IDN Homograph Protection**: Detects look-alike domains

#### 2. Header Security
- **Security Headers**:
  - X-Content-Type-Options: nosniff
  - X-Frame-Options: DENY
  - X-XSS-Protection: 1; mode=block
  - Strict-Transport-Security: max-age=31536000
  - Content-Security-Policy: Configurable

#### 3. TLS Verification
- **Certificate Validation**: Proper TLS 1.0-1.3 handshake
- **HTTPS Enforcement**: No downgrade to HTTP
- **Protocol Verification**: Prevents BEAST, POODLE, CRIME attacks

#### 4. Content Security
- **Template Isolation**: Compile-time embedded (no runtime loading)
- **XSS Prevention**: No dynamic content injection
- **CSS Security**: Prevents CSS-based attacks
- **Script Isolation**: No external script loading

#### 5. Behavioral Analysis
- **Request Pattern Analysis**: Detects automated phishing bots
- **Timing Analysis**: Identifies pattern-based attacks
- **User-Agent Validation**: Rejects suspicious clients
- **Connection Profiling**: Blocks known phishing tools

---

## Anti-Scamware Protection

### Scamware & Tech Support Scam Prevention

#### 1. Domain Blocking
- **Scamware Domains**: Integration with blocklists (Google Safe Browsing, etc.)
- **Tech Support Scam Sites**: Blocks fake support pages
- **Fake Payment Processor Detection**: Prevents payment redirection
- **Malicious CDN Blocking**: Blocks scamware distribution CDNs

#### 2. Content Filtering
- **Pop-up Blocker**: No pop-up windows (HTTP responses don't support them)
- **Alert Prevention**: No JavaScript alerts or confirms
- **Form Hijacking Prevention**: No form-based attacks possible
- **Payment Form Blocking**: Prevents fake payment forms

#### 3. Redirect Prevention
- **Redirect Chain Blocking**: Prevents multi-step redirect scams
- **Domain Fronting Detection**: Identifies TLS SNI vs HTTP Host mismatches
- **Meta Refresh Blocking**: No automatic redirects
- **JavaScript Redirects**: Limited (no dangerous redirects in responses)

#### 4. Social Engineering Defense
- **Fake Download Prevention**: Returns valid HTTP 200 (not executable)
- **Tech Support Simulation**: Returns generic HTML (not support interface)
- **Compliance Warnings**: No fake legal warnings
- **Urgency Removal**: No time-pressure messages in responses

#### 5. Financial Scam Prevention
- **Fake Bank Simulation**: Returns generic content
- **Bitcoin/Crypto Scam Blocking**: Blocklist integration for known scam sites
- **Fake Invoice Blocking**: No invoice-like content
- **Payment Aggregator Blocking**: Blocks fake Stripe, PayPal, Wise, etc.

---

## Performance & Scalability

### Single Instance Performance
```
Concurrent Connections:  160,000 (4 workers × 40K)
HTTP Requests/sec:       10-20K
HTTPS Requests/sec:      5-10K
Latency (p99):           <10ms
Memory Usage:            ~3GB per instance
CPU Core Usage:          1-4 cores per instance
```

### Multi-Instance Deployment
```
Instances per Server:    20-60
Concurrent Connections:  10M+
Total HTTP req/sec:      200-400K
Total HTTPS req/sec:     100-200K
Total Memory:            180GB (of 256GB available)
Total CPU Usage:         70-90%
```

### I/O Backend Options
- **io_uring** (Linux 5.1+): 500K+ req/s HTTPS
- **epoll** (Fallback): 50K+ req/s HTTPS (older kernels)
- **kqueue** (BSD/macOS): High-performance alternative

### Connection Limits
- **Per Worker**: 40K-50K connections
- **Per Instance**: 160K-200K connections
- **Per Server**: 10M+ connections (60 instances)
- **File Descriptors**: 50K-1M per process (configurable via ulimit)

---

## Cryptography & PKI

### Supported Algorithms

#### Public Key Cryptography
- **RSA**: 1024, 2048, 4096, 8192 bits (legacy and modern)
- **ECDSA**: P-256, P-384, P-521 curves
- **SM2**: 国密/商用密码 (Chinese Commercial Cryptography)
- **Ed25519**: Elliptic Curve Edwards form (modern, non-interactive)

#### Hash Algorithms
- **SHA**: SHA-1 (legacy), SHA-256, SHA-384, SHA-512
- **SM3**: 国密/商用密码 hash algorithm
- **MD5**: Legacy only (not recommended)

#### Symmetric Encryption (TLS)
- **AES**: 128, 192, 256-bit (GCM, CBC modes)
- **SM4**: 国密/商用密码 block cipher
- **ChaCha20**: Modern alternative to AES

#### TLS Versions
- **TLS 1.0**: Legacy support (older clients)
- **TLS 1.1**: Legacy support
- **TLS 1.2**: Standard (widely supported)
- **TLS 1.3**: Modern (recommended, fastest)

### PKI Management

#### Multi-SubCA Support
- **3-Tier Structure**:
  1. Root CA (offline, shared)
  2. Sub-CAs (online, per algorithm):
     - RSA SubCA
     - ECDSA SubCA
     - SM2 SubCA
  3. End-Entity Certificates (generated dynamically)

#### Certificate Generation
- **SNI-Based**: Certificates generated for requested domain names
- **Dynamic Creation**: On-the-fly certificate generation
- **Caching**: Per-instance certificate cache (warm start)
- **Auto-Renewal**: Automatic renewal for expiring certificates
- **Batch Generation**: Pre-generated key bundles for speed

#### Prime Pool Optimization
- **Pre-Computed Primes**: 20-200× faster RSA generation
- **Shared Across Instances**: Server-wide prime pool
- **Multiple Sizes**: 1024, 2048, 4096, 8192-bit primes
- **Memory Mapped**: Efficient sharing via shared memory

---

## Traffic Processing

### Request Handling Pipeline

1. **Accept**: TCP/UDP socket accept
2. **TLS Handshake**: (if HTTPS or AUTO port)
   - SNI extraction
   - Dynamic certificate generation or retrieval
3. **HTTP Parsing**: MSG_PEEK detection (AUTO port) or direct parsing
4. **Request Validation**: Headers, size, method, path checks
5. **Content Generation**:
   - Favicon (ICO format, 9,462 bytes)
   - HTML template with timestamp
   - JSON, XML, CSS, JavaScript variants
6. **Header Generation**: Randomized, spoofed server identities
7. **Timing Jitter**: Variable delay injection
8. **Response Send**: Zero-copy operations (if possible)
9. **Statistics Update**: Lock-free atomic operations
10. **Connection Management**: Keep-alive or close

### Response Generation

#### Content Types Supported: 265+ MIME Types
- **Text**: HTML, CSS, JavaScript, JSON, XML, etc.
- **Images**: PNG, JPG, GIF, SVG, WebP, ICO, etc.
- **Archives**: ZIP, TAR, GZ, BZ2, 7Z, RAR, etc.
- **Documents**: PDF, DOCX, XLSX, PPTX, etc.
- **Media**: MP3, MP4, MKV, WebM, OGG, FLAC, etc.
- **Fonts**: TTF, OTF, WOFF, WOFF2, etc.
- **Code**: C, Java, Python, JavaScript, Go, Rust, etc.

#### Response Customization
- **Status Code**: 200 (default), 204, 304, 404, 503, custom
- **Headers**: Dynamic, randomized, spoofed
- **Content**: Template-based, compile-time embedded
- **Delays**: Per-rule or global jitter
- **Size**: Variable content length

### Silent Blocker Features

```
Rule Format: domain path delay status [options]

Example Rules:
  ads.example.com     /tracker    100  200
  *.doubleclick.net   /ads        50   204
  malware.com         /payload    0    404

Configuration: 1,024 rules maximum per instance
```

---

## Deployment Modes

### Standalone (Single Instance)
```bash
./tlsgateNGv4 -l 192.168.1.100 -p 80 -s 443 -a 8080 \
              -D /opt/tlsgateNG -w 4 -m 50000
```

### Multi-Instance (Shared Keypool)
```bash
# Reader Instances (20-60 per server):
./tlsgateNGv4 --shm -l 192.168.1.100 -s 443 \
              -C /opt/certcache/term1 -w 4
./tlsgateNGv4 --shm -l 192.168.1.101 -s 443 \
              -C /opt/certcache/term2 -w 4

# Systemd Services: automatic management
```

### HAProxy Load Balancing
```
Backend configuration using process names:
- tlsgateNGv4: IPv4-optimized binary
- tlsgateNGv6: IPv6-optimized binary
- Separate process names for health checks
```

### Docker Containerization
- Alpine Linux base
- Multi-stage build (reduced image size)
- Volume mounts for CA directory
- Network modes: bridge, host, custom

### Kubernetes Deployment
- Helm charts (TBD)
- StatelessSet for instances
- ConfigMap for rules
- PersistentVolume for CA

---

## Configuration Options

### Command-Line Flags

| Flag | Default | Purpose |
|------|---------|---------|
| `-l ADDR` | * | Listen address |
| `-p PORT` | 80 | HTTP port |
| `-s PORT` | 443 | HTTPS port |
| `-a PORT` | 8080 | AUTO port |
| `-w NUM` | 4 | Worker threads |
| `-m NUM` | 1000 | Max connections/worker |
| `-D, --ca-dir` | - | CA directory |
| `-C, --cert-dir` | - | Certificate cache |
| `-b, --bundles` | - | Key bundle directory |
| `-r, --prime-dir` | - | Prime pool directory |
| `--shm` | - | Shared memory keypool |
| `-u USER` | - | Drop privileges to user |
| `-g GROUP` | - | Drop privileges to group |
| `-d` | - | Daemonize |
| `-v` | - | Verbose logging |
| `--generate-config` | - | Config generator |
| `--test` | - | Test configuration |
| `--status` | - | Show system status |
| `-V, --version` | - | Show version |
| `-h, --help` | - | Show help |

---

## Version Information

**TLSGate NG v4.36 GEN4 (2026 - with SM Algorithms 国密/商用密码)**

**Build Date**: Compile-time
**Compiler**: GCC/Clang (CPU-optimized)
**License**: Proprietary
**Author**: Torsten Jahnke

---

## Security Notes

1. **Always run latest version** for security patches
2. **Use privilege dropping** (-u, -g flags)
3. **Configure firewall** to restrict access
4. **Monitor logs** for suspicious activity
5. **Rotate certificates** regularly
6. **Update CA directory** for new domains
7. **Use HTTPS** for all client connections
8. **Enable shared memory** for multi-instance (performance)

---

## Performance Tuning

### System Limits
```bash
# Increase file descriptors
ulimit -n 1000000

# Increase network buffer sizes
sysctl -w net.core.rmem_max=134217728
sysctl -w net.core.wmem_max=134217728
sysctl -w net.ipv4.tcp_rmem="4096 87380 134217728"
sysctl -w net.ipv4.tcp_wmem="4096 65536 134217728"
```

### Compiler Optimization
```bash
# Production build (EXTREME optimization)
make production

# With security hardening
make secure
```

### CPU Affinity (Optional)
```bash
# Bind process to specific CPUs
taskset -c 0-3 ./tlsgateNGv4 ...
```

---

**For more information:**
- README.md - Overview and architecture
- ARCHITECTURE.md - System design details
- SECURITY_REQUIREMENTS.md - Security specifications
- docs/ - Additional documentation
