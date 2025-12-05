# TLSGateNG4 v4.36 GEN4 (2026) - Architecture

**国密/商用密码 Support - SM2/SM3/SM4 Chinese Commercial Cryptography**

## System-Typ: DNS Sinkhole Response Server

**TLSGateNG4 ist KEIN Proxy!** Es ist ein Response Generator für blockierte Domains.

## Wie funktioniert DNS Sinkhole Ad-Blocking?

```
┌─────────────────────────────────────────────────────────────────┐
│                    DNS SINKHOLE WORKFLOW                         │
└─────────────────────────────────────────────────────────────────┘

1. USER macht Request:
   ┌─────────┐
   │ Browser │ → "GET http://doubleclick.net/ads/tracker.js"
   └─────────┘
        │
        ├─ DNS Lookup: "doubleclick.net"
        │
        ▼
   ┌──────────────┐
   │  DNS Server  │ (Pi-hole, Unbound, dnsmasq)
   │  (Blocklist) │
   └──────────────┘
        │
        ├─ Domain ist auf Blocklist!
        ├─ Antwortet mit: 178.162.203.162 (TLSGate IP)
        │
        ▼
   ┌──────────────┐
   │ TLSGateNG4   │ ← Request geht zu TLSGate statt zu doubleclick.net
   │  (pixelserv) │
   └──────────────┘
        │
        ├─ Generiert minimale Response:
        ├─ • .js  → Leeres JS: "/* blocked */"
        ├─ • .css → Leeres CSS: "/* blocked */"
        ├─ • .gif → 1×1 transparentes GIF
        ├─ • .ico → 1×1 ICO (70 bytes)
        │
        ▼
   ┌─────────┐
   │ Browser │ ← Erhält Response (200 OK)
   └─────────┘
        │
        ├─ Browser denkt Request war erfolgreich
        ├─ KEINE Werbung wird angezeigt
        └─ KEIN gebrochenes Layout


┌─────────────────────────────────────────────────────────────────┐
│                    VERGLEICH: PROXY vs. SINKHOLE                 │
└─────────────────────────────────────────────────────────────────┘

❌ PROXY (Forward/Reverse):
   Browser → Proxy → Real Server → Proxy → Browser
   - Leitet Requests weiter
   - Filtert/Modifiziert Inhalte
   - Benötigt Browser-Konfiguration

✅ DNS SINKHOLE (TLSGate):
   Browser → DNS (umleiten) → TLSGate → Minimale Response
   - Leitet NICHTS weiter
   - Generiert eigene Responses
   - Transparent (keine Browser-Config)


┌─────────────────────────────────────────────────────────────────┐
│                    DEPLOYMENT BEISPIEL                           │
└─────────────────────────────────────────────────────────────────┘

Netzwerk Setup:
┌──────────────────────────────────────────────────────────────┐
│                    Enterprise Network                         │
│                                                              │
│  Router/Firewall                                            │
│  ├─ DNS: 192.168.1.1 (Pi-hole)                             │
│  └─ DHCP: DNS Server = 192.168.1.1                         │
│                                                              │
│  ┌────────────────┐          ┌────────────────┐           │
│  │   Pi-hole      │          │   TLSGate NX   │           │
│  │  192.168.1.1   │          │ 178.162.203.162│           │
│  │                │          │ 2a00:c98:...162│           │
│  │ - Blocklist:   │          │                │           │
│  │   doubleclick  │──────────│ - HTTP Port 80 │           │
│  │   facebook/ads │  points  │ - HTTPS Port443│           │
│  │   google-ads   │  blocked │ - 60-100 proc. │           │
│  │   ...          │  domains │ - 2-4 threads  │           │
│  │   2M+ domains  │    to    │ - 265+ MIMEs   │           │
│  └────────────────┘          └────────────────┘           │
│                                                              │
│  Clients (Laptops, Phones, IoT):                           │
│  - Nutzen DNS 192.168.1.1                                  │
│  - Keine Browser-Konfiguration nötig                       │
│  - Transparentes Ad-Blocking                               │
└──────────────────────────────────────────────────────────────┘


┌─────────────────────────────────────────────────────────────────┐
│                    MULTI-INSTANCE ARCHITECTURE                   │
└─────────────────────────────────────────────────────────────────┘

Server: AMD EPYC 32 Cores / 256GB RAM
├─ 10 Public IPs gebunden
├─ 60-100 TLSGate Prozesse (6-10 pro IP)
│
└─ Pro Prozess:
   ├─ 2-4 Worker Threads
   ├─ ~40K Connections pro Worker
   ├─ epoll Event Loop
   └─ Shared Memory:
      ├─ Keypool (RSA/ECDSA keys)
      ├─ Certificate Cache
      └─ Statistics


┌─────────────────────────────────────────────────────────────────┐
│                    RESPONSE TYPES                                │
└─────────────────────────────────────────────────────────────────┘

Extension    Response                      Size
────────────────────────────────────────────────────────────
.js          /* blocked */                  ~15 bytes
.css         /* blocked */                  ~15 bytes
.gif         1×1 transparent GIF            42 bytes
.ico         1×1 minimal ICO                70 bytes
.png         1×1 transparent PNG            ~68 bytes
.jpg         1×1 JPEG                       ~368 bytes
.json        {}                             2 bytes
.xml         <root/>                        ~8 bytes
.html        <!DOCTYPE html>...             ~150 bytes
favicon.ico  Real 48×47 favicon             9,462 bytes

+ 265+ weitere MIME types!


┌─────────────────────────────────────────────────────────────────┐
│                    ANTI-ADBLOCK FEATURES                         │
└─────────────────────────────────────────────────────────────────┘

Problem: Websites erkennen Ad-Blocker durch:
- Fehlende Responses
- Identische Content-Hashes
- Server Fingerprinting

TLSGate Lösung:
├─ Polymorphic Responses (variierender Content)
├─ Random Server Headers
├─ Timing Jitter
├─ Content Randomization:
│  ├─ JS: var x = 123; → var y = 456;
│  └─ CSS: margin: 5px; → margin: 8px;
└─ Result: Jede Response sieht anders aus


┌─────────────────────────────────────────────────────────────────┐
│                    SECURITY HEADERS                              │
└─────────────────────────────────────────────────────────────────┘

Alle Responses enthalten:
- Access-Control-Allow-Origin: *
- Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS
- Access-Control-Allow-Headers: *
- X-Content-Type-Options: nosniff
- X-Frame-Options: SAMEORIGIN

→ Verhindert CORS-Fehler und broken Layouts
```

## Zusammenfassung

**TLSGate NX ist:**
- ✅ DNS Sinkhole Response Server
- ✅ pixelserv-tls Nachfolger
- ✅ Ad-Blocking Response Generator
- ✅ High-Performance Enterprise Solution

**TLSGate NX ist NICHT:**
- ❌ Forward Proxy
- ❌ Reverse Proxy
- ❌ Traffic Filter
- ❌ Content Modifier

**Deployment:**
- Arbeitet mit DNS-Servern (Pi-hole, Unbound, etc.)
- Benötigt KEINE Browser-Konfiguration
- Transparent für End-User
- Skaliert auf Millionen Connections

---

## Erweiterte Architektur: Request Processing Pipeline

### Complete Request Lifecycle

```
CLIENT SENDS REQUEST
        │
        ▼
    [NETWORK LAYER]
    - TCP/UDP Accept
    - IP Validation
    - Port Binding
        │
        ▼
   [CONNECTION LAYER]
   - Connection Tracking
   - Timeout Management
   - Resource Limits
        │
        ▼
  [INPUT VALIDATION]
  - Method Validation
  - Header Limits
  - Path Validation
  - Size Limits
        │
        ├─ HTTPS/TLS:
        │  ├─ SNI Extraction
        │  ├─ Certificate Lookup
        │  └─ TLS Handshake
        │
        ▼
  [HTTP PARSING]
  - Request Line Parse
  - Header Parse
  - Content Type Detect
        │
        ▼
  [SILENT BLOCKER]
  - Domain Matching
  - Path Matching
  - Rule Check
        │
        ├─ BLOCKED:
        │  └─ Return Custom Status
        │
        ├─ FORWARD:
        │  └─ Reverse Proxy
        │
        ▼
  [CONTENT GENERATION]
  - Browser Detection
  - Content Selection
  - Randomization
        │
        ├─ JavaScript Content
        ├─ CSS Content
        ├─ JSON Content
        ├─ XML Content
        └─ HTML Template
        │
        ▼
  [HEADER GENERATION]
  - Server Spoofing (45 variants)
  - Cache Status (49 variants)
  - Vary Headers (81 variants)
  - CF-RAY (95 locations)
  - ETag (random 33%)
  - CORS (70% random)
        │
        ▼
  [TIMING DEFENSE]
  - Jitter Injection
  - Base Delay (1-50ms)
  - Extra Delay (0-30ms)
        │
        ▼
  [RESOURCE PROTECTION]
  - Rate Limit Check
  - Connection Cap Check
  - Per-IP Limits
        │
        ▼
  [STATISTICS]
  - Atomic Counter Update
  - Request Count
  - Bandwidth Tracking
        │
        ▼
  [SEND RESPONSE]
  - Zero-Copy if Possible
  - Connection Keep-Alive
  - Or Graceful Close
        │
        ▼
   CLIENT RECEIVES RESPONSE
```

---

## Architektur: Feature-Layer Modell

### 10-Layer Defense System

```
┌─────────────────────────────────────────────────────────────┐
│ LAYER 1: INPUT VALIDATION                                   │
│ • SNI validation (max 255 chars)                             │
│ • HTTP method validation (GET, POST, OPTIONS, HEAD)          │
│ • Request size limit (16KB)                                  │
│ • Header count limit (64 max)                                │
│ • Path validation (no .., //)                                │
└─────────────────────────────────────────────────────────────┘
                            ▲
                            │
┌─────────────────────────────────────────────────────────────┐
│ LAYER 2: NETWORK LAYER PROTECTION                            │
│ • IP binding validation (no wildcard)                         │
│ • IPv4/IPv6 support                                          │
│ • UDP socket handling (QUIC/HTTP3)                            │
│ • Port isolation                                              │
└─────────────────────────────────────────────────────────────┘
                            ▲
                            │
┌─────────────────────────────────────────────────────────────┐
│ LAYER 3: CONNECTION SECURITY                                │
│ • Connection timeout (300s max)                              │
│ • Read timeout (30s)                                          │
│ • Write timeout (30s)                                        │
│ • Slowloris protection                                        │
│ • Connection pool management (40K-50K per worker)             │
└─────────────────────────────────────────────────────────────┘
                            ▲
                            │
┌─────────────────────────────────────────────────────────────┐
│ LAYER 4: HTTP PROTOCOL PROTECTION                           │
│ • Silent Blocker (1,024 rules)                               │
│ • Domain pattern matching                                    │
│ • Path-specific blocking                                     │
│ • Reverse proxy option                                       │
│ • Custom delay injection                                     │
└─────────────────────────────────────────────────────────────┘
                            ▲
                            │
┌─────────────────────────────────────────────────────────────┐
│ LAYER 5: TLS/CERTIFICATE PROTECTION                         │
│ • Dynamic certificate generation (SNI-based)                 │
│ • Multi-SubCA support (RSA, ECDSA, SM2)                      │
│ • Certificate caching & indexing                             │
│ • Auto-renewal (12-hour maintenance)                         │
│ • Keypool management (shared memory)                          │
└─────────────────────────────────────────────────────────────┘
                            ▲
                            │
┌─────────────────────────────────────────────────────────────┐
│ LAYER 6: ANTI-FINGERPRINTING                                │
│ • Server header spoofing (45 variants)                       │
│ • Cache status rotation (49 variants)                        │
│ • Vary header rotation (81 variants)                         │
│ • CF-RAY simulation (95 locations)                            │
│ • ETag randomization (33% random)                            │
│ • CORS randomization (70% send)                              │
└─────────────────────────────────────────────────────────────┘
                            ▲
                            │
┌─────────────────────────────────────────────────────────────┐
│ LAYER 7: CONTENT RANDOMIZATION                              │
│ • JavaScript variants (185+)                                 │
│ • CSS variants (414+)                                        │
│ • JSON variants (149+)                                       │
│ • XML variants (40+)                                         │
│ • MIME type system (265+)                                    │
└─────────────────────────────────────────────────────────────┘
                            ▲
                            │
┌─────────────────────────────────────────────────────────────┐
│ LAYER 8: TIMING & BEHAVIORAL DEFENSE                        │
│ • Timing jitter (1-50ms base + 0-30ms extra)                 │
│ • Browser detection (88 UA patterns)                         │
│ • Bot detection (GoogleBot, BingBot, etc.)                   │
│ • WebView detection (Instagram, WeChat, TikTok)              │
│ • Regional headers (GDPR, CCPA, UK-GDPR)                     │
└─────────────────────────────────────────────────────────────┘
                            ▲
                            │
┌─────────────────────────────────────────────────────────────┐
│ LAYER 9: RESOURCE PROTECTION                                │
│ • Per-IP rate limiting (1K conn/sec, 10K req/sec)            │
│ • Connection pool exhaustion prevention                       │
│ • Worker thread management (1-64 workers)                    │
│ • File descriptor limits (50K+ per process)                  │
└─────────────────────────────────────────────────────────────┘
                            ▲
                            │
┌─────────────────────────────────────────────────────────────┐
│ LAYER 10: OBSERVABILITY & MONITORING                        │
│ • Lock-free statistics (atomic operations)                   │
│ • Real-time metrics (Prometheus + JSON)                      │
│ • Minimal logging (ERROR level only)                         │
│ • /stats and /metrics endpoints                              │
│ • Connection tracking & profiling                            │
└─────────────────────────────────────────────────────────────┘
```

---

## Module-Abhängigkeiten

```
tlsgateNG.c (Main)
    │
    ├─ version.c/h (Version & Help)
    │
    ├─ core/
    │  ├─ worker.c (Event Loop)
    │  │   ├─ connection.c (Connection Handling)
    │  │   ├─ anti_adblock/
    │  │   ├─ http/
    │  │   └─ tls/
    │  │
    │  └─ connection.c (Socket I/O)
    │      ├─ logger.c (Logging)
    │      └─ util.c (Utilities)
    │
    ├─ http/
    │  ├─ response.c (HTTP Responses)
    │  │  ├─ extension_lookup.c (MIME Types)
    │  │  ├─ silent_blocker.c (Domain Blocking)
    │  │  └─ reverse_proxy.c (Proxying)
    │  │
    │  └─ silent_blocker.c (Rules Engine)
    │      └─ config/config_file.c
    │
    ├─ anti_adblock/
    │  ├─ anti_adblock.c (Header Spoofing)
    │  │  ├─ browser_detection.c (UA Analysis)
    │  │  └─ timing_jitter.c (Delay Injection)
    │  │
    │  ├─ browser_detection.c (Bot Detection)
    │  └─ timing_jitter.c (Timing Randomization)
    │
    ├─ tls/
    │  └─ sni_extractor.c (SNI Validation)
    │
    ├─ cert/
    │  ├─ ca_loader.c (CA Management)
    │  ├─ cert_generator.c (Cert Generation)
    │  │  ├─ crypto/keypool.c (Keys)
    │  │  └─ pki/pki_manager.c (PKI)
    │  │
    │  ├─ cert_cache.c (Caching)
    │  ├─ cert_index.c (Indexing)
    │  ├─ cert_maintenance.c (Auto-Renewal)
    │  └─ second_level_tlds.c (TLD Validation)
    │
    ├─ crypto/
    │  └─ keypool.c (Key Pool)
    │
    ├─ pki/
    │  └─ pki_manager.c (PKI Operations)
    │
    ├─ ipc/
    │  └─ shm_manager.c (Shared Memory)
    │
    ├─ config/
    │  ├─ config_file.c (Config Parsing)
    │  └─ config_generator.c (Config Generation)
    │
    └─ util/
       ├─ logger.c (Logging)
       └─ util.c (Utilities)
```

---

## Performance-Charakteristiken

### Single Instance (4 Worker Threads)
```
Max Concurrent Connections:  160,000
HTTP Requests/sec:            10-20,000
HTTPS Requests/sec:            5-10,000
Latency (p99):                < 10ms
Memory Usage:                 ~3GB
```

### Multi-Instance (60 Instances per Server)
```
Max Concurrent Connections:   10,000,000+
Total HTTP req/sec:           200-400,000
Total HTTPS req/sec:          100-200,000
Total Memory:                 180GB (256GB available)
CPU Usage:                    70-90%
```

### I/O Backends
- **io_uring** (Linux 5.1+): 500K+ req/s HTTPS
- **epoll** (Fallback): 50K+ req/s HTTPS
- **kqueue** (BSD/macOS): High performance alternative

---

**For detailed security analysis, see: docs/SECURITY_FRAMEWORK.md**

**For feature documentation, see: docs/FEATURES.md**

**For performance tuning, see: docs/PERFORMANCE_TUNING.md**
