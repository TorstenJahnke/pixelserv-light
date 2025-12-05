# TLSGate NX v2 - Security Requirements

**Datum:** 2025-11-06
**Zweck:** Production Security Anforderungen

---

## 🔒 CRITICAL SECURITY RULES

### 1. IP Binding - NEVER BIND TO "*"

**REGEL:** Server bindet **AUSSCHLIESSLICH** auf definierte IP-Adressen!

**VERBOTEN:**
```c
addr.sin_addr.s_addr = INADDR_ANY;  // ❌ NIEMALS!
addr.sin6_addr = in6addr_any;       // ❌ NIEMALS!
```

**RICHTIG:**
```c
/* IPv4 - Spezifische IP */
inet_pton(AF_INET, "178.162.203.162", &addr.sin_addr);

/* IPv6 - Spezifische IP */
inet_pton(AF_INET6, "2a00:c98:2050:a02a:4::162", &addr6.sin6_addr);
```

**Warum?**
- Verhindert Binding auf unerwünschte Interfaces
- Kontrolle über welche IPs erreichbar sind
- Multi-IP Deployment (10+ IPs pro Server)
- Sicherheit: Kein unbeabsichtigtes Exponieren

---

## 🌍 Production IP Adressen

**IPv4:**
```
178.162.203.162
```

**IPv6:**
```
2a00:c98:2050:a02a:4::162
```

**Deployment:**
- Pro Server: 4-10 IP Adressen
- Pro IP: 6-10 Prozesse (Ports 80, 443, 8080, ...)
- Jeder Prozess bindet auf EINE spezifische IP:Port Kombination

---

## 🧪 Test Domains

**WICHTIG:** Für Tests NIEMALS localhost verwenden!

**Test Domains:**
```
example.com
example2.com
example.co.uk
```

**Test Commands:**
```bash
# HTTP Test
curl -H "Host: example.com" http://178.162.203.162/

# HTTPS Test (später)
curl -H "Host: example.com" https://178.162.203.162/ --resolve example.com:443:178.162.203.162

# IPv6 Test
curl -H "Host: example.com" http://[2a00:c98:2050:a02a:4::162]/
```

**Warum nicht localhost?**
- Production-realistische Tests
- DNS-based Traffic Redirect Simulation
- Host-Header Testing
- Virtual Host Simulation

---

## 🔐 Security Features

### Input Validation

**1. SNI Validation (später mit SSL)**
```c
bool is_valid_sni(const char *sni) {
    if (!sni || strlen(sni) > 255) return false;
    if (strlen(sni) < 3) return false;  // Minimum: "a.b"

    /* Nur alphanumerisch + . - _ */
    for (const char *p = sni; *p; p++) {
        if (!isalnum(*p) && *p != '.' && *p != '-' && *p != '_') {
            return false;
        }
    }

    /* Keine zwei aufeinander folgende dots */
    if (strstr(sni, "..")) return false;

    /* Nicht mit . oder - beginnen/enden */
    if (sni[0] == '.' || sni[0] == '-') return false;
    size_t len = strlen(sni);
    if (sni[len-1] == '.' || sni[len-1] == '-') return false;

    return true;
}
```

**2. HTTP Request Validation**
```c
/* Max request size */
#define MAX_REQUEST_SIZE  16384   /* 16KB */

/* Max header count */
#define MAX_HEADER_COUNT  64

/* Max URI length */
#define MAX_URI_LENGTH    8192

/* Allowed methods */
const char *allowed_methods[] = {"GET", "POST", "OPTIONS", "HEAD", NULL};
```

**3. Path Validation**
```c
bool is_valid_path(const char *path) {
    if (!path || strlen(path) > MAX_URI_LENGTH) return false;

    /* Keine Directory Traversal */
    if (strstr(path, "..")) return false;
    if (strstr(path, "//")) return false;

    /* Nur druckbare ASCII */
    for (const char *p = path; *p; p++) {
        if (*p < 0x20 || *p > 0x7E) return false;
    }

    return true;
}
```

### Resource Limits

**Per Connection:**
```c
#define CONN_TIMEOUT_SEC      300   /* 5 min max connection age */
#define READ_TIMEOUT_SEC      30    /* 30 sec read timeout */
#define WRITE_TIMEOUT_SEC     30    /* 30 sec write timeout */
#define KEEPALIVE_TIMEOUT_SEC 60    /* 60 sec keepalive */
```

**Per Worker:**
```c
#define MAX_CONN_PER_WORKER   40000  /* 40K connections */
#define MAX_EVENTS_PER_LOOP   1024   /* epoll batch size */
```

**Per Process:**
```c
#define MAX_FD_PER_PROCESS    50000  /* File descriptors */
#define MAX_MEMORY_MB         4096   /* 4GB per process */
```

**Rate Limiting (Per IP):**
```c
#define MAX_CONN_PER_IP_SEC   1000   /* 1K new connections/sec */
#define MAX_REQ_PER_IP_SEC    10000  /* 10K requests/sec */
#define MAX_BANDWIDTH_MBPS    100    /* 100 Mbps per IP */
```

---

## 🛡️ Attack Protection

### 1. Slowloris Protection
```c
/* Detect slow clients */
if (time(NULL) - conn->last_activity > SLOW_CLIENT_TIMEOUT) {
    /* Close connection if no data for 30 sec */
    connection_close(conn);
}
```

### 2. Request Flooding Protection
```c
/* Per-IP connection tracking */
typedef struct {
    uint32_t ip;
    atomic_int conn_count;
    atomic_int req_count;
    time_t window_start;
} ip_stats_t;

/* Check rate limits */
if (ip->req_count > MAX_REQ_PER_IP_SEC) {
    return -1;  /* Drop */
}
```

### 3. Memory Exhaustion Protection
```c
/* Connection pool exhaustion */
if (worker->active_connections >= MAX_CONN_PER_WORKER) {
    /* Reject new connections */
    close(client_fd);
    return;
}
```

### 4. TLS Handshake DoS Protection (später)
```c
/* Limit handshake time */
#define TLS_HANDSHAKE_TIMEOUT_SEC 10

/* Early detection of invalid ClientHello */
if (!is_valid_client_hello(buf, len)) {
    close(client_fd);
    return;
}
```

---

## 📝 Logging Policy

**WICHTIG:** TLSGate NX loggt **MINIMAL** für Performance!

**Was wird NICHT geloggt:**
- ❌ Normale HTTP Requests (zu viele!)
- ❌ Successful Responses
- ❌ DNS Requests (das macht der DNS Server!)

**Was wird geloggt:**
- ✅ Startup/Shutdown Events
- ✅ Errors (Connection failures, Parse errors)
- ✅ Security Events (Rate limit hits, Invalid SNI)
- ✅ Statistics (alle 60 sec)

**Log Levels:**
```c
typedef enum {
    LOG_FATAL,    /* Unrecoverable errors */
    LOG_ERROR,    /* Errors (connection issues) */
    LOG_WARN,     /* Warnings (rate limits) */
    LOG_INFO,     /* Info (startup/shutdown) */
    LOG_DEBUG     /* Debug (development only) */
} log_level_t;
```

**Production Log Level:** `LOG_ERROR`

---

## 🔍 Monitoring

### Statistics Collection (Lock-Free!)

```c
typedef struct {
    /* Connection stats */
    atomic_ulong total_accepts;
    atomic_ulong active_connections;
    atomic_ulong total_requests;
    atomic_ulong total_bytes_sent;
    atomic_ulong total_bytes_recv;

    /* Error stats */
    atomic_ulong connection_errors;
    atomic_ulong parse_errors;
    atomic_ulong timeout_errors;

    /* Performance */
    atomic_ulong request_duration_us_sum;
    atomic_ulong request_count;

} server_stats_t;
```

### /stats Endpoint

**HTTP GET /stats → JSON Response**

```json
{
  "uptime": 86400,
  "connections": {
    "active": 8540231,
    "total": 123456789,
    "errors": 12345
  },
  "requests": {
    "total": 987654321,
    "rate": 45231,
    "avg_latency_ms": 2.3
  },
  "workers": [
    {"id": 0, "connections": 133128, "requests": 2345678},
    {"id": 1, "connections": 142231, "requests": 2567890}
  ]
}
```

---

## ✅ Security Checklist

**Deployment:**
- [ ] Bindet auf spezifische IP (NIEMALS "*")
- [ ] Resource limits gesetzt (ulimit)
- [ ] Rate limiting aktiv
- [ ] Input validation implementiert
- [ ] Timeouts konfiguriert
- [ ] Logging auf ERROR level
- [ ] Statistics endpoint gesichert (nur localhost?)

**Code:**
- [ ] Keine Buffer Overflows
- [ ] Keine Use-After-Free
- [ ] Keine Memory Leaks
- [ ] Keine Integer Overflows
- [ ] Atomic operations für Stats

**Testing:**
- [ ] Fuzzing (AFL, libFuzzer)
- [ ] Stress Testing (slowhttptest)
- [ ] Load Testing (wrk, h2load)
- [ ] Memory Testing (Valgrind, ASan)

---

**ENDE SECURITY REQUIREMENTS**
