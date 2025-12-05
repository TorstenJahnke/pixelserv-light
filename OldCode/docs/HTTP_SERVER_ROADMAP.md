# TLSGate NX v2 - HTTP Server Development Roadmap

**Status:** Phase 1 COMPLETE ✅
**Datum:** 2025-11-06

---

## ✅ Phase 1: HTTP Foundation (DONE!)

**Ziel:** Funktionierender HTTP Server OHNE SSL

**Ergebnis:** `http_responder.c` (437 Zeilen)

**Features:**
- ✅ Plain HTTP Socket Server
- ✅ Request Parsing (method + path)
- ✅ html_index.h Response
- ✅ **favicon.ico Response (REAL 9,462 bytes from OldCodeBase)**
- ✅ **Other .ico files (httpnull_ico - 70 bytes)**
- ✅ MIME Type System (30+ types)
- ✅ Anti-AdBlock Randomisierung (JS/CSS)
- ✅ generate_204 Support
- ✅ **Security Headers (CORS, CSP neutralization)**
- ✅ **Specific IP binding (NEVER INADDR_ANY)**

**Tests:** Alle 7 Tests bestanden
```bash
./test_http_server.sh
✅ Root (/)
✅ /favicon.ico (Real 9,462 bytes)
✅ Other .ico files (httpnull_ico 70 bytes)
✅ JavaScript (randomized)
✅ CSS (randomized)
✅ generate_204
✅ MIME types + Security Headers (XML, JSON, PNG)
```

**Build & Run:**
```bash
gcc -o http_responder http_responder.c -O2
./http_responder 8080 127.0.0.1           # Test
./http_responder 80 178.162.203.162       # Production
```

---

## 🚧 Phase 2: Multi-Threaded HTTP Server (NEXT!)

**Ziel:** Scalable HTTP Server mit Worker Pool

**Aufgaben:**

### 2.1 - Worker Pool Architecture
```c
/* Pro Prozess: 2-4 Worker Threads */
typedef struct worker {
    int id;
    pthread_t thread;
    int epoll_fd;                  /* Event loop */
    connection_t *connections;     /* ~40K connections */
} worker_t;

typedef struct server {
    int listen_fd;
    worker_t *workers;             /* 2-4 workers */
    int num_workers;
} server_t;
```

**Implementation:**
- Datei: `http_server_multithread.c`
- Worker Pool: 2-4 Threads
- epoll event loop pro Worker
- Connection State Machine

### 2.2 - Connection State Machine
```c
typedef enum {
    CONN_STATE_ACCEPT,
    CONN_STATE_READ_REQUEST,
    CONN_STATE_PARSE_REQUEST,
    CONN_STATE_GENERATE_RESPONSE,
    CONN_STATE_SEND_RESPONSE,
    CONN_STATE_KEEPALIVE,
    CONN_STATE_CLOSE
} conn_state_t;

typedef struct connection {
    int fd;
    conn_state_t state;
    char read_buf[16KB];
    char write_buf[64KB];
    worker_t *worker;
} connection_t;
```

### 2.3 - epoll Integration
```c
/* Worker event loop */
void* worker_main(void *arg) {
    worker_t *worker = arg;

    while (running) {
        int n = epoll_wait(worker->epoll_fd, events, max_events, 100);

        for (int i = 0; i < n; i++) {
            connection_t *conn = events[i].data.ptr;
            handle_connection_event(conn, events[i].events);
        }
    }
}
```

**Ziel-Performance:**
- 40K connections pro Worker
- 2-4 Workers = 80-160K connections pro Prozess
- Non-blocking I/O
- State Machine statt Thread-per-Connection

---

## 🚧 Phase 3: Integration mit OldCodeBase (Woche 3-4)

**Ziel:** MIME Type System + Anti-AdBlock von OldCodeBase integrieren

### 3.1 - MIME Type System
```
OldCodeBase/extension_lookup.c → src/http/mime_types.c
OldCodeBase/extension_hash_table.h → src/http/mime_hash.h
```

**Features:**
- 265 Extensions (aus OldCodeBase)
- Binary Search Lookup (ultra-fast)
- Content-Type + Cache-Control

### 3.2 - Anti-AdBlock System
```
OldCodeBase/anti_adblock.c → src/anti_adblock/polymorphic.c
```

**Features:**
- Polymorphic JS/CSS responses
- Random headers
- Timing variation
- CORS randomization

### 3.3 - html_index + favicon from OldCodeBase
```
OldCodeBase/html_index.h → src/http/default_html.h
OldCodeBase/favicon.h → src/http/default_favicon.h
```

---

## 🚧 Phase 4: SSL/TLS Layer (Woche 5-6)

**Ziel:** SSL/TLS oben auf HTTP Server

**WICHTIG:** Erst wenn HTTP stabil läuft!

### 4.1 - OpenSSL Integration
```c
typedef struct connection {
    int fd;
    SSL *ssl;                      /* NULL = HTTP, non-NULL = HTTPS */
    conn_state_t state;
    ...
} connection_t;

/* Erweitere State Machine */
CONN_STATE_ACCEPT           → TCP accept()
CONN_STATE_TLS_HANDSHAKE    → SSL_accept() (NEW!)
CONN_STATE_SNI_EXTRACT      → SSL_get_servername() (NEW!)
CONN_STATE_READ_REQUEST     → SSL_read() oder recv()
```

### 4.2 - Certificate Generation (Client-Aware)
```
TLSGateNXv1_Crap/src/cert/ → src/cert/
```

**Features:**
- Client Detection (ECDSA vs RSA)
- On-demand Generation
- Certificate Cache
- Multi-Algorithm Support

### 4.3 - Keypool Integration
```
TLSGateNXv1_Crap/src/crypto/ → src/crypto/
```

**Features:**
- Shared Memory Keypool
- 1M keys (RSA + ECDSA)
- Prime Pool für RSA acceleration

---

## 🚧 Phase 5: Production Hardening (Woche 7-8)

### 5.1 - Error Handling
- Connection timeout (5 min)
- Read timeout (30 sec)
- Write timeout (30 sec)
- Graceful shutdown

### 5.2 - Resource Limits
- Max connections per worker
- Memory limits
- File descriptor limits
- Rate limiting (per-IP)

### 5.3 - Logging & Statistics
- Request counters (atomic)
- Error logging (syslog)
- Performance metrics
- /stats endpoint

### 5.4 - Testing
- Unit tests
- Integration tests
- Load tests (wrk, h2load)
- Stress tests

---

## 📈 Performance Targets

**Pro Prozess (2-4 Workers):**
```
Connections: 80-160K
Requests/sec: 20-40K (HTTP)
Requests/sec: 10-20K (HTTPS)
Latency p99: <10ms
Memory: ~3GB
```

**60 Prozesse (1 Server):**
```
Total Connections: 10M
Total Requests/sec: 200K-400K (HTTP)
Total Requests/sec: 100K-200K (HTTPS)
Total Memory: 180GB (von 256GB)
CPU Usage: 70-90%
```

---

## 🎯 Milestones

**✅ Milestone 1: HTTP Foundation**
- [x] http_server_simple.c
- [x] MIME types
- [x] Anti-AdBlock basics
- [x] Tests passing

**🚧 Milestone 2: Multi-Threading**
- [ ] Worker Pool (2-4 workers)
- [ ] epoll event loop
- [ ] Connection State Machine
- [ ] 40K connections/worker

**🚧 Milestone 3: Production HTTP**
- [ ] OldCodeBase MIME integration
- [ ] Full Anti-AdBlock system
- [ ] Error handling
- [ ] Statistics

**🚧 Milestone 4: SSL/TLS**
- [ ] OpenSSL integration
- [ ] Certificate Generation
- [ ] Keypool
- [ ] Client-Aware selection

**🚧 Milestone 5: Production Ready**
- [ ] Resource limits
- [ ] Logging
- [ ] Tests (unit + integration)
- [ ] Performance benchmarks

---

## 📅 Timeline

**Woche 1:** ✅ HTTP Foundation (DONE!)
**Woche 2:** Multi-Threading + epoll
**Woche 3:** OldCodeBase Integration
**Woche 4:** Testing & Hardening
**Woche 5-6:** SSL/TLS Layer
**Woche 7-8:** Production Ready

**Total:** 8 Wochen bis Production

---

## 🔥 NÄCHSTER SCHRITT

**JETZT:** Phase 2.1 - Worker Pool Architecture

**Datei:** `http_server_multithread.c`

**Aufgaben:**
1. Worker Pool erstellen (2-4 threads)
2. epoll setup pro Worker
3. Accept Loop → Worker distribution
4. Connection State Machine (basic)
5. Tests mit 1000+ concurrent connections

**Ziel:** Skalierbar HTTP Server der >1000 concurrent connections handhabt

---

**Soll ich mit Phase 2.1 beginnen?**
