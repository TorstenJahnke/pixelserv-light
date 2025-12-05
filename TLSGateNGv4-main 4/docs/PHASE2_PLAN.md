# Phase 2: Multi-Threaded HTTP Server - Implementation Plan

## Ziele

**Performance:**
- 2-4 Worker Threads pro Prozess
- 40.000+ Connections pro Worker Thread
- epoll Event Loop (non-blocking I/O)
- Connection State Machine

**Architektur:**
```
Main Thread
    │
    ├─ Accept Loop (new connections)
    │
    └─ Worker Pool (2-4 threads)
        ├─ Worker 1: epoll loop → 40K connections
        ├─ Worker 2: epoll loop → 40K connections  
        ├─ Worker 3: epoll loop → 40K connections
        └─ Worker 4: epoll loop → 40K connections
```

## Komponenten

### 1. Connection Pool
```c
typedef enum {
    CONN_STATE_IDLE,        // Connection in pool, not used
    CONN_STATE_READING,     // Reading HTTP request
    CONN_STATE_PROCESSING,  // Processing request
    CONN_STATE_WRITING,     // Sending response
    CONN_STATE_KEEPALIVE,   // Keep-alive waiting
    CONN_STATE_CLOSING      // Closing connection
} connection_state_t;

typedef struct connection {
    int fd;
    connection_state_t state;
    time_t last_activity;
    
    // Request buffer
    char request_buf[16384];
    size_t request_len;
    
    // Response buffer
    char *response_buf;
    size_t response_len;
    size_t response_sent;
    
    // HTTP parsing
    char method[16];
    char path[1024];
    int keep_alive;
    
    struct connection *next;  // Free list
} connection_t;
```

### 2. Worker Thread
```c
typedef struct worker {
    pthread_t thread_id;
    int epoll_fd;
    int worker_id;
    
    // Statistics (atomic for lock-free)
    atomic_uint_fast64_t connections_handled;
    atomic_uint_fast64_t requests_handled;
    atomic_uint_fast64_t bytes_sent;
    
    // Connection pool
    connection_t *connections;     // Array of 50K connections
    connection_t *free_list;       // Free connections
    
} worker_t;
```

### 3. Main Thread
```c
- Accepts new connections
- Distributes to workers (round-robin)
- Monitors worker health
- Handles signals (SIGTERM, SIGUSR1 for stats)
```

## Implementation Steps

### Step 1: Connection Pool ✅ TODO
- Allocate fixed pool (50K connections)
- Free list management
- Connection state machine
- Timeout handling

### Step 2: Worker Thread ✅ TODO
- epoll setup
- Event loop
- Connection state transitions
- Non-blocking I/O

### Step 3: Main Accept Loop ✅ TODO
- Accept connections
- Round-robin distribution to workers
- Worker pipe for fd passing

### Step 4: Statistics ✅ TODO
- Atomic counters (lock-free)
- Per-worker stats
- Aggregated stats
- SIGUSR1 handler for stats dump

### Step 5: Testing ✅ TODO
- Load test with wrk/ab
- 10K concurrent connections
- 100K requests/sec target
- Memory leak check (valgrind)

## epoll Usage

```c
// Setup
int epoll_fd = epoll_create1(EPOLL_CLOEXEC);

// Add connection
struct epoll_event ev;
ev.events = EPOLLIN | EPOLLET;  // Edge-triggered
ev.data.ptr = connection;
epoll_ctl(epoll_fd, EPOLL_CTL_ADD, conn_fd, &ev);

// Event loop
struct epoll_event events[MAX_EVENTS];
while (running) {
    int n = epoll_wait(epoll_fd, events, MAX_EVENTS, timeout);
    for (int i = 0; i < n; i++) {
        connection_t *conn = events[i].data.ptr;
        
        if (events[i].events & EPOLLIN) {
            handle_read(conn);
        }
        if (events[i].events & EPOLLOUT) {
            handle_write(conn);
        }
    }
}
```

## Connection State Machine

```
     NEW
      │
      ├─> READING ─┬─> PROCESSING ─> WRITING ─┬─> KEEPALIVE ─> READING
      │            │                           │
      │            └─> ERROR ──────────────────┴─> CLOSING ─> IDLE
      │
      └─ Timeout ──────────────────────────────────> CLOSING
```

## Memory Budget (per process)

```
Connections:  50,000 × 20KB = 1,000 MB
Buffers:      50,000 × 32KB = 1,600 MB (request + response)
Worker Meta:  4 workers × 1MB = 4 MB
Total:        ~2.6 GB per process
```

With 256GB RAM: ~90 processes possible (keeping some headroom)

## Performance Targets

- **Connections:** 40K per worker × 4 workers = 160K per process
- **Requests/sec:** 50K per worker × 4 workers = 200K per process
- **Latency:** < 1ms for minimal responses
- **CPU:** ~80% utilization at peak

## Testing Commands

```bash
# Build
make clean && make

# Test single-threaded (baseline)
./build/http_responder 8080 127.0.0.1

# Test multi-threaded
./build/http_responder_mt 8080 127.0.0.1 -w 4

# Load test with ab
ab -n 100000 -c 1000 http://127.0.0.1:8080/

# Load test with wrk
wrk -t4 -c1000 -d30s http://127.0.0.1:8080/

# Memory check
valgrind --leak-check=full ./build/http_responder_mt 8080 127.0.0.1
```

## Next Phase Preview

**Phase 3: SSL/TLS Integration**
- OpenSSL context setup
- Certificate generation
- TLS handshake handling
- SNI extraction
