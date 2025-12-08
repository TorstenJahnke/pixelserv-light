/*
* pixelserv.c - Memory-optimized version for higher concurrent connections
* 
* Key optimizations over original:
* - Connection object pooling
* - Lock-free statistics with atomic operations
* - Optimized socket options for high throughput
* - No logging overhead
*/

#include <fcntl.h>
#include <pthread.h>
#ifdef DROP_ROOT
#include <pwd.h>
#endif
#ifdef TEST
#include <arpa/inet.h>
#endif
#ifdef linux
#include <linux/version.h>
#endif
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <stdatomic.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>

#include "certs/certs.h"
#include "net/io_engine.h"
#include "core/logger.h"
#include "net/socket_handler.h"
#include "core/util.h"

#include "content/extension_lookup.h"
#include "content/anti_adblock.h"
#include "net/socket_handler_extended.h"
#include "index/index_master.h"
#include "index/index_protocol.h"

#if defined(__GLIBC__) && !defined(__UCLIBC__)
#  include <malloc.h>
#endif

#ifndef SO_BINDTODEVICE
#  define SO_BINDTODEVICE IP_RECVIF
#endif

#define PAGE_SIZE 4096
#define THREAD_STACK_SIZE  9*PAGE_SIZE
#define TCP_FASTOPEN_QLEN  25

// Connection pool configuration for high-performance operation
#define CONNECTION_POOL_SIZE 50000

typedef struct conn_node {
    conn_tlstor_struct conn_data;
    struct conn_node *next;
} conn_node_t;

typedef struct {
    conn_node_t *nodes;  // Actual storage
    conn_node_t *free_list;
    pthread_spinlock_t lock;
    atomic_int allocated;
    atomic_int peak_allocated;
} conn_pool_t;

// Global optimized state
static struct {
    conn_pool_t connections;
    
    // Lock-free statistics
    atomic_ulong total_requests;
    atomic_ulong active_connections;
    atomic_ulong conn_cache_hits;
    
    int initialized;
} perf_state = {0};

const char *tls_pem = DEFAULT_PEM_PATH;
int tls_ports[MAX_TLS_PORTS + 1] = {0};
int num_tls_ports = 0;
int auto_ports[MAX_TLS_PORTS + 1] = {0};  /* Auto-detect HTTP/HTTPS ports */
int num_auto_ports = 0;
int admin_port = 0;
struct Global *g;
cert_tlstor_t cert_tlstor;
pthread_t certgen_thread;

static int init_conn_pool(conn_pool_t *pool, size_t count) {
    pool->free_list = NULL;
    pthread_spin_init(&pool->lock, PTHREAD_PROCESS_PRIVATE);
    atomic_store(&pool->allocated, 0);
    atomic_store(&pool->peak_allocated, 0);
    
    // Allocate the actual storage
    pool->nodes = aligned_alloc(64, count * sizeof(conn_node_t));
    if (!pool->nodes) return -1;
    
    for (size_t i = 0; i < count; i++) {
        conn_node_t *node = &pool->nodes[i];
        memset(&node->conn_data, 0, sizeof(node->conn_data));
        node->conn_data.tlsext_cb_arg = &node->conn_data.v;
        node->next = pool->free_list;
        pool->free_list = node;
    }
    
    return 0;
}

static conn_tlstor_struct *acquire_connection(void) {
    conn_tlstor_struct *result = NULL;
    
    pthread_spin_lock(&perf_state.connections.lock);
    if (perf_state.connections.free_list) {
        conn_node_t *node = perf_state.connections.free_list;
        perf_state.connections.free_list = node->next;
        result = &node->conn_data;
        
        // Reset connection state
        memset(result, 0, sizeof(*result));
        result->tlsext_cb_arg = &result->v;
        
        int current = atomic_fetch_add(&perf_state.connections.allocated, 1) + 1;
        int peak = atomic_load(&perf_state.connections.peak_allocated);
        if (current > peak) {
            atomic_compare_exchange_weak(&perf_state.connections.peak_allocated, &peak, current);
        }
        
        atomic_fetch_add(&perf_state.conn_cache_hits, 1);
        atomic_fetch_add(&perf_state.active_connections, 1);
    }
    pthread_spin_unlock(&perf_state.connections.lock);
    
    if (!result) {
        // Fallback to malloc
        result = calloc(1, sizeof(conn_tlstor_struct));
        if (result) {
            result->tlsext_cb_arg = &result->v;
            atomic_fetch_add(&perf_state.active_connections, 1);
        }
    }
    
    return result;
}

static void release_connection(conn_tlstor_struct *conn) {
    if (!conn) return;
    
    // Check if connection belongs to pool by comparing with pool bounds
    conn_node_t *node = (conn_node_t*)((char*)conn - offsetof(conn_node_t, conn_data));
    
    pthread_spin_lock(&perf_state.connections.lock);
    if (perf_state.connections.nodes && 
        node >= perf_state.connections.nodes && 
        node < perf_state.connections.nodes + CONNECTION_POOL_SIZE) {
        node->next = perf_state.connections.free_list;
        perf_state.connections.free_list = node;
        atomic_fetch_sub(&perf_state.connections.allocated, 1);
    } else {
        // Was malloc'd
        free(conn);
    }
    pthread_spin_unlock(&perf_state.connections.lock);
    
    atomic_fetch_sub(&perf_state.active_connections, 1);
}

/* Detect if connection is TLS by peeking at first byte
 * TLS handshake starts with 0x16 (ContentType: Handshake)
 * SSLv2 starts with 0x80 (but deprecated)
 * HTTP starts with ASCII letters (GET, POST, HEAD, etc.)
 */
static int detect_tls_connection(int fd) {
    unsigned char peek_buf[1];
    ssize_t n = recv(fd, peek_buf, 1, MSG_PEEK | MSG_DONTWAIT);
    if (n <= 0) {
        return 0;  /* Error or no data - assume HTTP */
    }
    /* TLS record starts with ContentType byte:
     * 0x14 = ChangeCipherSpec, 0x15 = Alert, 0x16 = Handshake, 0x17 = ApplicationData
     * Client Hello is always Handshake (0x16)
     * SSLv2 ClientHello starts with 0x80 (length byte with high bit set)
     */
    return (peek_buf[0] == 0x16 || peek_buf[0] == 0x80);
}

// Enhanced conn_handler with memory pools
void* optimized_conn_handler(void *ptr) {
    if (!g) {
        return NULL;
    }
    
    atomic_fetch_add(&perf_state.total_requests, 1);
    
    // IMMER Extended Features verwenden
    return extended_conn_handler(ptr);
    
    // Connection is automatically released in release_connection()
    // which is called from the original conn_handler cleanup
}

void signal_handler(int sig)
{
  if (sig != SIGTERM && sig != SIGUSR1
#ifdef DEBUG
   && sig != SIGUSR2
#endif
  ) {
    return;
  }

#ifdef DEBUG
  if (sig == SIGUSR2) {
  } else {
#endif
    if (sig == SIGTERM) {
      signal(SIGTERM, SIG_IGN);
    }

    conn_stor_flush();

socket_handler_extended_cleanup();
anti_adblock_cleanup();
extension_lookup_cleanup();
    
    if (unlink(pixel_cert_pipe) == 0) {
    }

#if defined(__GLIBC__) && !defined(__UCLIBC__)
    malloc_trim(0);
#endif

    char* stats_string = get_stats(0, 0);
    if (stats_string) {
        free(stats_string);
    }

    sslctx_tbl_save(tls_pem);

    if (sig == SIGTERM) {
      exit(EXIT_SUCCESS);
    }
#ifdef DEBUG
  }
#endif
}

int main (int argc, char* argv[])
{
  int sockfd = 0;
  int new_fd = 0;
  struct sockaddr_storage their_addr;
  socklen_t sin_size;
  char* version_string = NULL;
  time_t select_timeout = DEFAULT_TIMEOUT;
  time_t http_keepalive = DEFAULT_KEEPALIVE;
  int rv = 0;
  char* ip_addr = DEFAULT_IP;
  int use_ip = 0;
  struct addrinfo hints, *servinfo = NULL;
  int error = 0;
  int pipefd[2];
  response_struct pipedata = { 0 };
  char* ports[MAX_PORTS + 1];
  char *port = NULL;
  int sockfds[MAX_PORTS] = {0};
  int num_ports = 0;
  int i;
  io_engine_t *io_engine = NULL;
  io_result_t io_results[MAX_PORTS + 1];  /* +1 for pipe */
#ifdef IF_MODE
  char *ifname = "";
  int use_if = 0;
#endif
#ifdef DROP_ROOT
  char *user = DEFAULT_USER;
  struct passwd *pw = 0;
#endif
  char* stats_url = DEFAULT_STATS_URL;
  char* stats_text_url = DEFAULT_STATS_TEXT_URL;
  int do_204 = 1;
#ifndef TEST
  int do_foreground = 0;
#endif
  int do_redirect = 0;
  int do_benchmark = 0;
  char *bm_cert = NULL;
#ifdef DEBUG
  int warning_time = 0;
#endif
  int max_num_threads = DEFAULT_THREAD_MAX;
  int cert_cache_size = DEFAULT_CERT_CACHE_SIZE;

  /* Index Master/Worker mode */
  int do_index_master = 0;
  char *master_socket = NULL;

#if !OPENSSL_API_1_1
  SSL_library_init();
  SSL_load_error_strings();
#else
  OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS | OPENSSL_INIT_LOAD_CRYPTO_STRINGS, NULL);
#endif

  // Initialize connection pool for high performance
  if (init_conn_pool(&perf_state.connections, CONNECTION_POOL_SIZE) < 0) {
    exit(EXIT_FAILURE);
  }
  perf_state.initialized = 1;

extension_lookup_init();
anti_adblock_init();
socket_handler_extended_init();

#if defined(__GLIBC__) && !defined(__UCLIBC__)
  mallopt(M_ARENA_MAX, 4); // Optimize for multi-threading
  mallopt(M_MMAP_THRESHOLD, 64 * 1024);
#endif

  // Set resource limits for high connection count
  struct rlimit rl;
  rl.rlim_cur = rl.rlim_max = max_num_threads * 2 + 1000;
  setrlimit(RLIMIT_NOFILE, &rl);
  
  rl.rlim_cur = rl.rlim_max = THREAD_STACK_SIZE * 2;
  setrlimit(RLIMIT_STACK, &rl);

  // Auto-detect index master mode from binary name
  {
    const char *binary_name = strrchr(argv[0], '/');
    binary_name = binary_name ? binary_name + 1 : argv[0];
    if (strstr(binary_name, "index") != NULL) {
      do_index_master = 1;
    }
  }

  // Command line parsing
  for (i = 1; i < argc && error == 0; ++i) {
    if (argv[i][0] == '-') {
      switch (argv[i][1]) {
        case '2': do_204 = 0; continue;
        case 'B':
          if ((i + 1) == argc || argv[i + 1][0] == '-') {
            do_benchmark = 1;
            bm_cert = NULL;
            continue;
          }
          break;
#ifndef TEST
        case 'f': do_foreground = 1; continue;
#endif
        case 'M': do_index_master = 1; continue;  /* Index master mode */
        case 'r': continue;
        case 'R': do_redirect = 1; continue;
        case 'l':
          if ((i + 1) == argc || argv[i + 1][0] == '-') {
            log_set_verb(LGG_INFO);
            continue;
          }
      }
      
      if ((i + 1) < argc) {
        switch (argv[i++][1]) {
          case 'B':
            do_benchmark = 1;
            if (argv[i][0] == '-') {
              error = 1;
            } else {
              bm_cert = argv[i];
            }
            continue;
          case 'c':
            errno = 0;
            cert_cache_size = strtol(argv[i], NULL, 10);
            if (errno || cert_cache_size <= 0) {
              error = 1;
            }
            continue;
          case 'l':
            if ((logger_level)atoi(argv[i]) > LGG_DEBUG || atoi(argv[i]) < 0) {
              error = 1;
            } else {
              log_set_verb((logger_level)atoi(argv[i]));
            }
            continue;
#ifdef IF_MODE
          case 'n':
            ifname = argv[i];
            use_if = 1;
            continue;
#endif
          case 'o':
            continue;
          case 'O':
            errno = 0;
            http_keepalive = strtol(argv[i], NULL, 10);
            if (errno || http_keepalive <= 0) {
              error = 1;
            }
            continue;
          case 'A':
            if (num_tls_ports < MAX_TLS_PORTS) {
              admin_port = atoi(argv[i]);
            } else {
              error = 1;
            }
            continue;
          case 'a':  /* Auto-detect HTTP/HTTPS port */
            if (num_auto_ports < MAX_TLS_PORTS) {
              auto_ports[num_auto_ports++] = atoi(argv[i]);
            } else {
              error = 1;
            }
            __attribute__((fallthrough));
          case 'k':
            if (argv[i - 1][1] == 'k' && num_tls_ports < MAX_TLS_PORTS) {
              tls_ports[num_tls_ports++] = atoi(argv[i]);
            }
            __attribute__((fallthrough));
          case 'p':
            if (num_ports < MAX_PORTS) {
              ports[num_ports++] = argv[i];
            } else {
              error = 1;
            }
            continue;
          case 'H':  /* External HTML file */
            if (load_external_html(argv[i]) < 0) {
              error = 1;
            }
            continue;
          case 's': stats_url = argv[i]; continue;
          case 't': stats_text_url = argv[i]; continue;
          case 'T':
            errno = 0;
            max_num_threads = strtol(argv[i], NULL, 10);
            if (errno || max_num_threads <= 0) {
              error = 1;
            }
            continue;
#ifdef DROP_ROOT
          case 'u': user = argv[i]; continue;
#endif
#ifdef DEBUG
          case 'w':
            errno = 0;
            warning_time = strtol(argv[i], NULL, 10);
            if (errno || warning_time <= 0) {
              error = 1;
            }
            continue;
#endif
          case 'z':
            tls_pem = argv[i];
            continue;
          case 'm':
            master_socket = argv[i];  /* Connect to index master */
            continue;
          default: error = 1; continue;
        }
      } else {
        error = 1;
      }
    } else if (use_ip == 0) {
      ip_addr = argv[i];
      use_ip = 1;
    } else {
      error = 1;
    }
  }

  if (error) {
    print_usage();
    exit(EXIT_FAILURE);
  }

#ifndef TEST
  if (!do_foreground && !do_benchmark && daemon(0, 0)) {
    exit(EXIT_FAILURE);
  }
#endif

  openlog("pixelserv-tls",
#ifdef DEBUG
    LOG_PERROR |
#endif
    LOG_PID, LOG_DAEMON);

  version_string = get_version(argc, argv);
  if (version_string) {
    free(version_string);
  } else {
    exit(EXIT_FAILURE);
  }

  generate_random_pipe_path(pixel_cert_pipe, sizeof(pixel_cert_pipe));
  if (mkfifo(pixel_cert_pipe, 0600) < 0 && errno != EEXIST) {
    exit(EXIT_FAILURE);
  }

#ifdef DROP_ROOT
  pw = getpwnam(user);
  if (!pw) {
    exit(EXIT_FAILURE);
  }
  if (chown(pixel_cert_pipe, pw->pw_uid, pw->pw_gid) < 0) {
    exit(EXIT_FAILURE);
  }
#endif

  /* Index Master mode: run as dedicated index server (minimal init) */
  if (do_index_master) {
    char socket_path[256];
    if (master_socket) {
      strncpy(socket_path, master_socket, sizeof(socket_path) - 1);
    } else {
      snprintf(socket_path, sizeof(socket_path), "%s/pixelserv-index.sock", tls_pem);
    }

    printf("Starting Index Master on %s\n", socket_path);
    printf("Workers should connect with: -m %s\n", socket_path);

    if (index_master_init(socket_path, tls_pem) < 0) {
      fprintf(stderr, "Failed to initialize index master\n");
      exit(EXIT_FAILURE);
    }

    /* Run the index master event loop (blocking) */
    index_master_run();
    index_master_shutdown();
    exit(EXIT_SUCCESS);
  }

  /* Normal/Worker mode: full initialization */
  ssl_init_locks();
  cert_tlstor_init(tls_pem, &cert_tlstor);
  sslctx_tbl_init(cert_cache_size);
  conn_stor_init(max_num_threads);

  sslctx_tbl_load(tls_pem, cert_tlstor.cachain);
  SSL_CTX *sslctx = create_default_sslctx(tls_pem);
  if (!sslctx) {
    exit(EXIT_FAILURE);
  }

  /* Worker mode: connect to index master */
  if (master_socket) {
    printf("Connecting to Index Master at %s\n", master_socket);
    if (cert_enable_worker_mode(master_socket) < 0) {
      fprintf(stderr, "Failed to connect to index master at %s\n", master_socket);
      fprintf(stderr, "Make sure index master is running with: pixelserv-tls -M -z %s\n", tls_pem);
      exit(EXIT_FAILURE);
    }
  }

  if (do_benchmark) {
    run_benchmark(&cert_tlstor, bm_cert);
    goto quit_main;
  } else {
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setstacksize(&attr, THREAD_STACK_SIZE);
    if (pthread_create(&certgen_thread, &attr, cert_generator, (void*)&cert_tlstor) != 0) {
      exit(EXIT_FAILURE);
    }
    pthread_attr_destroy(&attr);
  }

  memset(&hints, 0, sizeof hints);
#if defined(IPV4_ONLY)
  hints.ai_family = AF_INET;      /* IPv4 only */
#elif defined(IPV6_ONLY)
  hints.ai_family = AF_INET6;     /* IPv6 only */
#else
  hints.ai_family = AF_UNSPEC;    /* Both IPv4 and IPv6 */
#endif
  hints.ai_socktype = SOCK_STREAM;
  if (!use_ip) {
    hints.ai_flags = AI_PASSIVE;
  }

  if ((!admin_port && !num_ports) || (admin_port && num_ports == 1)) {
    tls_ports[num_tls_ports++] = atoi(SECOND_PORT);
    ports[num_ports++] = SECOND_PORT;
    ports[num_ports++] = DEFAULT_PORT;
  } else if ((!admin_port && !num_tls_ports) || (admin_port && num_tls_ports == 1)) {
    tls_ports[num_tls_ports++] = atoi(SECOND_PORT);
    ports[num_ports++] = SECOND_PORT;
  } else if (num_ports == num_tls_ports) {
    ports[num_ports++] = DEFAULT_PORT;
  }

  /* Add default auto-detect port (8080) if none specified */
  if (num_auto_ports == 0 && num_ports < MAX_PORTS) {
    auto_ports[num_auto_ports++] = 8080;
    ports[num_ports++] = "8080";
  }

  for (i = 0; i < num_ports; i++) {
    port = ports[i];

    rv = getaddrinfo(use_ip ? ip_addr : NULL, port, &hints, &servinfo);
    if (rv) {
      exit(EXIT_FAILURE);
    }

    sockfd = socket(servinfo->ai_family, servinfo->ai_socktype, servinfo->ai_protocol);
    if (sockfd < 1) {
      freeaddrinfo(servinfo);
      exit(EXIT_FAILURE);
    }

    // Optimized socket options for high throughput
    int opt = 1;
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
#ifdef SO_REUSEPORT
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));
#endif
    setsockopt(sockfd, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt));
    
    // Increase socket buffers for high throughput
    int buf_size = 256 * 1024;
    setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &buf_size, sizeof(buf_size));
    setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, &buf_size, sizeof(buf_size));

    if (servinfo->ai_family == AF_INET6) {
#if defined(IPV6_ONLY)
        /* IPv6-only mode: enable V6ONLY for pure IPv6 */
        int v6only = 1;
        setsockopt(sockfd, IPPROTO_IPV6, IPV6_V6ONLY, &v6only, sizeof(v6only));
#else
        /* Dual-stack mode: allow IPv4 connections on IPv6 socket */
        int off = 0;
        setsockopt(sockfd, IPPROTO_IPV6, IPV6_V6ONLY, &off, sizeof(off));
#endif
    }

#ifdef IF_MODE
    if (use_if && setsockopt(sockfd, SOL_SOCKET, SO_BINDTODEVICE, ifname, strlen(ifname)) < 0) {
      close(sockfd);
      freeaddrinfo(servinfo);
      exit(EXIT_FAILURE);
    }
#endif

#ifdef linux
#  if LINUX_VERSION_CODE >= KERNEL_VERSION(3,7,0) || defined(TCP_FASTOPEN)
    if (setsockopt(sockfd, IPPROTO_TCP, TCP_FASTOPEN, &(int){ TCP_FASTOPEN_QLEN }, sizeof(int)) < 0) {
    }
#  endif
#endif

    if (bind(sockfd, servinfo->ai_addr, servinfo->ai_addrlen) < 0 ||
        listen(sockfd, SOMAXCONN) < 0 ||
        fcntl(sockfd, F_SETFL, fcntl(sockfd, F_GETFL) | O_NONBLOCK) < 0) {
      close(sockfd);
      freeaddrinfo(servinfo);
      exit(EXIT_FAILURE);
    }

    sockfds[i] = sockfd;

    freeaddrinfo(servinfo);
    servinfo = NULL;
  }

  // Signal handling
  {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);
    
    if (sigaction(SIGTERM, &sa, NULL)) {
      exit(EXIT_FAILURE);
    }
    
    if (signal(SIGCHLD, SIG_IGN) == SIG_ERR) {
    }
    
    sa.sa_flags = SA_RESTART;
    if (sigaction(SIGUSR1, &sa, NULL)) {
      exit(EXIT_FAILURE);
    }

#if defined(__GLIBC__) && defined(BACKTRACE)
    sa.sa_handler = print_trace;
    sigaction(SIGSEGV, &sa, NULL);
    sigaction(SIGABRT, &sa, NULL);
    sigaction(SIGILL, &sa, NULL);
    sigaction(SIGFPE, &sa, NULL);
    sigaction(SIGBUS, &sa, NULL);
#endif

#ifdef DEBUG
    sa.sa_flags = SA_RESTART;
    if (sigaction(SIGUSR2, &sa, NULL)) {
      exit(EXIT_FAILURE);
    }
#endif
  }

#ifdef DROP_ROOT
  if (pw && setuid(pw->pw_uid)) {
  }
#endif

  signal(SIGPIPE, SIG_IGN);

  if (pipe(pipefd) == -1) {
    exit(EXIT_FAILURE);
  }

  if (fcntl(pipefd[0], F_SETFL, fcntl(pipefd[0], F_GETFL) | O_NONBLOCK) == -1) {
    exit(EXIT_FAILURE);
  }

  /* Create io_engine (uses epoll on Linux, kqueue on BSD) */
  io_engine = io_engine_create(MAX_PORTS + 1, MAX_PORTS + 1);
  if (!io_engine) {
    exit(EXIT_FAILURE);
  }

  /* Add all listening sockets to io_engine */
  for (i = 0; i < num_ports; i++) {
    io_event_t ev = { .fd = sockfds[i], .events = IO_IN, .user_data = (uint64_t)i };
    if (io_engine_add(io_engine, &ev) < 0) {
      exit(EXIT_FAILURE);
    }
  }

  /* Add pipe for stats (user_data = MAX_PORTS to distinguish from sockets) */
  {
    io_event_t ev = { .fd = pipefd[0], .events = IO_IN, .user_data = (uint64_t)MAX_PORTS };
    if (io_engine_add(io_engine, &ev) < 0) {
      exit(EXIT_FAILURE);
    }
  }

  sin_size = sizeof their_addr;

  struct Global _g = {
        argc,
        argv,
        select_timeout,
        http_keepalive,
        pipefd[1],
        stats_url,
        stats_text_url,
        do_204,
        do_redirect,
#ifdef DEBUG
        warning_time,
#endif
        tls_pem,
  };
  g = &_g;

  /* Main accept loop using io_engine (epoll/io_uring/kqueue) */
  while(1) {
    int nev = io_engine_wait(io_engine, io_results, -1);
    if (nev < 0) {
      if (errno == EINTR) continue;
      exit(EXIT_FAILURE);
    }

    for (int ev_idx = 0; ev_idx < nev; ev_idx++) {
      uint64_t ev_id = io_results[ev_idx].user_data;

      /* Handle pipe events (stats) */
      if (ev_id == MAX_PORTS) {
        rv = read(pipefd[0], &pipedata, sizeof(pipedata));
        if (rv == sizeof(pipedata)) {
          switch (pipedata.status) {
            case FAIL_GENERAL:   ++ers; break;
            case FAIL_TIMEOUT:   ++tmo; break;
            case FAIL_CLOSED:    ++cls; break;
            case FAIL_REPLY:     ++cly; break;
            case SEND_GIF:       ++gif; break;
            case SEND_TXT:       ++txt; break;
            case SEND_JPG:       ++jpg; break;
            case SEND_PNG:       ++png; break;
            case SEND_SWF:       ++swf; break;
            case SEND_ICO:       ++ico; break;
            case SEND_BAD:       ++bad; break;
            case SEND_STATS:     ++sta; break;
            case SEND_STATSTEXT: ++stt; break;
            case SEND_204:       ++noc; break;
            case SEND_REDIRECT:  ++rdr; break;
            case SEND_NO_EXT:    ++nfe; break;
            case SEND_UNK_EXT:   ++ufe; break;
            case SEND_NO_URL:    ++nou; break;
            case SEND_BAD_PATH:  ++pth; break;
            case SEND_POST:      ++pst; break;
            case SEND_HEAD:      ++hed; break;
            case SEND_OPTIONS:   ++opt; break;
            case ACTION_LOG_VERB:  log_set_verb(pipedata.verb); break;
            case ACTION_DEC_KCC: --kcc; break;
            default: ;
          }

          switch (pipedata.ssl) {
            case SSL_HIT_RTT0:   ++zrt;
                                 __attribute__((fallthrough));
            case SSL_HIT:        ++slh; break;
            case SSL_HIT_CLS:    ++slc; break;
            default:             ;
          }

          if (pipedata.ssl == SSL_HIT ||
              pipedata.ssl == SSL_HIT_RTT0 ||
              pipedata.ssl == SSL_HIT_CLS) {
            switch (pipedata.ssl_ver) {
#ifdef TLS1_3_VERSION
              case TLS1_3_VERSION: ++v13; break;
#endif
              case TLS1_2_VERSION: ++v12; break;
              case TLS1_VERSION:   ++v10; break;
              default:             ;
            }
          }

          if (pipedata.status < ACTION_LOG_VERB) {
            count++;
            if (pipedata.rx_total > 0) {
              static float favg = 0.0;
              static int favg_cnt = 0;
              favg = ema(favg, pipedata.rx_total, &favg_cnt);
              avg = favg + 0.5;
              if (pipedata.rx_total > rmx)
                rmx = pipedata.rx_total;
            }

            if (pipedata.status != FAIL_TIMEOUT && pipedata.rx_total > 0) {
              static float ftav = 0.0;
              static int ftav_cnt = 0;
              ftav = ema(ftav, pipedata.run_time, &ftav_cnt);
              tav = ftav + 0.5;
              if (pipedata.run_time + 0.5 > tmx)
                tmx = (pipedata.run_time + 0.5);
            }
          } else if (pipedata.status == ACTION_DEC_KCC) {
            static int kvg_cnt = 0;
            kvg = ema(kvg, pipedata.krq, &kvg_cnt);
            if (pipedata.krq > krq)
              krq = pipedata.krq;
          }
        }
        continue;
      }

      /* Handle socket events (new connections) */
      sockfd = sockfds[ev_id];

    struct timespec init_time = {0, 0};
    get_time(&init_time);
    new_fd = accept(sockfd, (struct sockaddr *) &their_addr, &sin_size);
    if (new_fd < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            cls++;
        }
        continue;
    }
    
    if (kcc >= max_num_threads) {
        clt++;
        shutdown(new_fd, SHUT_RDWR);
        close(new_fd);
        continue;
    }

    // Use memory pool for connection allocation
    conn_tlstor_struct *conn_tlstor = acquire_connection();
    if (conn_tlstor == NULL) {
      shutdown(new_fd, SHUT_RDWR);
      close(new_fd);
      continue;
    }

    int flags;
    if ((flags = fcntl(new_fd, F_GETFL, 0)) < 0 || 
        fcntl(new_fd, F_SETFL, flags & (~O_NONBLOCK)) < 0) {
    }

    if (setsockopt(new_fd, IPPROTO_TCP, TCP_NODELAY, &(int){ 1 }, sizeof(int)) ||
        setsockopt(new_fd, SOL_SOCKET, SO_RCVTIMEO, 
                  (char*)&(struct timeval){ 0, 150000 }, sizeof(struct timeval))) {
    }

    conn_tlstor->new_fd = new_fd;
    conn_tlstor->ssl = NULL;
    conn_tlstor->allow_admin = (!admin_port) ? 1 : 0;

    char *server_ip = conn_tlstor->tlsext_cb_arg->server_ip;
    int ssl_port = is_ssl_conn(new_fd, server_ip, INET6_ADDRSTRLEN, tls_ports, num_tls_ports);

    /* Check auto-detect ports if not already a known TLS port */
    if (!ssl_port) {
        int auto_port = is_ssl_conn(new_fd, NULL, 0, auto_ports, num_auto_ports);
        if (auto_port && detect_tls_connection(new_fd)) {
            ssl_port = auto_port;  /* TLS detected on auto port */
        }
    }

    if (ssl_port) {
      int ssl_attempt = 5;
      int sslerr = SSL_ERROR_NONE;
      char ip_buf[NI_MAXHOST], port_buf[NI_MAXSERV];

      tlsext_cb_arg_struct *t = conn_tlstor->tlsext_cb_arg;
      SSL *ssl = NULL;
      t->tls_pem = tls_pem;
      t->cachain = cert_tlstor.cachain;
      t->status = SSL_UNKNOWN;
      t->sslctx_idx = -1;

      ssl = SSL_new(sslctx);
      if (!ssl) {
        goto cleanup_connection;
      }
      
      SSL_set_fd(ssl, new_fd);
      conn_tlstor->ssl = ssl;
      
      if (ssl_port == admin_port)
        conn_tlstor->allow_admin = 1;

#ifdef TLS1_3_VERSION
      SSL_CTX_set_client_hello_cb(sslctx, tls_clienthello_cb, t);
      conn_tlstor->early_data = read_tls_early_data(ssl, &sslerr);
      if (conn_tlstor->early_data) {
        conn_tlstor->init_time = elapsed_time_msec(init_time);
        goto start_service_thread;
      }

      if (sslerr != SSL_ERROR_NONE)
        goto skip_ssl_accept;
#else
      SSL_CTX_set_tlsext_servername_arg(sslctx, t);
      conn_tlstor->early_data = NULL;
#endif
      conn_tlstor->init_time = elapsed_time_msec(init_time);

redo_ssl_accept:
      errno = 0;
      ERR_clear_error();
      int sslret = SSL_accept(ssl);
      if (sslret == 1)
        goto start_service_thread;
      sslerr = SSL_get_error(ssl, sslret);

#ifdef TLS1_3_VERSION
skip_ssl_accept:
#endif

      if (log_get_verb() >= LGG_WARNING && 
          getnameinfo((struct sockaddr *)&their_addr, sin_size,
                     ip_buf, sizeof ip_buf, port_buf, sizeof port_buf, 
                     NI_NUMERICHOST | NI_NUMERICSERV) != 0) {
        ip_buf[0] = '\0';
        port_buf[0] = '\0';
      }

      switch(sslerr) {
        case SSL_ERROR_WANT_READ:
          ssl_attempt--;
          if (ssl_attempt > 0) {
            get_time(&init_time);
            goto redo_ssl_accept;
          }
          break;
        case SSL_ERROR_SSL:
          switch(ERR_GET_REASON(ERR_peek_last_error())) {
              case SSL_R_SSLV3_ALERT_BAD_CERTIFICATE:
                  ucb++;
                  break;
              case SSL_R_TLSV1_ALERT_UNKNOWN_CA:
                  uca++;
                  break;
              case SSL_R_SSLV3_ALERT_CERTIFICATE_UNKNOWN:
                  uce++;
                  break;
              case SSL_R_PARSE_TLSEXT:
                  if (t->status == SSL_MISS)
                    break;
              default:
                  ;
          }
          break;
        case SSL_ERROR_SYSCALL:
            if (t->status == SSL_MISS)
              break;

            if (errno == 0 || errno == 104) {
              char m[2];
              int rv = recv(new_fd, m, 2, MSG_PEEK);
              if (rv == 0) {
                ush++;
                break;
              }
            }
            break;
        default:
          ;
      }
      
      count++;
      switch(t->status) {
        case SSL_ERR:        ++sle; break;
        case SSL_MISS:       ++slm; break;
        case SSL_HIT:
        case SSL_UNKNOWN:    ++slu; break;
        default:             ;
      }

cleanup_connection:
      if (ssl) {
        SSL_set_shutdown(ssl, SSL_SENT_SHUTDOWN | SSL_RECEIVED_SHUTDOWN);
        SSL_free(ssl);
        ssl = NULL;
        conn_tlstor->ssl = NULL;
      }
      shutdown(new_fd, SHUT_RDWR);
      close(new_fd);
      release_connection(conn_tlstor); // Return to pool
      continue;
    }

start_service_thread:
    conn_tlstor->init_time += elapsed_time_msec(init_time);
    pthread_t conn_thread;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    pthread_attr_setstacksize(&attr, THREAD_STACK_SIZE);
    
    // Use optimized handler
    int err = pthread_create(&conn_thread, &attr, optimized_conn_handler, (void*)conn_tlstor);
    if (err) {
      if (conn_tlstor->ssl) {
        SSL_set_shutdown(conn_tlstor->ssl, SSL_SENT_SHUTDOWN | SSL_RECEIVED_SHUTDOWN);
        SSL_free(conn_tlstor->ssl);
        conn_tlstor->ssl = NULL;
      }
      shutdown(new_fd, SHUT_RDWR);
      close(new_fd);
      release_connection(conn_tlstor); // Return to pool
      continue;
    }
    pthread_attr_destroy(&attr);

    if (++kcc > kmx)
      kmx = kcc;
    } /* end for ev_idx */
  } /* end while(1) */

  io_engine_destroy(io_engine);
  pthread_cancel(certgen_thread);
  pthread_join(certgen_thread, NULL);

quit_main:
  SSL_CTX_free(sslctx);
  conn_stor_flush();
  sslctx_tbl_cleanup();
  cert_tlstor_cleanup(&cert_tlstor);
  ssl_free_locks();
  socket_handler_cleanup();
  
  if (pipefd[0] >= 0) close(pipefd[0]);
  if (pipefd[1] >= 0) close(pipefd[1]);
  
  for (i = 0; i < num_ports; i++) {
    if (sockfds[i] >= 0) close(sockfds[i]);
  }
  
  return (EXIT_SUCCESS);
}
